import { PolicyIntel } from '../../shared/ipcSchemas';
import { addActivityLog } from './activityLog';
import { getAddressWatchSummary, AddressWatch } from './networkMonitor';
import { getIPMetadataService } from './shieldData';
import { inspectTLS } from './tlsInspector';
import { upsertPolicySuggestionByFingerprint } from './telemetryStore';

const POLICY_SCAN_INTERVAL_MS = Number(process.env.POLICY_SCAN_INTERVAL_MS || 20_000);
const MAX_ANALYZED_WATCH_ENTRIES = Number(process.env.POLICY_SCAN_WATCH_LIMIT || 25);
const MIN_WATCH_HITS = Number(process.env.POLICY_SCAN_MIN_HITS || 2);

let scanTimer: NodeJS.Timeout | null = null;
let running = false;
let activeScan: Promise<void> | null = null;

export function startPolicyScanner() {
  if (running) {
    return;
  }
  running = true;
  scheduleNextScan(1000);
  addActivityLog('policy', 'scanner-start', 'Policy scanner activated', 'info');
}

export async function stopPolicyScanner() {
  running = false;
  if (scanTimer) {
    clearTimeout(scanTimer);
    scanTimer = null;
  }
  if (activeScan) {
    try {
      await activeScan;
    } catch {
      // ignore
    }
    activeScan = null;
  }
  addActivityLog('policy', 'scanner-stop', 'Policy scanner stopped', 'info');
}

function scheduleNextScan(delay = POLICY_SCAN_INTERVAL_MS) {
  if (!running) {
    return;
  }
  if (scanTimer) {
    clearTimeout(scanTimer);
  }
  scanTimer = setTimeout(() => {
    scanTimer = null;
    activeScan = runScan()
      .catch((err) => {
        console.warn('[PolicyScanner] Scan failed', err);
        addActivityLog('policy', 'scanner-error', String(err), 'warning');
      })
      .finally(() => {
        activeScan = null;
        scheduleNextScan();
      });
  }, delay);
}

async function runScan() {
  const watchEntries = getAddressWatchSummary()
    .filter((entry) => entry.hits >= MIN_WATCH_HITS)
    .sort((a, b) => b.hits - a.hits)
    .slice(0, MAX_ANALYZED_WATCH_ENTRIES);

  if (!watchEntries.length) {
    return;
  }

  await Promise.all(watchEntries.map((record) => analyzeWatchEntry(record)));
}

async function analyzeWatchEntry(record: AddressWatch) {
  const ip = record.ip?.trim();
  if (!ip) {
    return;
  }
  const fingerprint = `watch:${ip}`;
  const intel = await buildPolicyIntel(record).catch((err) => {
    console.warn('[PolicyScanner] Failed to build intel', ip, err);
    return buildFallbackIntel(record);
  });

  const leakSignals = intel.leakSignals ?? [];
  const tlsIssues = intel.tlsIssues ?? [];
  const evidenceBoost = leakSignals.length + tlsIssues.length;
  const evidenceCount = Math.max(record.hits + evidenceBoost, 1);
  const confidence = Math.min(1, 0.3 + record.hits * 0.05 + evidenceBoost * 0.1);
  const recommendation = `Promote containment rule for ${ip} (${record.hits} watch hits)`;

  await upsertPolicySuggestionByFingerprint(fingerprint, {
    recommendation,
    remoteIP: ip,
    processName: intel.org || 'Unknown',
    confidence,
    evidenceCount,
    intel,
  });
}

function buildFallbackIntel(record: AddressWatch): PolicyIntel {
  return {
    ip: record.ip,
    watchHits: record.hits,
    lastSeen: record.lastSeen,
    riskSummary: `No metadata available. ${record.hits} watch hits recorded.`,
  };
}

async function buildPolicyIntel(record: AddressWatch): Promise<PolicyIntel> {
  const metaResult = await getIPMetadataService(record.ip);
  const tlsSummary = record.hits >= 4 ? await safeInspectTLS(record.ip) : null;

  const intel: PolicyIntel = {
    ip: record.ip,
    watchHits: record.hits,
    lastSeen: record.lastSeen,
  };

  if (metaResult?.success && metaResult.data) {
    const data = metaResult.data;
    intel.org = data.org || data.orgName || data.isp;
    intel.country = data.country || data.countryCode;
    intel.region = data.region;
    intel.city = data.city;
  }

  if (tlsSummary) {
    intel.tlsGrade = tlsSummary.grade;
    intel.tlsIssues = tlsSummary.issues || [];
  }

  const leakSignals: string[] = [];
  if (record.hits >= 5) {
    leakSignals.push('Repeated watchlist hits');
  }
  if (intel.org && /hosting|vpn|cloud|colo|datacenter/i.test(intel.org)) {
    leakSignals.push('Runs on hosting/VPN provider');
  }
  if (tlsSummary && (tlsSummary.grade ?? 'F') <= 'C') {
    leakSignals.push(`Weak TLS grade (${tlsSummary.grade})`);
  }

  intel.leakSignals = leakSignals.length ? leakSignals : undefined;
  intel.riskSummary = buildRiskSummary(intel);
  return intel;
}

async function safeInspectTLS(ip: string) {
  try {
    return await inspectTLS(ip);
  } catch (err) {
    console.warn('[PolicyScanner] TLS inspection failed', ip, err);
    return null;
  }
}

function buildRiskSummary(intel: PolicyIntel): string {
  const parts: string[] = [];
  if (intel.country) {
    parts.push(intel.country);
  }
  if (intel.org) {
    parts.push(intel.org);
  }
  if (intel.leakSignals?.length) {
    parts.push(intel.leakSignals.join('; '));
  }
  if (!parts.length) {
    return 'Insufficient intelligence gathered.';
  }
  return parts.join(' • ');
}
