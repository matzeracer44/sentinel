import { checkSecurityEventsStoreHealth } from './securityEventsStore';
import { getThreatEventsPage, isTelemetryStoreReady } from './telemetryStore';
import { isFirewallHistoryStoreReady, loadFirewallStacks } from './firewallHistoryStore';
import { getConnectivityStatus } from './firewallSafety';

export type HealthStatus = 'pass' | 'warn' | 'fail';

export interface HealthCheckEntry {
  component: string;
  status: HealthStatus;
  durationMs: number;
  details?: string;
  error?: string;
  meta?: Record<string, unknown>;
}

export interface HealthReportSummary {
  generatedAt: number;
  cached: boolean;
  totalDurationMs: number;
  healthy: boolean;
  failing: number;
  warning: number;
}

export interface HealthReport {
  summary: HealthReportSummary;
  checks: {
    sqlite: HealthCheckEntry;
    telemetry: HealthCheckEntry;
    firewallHistory: HealthCheckEntry;
    connectivity: HealthCheckEntry;
  };
}

const CACHE_TTL_MS = 15_000;
let lastReport: HealthReport | null = null;

export async function getHealthReport(options: { force?: boolean } = {}): Promise<HealthReport> {
  const now = Date.now();
  if (!options.force && lastReport && now - lastReport.summary.generatedAt < CACHE_TTL_MS) {
    return {
      ...lastReport,
      summary: { ...lastReport.summary, cached: true },
    };
  }

  const start = Date.now();
  const [sqlite, telemetry, firewallHistory, connectivity] = await Promise.all([
    checkSqliteStore(),
    checkTelemetryStore(),
    checkFirewallHistoryStore(),
    checkConnectivity(options.force),
  ]);

  const failing = [sqlite, telemetry, firewallHistory, connectivity].filter((c) => c.status === 'fail').length;
  const warning = [sqlite, telemetry, firewallHistory, connectivity].filter((c) => c.status === 'warn').length;

  const report: HealthReport = {
    summary: {
      generatedAt: Date.now(),
      cached: false,
      totalDurationMs: Date.now() - start,
      healthy: failing === 0,
      failing,
      warning,
    },
    checks: {
      sqlite,
      telemetry,
      firewallHistory,
      connectivity,
    },
  };

  lastReport = report;
  return report;
}

async function checkSqliteStore(): Promise<HealthCheckEntry> {
  const start = Date.now();
  const result = checkSecurityEventsStoreHealth();
  return {
    component: 'better-sqlite3',
    status: result.ok ? 'pass' : 'fail',
    durationMs: Date.now() - start,
    details: result.ok ? 'Security events DB OK' : undefined,
    error: result.ok ? undefined : result.message,
  };
}

async function checkTelemetryStore(): Promise<HealthCheckEntry> {
  const start = Date.now();
  try {
    if (!isTelemetryStoreReady()) {
      return {
        component: 'telemetry-leveldb',
        status: 'fail',
        durationMs: Date.now() - start,
        error: 'Telemetry store not initialized',
      };
    }
    const page = await getThreatEventsPage({ limit: 1 });
    return {
      component: 'telemetry-leveldb',
      status: 'pass',
      durationMs: Date.now() - start,
      details: `Entries available: ${page.entries.length}`,
    };
  } catch (err: any) {
    return {
      component: 'telemetry-leveldb',
      status: 'fail',
      durationMs: Date.now() - start,
      error: err?.message || String(err),
    };
  }
}

async function checkFirewallHistoryStore(): Promise<HealthCheckEntry> {
  const start = Date.now();
  try {
    if (!isFirewallHistoryStoreReady()) {
      return {
        component: 'firewall-history-leveldb',
        status: 'fail',
        durationMs: Date.now() - start,
        error: 'Firewall history store not initialized',
      };
    }
    const stacks = await loadFirewallStacks();
    return {
      component: 'firewall-history-leveldb',
      status: 'pass',
      durationMs: Date.now() - start,
      details: `undo=${stacks.undo.length}, redo=${stacks.redo.length}`,
    };
  } catch (err: any) {
    return {
      component: 'firewall-history-leveldb',
      status: 'fail',
      durationMs: Date.now() - start,
      error: err?.message || String(err),
    };
  }
}

async function checkConnectivity(force?: boolean): Promise<HealthCheckEntry> {
  const start = Date.now();
  try {
    const result = await getConnectivityStatus({ force });
    return {
      component: 'connectivity',
      status: result.connected ? 'pass' : 'warn',
      durationMs: Date.now() - start,
      details: result.connected
        ? `DNS ${result.dnsTimeMs ?? '-'} ms / HTTP ${result.httpTimeMs ?? '-'} ms`
        : result.error || 'Connectivity degraded',
      meta: {
        connected: result.connected,
        dnsTimeMs: result.dnsTimeMs,
        httpTimeMs: result.httpTimeMs,
        totalTimeMs: result.totalTimeMs,
        checkedAt: result.checkedAt,
        cached: result.cached,
        error: result.error,
      },
    };
  } catch (err: any) {
    return {
      component: 'connectivity',
      status: 'fail',
      durationMs: Date.now() - start,
      error: err?.message || String(err),
    };
  }
}
