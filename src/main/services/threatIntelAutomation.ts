/**
 * SENTINEL — Automated Threat Intelligence Engine
 *
 * Runs YARA scans, MISP/IoC feed syncs, and network IoC checks AUTOMATICALLY.
 * No user interaction required — full DSGVO Art.32 compliance.
 *
 * 1. Auto-YARA:  Periodic scans of critical system paths (Downloads, Temp, Startup)
 * 2. Auto-IoC:   Continuous network connection checks against IoC feeds
 * 3. Auto-Feed:  Periodic MISP/abuse.ch feed sync (delegates to threatIntel.ts)
 * 4. Status:     Real-time status for Dashboard visibility — NO hidden tabs
 *
 * All scanning is 100% LOCAL. Feed downloads use free community feeds only.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { app } from 'electron';
import { addActivityLog } from './activityLog';

// ═══ Types ═══

export interface AutomationConfig {
  enabled: boolean;
  yaraEnabled: boolean;
  yaraIntervalMin: number;
  iocEnabled: boolean;
  iocIntervalSec: number;
  feedEnabled: boolean;
  feedIntervalHours: number;
  monitoredPaths: string[];
}

export interface YaraHit {
  file: string;
  rules: string[];
  severity: 'clean' | 'suspicious' | 'malicious';
  ts: string;
}

export interface IoCHit {
  ip: string;
  source: string;
  process: string;
  ts: string;
}

export interface AutomationStatus {
  running: boolean;
  yara: {
    enabled: boolean;
    scanning: boolean;
    lastScan: string | null;
    nextScan: string | null;
    filesScanned: number;
    threatsFound: number;
    totalScans: number;
    totalThreats: number;
  };
  ioc: {
    enabled: boolean;
    checking: boolean;
    lastCheck: string | null;
    connectionsChecked: number;
    hitsFound: number;
    totalChecks: number;
    totalHits: number;
  };
  feed: {
    enabled: boolean;
    syncing: boolean;
    lastSync: string | null;
    nextSync: string | null;
    ips: number;
    hashes: number;
    domains: number;
  };
  recentYaraHits: YaraHit[];
  recentIoCHits: IoCHit[];
}

// ═══ State ═══

const DEFAULT_PATHS = [
  path.join(os.homedir(), 'Downloads'),
  os.tmpdir(),
  path.join(os.homedir(), 'AppData', 'Local', 'Temp'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
  'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
];

let _cfg: AutomationConfig = {
  enabled: true,
  yaraEnabled: true,
  yaraIntervalMin: 30,
  iocEnabled: true,
  iocIntervalSec: 60,
  feedEnabled: true,
  feedIntervalHours: 6,
  monitoredPaths: DEFAULT_PATHS,
};

let _running = false;
let _yaraTimer: ReturnType<typeof setInterval> | null = null;
let _iocTimer: ReturnType<typeof setInterval> | null = null;
let _feedTimer: ReturnType<typeof setInterval> | null = null;

// YARA
let _yaraScanning = false;
let _yaraLastScan: string | null = null;
let _yaraNextScan: string | null = null;
let _yaraFilesScanned = 0;
let _yaraThreatsFound = 0;
let _yaraTotalScans = 0;
let _yaraTotalThreats = 0;
let _yaraRecentHits: YaraHit[] = [];
let _yaraSeenFiles: Set<string> = new Set();

// IoC
let _iocChecking = false;
let _iocLastCheck: string | null = null;
let _iocConnsChecked = 0;
let _iocHitsFound = 0;
let _iocTotalChecks = 0;
let _iocTotalHits = 0;
let _iocRecentHits: IoCHit[] = [];

// Feed
let _feedSyncing = false;
let _feedLastSync: string | null = null;
let _feedNextSync: string | null = null;
let _feedIPs = 0;
let _feedHashes = 0;
let _feedDomains = 0;

// External deps injected at init
let _argusManager: any = null;
let _getConnections: (() => Promise<Array<{ remoteAddress: string; owningProcess?: string; processName?: string }>>) | null = null;
let _checkIP: ((ip: string) => { malicious: boolean; source?: string }) | null = null;
let _refreshFeeds: (() => Promise<{ success: boolean; ips: number; hashes: number; domains: number; errors: string[] }>) | null = null;
let _getStats: (() => { ips: number; hashes: number; domains: number; lastUpdate: string | null }) | null = null;

// ═══ Config persistence ═══

function cfgPath(): string { return path.join(app.getPath('userData'), 'threat-intel-automation.json'); }

function loadCfg(): void {
  try {
    const p = cfgPath();
    if (fs.existsSync(p)) _cfg = { ..._cfg, ...JSON.parse(fs.readFileSync(p, 'utf8')) };
  } catch { /* first run */ }
}

function saveCfg(): void {
  try {
    fs.writeFileSync(cfgPath(), JSON.stringify(_cfg, null, 2), 'utf8');
  } catch { /* non-fatal */ }
}

// ═══ YARA Auto-Scan ═══

function fileHash(filePath: string): string {
  try {
    const buf = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(buf).digest('hex').slice(0, 16);
  } catch { return filePath; }
}

function collectFiles(dirs: string[], maxPerDir = 200): string[] {
  const result: string[] = [];
  const SCAN_EXTENSIONS = new Set([
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf',
    '.msi', '.scr', '.pif', '.com', '.hta', '.cpl', '.jar', '.py',
    '.lnk', '.reg', '.inf', '.doc', '.docx', '.xls', '.xlsx', '.pdf',
    '.zip', '.rar', '.7z', '.iso',
  ]);

  for (const dir of dirs) {
    try {
      if (!fs.existsSync(dir)) continue;
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      let count = 0;
      for (const entry of entries) {
        if (count >= maxPerDir) break;
        if (!entry.isFile()) continue;
        const ext = path.extname(entry.name).toLowerCase();
        if (!SCAN_EXTENSIONS.has(ext)) continue;
        const fullPath = path.join(dir, entry.name);
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size > 100 * 1024 * 1024) continue; // skip >100MB
          result.push(fullPath);
          count++;
        } catch { continue; }
      }
    } catch { continue; }
  }
  return result;
}

async function runYaraScan(): Promise<void> {
  if (_yaraScanning || !_argusManager) return;
  _yaraScanning = true;

  try {
    const files = collectFiles(_cfg.monitoredPaths);
    let threatsThisRun = 0;
    let scannedThisRun = 0;

    for (const filePath of files) {
      const hash = fileHash(filePath);
      if (_yaraSeenFiles.has(hash)) continue;

      try {
        const result = await _argusManager.safeFetch('/api/yara/scan', {
          method: 'POST',
          body: JSON.stringify({ file_path: filePath }),
        }) as Record<string, unknown>;

        scannedThisRun++;
        _yaraSeenFiles.add(hash);

        const matches = (result?.matches as any[]) || [];
        if (matches.length > 0) {
          threatsThisRun++;
          const ruleNames = matches.map((m: any) => m?.rule || m?.name || 'unknown').slice(0, 5);
          const severity = ruleNames.some((r: string) => /ransomware|trojan|backdoor|rootkit/i.test(r)) ? 'malicious' as const : 'suspicious' as const;

          const hit: YaraHit = {
            file: filePath,
            rules: ruleNames,
            severity,
            ts: new Date().toISOString(),
          };
          _yaraRecentHits = [hit, ..._yaraRecentHits.slice(0, 49)];

          addActivityLog('ThreatIntel-Auto', 'YARA-Treffer',
            `${severity === 'malicious' ? '🚨 MALWARE' : '⚠ Verdächtig'}: ${path.basename(filePath)} — Regeln: ${ruleNames.join(', ')}`,
            severity === 'malicious' ? 'error' : 'warning');
        }
      } catch {
        // ARGUS offline or scan failed — skip silently
      }
    }

    _yaraFilesScanned = scannedThisRun;
    _yaraThreatsFound = threatsThisRun;
    _yaraTotalScans++;
    _yaraTotalThreats += threatsThisRun;
    _yaraLastScan = new Date().toISOString();
    _yaraNextScan = new Date(Date.now() + _cfg.yaraIntervalMin * 60_000).toISOString();

    if (scannedThisRun > 0) {
      addActivityLog('ThreatIntel-Auto', 'YARA-Scan',
        `Auto-Scan abgeschlossen: ${scannedThisRun} Dateien geprüft, ${threatsThisRun} Bedrohungen gefunden`,
        threatsThisRun > 0 ? 'warning' : 'success');
    }
  } catch (e: any) {
    addActivityLog('ThreatIntel-Auto', 'YARA-Fehler', `Auto-YARA-Scan fehlgeschlagen: ${e?.message}`, 'error');
  } finally {
    _yaraScanning = false;
  }
}

// ═══ IoC Network Check ═══

async function runIoCCheck(): Promise<void> {
  if (_iocChecking || !_getConnections || !_checkIP) return;
  _iocChecking = true;

  try {
    const conns = await _getConnections();
    let hits = 0;

    for (const conn of conns) {
      if (!conn.remoteAddress || conn.remoteAddress === '0.0.0.0' || conn.remoteAddress === '::' ||
          conn.remoteAddress.startsWith('127.') || conn.remoteAddress.startsWith('192.168.') ||
          conn.remoteAddress.startsWith('10.') || conn.remoteAddress.startsWith('172.')) continue;

      const result = _checkIP(conn.remoteAddress);
      if (result.malicious) {
        hits++;
        const hit: IoCHit = {
          ip: conn.remoteAddress,
          source: result.source || 'IoC-Feed',
          process: conn.processName || conn.owningProcess?.toString() || 'Unbekannt',
          ts: new Date().toISOString(),
        };

        // Dedupe: don't re-alert same IP within 10 min
        const isDupe = _iocRecentHits.some(h => h.ip === hit.ip && Date.now() - new Date(h.ts).getTime() < 600_000);
        if (!isDupe) {
          _iocRecentHits = [hit, ..._iocRecentHits.slice(0, 49)];
          addActivityLog('ThreatIntel-Auto', 'IoC-Treffer',
            `🚨 Verbindung zu bekannter bösartiger IP: ${hit.ip} (Prozess: ${hit.process}, Quelle: ${hit.source})`,
            'error');
        }
      }
    }

    _iocConnsChecked = conns.length;
    _iocHitsFound = hits;
    _iocTotalChecks++;
    _iocTotalHits += hits;
    _iocLastCheck = new Date().toISOString();
  } catch (e: any) {
    // Silent — network check failures are non-fatal
  } finally {
    _iocChecking = false;
  }
}

// ═══ Feed Auto-Sync ═══

async function runFeedSync(): Promise<void> {
  if (_feedSyncing || !_refreshFeeds) return;
  _feedSyncing = true;

  try {
    const result = await _refreshFeeds();
    _feedIPs = result.ips;
    _feedHashes = result.hashes;
    _feedDomains = result.domains;
    _feedLastSync = new Date().toISOString();
    _feedNextSync = new Date(Date.now() + _cfg.feedIntervalHours * 3600_000).toISOString();
    // Activity log is already handled by threatIntel.ts refreshFeeds()
  } catch (e: any) {
    addActivityLog('ThreatIntel-Auto', 'Feed-Fehler', `Auto-Feed-Sync fehlgeschlagen: ${e?.message}`, 'error');
  } finally {
    _feedSyncing = false;
  }
}

// ═══ Timer Management ═══

function startTimers(): void {
  stopTimers();

  if (_cfg.yaraEnabled) {
    _yaraNextScan = new Date(Date.now() + 15_000).toISOString(); // first scan 15s after start
    setTimeout(() => runYaraScan().catch(() => {}), 15_000);
    _yaraTimer = setInterval(() => runYaraScan().catch(() => {}), _cfg.yaraIntervalMin * 60_000);
  }

  if (_cfg.iocEnabled) {
    setTimeout(() => runIoCCheck().catch(() => {}), 10_000);
    _iocTimer = setInterval(() => runIoCCheck().catch(() => {}), _cfg.iocIntervalSec * 1000);
  }

  if (_cfg.feedEnabled) {
    _feedNextSync = new Date(Date.now() + _cfg.feedIntervalHours * 3600_000).toISOString();
    _feedTimer = setInterval(() => runFeedSync().catch(() => {}), _cfg.feedIntervalHours * 3600_000);
  }
}

function stopTimers(): void {
  if (_yaraTimer) { clearInterval(_yaraTimer); _yaraTimer = null; }
  if (_iocTimer) { clearInterval(_iocTimer); _iocTimer = null; }
  if (_feedTimer) { clearInterval(_feedTimer); _feedTimer = null; }
}

// ═══ Public API ═══

export function initThreatIntelAutomation(deps: {
  argusManager?: any;
  getConnections?: () => Promise<Array<{ remoteAddress: string; owningProcess?: string; processName?: string }>>;
  checkIP?: (ip: string) => { malicious: boolean; source?: string };
  refreshFeeds?: () => Promise<{ success: boolean; ips: number; hashes: number; domains: number; errors: string[] }>;
  getStats?: () => { ips: number; hashes: number; domains: number; lastUpdate: string | null };
}): void {
  loadCfg();
  _argusManager = deps.argusManager || null;
  _getConnections = deps.getConnections || null;
  _checkIP = deps.checkIP || null;
  _refreshFeeds = deps.refreshFeeds || null;
  _getStats = deps.getStats || null;

  // Read current feed stats
  if (_getStats) {
    try {
      const stats = _getStats();
      _feedIPs = stats.ips;
      _feedHashes = stats.hashes;
      _feedDomains = stats.domains;
      _feedLastSync = stats.lastUpdate;
    } catch { /* ok */ }
  }

  if (_cfg.enabled) {
    _running = true;
    startTimers();
    addActivityLog('ThreatIntel-Auto', 'Engine gestartet',
      `Automatische Bedrohungsanalyse aktiv — YARA: ${_cfg.yaraEnabled ? 'alle ' + _cfg.yaraIntervalMin + ' Min' : 'aus'}, IoC: ${_cfg.iocEnabled ? 'alle ' + _cfg.iocIntervalSec + 's' : 'aus'}, Feeds: ${_cfg.feedEnabled ? 'alle ' + _cfg.feedIntervalHours + 'h' : 'aus'}`,
      'success');
  }

  console.log(`[ThreatIntelAutomation] Init — enabled=${_cfg.enabled}, yara=${_cfg.yaraEnabled}, ioc=${_cfg.iocEnabled}, feed=${_cfg.feedEnabled}`);
}

export function stopThreatIntelAutomation(): void {
  stopTimers();
  _running = false;
}

export function getAutomationStatus(): AutomationStatus {
  // Refresh feed stats if available
  if (_getStats) {
    try {
      const stats = _getStats();
      _feedIPs = stats.ips;
      _feedHashes = stats.hashes;
      _feedDomains = stats.domains;
      if (stats.lastUpdate) _feedLastSync = stats.lastUpdate;
    } catch { /* ok */ }
  }

  return {
    running: _running,
    yara: {
      enabled: _cfg.yaraEnabled,
      scanning: _yaraScanning,
      lastScan: _yaraLastScan,
      nextScan: _yaraNextScan,
      filesScanned: _yaraFilesScanned,
      threatsFound: _yaraThreatsFound,
      totalScans: _yaraTotalScans,
      totalThreats: _yaraTotalThreats,
    },
    ioc: {
      enabled: _cfg.iocEnabled,
      checking: _iocChecking,
      lastCheck: _iocLastCheck,
      connectionsChecked: _iocConnsChecked,
      hitsFound: _iocHitsFound,
      totalChecks: _iocTotalChecks,
      totalHits: _iocTotalHits,
    },
    feed: {
      enabled: _cfg.feedEnabled,
      syncing: _feedSyncing,
      lastSync: _feedLastSync,
      nextSync: _feedNextSync,
      ips: _feedIPs,
      hashes: _feedHashes,
      domains: _feedDomains,
    },
    recentYaraHits: _yaraRecentHits.slice(0, 10),
    recentIoCHits: _iocRecentHits.slice(0, 10),
  };
}

export function getAutomationConfig(): AutomationConfig { return { ..._cfg }; }

export function setAutomationConfig(update: Partial<AutomationConfig>): AutomationConfig {
  const wasEnabled = _cfg.enabled;
  _cfg = { ..._cfg, ...update };
  saveCfg();

  if (_cfg.enabled && !wasEnabled) {
    _running = true;
    startTimers();
    addActivityLog('ThreatIntel-Auto', 'Aktiviert', 'Automatische Bedrohungsanalyse aktiviert', 'success');
  } else if (!_cfg.enabled && wasEnabled) {
    stopTimers();
    _running = false;
    addActivityLog('ThreatIntel-Auto', 'Deaktiviert', 'Automatische Bedrohungsanalyse deaktiviert', 'warning');
  } else if (_cfg.enabled) {
    startTimers(); // restart with new intervals
  }

  return { ..._cfg };
}

export async function triggerYaraScan(): Promise<{ success: boolean; files: number; threats: number }> {
  await runYaraScan();
  return { success: true, files: _yaraFilesScanned, threats: _yaraThreatsFound };
}

export async function triggerIoCCheck(): Promise<{ success: boolean; connections: number; hits: number }> {
  await runIoCCheck();
  return { success: true, connections: _iocConnsChecked, hits: _iocHitsFound };
}

export async function triggerFeedSync(): Promise<{ success: boolean; ips: number; hashes: number; domains: number }> {
  await runFeedSync();
  return { success: true, ips: _feedIPs, hashes: _feedHashes, domains: _feedDomains };
}

export function clearYaraCache(): void {
  _yaraSeenFiles.clear();
  addActivityLog('ThreatIntel-Auto', 'Cache geleert', 'YARA-Datei-Cache zurückgesetzt — alle Dateien werden beim nächsten Scan erneut geprüft', 'info');
}
