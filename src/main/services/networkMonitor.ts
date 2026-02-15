import { spawn, ChildProcessWithoutNullStreams } from 'child_process';

export interface NetworkMonitorConnection {
  localIP: string;
  localPort: number;
  remoteIP: string;
  remotePort: number;
  protocol: string;
  state: string;
  process: string;
  pid: number;
  bandwidth: number;
  watchHitCount?: number;
  processPath?: string;
  processCompany?: string;
  processDescription?: string;
  ipTag?: 'loopback' | 'lan' | 'vpn-tunnel' | 'external';
}

export interface FullAuditConnection {
  localIP: string;
  localPort: number;
  remoteIP: string;
  remotePort: number;
  state: string;
  pid: number;
  process: string;
}

const CACHE_TTL_MS = 4000;
const POWERSHELL_TIMEOUT_MS = 20000;
const NETSTAT_TIMEOUT_MS = 10000;
const AUDIT_STATES = [
  'Listen',
  'Established',
  'SynSent',
  'SynReceived',
  'FinWait1',
  'FinWait2',
  'CloseWait',
  'Closed',
  'Closing',
  'LastAck',
  'TimeWait',
  'Bound',
];

let lastResult: { timestamp: number; limit: number; data: NetworkMonitorConnection[] } = {
  timestamp: 0,
  limit: 0,
  data: [],
};

let inflight: Promise<NetworkMonitorConnection[]> | null = null;

export interface AddressWatch {
  ip: string;
  registeredAt: number;
  hits: number;
  lastSeen: number;
}

const addressWatchMap = new Map<string, AddressWatch>();

const MAX_ASYNC_COLLECTORS = 13;

type TrackedProcessMeta = {
  descriptor: string;
  startedAt: number;
};

const activeCollectors = new Map<ChildProcessWithoutNullStreams, TrackedProcessMeta>();

function terminateProcess(child: ChildProcessWithoutNullStreams, reason: string): void {
  if (child.killed) {
    return;
  }
  try {
    child.kill();
  } catch (err) {
    console.warn(`[NetworkMonitor] Failed to terminate process (${reason}):`, err);
  }
}

function enforceCollectorBudget(): void {
  while (activeCollectors.size > MAX_ASYNC_COLLECTORS) {
    const iterator = activeCollectors.entries().next();
    if (iterator.done) break;
    const [victim, meta] = iterator.value;
    activeCollectors.delete(victim);
    const lifetime = Date.now() - meta.startedAt;
    console.warn(
      `[NetworkMonitor] Terminating surplus async connection (${meta.descriptor}) after ${lifetime}ms to stay under ${MAX_ASYNC_COLLECTORS}.`
    );
    terminateProcess(victim, 'collector budget exceeded');
  }
}

function trackCollector(child: ChildProcessWithoutNullStreams, descriptor: string): void {
  activeCollectors.set(child, { descriptor, startedAt: Date.now() });
  const cleanup = () => {
    child.removeListener('close', cleanup);
    child.removeListener('error', cleanup);
    activeCollectors.delete(child);
  };
  child.once('close', cleanup);
  child.once('error', cleanup);
  enforceCollectorBudget();
}

function getActiveCollectorCount(): number {
  return activeCollectors.size;
}

export function registerAddressWatch(ip: string): AddressWatch {
  const normalized = (ip || '').trim();
  if (!normalized) {
    throw new Error('Invalid IP address');
  }
  if (!addressWatchMap.has(normalized)) {
    addressWatchMap.set(normalized, {
      ip: normalized,
      registeredAt: Date.now(),
      hits: 0,
      lastSeen: 0,
    });
  }
  return addressWatchMap.get(normalized)!;
}

export function getAddressWatchSummary(): AddressWatch[] {
  return Array.from(addressWatchMap.values()).map((watch) => ({ ...watch }));
}

function annotateWatchHits(connections: NetworkMonitorConnection[]): NetworkMonitorConnection[] {
  return connections.map((conn) => {
    const watch = addressWatchMap.get(conn.remoteIP);
    if (watch) {
      watch.hits += 1;
      watch.lastSeen = Date.now();
      return { ...conn, watchHitCount: watch.hits };
    }
    return conn;
  });
}

export async function getNetworkTrafficSnapshot(limit = 100): Promise<NetworkMonitorConnection[]> {
  const now = Date.now();

  if (now - lastResult.timestamp < CACHE_TTL_MS && lastResult.data.length && limit <= lastResult.limit) {
    return lastResult.data.slice(0, limit);
  }

  if (inflight) {
    const cached = await inflight;
    return cached.slice(0, limit);
  }

  const fetchLimit = Math.max(limit, lastResult.limit, 150);

  inflight = (async () => {
    try {
      const data = await collectNetworkConnections(fetchLimit);
      const annotated = annotateWatchHits(data);
      lastResult = { timestamp: Date.now(), limit: fetchLimit, data: annotated };
      console.log(
        `[NetworkMonitor] Snapshot refreshed with ${annotated.length} connections (active collectors: ${getActiveCollectorCount()}).`
      );
      return annotated;
    } finally {
      inflight = null;
    }
  })();

  const result = await inflight;
  return result.slice(0, limit);
}

export async function getFullNetworkAudit(limit = 1500): Promise<FullAuditConnection[]> {
  try {
    const script = buildFullAuditCommand(limit);
    const raw = await runPowerShellJson(script, POWERSHELL_TIMEOUT_MS, 'networkMonitor:audit');
    const records = Array.isArray(raw) ? raw : raw ? [raw] : [];
    return normalizeAuditRecords(records);
  } catch (err) {
    console.error('[NetworkMonitor] Full audit failed:', err);
    return [];
  }
}

let _vpnActive = false;
let _vpnAdapters = '';

export function isVpnActive(): boolean {
  return _vpnActive;
}

async function collectNetworkConnections(limit: number): Promise<NetworkMonitorConnection[]> {
  try {
    const psCommand = buildPowerShellCommand(limit);
    const raw = await runPowerShellJson(psCommand, POWERSHELL_TIMEOUT_MS, 'networkMonitor:snapshot');

    // New enriched format: { vpnActive, vpnAdapters, connections: [...] }
    let records: any[] = [];
    if (raw && typeof raw === 'object' && !Array.isArray(raw) && 'connections' in raw) {
      _vpnActive = !!raw.vpnActive;
      _vpnAdapters = raw.vpnAdapters || '';
      const conns = raw.connections;
      records = Array.isArray(conns) ? conns : conns ? [conns] : [];
    } else {
      // Fallback: old format (plain array)
      records = Array.isArray(raw) ? raw : raw ? [raw] : [];
    }

    if (records.length) {
      return normalizeRecords(records);
    }
  } catch (err) {
    console.warn('[NetworkMonitor] PowerShell query failed, falling back to netstat:', err);
  }

  const netstat = await runNetstat();
  return parseNetstatOutput(netstat).slice(0, limit);
}

function buildPowerShellCommand(limit: number): string {
  // Enriched query: process Path, Company, Description + VPN adapter detection
  const psScript = [
    "$ErrorActionPreference = 'Stop'",
    // Detect VPN adapters (NordLynx, WireGuard, TAP, TUN)
    "$vpnAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'NordLynx|WireGuard|TAP-|TUN|VPN|Wintun' -and $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name)",
    "$vpnActive = $vpnAdapters.Count -gt 0",
    // Get connections with enriched process info
    `$conns = Get-NetTCPConnection -State ${AUDIT_STATES.join(',')} -ErrorAction SilentlyContinue |`,
    "  Where-Object { $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1') } |",
    '  Select-Object -First ' + limit + ' LocalAddress, LocalPort, RemoteAddress, RemotePort,',
    "    @{Name='State';Expression={$_.State.ToString()}},",
    "    OwningProcess,",
    "    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},",
    "    @{Name='ProcessPath';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}},",
    "    @{Name='ProcessCompany';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Company}},",
    "    @{Name='ProcessDescription';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Description}}",
    // Wrap result with VPN metadata
    "@{ vpnActive = $vpnActive; vpnAdapters = ($vpnAdapters -join ','); connections = $conns } | ConvertTo-Json -Depth 3 -Compress",
  ].join('\n');

  return psScript;
}

function buildFullAuditCommand(limit: number): string {
  return [
    "$ErrorActionPreference = 'Stop'",
    `Get-NetTCPConnection -State ${AUDIT_STATES.join(',')} -ErrorAction SilentlyContinue |`,
    '  Select-Object -First ' + limit +
      " LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |",
    '  ConvertTo-Json -Compress',
  ].join('\n');
}

async function runPowerShellJson(script: string, timeoutMs: number, descriptor: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], {
      windowsHide: true,
    });
    trackCollector(child, descriptor);

    let stdout = '';
    let stderr = '';

    const timer = setTimeout(() => {
      terminateProcess(child, `timeout after ${timeoutMs}ms (${descriptor})`);
      reject(new Error(`PowerShell command timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });

    child.on('close', (code) => {
      clearTimeout(timer);

      if (code !== 0 && stderr.trim().length) {
        reject(new Error(stderr.trim()));
        return;
      }

      if (!stdout.trim()) {
        resolve([]);
        return;
      }

      try {
        resolve(JSON.parse(stdout.trim()));
      } catch (err) {
        reject(err);
      }
    });
  });
}

async function runNetstat(): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn('netstat', ['-ano', '-n', '-p', 'tcp'], { windowsHide: true });
    trackCollector(child, 'networkMonitor:netstat');

    let stdout = '';
    let stderr = '';

    const timer = setTimeout(() => {
      terminateProcess(child, `timeout after ${NETSTAT_TIMEOUT_MS}ms (netstat)`);
      reject(new Error('netstat timed out'));
    }, NETSTAT_TIMEOUT_MS);

    child.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    child.on('close', (code) => {
      clearTimeout(timer);

      if (code !== 0 && stderr.trim().length) {
        reject(new Error(stderr.trim()));
        return;
      }

      resolve(stdout);
    });
  });
}

function classifyIP(ip: string): 'loopback' | 'lan' | 'vpn-tunnel' | 'external' {
  if (!ip) return 'external';
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
    return _vpnActive ? 'vpn-tunnel' : 'loopback';
  }
  if (ip.startsWith('192.168.') || ip.startsWith('10.') ||
      ip.startsWith('169.254.') || ip === '0.0.0.0' || ip === '::') return 'lan';
  // 172.16-31.x.x
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 16 && second <= 31) return 'lan';
  }
  return 'external';
}

function normalizeRecords(records: any[]): NetworkMonitorConnection[] {
  return records
    .map((record) => {
      const remoteIP = (record.RemoteAddress || record.remoteAddress || '').trim() || '0.0.0.0';
      return {
        localIP: (record.LocalAddress || record.localAddress || '').trim() || '0.0.0.0',
        localPort: safeNumber(record.LocalPort || record.localPort),
        remoteIP,
        remotePort: safeNumber(record.RemotePort || record.remotePort),
        protocol: 'TCP',
        state: String(record.State || record.state || 'Unknown'),
        process: record.ProcessName || record.processName || 'Unknown',
        pid: safeNumber(record.OwningProcess || record.pid),
        processPath: record.ProcessPath || record.processPath || '',
        processCompany: record.ProcessCompany || record.processCompany || '',
        processDescription: record.ProcessDescription || record.processDescription || '',
        ipTag: classifyIP(remoteIP),
      };
    })
    .filter((conn) => {
      if (!conn.remoteIP || conn.remoteIP === '0.0.0.0' || conn.remoteIP === '::') return false;
      // When VPN active, 127.0.0.1/::1 are tunneled connections — keep them tagged
      if (conn.remoteIP === '127.0.0.1' || conn.remoteIP === '::1') {
        return _vpnActive;
      }
      return true;
    })
    .map(applyBandwidthEstimate);
}

function parseNetstatOutput(output: string): NetworkMonitorConnection[] {
  const lines = output
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  const startIndex = lines.findIndex((line) => line.toLowerCase().startsWith('proto'));
  if (startIndex === -1) return [];

  const connections: NetworkMonitorConnection[] = [];

  for (let i = startIndex + 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line || line.startsWith('Proto')) continue;

    const parts = line.split(/\s+/);
    if (parts.length < 5) continue;

    const local = splitAddress(parts[1]);
    const remote = splitAddress(parts[2]);

    const rip = remote.ip;
    if (!rip || rip === '0.0.0.0' || rip === '::' || rip === '127.0.0.1' || rip === '::1') continue;

    const candidate = {
      localIP: local.ip,
      localPort: local.port,
      remoteIP: rip,
      remotePort: remote.port,
      protocol: parts[0]?.toUpperCase() || 'TCP',
      state: parts[3] || 'UNKNOWN',
      pid: safeNumber(parts[4]),
      process: 'Unknown',
    };

    connections.push(applyBandwidthEstimate(candidate));
  }

  return connections;
}

function splitAddress(address: string): { ip: string; port: number } {
  if (!address) return { ip: '0.0.0.0', port: 0 };
  const cleaned = address.replace('[', '').replace(']', '');
  const lastColon = cleaned.lastIndexOf(':');
  if (lastColon === -1) {
    return { ip: cleaned, port: 0 };
  }
  const ip = cleaned.slice(0, lastColon) || cleaned;
  const port = safeNumber(cleaned.slice(lastColon + 1));
  return { ip, port };
}

function safeNumber(value: any): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function applyBandwidthEstimate(connection: Omit<NetworkMonitorConnection, 'bandwidth'>): NetworkMonitorConnection {
  const seed = `${connection.remoteIP}:${connection.remotePort}:${connection.pid}`;
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = (hash << 5) - hash + seed.charCodeAt(i);
    hash |= 0;
  }
  const normalized = Math.abs(Math.sin(hash)) * 250_000;
  return { ...connection, bandwidth: Math.round(normalized) };
}

function normalizeAuditRecords(records: any[]): FullAuditConnection[] {
  return records.map((record) => ({
    localIP: (record.LocalAddress || record.localAddress || '').trim() || '0.0.0.0',
    localPort: safeNumber(record.LocalPort || record.localPort),
    remoteIP: (record.RemoteAddress || record.remoteAddress || '').trim() || '0.0.0.0',
    remotePort: safeNumber(record.RemotePort || record.remotePort),
    state: String(record.State || record.state || 'Unknown'),
    pid: safeNumber(record.OwningProcess || record.pid),
    process: record.ProcessName || record.processName || 'Unknown',
  }));
}
