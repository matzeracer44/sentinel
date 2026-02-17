import { ipcMain } from 'electron';
import { exec, execFile } from 'child_process';
import { promisify } from 'util';
const execAsync = promisify(exec);
async function runShellCmd(cmd: string, opts: Record<string, any> = {}): Promise<string> {
  const { stdout } = await execAsync(cmd, { encoding: 'utf8', windowsHide: true, timeout: 10000, ...opts });
  return (stdout || '').trim();
}
import * as os from 'os';
import { addActivityLog } from '../services/activityLog';
import { sanitizeShellArg, validateIPForShell } from '../../shared/utils';
import {
  testInternet,
  safeBlockPort,
  blockSubnet,
  undoFirewallAction,
  redoFirewallAction,
  getUndoRedoStatus,
  blockProcessByPid,
} from '../services/firewallSafety';
import {
  ShieldBlockPidRequestSchema,
  ShieldBlockPortRequestSchema,
  ShieldBlockSubnetRequestSchema,
} from '../../shared/ipcSchemas';
import { getNetworkTrafficSnapshot, getFullNetworkAudit } from '../services/networkMonitor';
import { isExternalIpLookupAllowed } from '../services/sentinelConfig';
import { killProcess as killProcessService, getSentinelRules, getBlockedIPs, IPBlockInfo } from '../services/shieldData';
import { runPowerShellSafe } from '../services/execOptions';

// ── IP Metadata Cache (saves ipinfo.io free-tier credits) ──
const IP_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const IP_CACHE_MAX = 500;
const _ipMetadataCache = new Map<string, { data: any; expiresAt: number }>();

function getCachedIpMetadata(ip: string): any | null {
  const entry = _ipMetadataCache.get(ip);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { _ipMetadataCache.delete(ip); return null; }
  return entry.data;
}

function setCachedIpMetadata(ip: string, data: any): void {
  if (_ipMetadataCache.size >= IP_CACHE_MAX) {
    const oldest = _ipMetadataCache.keys().next().value;
    if (oldest) _ipMetadataCache.delete(oldest);
  }
  _ipMetadataCache.set(ip, { data, expiresAt: Date.now() + IP_CACHE_TTL_MS });
}

export function getIpCacheStats(): { cachedEntries: number; maxEntries: number; ttlMs: number } {
  // Prune expired entries
  const now = Date.now();
  for (const [key, entry] of _ipMetadataCache) {
    if (now > entry.expiresAt) _ipMetadataCache.delete(key);
  }
  return { cachedEntries: _ipMetadataCache.size, maxEntries: IP_CACHE_MAX, ttlMs: IP_CACHE_TTL_MS };
}


interface SentinelFirewallRule {
  name: string;
  direction: string;
  action: string;
  enabled: string | boolean;
  profile: string;
  protocol: string;
  program: string;
  localPort: string;
  remotePort: string;
  localAddress: string;
  remoteAddress: string;
  description: string;
  timeCreated: string | null;
}

interface FirewallAggregationReport {
  rules: SentinelFirewallRule[];
  meta: {
    totalCollected: number;
    sentinelTagged: number;
    tracked: number;
    fallbackUsed: boolean;
    powershellRuleCount: number;
    errors: string[];
    generatedAt: number;
  };
}

const LOCALIZED_LABELS: Record<string, string[]> = {
  name: ['Rule Name', 'Regelname'],
  direction: ['Direction', 'Richtung'],
  action: ['Action', 'Aktion'],
  enabled: ['Enabled', 'Aktiviert'],
  profile: ['Profile', 'Profil'],
  protocol: ['Protocol', 'Protokoll'],
  program: ['Program', 'Programm'],
  localPort: ['LocalPort', 'Lokaler Port'],
  remotePort: ['RemotePort', 'Remoteport', 'Entfernter Port'],
  localAddress: ['LocalIP', 'Local Address', 'Lokale IP-Adresse'],
  remoteAddress: ['RemoteIP', 'Remote Address', 'Remote IP-Adresse'],
  description: ['Description', 'Beschreibung'],
};

const captureLabel = (block: string, labels: string[], fallback = 'Any') => {
  for (const label of labels) {
    const match = block.match(new RegExp(`${label}:\\s*(.+)`, 'i'));
    if (match?.[1]) {
      return match[1].trim();
    }
  }
  return fallback;
};

function normalizeDirection(raw: string | number): string {
  if (typeof raw === 'number') return raw === 1 ? 'Inbound' : raw === 2 ? 'Outbound' : String(raw);
  const lower = String(raw).trim().toLowerCase();
  if (lower === 'inbound' || lower === 'eingehend' || lower === 'in' || lower === '1') return 'Inbound';
  if (lower === 'outbound' || lower === 'ausgehend' || lower === 'out' || lower === '2') return 'Outbound';
  if (lower === 'both' || lower === 'beide') return 'Both';
  return String(raw);
}

function normalizeAction(raw: string | number): string {
  if (typeof raw === 'number') return raw === 2 ? 'Allow' : raw === 4 ? 'Block' : String(raw);
  const lower = String(raw).trim().toLowerCase();
  if (lower === 'allow' || lower === 'zulassen') return 'Allow';
  if (lower === 'block' || lower === 'blockieren') return 'Block';
  return String(raw);
}

function normalizeEnabled(raw: string | boolean | number): boolean {
  if (typeof raw === 'boolean') return raw;
  if (typeof raw === 'number') return raw === 1 || raw === 2; // PS enum: 1=True, 2=True
  const lower = String(raw).trim().toLowerCase();
  return lower === 'true' || lower === 'ja' || lower === 'yes' || lower === '1';
}

const parseNetshRuleBlocks = (input: string): SentinelFirewallRule[] => {
  if (!input) return [];
  return input
    .split(/\r?\n\s*\r?\n/)
    .map((block) => {
      const name = captureLabel(block, LOCALIZED_LABELS.name, '').trim();
      if (!name) return null;
      return {
        name,
        direction: normalizeDirection(captureLabel(block, LOCALIZED_LABELS.direction, 'N/A')),
        action: normalizeAction(captureLabel(block, LOCALIZED_LABELS.action, 'N/A')),
        enabled: normalizeEnabled(captureLabel(block, LOCALIZED_LABELS.enabled, 'Yes')),
        profile: captureLabel(block, LOCALIZED_LABELS.profile, 'Any'),
        protocol: captureLabel(block, LOCALIZED_LABELS.protocol, 'Any'),
        program: captureLabel(block, LOCALIZED_LABELS.program, 'Any process'),
        localPort: captureLabel(block, LOCALIZED_LABELS.localPort, 'Any'),
        remotePort: captureLabel(block, LOCALIZED_LABELS.remotePort, 'Any'),
        localAddress: captureLabel(block, LOCALIZED_LABELS.localAddress, 'Any'),
        remoteAddress: captureLabel(block, LOCALIZED_LABELS.remoteAddress, 'Any'),
        description: captureLabel(block, LOCALIZED_LABELS.description, ''),
        timeCreated: null,
      } as SentinelFirewallRule;
    })
    .filter((rule): rule is SentinelFirewallRule => Boolean(rule));
};

const mapFirewallRecords = (records: any[]): SentinelFirewallRule[] =>
  records.map((rule: any) => ({
    name: rule?.DisplayName || rule?.Name || 'Unnamed Rule',
    direction: normalizeDirection(rule?.Direction ?? 'N/A'),
    action: normalizeAction(rule?.Action ?? 'N/A'),
    enabled: normalizeEnabled(rule?.Enabled ?? true),
    profile: rule?.Profile || 'Any',
    protocol: rule?.Protocol || 'Any',
    program: rule?.Program || 'Any',
    localPort: rule?.LocalPort || 'Any',
    remotePort: rule?.RemotePort || 'Any',
    localAddress: rule?.LocalAddress || 'Any',
    remoteAddress: rule?.RemoteAddress || 'Any',
    description: rule?.Description || '',
    timeCreated: rule?.TimeCreated || null,
  }));

const fetchRulesFromTrackedNames = async (): Promise<SentinelFirewallRule[]> => {
  const trackedNames = getSentinelRules();
  if (!trackedNames?.length) return [];

  const collected: SentinelFirewallRule[] = [];
  for (const rawName of trackedNames) {
    try {
      const safeName = sanitizeShellArg(rawName);
      if (!safeName) continue;
      const output = await runShellCmd(`netsh advfirewall firewall show rule name="${safeName}"`);
      collected.push(...parseNetshRuleBlocks(output));
    } catch (err) {
      console.warn('[Firewall] Unable to describe tracked rule', rawName, err);
    }
  }

  return dedupeFirewallRules(collected);
};

const dedupeFirewallRules = (rules: SentinelFirewallRule[]): SentinelFirewallRule[] => {
  const map = new Map<string, SentinelFirewallRule>();
  for (const rule of rules) {
    const key = `${rule.name}|${rule.direction}|${rule.localPort}|${rule.remoteAddress}`;
    if (!map.has(key)) {
      map.set(key, rule);
    }
  }
  return Array.from(map.values());
};

const fetchSentinelRulesViaPowerShell = async (): Promise<SentinelFirewallRule[]> => {
  try {
    const psCommand = `powershell -ExecutionPolicy Bypass -NoProfile -Command "
$ErrorActionPreference = 'Stop'
$rules = Show-NetFirewallRule -PolicyStore ActiveStore -Detailed |
  Where-Object { ($_.DisplayName -like '*Sentinel*') -or ($_.Name -like '*Sentinel*') } |
  Select-Object DisplayName, Name, Direction, Action, Enabled, Profile, Program,
                @{Name='Protocol';Expression={$_.PrimaryStatusInformation.Protocol}},
                @{Name='LocalPort';Expression={$_.PrimaryStatusInformation.LocalPort}},
                @{Name='RemotePort';Expression={$_.PrimaryStatusInformation.RemotePort}},
                @{Name='LocalAddress';Expression={$_.PrimaryStatusInformation.LocalAddress}},
                @{Name='RemoteAddress';Expression={$_.PrimaryStatusInformation.RemoteAddress}},
                Description, TimeCreated
$rules | ConvertTo-Json -Depth 4
"`;

    const output = await runShellCmd(psCommand, { timeout: 15000 });

    let parsed = JSON.parse(output || '[]');
    if (!Array.isArray(parsed)) {
      parsed = parsed ? [parsed] : [];
    }

    return mapFirewallRecords(parsed);
  } catch (err) {
    console.warn('[Firewall] Failed to fetch Sentinel-tagged rules via PowerShell:', err);
    return [];
  }
};

const FIREWALL_ENUM_CMD_OPTS = {
  encoding: 'utf-8' as BufferEncoding,
  stdio: ['ignore', 'pipe', 'pipe'] as [any, any, any],
  maxBuffer: 25 * 1024 * 1024,
  windowsHide: true,
};

export const aggregateFirewallRules = async (): Promise<FirewallAggregationReport> => {
  const aggregated: SentinelFirewallRule[] = [];
  const errors: string[] = [];
  let powershellRuleCount = 0;

  try {
    const psCommand = `powershell -ExecutionPolicy Bypass -NoProfile -Command "
$ErrorActionPreference = 'Stop'
Import-Module NetSecurity -ErrorAction SilentlyContinue | Out-Null
$rules = Get-NetFirewallRule -PolicyStore ActiveStore
$list = @()
foreach ($rule in $rules) {
  $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
  $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
  $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue

  $list += [PSCustomObject]@{
    DisplayName   = $rule.DisplayName
    Name          = $rule.Name
    Direction     = [int]$rule.Direction
    Action        = [int]$rule.Action
    Enabled       = [int]$rule.Enabled
    Profile       = $rule.Profile
    Program       = if ($appFilter -and $appFilter.Program) { $appFilter.Program } else { $rule.Program }
    Protocol      = if ($portFilter -and $portFilter.Protocol) { $portFilter.Protocol } else { $rule.Protocol }
    LocalPort     = if ($portFilter -and $portFilter.LocalPort) { ($portFilter.LocalPort -join ',') } else { 'Any' }
    RemotePort    = if ($portFilter -and $portFilter.RemotePort) { ($portFilter.RemotePort -join ',') } else { 'Any' }
    LocalAddress  = if ($addressFilter -and $addressFilter.LocalAddress) { ($addressFilter.LocalAddress -join ',') } else { 'Any' }
    RemoteAddress = if ($addressFilter -and $addressFilter.RemoteAddress) { ($addressFilter.RemoteAddress -join ',') } else { 'Any' }
    Description   = $rule.Description
    TimeCreated   = if ($rule.TimeCreated) { $rule.TimeCreated.ToString('o') } else { $null }
  }
}
$list | ConvertTo-Json -Depth 4
"`;
    const output = await runShellCmd(psCommand, { timeout: (FIREWALL_ENUM_CMD_OPTS as any).timeout || 30000, maxBuffer: (FIREWALL_ENUM_CMD_OPTS as any).maxBuffer || 20 * 1024 * 1024 });
    let parsed = JSON.parse(output || '[]');
    if (!Array.isArray(parsed)) {
      parsed = parsed ? [parsed] : [];
    }
    const mapped = mapFirewallRecords(parsed);
    powershellRuleCount = mapped.length;
    aggregated.push(...mapped);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    errors.push(`Get-NetFirewallRule failed: ${message}`);
    console.error('[Firewall] Get-NetFirewallRule failed, attempting netsh fallback:', err);
  }

  const sentinelRules = await fetchSentinelRulesViaPowerShell();
  const sentinelTagged = sentinelRules.length;
  if (sentinelTagged) {
    aggregated.push(...sentinelRules);
  }

  const trackedRules = await fetchRulesFromTrackedNames();
  const tracked = trackedRules.length;
  if (tracked) {
    aggregated.push(...trackedRules);
  }

  let fallbackUsed = false;
  let finalRules = aggregated;

  if (!finalRules.length) {
    try {
      const fallbackOutput = await runShellCmd('netsh advfirewall firewall show rule name=all', { timeout: (FIREWALL_ENUM_CMD_OPTS as any).timeout || 30000, maxBuffer: (FIREWALL_ENUM_CMD_OPTS as any).maxBuffer || 20 * 1024 * 1024 });
      finalRules = parseNetshRuleBlocks(fallbackOutput);
      fallbackUsed = true;
    } catch (fallbackErr) {
      const fallbackMessage = fallbackErr instanceof Error ? fallbackErr.message : String(fallbackErr);
      errors.push(`netsh fallback failed: ${fallbackMessage}`);
      console.error('[Firewall] netsh fallback failed:', fallbackErr);
      finalRules = [];
    }
  }

  const deduped = dedupeFirewallRules(finalRules);

  return {
    rules: deduped,
    meta: {
      totalCollected: deduped.length,
      sentinelTagged,
      tracked,
      fallbackUsed,
      powershellRuleCount,
      errors,
      generatedAt: Date.now(),
    },
  };
};

/**
 * SHIELD IPC HANDLERS
 * Provides system monitoring, process management, firewall control, and network inspection
 */

export const registerShieldHandlers = () => {
  /**
   * Get system-wide statistics (CPU, RAM, Disk usage)
   */
  ipcMain.handle('shield-get-system-stats', async () => {
    try {
      const os = require('os');
      const totalMemory = os.totalmem();
      const freeMemory = os.freemem();

      // Real CPU usage via os.cpus() — compare idle vs total across a 200ms sample
      let cpuPercent = 0;
      try {
        const cpus1 = os.cpus();
        await new Promise((r) => setTimeout(r, 200));
        const cpus2 = os.cpus();
        let idleDiff = 0, totalDiff = 0;
        for (let i = 0; i < cpus1.length; i++) {
          const t1 = cpus1[i].times, t2 = cpus2[i].times;
          const idle = t2.idle - t1.idle;
          const total = (t2.user - t1.user) + (t2.nice - t1.nice) + (t2.sys - t1.sys) + (t2.irq - t1.irq) + idle;
          idleDiff += idle;
          totalDiff += total;
        }
        cpuPercent = totalDiff > 0 ? Math.round(((totalDiff - idleDiff) / totalDiff) * 100) : 0;
      } catch { cpuPercent = -1; }

      // Real disk usage via PowerShell
      let diskPercent = -1;
      try {
        const diskOut = await runShellCmd(
          'powershell -NoProfile -Command "(Get-PSDrive C).Used / ((Get-PSDrive C).Used + (Get-PSDrive C).Free) * 100"',
          { timeout: 5000 }
        );
        diskPercent = Math.round(parseFloat(diskOut));
        if (isNaN(diskPercent)) diskPercent = -1;
      } catch { diskPercent = -1; }

      return {
        success: true,
        cpu: cpuPercent,
        ram: Math.round(((totalMemory - freeMemory) / totalMemory) * 100),
        disk: diskPercent,
      };
    } catch (err) {
      return { success: false, error: String(err) };
    }
  });

  /**
   * Block every connection for a process by PID
   */
  ipcMain.handle('shield-block-pid', async (_event, payload: unknown) => {
    try {
      const parsed = ShieldBlockPidRequestSchema.parse(payload);
      const result = await blockProcessByPid(parsed.pid, parsed.direction);
      if (result.success) {
        await addActivityLog('shield', 'block-pid', `Blocked PID ${parsed.pid} (${parsed.direction})`, 'success');
      }
      return result;
    } catch (err) {
      return { success: false, error: String(err) };
    }
  });

  /**
   * Get all processes with real CPU% via delta calculation
   */
  const _prevCpuSnapshot = new Map<number, { name: string; cpuMs: number; ts: number }>();
  const _numCores = os.cpus().length || 1;

  ipcMain.handle('shield-get-processes', async () => {
    try {
      const { getProcessKillRisk } = await import('../../shared/constants');
      const psScript = `$ErrorActionPreference='SilentlyContinue'
Get-Process | Where-Object { $_.Id -gt 0 } | ForEach-Object {
  $cpuMs=0; try{$cpuMs=[math]::Round($_.TotalProcessorTime.TotalMilliseconds)}catch{}
  $ramMB=0; try{$ramMB=[math]::Round($_.WorkingSet64/1MB,1)}catch{}
  $tc=0; try{$tc=$_.Threads.Count}catch{}
  $hc=0; try{$hc=$_.HandleCount}catch{}
  $pp=$null; try{if($_.Path){$pp=$_.Path}}catch{}
  $dd=$null; try{if($_.Description){$dd=$_.Description}}catch{}
  $cc=$null; try{if($_.Company){$cc=$_.Company}}catch{}
  $st=$null; try{if($_.StartTime){$st=$_.StartTime.ToString('o')}}catch{}
  [PSCustomObject]@{PID=$_.Id;Name=$_.ProcessName;CPUms=$cpuMs;RamMB=$ramMB;Threads=$tc;Handles=$hc;Path=$pp;Description=$dd;Company=$cc;StartTime=$st}
} | ConvertTo-Json -Compress`;
      const raw = await runPowerShellSafe(psScript, { timeout: 12000, maxBuffer: 10 * 1024 * 1024 });
      let parsed = JSON.parse((raw || '[]').trim());
      if (!Array.isArray(parsed)) parsed = parsed ? [parsed] : [];

      const now = Date.now();
      const processes = parsed.map((p: { PID: number; Name: string; CPUms: number; RamMB: number; Threads: number; Handles: number; Path: string | null; Description: string | null; Company: string | null; StartTime: string | null }) => {
        let cpuPercent = 0;
        const prev = _prevCpuSnapshot.get(p.PID);
        if (prev && prev.name === p.Name) {
          const timeDelta = now - prev.ts;
          const cpuDelta = p.CPUms - prev.cpuMs;
          if (timeDelta > 0 && cpuDelta >= 0) {
            cpuPercent = Math.min(100, (cpuDelta / timeDelta) * 100 / _numCores);
          }
        }
        _prevCpuSnapshot.set(p.PID, { name: p.Name, cpuMs: p.CPUms, ts: now });

        return {
          pid: p.PID,
          name: p.Name,
          cpu: Math.round(cpuPercent * 10) / 10,
          ram: p.RamMB,
          threads: p.Threads || 0,
          handles: p.Handles || 0,
          path: p.Path || undefined,
          description: p.Description || undefined,
          company: p.Company || undefined,
          startTime: p.StartTime || undefined,
          killRisk: getProcessKillRisk(p.Name, p.PID),
          trustScore: -1,
          connections: [],
        };
      }).filter((p: { pid: number }) => !isNaN(p.pid));

      // Purge stale entries from snapshot
      for (const [pid] of _prevCpuSnapshot) {
        if (!parsed.some((p: { PID: number }) => p.PID === pid)) _prevCpuSnapshot.delete(pid);
      }

      return processes;
    } catch (err) {
      console.error('Failed to get processes:', err);
      return [];
    }
  });

  /**
   * Get network traffic snapshot using modern PowerShell Get-NetTCPConnection cmdlet
   */
  ipcMain.handle('shield-get-network-traffic', async (_event, limit = 100) => {
    try {
      const connections = await getNetworkTrafficSnapshot(limit);
      console.log('[Network Traffic] Returning', connections.length, 'async connections');
      return connections;
    } catch (err: any) {
      console.error('[Network Traffic] Error:', err?.message || err);
      return [];
    }
  });

  ipcMain.handle('shield-get-full-network-audit', async (_event, limit = 1500) => {
    try {
      const audit = await getFullNetworkAudit(limit);
      console.log('[Network Audit] Returning', audit.length, 'connections');
      return { success: true, data: audit };
    } catch (err: any) {
      console.error('[Network Audit] Error:', err?.message || err);
      return { success: false, error: err?.message || 'Unknown error', data: [] };
    }
  });

  /**
   * Get firewall rules
   */
  ipcMain.handle('shield-get-firewall-rules', async () => {
    try {
      const aggregation = await aggregateFirewallRules();
      return { success: true, rules: aggregation.rules, meta: aggregation.meta };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { success: false, error: message, rules: [] };
    }
  });

  ipcMain.handle('shield-get-firewall-inventory', async () => {
    try {
      const aggregation = await aggregateFirewallRules();
      let blockedIps: IPBlockInfo[] = [];
      let blockedIpsError: string | null = null;

      try {
        blockedIps = await getBlockedIPs();
      } catch (blockedErr) {
        blockedIpsError = blockedErr instanceof Error ? blockedErr.message : String(blockedErr);
        console.error('[Firewall] Failed to collect blocked IPs:', blockedErr);
      }

      return {
        success: true,
        rules: aggregation.rules,
        blockedIps,
        meta: {
          ...aggregation.meta,
          blockedIpCount: blockedIps.length,
          blockedIpsError,
        },
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { success: false, error: message, rules: [], blockedIps: [] };
    }
  });

  /**
   * Block a specific port
   */
  ipcMain.handle('shield-block-port', async (_event, payload: unknown) => {
    try {
      const parsed = ShieldBlockPortRequestSchema.parse(payload);
      const result = await safeBlockPort(parsed.port, parsed.direction, parsed.protocol, parsed.options);
      if (result.success) {
        await addActivityLog(
          'shield',
          'block-port',
          `Blocked port ${parsed.port}/${parsed.protocol}`,
          'success'
        );
      }
      return result;
    } catch (err) {
      return { success: false, error: String(err) };
    }
  });

  /**
   * Block an IP subnet
   */
  ipcMain.handle('shield-block-subnet', async (_event, payload: unknown) => {
    try {
      const parsed = ShieldBlockSubnetRequestSchema.parse(payload);
      const targetMask = parsed.subnetMask ?? 32;
      const result = await blockSubnet(parsed.input, targetMask, parsed.direction);
      if (result.success) {
        await addActivityLog(
          'shield',
          'block-subnet',
          `Blocked subnet ${parsed.input}/${targetMask}`,
          'success'
        );
      }
      return result;
    } catch (err) {
      return { success: false, error: String(err) };
    }
  });

  /**
   * Undo last firewall action
   */
  ipcMain.handle('shield-undo-firewall', async () => {
    try {
      const result = await undoFirewallAction();
      if (result.success) {
        await addActivityLog('shield', 'undo', 'Undid firewall action', 'success');
      }
      return result;
    } catch (err) {
      return { success: false, error: String(err), message: 'Nothing to undo' };
    }
  });

  /**
   * Redo last firewall action
   */
  ipcMain.handle('shield-redo-firewall', async () => {
    try {
      const result = await redoFirewallAction();
      if (result.success) {
        await addActivityLog('shield', 'redo', 'Redid firewall action', 'success');
      }
      return result;
    } catch (err) {
      return { success: false, error: String(err), message: 'Nothing to redo' };
    }
  });

  /**
   * Get undo/redo state
   */
  ipcMain.handle('shield-get-undo-redo-state', async () => {
    try {
      return await getUndoRedoStatus();
    } catch (err) {
      return { canUndo: false, canRedo: false, undoCount: 0, redoCount: 0 };
    }
  });

  /**
   * Kill all connections for a process
   */
  ipcMain.handle('shield-kill-process', async (_event, pid: number, processName: string) => {
    const { getProcessKillRisk } = await import('../../shared/constants');
    const risk = getProcessKillRisk(processName || '', pid);
    if (risk === 'forbidden') {
      return {
        success: false,
        error: `Cannot terminate ${processName || 'process'} (PID ${pid}) — system-critical process. Terminating would cause a Blue Screen of Death or system hang.`,
      };
    }
    try {
      const result = await killProcessService(pid, processName || `PID ${pid}`);
      if (result.success) {
        await addActivityLog('shield', 'kill-process', `Killed ${processName || 'process'} (PID ${pid})`, risk === 'caution' ? 'warning' : 'info');
      }
      return result;
    } catch (err) {
      return { success: false, error: String(err) };
    }
  });

  /**
   * Delete a firewall rule — escape special chars, verify removal
   */
  ipcMain.handle('shield-delete-firewall-rule', async (_event, ruleName: string) => {
    if (!ruleName || typeof ruleName !== 'string') {
      return { success: false, error: 'Invalid rule name' };
    }
    try {
      // Sanitize for shell injection prevention
      const safeName = sanitizeShellArg(ruleName);
      if (!safeName) return { success: false, error: 'Rule name contains invalid characters' };

      // Try PowerShell Remove-NetFirewallRule first (handles special chars better)
      try {
        await runShellCmd(
          `powershell -NoProfile -ExecutionPolicy Bypass -Command "Remove-NetFirewallRule -DisplayName '${safeName}' -ErrorAction Stop"`,
          { timeout: 10000 }
        );
      } catch {
        // Fallback: netsh
        await runShellCmd(`netsh advfirewall firewall delete rule name="${safeName}"`, { timeout: 10000 });
      }

      // Verify deletion
      try {
        const check = await runShellCmd(
          `powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-NetFirewallRule -DisplayName '${safeName}' -ErrorAction SilentlyContinue) -ne $null"`,
          { timeout: 5000 }
        );
        if (check === 'True') {
          return { success: false, error: `Rule "${ruleName}" still exists after delete attempt` };
        }
      } catch { /* verification failed, assume success */ }

      await addActivityLog('shield', 'delete-rule', `Deleted firewall rule: ${ruleName}`, 'info');
      return { success: true, message: `Deleted rule: ${ruleName}` };
    } catch (err: any) {
      const msg = err?.stderr?.toString() || err?.message || String(err);
      return { success: false, error: `Failed to delete "${ruleName}": ${msg}` };
    }
  });

  /**
   * Test internet connectivity
   */
  ipcMain.handle('shield-test-internet', async () => {
    try {
      const result = await testInternet();
      return result;
    } catch (err) {
      return { success: false, connected: false, latency: -1 };
    }
  });

  /**
   * Get network diagnostics using PowerShell Get-NetTCPConnection
   */
  ipcMain.handle('shield-get-network-diagnostics', async () => {
    try {
      console.log('[Network Diagnostics] Starting comprehensive diagnostics...');

      const powershellScript = `
$ErrorActionPreference = 'Stop'

$result = @{
    Services = @()
    NetworkStatistics = @()
}

# Service Status Check
try {
    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Sentinel*" -or $_.DisplayName -like "*Sentinel*" }
    
    if ($services) {
        foreach ($service in $services) {
            $result.Services += @{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status.ToString()
            }
        }
    }
} catch {
    $result.Services = @(@{
        Error = "Failed to retrieve service information: $($_.Exception.Message)"
    })
}

# Network Connection Analysis using Get-NetTCPConnection
try {
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -notin @('0.0.0.0','127.0.0.1','::') } |
        Select-Object -First 100
    
    if ($connections) {
        foreach ($conn in $connections) {
            try {
                $processName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            } catch {
                $processName = "Unknown"
            }
            
            $result.NetworkStatistics += @{
                Protocol = "TCP"
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                State = $conn.State
                PID = $conn.OwningProcess
                ProcessName = $processName
            }
        }
    }
} catch {
    $result.NetworkStatistics = @(@{
        Error = "Failed to retrieve network statistics: $($_.Exception.Message)"
    })
}

$result | ConvertTo-Json -Depth 10
`;

      const { spawn } = require('child_process');

      return new Promise((resolve) => {
        const child = spawn('powershell.exe', [
          '-NoProfile',
          '-ExecutionPolicy', 'Bypass',
          '-Command', powershellScript
        ]);

        let stdout = '';
        let stderr = '';

        child.stdout.on('data', (data) => {
          stdout += data.toString();
        });

        child.stderr.on('data', (data) => {
          stderr += data.toString();
        });

        child.on('close', (code) => {
          if (code !== 0) {
            console.error('[Network Diagnostics] PowerShell exited with code:', code);
            console.error('[Network Diagnostics] stderr:', stderr);
            resolve({ success: false, error: `PowerShell exited with code ${code}` });
            return;
          }

          try {
            const diagnostics = JSON.parse(stdout.trim());
            console.log('[Network Diagnostics] Services found:', diagnostics.Services?.length || 0);
            console.log('[Network Diagnostics] Connections found:', diagnostics.NetworkStatistics?.length || 0);

            resolve({
              success: true,
              data: diagnostics,
            });
          } catch (parseErr: any) {
            console.error('[Network Diagnostics] JSON parse error:', parseErr.message);
            resolve({ success: false, error: parseErr.message });
          }
        });

        child.on('error', (err) => {
          console.error('[Network Diagnostics] Spawn error:', err);
          resolve({ success: false, error: err.message });
        });
      });
    } catch (err: any) {
      console.error('[Network Diagnostics] Handler error:', err);
      return {
        success: false,
        error: err.message || 'Unknown error',
      };
    }
  });

  /**
   * Get IP geolocation and metadata
   */
  ipcMain.handle('shield-get-ip-metadata', async (_event, ip: string) => {
    try {
      // DSGVO Art. 5 — no PII in logs
      
      // Check if private/local IP
      const isPrivate = 
        ip.startsWith('192.168.') ||
        ip.startsWith('10.') ||
        ip.startsWith('172.16.') || ip.startsWith('172.17.') ||
        ip.startsWith('172.18.') || ip.startsWith('172.19.') ||
        ip.startsWith('172.20.') || ip.startsWith('172.21.') ||
        ip.startsWith('172.22.') || ip.startsWith('172.23.') ||
        ip.startsWith('172.24.') || ip.startsWith('172.25.') ||
        ip.startsWith('172.26.') || ip.startsWith('172.27.') ||
        ip.startsWith('172.28.') || ip.startsWith('172.29.') ||
        ip.startsWith('172.30.') || ip.startsWith('172.31.') ||
        ip.startsWith('127.') ||
        ip.startsWith('169.254.') ||
        ip === 'localhost' ||
        ip === '::1';
      
      if (isPrivate) {
        // Local IP — resolve via ARP/DNS locally
        
        let hostname = 'Unknown';
        let macAddress = 'Unknown';
        let vendor = 'Unknown';
        let deviceType = 'Unknown';
        
        try {
          // Try to resolve hostname
          try {
            const safeIp = validateIPForShell(ip);
            if (!safeIp) throw new Error('Invalid IP for DNS resolution');
            const hostnameCmd = `powershell -NoProfile -Command "Resolve-DnsName -Name ${safeIp} -Type PTR -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost"`;
            hostname = await runShellCmd(hostnameCmd, { timeout: 3000 });
            if (!hostname) hostname = 'Unknown';
          } catch {
            hostname = 'Unknown';
          }
          
          // Get MAC address from ARP table
          try {
            const safeArpIp = validateIPForShell(ip);
            if (!safeArpIp) throw new Error('Invalid IP for ARP lookup');
            const arpCmd = `arp -a ${safeArpIp}`;
            const arpOutput = await runShellCmd(arpCmd, { timeout: 2000 });
            const macMatch = arpOutput.match(/([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/);
            if (macMatch) {
              macAddress = macMatch[0].toUpperCase().replace(/-/g, ':');
              
              // Vendor lookup by MAC prefix
              const vendorMap: Record<string, string> = {
                '00:50:56': 'VMware',
                '00:0C:29': 'VMware',
                '00:16:E3': 'Apple',
                '3C:07:54': 'Apple',
                '4C:57:CA': 'Apple',
                '00:24:8C': 'Samsung',
                'AC:5F:3E': 'Samsung',
                '00:1A:4D': 'Dell',
                '00:1E:4F': 'HP',
                '00:04:23': 'Intel',
                '00:E0:4C': 'Realtek',
                '52:54:00': 'QEMU/KVM',
                '08:00:27': 'VirtualBox',
                '00:15:5D': 'Microsoft Hyper-V',
                '00:03:FF': 'Microsoft',
                '00:50:F2': 'Microsoft'
              };
              
              for (const [prefix, vendorName] of Object.entries(vendorMap)) {
                if (macAddress.startsWith(prefix)) {
                  vendor = vendorName;
                  break;
                }
              }
            }
          } catch {
            macAddress = 'Unknown';
          }
          
          // Determine device type
          const hostLower = hostname.toLowerCase();
          if (hostLower.includes('router') || hostLower.includes('gateway')) {
            deviceType = 'Router/Gateway';
          } else if (hostLower.includes('switch')) {
            deviceType = 'Network Switch';
          } else if (hostLower.includes('printer')) {
            deviceType = 'Printer';
          } else if (hostLower.includes('phone') || hostLower.includes('mobile')) {
            deviceType = 'Mobile Device';
          } else if (hostLower.includes('tablet') || hostLower.includes('ipad')) {
            deviceType = 'Tablet';
          } else if (vendor.toLowerCase().includes('vmware') || vendor.toLowerCase().includes('virtualbox')) {
            deviceType = 'Virtual Machine';
          } else if (vendor === 'Apple' || vendor === 'Samsung') {
            deviceType = 'Mobile/Computer';
          } else {
            deviceType = 'Computer/Device';
          }
          
        } catch (err: any) {
          console.error('[IP Metadata] Error gathering local info:', err);
        }
        
        return {
          success: true,
          data: {
            ip: ip,
            type: 'local',
            country: 'Local Network',
            countryCode: 'LAN',
            region: 'Private Network',
            city: 'Local',
            zip: 'N/A',
            isp: 'Private Network',
            org: hostname !== 'Unknown' ? hostname : 'Local Device',
            as: macAddress !== 'Unknown' ? `MAC: ${macAddress}` : 'N/A',
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            lat: 0,
            lon: 0,
            mobile: deviceType.includes('Mobile') || deviceType.includes('Tablet'),
            proxy: false,
            hosting: false,
            reputation: `${vendor !== 'Unknown' ? vendor : 'Unknown Vendor'} - ${deviceType}`,
            riskLevel: 'safe',
            hostname: hostname,
            macAddress: macAddress,
            vendor: vendor,
            deviceType: deviceType
          }
        };
      }

      // EXTERNAL IP — gated behind DSGVO-compliant user toggle (Art. 6 DSGVO)
      if (!isExternalIpLookupAllowed()) {
        return { success: false, error: 'External IP lookups disabled (Datenschutz). Enable in Settings → Datenschutz.' };
      }

      // Check local cache first (saves ipinfo.io free-tier credits)
      const cached = getCachedIpMetadata(ip);
      if (cached) {
        return { success: true, data: cached, cached: true };
      }
      
      const https = require('https');
      const { getApiKey } = await import('../services/shared/envLoader');
      const ipinfoToken = getApiKey('IPINFO_TOKEN');
      const url = ipinfoToken ? `https://ipinfo.io/${ip}/json?token=${ipinfoToken}` : `https://ipinfo.io/${ip}/json`;
      
      return new Promise((resolve) => {
        const req = https.get(url, { timeout: 8000 }, (res: any) => {
          let data = '';
          
          res.on('data', (chunk: any) => {
            data += chunk;
          });
          
          res.on('end', () => {
            try {
              const parsed = JSON.parse(data);
              // DSGVO Art. 5 — no PII in production logs
              
              if (parsed.bogon) {
                resolve({ success: false, error: 'Private/Reserved IP' });
                return;
              }
              
              if (parsed.error) {
                resolve({ success: false, error: parsed.error });
                return;
              }
              
              const countryCode = parsed.country || '??';
              const org = parsed.org || 'Unknown';
              const orgLower = org.toLowerCase();
              
              let riskLevel = 'low';
              let reputation = 'Clean';
              
              const isHosting = orgLower.includes('hosting') || orgLower.includes('cloud') ||
                orgLower.includes('vpn') || orgLower.includes('proxy') ||
                orgLower.includes('datacenter') || orgLower.includes('amazon') ||
                orgLower.includes('google') || orgLower.includes('microsoft');
              
              if (isHosting) {
                riskLevel = 'medium';
                reputation = 'Hosting/Cloud Provider';
              }
              
              const highRisk = ['KP', 'IR', 'SY', 'CU'];
              if (highRisk.includes(countryCode)) {
                riskLevel = 'high';
                reputation = 'High Risk Region';
              }
              
              const [lat, lon] = parsed.loc ? parsed.loc.split(',').map(Number) : [0, 0];
              const asMatch = org.match(/AS(\d+)/i);
              const asNumber = asMatch ? asMatch[0] : 'N/A';
              
              const resultData = {
                  ip: parsed.ip || ip,
                  type: 'external',
                  country: parsed.country || '??',
                  countryCode: countryCode,
                  region: parsed.region || 'Unknown',
                  city: parsed.city || 'Unknown',
                  zip: parsed.postal || 'N/A',
                  isp: org,
                  org: org,
                  as: asNumber,
                  timezone: parsed.timezone || 'UTC',
                  lat: lat,
                  lon: lon,
                  mobile: false,
                  proxy: isHosting,
                  hosting: isHosting,
                  reputation: reputation,
                  riskLevel: riskLevel,
                  raw: parsed
              };
              // Cache result to save ipinfo.io free-tier credits
              setCachedIpMetadata(ip, resultData);
              resolve({ success: true, data: resultData });
              
            } catch (err: any) {
              console.error('[IP Metadata] Parse error:', err);
              resolve({ success: false, error: 'Invalid response' });
            }
          });
        });
        
        req.on('timeout', () => {
          req.destroy();
          resolve({ success: false, error: 'Request timeout' });
        });
        
        req.on('error', (err: any) => {
          console.error('[IP Metadata] Network error:', err.message);
          resolve({ success: false, error: err.message });
        });
      });
      
    } catch (error: any) {
      console.error('[IP Metadata] Outer catch error:', error);
      return {
        success: false,
        error: error.message || 'Unknown error'
      };
    }
  });
};
