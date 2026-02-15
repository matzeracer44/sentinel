import { exec, execFile } from 'child_process';
import { promisify } from 'util';
import { addActivityLog } from './activityLog';
import * as path from 'path';
import * as fs from 'fs';
import { isExternalIpLookupAllowed } from './sentinelConfig';
import { validateIPForShell, sanitizeShellArg } from '../../shared/utils';

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

async function runCmd(cmd: string, opts: { timeout?: number; maxBuffer?: number; windowsHide?: boolean } = {}): Promise<string> {
  const { stdout } = await execAsync(cmd, { encoding: 'utf8', windowsHide: true, timeout: 10000, ...opts });
  return (stdout || '').trim();
}

async function runPS(script: string, timeout = 15000): Promise<string> {
  const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], {
    timeout, windowsHide: true, encoding: 'utf8', maxBuffer: 50 * 1024 * 1024,
  });
  return (stdout || '').trim();
}

export interface ProcessInfo {
  pid: number;
  name: string;
  path: string;
  memoryMB: number;
  cpuPercent: number;
  isBloatware: boolean;
}

export interface IPBlockInfo {
  ip: string;
  reason: string;
  blocked: boolean;
  timestamp: string;
}

export interface FirewallRule {
  name: string;
  direction: 'Inbound' | 'Outbound';
  action: 'Allow' | 'Block';
  protocol: string;
  enabled: boolean;
}

export interface PortInfo {
  port: number;
  protocol: string;
  state: 'LISTENING' | 'ESTABLISHED' | 'CLOSED';
  process: string;
  pid?: number;
}

export interface NetworkConnection {
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
  pid?: number;
  process?: string;
  metadata?: IPMetadataResult | null;
}

// === PROCESS MANAGEMENT ===

export async function getProcessesByMemory(limit: number = 20): Promise<ProcessInfo[]> {
	try {
		try {
			const psScript = `Get-CimInstance Win32_Process|Where-Object{$_.Name -ne 'Idle'}|Sort-Object -Property @{Expression={[long]$_.WorkingSetSize}} -Descending|Select-Object -First ${limit} @{n='pid';e={$_.ProcessId}},@{n='name';e={$_.Name}},@{n='path';e={$_.ExecutablePath}},@{n='memory';e={[math]::Round($_.WorkingSetSize/1MB)}}|ConvertTo-Json -Depth 2`;
			const result = await runPS(psScript, 10000);
			const processes = JSON.parse(result);
			if (processes && (Array.isArray(processes) || typeof processes === 'object')) {
				const arr = Array.isArray(processes) ? processes : [processes];
				return arr.map((p: any) => ({
					pid: Number(p.pid) || 0,
					name: (p.name || '').toString(),
					path: p.path || 'N/A',
					memoryMB: Number(p.memory) || 0,
					cpuPercent: 0,
					isBloatware: isBloatwareProcess((p.name || '').toString()),
				})).slice(0, limit);
			}
		} catch (psErr) {
			console.warn('PowerShell process list failed, falling back to tasklist:', psErr?.message || psErr);
		}

		// Fallback: use tasklist CSV parsing (works reliably without complex PowerShell)
		try {
			const out = await runCmd('tasklist /FO CSV /NH', { timeout: 8000 });
			const lines = out.split('\n').map(l => l.trim()).filter(Boolean);
			const items: Array<{ pid: number; name: string; memoryMB: number }> = [];
			for (const ln of lines) {
				// CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
				const cols = ln.split('","').map(s => s.replace(/^"+|"+$/g, ''));
				if (cols.length >= 5) {
					const name = cols[0];
					const pid = Number(cols[1]) || 0;
					const memStr = cols[4].replace(/[\s,Kk]/g, '').replace(',', '');
					const memKB = Number(memStr) || 0;
					items.push({ pid, name, memoryMB: Math.round(memKB / 1024) });
				}
			}
			items.sort((a, b) => b.memoryMB - a.memoryMB);
			return items.slice(0, limit).map(i => ({
				pid: i.pid,
				name: i.name,
				path: 'N/A',
				memoryMB: i.memoryMB,
				cpuPercent: 0,
				isBloatware: isBloatwareProcess(i.name),
			}));
		} catch (taskErr) {
			console.warn('tasklist fallback failed:', taskErr?.message || taskErr);
		}

		return [];
	} catch (error: any) {
		console.error('Error getting processes:', error?.message || error);
		addActivityLog('Shield', 'Get Processes', 'Failed to retrieve process list', 'error');
		return [];
	}
}

async function ensureProcessNotRunning(pid: number): Promise<boolean> {
  try {
    await runPS(`if(Get-Process -Id ${pid} -EA SilentlyContinue){throw 'alive'}`, 5000);
    return true;
  } catch (err: any) {
    return err?.message?.includes('alive') ? false : true;
  }
}

async function stopProcessForcefully(pid: number): Promise<void> {
  const commands = [
    `taskkill /F /PID ${pid}`,
  ];
  const psCommands = [
    `if(Get-Process -Id ${pid} -EA SilentlyContinue){Stop-Process -Id ${pid} -Force -EA Stop}`,
    `try{$p=Get-CimInstance Win32_Process -Filter 'ProcessId = ${pid}';if($p){$p|Remove-CimInstance -EA Stop}}catch{}`,
  ];

  // Try taskkill first (fastest)
  for (const cmd of commands) {
    try {
      await runCmd(cmd, { timeout: 5000 });
      if (await ensureProcessNotRunning(pid)) return;
    } catch { /* next strategy */ }
  }
  // Then PS strategies
  for (const ps of psCommands) {
    try {
      await runPS(ps, 5000);
      if (await ensureProcessNotRunning(pid)) return;
    } catch { /* next strategy */ }
  }

  if (!(await ensureProcessNotRunning(pid))) {
    throw new Error(`Process ${pid} resisted termination`);
  }
}

export async function killProcess(pid: number, processName: string): Promise<{ success: boolean; message: string }> {
  try {
    await stopProcessForcefully(pid);
    addActivityLog('Shield', 'Kill Process', `Terminated process: ${processName} (PID: ${pid})`, 'success');
    return { success: true, message: `Killed process ${processName}` };
  } catch (error: any) {
    const message = `Failed to kill process: ${error.message}`;
    addActivityLog('Shield', 'Kill Process', message, 'error');
    return { success: false, message };
  }
}

// === IP BLOCKING ===

export async function getBlockedIPs(): Promise<IPBlockInfo[]> {
  try {
    const hostsFile = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
    const content = await runCmd(`type "${hostsFile}"`);
    
    const blockedIPs: IPBlockInfo[] = [];
    const lines = content.split('\n');
    
    lines.forEach((line: string) => {
      if (line.startsWith('127.0.0.1') || line.startsWith('0.0.0.0')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          blockedIPs.push({
            ip: parts[1],
            reason: 'Manual block (via hosts file)',
            blocked: true,
            timestamp: new Date().toISOString()
          });
        }
      }
    });
    
    return blockedIPs;
  } catch (error: any) {
    console.error('Error getting blocked IPs:', error.message);
    return [];
  }
}

export async function blockIP(ip: string, reason: string): Promise<{ success: boolean; message: string }> {
  try {
    const safeIp = validateIPForShell(ip);
    if (!safeIp) return { success: false, message: 'Invalid IP address format' };
    const safeReason = sanitizeShellArg(reason).slice(0, 200);
    // Add to hosts file
    await runPS(`Add-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Value '127.0.0.1 ${safeIp}' -Force`);

    // Also create a /24 firewall rule
    try {
      // compute /24 if IPv4
      const octets = ip.split('.');
      if (octets.length === 4) {
        const subnet = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
        await blockSubnet(subnet, `Sentinel Block SUBNET ${subnet}`, 'both');
      }
    } catch (e) {
      // Non-critical: log but continue
      addActivityLog('Shield', 'Block IP', `Failed to add firewall subnet rule for ${ip}: ${String(e)}`, 'warning');
    }
    
    addActivityLog('Shield', 'Block IP', `Blocked IP: ${safeIp} - Reason: ${safeReason}`, 'success');
    return { success: true, message: `Blocked IP ${safeIp} and /24 subnet` };
  } catch (error: any) {
    const message = `Failed to block IP: ${error.message}`;
    addActivityLog('Shield', 'Block IP', message, 'error');
    return { success: false, message };
  }
}

export async function blockSubnet(
  subnetOrIp: string,
  ruleName?: string,
  direction: 'in' | 'out' | 'both' = 'both'
): Promise<{ success: boolean; message: string }> {
  try {
    // If an IP was provided, convert to /24
    let subnet = subnetOrIp;
    if (!subnet.includes('/')) {
      const octets = subnetOrIp.split('.');
      if (octets.length !== 4) {
        return { success: false, message: 'Invalid IPv4 address for /24 conversion' };
      }
      subnet = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
    }

    const safeSubnet = validateIPForShell(subnet);
    if (!safeSubnet) return { success: false, message: 'Invalid subnet/IP format' };

    const baseName = sanitizeShellArg(ruleName || `Sentinel Block SUBNET ${safeSubnet}`).slice(0, 200);
    if (!baseName) return { success: false, message: 'Invalid rule name' };

    if (direction === 'in' || direction === 'both') {
      const inName = `${baseName} - IN`;
      await runCmd(`netsh advfirewall firewall add rule name="${inName}" dir=in action=block remoteip=${safeSubnet} enable=yes`);
      addSentinelRule(inName);
    }
    if (direction === 'out' || direction === 'both') {
      const outName = `${baseName} - OUT`;
      await runCmd(`netsh advfirewall firewall add rule name="${outName}" dir=out action=block remoteip=${safeSubnet} enable=yes`);
      addSentinelRule(outName);
    }

    addActivityLog('Shield', 'Block Subnet', `Blocked subnet: ${safeSubnet} (${direction})`, 'success');
    return { success: true, message: `Created firewall rule(s) for ${safeSubnet}` };
  } catch (error: any) {
    const message = `Failed to create subnet firewall rule: ${error.message}`;
    addActivityLog('Shield', 'Block Subnet', message, 'error');
    return { success: false, message };
  }
}

export async function blockPort(
  port: number,
  protocol: 'TCP' | 'UDP' | 'Any' = 'TCP',
  ruleName?: string,
  direction: 'in' | 'out' | 'both' = 'both'
): Promise<{ success: boolean; message: string }> {
  try {
    const proto = protocol === 'Any' ? 'any' : protocol.toLowerCase();
    const baseName = ruleName || `Sentinel Block Port ${port}/${protocol}`;

    if (direction === 'in' || direction === 'both') {
      const inName = `${baseName} - IN`;
      await runCmd(`netsh advfirewall firewall add rule name="${inName}" dir=in action=block protocol=${proto} localport=${port} enable=yes`);
      addSentinelRule(inName);
    }
    if (direction === 'out' || direction === 'both') {
      const outName = `${baseName} - OUT`;
      await runCmd(`netsh advfirewall firewall add rule name="${outName}" dir=out action=block protocol=${proto} localport=${port} enable=yes`);
      addSentinelRule(outName);
    }

    addActivityLog('Shield', 'Block Port', `Blocked ${protocol} port: ${port} (${direction})`, 'success');
    return { success: true, message: `Created firewall rule(s) for port ${port}` };
  } catch (error: any) {
    const message = `Failed to create port firewall rule: ${error.message}`;
    addActivityLog('Shield', 'Block Port', message, 'error');
    return { success: false, message };
  }
}

export async function blockIPRange(
  startIP: string,
  endIP: string,
  ruleName?: string,
  direction: 'in' | 'out' | 'both' = 'both'
): Promise<{ success: boolean; message: string }> {
  try {
    const safeStart = validateIPForShell(startIP);
    const safeEnd = validateIPForShell(endIP);
    if (!safeStart || !safeEnd) return { success: false, message: 'Invalid IP address format in range' };

    // netsh supports remoteip=start-end
    const baseName = sanitizeShellArg(ruleName || `Sentinel Block Range ${safeStart}-${safeEnd}`).slice(0, 200);
    if (!baseName) return { success: false, message: 'Invalid rule name' };

    if (direction === 'in' || direction === 'both') {
      const inName = `${baseName} - IN`;
      await runCmd(`netsh advfirewall firewall add rule name="${inName}" dir=in action=block remoteip=${safeStart}-${safeEnd} enable=yes`);
      addSentinelRule(inName);
    }
    if (direction === 'out' || direction === 'both') {
      const outName = `${baseName} - OUT`;
      await runCmd(`netsh advfirewall firewall add rule name="${outName}" dir=out action=block remoteip=${safeStart}-${safeEnd} enable=yes`);
      addSentinelRule(outName);
    }

    addActivityLog('Shield', 'Block IP Range', `Blocked range: ${safeStart} - ${safeEnd}`, 'success');
    return { success: true, message: `Created firewall rule(s) for range ${safeStart}-${safeEnd}` };
  } catch (error: any) {
    const message = `Failed to create IP range firewall rule: ${error.message}`;
    addActivityLog('Shield', 'Block IP Range', message, 'error');
    return { success: false, message };
  }
}

// === FIREWALL RULES ===

export async function getFirewallRules(protocol: string = 'TCP'): Promise<FirewallRule[]> {
  try {
    // Batch fetch: rules + app filters in one script, joined by InstanceID
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$appMap = @{}
Get-NetFirewallApplicationFilter | ForEach-Object {
  if ($_.Program -and $_.Program -ne 'Any') { $appMap[$_.InstanceID] = $_.Program }
}
Get-NetFirewallRule | ForEach-Object {
  $dir = if($_.Direction -eq 1){'Inbound'}elseif($_.Direction -eq 2){'Outbound'}else{$_.Direction.ToString()}
  $act = if($_.Action -eq 2){'Allow'}elseif($_.Action -eq 4){'Block'}else{$_.Action.ToString()}
  [PSCustomObject]@{
    name = $_.DisplayName
    direction = $dir
    action = $act
    enabled = ($_.Enabled -eq 1)
    profile = $_.Profile.ToString()
    description = $_.Description
    program = if($appMap.ContainsKey($_.InstanceID)){$appMap[$_.InstanceID]}else{''}
  }
} | ConvertTo-Json -Depth 2 -Compress
`;
    const output = await runPS(psScript.trim(), 45000);
    if (!output) return [];
    const rules = JSON.parse(output);
    
    return Array.isArray(rules) ? rules : rules ? [rules] : [];
  } catch (error: any) {
    console.error('Error getting firewall rules:', error.message);
    return [];
  }
}

export async function createFirewallRule(
  ruleName: string,
  protocol: string,
  port: number,
  action: 'Allow' | 'Block'
): Promise<{ success: boolean; message: string }> {
  try {
    const command = `netsh advfirewall firewall add rule name="${ruleName}" dir=in action=${action.toLowerCase()} protocol=${protocol.toUpperCase()} localport=${port}`;
    await runCmd(command);
    
    addActivityLog('Shield', 'Create Firewall Rule', `Created rule: ${ruleName} (${protocol}:${port})`, 'success');

    // Track it persistently
    addSentinelRule(ruleName);

    return { success: true, message: `Created firewall rule ${ruleName}` };
  } catch (error: any) {
    const message = `Failed to create firewall rule: ${error.message}`;
    addActivityLog('Shield', 'Create Firewall Rule', message, 'error');
    return { success: false, message };
  }
}

export async function deleteFirewallRule(ruleName: string): Promise<{ success: boolean; message: string }> {
  try {
    const command = `netsh advfirewall firewall delete rule name="${ruleName}"`;
    await runCmd(command);
    
    addActivityLog('Shield', 'Delete Firewall Rule', `Deleted rule: ${ruleName}`, 'success');

    // Remove from tracking if present
    removeSentinelRule(ruleName);

    return { success: true, message: `Deleted firewall rule ${ruleName}` };
  } catch (error: any) {
    const message = `Failed to delete firewall rule: ${error.message}`;
    addActivityLog('Shield', 'Delete Firewall Rule', message, 'error');
    return { success: false, message };
  }
}

export async function setFirewallRuleEnabled(ruleName: string, enabled: boolean): Promise<{ success: boolean; message: string }> {
  try {
    if (!ruleName) return { success: false, message: 'Rule name required' };
    // Escape double quotes in name
    const nameEsc = ruleName.replace(/"/g, '\\"');
    const cmd = `netsh advfirewall firewall set rule name="${nameEsc}" new enable=${enabled ? 'yes' : 'no'}`;
    await runCmd(cmd);
    addActivityLog('Shield', 'Set Firewall Rule Enabled', `Rule "${ruleName}" set to ${enabled ? 'enabled' : 'disabled'}`, 'success');
    return { success: true, message: `Rule ${ruleName} ${enabled ? 'enabled' : 'disabled'}` };
  } catch (error: any) {
    const message = `Failed to set rule enabled state: ${error.message}`;
    addActivityLog('Shield', 'Set Firewall Rule Enabled', message, 'error');
    return { success: false, message };
  }
}

export async function updateFirewallRule(
  ruleName: string,
  options: {
    action?: 'Allow' | 'Block';
    protocol?: string;
    localPort?: string | number;
    remoteIP?: string;
    direction?: 'in' | 'out' | 'both';
  }
): Promise<{ success: boolean; message: string }> {
  try {
    if (!ruleName) return { success: false, message: 'Rule name required' };
    const nameEsc = ruleName.replace(/"/g, '\\"');
    const parts: string[] = [];

    if (options.action) parts.push(`action=${options.action.toLowerCase()}`);
    if (options.protocol) parts.push(`protocol=${options.protocol}`);
    if (options.localPort !== undefined) parts.push(`localport=${options.localPort}`);
    if (options.remoteIP) parts.push(`remoteip=${options.remoteIP}`);
    // netsh uses dir= in/out when adding; for set, sometimes 'dir' not changeable; include direction as part of name creation if needed

    if (parts.length === 0) return { success: false, message: 'No update options provided' };

    const cmd = `netsh advfirewall firewall set rule name="${nameEsc}" new ${parts.join(' ')}`;
    await runCmd(cmd);

    addActivityLog('Shield', 'Update Firewall Rule', `Updated rule "${ruleName}" with ${JSON.stringify(options)}`, 'success');
    return { success: true, message: `Updated rule ${ruleName}` };
  } catch (error: any) {
    const message = `Failed to update firewall rule: ${error.message}`;
    addActivityLog('Shield', 'Update Firewall Rule', message, 'error');
    return { success: false, message };
  }
}

// === PORT SCANNING ===

export async function scanOpenPorts(): Promise<PortInfo[]> {
  try {
    const psScript = `Get-NetTCPConnection -State Listen|Select-Object @{n='port';e='LocalPort'},@{n='process';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}},@{n='pid';e='OwningProcess'}|ConvertTo-Json`;
    const result = await runPS(psScript, 10000);
    const ports = JSON.parse(result);
    
    return Array.isArray(ports)
      ? ports.map((p: any) => ({
          port: p.port,
          protocol: 'TCP',
          state: 'LISTENING',
          process: p.process || 'Unknown',
          pid: p.pid
        }))
      : [];
  } catch (error: any) {
    console.error('Error scanning ports:', error.message);
    return [];
  }
}

// === HELPERS ===

function isBloatwareProcess(processName: string): boolean {
  const bloatware = [
    'onedrive', 'xbox', 'xboxgamebar', 'teams', 'microsoftedge',
    'spotify', 'discord', 'skype', 'ccleaner', 'pcoptimizer'
  ];
  return bloatware.some(bw => processName.toLowerCase().includes(bw));
}

export async function getSecurityOverview(): Promise<{
  processCount: number;
  blockedIPs: number;
  activeRules: number;
  openPorts: number;
  threatLevel: 'Low' | 'Medium' | 'High';
}> {
  try {
    const processes = await getProcessesByMemory(100);
    const blockedIPs = await getBlockedIPs();
    const rules = await getFirewallRules();
    const ports = await scanOpenPorts();

    const bloatwareCount = processes.filter(p => p.isBloatware).length;
    let threatLevel: 'Low' | 'Medium' | 'High' = 'Low';
    if (bloatwareCount > 5) {
      threatLevel = 'High';
    } else if (bloatwareCount > 2) {
      threatLevel = 'Medium';
    }

    return {
      processCount: processes.length,
      blockedIPs: blockedIPs.length,
      activeRules: rules.length,
      openPorts: ports.length,
      threatLevel
    };
  } catch (error: any) {
    console.error('Error getting security overview:', error.message);
    return {
      processCount: 0,
      blockedIPs: 0,
      activeRules: 0,
      openPorts: 0,
      threatLevel: 'Low'
    };
  }
}

// New: IP metadata types, cache and metrics
export interface IPMetadataResult {
  success: boolean;
  data?: any;
  error?: string;
  source?: 'cache' | 'local' | 'ipinfo' | 'ipapi' | 'fallback';
  latencyMs?: number;
  fetchedAt?: number;
}

const IP_TTL_MS = Number(process.env.IP_METADATA_TTL_MS || 6 * 60 * 60 * 1000); // default 6h
const MAX_CONCURRENT_EXTERNAL = Number(process.env.IP_METADATA_MAX_CONCURRENT || 5);
const PROVIDER_TIMEOUT_MS = Number(process.env.IP_METADATA_TIMEOUT_MS || 5000);

const ipCache = new Map<string, { ts: number; value: IPMetadataResult }>();
const stats = {
  totalRequests: 0,
  cacheHits: 0,
  externalCalls: 0,
  externalFailures: 0,
  cacheSize: () => ipCache.size,
};

// Simple concurrency queue for external calls
let concurrent = 0;
const pendingQueue: Array<() => void> = [];
function acquireSlot(): Promise<() => void> {
  return new Promise(resolve => {
    const tryAcquire = () => {
      if (concurrent < MAX_CONCURRENT_EXTERNAL) {
        concurrent++;
        resolve(() => {
          concurrent = Math.max(0, concurrent - 1);
          if (pendingQueue.length) {
            const next = pendingQueue.shift();
            if (next) next();
          }
        });
      } else {
        pendingQueue.push(tryAcquire);
      }
    };
    tryAcquire();
  });
}

// Basic validation helpers
function isPrivateIP(ip: string) {
  return /^(localhost|::1|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(ip);
}
function isIPv4(ip: string) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
}

// Provider calls (IPInfo, fallback to ipapi)
function callProvider(url: string, timeout = PROVIDER_TIMEOUT_MS): Promise<any> {
  return new Promise((resolve, reject) => {
    const https = require('https');
    const req = https.get(url, { timeout }, (res: any) => {
      let data = '';
      res.on('data', (chunk: any) => (data += chunk));
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e: any) { reject(e); }
      });
    });
    req.on('error', (err: any) => reject(err));
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

async function fetchFromIpInfo(ip: string): Promise<any> {
  const { getApiKey } = await import('./shared/envLoader');
  const token = getApiKey('IPINFO_TOKEN');
  const url = token ? `https://ipinfo.io/${ip}/json?token=${token}` : `https://ipinfo.io/${ip}/json`;
  return callProvider(url);
}

async function fetchFromIpApi(ip: string): Promise<any> {
  const url = `https://ipapi.co/${ip}/json/`;
  return callProvider(url);
}

// Public: getIPMetadata
export async function getIPMetadataService(ip: string): Promise<IPMetadataResult> {
  stats.totalRequests++;
  if (!ip || typeof ip !== 'string') return { success: false, error: 'Invalid IP' };
  ip = ip.trim();

  // Cache lookup
  const cached = ipCache.get(ip);
  if (cached && (Date.now() - cached.ts) < IP_TTL_MS) {
    stats.cacheHits++;
    return { ...cached.value, source: 'cache' };
  }

  // Private/local handling (fast, no external call)
  if (isPrivateIP(ip) || ip === 'localhost') {
    const local = {
      success: true,
      data: {
        ip,
        type: 'local',
        country: 'Local Network',
        org: 'Local Network Device',
      },
      source: 'local',
      fetchedAt: Date.now(),
    } as IPMetadataResult;
    ipCache.set(ip, { ts: Date.now(), value: local });
    return local;
  }

  // DSGVO Art. 6 — external lookup gated behind user toggle
  if (!isExternalIpLookupAllowed()) {
    return { success: false, error: 'External IP lookups disabled (Datenschutz). Enable in Settings → Datenschutz.' };
  }

  // External lookup with concurrency control + fallback
  const release = await acquireSlot();
  stats.externalCalls++;
  const start = Date.now();
  try {
    let providerRes;
    try {
      providerRes = await fetchFromIpInfo(ip);
      ipCache.set(ip, { ts: Date.now(), value: { success: true, data: providerRes, source: 'ipinfo', latencyMs: Date.now() - start, fetchedAt: Date.now() } });
      return { success: true, data: providerRes, source: 'ipinfo', latencyMs: Date.now() - start, fetchedAt: Date.now() };
    } catch (e1) {
      // fallback
      try {
        providerRes = await fetchFromIpApi(ip);
        ipCache.set(ip, { ts: Date.now(), value: { success: true, data: providerRes, source: 'ipapi', latencyMs: Date.now() - start, fetchedAt: Date.now() } });
        return { success: true, data: providerRes, source: 'ipapi', latencyMs: Date.now() - start, fetchedAt: Date.now() };
      } catch (e2) {
        stats.externalFailures++;
        return { success: false, error: `Providers failed: ${e1?.message || e1} / ${e2?.message || e2}`, source: 'fallback' };
      }
    }
  } finally {
    release();
  }
}

// Public: simple stats getter
export function getIPMetadataStats() {
  return {
    totalRequests: stats.totalRequests,
    cacheHits: stats.cacheHits,
    cacheSize: stats.cacheSize(),
    externalCalls: stats.externalCalls,
    externalFailures: stats.externalFailures,
    concurrent: concurrent,
    maxConcurrent: MAX_CONCURRENT_EXTERNAL,
    ttlMs: IP_TTL_MS
  };
}

// --- Sentinel rule tracking (persistent) ---
function getTrackingFilePath() {
	// lazy require to avoid electron import at top-level in tests
	const { app } = require('electron');
	return path.join(app.getPath('userData'), 'sentinel_firewall_rules.json');
}

function loadSentinelRules(): string[] {
	try {
		const p = getTrackingFilePath();
		if (!fs.existsSync(p)) return [];
		const data = fs.readFileSync(p, 'utf8');
		return JSON.parse(data || '[]');
	} catch (e) {
		console.warn('Failed to load sentinel rules:', e);
		return [];
	}
}

function saveSentinelRules(rules: string[]) {
	try {
		const p = getTrackingFilePath();
		fs.mkdirSync(path.dirname(p), { recursive: true });
		fs.writeFileSync(p, JSON.stringify(Array.from(new Set(rules)), null, 2), 'utf8');
	} catch (e) {
		console.warn('Failed to save sentinel rules:', e);
	}
}

export function addSentinelRule(name: string) {
	if (!name) return;
	try {
		const rules = loadSentinelRules();
		if (!rules.includes(name)) {
			rules.push(name);
			saveSentinelRules(rules);
		}
	} catch (e) { console.warn(e); }
}

export function removeSentinelRule(name: string) {
	try {
		const rules = loadSentinelRules().filter(r => r !== name);
		saveSentinelRules(rules);
	} catch (e) { console.warn(e); }
}

export function getSentinelRules() {
	return loadSentinelRules();
}

export function clearSentinelRules() {
	saveSentinelRules([]);
	return true;
}

// === NETWORK TRAFFIC ===

/**
 * Returns current established TCP connections and resolves metadata for remote IPs.
 * - limitIPs: maximum unique remote IPs to resolve (to avoid API overuse)
 */
export async function getNetworkTrafficWithMetadata(limitIPs: number = 50): Promise<{
  connections: NetworkConnection[];
  uniqueIPs: string[];
  metadata: Record<string, IPMetadataResult>;
}> {
  try {
    let raw = '';
    try {
      raw = await runPS(`Get-NetTCPConnection -State Established|Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{n='ProcessName';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}}|ConvertTo-Json`, 10000);
    } catch (e) {
      // Fallback to netstat -ano parsing
      const netstat = await runCmd('netstat -ano -p tcp', { timeout: 10000, maxBuffer: 5 * 1024 * 1024 });
      const lines = netstat.split('\n').slice(4).map(l => l.trim()).filter(Boolean);
      const connections: NetworkConnection[] = [];
      for (const line of lines) {
        // Example: TCP    192.168.1.100:54321   93.184.216.34:443   ESTABLISHED    1234
        const parts = line.split(/\s+/);
        if (parts.length >= 5) {
          const local = parts[1].split(':');
          const remote = parts[2].split(':');
          connections.push({
            localAddress: local.slice(0, -1).join(':') || local[0],
            localPort: Number(local[local.length - 1]) || 0,
            remoteAddress: remote.slice(0, -1).join(':') || remote[0],
            remotePort: Number(remote[remote.length - 1]) || 0,
            state: parts[3],
            pid: Number(parts[4]) || undefined,
            process: undefined,
          });
        }
      }
      // Resolve metadata for these connections below
      raw = JSON.stringify(connections);
    }

    const parsed = JSON.parse(raw);
    const arr = Array.isArray(parsed) ? parsed : [parsed];

    // Normalize to NetworkConnection[]
    const connections: NetworkConnection[] = arr.map((c: any) => ({
      localAddress: c.LocalAddress || c.localAddress || c.local || '',
      localPort: Number(c.LocalPort || c.localPort || 0),
      remoteAddress: c.RemoteAddress || c.remoteAddress || c.remote || '',
      remotePort: Number(c.RemotePort || c.remotePort || 0),
      state: c.State || c.state || '',
      pid: c.OwningProcess ? Number(c.OwningProcess) : (c.pid ? Number(c.pid) : undefined),
      process: c.ProcessName || c.processName || c.Process || undefined,
      metadata: null,
    }));

    // Get unique remote IPs, exclude empty/0.0.0.0 and local host marker
    const uniqueSet = new Set<string>();
    for (const conn of connections) {
      const ip = (conn.remoteAddress || '').trim();
      if (!ip || ip === '0.0.0.0' || ip === '::' || ip === '127.0.0.1' || ip === '::1' || ip === '*') continue;
      uniqueSet.add(ip);
    }

    const uniqueIPs = Array.from(uniqueSet).slice(0, limitIPs);

    // Resolve metadata for unique IPs using ipinfo.io as primary provider
    const metadata: Record<string, IPMetadataResult> = {};
    await Promise.all(uniqueIPs.map(async (ip) => {
      // Use cache if fresh
      const cached = ipCache.get(ip);
      if (cached && (Date.now() - cached.ts) < IP_TTL_MS) {
        metadata[ip] = { ...cached.value, source: 'cache' };
        return;
      }

      // Local/private IP shortcut
      if (isPrivateIP(ip) || ip === 'localhost') {
        const local: IPMetadataResult = {
          success: true,
          data: { ip, type: 'local', country: 'Local Network', org: 'Local Network Device' },
          source: 'local',
          fetchedAt: Date.now()
        };
        ipCache.set(ip, { ts: Date.now(), value: local });
        metadata[ip] = local;
        return;
      }

      // DSGVO Art. 6 — batch path also gated behind user toggle
      if (!isExternalIpLookupAllowed()) {
        metadata[ip] = { success: false, error: 'External IP lookups disabled (Datenschutz)', source: 'fallback' };
        return;
      }

      // Call ipinfo.io directly with concurrency control
      let release: (() => void) | undefined;
      try {
        release = await acquireSlot();
        const start = Date.now();
        const providerRes = await fetchFromIpInfo(ip);
        const result: IPMetadataResult = {
          success: true,
          data: providerRes,
          source: 'ipinfo',
          latencyMs: Date.now() - start,
          fetchedAt: Date.now()
        };
        ipCache.set(ip, { ts: Date.now(), value: result });
        metadata[ip] = result;
      } catch (err: any) {
        stats.externalFailures++;
        // Do not attempt automatic fallback here — caller requested ipinfo.io specifically
        metadata[ip] = { success: false, error: err?.message || String(err), source: 'ipinfo' };
      } finally {
        if (release) release();
      }
    }));
     
     // Attach metadata to connections where available
     for (const conn of connections) {
       const ip = (conn.remoteAddress || '').trim();
       if (metadata[ip]) conn.metadata = metadata[ip];
     }
 
     return { connections, uniqueIPs, metadata };
   } catch (error: any) {
     console.error('Error gathering network traffic:', error);
     return { connections: [], uniqueIPs: [], metadata: {} };
   }
}

// === UNBLOCKING ===

export async function unblockIP(ip: string): Promise<{ success: boolean; message: string }> {
  try {
    const safeIp = validateIPForShell(ip);
    if (!safeIp) return { success: false, message: 'Invalid IP address format' };
    // Remove from hosts file
    const escapedIp = safeIp.replace(/\./g, '\\.');
    await runPS(`(Get-Content 'C:\Windows\System32\drivers\etc\hosts')|Where-Object{$_ -notmatch '${escapedIp}'}|Set-Content 'C:\Windows\System32\drivers\etc\hosts' -Force`);

    // Also delete related /24 sentinel firewall rules (best-effort)
    try {
      const octets = ip.split('.');
      if (octets.length === 4) {
        const subnet = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
        const baseName = `Sentinel Block SUBNET ${subnet}`;
        await deleteFirewallRule(`${baseName} - IN`).catch(() => {});
        await deleteFirewallRule(`${baseName} - OUT`).catch(() => {});
      }
    } catch (e) {
      // Non-critical; continue
      addActivityLog('Shield', 'Unblock IP', `Failed to remove related firewall rules for ${ip}: ${String(e)}`, 'warning');
    }

    addActivityLog('Shield', 'Unblock IP', `Unblocked IP: ${ip}`, 'success');
    return { success: true, message: `Unblocked IP ${ip}` };
  } catch (error: any) {
    const message = `Failed to unblock IP: ${error.message}`;
    addActivityLog('Shield', 'Unblock IP', message, 'error');
    return { success: false, message };
  }
}
