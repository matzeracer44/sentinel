/**
 * SENTINEL UNIFIED — Network Cluster IPC Handlers
 * Network monitoring, TLS inspection, IP metadata, sessions, processes.
 */

import { ipcMain } from 'electron';
import { execSync, spawn } from 'child_process';
import * as os from 'os';
import { IPC } from '../../shared/constants';
import { serializeError } from '../../shared/utils';
import { getNetworkTrafficSnapshot, getFullNetworkAudit, registerAddressWatch, getAddressWatchSummary } from '../services/networkMonitor';
import { inspectTLS } from '../services/tlsInspector';
import { killProcess as killProcessService } from '../services/shieldData';
import { getArgusManager } from '../services/argusManager';
import { isExternalIpLookupAllowed } from '../services/sentinelConfig';

export function registerNetworkHandlers(): void {
  // ─── Get Network Traffic ───
  ipcMain.handle(IPC.NETWORK.GET_TRAFFIC, async (_event, limit = 100) => {
    try {
      const connections = await getNetworkTrafficSnapshot(limit);
      return connections;
    } catch (err) {
      console.error('[Network Traffic] Error:', err);
      return [];
    }
  });

  // ─── Full Network Audit ───
  ipcMain.handle(IPC.NETWORK.GET_FULL_AUDIT, async (_event, limit = 1500) => {
    try {
      const audit = await getFullNetworkAudit(limit);
      return { success: true, data: audit };
    } catch (err) {
      return { success: false, error: serializeError(err), data: [] };
    }
  });

  // ─── Network Diagnostics ───
  ipcMain.handle(IPC.NETWORK.GET_DIAGNOSTICS, async () => {
    try {
      const powershellScript = `
$ErrorActionPreference = 'Stop'
$result = @{ Services = @(); NetworkStatistics = @() }
try {
    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Sentinel*" -or $_.DisplayName -like "*Sentinel*" }
    if ($services) {
        foreach ($service in $services) {
            $result.Services += @{ Name = $service.Name; DisplayName = $service.DisplayName; Status = $service.Status.ToString() }
        }
    }
} catch { $result.Services = @(@{ Error = "Failed: $($_.Exception.Message)" }) }
try {
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -notin @('0.0.0.0','127.0.0.1','::') } | Select-Object -First 100
    if ($connections) {
        foreach ($conn in $connections) {
            try { $processName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch { $processName = "Unknown" }
            $result.NetworkStatistics += @{
                Protocol = "TCP"; LocalAddress = $conn.LocalAddress; LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress; RemotePort = $conn.RemotePort
                State = $conn.State; PID = $conn.OwningProcess; ProcessName = $processName
            }
        }
    }
} catch { $result.NetworkStatistics = @(@{ Error = "Failed: $($_.Exception.Message)" }) }
$result | ConvertTo-Json -Depth 10`;

      return new Promise((resolve) => {
        const child = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', powershellScript]);
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (d) => { stdout += d.toString(); });
        child.stderr.on('data', (d) => { stderr += d.toString(); });
        child.on('close', (code) => {
          if (code !== 0) { resolve({ success: false, error: `PowerShell exited with code ${code}` }); return; }
          try {
            const diagnostics = JSON.parse(stdout.trim());
            resolve({ success: true, data: diagnostics });
          } catch (parseErr) {
            resolve({ success: false, error: parseErr instanceof Error ? parseErr.message : 'Parse error' });
          }
        });
        child.on('error', (err) => { resolve({ success: false, error: err.message }); });
      });
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── IP Metadata ───
  ipcMain.handle(IPC.NETWORK.GET_IP_METADATA, async (_event, ip: string) => {
    try {
      const isPrivate =
        ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('127.') ||
        ip.startsWith('169.254.') || ip === 'localhost' || ip === '::1' ||
        (ip.startsWith('172.') && (() => { const s = parseInt(ip.split('.')[1], 10); return s >= 16 && s <= 31; })());

      if (isPrivate) {
        let hostname = 'Unknown';
        let macAddress = 'Unknown';
        let vendor = 'Unknown';
        let deviceType = 'Computer/Device';
        try {
          try {
            const hostnameCmd = `powershell -Command "Resolve-DnsName -Name ${ip} -Type PTR -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost"`;
            hostname = execSync(hostnameCmd, { timeout: 3000 }).toString().trim() || 'Unknown';
          } catch { hostname = 'Unknown'; }
          try {
            const arpOutput = execSync(`arp -a ${ip}`, { timeout: 2000 }).toString();
            const macMatch = arpOutput.match(/([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/);
            if (macMatch) {
              macAddress = macMatch[0].toUpperCase().replace(/-/g, ':');
              const vendorMap: Record<string, string> = {
                '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:16:E3': 'Apple', '3C:07:54': 'Apple',
                '00:24:8C': 'Samsung', '00:1A:4D': 'Dell', '00:1E:4F': 'HP', '08:00:27': 'VirtualBox',
                '00:15:5D': 'Microsoft Hyper-V', '00:50:F2': 'Microsoft',
              };
              for (const [prefix, v] of Object.entries(vendorMap)) {
                if (macAddress.startsWith(prefix)) { vendor = v; break; }
              }
            }
          } catch { /* non-critical */ }
          const hostLower = hostname.toLowerCase();
          if (hostLower.includes('router') || hostLower.includes('gateway')) deviceType = 'Router/Gateway';
          else if (vendor.includes('VMware') || vendor.includes('VirtualBox')) deviceType = 'Virtual Machine';
        } catch { /* non-critical */ }

        return {
          success: true,
          data: {
            ip, type: 'local', country: 'Local Network', countryCode: 'LAN', region: 'Private Network',
            city: 'Local', zip: 'N/A', isp: 'Private Network', org: hostname !== 'Unknown' ? hostname : 'Local Device',
            as: macAddress !== 'Unknown' ? `MAC: ${macAddress}` : 'N/A',
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            lat: 0, lon: 0, mobile: false, proxy: false, hosting: false,
            reputation: `${vendor !== 'Unknown' ? vendor : 'Unknown Vendor'} - ${deviceType}`,
            riskLevel: 'safe', hostname, macAddress, vendor, deviceType,
          },
        };
      }

      // External IP — gated behind DSGVO user toggle (Art. 6 DSGVO)
      if (!isExternalIpLookupAllowed()) {
        return { success: false, error: 'External IP lookups disabled (Datenschutz). Enable in Settings → Datenschutz.' };
      }
      const https = require('https');
      const { getApiKey } = await import('../services/shared/envLoader');
      const ipinfoToken = getApiKey('IPINFO_TOKEN');
      const url = ipinfoToken ? `https://ipinfo.io/${ip}/json?token=${ipinfoToken}` : `https://ipinfo.io/${ip}/json`;
      return new Promise((resolve) => {
        const req = https.get(url, { timeout: 8000 }, (res: any) => {
          let data = '';
          res.on('data', (chunk: any) => { data += chunk; });
          res.on('end', () => {
            try {
              const parsed = JSON.parse(data);
              if (parsed.bogon) { resolve({ success: false, error: 'Private/Reserved IP' }); return; }
              if (parsed.error) { resolve({ success: false, error: parsed.error }); return; }
              const countryCode = parsed.country || '??';
              const org = parsed.org || 'Unknown';
              const orgLower = org.toLowerCase();
              let riskLevel = 'low';
              let reputation = 'Clean';
              const isHosting = orgLower.includes('hosting') || orgLower.includes('cloud') || orgLower.includes('vpn') ||
                orgLower.includes('proxy') || orgLower.includes('datacenter') || orgLower.includes('amazon') ||
                orgLower.includes('google') || orgLower.includes('microsoft');
              if (isHosting) { riskLevel = 'medium'; reputation = 'Hosting/Cloud Provider'; }
              if (['KP', 'IR', 'SY', 'CU'].includes(countryCode)) { riskLevel = 'high'; reputation = 'High Risk Region'; }
              const [lat, lon] = parsed.loc ? parsed.loc.split(',').map(Number) : [0, 0];
              resolve({
                success: true,
                data: {
                  ip: parsed.ip || ip, type: 'external', country: parsed.country || '??', countryCode,
                  region: parsed.region || 'Unknown', city: parsed.city || 'Unknown', zip: parsed.postal || 'N/A',
                  isp: org, org, as: org.match(/AS(\d+)/i)?.[0] || 'N/A',
                  timezone: parsed.timezone || 'UTC', lat, lon, mobile: false, proxy: isHosting, hosting: isHosting,
                  reputation, riskLevel, raw: parsed,
                },
              });
            } catch { resolve({ success: false, error: 'Invalid response' }); }
          });
        });
        req.on('timeout', () => { req.destroy(); resolve({ success: false, error: 'Request timeout' }); });
        req.on('error', (err: Error) => { resolve({ success: false, error: err.message }); });
      });
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── TLS Inspection ───
  ipcMain.handle(IPC.NETWORK.INSPECT_TLS, async (_event, host: string) => {
    try {
      const sanitized = (host || '').trim();
      if (!sanitized) return { success: false, error: { message: 'Host is required' } };
      const summary = await inspectTLS(sanitized);
      return { success: true, data: summary };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Address Watch ───
  ipcMain.handle(IPC.NETWORK.REGISTER_WATCH, async (_event, ip: string) => {
    try {
      const normalized = (ip || '').trim();
      if (!normalized) return { success: false, error: { message: 'IP address is required' } };
      const record = registerAddressWatch(normalized);
      return { success: true, data: record };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.NETWORK.GET_WATCH, async () => {
    try {
      const tracked = getAddressWatchSummary();
      const topHit = tracked.reduce<ReturnType<typeof getAddressWatchSummary>[number] | null>((best, current) => {
        if (!best) return current;
        return current.hits > best.hits ? current : best;
      }, null);
      return {
        success: true,
        data: { summary: { totalTracked: tracked.length, topHit }, tracked, fetchedAt: Date.now() },
      };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Internet Test ───
  ipcMain.handle(IPC.NETWORK.TEST_INTERNET, async () => {
    try {
      const { testInternet } = require('../services/firewallSafety');
      const result = await testInternet();
      return result;
    } catch {
      return { success: false, connected: false, latency: -1 };
    }
  });

  // ─── Processes (real data from tasklist) ───
  ipcMain.handle(IPC.NETWORK.GET_PROCESSES, async () => {
    try {
      // tasklist columns: "Image Name","PID","Session Name","Session#","Mem Usage"
      const taskListOutput = execSync('tasklist /FO CSV /NH', { encoding: 'utf-8', windowsHide: true, timeout: 10000 });
      return taskListOutput.split('\n').filter((l) => l.trim()).slice(0, 50).map((line) => {
        const cols = line.split(',').map((s) => s.replace(/"/g, '').trim());
        const name = cols[0] || 'Unknown';
        const pid = parseInt(cols[1], 10);
        const memStr = (cols[4] || '0').replace(/[^0-9]/g, '');
        const ramMB = Math.round(parseInt(memStr, 10) / 1024) || 0;
        return { pid, name, cpu: -1, ram: ramMB, trustScore: -1, connections: [] };
      }).filter((p) => !isNaN(p.pid));
    } catch { return []; }
  });

  ipcMain.handle(IPC.NETWORK.KILL_PROCESS, async (_event, pid: number, processName: string) => {
    try {
      return await killProcessService(pid, processName || `PID ${pid}`);
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── System Stats (real CPU + disk) ───
  ipcMain.handle(IPC.NETWORK.GET_SYSTEM_STATS, async () => {
    try {
      const totalMemory = os.totalmem();
      const freeMemory = os.freemem();

      // Real CPU via 200ms sample
      let cpuPercent = -1;
      try {
        const cpus1 = os.cpus();
        await new Promise((r) => setTimeout(r, 200));
        const cpus2 = os.cpus();
        let idleDiff = 0, totalDiff = 0;
        for (let i = 0; i < cpus1.length; i++) {
          const t1 = cpus1[i].times, t2 = cpus2[i].times;
          const idle = t2.idle - t1.idle;
          const total = (t2.user - t1.user) + (t2.nice - t1.nice) + (t2.sys - t1.sys) + (t2.irq - t1.irq) + idle;
          idleDiff += idle; totalDiff += total;
        }
        cpuPercent = totalDiff > 0 ? Math.round(((totalDiff - idleDiff) / totalDiff) * 100) : -1;
      } catch { cpuPercent = -1; }

      // Real disk
      let diskPercent = -1;
      try {
        const diskOut = execSync(
          'powershell -NoProfile -Command "(Get-PSDrive C).Used / ((Get-PSDrive C).Used + (Get-PSDrive C).Free) * 100"',
          { encoding: 'utf-8', timeout: 5000, windowsHide: true }
        ).trim();
        diskPercent = Math.round(parseFloat(diskOut));
        if (isNaN(diskPercent)) diskPercent = -1;
      } catch { diskPercent = -1; }

      return { success: true, cpu: cpuPercent, ram: Math.round(((totalMemory - freeMemory) / totalMemory) * 100), disk: diskPercent };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── ARGUS Sandbox ───
  ipcMain.handle(IPC.NETWORK.SANDBOX_STATUS, async () => {
    try {
      const result = await getArgusManager().getSandboxStatus();
      return { success: true, data: result };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.NETWORK.SANDBOX_TOGGLE, async (_event, enabled: boolean) => {
    try {
      const result = await getArgusManager().toggleSandbox(enabled);
      return { success: true, data: result };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });
}
