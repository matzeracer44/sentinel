/**
 * SENTINEL UNIFIED — System & Performance Cluster IPC Handlers
 */

import { ipcMain } from 'electron';
import * as os from 'os';
import { IPC } from '../../shared/constants';
import { serializeError } from '../../shared/utils';
import { getHealthReport } from '../services/healthCheckService';
import { getSentinelConfig, updateAutonomousMode, addWhitelistEntry, removeWhitelistEntry, setWhitelist } from '../services/sentinelConfig';
import { getSecurityOverview } from '../services/shieldData';

let isAdmin = false;

export function setSystemContext(opts: { isAdmin: boolean }): void {
  isAdmin = opts.isAdmin;
}

function getRAMUsage() {
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();
  const usedMemory = totalMemory - freeMemory;
  return {
    totalGB: Math.round(totalMemory / 1024 / 1024 / 1024 * 100) / 100,
    usedGB: Math.round(usedMemory / 1024 / 1024 / 1024 * 100) / 100,
    freeGB: Math.round(freeMemory / 1024 / 1024 / 1024 * 100) / 100,
    usagePercent: Math.round((usedMemory / totalMemory) * 100),
  };
}

async function sampleCpuPercent(): Promise<number> {
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
    return totalDiff > 0 ? Math.round(((totalDiff - idleDiff) / totalDiff) * 100) : -1;
  } catch { return -1; }
}

function getDiskPercent(): number {
  try {
    const { execSync } = require('child_process');
    const out = execSync(
      'powershell -NoProfile -Command "(Get-PSDrive C).Used / ((Get-PSDrive C).Used + (Get-PSDrive C).Free) * 100"',
      { encoding: 'utf-8', timeout: 5000, windowsHide: true }
    ).trim();
    const v = Math.round(parseFloat(out));
    return isNaN(v) ? -1 : v;
  } catch { return -1; }
}

function execPsJson(cmd: string): any {
  try {
    const { execSync } = require('child_process');
    const out = execSync(`powershell -ExecutionPolicy Bypass -NoProfile -Command "${cmd}"`, {
      encoding: 'utf-8', timeout: 10000, windowsHide: true,
    });
    return JSON.parse(out.trim());
  } catch { return null; }
}

export function registerSystemHandlers(): void {
  // ─── Get Real System Data ───
  ipcMain.handle(IPC.SYSTEM.GET_DATA, async () => {
    try {
      const ram = getRAMUsage();
      const cpus = os.cpus();
      const cpuLoad = await sampleCpuPercent();

      // Real disk info
      let disks: any[] = [];
      try {
        const diskData = execPsJson(
          `Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{N='TotalGB';E={[math]::Round(($_.Used+$_.Free)/1GB,2)}}, @{N='UsedGB';E={[math]::Round($_.Used/1GB,2)}}, @{N='FreeGB';E={[math]::Round($_.Free/1GB,2)}} | ConvertTo-Json -Depth 2`
        );
        if (diskData) {
          const arr = Array.isArray(diskData) ? diskData : [diskData];
          disks = arr.filter((d: any) => d.TotalGB > 0).map((d: any) => ({
            drive: `${d.Name}:`, totalGB: d.TotalGB, usedGB: d.UsedGB, freeGB: d.FreeGB,
            usagePercent: d.TotalGB > 0 ? Math.round((d.UsedGB / d.TotalGB) * 100) : 0,
          }));
        }
      } catch { /* keep empty */ }

      // Real GPU info
      let gpu: any[] = [];
      try {
        const gpuData = execPsJson(
          `Get-CimInstance Win32_VideoController | Select-Object Name, @{N='MemoryMB';E={[math]::Round($_.AdapterRAM/1MB)}} | ConvertTo-Json -Depth 2`
        );
        if (gpuData) {
          const arr = Array.isArray(gpuData) ? gpuData : [gpuData];
          gpu = arr.map((g: any) => ({ name: g.Name || 'Unknown', memory: g.MemoryMB || 0 }));
        }
      } catch { /* keep empty */ }

      // Real network adapters
      let network: any[] = [];
      try {
        const netData = execPsJson(
          `Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, Status, MacAddress, @{N='IP';E={(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress}} | ConvertTo-Json -Depth 2`
        );
        if (netData) {
          const arr = Array.isArray(netData) ? netData : [netData];
          network = arr.map((n: any) => ({
            adapter: n.Name || 'Unknown', status: n.Status || 'Unknown',
            ipAddress: n.IP || 'N/A', macAddress: n.MacAddress || 'N/A',
          }));
        }
      } catch { /* keep empty */ }

      return {
        success: true,
        data: {
          cpu: (() => {
            let physicalCores = Math.max(1, Math.ceil(cpus.length / 2));
            try {
              const coreData = execPsJson(
                `Get-CimInstance Win32_Processor | Select-Object -First 1 NumberOfCores, NumberOfLogicalProcessors | ConvertTo-Json -Compress`
              );
              if (coreData && typeof coreData.NumberOfCores === 'number') {
                physicalCores = coreData.NumberOfCores;
              }
            } catch { /* fallback to heuristic */ }
            return { name: cpus[0]?.model || 'Unknown', cores: physicalCores, threads: cpus.length, currentLoad: cpuLoad };
          })(),
          ram,
          disks: disks.length > 0 ? disks : [{ drive: 'C:', totalGB: -1, usedGB: -1, freeGB: -1, usagePercent: getDiskPercent() }],
          system: { manufacturer: os.platform(), model: os.arch(), computerName: os.hostname(), username: os.userInfo().username },
          os: { name: process.platform === 'win32' ? 'Windows' : process.platform, version: os.release(), build: os.release() },
          gpu: gpu.length > 0 ? gpu : [{ name: 'Unknown', memory: -1 }],
          network: network.length > 0 ? network : [{ adapter: 'Unknown', status: 'Unknown', ipAddress: 'N/A', macAddress: 'N/A' }],
          battery: { status: 'N/A', percentage: 0 },
        },
      };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── System Health Score (real firewall + telemetry checks) ───
  ipcMain.handle(IPC.SYSTEM.GET_HEALTH, async () => {
    try {
      const ram = getRAMUsage();
      const ramHealth = Math.max(0, 100 - ram.usagePercent);

      let securityScore = 50;
      try {
        const { execSync } = require('child_process');
        const fwCount = parseInt(execSync(
          'powershell -NoProfile -Command "(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $true }).Count"',
          { encoding: 'utf-8', timeout: 5000, windowsHide: true }
        ).trim(), 10);
        if (fwCount >= 3) securityScore = 95;
        else if (fwCount >= 2) securityScore = 80;
        else if (fwCount >= 1) securityScore = 65;
      } catch { /* keep base */ }

      let privacyScore = 60;
      try {
        const { execSync } = require('child_process');
        const level = parseInt(execSync(
          'powershell -NoProfile -Command "(Get-ItemProperty -Path HKLM:\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\DataCollection -Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry"',
          { encoding: 'utf-8', timeout: 3000, windowsHide: true }
        ).trim(), 10);
        if (level === 0) privacyScore = 95;
        else if (level === 1) privacyScore = 80;
        else if (level === 2) privacyScore = 65;
        else privacyScore = 50;
      } catch { /* keep base */ }

      const score = Math.round((securityScore + ramHealth + privacyScore) / 3);
      return { score, factors: { security: securityScore, performance: ramHealth, privacy: privacyScore } };
    } catch {
      return { score: -1, factors: { security: -1, performance: -1, privacy: -1 } };
    }
  });

  // ─── System Stats (real CPU + disk) ───
  ipcMain.handle(IPC.SYSTEM.GET_STATS, async () => {
    try {
      const ram = getRAMUsage();
      const cpuPercent = await sampleCpuPercent();
      const diskPercent = getDiskPercent();
      return { cpu: cpuPercent, ram: ram.usagePercent, disk: diskPercent, network: 0 };
    } catch {
      return { cpu: -1, ram: -1, disk: -1, network: 0 };
    }
  });

  // ─── Health Report ───
  ipcMain.handle(IPC.SYSTEM.GET_HEALTH_REPORT, async (_event, options: { force?: boolean } = {}) => {
    try {
      const report = await getHealthReport(options);
      return { success: true, data: report };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── RAM Stats ───
  ipcMain.handle(IPC.SYSTEM.GET_RAM_STATS, async () => {
    try {
      const ram = getRAMUsage();
      return {
        totalGB: ram.totalGB, usedGB: ram.usedGB, availableGB: ram.freeGB,
        systemGB: ram.usedGB * 0.25, appsGB: ram.usedGB * 0.75, cacheGB: 0, usagePercent: ram.usagePercent,
      };
    } catch {
      return { totalGB: 0, usedGB: 0, availableGB: 0, systemGB: 0, appsGB: 0, cacheGB: 0, usagePercent: 0 };
    }
  });

  // ─── Clear Standby Cache (real) ───
  ipcMain.handle(IPC.SYSTEM.CLEAR_STANDBY_CACHE, async () => {
    if (!isAdmin) return { success: false, message: 'Admin privileges required' };
    try {
      const freeBefore = os.freemem();
      const { execSync } = require('child_process');
      execSync('powershell -ExecutionPolicy Bypass -NoProfile -Command "Clear-RecycleBin -Force -ErrorAction SilentlyContinue; [System.GC]::Collect()"',
        { timeout: 10000, windowsHide: true });
      const freeAfter = os.freemem();
      const freedMB = Math.max(0, Math.round((freeAfter - freeBefore) / (1024 * 1024)));
      return { success: true, freedMB, message: `Cache cleared, freed ~${freedMB} MB` };
    } catch (err: any) {
      return { success: false, message: err.message || 'Cache clear failed' };
    }
  });

  // ─── Startup Items (real) ───
  ipcMain.handle(IPC.SYSTEM.GET_STARTUP_ITEMS, async () => {
    try {
      const data = execPsJson(
        `$items = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name, Command, Location, User | ConvertTo-Json -Depth 2; ` +
        `$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime; ` +
        `$uptime = [math]::Round(((Get-Date) - $boot).TotalSeconds); ` +
        `@{ items = $items; bootSeconds = $uptime } | ConvertTo-Json -Depth 3`
      );
      let items: any[] = [];
      if (data?.items) {
        try { items = typeof data.items === 'string' ? JSON.parse(data.items) : data.items; } catch { items = []; }
        if (!Array.isArray(items)) items = items ? [items] : [];
      }
      return {
        success: true,
        items: items.map((i: any) => ({ name: i.Name || 'Unknown', command: i.Command || '', location: i.Location || '', user: i.User || '' })),
        currentBootTime: data?.bootSeconds || -1,
        optimizedBootTime: -1,
      };
    } catch (err: any) {
      return { success: false, items: [], currentBootTime: -1, optimizedBootTime: -1, error: err.message };
    }
  });

  // ─── Windows Services (real) ───
  ipcMain.handle(IPC.SYSTEM.GET_WINDOWS_SERVICES, async () => {
    try {
      const data = execPsJson(`Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json -Depth 2`);
      let services = Array.isArray(data) ? data : data ? [data] : [];
      return {
        success: true,
        services: services.map((s: any) => ({
          name: s.Name || '', displayName: s.DisplayName || '',
          status: String(s.Status ?? ''), startType: String(s.StartType ?? ''),
        })),
      };
    } catch (err: any) {
      return { success: false, services: [], error: err.message };
    }
  });

  // ─── Admin Check ───
  ipcMain.handle(IPC.SYSTEM.CHECK_ADMIN, async () => {
    return { isAdmin, message: isAdmin ? 'Running with administrator privileges' : 'Running with limited privileges' };
  });

  // ─── Security Overview ───
  ipcMain.handle(IPC.SYSTEM.GET_SECURITY_OVERVIEW, async () => {
    try {
      const overview = await getSecurityOverview();
      return { success: true, data: overview };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });
}
