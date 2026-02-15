/**
 * SENTINEL — Local Port Scanner Service
 * Scans this machine's open/listening ports via PowerShell Get-NetTCPConnection.
 * Enriches with process name, PID, service name, and risk assessment.
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const PS_TIMEOUT = 8000;
const PS_MAX_BUFFER = 4 * 1024 * 1024;

export interface OpenPort {
  port: number;
  protocol: string;
  state: string;
  process: string;
  pid: number;
  localAddress: string;
  remoteAddress: string;
  risk: 'high' | 'medium' | 'low' | 'safe';
  riskReason: string;
}

export interface PortScanResult {
  ports: OpenPort[];
  totalListening: number;
  highRisk: number;
  timestamp: string;
}

const HIGH_RISK_PORTS: Record<number, string> = {
  21: 'FTP — plaintext credentials',
  23: 'Telnet — plaintext remote shell',
  25: 'SMTP — mail relay abuse risk',
  135: 'RPC — remote code execution vector',
  137: 'NetBIOS — information disclosure',
  138: 'NetBIOS — information disclosure',
  139: 'NetBIOS — SMB over NetBIOS',
  445: 'SMB — lateral movement / WannaCry',
  1433: 'MSSQL — database exposure',
  1434: 'MSSQL Browser — enumeration',
  3389: 'RDP — remote desktop brute force',
  4444: 'Metasploit default — backdoor indicator',
  5800: 'VNC HTTP — remote access',
  5900: 'VNC — remote access',
  8080: 'HTTP Alt — possible misconfigured service',
};

const MEDIUM_RISK_PORTS: Record<number, string> = {
  22: 'SSH — verify authorized access only',
  53: 'DNS — open resolver risk',
  80: 'HTTP — unencrypted web traffic',
  110: 'POP3 — plaintext email',
  143: 'IMAP — plaintext email',
  389: 'LDAP — directory enumeration',
  636: 'LDAPS — encrypted but exposed',
  993: 'IMAPS — encrypted email',
  995: 'POP3S — encrypted email',
  3306: 'MySQL — database exposure',
  5432: 'PostgreSQL — database exposure',
  6379: 'Redis — often no auth',
  8443: 'HTTPS Alt — verify purpose',
  9200: 'Elasticsearch — data exposure',
  27017: 'MongoDB — often no auth',
};

const SAFE_PORTS = new Set([443, 49152, 49153, 49154, 49155, 49156]);

function assessPortRisk(port: number, process: string): { risk: OpenPort['risk']; reason: string } {
  if (HIGH_RISK_PORTS[port]) return { risk: 'high', reason: HIGH_RISK_PORTS[port] };
  if (MEDIUM_RISK_PORTS[port]) return { risk: 'medium', reason: MEDIUM_RISK_PORTS[port] };
  if (SAFE_PORTS.has(port) || port >= 49152) return { risk: 'safe', reason: 'Ephemeral/standard port' };
  if (port === 443) return { risk: 'safe', reason: 'HTTPS — encrypted' };
  return { risk: 'low', reason: `Port ${port} — ${process || 'unknown process'}` };
}

export async function scanLocalPorts(): Promise<PortScanResult> {
  const ports: OpenPort[] = [];

  try {
    const psScript = `
      Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
      Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
      ConvertTo-Json -Compress
    `;
    const { stdout } = await execAsync(
      `powershell -NoProfile -NonInteractive -Command "${psScript.replace(/\n/g, ' ')}"`,
      { timeout: PS_TIMEOUT, maxBuffer: PS_MAX_BUFFER }
    );

    const raw = JSON.parse(stdout.trim() || '[]');
    const connections = Array.isArray(raw) ? raw : [raw];

    const pidSet = new Set<number>();
    for (const c of connections) pidSet.add(c.OwningProcess);

    const pidToName: Record<number, string> = {};
    if (pidSet.size > 0) {
      try {
        const pidScript = `
          Get-Process -Id ${[...pidSet].join(',')} -ErrorAction SilentlyContinue |
          Select-Object Id, ProcessName |
          ConvertTo-Json -Compress
        `;
        const { stdout: procOut } = await execAsync(
          `powershell -NoProfile -NonInteractive -Command "${pidScript.replace(/\n/g, ' ')}"`,
          { timeout: PS_TIMEOUT, maxBuffer: PS_MAX_BUFFER }
        );
        const procs = JSON.parse(procOut.trim() || '[]');
        const procList = Array.isArray(procs) ? procs : [procs];
        for (const p of procList) {
          pidToName[p.Id] = p.ProcessName || `PID ${p.Id}`;
        }
      } catch {
        // Process name resolution failed — continue without
      }
    }

    for (const c of connections) {
      const port = c.LocalPort;
      const pid = c.OwningProcess;
      const process = pidToName[pid] || `PID ${pid}`;
      const { risk, reason } = assessPortRisk(port, process);

      ports.push({
        port,
        protocol: 'TCP',
        state: c.State || 'Listen',
        process,
        pid,
        localAddress: c.LocalAddress || '0.0.0.0',
        remoteAddress: c.RemoteAddress || '*',
        risk,
        riskReason: reason,
      });
    }

    ports.sort((a, b) => {
      const riskOrder = { high: 0, medium: 1, low: 2, safe: 3 };
      return (riskOrder[a.risk] - riskOrder[b.risk]) || (a.port - b.port);
    });
  } catch (err) {
    console.error('[PortScanner] Scan failed:', err instanceof Error ? err.message : err);
  }

  return {
    ports,
    totalListening: ports.length,
    highRisk: ports.filter(p => p.risk === 'high').length,
    timestamp: new Date().toISOString(),
  };
}
