/**
 * SENTINEL — SIEM/MDR Event Exporter
 * Exports security events in CEF, JSON, and Syslog formats.
 * Enables KMUs without SOC to feed MDR services (CrowdStrike, etc.).
 * Zero external deps — pure Node.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as dgram from 'dgram';
import { app } from 'electron';

export type SiemFormat = 'cef' | 'json' | 'syslog';

export interface SiemEvent {
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  module: string;
  action: string;
  message: string;
  sourceIp?: string;
  destIp?: string;
  port?: number;
  pid?: number;
  processName?: string;
  riskScore?: number;
}

export interface SiemExportConfig {
  enabled: boolean;
  format: SiemFormat;
  syslogHost: string | null;
  syslogPort: number;
  autoExport: boolean;
  maxFileEvents: number;
}

let _cfg: SiemExportConfig = {
  enabled: false,
  format: 'json',
  syslogHost: null,
  syslogPort: 514,
  autoExport: false,
  maxFileEvents: 10000,
};

function cfgPath(): string { return path.join(app.getPath('userData'), 'siem-config.json'); }
function exportDir(): string { return path.join(app.getPath('userData'), 'siem-exports'); }

function ensureDir(d: string): void { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); }

export function initSiemExporter(): void {
  try {
    const p = cfgPath();
    if (fs.existsSync(p)) _cfg = { ..._cfg, ...JSON.parse(fs.readFileSync(p, 'utf8')) };
  } catch { /* first run */ }
}

export function getSiemConfig(): SiemExportConfig { return { ..._cfg }; }

export function setSiemConfig(update: Partial<SiemExportConfig>): SiemExportConfig {
  _cfg = { ..._cfg, ...update };
  try {
    ensureDir(path.dirname(cfgPath()));
    fs.writeFileSync(cfgPath(), JSON.stringify(_cfg, null, 2), 'utf8');
  } catch (e: any) { console.warn('[SIEM] config save failed:', e?.message); }
  return { ..._cfg };
}

const SEV_MAP: Record<string, number> = { low: 3, medium: 5, high: 8, critical: 10 };

function toCEF(evt: SiemEvent): string {
  const sev = SEV_MAP[evt.severity] ?? 5;
  const ext = [
    evt.sourceIp ? `src=${evt.sourceIp}` : '',
    evt.destIp ? `dst=${evt.destIp}` : '',
    evt.port ? `dpt=${evt.port}` : '',
    evt.pid ? `dvcpid=${evt.pid}` : '',
    evt.processName ? `dproc=${evt.processName}` : '',
    evt.riskScore != null ? `flexNumber1=${evt.riskScore}` : '',
    `rt=${new Date(evt.timestamp).getTime()}`,
  ].filter(Boolean).join(' ');
  return `CEF:0|Sentinel|SecuritySuite|1.0|${evt.action}|${evt.message.replace(/\|/g, '\\|')}|${sev}|${ext}`;
}

function toSyslog(evt: SiemEvent): string {
  const facility = 4; // auth
  const sevNum = evt.severity === 'critical' ? 2 : evt.severity === 'high' ? 3 : evt.severity === 'medium' ? 4 : 6;
  const pri = facility * 8 + sevNum;
  const ts = new Date(evt.timestamp).toISOString();
  return `<${pri}>1 ${ts} sentinel ${evt.module} - - - [${evt.action}] ${evt.message}`;
}

function toJSON(evt: SiemEvent): string {
  return JSON.stringify(evt);
}

function formatEvent(evt: SiemEvent, fmt: SiemFormat): string {
  if (fmt === 'cef') return toCEF(evt);
  if (fmt === 'syslog') return toSyslog(evt);
  return toJSON(evt);
}

export function exportEvents(events: SiemEvent[], format?: SiemFormat): { success: boolean; path?: string; count: number } {
  const fmt = format || _cfg.format;
  const ext = fmt === 'json' ? 'json' : fmt === 'cef' ? 'cef.log' : 'syslog.log';
  const dir = exportDir();
  ensureDir(dir);

  const filename = `sentinel-events-${Date.now()}.${ext}`;
  const filePath = path.join(dir, filename);
  const lines = events.slice(0, _cfg.maxFileEvents).map(e => formatEvent(e, fmt));
  fs.writeFileSync(filePath, lines.join('\n') + '\n', 'utf8');
  return { success: true, path: filePath, count: lines.length };
}

export function sendToSyslog(events: SiemEvent[]): Promise<{ success: boolean; sent: number; error?: string }> {
  return new Promise((resolve) => {
    if (!_cfg.syslogHost) {
      resolve({ success: false, sent: 0, error: 'No syslog host configured' });
      return;
    }

    const client = dgram.createSocket('udp4');
    let sent = 0;
    let pending = events.length;

    if (pending === 0) { client.close(); resolve({ success: true, sent: 0 }); return; }

    for (const evt of events) {
      const msg = Buffer.from(toSyslog(evt), 'utf8');
      client.send(msg, _cfg.syslogPort, _cfg.syslogHost!, (err) => {
        if (!err) sent++;
        pending--;
        if (pending <= 0) {
          client.close();
          resolve({ success: sent > 0, sent, error: sent === 0 ? 'All messages failed' : undefined });
        }
      });
    }

    setTimeout(() => { try { client.close(); } catch { /* already closed */ } resolve({ success: sent > 0, sent }); }, 5000);
  });
}

export function convertSecurityEventsToSiem(records: Array<{
  pid?: number; processName?: string; remoteIP?: string; localPort?: number;
  riskScore?: number; riskLevel?: string; actionTaken?: string; reason?: string; timestamp?: number;
}>): SiemEvent[] {
  return records.map(r => ({
    timestamp: r.timestamp ? new Date(r.timestamp).toISOString() : new Date().toISOString(),
    severity: (r.riskLevel?.toLowerCase() as SiemEvent['severity']) || 'medium',
    module: 'Shield',
    action: r.actionTaken || 'Alert',
    message: r.reason || `${r.actionTaken || 'Event'} — ${r.processName || 'unknown'}:${r.pid || 0} → ${r.remoteIP || '?'}:${r.localPort || 0}`,
    sourceIp: r.remoteIP,
    port: r.localPort,
    pid: r.pid,
    processName: r.processName,
    riskScore: r.riskScore,
  }));
}

export function listExports(): Array<{ name: string; size: number; created: string }> {
  const dir = exportDir();
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter(f => f.startsWith('sentinel-events-'))
    .map(f => {
      const stat = fs.statSync(path.join(dir, f));
      return { name: f, size: stat.size, created: stat.mtime.toISOString() };
    })
    .sort((a, b) => b.created.localeCompare(a.created))
    .slice(0, 50);
}
