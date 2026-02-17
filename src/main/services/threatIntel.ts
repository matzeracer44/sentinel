/**
 * SENTINEL — Local Threat Intelligence (MISP Community Feeds)
 * Downloads IoC feeds locally, caches them, enriches Network Monitor connections.
 * Zero-cost: uses free MISP community feeds (circl.lu). DSGVO-compliant: local-only.
 *
 * Feeds: malicious IPs, domains, file hashes. Cached in userData/threat-intel/.
 * Enrichment: O(1) Set lookup per connection — zero latency impact.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import { app } from 'electron';
import { addActivityLog } from './activityLog';

export interface IoC {
  type: 'ip' | 'domain' | 'hash';
  value: string;
  source: string;
  description?: string;
  lastSeen?: string;
}

export interface ThreatIntelConfig {
  enabled: boolean;
  autoRefreshHours: number;
  feeds: string[];
}

interface FeedCache {
  updatedAt: string;
  ips: string[];
  domains: string[];
  hashes: string[];
}

const FEED_URLS = [
  'https://bazaar.abuse.ch/export/txt/md5/recent/',
  'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
  'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
];

let _cfg: ThreatIntelConfig = {
  enabled: true,
  autoRefreshHours: 6,
  feeds: FEED_URLS,
};

let _maliciousIPs: Set<string> = new Set();
let _maliciousDomains: Set<string> = new Set();
let _maliciousHashes: Set<string> = new Set();
let _lastUpdate: string | null = null;
let _refreshTimer: ReturnType<typeof setInterval> | null = null;

function dataDir(): string { return path.join(app.getPath('userData'), 'threat-intel'); }
function cachePath(): string { return path.join(dataDir(), 'ioc-cache.json'); }
function cfgPath(): string { return path.join(dataDir(), 'config.json'); }

function ensureDir(): void {
  const d = dataDir();
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

function loadCache(): void {
  try {
    if (fs.existsSync(cachePath())) {
      const data: FeedCache = JSON.parse(fs.readFileSync(cachePath(), 'utf8'));
      _maliciousIPs = new Set(data.ips || []);
      _maliciousDomains = new Set(data.domains || []);
      _maliciousHashes = new Set(data.hashes || []);
      _lastUpdate = data.updatedAt || null;
    }
  } catch (e: any) { console.warn('[ThreatIntel] cache load failed:', e?.message); }
}

function saveCache(): void {
  try {
    ensureDir();
    const data: FeedCache = {
      updatedAt: new Date().toISOString(),
      ips: Array.from(_maliciousIPs).slice(0, 100_000),
      domains: Array.from(_maliciousDomains).slice(0, 50_000),
      hashes: Array.from(_maliciousHashes).slice(0, 50_000),
    };
    fs.writeFileSync(cachePath(), JSON.stringify(data), 'utf8');
  } catch (e: any) { console.warn('[ThreatIntel] cache save failed:', e?.message); }
}

function loadConfig(): void {
  try {
    if (fs.existsSync(cfgPath())) _cfg = { ..._cfg, ...JSON.parse(fs.readFileSync(cfgPath(), 'utf8')) };
  } catch { /* first run */ }
}

function saveConfig(): void {
  try { ensureDir(); fs.writeFileSync(cfgPath(), JSON.stringify(_cfg, null, 2), 'utf8'); } catch { /* non-fatal */ }
}

function fetchText(url: string, timeoutMs = 15000): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200) { reject(new Error(`HTTP ${res.statusCode}`)); res.resume(); return; }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (c: Buffer) => { size += c.length; if (size > 10 * 1024 * 1024) { req.destroy(); reject(new Error('Feed too large')); } chunks.push(c); });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function parseLines(text: string): string[] {
  return text.split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#') && !l.startsWith('//'));
}

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const HASH_RE = /^[a-f0-9]{32,64}$/i;

export async function refreshFeeds(): Promise<{ success: boolean; ips: number; domains: number; hashes: number; errors: string[] }> {
  const errors: string[] = [];
  const newIPs = new Set(_maliciousIPs);
  const newHashes = new Set(_maliciousHashes);

  for (const url of _cfg.feeds) {
    try {
      const text = await fetchText(url);
      const lines = parseLines(text);
      for (const line of lines) {
        const val = line.split(/\s+/)[0].trim();
        if (IP_RE.test(val)) newIPs.add(val);
        else if (HASH_RE.test(val)) newHashes.add(val);
      }
    } catch (e: any) {
      errors.push(`${url}: ${e?.message}`);
    }
  }

  _maliciousIPs = newIPs;
  _maliciousHashes = newHashes;
  _lastUpdate = new Date().toISOString();
  saveCache();

  addActivityLog('ThreatIntel', 'Feed Refresh',
    `${_maliciousIPs.size} IPs, ${_maliciousHashes.size} hashes loaded (${errors.length} errors)`,
    errors.length > 0 ? 'warning' : 'success');

  return { success: true, ips: _maliciousIPs.size, domains: _maliciousDomains.size, hashes: _maliciousHashes.size, errors };
}

export function checkIP(ip: string): { malicious: boolean; source?: string } {
  if (_maliciousIPs.has(ip)) return { malicious: true, source: 'MISP/abuse.ch' };
  return { malicious: false };
}

export function checkHash(hash: string): { malicious: boolean; source?: string } {
  if (_maliciousHashes.has(hash.toLowerCase())) return { malicious: true, source: 'MalwareBazaar' };
  return { malicious: false };
}

export function checkDomain(domain: string): { malicious: boolean; source?: string } {
  if (_maliciousDomains.has(domain.toLowerCase())) return { malicious: true, source: 'MISP' };
  return { malicious: false };
}

export function enrichConnection(remoteIP: string): { iocMatch: boolean; source?: string; threat?: string } {
  const ipCheck = checkIP(remoteIP);
  if (ipCheck.malicious) return { iocMatch: true, source: ipCheck.source, threat: 'Known malicious IP (IoC feed)' };
  return { iocMatch: false };
}

export function getStats(): { enabled: boolean; lastUpdate: string | null; ips: number; domains: number; hashes: number } {
  return { enabled: _cfg.enabled, lastUpdate: _lastUpdate, ips: _maliciousIPs.size, domains: _maliciousDomains.size, hashes: _maliciousHashes.size };
}

export function getThreatIntelConfig(): ThreatIntelConfig { return { ..._cfg }; }

export function setThreatIntelConfig(update: Partial<ThreatIntelConfig>): ThreatIntelConfig {
  _cfg = { ..._cfg, ...update };
  saveConfig();
  if (_refreshTimer) { clearInterval(_refreshTimer); _refreshTimer = null; }
  if (_cfg.enabled) startAutoRefresh();
  return { ..._cfg };
}

function startAutoRefresh(): void {
  if (_refreshTimer) clearInterval(_refreshTimer);
  if (!_cfg.enabled) return;
  const ms = _cfg.autoRefreshHours * 3600 * 1000;
  _refreshTimer = setInterval(() => { refreshFeeds().catch(() => {}); }, ms);
}

export function initThreatIntel(): void {
  loadConfig();
  loadCache();
  if (_cfg.enabled) {
    startAutoRefresh();
    if (!_lastUpdate || Date.now() - new Date(_lastUpdate).getTime() > _cfg.autoRefreshHours * 3600 * 1000) {
      setTimeout(() => refreshFeeds().catch(() => {}), 5000);
    }
  }
  console.log(`[ThreatIntel] Init — ${_maliciousIPs.size} IPs, ${_maliciousHashes.size} hashes cached`);
}

export function stopThreatIntel(): void {
  if (_refreshTimer) { clearInterval(_refreshTimer); _refreshTimer = null; }
}
