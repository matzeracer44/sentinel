/**
 * SENTINEL — File Integrity Monitoring (FIM)
 * Monitors critical system paths for changes using periodic hash comparison.
 * Watches: System32, hosts file, Registry hives, Startup folders
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { app } from 'electron';
import { addActivityLog } from './activityLog';

export interface FimConfig {
  enabled: boolean;
  paths: string[];
  pollIntervalMs: number;
}

export interface FimChange {
  id: string;
  filePath: string;
  changeType: 'modified' | 'created' | 'deleted';
  detectedAt: string;
  previousHash?: string;
  currentHash?: string;
  sizeBytes?: number;
  risk: 'low' | 'medium' | 'high' | 'critical';
  manipulation?: ManipulationIndicator;
}

export interface ManipulationIndicator {
  type: 'entropy-spike' | 'micro-edit' | 'mass-modify' | 'none';
  confidence: number;
  detail: string;
}

interface BaselineEntry {
  path: string;
  hash: string;
  size: number;
  mtime: string;
  entropy?: number;
}

const DEFAULT_WATCHED_PATHS = [
  'C:\\Windows\\System32\\drivers\\etc\\hosts',
  'C:\\Windows\\System32\\config\\SAM',
  'C:\\Windows\\System32\\config\\SYSTEM',
  'C:\\Windows\\System32\\config\\SOFTWARE',
];

const DEFAULT_WATCHED_DIRS = [
  { dir: 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp', ext: '*' },
];

let _config: FimConfig = {
  enabled: true,
  paths: [...DEFAULT_WATCHED_PATHS],
  pollIntervalMs: 60000,
};

let _baseline: Map<string, BaselineEntry> = new Map();
let _changes: FimChange[] = [];
let _pollTimer: ReturnType<typeof setInterval> | null = null;

const _dataDir = () => {
  try { return path.join(app.getPath('userData'), 'fim'); } catch { return ''; }
};
const _baselinePath = () => path.join(_dataDir(), 'baseline.json');
const _changesPath = () => path.join(_dataDir(), 'changes.json');
const _configPath = () => path.join(_dataDir(), 'config.json');

function hashFile(filePath: string): string {
  try {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
  } catch {
    return '';
  }
}

function calcEntropy(filePath: string): number {
  try {
    const buf = fs.readFileSync(filePath);
    if (buf.length === 0) return 0;
    const freq = new Uint32Array(256);
    for (let i = 0; i < buf.length; i++) freq[buf[i]]++;
    let ent = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] === 0) continue;
      const p = freq[i] / buf.length;
      ent -= p * Math.log2(p);
    }
    return Math.round(ent * 1000) / 1000;
  } catch { return 0; }
}

let _recentModCount = 0;
let _recentModWindow = 0;
const MASS_MODIFY_THRESHOLD = 5;
const MASS_MODIFY_WINDOW_MS = 10_000;
const ENTROPY_SPIKE_THRESHOLD = 1.5;

function detectManipulation(
  fp: string, existing: BaselineEntry | undefined, currentSize: number
): ManipulationIndicator {
  if (!existing) return { type: 'none', confidence: 0, detail: '' };

  const now = Date.now();
  if (now - _recentModWindow > MASS_MODIFY_WINDOW_MS) {
    _recentModCount = 0; _recentModWindow = now;
  }
  _recentModCount++;

  if (_recentModCount >= MASS_MODIFY_THRESHOLD) {
    return {
      type: 'mass-modify',
      confidence: Math.min(0.95, 0.5 + _recentModCount * 0.05),
      detail: `${_recentModCount} files modified within ${MASS_MODIFY_WINDOW_MS / 1000}s — possible ransomware`,
    };
  }

  const oldEntropy = existing.entropy ?? 0;
  if (oldEntropy > 0) {
    const newEntropy = calcEntropy(fp);
    const delta = newEntropy - oldEntropy;
    if (delta > ENTROPY_SPIKE_THRESHOLD) {
      return {
        type: 'entropy-spike',
        confidence: Math.min(0.95, 0.4 + delta * 0.15),
        detail: `Entropy jumped ${oldEntropy.toFixed(2)} → ${newEntropy.toFixed(2)} (+${delta.toFixed(2)}) — possible encryption`,
      };
    }
  }

  const sizeDelta = Math.abs(currentSize - existing.size);
  if (sizeDelta > 0 && sizeDelta < 512 && existing.size > 1024) {
    return {
      type: 'micro-edit',
      confidence: 0.3,
      detail: `Subtle ${sizeDelta}B change in ${(existing.size / 1024).toFixed(1)}KB file — possible data poisoning`,
    };
  }

  return { type: 'none', confidence: 0, detail: '' };
}

function assessRisk(filePath: string, changeType: string): FimChange['risk'] {
  const lower = filePath.toLowerCase();
  if (lower.includes('\\drivers\\etc\\hosts')) return 'critical';
  if (lower.includes('\\config\\sam') || lower.includes('\\config\\system')) return 'critical';
  if (lower.includes('\\config\\software')) return 'high';
  if (lower.includes('startup')) return 'high';
  if (changeType === 'deleted') return 'high';
  return 'medium';
}

function expandPaths(): string[] {
  const files: string[] = [];

  for (const p of _config.paths) {
    if (fs.existsSync(p)) {
      const stat = fs.statSync(p);
      if (stat.isFile()) {
        files.push(p);
      } else if (stat.isDirectory()) {
        try {
          const entries = fs.readdirSync(p);
          for (const e of entries) {
            const fp = path.join(p, e);
            try { if (fs.statSync(fp).isFile()) files.push(fp); } catch { /* stat may fail for locked/deleted files */ }
          }
        } catch { /* dir may be inaccessible */ }
      }
    }
  }

  for (const wd of DEFAULT_WATCHED_DIRS) {
    if (fs.existsSync(wd.dir)) {
      try {
        const entries = fs.readdirSync(wd.dir);
        for (const e of entries) {
          const fp = path.join(wd.dir, e);
          try { if (fs.statSync(fp).isFile()) files.push(fp); } catch { /* stat may fail for locked/deleted files */ }
        }
      } catch { /* dir may be inaccessible */ }
    }
  }

  return [...new Set(files)];
}

function saveBaseline(): void {
  try {
    const dir = _dataDir();
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const arr = Array.from(_baseline.values());
    fs.writeFileSync(_baselinePath(), JSON.stringify(arr, null, 2), 'utf8');
  } catch (e: any) { console.warn('[FIM] Failed to save baseline:', e?.message); }
}

function loadBaseline(): void {
  try {
    if (fs.existsSync(_baselinePath())) {
      const arr: BaselineEntry[] = JSON.parse(fs.readFileSync(_baselinePath(), 'utf8'));
      _baseline.clear();
      for (const e of arr) _baseline.set(e.path, e);
    }
  } catch (e: any) { console.warn('[FIM] Failed to load baseline:', e?.message); }
}

function saveChanges(): void {
  try {
    const dir = _dataDir();
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(_changesPath(), JSON.stringify(_changes.slice(-500), null, 2), 'utf8');
  } catch (e: any) { console.warn('[FIM] Failed to save changes:', e?.message); }
}

function loadChanges(): void {
  try {
    if (fs.existsSync(_changesPath())) {
      _changes = JSON.parse(fs.readFileSync(_changesPath(), 'utf8'));
    }
  } catch { _changes = []; }
}

function loadConfig(): void {
  try {
    if (fs.existsSync(_configPath())) {
      const saved = JSON.parse(fs.readFileSync(_configPath(), 'utf8'));
      _config = { ..._config, ...saved };
    }
  } catch (e: any) { console.warn('[FIM] Failed to load config:', e?.message); }
}

function saveConfig(): void {
  try {
    const dir = _dataDir();
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(_configPath(), JSON.stringify(_config, null, 2), 'utf8');
  } catch (e: any) { console.warn('[FIM] Failed to save config:', e?.message); }
}

/**
 * Run a single integrity check cycle
 */
export function runCheck(): FimChange[] {
  const newChanges: FimChange[] = [];
  const files = expandPaths();
  const seen = new Set<string>();

  for (const fp of files) {
    seen.add(fp);
    const hash = hashFile(fp);
    if (!hash) continue;

    let size = 0;
    let mtime = '';
    try {
      const stat = fs.statSync(fp);
      size = stat.size;
      mtime = stat.mtime.toISOString();
    } catch { /* file may have been deleted between scan and stat */ }

    const existing = _baseline.get(fp);

    if (!existing) {
      // New file
      const change: FimChange = {
        id: `fim-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        filePath: fp,
        changeType: 'created',
        detectedAt: new Date().toISOString(),
        currentHash: hash,
        sizeBytes: size,
        risk: assessRisk(fp, 'created'),
      };
      newChanges.push(change);
      _baseline.set(fp, { path: fp, hash, size, mtime });
    } else if (existing.hash !== hash) {
      // Modified — run Ransomware 3.0 manipulation detection
      const manip = detectManipulation(fp, existing, size);
      const baseRisk = assessRisk(fp, 'modified');
      const escalatedRisk = manip.type !== 'none' && manip.confidence > 0.5
        ? 'critical' : baseRisk;
      const change: FimChange = {
        id: `fim-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        filePath: fp,
        changeType: 'modified',
        detectedAt: new Date().toISOString(),
        previousHash: existing.hash,
        currentHash: hash,
        sizeBytes: size,
        risk: escalatedRisk,
        manipulation: manip.type !== 'none' ? manip : undefined,
      };
      newChanges.push(change);
      const ent = calcEntropy(fp);
      _baseline.set(fp, { path: fp, hash, size, mtime, entropy: ent });
    }
  }

  // Check for deleted files
  for (const [fp] of _baseline) {
    if (!seen.has(fp) && !fs.existsSync(fp)) {
      const change: FimChange = {
        id: `fim-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        filePath: fp,
        changeType: 'deleted',
        detectedAt: new Date().toISOString(),
        previousHash: _baseline.get(fp)?.hash,
        risk: assessRisk(fp, 'deleted'),
      };
      newChanges.push(change);
      _baseline.delete(fp);
    }
  }

  if (newChanges.length > 0) {
    _changes.push(...newChanges);
    saveBaseline();
    saveChanges();
    for (const c of newChanges) {
      addActivityLog('FIM', 'File Change', `${c.changeType}: ${c.filePath} [${c.risk}]`, c.risk === 'critical' ? 'error' : 'warning');
    }
  }

  return newChanges;
}

/**
 * Initialize FIM: load state, create baseline if needed, start polling
 */
export function initFim(): void {
  loadConfig();
  loadBaseline();
  loadChanges();

  if (_baseline.size === 0) {
    // Create initial baseline
    const files = expandPaths();
    for (const fp of files) {
      const hash = hashFile(fp);
      if (!hash) continue;
      try {
        const stat = fs.statSync(fp);
        const ent = calcEntropy(fp);
        _baseline.set(fp, { path: fp, hash, size: stat.size, mtime: stat.mtime.toISOString(), entropy: ent });
      } catch { /* file may vanish between hash and stat */ }
    }
    saveBaseline();
  }

  startPolling();
}

export function startPolling(): void {
  if (_pollTimer) clearInterval(_pollTimer);
  if (!_config.enabled) return;
  _pollTimer = setInterval(() => runCheck(), _config.pollIntervalMs);
}

export function stopPolling(): void {
  if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
}

export function getConfig(): FimConfig {
  return { ..._config };
}

export function setConfig(update: Partial<FimConfig>): FimConfig {
  _config = { ..._config, ...update };
  saveConfig();
  if (_pollTimer) { stopPolling(); startPolling(); }
  return _config;
}

export function getChanges(): FimChange[] {
  return [..._changes];
}

export function getBaseline(): BaselineEntry[] {
  return Array.from(_baseline.values());
}

export function resetBaseline(): void {
  _baseline.clear();
  const files = expandPaths();
  for (const fp of files) {
    const hash = hashFile(fp);
    if (!hash) continue;
    try {
      const stat = fs.statSync(fp);
      const ent = calcEntropy(fp);
      _baseline.set(fp, { path: fp, hash, size: stat.size, mtime: stat.mtime.toISOString(), entropy: ent });
    } catch { /* file may vanish between hash and stat */ }
  }
  saveBaseline();
  _changes = [];
  saveChanges();
}
