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
}

interface BaselineEntry {
  path: string;
  hash: string;
  size: number;
  mtime: string;
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
      // Modified
      const change: FimChange = {
        id: `fim-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        filePath: fp,
        changeType: 'modified',
        detectedAt: new Date().toISOString(),
        previousHash: existing.hash,
        currentHash: hash,
        sizeBytes: size,
        risk: assessRisk(fp, 'modified'),
      };
      newChanges.push(change);
      _baseline.set(fp, { path: fp, hash, size, mtime });
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
        _baseline.set(fp, { path: fp, hash, size: stat.size, mtime: stat.mtime.toISOString() });
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
      _baseline.set(fp, { path: fp, hash, size: stat.size, mtime: stat.mtime.toISOString() });
    } catch { /* file may vanish between hash and stat */ }
  }
  saveBaseline();
  _changes = [];
  saveChanges();
}
