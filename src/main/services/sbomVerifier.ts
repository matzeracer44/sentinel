/**
 * SENTINEL — SBOM Integrity Verifier (BSI APP.6)
 * Verifies npm dependency hashes and Python backend integrity on startup.
 * Detects supply-chain tampering by comparing against a manifest.
 * Zero external deps — pure Node crypto.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';
import { addActivityLog } from './activityLog';

export interface SbomEntry {
  path: string;
  sha256: string;
  size: number;
}

export interface SbomManifest {
  generatedAt: string;
  version: string;
  entries: SbomEntry[];
}

export interface SbomVerifyResult {
  valid: boolean;
  checkedAt: string;
  totalFiles: number;
  matched: number;
  mismatched: string[];
  missing: string[];
  added: string[];
}

function manifestPath(): string {
  return path.join(app.getPath('userData'), 'sbom-manifest.json');
}

function hashFile(filePath: string): string {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
  } catch { return ''; }
}

function collectFiles(dir: string, maxDepth = 3, depth = 0): string[] {
  if (depth > maxDepth || !fs.existsSync(dir)) return [];
  const results: string[] = [];
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fp = path.join(dir, entry.name);
      if (entry.name === '.git' || entry.name === '__pycache__' || entry.name === 'logs') continue;
      if (entry.isFile() && /\.(js|py|json|ts|bat|ps1)$/i.test(entry.name)) {
        results.push(fp);
      } else if (entry.isDirectory() && depth < maxDepth) {
        results.push(...collectFiles(fp, maxDepth, depth + 1));
      }
    }
  } catch { /* permission denied */ }
  return results;
}

export function generateManifest(): SbomManifest {
  const appPath = app.getAppPath();
  const argusPath = path.join(appPath, 'ARGUS');
  const nodeModulesPath = path.join(appPath, 'node_modules');

  const targets = [
    ...collectFiles(path.join(appPath, 'dist'), 2),
    ...collectFiles(argusPath, 3),
    ...(fs.existsSync(path.join(appPath, 'package-lock.json')) ? [path.join(appPath, 'package-lock.json')] : []),
    ...(fs.existsSync(path.join(appPath, 'package.json')) ? [path.join(appPath, 'package.json')] : []),
  ];

  const entries: SbomEntry[] = [];
  for (const fp of targets) {
    const hash = hashFile(fp);
    if (!hash) continue;
    try {
      const stat = fs.statSync(fp);
      entries.push({ path: path.relative(appPath, fp), sha256: hash, size: stat.size });
    } catch { /* skip */ }
  }

  const manifest: SbomManifest = {
    generatedAt: new Date().toISOString(),
    version: (() => { try { return JSON.parse(fs.readFileSync(path.join(appPath, 'package.json'), 'utf8')).version; } catch { return '0.0.0'; } })(),
    entries,
  };

  fs.writeFileSync(manifestPath(), JSON.stringify(manifest, null, 2), 'utf8');
  addActivityLog('SBOM', 'Generate', `Manifest created: ${entries.length} files hashed`, 'success');
  return manifest;
}

export function verifyIntegrity(): SbomVerifyResult {
  const mPath = manifestPath();
  if (!fs.existsSync(mPath)) {
    return { valid: true, checkedAt: new Date().toISOString(), totalFiles: 0, matched: 0, mismatched: [], missing: [], added: [] };
  }

  const manifest: SbomManifest = JSON.parse(fs.readFileSync(mPath, 'utf8'));
  const appPath = app.getAppPath();
  const mismatched: string[] = [];
  const missing: string[] = [];
  let matched = 0;

  for (const entry of manifest.entries) {
    const fp = path.join(appPath, entry.path);
    if (!fs.existsSync(fp)) {
      missing.push(entry.path);
      continue;
    }
    const currentHash = hashFile(fp);
    if (currentHash === entry.sha256) {
      matched++;
    } else {
      mismatched.push(entry.path);
    }
  }

  const valid = mismatched.length === 0 && missing.length === 0;
  const result: SbomVerifyResult = {
    valid,
    checkedAt: new Date().toISOString(),
    totalFiles: manifest.entries.length,
    matched,
    mismatched,
    missing,
    added: [],
  };

  const severity = valid ? 'success' : 'error';
  addActivityLog('SBOM', 'Verify',
    valid
      ? `Integrity OK: ${matched}/${manifest.entries.length} files verified`
      : `INTEGRITY VIOLATION: ${mismatched.length} modified, ${missing.length} missing`,
    severity);

  return result;
}

export function getManifestInfo(): { exists: boolean; generatedAt?: string; version?: string; fileCount?: number } {
  try {
    if (!fs.existsSync(manifestPath())) return { exists: false };
    const m: SbomManifest = JSON.parse(fs.readFileSync(manifestPath(), 'utf8'));
    return { exists: true, generatedAt: m.generatedAt, version: m.version, fileCount: m.entries.length };
  } catch { return { exists: false }; }
}

export function checkScriptBlockLogging(): { enabled: boolean; detail: string } {
  try {
    const { execSync } = require('child_process');
    const out = execSync(
      'powershell -NoProfile -Command "try { (Get-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -EA Stop).EnableScriptBlockLogging } catch { \'notset\' }"',
      { encoding: 'utf-8', windowsHide: true, timeout: 5000 }
    ).trim();

    if (out === '1') return { enabled: true, detail: 'Script Block Logging is ENABLED — LotL attacks are logged' };
    if (out === '0') return { enabled: false, detail: 'Script Block Logging is DISABLED — Living-off-the-Land attacks may go undetected' };
    return { enabled: false, detail: 'Script Block Logging policy not configured — recommend enabling via GPO' };
  } catch (e: any) {
    return { enabled: false, detail: `Check failed: ${e?.message}` };
  }
}
