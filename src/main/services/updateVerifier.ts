/**
 * SENTINEL — Cryptographic Update Signature Verifier (BSI APP.6.A4)
 * Ed25519 verify-only. Zero external deps. Prevents supply-chain attacks.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';

export interface UpdateManifest {
  version: string;
  channel: 'stable' | 'beta';
  sha256: string;
  fileSize: number;
  releaseDate: string;
  minVersion: string;
  signature: string;
  publicKeyId: string;
}

export interface VerifyResult {
  valid: boolean;
  version: string;
  errors: string[];
  warnings: string[];
  checkedAt: string;
}

interface TrustedKey { id: string; pem: string; }

const CURRENT_VERSION = (() => {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(app.getAppPath(), 'package.json'), 'utf8'));
    return pkg.version || '0.0.0';
  } catch { return '0.0.0'; }
})();

let _trustedKeys: TrustedKey[] = [];
let _history: VerifyResult[] = [];

function keysPath(): string { return path.join(app.getPath('userData'), 'updates', 'trusted-keys.json'); }
function histPath(): string { return path.join(app.getPath('userData'), 'updates', 'verify-history.json'); }

function ensureDir(): void {
  const d = path.join(app.getPath('userData'), 'updates');
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

export function initUpdateVerifier(): void {
  try { if (fs.existsSync(keysPath())) _trustedKeys = JSON.parse(fs.readFileSync(keysPath(), 'utf8')); } catch { /* first run */ }
  try { if (fs.existsSync(histPath())) _history = JSON.parse(fs.readFileSync(histPath(), 'utf8')); } catch { _history = []; }
}

export function addTrustedKey(id: string, pem: string): { success: boolean } {
  if (_trustedKeys.some(k => k.id === id)) throw new Error(`Key ${id} already trusted`);
  _trustedKeys.push({ id, pem });
  ensureDir();
  fs.writeFileSync(keysPath(), JSON.stringify(_trustedKeys, null, 2), 'utf8');
  return { success: true };
}

export function listTrustedKeys(): Array<{ id: string }> {
  return _trustedKeys.map(k => ({ id: k.id }));
}

export function removeTrustedKey(id: string): boolean {
  const i = _trustedKeys.findIndex(k => k.id === id);
  if (i === -1) return false;
  _trustedKeys.splice(i, 1);
  ensureDir();
  fs.writeFileSync(keysPath(), JSON.stringify(_trustedKeys, null, 2), 'utf8');
  return true;
}

function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); }
  return 0;
}

export function verifyManifest(manifest: UpdateManifest): VerifyResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!manifest.version) errors.push('Missing version');
  if (!manifest.sha256) errors.push('Missing SHA-256 hash');
  if (!manifest.signature) errors.push('Missing signature');
  if (!manifest.publicKeyId) errors.push('Missing publicKeyId');

  if (manifest.version && compareVersions(manifest.version, CURRENT_VERSION) <= 0) {
    errors.push(`Rollback rejected: ${manifest.version} <= current ${CURRENT_VERSION}`);
  }

  if (manifest.minVersion && compareVersions(CURRENT_VERSION, manifest.minVersion) < 0) {
    warnings.push(`Current version ${CURRENT_VERSION} < minVersion ${manifest.minVersion}`);
  }

  const key = _trustedKeys.find(k => k.id === manifest.publicKeyId);
  if (!key) {
    errors.push(`Untrusted key: ${manifest.publicKeyId}`);
  } else if (manifest.signature && manifest.sha256) {
    try {
      const signedPayload = `${manifest.version}:${manifest.sha256}:${manifest.channel}:${manifest.releaseDate}`;
      const isValid = crypto.verify(
        null,
        Buffer.from(signedPayload, 'utf8'),
        { key: key.pem, format: 'pem', type: 'spki' },
        Buffer.from(manifest.signature, 'base64')
      );
      if (!isValid) errors.push('Signature verification FAILED — possible tampering');
    } catch (e: any) {
      errors.push(`Signature check error: ${e?.message}`);
    }
  }

  const result: VerifyResult = {
    valid: errors.length === 0,
    version: manifest.version || 'unknown',
    errors, warnings,
    checkedAt: new Date().toISOString(),
  };

  _history.push(result);
  if (_history.length > 50) _history.splice(0, _history.length - 50);
  try { ensureDir(); fs.writeFileSync(histPath(), JSON.stringify(_history, null, 2), 'utf8'); } catch { /* non-fatal */ }

  return result;
}

export function verifyFileHash(filePath: string, expectedSha256: string): boolean {
  const hash = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
  return hash.toLowerCase() === expectedSha256.toLowerCase();
}

export function getVerifyHistory(): VerifyResult[] { return [..._history]; }

export function generateSigningKeyPair(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) as string,
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
  };
}
