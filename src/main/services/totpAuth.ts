/**
 * SENTINEL — TOTP Multi-Factor Authentication
 * RFC 6238 compliant TOTP implementation. Zero external deps — pure Node crypto.
 * Generates secrets, produces QR-code-compatible URIs, verifies 6-digit codes.
 * Stored alongside PIN config in auth-config.json. DSGVO Art.32 compliant.
 *
 * Window: ±1 step (30s each) to tolerate clock drift.
 * Secret: 20 random bytes, Base32 encoded, stored encrypted with machine key.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';
import { addActivityLog } from './activityLog';

// ── Base32 Encoder/Decoder (RFC 4648) ──
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_CHARS[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(str: string): Buffer {
  const cleaned = str.replace(/[=\s]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  for (const ch of cleaned) {
    const idx = BASE32_CHARS.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

// ── TOTP Core (RFC 6238) ──
function generateHOTP(secret: Buffer, counter: bigint): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(counter);
  const hmac = crypto.createHmac('sha1', secret).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, '0');
}

function generateTOTP(secret: Buffer, timeStepSeconds = 30): string {
  const counter = BigInt(Math.floor(Date.now() / 1000 / timeStepSeconds));
  return generateHOTP(secret, counter);
}

function verifyTOTP(secret: Buffer, token: string, window = 1, timeStepSeconds = 30): boolean {
  const counter = BigInt(Math.floor(Date.now() / 1000 / timeStepSeconds));
  for (let i = -window; i <= window; i++) {
    if (generateHOTP(secret, counter + BigInt(i)) === token) return true;
  }
  return false;
}

// ── Config Persistence ──
export interface TotpConfig {
  enabled: boolean;
  secret: string | null;  // Base32-encoded, encrypted at rest with machine key
  issuer: string;
  label: string;
  verifiedAt: string | null;
  backupCodes: string[];  // hashed backup codes
}

let _cfg: TotpConfig = {
  enabled: false,
  secret: null,
  issuer: 'Sentinel Security Suite',
  label: 'vault@sentinel',
  verifiedAt: null,
  backupCodes: [],
};

function cfgPath(): string {
  return path.join(app.getPath('userData'), 'totp-config.json');
}

function getMachineKey(): Buffer {
  const machineId = `${process.env.COMPUTERNAME || 'sentinel'}-${process.env.USERNAME || 'user'}-totp-v1`;
  return crypto.createHash('sha256').update(machineId).digest();
}

function encryptSecret(plainBase32: string): string {
  const key = getMachineKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let enc = cipher.update(plainBase32, 'utf8', 'hex');
  enc += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc;
}

function decryptSecret(encrypted: string): string {
  const parts = encrypted.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted secret format');
  const key = getMachineKey();
  const iv = Buffer.from(parts[0], 'hex');
  const tag = Buffer.from(parts[1], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let dec = decipher.update(parts[2], 'hex', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}

function load(): void {
  try {
    const p = cfgPath();
    if (fs.existsSync(p)) _cfg = { ..._cfg, ...JSON.parse(fs.readFileSync(p, 'utf8')) };
  } catch { /* first run */ }
}

function save(): void {
  try {
    const dir = path.dirname(cfgPath());
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(cfgPath(), JSON.stringify(_cfg, null, 2), 'utf8');
  } catch (e: any) { console.warn('[TotpAuth] save failed:', e?.message); }
}

// ── Public API ──

export function initTotpAuth(): void {
  load();
}

export function getTotpStatus(): { enabled: boolean; configured: boolean; verifiedAt: string | null; backupCodesRemaining: number } {
  return {
    enabled: _cfg.enabled,
    configured: !!_cfg.secret,
    verifiedAt: _cfg.verifiedAt,
    backupCodesRemaining: _cfg.backupCodes.length,
  };
}

export function setupTotp(): { success: boolean; secret: string; uri: string; qrData: string } {
  const secretBytes = crypto.randomBytes(20);
  const secretBase32 = base32Encode(secretBytes);

  // Store encrypted
  _cfg.secret = encryptSecret(secretBase32);
  _cfg.enabled = false; // Not enabled until verified
  _cfg.verifiedAt = null;
  save();

  const uri = `otpauth://totp/${encodeURIComponent(_cfg.label)}?secret=${secretBase32}&issuer=${encodeURIComponent(_cfg.issuer)}&algorithm=SHA1&digits=6&period=30`;

  addActivityLog('TotpAuth', 'setup', 'TOTP secret generated — awaiting verification');

  return {
    success: true,
    secret: secretBase32,
    uri,
    qrData: uri, // Can be used to generate QR code client-side
  };
}

export function verifyAndEnableTotp(token: string): { success: boolean; backupCodes?: string[] } {
  if (!_cfg.secret) throw new Error('TOTP not configured — run setup first');

  const secretBase32 = decryptSecret(_cfg.secret);
  const secretBuffer = base32Decode(secretBase32);

  if (!verifyTOTP(secretBuffer, token)) {
    throw new Error('Invalid TOTP code — ensure your authenticator app clock is synced');
  }

  // Generate 8 backup codes
  const rawBackupCodes: string[] = [];
  const hashedBackupCodes: string[] = [];
  for (let i = 0; i < 8; i++) {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    rawBackupCodes.push(code);
    hashedBackupCodes.push(crypto.createHash('sha256').update(code).digest('hex'));
  }

  _cfg.enabled = true;
  _cfg.verifiedAt = new Date().toISOString();
  _cfg.backupCodes = hashedBackupCodes;
  save();

  addActivityLog('TotpAuth', 'enable', 'TOTP MFA enabled and verified — 8 backup codes generated');

  return { success: true, backupCodes: rawBackupCodes };
}

export function verifyTotpCode(token: string): { success: boolean; method: 'totp' | 'backup' } {
  if (!_cfg.enabled || !_cfg.secret) throw new Error('TOTP not enabled');

  // Try TOTP first
  const secretBase32 = decryptSecret(_cfg.secret);
  const secretBuffer = base32Decode(secretBase32);

  if (verifyTOTP(secretBuffer, token)) {
    return { success: true, method: 'totp' };
  }

  // Try backup codes
  const tokenHash = crypto.createHash('sha256').update(token.toUpperCase()).digest('hex');
  const idx = _cfg.backupCodes.indexOf(tokenHash);
  if (idx !== -1) {
    _cfg.backupCodes.splice(idx, 1); // One-time use
    save();
    addActivityLog('TotpAuth', 'backup-used', `Backup code used — ${_cfg.backupCodes.length} remaining`);
    return { success: true, method: 'backup' };
  }

  throw new Error('Invalid TOTP code or backup code');
}

export function disableTotp(totpToken: string): { success: boolean } {
  if (!_cfg.enabled || !_cfg.secret) throw new Error('TOTP not enabled');

  // Require valid TOTP to disable
  const secretBase32 = decryptSecret(_cfg.secret);
  const secretBuffer = base32Decode(secretBase32);

  if (!verifyTOTP(secretBuffer, totpToken)) {
    throw new Error('Invalid TOTP code — cannot disable without valid code');
  }

  _cfg.enabled = false;
  _cfg.secret = null;
  _cfg.verifiedAt = null;
  _cfg.backupCodes = [];
  save();

  addActivityLog('TotpAuth', 'disable', 'TOTP MFA disabled');
  return { success: true };
}

// ── Exports for testing ──
export const _testing = {
  base32Encode,
  base32Decode,
  generateTOTP,
  verifyTOTP,
  generateHOTP,
};
