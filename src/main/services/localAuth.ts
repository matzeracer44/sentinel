/**
 * SENTINEL — Local PIN/Password Lock
 * HMAC-SHA256 challenge-response. Zero external deps. Pure Node crypto.
 * PIN hash stored locally (never plaintext). 30-min session TTL.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';

export interface LocalAuthConfig {
  enabled: boolean;
  requireOnLaunch: boolean;
  sessionTtlMs: number;
  pinHash: string | null;
  salt: string | null;
  failedAttempts: number;
  lockedUntil: number | null;
}

interface Session { token: string; expiresAt: number; }

const SESSION_TTL = 30 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 5 * 60 * 1000;

let _cfg: LocalAuthConfig = {
  enabled: false, requireOnLaunch: false, sessionTtlMs: SESSION_TTL,
  pinHash: null, salt: null, failedAttempts: 0, lockedUntil: null,
};
let _session: Session | null = null;
let _secret = crypto.randomBytes(32);

function cfgPath(): string { return path.join(app.getPath('userData'), 'auth-config.json'); }

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
  } catch (e: any) { console.warn('[LocalAuth] save failed:', e?.message); }
}

function hashPin(pin: string, salt: string): string {
  return crypto.pbkdf2Sync(pin, salt, 100_000, 64, 'sha512').toString('hex');
}

export function initLocalAuth(): void { load(); }

export function getAuthStatus(): { enabled: boolean; hasPin: boolean; requireOnLaunch: boolean; locked: boolean; sessionValid: boolean } {
  return {
    enabled: _cfg.enabled,
    hasPin: !!_cfg.pinHash,
    requireOnLaunch: _cfg.requireOnLaunch,
    locked: !!_cfg.lockedUntil && Date.now() < _cfg.lockedUntil,
    sessionValid: !!_session && Date.now() < _session.expiresAt,
  };
}

export function setPin(pin: string): { success: boolean } {
  if (!pin || pin.length < 4) throw new Error('PIN must be at least 4 characters');
  const salt = crypto.randomBytes(32).toString('hex');
  _cfg.pinHash = hashPin(pin, salt);
  _cfg.salt = salt;
  _cfg.enabled = true;
  _cfg.requireOnLaunch = true; // OSOP Zero-Trust: always re-auth on launch
  _cfg.failedAttempts = 0;
  _cfg.lockedUntil = null;
  save();
  return { success: true };
}

export function removePin(currentPin: string): { success: boolean } {
  if (!verifyPin(currentPin)) throw new Error('Current PIN incorrect');
  _cfg.pinHash = null; _cfg.salt = null; _cfg.enabled = false;
  _cfg.requireOnLaunch = false; _cfg.failedAttempts = 0; _cfg.lockedUntil = null;
  _session = null;
  save();
  return { success: true };
}

export function setRequireOnLaunch(enabled: boolean): { success: boolean; requireOnLaunch: boolean } {
  // OSOP Zero-Trust: when PIN is set, requireOnLaunch is ALWAYS true.
  // The user may only disable it if PIN itself is removed.
  _cfg.requireOnLaunch = _cfg.pinHash ? true : enabled;
  save();
  return { success: true, requireOnLaunch: _cfg.requireOnLaunch };
}

function verifyPin(pin: string): boolean {
  if (!_cfg.pinHash || !_cfg.salt) return false;
  return crypto.timingSafeEqual(
    Buffer.from(hashPin(pin, _cfg.salt), 'hex'),
    Buffer.from(_cfg.pinHash, 'hex')
  );
}

export function authenticate(pin: string): { success: boolean; token?: string; expiresAt?: number; locked?: boolean; lockRemainingMs?: number } {
  if (_cfg.lockedUntil && Date.now() < _cfg.lockedUntil) {
    return { success: false, locked: true, lockRemainingMs: _cfg.lockedUntil - Date.now() };
  }
  if (_cfg.lockedUntil && Date.now() >= _cfg.lockedUntil) {
    _cfg.lockedUntil = null; _cfg.failedAttempts = 0; save();
  }

  if (!verifyPin(pin)) {
    _cfg.failedAttempts++;
    if (_cfg.failedAttempts >= MAX_ATTEMPTS) {
      _cfg.lockedUntil = Date.now() + LOCKOUT_MS;
      save();
      return { success: false, locked: true, lockRemainingMs: LOCKOUT_MS };
    }
    save();
    throw new Error(`Wrong PIN (${MAX_ATTEMPTS - _cfg.failedAttempts} attempts left)`);
  }

  _cfg.failedAttempts = 0; _cfg.lockedUntil = null; save();
  const payload = `${Date.now()}:${crypto.randomBytes(16).toString('hex')}`;
  const token = crypto.createHmac('sha256', _secret).update(payload).digest('hex');
  _session = { token, expiresAt: Date.now() + _cfg.sessionTtlMs };
  return { success: true, token, expiresAt: _session.expiresAt };
}

export function checkSession(): { valid: boolean; expiresAt?: number } {
  if (!_cfg.enabled) return { valid: true };
  if (!_session || Date.now() > _session.expiresAt) { _session = null; return { valid: false }; }
  return { valid: true, expiresAt: _session.expiresAt };
}

export function lockNow(): void { _session = null; }

export function isAuthRequired(): boolean {
  if (!_cfg.enabled || !_cfg.pinHash) return false;
  if (_cfg.requireOnLaunch && (!_session || Date.now() > _session.expiresAt)) return true;
  return false;
}
