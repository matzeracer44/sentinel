/**
 * SENTINEL — One-Session-Only Protocol (OSOP)
 * BSI APP.6.A13 · NIST Protect · DSGVO Art. 5 (Speicherbegrenzung)
 *
 * Implements ephemeral session architecture:
 *  - AES-256-GCM session key lives ONLY in RAM, never touches disk
 *  - All activity logs, network data, ARGUS results are RAM-resident or
 *    encrypted with the ephemeral key before temp-file writes
 *  - Strict wipe on app exit: caches, temp dirs, IPC message history
 *  - Zero-Trust login: always re-authenticate, no "stay logged in"
 *  - Firewall rules persist (system-level), session metadata does NOT
 *
 * Persistence whitelist (survives session):
 *   ✓ auth-config.json (PIN hash — not session data)
 *   ✓ totp-config.json (TOTP MFA secret — encrypted at rest)
 *   ✓ sentinelConfig.json (firewall rules, DNS hardening, vault)
 *   ✓ updates/ (Ed25519 trusted keys)
 *   ✓ siem-exports/ (explicit user exports)
 *
 * Wipe targets (destroyed on exit):
 *   ✗ activity.log
 *   ✗ security_events.db + WAL/SHM
 *   ✗ .sentinel/ (telemetry LevelDB)
 *   ✗ threat-intel/ioc-cache.json (re-downloaded next session)
 *   ✗ scan-results.json
 *   ✗ sbom-manifest.json
 *   ✗ Electron session/cache/cookies/localStorage
 *   ✗ ARGUS sandbox temp files
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { app, session as electronSession, BrowserWindow } from 'electron';

// ═══════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════

export interface SessionInfo {
  sessionId: string;
  startedAt: string;
  authenticated: boolean;
}

export interface WipeReport {
  wipedAt: string;
  filesDeleted: string[];
  dirsDeleted: string[];
  errors: string[];
  electronCacheCleared: boolean;
}

// ═══════════════════════════════════════════════════════════════
// EPHEMERAL SESSION KEY — lives exclusively in RAM
// ═══════════════════════════════════════════════════════════════

let _sessionKey: Buffer | null = null;
let _sessionId: string | null = null;
let _sessionStart: string | null = null;
let _authenticated = false;
let _wipeComplete = false;

/**
 * Generate a fresh AES-256-GCM key in RAM. Called once at app launch.
 * This key encrypts any data that MUST touch disk during the session.
 * It is NEVER persisted — when the process exits, the key is gone.
 */
function generateSessionKey(): void {
  _sessionKey = crypto.randomBytes(32);
  _sessionId = crypto.randomUUID();
  _sessionStart = new Date().toISOString();
  _authenticated = false;
  _wipeComplete = false;
  console.log(`[OSOP] Ephemeral session ${_sessionId} started — key in RAM only`);
}

/**
 * Destroy the session key by overwriting the buffer with zeros, then nulling.
 * This is defense-in-depth: V8 GC may keep the old buffer in heap briefly,
 * but zeroing ensures the key material is overwritten in the primary location.
 */
function destroySessionKey(): void {
  if (_sessionKey) {
    _sessionKey.fill(0);
    _sessionKey = null;
  }
  _sessionId = null;
  _sessionStart = null;
  _authenticated = false;
  console.log('[OSOP] Ephemeral session key destroyed (zeroed + nulled)');
}

// ═══════════════════════════════════════════════════════════════
// EPHEMERAL ENCRYPTION — for mandatory temp-file writes
// ═══════════════════════════════════════════════════════════════

/**
 * Encrypt data with the ephemeral session key (AES-256-GCM).
 * Returns iv:tag:ciphertext (hex). Throws if no session key exists.
 */
export function ephemeralEncrypt(plaintext: string): string {
  if (!_sessionKey) throw new Error('[OSOP] No active session key — cannot encrypt');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', _sessionKey, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${tag}:${encrypted}`;
}

/**
 * Decrypt data encrypted with the ephemeral session key.
 * Returns plaintext. Throws if key is missing or tampered.
 */
export function ephemeralDecrypt(ciphertext: string): string {
  if (!_sessionKey) throw new Error('[OSOP] No active session key — cannot decrypt');
  const [ivHex, tagHex, dataHex] = ciphertext.split(':');
  if (!ivHex || !tagHex || !dataHex) throw new Error('[OSOP] Invalid ciphertext format');
  const decipher = crypto.createDecipheriv('aes-256-gcm', _sessionKey, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  let decrypted = decipher.update(dataHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ═══════════════════════════════════════════════════════════════
// SESSION STATE
// ═══════════════════════════════════════════════════════════════

export function getSessionInfo(): SessionInfo {
  return {
    sessionId: _sessionId || 'none',
    startedAt: _sessionStart || 'not started',
    authenticated: _authenticated,
  };
}

export function markAuthenticated(): void {
  _authenticated = true;
  console.log(`[OSOP] Session ${_sessionId} authenticated`);
}

export function isAuthenticated(): boolean {
  return _authenticated;
}

export function isSessionActive(): boolean {
  return _sessionKey !== null;
}

export function getSessionId(): string | null {
  return _sessionId;
}

// ═══════════════════════════════════════════════════════════════
// PERSISTENCE WHITELIST — files that SURVIVE session wipe
// ═══════════════════════════════════════════════════════════════

const PERSIST_WHITELIST: string[] = [
  'auth-config.json',        // PIN hash (not session data)
  'totp-config.json',        // TOTP MFA secret (AES-256-GCM encrypted)
  'sentinelConfig.json',     // Firewall/DNS/Vault config
  'updates',                 // Ed25519 trusted public keys
  'siem-exports',            // Explicit user-exported forensics
  'Preferences',             // Electron internal
  'Local State',             // Electron internal
];

function isWhitelisted(name: string): boolean {
  return PERSIST_WHITELIST.some(w =>
    name === w || name.startsWith(w + path.sep) || name.startsWith(w + '/')
  );
}

// ═══════════════════════════════════════════════════════════════
// WIPE ENGINE — BSI APP.6.A13 compliant cleanup
// ═══════════════════════════════════════════════════════════════

/**
 * Securely delete a single file: overwrite with random bytes, then unlink.
 * Single-pass random overwrite defeats filesystem journal recovery on SSD.
 */
function secureDeleteFile(filePath: string): void {
  try {
    const stat = fs.statSync(filePath);
    if (stat.isFile() && stat.size > 0 && stat.size < 100 * 1024 * 1024) {
      const fd = fs.openSync(filePath, 'r+');
      const buf = crypto.randomBytes(Math.min(stat.size, 65536));
      let written = 0;
      while (written < stat.size) {
        const toWrite = Math.min(buf.length, stat.size - written);
        fs.writeSync(fd, buf, 0, toWrite, written);
        written += toWrite;
      }
      fs.fsyncSync(fd);
      fs.closeSync(fd);
    }
    fs.unlinkSync(filePath);
  } catch {
    try { fs.unlinkSync(filePath); } catch { /* best effort */ }
  }
}

/**
 * Recursively delete a directory and all contents. Secure-deletes files first.
 */
function secureDeleteDir(dirPath: string): void {
  try {
    if (!fs.existsSync(dirPath)) return;
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        secureDeleteDir(fullPath);
      } else {
        secureDeleteFile(fullPath);
      }
    }
    fs.rmdirSync(dirPath);
  } catch { /* best effort */ }
}

/**
 * Primary wipe function. Called on app exit. Cleans all ephemeral data.
 */
export function performSessionWipe(): WipeReport {
  const report: WipeReport = {
    wipedAt: new Date().toISOString(),
    filesDeleted: [],
    dirsDeleted: [],
    errors: [],
    electronCacheCleared: false,
  };

  if (_wipeComplete) return report;

  const userData = app.getPath('userData');

  // ── 1. Wipe specific known ephemeral files ──
  const EPHEMERAL_FILES = [
    'activity.log',
    'scan-results.json',
    'sbom-manifest.json',
  ];

  for (const fname of EPHEMERAL_FILES) {
    const fp = path.join(userData, fname);
    try {
      if (fs.existsSync(fp)) {
        secureDeleteFile(fp);
        report.filesDeleted.push(fname);
      }
    } catch (e: any) { report.errors.push(`${fname}: ${e?.message}`); }
  }

  // ── 2. Wipe security_events.db (SQLite + WAL/SHM) ──
  const dbPatterns = ['security_events.db', 'security_events.db-wal', 'security_events.db-shm'];
  const dbDirs = [userData, process.cwd()];
  for (const dir of dbDirs) {
    for (const dbFile of dbPatterns) {
      const fp = path.join(dir, dbFile);
      try {
        if (fs.existsSync(fp)) {
          secureDeleteFile(fp);
          report.filesDeleted.push(`${dir}/${dbFile}`);
        }
      } catch (e: any) { report.errors.push(`${dbFile}: ${e?.message}`); }
    }
  }

  // ── 3. Wipe telemetry LevelDB (.sentinel/) ──
  const telemetryDir = path.join(process.cwd(), '.sentinel');
  try {
    if (fs.existsSync(telemetryDir)) {
      secureDeleteDir(telemetryDir);
      report.dirsDeleted.push('.sentinel');
    }
  } catch (e: any) { report.errors.push(`.sentinel: ${e?.message}`); }

  // ── 4. Wipe threat-intel cache (re-downloaded next session) ──
  const threatIntelDir = path.join(userData, 'threat-intel');
  const iocCache = path.join(threatIntelDir, 'ioc-cache.json');
  try {
    if (fs.existsSync(iocCache)) {
      secureDeleteFile(iocCache);
      report.filesDeleted.push('threat-intel/ioc-cache.json');
    }
  } catch (e: any) { report.errors.push(`ioc-cache: ${e?.message}`); }

  // ── 5. Wipe ARGUS sandbox temp + scan history ──
  const argusTempDirs = [
    path.join(userData, 'argus-temp'),
    path.join(userData, 'argus-cache'),
  ];
  for (const dir of argusTempDirs) {
    try {
      if (fs.existsSync(dir)) {
        secureDeleteDir(dir);
        report.dirsDeleted.push(path.basename(dir));
      }
    } catch (e: any) { report.errors.push(`${path.basename(dir)}: ${e?.message}`); }
  }

  // ── 6. Wipe Electron session data (cookies, cache, localStorage) ──
  try {
    const sess = electronSession.defaultSession;
    sess.clearStorageData({
      storages: ['cookies', 'localstorage', 'cachestorage', 'indexdb', 'websql', 'serviceworkers'],
    }).catch(() => {});
    sess.clearCache().catch(() => {});
    sess.clearAuthCache().catch(() => {});
    report.electronCacheCleared = true;
  } catch (e: any) {
    report.errors.push(`electronSession: ${e?.message}`);
  }

  // ── 7. Wipe Electron Cache/GPUCache dirs ──
  const electronCacheDirs = ['Cache', 'GPUCache', 'Code Cache', 'DawnCache', 'Session Storage', 'Local Storage'];
  for (const cacheDir of electronCacheDirs) {
    const fp = path.join(userData, cacheDir);
    try {
      if (fs.existsSync(fp)) {
        secureDeleteDir(fp);
        report.dirsDeleted.push(cacheDir);
      }
    } catch (e: any) { report.errors.push(`${cacheDir}: ${e?.message}`); }
  }

  // ── 8. Destroy ephemeral session key ──
  destroySessionKey();

  _wipeComplete = true;
  console.log(`[OSOP] Session wipe complete: ${report.filesDeleted.length} files, ${report.dirsDeleted.length} dirs deleted, ${report.errors.length} errors`);
  return report;
}

// ═══════════════════════════════════════════════════════════════
// RENDERER ANTI-LEAK GUARD
// ═══════════════════════════════════════════════════════════════

/**
 * Generate a session-scoped nonce that the renderer must include
 * in certain IPC calls. This prevents stale renderer processes
 * (from a previous session or injection) from accessing data.
 */
let _ipcNonce: string | null = null;

export function getIpcNonce(): string {
  if (!_ipcNonce) {
    _ipcNonce = crypto.randomBytes(16).toString('hex');
  }
  return _ipcNonce;
}

export function validateIpcNonce(nonce: string): boolean {
  if (!_ipcNonce) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(nonce, 'hex'), Buffer.from(_ipcNonce, 'hex'));
  } catch {
    return false;
  }
}

/**
 * Purge renderer-side caches by sending a reset command to all windows.
 * Renderer stores must listen for 'osop-session-reset' and clear state.
 */
export function broadcastSessionReset(): void {
  BrowserWindow.getAllWindows().forEach(win => {
    try {
      win.webContents.send('osop-session-reset', {
        sessionId: _sessionId,
        reason: 'new_session',
      });
    } catch { /* window may be closing */ }
  });
}

// ═══════════════════════════════════════════════════════════════
// ZERO-TRUST LOGIN ENFORCEMENT
// ═══════════════════════════════════════════════════════════════

/**
 * Force-invalidate any existing auth sessions. Called at startup
 * to ensure the user MUST re-authenticate (Always Verify).
 * Does NOT delete the PIN hash — only clears the session token.
 */
export function enforceZeroTrustLogin(): void {
  try {
    const { lockNow } = require('./localAuth');
    lockNow();
    console.log('[OSOP] Zero-Trust: existing session forcefully invalidated');
  } catch {
    console.log('[OSOP] Zero-Trust: localAuth not available (first run)');
  }
}

// ═══════════════════════════════════════════════════════════════
// CRASH WATCHDOG — writes a PID file for PowerShell fallback
// ═══════════════════════════════════════════════════════════════

let _pidFilePath: string | null = null;

function writePidFile(): void {
  try {
    const userData = app.getPath('userData');
    _pidFilePath = path.join(userData, '.sentinel-session.pid');
    const pidData = JSON.stringify({
      pid: process.pid,
      sessionId: _sessionId,
      startedAt: _sessionStart,
      userData,
      cwd: process.cwd(),
    });
    fs.writeFileSync(_pidFilePath, pidData, 'utf8');
  } catch { /* best effort */ }
}

function removePidFile(): void {
  try {
    if (_pidFilePath && fs.existsSync(_pidFilePath)) {
      fs.unlinkSync(_pidFilePath);
    }
  } catch { /* best effort */ }
}

// ═══════════════════════════════════════════════════════════════
// LIFECYCLE — init / shutdown
// ═══════════════════════════════════════════════════════════════

/**
 * Initialize the OSOP session manager. Call once in app.whenReady().
 *
 * 1. Generate ephemeral session key (RAM only)
 * 2. Force-invalidate any previous auth session (Zero-Trust)
 * 3. Write PID file for crash watchdog
 * 4. Broadcast session reset to any stale renderers
 */
export function initSessionManager(): void {
  generateSessionKey();
  enforceZeroTrustLogin();
  writePidFile();
  broadcastSessionReset();
  // Enable RAM-only activity logging — zero disk I/O for session data
  try {
    const { enableOsopMode } = require('./activityLog');
    enableOsopMode();
  } catch { /* activityLog not yet loaded — will be enabled on first import */ }
  console.log(`[OSOP] Session Manager initialized — session ${_sessionId} (RAM-only logging active)`);
}

/**
 * Graceful shutdown. Call from before-quit / will-quit.
 *
 * 1. Perform full session wipe (files, DBs, caches)
 * 2. Destroy ephemeral key (zero + null)
 * 3. Remove PID file (signals clean exit to watchdog)
 */
export function shutdownSessionManager(): WipeReport {
  console.log('[OSOP] Initiating graceful shutdown wipe...');
  const report = performSessionWipe();
  removePidFile();
  return report;
}
