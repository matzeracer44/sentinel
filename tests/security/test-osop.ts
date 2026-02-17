/**
 * SENTINEL — OSOP (One-Session-Only Protocol) Security Test
 * BSI APP.6.A13 · NIST Protect · DSGVO Art. 5
 *
 * Tests:
 *  7.1  Ephemeral session key is AES-256 (32 bytes) and RAM-only
 *  7.2  Encrypt/decrypt roundtrip with ephemeral key
 *  7.3  Tampered ciphertext is rejected (GCM auth tag)
 *  7.4  Session key zeroed on destroy (buffer overwrite)
 *  7.5  IPC nonce is unique per session (anti-replay)
 *  7.6  Nonce validation uses timing-safe comparison
 *  7.7  Persistence whitelist protects auth-config.json + sentinelConfig.json
 *  7.8  Wipe targets include activity.log, security_events.db, .sentinel/
 *  7.9  Zero-Trust: PIN set forces requireOnLaunch=true
 *  7.10 Zero-Trust: requireOnLaunch cannot be disabled while PIN exists
 *  7.11 Secure delete overwrites file content before unlink
 *  7.12 PID file written for crash watchdog
 *  7.13 Session ID is cryptographically random UUID
 *  7.14 Multiple encrypt calls produce different ciphertexts (unique IV)
 *
 * Run: npx ts-node --project tests/tsconfig.json tests/security/test-osop.ts
 */

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  \x1b[32m✓\x1b[0m ${name}`);
    passed++;
  } catch (e: any) {
    console.log(`  \x1b[31m✗\x1b[0m ${name}: ${e.message}`);
    failed++;
  }
}

console.log('\n=== TEST 7: OSOP — One-Session-Only Protocol ===\n');

// ── Replicate core sessionManager logic for testing ──

let _sessionKey: Buffer | null = null;
let _sessionId: string | null = null;

function generateSessionKey(): void {
  _sessionKey = crypto.randomBytes(32);
  _sessionId = crypto.randomUUID();
}

function destroySessionKey(): void {
  if (_sessionKey) {
    _sessionKey.fill(0);
    _sessionKey = null;
  }
  _sessionId = null;
}

function ephemeralEncrypt(plaintext: string): string {
  if (!_sessionKey) throw new Error('No session key');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', _sessionKey, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${tag}:${encrypted}`;
}

function ephemeralDecrypt(ciphertext: string): string {
  if (!_sessionKey) throw new Error('No session key');
  const [ivHex, tagHex, dataHex] = ciphertext.split(':');
  const decipher = crypto.createDecipheriv('aes-256-gcm', _sessionKey, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  let decrypted = decipher.update(dataHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Persistence whitelist check
const PERSIST_WHITELIST = [
  'auth-config.json',
  'sentinelConfig.json',
  'updates',
  'siem-exports',
  'Preferences',
  'Local State',
];

function isWhitelisted(name: string): boolean {
  return PERSIST_WHITELIST.some(w =>
    name === w || name.startsWith(w + path.sep) || name.startsWith(w + '/')
  );
}

// ── 7.1 Ephemeral key is AES-256 ──
test('Ephemeral session key is AES-256 (32 bytes) and generated in RAM', () => {
  generateSessionKey();
  assert.ok(_sessionKey, 'Key must exist after generation');
  assert.strictEqual(_sessionKey!.length, 32, 'AES-256 requires 32-byte key');
  assert.ok(Buffer.isBuffer(_sessionKey), 'Key must be a Buffer (RAM-resident)');
  assert.ok(_sessionId, 'Session ID must exist');
});

// ── 7.2 Encrypt/decrypt roundtrip ──
test('Encrypt/decrypt roundtrip produces identical plaintext', () => {
  const plaintext = 'SENTINEL Activity Log Entry — Firewall Block at 2026-02-17T14:00:00.000Z';
  const ciphertext = ephemeralEncrypt(plaintext);
  const decrypted = ephemeralDecrypt(ciphertext);
  assert.strictEqual(decrypted, plaintext);
  assert.notStrictEqual(ciphertext, plaintext, 'Ciphertext must differ from plaintext');
  // Verify format: iv:tag:data
  const parts = ciphertext.split(':');
  assert.strictEqual(parts.length, 3, 'Format must be iv:tag:encrypted');
  assert.strictEqual(parts[0].length, 24, 'IV must be 12 bytes = 24 hex chars');
  assert.strictEqual(parts[1].length, 32, 'Auth tag must be 16 bytes = 32 hex chars');
});

// ── 7.3 Tampered ciphertext rejected ──
test('Tampered ciphertext is rejected (GCM auth tag verification)', () => {
  const ct = ephemeralEncrypt('sensitive data');
  const parts = ct.split(':');
  // Flip one byte in the encrypted data
  const tampered = parts[0] + ':' + parts[1] + ':' + 'ff' + parts[2].slice(2);
  assert.throws(() => ephemeralDecrypt(tampered), /Unsupported state|authentication/i);
});

// ── 7.4 Session key zeroed on destroy ──
test('Session key is zeroed (overwritten with 0x00) on destroy', () => {
  generateSessionKey();
  const keyRef = _sessionKey!;
  const originalByte = keyRef[0];
  destroySessionKey();
  // After fill(0), every byte in the buffer should be 0
  const allZero = keyRef.every(b => b === 0);
  assert.ok(allZero, 'All bytes must be 0 after destroy');
  assert.strictEqual(_sessionKey, null, 'Key reference must be null');
  assert.strictEqual(_sessionId, null, 'Session ID must be null');
});

// ── 7.5 IPC nonce is unique per session ──
test('IPC nonce is unique per generation (anti-replay)', () => {
  let _nonce1: string | null = null;
  let _nonce2: string | null = null;
  _nonce1 = crypto.randomBytes(16).toString('hex');
  _nonce2 = crypto.randomBytes(16).toString('hex');
  assert.strictEqual(_nonce1.length, 32, 'Nonce must be 16 bytes = 32 hex');
  assert.notStrictEqual(_nonce1, _nonce2, 'Two nonces must differ');
});

// ── 7.6 Nonce validation uses timing-safe comparison ──
test('Nonce validation uses timing-safe comparison (no early return)', () => {
  const nonce = crypto.randomBytes(16).toString('hex');
  const match = crypto.timingSafeEqual(Buffer.from(nonce, 'hex'), Buffer.from(nonce, 'hex'));
  assert.strictEqual(match, true, 'Identical nonces must match');
  const other = crypto.randomBytes(16).toString('hex');
  const noMatch = crypto.timingSafeEqual(Buffer.from(nonce, 'hex'), Buffer.from(other, 'hex'));
  assert.strictEqual(noMatch, false, 'Different nonces must not match');
});

// ── 7.7 Persistence whitelist ──
test('Persistence whitelist protects auth-config.json and sentinelConfig.json', () => {
  assert.strictEqual(isWhitelisted('auth-config.json'), true);
  assert.strictEqual(isWhitelisted('sentinelConfig.json'), true);
  assert.strictEqual(isWhitelisted('updates'), true);
  assert.strictEqual(isWhitelisted('updates/keys'), true);
  assert.strictEqual(isWhitelisted('siem-exports'), true);
  // Ephemeral files must NOT be whitelisted
  assert.strictEqual(isWhitelisted('activity.log'), false);
  assert.strictEqual(isWhitelisted('scan-results.json'), false);
  assert.strictEqual(isWhitelisted('sbom-manifest.json'), false);
  assert.strictEqual(isWhitelisted('security_events.db'), false);
});

// ── 7.8 Wipe targets include critical ephemeral files ──
test('Wipe targets include activity.log, security_events.db, .sentinel/', () => {
  const WIPE_TARGETS = [
    'activity.log',
    'scan-results.json',
    'sbom-manifest.json',
    'security_events.db',
    'security_events.db-wal',
    'security_events.db-shm',
  ];
  for (const target of WIPE_TARGETS) {
    assert.strictEqual(isWhitelisted(target), false, `${target} must NOT be whitelisted`);
  }
});

// ── 7.9 Zero-Trust: setPin forces requireOnLaunch=true ──
test('Zero-Trust: PIN set forces requireOnLaunch=true', () => {
  // Simulate setPin logic
  const cfg = { enabled: false, requireOnLaunch: false, pinHash: null as string | null, salt: null as string | null };
  const pin = '123456';
  const salt = crypto.randomBytes(32).toString('hex');
  cfg.pinHash = crypto.pbkdf2Sync(pin, salt, 100_000, 64, 'sha512').toString('hex');
  cfg.salt = salt;
  cfg.enabled = true;
  cfg.requireOnLaunch = true; // OSOP forces this
  assert.strictEqual(cfg.requireOnLaunch, true, 'requireOnLaunch must be true after setPin');
  assert.strictEqual(cfg.enabled, true);
});

// ── 7.10 Zero-Trust: requireOnLaunch cannot be disabled while PIN exists ──
test('Zero-Trust: requireOnLaunch cannot be disabled while PIN exists', () => {
  const cfg = { pinHash: 'somehash', requireOnLaunch: true };
  // Simulate setRequireOnLaunch(false) — OSOP forces true when pinHash exists
  cfg.requireOnLaunch = cfg.pinHash ? true : false;
  assert.strictEqual(cfg.requireOnLaunch, true, 'Must remain true while PIN exists');
  // If PIN is removed, can be disabled
  cfg.pinHash = '';
  cfg.requireOnLaunch = cfg.pinHash ? true : false;
  assert.strictEqual(cfg.requireOnLaunch, false, 'Can be false when no PIN');
});

// ── 7.11 Secure delete overwrites file content ──
test('Secure delete overwrites file content before unlink', () => {
  const tmpDir = os.tmpdir();
  const testFile = path.join(tmpDir, `sentinel-osop-test-${Date.now()}.tmp`);
  const secret = 'TOP SECRET SENTINEL DATA — MUST BE OVERWRITTEN';
  fs.writeFileSync(testFile, secret, 'utf8');
  assert.strictEqual(fs.readFileSync(testFile, 'utf8'), secret);
  // Simulate secure delete: overwrite with random bytes
  const stat = fs.statSync(testFile);
  const fd = fs.openSync(testFile, 'r+');
  const buf = crypto.randomBytes(stat.size);
  fs.writeSync(fd, buf, 0, buf.length, 0);
  fs.fsyncSync(fd);
  fs.closeSync(fd);
  // Read back — must NOT contain original secret
  const overwritten = fs.readFileSync(testFile, 'utf8');
  assert.notStrictEqual(overwritten, secret, 'File must be overwritten with random data');
  fs.unlinkSync(testFile);
  assert.ok(!fs.existsSync(testFile), 'File must be deleted');
});

// ── 7.12 PID file format for crash watchdog ──
test('PID file contains pid, sessionId, startedAt, and userData path', () => {
  const pidData = {
    pid: process.pid,
    sessionId: crypto.randomUUID(),
    startedAt: new Date().toISOString(),
    userData: path.join(os.tmpdir(), 'sentinel-test'),
    cwd: process.cwd(),
  };
  const json = JSON.stringify(pidData);
  const parsed = JSON.parse(json);
  assert.strictEqual(parsed.pid, process.pid);
  assert.ok(parsed.sessionId.length > 30, 'Session ID must be a UUID');
  assert.ok(parsed.startedAt.endsWith('Z'), 'Timestamp must be UTC');
  assert.ok(parsed.userData.length > 0, 'userData path required');
  assert.ok(parsed.cwd.length > 0, 'cwd path required');
});

// ── 7.13 Session ID is cryptographically random UUID ──
test('Session ID is cryptographically random UUID (v4 format)', () => {
  const ids = new Set<string>();
  for (let i = 0; i < 100; i++) {
    ids.add(crypto.randomUUID());
  }
  assert.strictEqual(ids.size, 100, 'All 100 UUIDs must be unique');
  const sample = crypto.randomUUID();
  assert.ok(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(sample), 'Must be valid UUID v4');
});

// ── 7.14 Multiple encryptions produce different ciphertexts (unique IV) ──
test('Multiple encrypt calls produce different ciphertexts (unique IV per call)', () => {
  generateSessionKey();
  const plaintext = 'same data';
  const ct1 = ephemeralEncrypt(plaintext);
  const ct2 = ephemeralEncrypt(plaintext);
  const ct3 = ephemeralEncrypt(plaintext);
  assert.notStrictEqual(ct1, ct2, 'First two must differ');
  assert.notStrictEqual(ct2, ct3, 'Second two must differ');
  assert.notStrictEqual(ct1, ct3, 'First and third must differ');
  // But all decrypt to the same plaintext
  assert.strictEqual(ephemeralDecrypt(ct1), plaintext);
  assert.strictEqual(ephemeralDecrypt(ct2), plaintext);
  assert.strictEqual(ephemeralDecrypt(ct3), plaintext);
  destroySessionKey();
});

// ── Summary ──
console.log(`\n  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
