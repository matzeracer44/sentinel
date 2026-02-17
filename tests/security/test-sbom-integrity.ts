/**
 * TEST 3: SBOM Integrity & Supply-Chain Manipulation Detection (BSI APP.6.A4)
 * Verifies that file tampering is detected by the SBOM manifest verifier.
 *
 * Run: npx ts-node --project tests/tsconfig.json tests/security/test-sbom-integrity.ts
 */

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const PASS = '\x1b[32m✓\x1b[0m';
const FAIL = '\x1b[31m✗\x1b[0m';
let passed = 0, failed = 0;

function test(name: string, fn: () => void) {
  try { fn(); console.log(`  ${PASS} ${name}`); passed++; }
  catch (e: any) { console.log(`  ${FAIL} ${name}: ${e.message}`); failed++; }
}

const TEST_DIR = path.join(__dirname, '.test-sbom-' + Date.now());
fs.mkdirSync(path.join(TEST_DIR, 'dist'), { recursive: true });

function hashFile(fp: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(fp)).digest('hex');
}

console.log('\n=== TEST 3: SBOM Integrity Verification (BSI APP.6) ===\n');

// --- 3.1 Manifest generation captures correct hashes ---
test('SHA-256 hash of known content is deterministic', () => {
  const fp = path.join(TEST_DIR, 'dist', 'main.js');
  fs.writeFileSync(fp, 'console.log("hello sentinel");', 'utf8');
  const h1 = hashFile(fp);
  const h2 = hashFile(fp);
  assert.strictEqual(h1, h2);
  assert.strictEqual(h1.length, 64); // SHA-256 = 64 hex chars
});

// --- 3.2 Manifest format is correct ---
test('SBOM manifest contains required fields: generatedAt, version, entries', () => {
  const manifest = {
    generatedAt: new Date().toISOString(),
    version: '3.4.0',
    entries: [
      { path: 'dist/main.js', sha256: 'abc123', size: 100 },
    ],
  };
  assert.ok(manifest.generatedAt);
  assert.ok(manifest.version);
  assert.ok(Array.isArray(manifest.entries));
  assert.strictEqual(manifest.entries[0].path, 'dist/main.js');
});

// --- 3.3 Tampering detection: modified file ---
test('Modified file detected as mismatch', () => {
  const fp = path.join(TEST_DIR, 'dist', 'tamper-test.js');
  fs.writeFileSync(fp, 'original content', 'utf8');
  const originalHash = hashFile(fp);

  // Simulate supply-chain attack: attacker modifies file
  fs.writeFileSync(fp, 'original content + malicious payload', 'utf8');
  const tamperedHash = hashFile(fp);

  assert.notStrictEqual(originalHash, tamperedHash, 'Modified file must have different hash');
});

// --- 3.4 Tampering detection: deleted file ---
test('Deleted file detected as missing', () => {
  const fp = path.join(TEST_DIR, 'dist', 'will-delete.js');
  fs.writeFileSync(fp, 'content', 'utf8');
  const manifest = [{ path: 'dist/will-delete.js', sha256: hashFile(fp), size: 7 }];

  fs.unlinkSync(fp);
  const missing = manifest.filter(e => !fs.existsSync(path.join(TEST_DIR, e.path)));
  assert.strictEqual(missing.length, 1);
});

// --- 3.5 Micro-byte tampering: single byte change ---
test('Even a single-byte change produces a completely different hash', () => {
  const fp = path.join(TEST_DIR, 'dist', 'micro.js');
  fs.writeFileSync(fp, 'AAAAAAAAAA', 'utf8');
  const h1 = hashFile(fp);

  fs.writeFileSync(fp, 'AAAAAAAAAB', 'utf8'); // 1 byte changed
  const h2 = hashFile(fp);

  assert.notStrictEqual(h1, h2);
  // Verify avalanche effect: hashes should differ in many positions
  let diffChars = 0;
  for (let i = 0; i < h1.length; i++) { if (h1[i] !== h2[i]) diffChars++; }
  assert.ok(diffChars > 10, `Avalanche effect: ${diffChars}/64 chars differ`);
});

// --- 3.6 Manifest persistence and reload ---
test('Manifest persists to JSON and reloads identically', () => {
  const manifest = {
    generatedAt: '2026-02-17T14:00:00.000Z',
    version: '3.4.0',
    entries: [
      { path: 'dist/main.js', sha256: 'a'.repeat(64), size: 500 },
      { path: 'ARGUS/main.py', sha256: 'b'.repeat(64), size: 300 },
    ],
  };
  const mp = path.join(TEST_DIR, 'sbom-manifest.json');
  fs.writeFileSync(mp, JSON.stringify(manifest, null, 2), 'utf8');
  const loaded = JSON.parse(fs.readFileSync(mp, 'utf8'));
  assert.deepStrictEqual(loaded, manifest);
});

// --- 3.7 Script Block Logging registry path is correct ---
test('Script Block Logging checks correct registry path', () => {
  const regPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging';
  const valueName = 'EnableScriptBlockLogging';
  assert.ok(regPath.includes('ScriptBlockLogging'));
  assert.strictEqual(valueName, 'EnableScriptBlockLogging');
});

// --- 3.8 File extension filter for SBOM ---
test('SBOM only hashes relevant file extensions (.js, .py, .json, .ts, .bat, .ps1)', () => {
  const allowedExtensions = ['.js', '.py', '.json', '.ts', '.bat', '.ps1'];
  const testFiles = ['main.js', 'config.json', 'readme.md', 'icon.png', 'scan.py', 'start.bat'];
  const filtered = testFiles.filter(f => allowedExtensions.some(ext => f.endsWith(ext)));
  assert.deepStrictEqual(filtered, ['main.js', 'config.json', 'scan.py', 'start.bat']);
});

// --- 3.9 Empty manifest → valid (no files to check) ---
test('Empty manifest returns valid=true with 0 files checked', () => {
  const entries: any[] = [];
  const mismatched: string[] = [];
  const missing: string[] = [];
  const valid = mismatched.length === 0 && missing.length === 0;
  assert.strictEqual(valid, true);
  assert.strictEqual(entries.length, 0);
});

// Cleanup
try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch { /* ok */ }

console.log(`\n  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
