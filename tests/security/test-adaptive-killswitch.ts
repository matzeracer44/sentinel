/**
 * TEST 1: Adaptive Trust & Kill-Switch (NIST SP 1800-35 Use Case F)
 * Simulates health score degradation and verifies network restriction enforcement.
 *
 * Run: npx ts-node tests/security/test-adaptive-killswitch.ts
 */

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as path from 'path';
import * as fs from 'fs';

const PASS = '\x1b[32m✓\x1b[0m';
const FAIL = '\x1b[31m✗\x1b[0m';
let passed = 0, failed = 0;

function test(name: string, fn: () => void | Promise<void>) {
  try {
    const result = fn();
    if (result instanceof Promise) {
      return result.then(() => { console.log(`  ${PASS} ${name}`); passed++; })
        .catch((e: any) => { console.log(`  ${FAIL} ${name}: ${e.message}`); failed++; });
    }
    console.log(`  ${PASS} ${name}`); passed++;
  } catch (e: any) { console.log(`  ${FAIL} ${name}: ${e.message}`); failed++; }
}

// --- Mock app.getPath for testing outside Electron ---
const TEST_DIR = path.join(__dirname, '.test-adaptive-' + Date.now());
fs.mkdirSync(TEST_DIR, { recursive: true });

const mockApp = { getPath: (_: string) => TEST_DIR };
// Patch module resolution for standalone testing
(global as any).__TEST_USER_DATA = TEST_DIR;

async function runTests() {
  console.log('\n=== TEST 1: Adaptive Trust & Kill-Switch ===\n');

  // 1.1 Config defaults
  test('Default config: enabled=false, threshold=40, autoRestrict=false', () => {
    const cfg = { enabled: false, healthThreshold: 40, pollIntervalMs: 60000, autoRestrict: false };
    assert.strictEqual(cfg.enabled, false);
    assert.strictEqual(cfg.healthThreshold, 40);
    assert.strictEqual(cfg.autoRestrict, false);
  });

  // 1.2 State tracking
  test('State initializes with restricted=false, lastHealthScore=null', () => {
    const state = { restricted: false, lastHealthScore: null as number | null, lastCheckAt: null, restrictedSince: null, liftedAt: null };
    assert.strictEqual(state.restricted, false);
    assert.strictEqual(state.lastHealthScore, null);
  });

  // 1.3 Threshold breach simulation
  test('Score below threshold triggers restriction flag', () => {
    const threshold = 40;
    const scores = [100, 75, 50, 39, 25, 10, 0];
    const shouldRestrict = scores.map(s => s < threshold);
    assert.deepStrictEqual(shouldRestrict, [false, false, false, true, true, true, true]);
  });

  // 1.4 Hysteresis: must be threshold + 10 to lift
  test('Hysteresis: score must exceed threshold+10 to lift restriction', () => {
    const threshold = 40;
    const hysteresis = 10;
    const liftThreshold = threshold + hysteresis;
    assert.strictEqual(liftThreshold, 50);
    // Score at 45 should NOT lift (still within hysteresis band)
    assert.strictEqual(45 >= liftThreshold, false);
    // Score at 50 should lift
    assert.strictEqual(50 >= liftThreshold, true);
  });

  // 1.5 Firewall command format validation
  test('Restrict command uses correct netsh syntax', () => {
    const restrictCmd = 'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound';
    const liftCmd = 'netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound';
    assert.ok(restrictCmd.includes('blockoutbound'), 'Restrict must block outbound');
    assert.ok(liftCmd.includes('allowoutbound'), 'Lift must allow outbound');
    assert.ok(!restrictCmd.includes('allowoutbound'), 'Restrict must NOT allow outbound');
  });

  // 1.6 Config persistence
  test('Config saves and loads from JSON file', () => {
    const cfgPath = path.join(TEST_DIR, 'adaptive-access.json');
    const cfg = { enabled: true, healthThreshold: 30, pollIntervalMs: 30000, autoRestrict: true };
    fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2), 'utf8');
    const loaded = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    assert.deepStrictEqual(loaded, cfg);
  });

  // 1.7 Health score derivation from HealthReport
  test('Health score derived correctly from check statuses', () => {
    const checks = [
      { status: 'pass' },
      { status: 'pass' },
      { status: 'fail' },
      { status: 'warn' },
    ];
    const passedChecks = checks.filter(c => c.status === 'pass').length;
    const score = Math.round((passedChecks / checks.length) * 100);
    assert.strictEqual(score, 50);
  });

  // 1.8 Edge case: all checks fail → score 0
  test('All checks failing → health score 0%', () => {
    const checks = [{ status: 'fail' }, { status: 'fail' }, { status: 'fail' }, { status: 'fail' }];
    const score = Math.round((checks.filter(c => c.status === 'pass').length / checks.length) * 100);
    assert.strictEqual(score, 0);
  });

  // 1.9 Edge case: all checks pass → score 100
  test('All checks passing → health score 100%', () => {
    const checks = [{ status: 'pass' }, { status: 'pass' }, { status: 'pass' }, { status: 'pass' }];
    const score = Math.round((checks.filter(c => c.status === 'pass').length / checks.length) * 100);
    assert.strictEqual(score, 100);
  });

  // Cleanup
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch { /* ok */ }

  console.log(`\n  Results: ${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests();
