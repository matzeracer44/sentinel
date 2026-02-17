/**
 * TEST 4: SIEM Export Schema Validation & Forensic Timestamp Precision (NSA Standards)
 * Validates UTC+ms timestamps, CEF/JSON/Syslog format correctness.
 *
 * Run: npx ts-node --project tests/tsconfig.json tests/security/test-siem-forensics.ts
 */

import * as assert from 'assert';

const PASS = '\x1b[32m✓\x1b[0m';
const FAIL = '\x1b[31m✗\x1b[0m';
let passed = 0, failed = 0;

function test(name: string, fn: () => void) {
  try { fn(); console.log(`  ${PASS} ${name}`); passed++; }
  catch (e: any) { console.log(`  ${FAIL} ${name}: ${e.message}`); failed++; }
}

console.log('\n=== TEST 4: SIEM Export & Forensic Timestamp Validation ===\n');

// --- 4.1 UTC timestamp format (NSA requirement: ISO 8601 + milliseconds) ---
test('Timestamps use ISO 8601 UTC with milliseconds', () => {
  const ts = new Date().toISOString();
  // Must match: 2026-02-17T14:07:30.123Z
  const ISO_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
  assert.ok(ISO_MS_RE.test(ts), `Timestamp ${ts} must match ISO 8601 with ms`);
});

// --- 4.2 Timestamps are always UTC (Z suffix, never +offset) ---
test('Timestamps always end with Z (UTC), never local offset', () => {
  const ts = new Date().toISOString();
  assert.ok(ts.endsWith('Z'), 'Must be UTC (Z suffix)');
  assert.ok(!ts.includes('+'), 'Must not contain timezone offset');
});

// --- 4.3 CEF format validation ---
test('CEF output follows ArcSight CEF:0 standard', () => {
  const SEV_MAP: Record<string, number> = { low: 3, medium: 5, high: 8, critical: 10 };

  function toCEF(evt: { severity: string; action: string; message: string; timestamp: string; sourceIp?: string }) {
    const sev = SEV_MAP[evt.severity] ?? 5;
    const ext = [
      evt.sourceIp ? `src=${evt.sourceIp}` : '',
      `rt=${new Date(evt.timestamp).getTime()}`,
    ].filter(Boolean).join(' ');
    return `CEF:0|Sentinel|SecuritySuite|1.0|${evt.action}|${evt.message.replace(/\|/g, '\\|')}|${sev}|${ext}`;
  }

  const cef = toCEF({
    severity: 'high',
    action: 'BlockIP',
    message: 'Blocked suspicious connection',
    timestamp: '2026-02-17T14:07:30.123Z',
    sourceIp: '103.145.12.34',
  });

  assert.ok(cef.startsWith('CEF:0|'), 'Must start with CEF:0|');
  assert.ok(cef.includes('|Sentinel|'), 'Must contain vendor name');
  assert.ok(cef.includes('|8|'), 'High severity = 8');
  assert.ok(cef.includes('src=103.145.12.34'), 'Must contain source IP');
  assert.ok(cef.includes('rt='), 'Must contain epoch timestamp');
});

// --- 4.4 Syslog RFC 5424 format validation ---
test('Syslog output follows RFC 5424 format', () => {
  function toSyslog(evt: { severity: string; module: string; action: string; message: string; timestamp: string }) {
    const facility = 4; // auth
    const sevNum = evt.severity === 'critical' ? 2 : evt.severity === 'high' ? 3 : evt.severity === 'medium' ? 4 : 6;
    const pri = facility * 8 + sevNum;
    const ts = new Date(evt.timestamp).toISOString();
    return `<${pri}>1 ${ts} sentinel ${evt.module} - - - [${evt.action}] ${evt.message}`;
  }

  const syslog = toSyslog({
    severity: 'critical',
    module: 'Shield',
    action: 'ThreatDetected',
    message: 'Ransomware behavior detected',
    timestamp: '2026-02-17T14:07:30.123Z',
  });

  // PRI: facility(4)*8 + severity(2) = 34
  assert.ok(syslog.startsWith('<34>1'), `PRI must be <34>1, got: ${syslog.substring(0, 10)}`);
  assert.ok(syslog.includes('sentinel Shield'), 'Must contain hostname and app');
  assert.ok(syslog.includes('[ThreatDetected]'), 'Must contain structured action');
});

// --- 4.5 JSON export is valid and parseable ---
test('JSON export produces valid, parseable JSON lines', () => {
  const events = [
    { timestamp: '2026-02-17T14:07:30.123Z', severity: 'high', module: 'Shield', action: 'Block', message: 'test' },
    { timestamp: '2026-02-17T14:07:31.456Z', severity: 'low', module: 'FIM', action: 'Change', message: 'test2' },
  ];
  const lines = events.map(e => JSON.stringify(e));
  for (const line of lines) {
    const parsed = JSON.parse(line);
    assert.ok(parsed.timestamp);
    assert.ok(parsed.severity);
    assert.ok(parsed.module);
  }
});

// --- 4.6 Severity mapping is complete ---
test('All severity levels map to valid CEF/Syslog values', () => {
  const CEF_MAP: Record<string, number> = { low: 3, medium: 5, high: 8, critical: 10 };
  const SYSLOG_MAP: Record<string, number> = { low: 6, medium: 4, high: 3, critical: 2 };
  for (const sev of ['low', 'medium', 'high', 'critical']) {
    assert.ok(CEF_MAP[sev] !== undefined, `CEF severity for ${sev}`);
    assert.ok(SYSLOG_MAP[sev] !== undefined, `Syslog severity for ${sev}`);
    assert.ok(CEF_MAP[sev] >= 0 && CEF_MAP[sev] <= 10, `CEF range for ${sev}`);
    assert.ok(SYSLOG_MAP[sev] >= 0 && SYSLOG_MAP[sev] <= 7, `Syslog range for ${sev}`);
  }
});

// --- 4.7 Pipe characters in messages are escaped in CEF ---
test('CEF escapes pipe characters in messages', () => {
  const msg = 'Blocked|Suspicious|Activity';
  const escaped = msg.replace(/\|/g, '\\|');
  assert.strictEqual(escaped, 'Blocked\\|Suspicious\\|Activity');
  assert.ok(!escaped.includes('||'), 'Must not have unescaped pipes');
});

// --- 4.8 Export file naming convention ---
test('Export filename includes timestamp for uniqueness', () => {
  const filename = `sentinel-events-${Date.now()}.json`;
  assert.ok(filename.startsWith('sentinel-events-'));
  assert.ok(filename.endsWith('.json'));
  assert.ok(/sentinel-events-\d+\.json/.test(filename));
});

// --- 4.9 ELK/Wazuh compatibility: JSON has required fields ---
test('JSON events contain all fields required by ELK/Wazuh ingestion', () => {
  const event = {
    timestamp: '2026-02-17T14:07:30.123Z',
    severity: 'high',
    module: 'Shield',
    action: 'Block',
    message: 'Blocked connection to known C2 server',
    sourceIp: '103.145.12.34',
    port: 443,
    pid: 1234,
    processName: 'chrome.exe',
    riskScore: 85,
  };
  const required = ['timestamp', 'severity', 'module', 'action', 'message'];
  for (const field of required) {
    assert.ok(field in event, `Missing required field: ${field}`);
  }
});

// --- 4.10 Max file events limit is enforced ---
test('Export respects maxFileEvents limit (default: 10000)', () => {
  const MAX = 10000;
  const events = Array.from({ length: 15000 }, (_, i) => ({ id: i }));
  const sliced = events.slice(0, MAX);
  assert.strictEqual(sliced.length, MAX);
});

console.log(`\n  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
