/**
 * SENTINEL — Unified Security Test Runner
 * Runs all 6 test suites and generates the final test report.
 *
 * Run: npx ts-node --project tests/tsconfig.json tests/security/run-all.ts
 */

import { execSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

const TESTS = [
  { id: 'T1', name: 'Adaptive Trust & Kill-Switch', file: 'test-adaptive-killswitch.ts' },
  { id: 'T2', name: 'YARA & MISP Threat Intel', file: 'test-yara-misp.ts' },
  { id: 'T3', name: 'SBOM Integrity (BSI APP.6)', file: 'test-sbom-integrity.ts' },
  { id: 'T4', name: 'SIEM Export & Forensics (NSA)', file: 'test-siem-forensics.ts' },
  { id: 'T5', name: 'Vault Auth & AES-256-GCM', file: 'test-vault-auth.ts' },
  { id: 'T6', name: 'PowerShell Hardening', file: 'test-powershell-hardening.ts' },
  { id: 'T7', name: 'OSOP Ephemeral Session (BSI APP.6.A13)', file: 'test-osop.ts' },
  { id: 'T8', name: 'TOTP Multi-Factor Auth (RFC 6238)', file: 'test-totp.ts' },
];

interface TestResult {
  id: string;
  name: string;
  passed: number;
  failed: number;
  total: number;
  output: string;
  success: boolean;
}

const results: TestResult[] = [];
const testDir = __dirname;
const projectRoot = path.resolve(testDir, '..', '..');

console.log('\n╔══════════════════════════════════════════════════════════╗');
console.log('║     SENTINEL — Security Verification Suite v3.4.0      ║');
console.log('║     NIST SP 1800-35 · BSI APP.6 · NSA Standards        ║');
console.log('╚══════════════════════════════════════════════════════════╝\n');

for (const test of TESTS) {
  const filePath = path.join(testDir, test.file);
  console.log(`\x1b[36m► Running ${test.id}: ${test.name}\x1b[0m`);

  try {
    const output = execSync(
      `npx ts-node --project "${path.join(testDir, '..', 'tsconfig.json')}" "${filePath}"`,
      { encoding: 'utf-8', cwd: projectRoot, timeout: 30000, windowsHide: true }
    );

    const passMatch = output.match(/Results:\s*(\d+) passed/);
    const failMatch = output.match(/Results:\s*\d+ passed,\s*(\d+) failed/);
    const passed = passMatch ? parseInt(passMatch[1], 10) : 0;
    const failed = failMatch ? parseInt(failMatch[1], 10) : 0;

    results.push({ id: test.id, name: test.name, passed, failed, total: passed + failed, output, success: failed === 0 });
  } catch (e: any) {
    const output = e.stdout || e.stderr || e.message || 'Unknown error';
    const passMatch = output.match(/Results:\s*(\d+) passed/);
    const failMatch = output.match(/Results:\s*\d+ passed,\s*(\d+) failed/);
    const passed = passMatch ? parseInt(passMatch[1], 10) : 0;
    const failed = failMatch ? parseInt(failMatch[1], 10) : 0;

    results.push({ id: test.id, name: test.name, passed, failed: failed || 1, total: passed + (failed || 1), output, success: false });
  }
}

// Summary
console.log('\n╔══════════════════════════════════════════════════════════╗');
console.log('║                    RESULTS SUMMARY                      ║');
console.log('╠══════════════════════════════════════════════════════════╣');

let totalPassed = 0, totalFailed = 0;

for (const r of results) {
  totalPassed += r.passed;
  totalFailed += r.failed;
  const icon = r.success ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m';
  const pad = r.name.padEnd(38);
  console.log(`║ ${icon} ${pad} ${String(r.passed).padStart(2)}/${String(r.total).padStart(2)} ║`);
}

const totalTests = totalPassed + totalFailed;
const allPassed = totalFailed === 0;
const verdict = allPassed ? '\x1b[32mALL TESTS PASSED\x1b[0m' : `\x1b[31m${totalFailed} FAILURES\x1b[0m`;

console.log('╠══════════════════════════════════════════════════════════╣');
console.log(`║ TOTAL: ${totalPassed}/${totalTests} passed                ${verdict.padEnd(30)}║`);
console.log('╚══════════════════════════════════════════════════════════╝\n');

// Generate filled report
try {
  const reportTemplate = fs.readFileSync(path.join(testDir, '..', 'test-report.md'), 'utf8');
  let report = reportTemplate
    .replace('{{DATE}}', new Date().toISOString())
    .replace('{{VERDICT}}', allPassed ? '✅ ALL TESTS PASSED' : `❌ ${totalFailed} FAILURES`)
    .replace('{{TOTAL}}', String(totalTests))
    .replace('{{PASS}}', String(totalPassed))
    .replace('{{FAIL}}', String(totalFailed));

  for (const r of results) {
    report = report
      .replace(`{{${r.id}_TOTAL}}`, String(r.total))
      .replace(`{{${r.id}_PASS}}`, String(r.passed))
      .replace(`{{${r.id}_FAIL}}`, String(r.failed))
      .replace(`{{${r.id}_OUTPUT}}`, r.output.trim());
  }

  report = report.replace(/\{\{STATUS\}\}/g, allPassed ? '✅ PASS' : '⚠️ REVIEW');

  const outPath = path.join(testDir, '..', `test-report-${Date.now()}.md`);
  fs.writeFileSync(outPath, report, 'utf8');
  console.log(`📄 Report saved: ${outPath}\n`);
} catch (e: any) {
  console.warn(`Report generation failed: ${e.message}`);
}

process.exit(totalFailed > 0 ? 1 : 0);
