/**
 * SENTINEL — Security Report Generator
 * Aggregates data from all scan modules, hardware discovery, event logs,
 * and system state into a comprehensive security report.
 * Output: structured JSON that can be rendered in UI or exported as HTML/PDF.
 */

import * as os from 'os';

export interface SecurityReportSection {
  title: string;
  score: number;
  maxScore: number;
  status: 'pass' | 'warn' | 'fail';
  items: Array<{
    name: string;
    status: 'pass' | 'warn' | 'fail';
    detail: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  }>;
}

export interface SecurityReport {
  generatedAt: string;
  systemInfo: {
    hostname: string;
    username: string;
    platform: string;
    osVersion: string;
    arch: string;
    cpuModel: string;
    totalRAM_GB: number;
    uptimeHours: number;
  };
  overallScore: number;
  overallGrade: string;
  sections: SecurityReportSection[];
  criticalFindings: string[];
  recommendations: string[];
  exportFormats: string[];
}

function computeGrade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

export async function generateSecurityReport(
  scanModules?: Record<string, { score: number; passed: number; total: number; checks: Array<{ name: string; status: string; detail?: string; risk?: string }> }>
): Promise<SecurityReport> {
  const cpus = os.cpus();
  const report: SecurityReport = {
    generatedAt: new Date().toISOString(),
    systemInfo: {
      hostname: os.hostname(),
      username: os.userInfo().username,
      platform: `${os.platform()} ${os.release()}`,
      osVersion: os.release(),
      arch: os.arch(),
      cpuModel: cpus.length > 0 ? cpus[0].model.trim() : 'Unknown',
      totalRAM_GB: Math.round((os.totalmem() / (1024 ** 3)) * 10) / 10,
      uptimeHours: Math.round((os.uptime() / 3600) * 10) / 10,
    },
    overallScore: 0,
    overallGrade: 'F',
    sections: [],
    criticalFindings: [],
    recommendations: [],
    exportFormats: ['json', 'html'],
  };

  if (scanModules) {
    const moduleLabels: Record<string, string> = {
      kernel: 'Kernel & Firmware Integrity',
      edr: 'EDR & Behavioral Analysis',
      network: 'Network Security',
      performance: 'System Performance',
      privacy: 'Privacy & Hardening',
    };

    for (const [key, mod] of Object.entries(scanModules)) {
      const section: SecurityReportSection = {
        title: moduleLabels[key] || key,
        score: mod.score,
        maxScore: 100,
        status: mod.score >= 80 ? 'pass' : mod.score >= 50 ? 'warn' : 'fail',
        items: (mod.checks || []).map(c => ({
          name: c.name,
          status: (c.status === 'pass' ? 'pass' : c.status === 'fail' ? 'fail' : 'warn') as 'pass' | 'warn' | 'fail',
          detail: c.detail || '',
          severity: mapRisk(c.risk),
        })),
      };
      report.sections.push(section);

      // Extract critical findings
      for (const check of mod.checks || []) {
        if (check.status === 'fail' && (check.risk === 'high' || check.risk === 'critical')) {
          report.criticalFindings.push(`[${moduleLabels[key] || key}] ${check.name}: ${check.detail || 'Failed'}`);
        }
      }
    }

    // Compute overall score (weighted average)
    const weights: Record<string, number> = { kernel: 25, edr: 25, network: 20, privacy: 15, performance: 15 };
    let weightedSum = 0;
    let totalWeight = 0;
    for (const [key, mod] of Object.entries(scanModules)) {
      const w = weights[key] || 10;
      weightedSum += mod.score * w;
      totalWeight += w;
    }
    report.overallScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;
    report.overallGrade = computeGrade(report.overallScore);
  }

  // Generate recommendations based on findings
  if (report.overallScore < 50) {
    report.recommendations.push('CRITICAL: System security is severely compromised. Address all critical findings immediately.');
  }
  if (report.criticalFindings.length > 5) {
    report.recommendations.push(`${report.criticalFindings.length} critical issues found. Prioritize kernel and EDR fixes first.`);
  }
  if (report.sections.find(s => s.title.includes('Network') && s.score < 60)) {
    report.recommendations.push('Network security score is low. Run the Network Scanner and apply recommended firewall rules.');
  }
  if (report.sections.find(s => s.title.includes('Privacy') && s.score < 60)) {
    report.recommendations.push('Privacy score is low. Review DNS settings, telemetry, and tracking protection.');
  }
  if (report.sections.find(s => s.title.includes('Kernel') && s.score < 70)) {
    report.recommendations.push('Kernel integrity needs attention. Enable Secure Boot, TPM, and HVCI.');
  }
  if (report.recommendations.length === 0) {
    report.recommendations.push('System is well-protected. Continue regular scanning to maintain security posture.');
  }

  return report;
}

function mapRisk(risk?: string): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (!risk) return 'LOW';
  const r = risk.toLowerCase();
  if (r === 'critical') return 'CRITICAL';
  if (r === 'high') return 'HIGH';
  if (r === 'medium') return 'MEDIUM';
  return 'LOW';
}

export function generateReportHTML(report: SecurityReport): string {
  const gradeColor = report.overallScore >= 80 ? '#00ff88' : report.overallScore >= 50 ? '#ffaa00' : '#ff3366';
  const sectionRows = report.sections.map(s => {
    const sColor = s.score >= 80 ? '#00ff88' : s.score >= 50 ? '#ffaa00' : '#ff3366';
    const items = s.items.map(i => {
      const iColor = i.status === 'pass' ? '#00ff88' : i.status === 'fail' ? '#ff3366' : '#ffaa00';
      return `<tr><td style="color:${iColor}">${i.status === 'pass' ? '✓' : i.status === 'fail' ? '✕' : '⚠'}</td><td>${i.name}</td><td>${i.detail}</td><td>${i.severity}</td></tr>`;
    }).join('');
    return `
      <div style="margin-bottom:24px;border:1px solid rgba(109,120,255,0.2);border-radius:12px;padding:16px;background:rgba(15,23,42,0.6)">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
          <h3 style="margin:0;color:#e2e8f0">${s.title}</h3>
          <span style="font-size:1.5rem;font-weight:700;color:${sColor}">${s.score}%</span>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:0.8rem">
          <thead><tr style="color:rgba(160,168,220,0.6);text-align:left;border-bottom:1px solid rgba(109,120,255,0.15)">
            <th style="width:30px;padding:4px"></th><th style="padding:4px">Check</th><th style="padding:4px">Detail</th><th style="padding:4px;width:80px">Severity</th>
          </tr></thead>
          <tbody style="color:#cbd5e1">${items}</tbody>
        </table>
      </div>`;
  }).join('');

  const criticalList = report.criticalFindings.map(f => `<li style="color:#ff3366;margin-bottom:4px">${f}</li>`).join('');
  const recoList = report.recommendations.map(r => `<li style="color:#00ccff;margin-bottom:4px">${r}</li>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Sentinel Security Report — ${report.generatedAt}</title>
  <style>
    body { background:#0f172a; color:#e2e8f0; font-family:'Segoe UI',system-ui,sans-serif; padding:40px; max-width:1000px; margin:0 auto; }
    h1 { color:#00ccff; margin-bottom:4px; }
    h2 { color:rgba(160,168,220,0.8); margin-top:32px; }
    .info-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:20px 0; }
    .info-card { background:rgba(109,120,255,0.06); border:1px solid rgba(109,120,255,0.15); border-radius:8px; padding:12px; }
    .info-label { font-size:0.7rem; color:rgba(160,168,220,0.5); text-transform:uppercase; }
    .info-value { font-size:0.875rem; font-weight:600; margin-top:4px; }
  </style>
</head>
<body>
  <h1>SENTINEL Security Report</h1>
  <p style="color:rgba(160,168,220,0.6);margin-top:0">Generated: ${new Date(report.generatedAt).toLocaleString('de-DE')}</p>

  <div style="display:flex;align-items:center;gap:24px;margin:24px 0;padding:20px;border:1px solid ${gradeColor}33;border-radius:16px;background:${gradeColor}08">
    <div style="font-size:4rem;font-weight:700;color:${gradeColor}">${report.overallGrade}</div>
    <div>
      <div style="font-size:2rem;font-weight:700;color:${gradeColor}">${report.overallScore}/100</div>
      <div style="color:rgba(160,168,220,0.6)">Overall Security Score</div>
    </div>
  </div>

  <div class="info-grid">
    ${[
      { label: 'Hostname', value: report.systemInfo.hostname },
      { label: 'User', value: report.systemInfo.username },
      { label: 'Platform', value: report.systemInfo.platform },
      { label: 'CPU', value: report.systemInfo.cpuModel },
      { label: 'RAM', value: `${report.systemInfo.totalRAM_GB} GB` },
      { label: 'Architecture', value: report.systemInfo.arch },
      { label: 'Uptime', value: `${report.systemInfo.uptimeHours}h` },
      { label: 'Scan Modules', value: `${report.sections.length}` },
    ].map(i => `<div class="info-card"><div class="info-label">${i.label}</div><div class="info-value">${i.value}</div></div>`).join('')}
  </div>

  ${report.criticalFindings.length > 0 ? `<h2>Critical Findings (${report.criticalFindings.length})</h2><ul>${criticalList}</ul>` : ''}

  <h2>Module Results</h2>
  ${sectionRows}

  <h2>Recommendations</h2>
  <ul>${recoList}</ul>

  <footer style="margin-top:40px;padding-top:16px;border-top:1px solid rgba(109,120,255,0.15);color:rgba(160,168,220,0.4);font-size:0.75rem">
    Sentinel Security Suite — Report generated ${new Date(report.generatedAt).toLocaleString('de-DE')}
  </footer>
</body>
</html>`;
}
