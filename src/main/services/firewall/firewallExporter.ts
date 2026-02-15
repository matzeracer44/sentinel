/**
 * SENTINEL — Firewall Rules Exporter
 * Exports firewall rules as TXT (padded table), CSV, or JSON.
 */

import * as os from 'os';

export interface FirewallExportOptions {
  format: 'txt' | 'csv' | 'json';
  filter?: 'all' | 'inbound' | 'outbound' | 'sentinel-only' | 'block-only';
  includeDisabled?: boolean;
}

export interface ExportableRule {
  name: string;
  direction: string;
  action: string;
  enabled: boolean | string;
  profile?: string;
  protocol?: string;
  localPort?: string;
  remotePort?: string;
  program?: string;
  localAddress?: string;
  remoteAddress?: string;
  description?: string;
  riskLevel?: string;
  group?: string;
}

export function exportFirewallRules(rules: ExportableRule[], options: FirewallExportOptions): string {
  const filtered = rules
    .filter((r) => {
      if (options.filter === 'inbound') return r.direction === 'Inbound';
      if (options.filter === 'outbound') return r.direction === 'Outbound';
      if (options.filter === 'sentinel-only') return r.group?.startsWith('Sentinel') || r.name?.startsWith('Sentinel');
      if (options.filter === 'block-only') return r.action === 'Block';
      return true;
    })
    .filter((r) => {
      if (options.includeDisabled) return true;
      return r.enabled === true || r.enabled === 'true' || r.enabled === 'Yes';
    });

  switch (options.format) {
    case 'csv': return formatCSV(filtered);
    case 'json': return JSON.stringify(filtered, null, 2);
    case 'txt':
    default: return formatTXT(filtered);
  }
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 2) + '..' : s;
}

function padRow(cols: string[]): string {
  const widths = [37, 5, 10, 7, 7, 8, 27, 22, 8];
  return cols.map((c, i) => c.padEnd(widths[i] ?? 20)).join('');
}

function isEnabled(e: boolean | string): boolean {
  if (typeof e === 'boolean') return e;
  const s = String(e).toLowerCase();
  return s === 'true' || s === 'yes' || s === 'ja' || s === '1';
}

function formatTXT(rules: ExportableRule[]): string {
  const header = [
    'SENTINEL FIREWALL EXPORT',
    `Generated: ${new Date().toISOString()}`,
    `Total Rules: ${rules.length}`,
    `Machine: ${os.hostname()}`,
    '='.repeat(120),
    '',
    padRow(['RULE NAME', 'DIR', 'ACTION', 'RISK', 'PROTO', 'PORT', 'PROGRAM', 'REMOTE', 'ENABLED']),
    '-'.repeat(120),
  ].join('\n');

  const rows = rules.map((r) =>
    padRow([
      truncate(r.name || '', 35),
      r.direction === 'Inbound' ? 'IN' : r.direction === 'Outbound' ? 'OUT' : r.direction || 'N/A',
      r.action || 'N/A',
      r.riskLevel ?? 'N/A',
      r.protocol ?? 'Any',
      r.localPort ?? 'Any',
      truncate(r.program ?? 'Any process', 25),
      truncate(r.remoteAddress ?? 'Any', 20),
      isEnabled(r.enabled) ? 'YES' : 'NO',
    ])
  );

  const summary = [
    '',
    '='.repeat(120),
    'SUMMARY:',
    `  Allow rules: ${rules.filter((r) => r.action === 'Allow').length}`,
    `  Block rules: ${rules.filter((r) => r.action === 'Block').length}`,
    `  Inbound:     ${rules.filter((r) => r.direction === 'Inbound').length}`,
    `  Outbound:    ${rules.filter((r) => r.direction === 'Outbound').length}`,
    `  Enabled:     ${rules.filter((r) => isEnabled(r.enabled)).length}`,
    `  Disabled:    ${rules.filter((r) => !isEnabled(r.enabled)).length}`,
    `  Sentinel:    ${rules.filter((r) => r.group?.startsWith('Sentinel') || r.name?.startsWith('Sentinel')).length}`,
  ].join('\n');

  return header + '\n' + rows.join('\n') + summary;
}

function formatCSV(rules: ExportableRule[]): string {
  const headers = 'Name,Direction,Action,Risk,Protocol,LocalPort,RemotePort,Program,RemoteAddress,Enabled,Group,Profile\n';
  const rows = rules
    .map((r) =>
      [
        r.name, r.direction, r.action, r.riskLevel, r.protocol, r.localPort,
        r.remotePort, r.program, r.remoteAddress, isEnabled(r.enabled) ? 'Yes' : 'No',
        r.group, r.profile,
      ]
        .map((v) => `"${String(v ?? '').replace(/"/g, '""')}"`)
        .join(',')
    )
    .join('\n');
  return headers + rows;
}
