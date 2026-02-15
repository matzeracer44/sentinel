/**
 * SENTINEL — Event Log Analyzer Service
 * Queries Windows Event Log for security-relevant events:
 * - Failed logins (4625), successful logins (4624), privilege escalation (4672)
 * - Service installs (7045), audit policy changes (4719), account changes (4720-4726)
 * - Process creation (4688), firewall changes (2004/2006), Defender events
 * Single PowerShell call for efficiency.
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const PS_TIMEOUT = 15000;
const PS_MAX_BUFFER = 8 * 1024 * 1024;

export interface EventLogEntry {
  id: number;
  timeCreated: string;
  level: 'Information' | 'Warning' | 'Error' | 'Critical';
  source: string;
  message: string;
  category: string;
}

export interface EventLogSummary {
  failedLogins: { count: number; recent: EventLogEntry[] };
  privilegeEscalations: { count: number; recent: EventLogEntry[] };
  serviceInstalls: { count: number; recent: EventLogEntry[] };
  auditPolicyChanges: { count: number; recent: EventLogEntry[] };
  accountChanges: { count: number; recent: EventLogEntry[] };
  defenderEvents: { count: number; recent: EventLogEntry[] };
  firewallChanges: { count: number; recent: EventLogEntry[] };
  criticalErrors: { count: number; recent: EventLogEntry[] };
  totalSecurityEvents: number;
  analysisTime: string;
  riskScore: number;
  riskFactors: string[];
}

const PS_SCRIPT = `
$ErrorActionPreference='SilentlyContinue'
$24h = (Get-Date).AddHours(-24)
$fmt = 'yyyy-MM-ddTHH:mm:ss'

function Evt($log,$ids,$max=10) {
  $events = @()
  try {
    $raw = Get-WinEvent -FilterHashtable @{LogName=$log;Id=$ids;StartTime=$24h} -MaxEvents $max -EA SilentlyContinue
    foreach($e in $raw) {
      $lvl = switch($e.Level){1{'Critical'}2{'Error'}3{'Warning'}default{'Information'}}
      $events += @{
        Id = $e.Id
        TimeCreated = $e.TimeCreated.ToString($fmt)
        Level = $lvl
        Source = $e.ProviderName
        Message = ($e.Message -replace '\\r\\n',' ' -replace '\\s+',' ').Substring(0,[Math]::Min(300,$e.Message.Length))
      }
    }
  } catch { <# event log may be inaccessible #> }
  $count = 0
  try { $count = (Get-WinEvent -FilterHashtable @{LogName=$log;Id=$ids;StartTime=$24h} -EA SilentlyContinue | Measure-Object).Count } catch { <# no matching events #> }
  @{ Count = $count; Recent = $events }
}

$failedLogins = Evt 'Security' @(4625)
$privEsc = Evt 'Security' @(4672) 5
$svcInstall = Evt 'System' @(7045)
$auditChange = Evt 'Security' @(4719)
$acctChange = Evt 'Security' @(4720,4722,4723,4724,4725,4726)
$defender = Evt 'Microsoft-Windows-Windows Defender/Operational' @(1006,1007,1008,1116,1117,5001)
$fwChange = Evt 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' @(2004,2005,2006,2033)
$critical = Evt 'System' @(41,1001,6008)

$totalSec = 0
try { $totalSec = (Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=$24h} -EA SilentlyContinue | Measure-Object).Count } catch { <# security log may require admin #> }

[PSCustomObject]@{
  FailedLogins = $failedLogins
  PrivilegeEscalations = $privEsc
  ServiceInstalls = $svcInstall
  AuditPolicyChanges = $auditChange
  AccountChanges = $acctChange
  DefenderEvents = $defender
  FirewallChanges = $fwChange
  CriticalErrors = $critical
  TotalSecurityEvents = $totalSec
} | ConvertTo-Json -Depth 4 -Compress
`.replace(/\n/g, ' ');

function parseCategory(entries: EventLogEntry[]): EventLogEntry[] {
  return entries;
}

function mapEntries(raw: { Id?: number; TimeCreated?: string; Level?: string; Source?: string; Message?: string }[], category: string): EventLogEntry[] {
  if (!raw || !Array.isArray(raw)) return [];
  return raw.map(e => ({
    id: e.Id || 0,
    timeCreated: e.TimeCreated || '',
    level: (e.Level || 'Information') as EventLogEntry['level'],
    source: e.Source || '',
    message: e.Message || '',
    category,
  }));
}

export async function analyzeEventLogs(): Promise<EventLogSummary> {
  const summary: EventLogSummary = {
    failedLogins: { count: 0, recent: [] },
    privilegeEscalations: { count: 0, recent: [] },
    serviceInstalls: { count: 0, recent: [] },
    auditPolicyChanges: { count: 0, recent: [] },
    accountChanges: { count: 0, recent: [] },
    defenderEvents: { count: 0, recent: [] },
    firewallChanges: { count: 0, recent: [] },
    criticalErrors: { count: 0, recent: [] },
    totalSecurityEvents: 0,
    analysisTime: new Date().toISOString(),
    riskScore: 0,
    riskFactors: [],
  };

  try {
    const { stdout } = await execAsync(
      `powershell -NoProfile -NonInteractive -Command "${PS_SCRIPT.replace(/"/g, '\\"')}"`,
      { timeout: PS_TIMEOUT, maxBuffer: PS_MAX_BUFFER }
    );
    const d = JSON.parse(stdout.trim());

    const mapSection = (section: { Count?: number; Recent?: any[] } | undefined, category: string) => ({
      count: section?.Count || 0,
      recent: parseCategory(mapEntries(Array.isArray(section?.Recent) ? section!.Recent : [], category)),
    });

    summary.failedLogins = mapSection(d.FailedLogins, 'Failed Login');
    summary.privilegeEscalations = mapSection(d.PrivilegeEscalations, 'Privilege Escalation');
    summary.serviceInstalls = mapSection(d.ServiceInstalls, 'Service Install');
    summary.auditPolicyChanges = mapSection(d.AuditPolicyChanges, 'Audit Policy Change');
    summary.accountChanges = mapSection(d.AccountChanges, 'Account Change');
    summary.defenderEvents = mapSection(d.DefenderEvents, 'Defender Event');
    summary.firewallChanges = mapSection(d.FirewallChanges, 'Firewall Change');
    summary.criticalErrors = mapSection(d.CriticalErrors, 'Critical Error');
    summary.totalSecurityEvents = d.TotalSecurityEvents || 0;

    // Risk scoring
    let risk = 0;
    const factors: string[] = [];

    if (summary.failedLogins.count > 10) {
      risk += 30; factors.push(`${summary.failedLogins.count} failed login attempts (brute force indicator)`);
    } else if (summary.failedLogins.count > 3) {
      risk += 10; factors.push(`${summary.failedLogins.count} failed login attempts`);
    }

    if (summary.serviceInstalls.count > 0) {
      risk += 15; factors.push(`${summary.serviceInstalls.count} new service(s) installed`);
    }

    if (summary.auditPolicyChanges.count > 0) {
      risk += 25; factors.push(`Audit policy modified ${summary.auditPolicyChanges.count} time(s)`);
    }

    if (summary.accountChanges.count > 0) {
      risk += 20; factors.push(`${summary.accountChanges.count} account change(s)`);
    }

    if (summary.defenderEvents.count > 0) {
      risk += 15; factors.push(`${summary.defenderEvents.count} Defender alert(s)`);
    }

    if (summary.criticalErrors.count > 0) {
      risk += 10; factors.push(`${summary.criticalErrors.count} critical system error(s)`);
    }

    summary.riskScore = Math.min(100, risk);
    summary.riskFactors = factors;
  } catch (err) {
    console.error('[EventLogAnalyzer] Failed:', err instanceof Error ? err.message : err);
  }

  return summary;
}
