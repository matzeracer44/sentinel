/**
 * SENTINEL — System Hardening Audit Service
 * Checks 12 security hardening controls, each weighted, producing a 0-100 score.
 * PowerShell-based checks for: Firewall, Defender, UAC, BitLocker, SecureBoot,
 * SMBv1, RDP, Guest account, Audit policy, PowerShell execution policy, Auto-Updates.
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const PS_TIMEOUT = 8000;
const PS_MAX_BUFFER = 4 * 1024 * 1024;

export interface HardeningCheck {
  id: string;
  name: string;
  description: string;
  status: 'pass' | 'fail' | 'warn' | 'error';
  weight: number;
  detail: string;
  fixable: boolean;
  fixCommand?: string;
}

export interface HardeningResult {
  score: number;
  maxScore: number;
  percentage: number;
  checks: HardeningCheck[];
  timestamp: string;
}

async function runPS(cmd: string): Promise<string> {
  try {
    const { stdout } = await execAsync(
      `powershell -NoProfile -NonInteractive -Command "${cmd.replace(/"/g, '\\"')}"`,
      { timeout: PS_TIMEOUT, maxBuffer: PS_MAX_BUFFER }
    );
    return stdout.trim();
  } catch {
    return '';
  }
}

async function checkFirewall(): Promise<HardeningCheck> {
  const out = await runPS(
    "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress"
  );
  try {
    const profiles = JSON.parse(out || '[]');
    const list = Array.isArray(profiles) ? profiles : [profiles];
    const allEnabled = list.every((p: { Enabled: boolean }) => p.Enabled === true);
    const enabledCount = list.filter((p: { Enabled: boolean }) => p.Enabled).length;
    return {
      id: 'firewall', name: 'Windows Firewall', description: 'All firewall profiles active',
      status: allEnabled ? 'pass' : enabledCount > 0 ? 'warn' : 'fail',
      weight: 15, detail: `${enabledCount}/${list.length} profiles enabled`,
      fixable: true, fixCommand: 'Set-NetFirewallProfile -All -Enabled True',
    };
  } catch {
    return { id: 'firewall', name: 'Windows Firewall', description: 'All firewall profiles active', status: 'error', weight: 15, detail: 'Could not query firewall', fixable: false };
  }
}

async function checkDefender(): Promise<HardeningCheck> {
  const out = await runPS(
    "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge | ConvertTo-Json -Compress"
  );
  try {
    const d = JSON.parse(out);
    const enabled = d.AMServiceEnabled && d.AntivirusEnabled && d.RealTimeProtectionEnabled;
    const sigAge = d.AntivirusSignatureAge || 999;
    const upToDate = sigAge <= 3;
    return {
      id: 'defender', name: 'Windows Defender', description: 'Defender active + signatures current',
      status: enabled && upToDate ? 'pass' : enabled ? 'warn' : 'fail',
      weight: 15, detail: enabled ? `Signatures ${sigAge}d old` : 'Defender disabled',
      fixable: false,
    };
  } catch {
    return { id: 'defender', name: 'Windows Defender', description: 'Defender active + signatures current', status: 'error', weight: 15, detail: 'Could not query Defender', fixable: false };
  }
}

async function checkUAC(): Promise<HardeningCheck> {
  const out = await runPS(
    "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA"
  );
  const enabled = out.trim() === '1';
  return {
    id: 'uac', name: 'User Account Control', description: 'UAC enabled',
    status: enabled ? 'pass' : 'fail', weight: 10,
    detail: enabled ? 'UAC is enabled' : 'UAC is disabled',
    fixable: true,
  };
}

async function checkAutoUpdates(): Promise<HardeningCheck> {
  const out = await runPS(
    "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoUpdate -ErrorAction SilentlyContinue).NoAutoUpdate"
  );
  const disabled = out.trim() === '1';
  return {
    id: 'autoupdate', name: 'Automatic Updates', description: 'Windows Update not disabled by policy',
    status: disabled ? 'fail' : 'pass', weight: 10,
    detail: disabled ? 'Auto-updates disabled by policy' : 'Auto-updates enabled',
    fixable: false,
  };
}

async function checkBitLocker(): Promise<HardeningCheck> {
  const out = await runPS(
    "Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProtectionStatus"
  );
  const isOn = out.trim() === 'On' || out.trim() === '1';
  return {
    id: 'bitlocker', name: 'BitLocker Encryption', description: 'System drive encrypted',
    status: isOn ? 'pass' : 'warn', weight: 10,
    detail: isOn ? 'C: drive encrypted' : 'C: drive not encrypted',
    fixable: false,
  };
}

async function checkSecureBoot(): Promise<HardeningCheck> {
  const out = await runPS("Confirm-SecureBootUEFI -ErrorAction SilentlyContinue");
  const enabled = out.trim().toLowerCase() === 'true';
  return {
    id: 'secureboot', name: 'Secure Boot', description: 'UEFI Secure Boot enabled',
    status: enabled ? 'pass' : 'warn', weight: 5,
    detail: enabled ? 'Secure Boot active' : 'Secure Boot not detected',
    fixable: false,
  };
}

async function checkSMBv1(): Promise<HardeningCheck> {
  const out = await runPS(
    "(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol"
  );
  const enabled = out.trim().toLowerCase() === 'true';
  return {
    id: 'smbv1', name: 'SMBv1 Disabled', description: 'Legacy SMBv1 protocol disabled',
    status: enabled ? 'fail' : 'pass', weight: 10,
    detail: enabled ? 'SMBv1 is ENABLED (vulnerable)' : 'SMBv1 disabled',
    fixable: true, fixCommand: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force',
  };
}

async function checkRDP(): Promise<HardeningCheck> {
  const out = await runPS(
    "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections"
  );
  const denied = out.trim() === '1';
  return {
    id: 'rdp', name: 'Remote Desktop', description: 'RDP disabled when not needed',
    status: denied ? 'pass' : 'warn', weight: 5,
    detail: denied ? 'RDP is disabled' : 'RDP is enabled',
    fixable: true,
  };
}

async function checkGuestAccount(): Promise<HardeningCheck> {
  const out = await runPS(
    "(Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled"
  );
  const enabled = out.trim().toLowerCase() === 'true';
  return {
    id: 'guest', name: 'Guest Account', description: 'Guest account disabled',
    status: enabled ? 'fail' : 'pass', weight: 5,
    detail: enabled ? 'Guest account ENABLED' : 'Guest account disabled',
    fixable: true, fixCommand: 'Disable-LocalUser -Name Guest',
  };
}

async function checkAuditPolicy(): Promise<HardeningCheck> {
  const out = await runPS(
    "auditpol /get /category:* 2>$null | Select-String 'Success and Failure' | Measure-Object | Select-Object -ExpandProperty Count"
  );
  const count = parseInt(out.trim(), 10) || 0;
  return {
    id: 'audit', name: 'Audit Policy', description: 'Audit logging for security events',
    status: count >= 5 ? 'pass' : count >= 1 ? 'warn' : 'fail', weight: 5,
    detail: `${count} audit categories with full logging`,
    fixable: false,
  };
}

async function checkPSExecutionPolicy(): Promise<HardeningCheck> {
  const out = await runPS("Get-ExecutionPolicy");
  const policy = out.trim();
  const restricted = ['Restricted', 'AllSigned', 'RemoteSigned'].includes(policy);
  return {
    id: 'ps-policy', name: 'PowerShell Execution Policy', description: 'Script execution restricted',
    status: restricted ? 'pass' : 'warn', weight: 5,
    detail: `Policy: ${policy || 'Unknown'}`,
    fixable: false,
  };
}

export async function runHardeningAudit(): Promise<HardeningResult> {
  const checks = await Promise.all([
    checkFirewall(),
    checkDefender(),
    checkUAC(),
    checkAutoUpdates(),
    checkBitLocker(),
    checkSecureBoot(),
    checkSMBv1(),
    checkRDP(),
    checkGuestAccount(),
    checkAuditPolicy(),
    checkPSExecutionPolicy(),
  ]);

  const maxScore = checks.reduce((sum, c) => sum + c.weight, 0);
  const earned = checks.reduce((sum, c) => {
    if (c.status === 'pass') return sum + c.weight;
    if (c.status === 'warn') return sum + Math.floor(c.weight * 0.5);
    return sum;
  }, 0);

  return {
    score: earned,
    maxScore,
    percentage: Math.round((earned / maxScore) * 100),
    checks,
    timestamp: new Date().toISOString(),
  };
}
