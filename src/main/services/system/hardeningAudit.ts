/**
 * SENTINEL — System Hardening Audit Service
 * Checks 12 security hardening controls, each weighted, producing a 0-100 score.
 * PowerShell-based checks for: Firewall, Defender, UAC, BitLocker, SecureBoot,
 * SMBv1, RDP, Guest account, Audit policy, PowerShell execution policy, Auto-Updates.
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const PS_TIMEOUT = 12000;
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
  // Primary: PowerShell cmdlet
  let out = await runPS(
    "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress"
  );
  try {
    if (out) {
      const profiles = JSON.parse(out);
      const list = Array.isArray(profiles) ? profiles : [profiles];
      const allEnabled = list.every((p: any) => p.Enabled === true || p.Enabled === 1);
      const enabledCount = list.filter((p: any) => p.Enabled === true || p.Enabled === 1).length;
      return {
        id: 'firewall', name: 'Windows-Firewall', description: 'Alle Firewall-Profile aktiv',
        status: allEnabled ? 'pass' : enabledCount > 0 ? 'warn' : 'fail',
        weight: 15, detail: allEnabled ? 'Alle Profile aktiv' : `${enabledCount}/${list.length} Profile aktiv`,
        fixable: true, fixCommand: 'Set-NetFirewallProfile -All -Enabled True',
      };
    }
  } catch { /* fallback below */ }
  // Fallback: netsh (works without admin)
  const netsh = await runPS("netsh advfirewall show allprofiles state");
  if (netsh) {
    const onCount = (netsh.match(/EIN|ON/gi) || []).length;
    return {
      id: 'firewall', name: 'Windows-Firewall', description: 'Alle Firewall-Profile aktiv',
      status: onCount >= 3 ? 'pass' : onCount > 0 ? 'warn' : 'fail',
      weight: 15, detail: onCount >= 3 ? 'Alle Profile aktiv' : `${onCount}/3 Profile aktiv`,
      fixable: true, fixCommand: 'Set-NetFirewallProfile -All -Enabled True',
    };
  }
  return { id: 'firewall', name: 'Windows-Firewall', description: 'Alle Firewall-Profile aktiv', status: 'error', weight: 15, detail: 'Firewall-Status konnte nicht abgefragt werden', fixable: false };
}

async function checkDefender(): Promise<HardeningCheck> {
  // Try Get-MpComputerStatus first
  const out = await runPS(
    "Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge | ConvertTo-Json -Compress"
  );
  try {
    if (out) {
      const d = JSON.parse(out);
      const enabled = (d.AMServiceEnabled === true || d.AMServiceEnabled === 1) &&
                      (d.AntivirusEnabled === true || d.AntivirusEnabled === 1) &&
                      (d.RealTimeProtectionEnabled === true || d.RealTimeProtectionEnabled === 1);
      const sigAge = typeof d.AntivirusSignatureAge === 'number' ? d.AntivirusSignatureAge : 999;
      const upToDate = sigAge <= 7;
      return {
        id: 'defender', name: 'Windows Defender', description: 'Defender aktiv mit aktuellen Signaturen',
        status: enabled && upToDate ? 'pass' : enabled ? 'warn' : 'fail',
        weight: 15, detail: enabled ? (upToDate ? `Aktiv, Signaturen aktuell (${sigAge}d)` : `Aktiv, Signaturen ${sigAge} Tage alt`) : 'Defender deaktiviert',
        fixable: false,
      };
    }
  } catch { /* fallback below */ }
  // Fallback: check if Defender service is running
  const svc = await runPS("(Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status");
  if (svc && (svc.toLowerCase().includes('running') || svc.toLowerCase().includes('gestartet'))) {
    return {
      id: 'defender', name: 'Windows Defender', description: 'Defender aktiv mit aktuellen Signaturen',
      status: 'pass', weight: 15, detail: 'Defender-Dienst aktiv',
      fixable: false,
    };
  }
  return { id: 'defender', name: 'Windows Defender', description: 'Defender aktiv mit aktuellen Signaturen', status: 'error', weight: 15, detail: 'Defender-Status konnte nicht abgefragt werden', fixable: false };
}

async function checkUAC(): Promise<HardeningCheck> {
  const out = await runPS(
    "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA"
  );
  const enabled = out.trim() === '1';
  return {
    id: 'uac', name: 'Benutzerkontensteuerung (UAC)', description: 'UAC aktiviert',
    status: enabled ? 'pass' : 'fail', weight: 10,
    detail: enabled ? 'UAC ist aktiviert' : 'UAC ist deaktiviert',
    fixable: true,
  };
}

async function checkAutoUpdates(): Promise<HardeningCheck> {
  const out = await runPS(
    "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoUpdate -ErrorAction SilentlyContinue).NoAutoUpdate"
  );
  const disabled = out.trim() === '1';
  return {
    id: 'autoupdate', name: 'Automatische Updates', description: 'Windows Update nicht per Richtlinie deaktiviert',
    status: disabled ? 'fail' : 'pass', weight: 10,
    detail: disabled ? 'Updates per Richtlinie deaktiviert' : 'Automatische Updates aktiv',
    fixable: false,
  };
}

async function checkBitLocker(): Promise<HardeningCheck> {
  const out = await runPS(
    "Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProtectionStatus"
  );
  const isOn = out.trim() === 'On' || out.trim() === '1';
  // Windows Home has no BitLocker — don't penalize
  if (!out.trim() || out.toLowerCase().includes('error') || out.toLowerCase().includes('not recognized')) {
    return {
      id: 'bitlocker', name: 'BitLocker-Verschl\u00fcsselung', description: 'Systemlaufwerk verschl\u00fcsselt',
      status: 'warn', weight: 5, detail: 'BitLocker nicht verf\u00fcgbar (Windows Home)',
      fixable: false,
    };
  }
  return {
    id: 'bitlocker', name: 'BitLocker-Verschl\u00fcsselung', description: 'Systemlaufwerk verschl\u00fcsselt',
    status: isOn ? 'pass' : 'warn', weight: 10,
    detail: isOn ? 'Laufwerk C: verschl\u00fcsselt' : 'Laufwerk C: nicht verschl\u00fcsselt',
    fixable: false,
  };
}

async function checkSecureBoot(): Promise<HardeningCheck> {
  const out = await runPS("Confirm-SecureBootUEFI -ErrorAction SilentlyContinue");
  const enabled = out.trim().toLowerCase() === 'true';
  return {
    id: 'secureboot', name: 'Secure Boot', description: 'UEFI Secure Boot aktiviert',
    status: enabled ? 'pass' : 'warn', weight: 5,
    detail: enabled ? 'Secure Boot aktiv' : 'Secure Boot nicht erkannt',
    fixable: false,
  };
}

async function checkSMBv1(): Promise<HardeningCheck> {
  const out = await runPS(
    "(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol"
  );
  const smbEnabled = out.trim().toLowerCase() === 'true';
  return {
    id: 'smbv1', name: 'SMBv1 deaktiviert', description: 'Legacy-SMBv1-Protokoll deaktiviert',
    status: smbEnabled ? 'fail' : 'pass', weight: 10,
    detail: smbEnabled ? 'SMBv1 ist AKTIV (verwundbar)' : 'SMBv1 deaktiviert',
    fixable: true, fixCommand: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force',
  };
}

async function checkRDP(): Promise<HardeningCheck> {
  const out = await runPS(
    "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections"
  );
  const denied = out.trim() === '1';
  return {
    id: 'rdp', name: 'Remotedesktop', description: 'RDP deaktiviert wenn nicht ben\u00f6tigt',
    status: denied ? 'pass' : 'warn', weight: 5,
    detail: denied ? 'RDP ist deaktiviert' : 'RDP ist aktiviert',
    fixable: true,
  };
}

async function checkGuestAccount(): Promise<HardeningCheck> {
  const out = await runPS(
    "(Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled"
  );
  const guestEnabled = out.trim().toLowerCase() === 'true';
  return {
    id: 'guest', name: 'Gastkonto', description: 'Gastkonto deaktiviert',
    status: guestEnabled ? 'fail' : 'pass', weight: 5,
    detail: guestEnabled ? 'Gastkonto ist AKTIV' : 'Gastkonto deaktiviert',
    fixable: true, fixCommand: 'Disable-LocalUser -Name Guest',
  };
}

async function checkAuditPolicy(): Promise<HardeningCheck> {
  const out = await runPS(
    "auditpol /get /category:* 2>$null | Select-String 'Success and Failure|Erfolg und Fehler' | Measure-Object | Select-Object -ExpandProperty Count"
  );
  const count = parseInt(out.trim(), 10) || 0;
  return {
    id: 'audit', name: '\u00dcberwachungsrichtlinie', description: 'Audit-Protokollierung f\u00fcr Sicherheitsereignisse',
    status: count >= 5 ? 'pass' : count >= 1 ? 'warn' : 'fail', weight: 5,
    detail: `${count} Audit-Kategorien mit vollst\u00e4ndiger Protokollierung`,
    fixable: false,
  };
}

async function checkPSExecutionPolicy(): Promise<HardeningCheck> {
  const out = await runPS("Get-ExecutionPolicy");
  const policy = out.trim();
  const restricted = ['Restricted', 'AllSigned', 'RemoteSigned'].includes(policy);
  return {
    id: 'ps-policy', name: 'PowerShell-Ausf\u00fchrungsrichtlinie', description: 'Skriptausf\u00fchrung eingeschr\u00e4nkt',
    status: restricted ? 'pass' : 'warn', weight: 5,
    detail: `Richtlinie: ${policy || 'Unbekannt'}`,
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
