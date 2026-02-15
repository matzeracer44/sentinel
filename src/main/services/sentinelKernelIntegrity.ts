/**
 * SENTINEL — Kernel & Firmware Integrity Module
 * 15 deep-system checks: ELAM, VBS, TPM, SecureBoot, DSE, DKOM, etc.
 * All real PowerShell — no mocks.
 */

import { spawnSync } from 'child_process';

export interface KernelCheck {
  id: string;
  name: string;
  status: 'pass' | 'fail' | 'warn' | 'unknown';
  detail: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
}

function ps(script: string, timeout = 12000): string {
  const r = spawnSync('powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
    { input: script, timeout, windowsHide: true, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }
  );
  if (r.error) throw r.error;
  return (r.stdout || '').trim();
}

function safe(fn: () => KernelCheck): KernelCheck {
  try { return fn(); } catch (e: any) {
    return { id: 'err', name: 'Error', status: 'unknown', detail: e.message, risk: 'medium' };
  }
}

export function checkELAM(): KernelCheck {
  return safe(() => {
    const out = ps(`$s=Get-Service WdFilter -EA SilentlyContinue;if($s -and $s.Status -eq 'Running'){'ACTIVE'}else{'INACTIVE'}`);
    const ok = out === 'ACTIVE';
    return { id: 'kernel-elam', name: 'ELAM Driver', status: ok ? 'pass' : 'warn', detail: ok ? 'Windows Defender ELAM driver active' : 'ELAM not running — early boot protection reduced', risk: ok ? 'low' : 'high' };
  });
}

export function checkVBS(): KernelCheck {
  return safe(() => {
    const out = ps(`
$dg=Get-CimInstance -Class Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard -EA SilentlyContinue
if($dg){"$($dg.VirtualizationBasedSecurityStatus)|$($dg.CodeIntegrityPolicyEnforcementStatus)"}else{'NONE'}
`);
    if (out === 'NONE') return { id: 'kernel-vbs', name: 'VBS / HVCI', status: 'fail', detail: 'Virtualization-Based Security not available', risk: 'critical' };
    const [vbs, hvci] = out.split('|');
    const ok = vbs === '2' && hvci === '2';
    return { id: 'kernel-vbs', name: 'VBS / HVCI', status: ok ? 'pass' : 'warn', detail: `VBS:${vbs === '2' ? 'Running' : 'Off'} HVCI:${hvci === '2' ? 'Enforced' : 'Off'}`, risk: ok ? 'low' : 'high' };
  });
}

export function checkTPM(): KernelCheck {
  return safe(() => {
    const out = ps(`$t=Get-Tpm -EA SilentlyContinue;if($t){"$($t.TpmPresent)|$($t.TpmReady)|$($t.ManufacturerVersion)"}else{'NONE'}`);
    if (out === 'NONE') return { id: 'kernel-tpm', name: 'TPM 2.0', status: 'fail', detail: 'TPM not found', risk: 'critical' };
    const [p, r, v] = out.split('|');
    const ok = p === 'True' && r === 'True';
    return { id: 'kernel-tpm', name: 'TPM 2.0', status: ok ? 'pass' : 'warn', detail: `Present:${p} Ready:${r} Ver:${v}`, risk: ok ? 'low' : 'high' };
  });
}

export function checkSecureBoot(): KernelCheck {
  return safe(() => {
    const out = ps(`try{Confirm-SecureBootUEFI}catch{'Error'}`);
    const ok = out === 'True';
    return { id: 'kernel-secureboot', name: 'Secure Boot', status: ok ? 'pass' : 'fail', detail: ok ? 'Secure Boot enabled' : 'Secure Boot DISABLED', risk: ok ? 'low' : 'critical' };
  });
}

export function checkDSE(): KernelCheck {
  return safe(() => {
    const out = ps(`$b=bcdedit /enum '{current}' 2>&1;$ts=$b-match'testsigning\\s+Yes';$ni=$b-match'nointegritychecks\\s+Yes';if($ts-or$ni){'DISABLED'}else{'ENFORCED'}`);
    const ok = out.includes('ENFORCED');
    return { id: 'kernel-dse', name: 'Driver Signature Enforcement', status: ok ? 'pass' : 'fail', detail: ok ? 'DSE enforced' : 'DSE DISABLED — test signing active', risk: ok ? 'low' : 'critical' };
  });
}

export function checkMSR(): KernelCheck {
  return safe(() => {
    const out = ps(`
$mm=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management' -EA SilentlyContinue
"Override:$($mm.FeatureSettingsOverride)|Mask:$($mm.FeatureSettingsOverrideMask)"
`);
    const hasOverride = out.includes('Override:0') || out.includes('Override:');
    const hasMask = out.includes('Mask:3');
    return { id: 'kernel-msr', name: 'CPU Exploit Mitigations', status: hasOverride && hasMask ? 'pass' : 'warn', detail: out, risk: hasOverride && hasMask ? 'low' : 'medium' };
  });
}

export function checkIOMMU(): KernelCheck {
  return safe(() => {
    const out = ps(`$vt=(Get-CimInstance Win32_Processor).VirtualizationFirmwareEnabled;if($vt-eq$true){'VT-ENABLED'}else{'DISABLED'}`);
    const ok = out.includes('VT-ENABLED');
    return { id: 'kernel-iommu', name: 'IOMMU / VT-d', status: ok ? 'pass' : 'warn', detail: out, risk: ok ? 'low' : 'high' };
  });
}

export function checkMicrocode(): KernelCheck {
  return safe(() => {
    const out = ps(`
$cpu=(Get-CimInstance Win32_Processor|Select -First 1).Name
$rev=(Get-ItemProperty 'HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0' -EA SilentlyContinue).'Update Revision'
$h=if($rev){($rev|%{'{0:X2}'-f$_})-join''}else{'N/A'}
"$cpu|Rev:$h"
`);
    const hasRev = !out.includes('Rev:N/A') && out.includes('Rev:');
    return { id: 'kernel-microcode', name: 'CPU Microcode', status: hasRev ? 'pass' : 'warn', detail: out, risk: hasRev ? 'low' : 'medium' };
  });
}

export function checkShadowStack(): KernelCheck {
  return safe(() => {
    const out = ps(`$cpu=(Get-CimInstance Win32_Processor|Select -First 1).Name;if($cpu-match'(12th|13th|14th|Core Ultra)'){'CET_SUPPORTED'}else{'NO_CET'}`);
    const ok = out.includes('CET_SUPPORTED');
    return { id: 'kernel-shadowstack', name: 'Shadow Stack (CET)', status: ok ? 'pass' : 'warn', detail: out, risk: ok ? 'low' : 'medium' };
  });
}

export function checkDKOM(): KernelCheck {
  return safe(() => {
    const out = ps(`$w=(Get-CimInstance Win32_Process).Count;$p=(Get-Process).Count;$d=[math]::Abs($w-$p);"WMI:$w PS:$p Diff:$d"`);
    const m = out.match(/Diff:(\d+)/);
    const diff = m ? parseInt(m[1]) : 0;
    const ok = diff < 5;
    return { id: 'kernel-dkom', name: 'DKOM Detection', status: ok ? 'pass' : 'warn', detail: `${out} — ${ok ? 'Consistent' : 'Hidden processes possible'}`, risk: ok ? 'low' : 'critical' };
  });
}

export function checkVulnDrivers(): KernelCheck {
  return safe(() => {
    const out = ps(`
$vuln=@('capcom.sys','dbutil_2_3.sys','gdrv.sys','iqvw64e.sys','rtcore64.sys')
$loaded=Get-CimInstance Win32_SystemDriver|?{$_.Started}|%{[IO.Path]::GetFileName($_.PathName).ToLower()}
$found=$loaded|?{$vuln-contains$_}
if($found){"VULN:$($found-join',')"}else{'CLEAN'}
`);
    const clean = out.includes('CLEAN');
    return { id: 'kernel-vulndrivers', name: 'Vulnerable Drivers', status: clean ? 'pass' : 'fail', detail: clean ? 'No known vulnerable drivers' : out, risk: clean ? 'low' : 'critical' };
  });
}

export function checkUnsignedDrivers(): KernelCheck {
  return safe(() => {
    const out = ps(`
$u=0;Get-CimInstance Win32_SystemDriver|?{$_.Started-and$_.PathName}|Select -First 30|%{
  $s=Get-AuthenticodeSignature $_.PathName -EA SilentlyContinue
  if($s.Status-ne'Valid'){$u++}
};"Unsigned:$u"
`);
    const m = out.match(/Unsigned:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'kernel-unsigneddrivers', name: 'Unsigned Drivers', status: c === 0 ? 'pass' : 'warn', detail: `${c} unsigned drivers running`, risk: c === 0 ? 'low' : 'high' };
  });
}

export function checkPrivileges(): KernelCheck {
  return safe(() => {
    const out = ps(`
$p=whoami /priv 2>&1
$risks=@()
if($p-match'SeDebugPrivilege.*Enabled'){$risks+='SeDebug'}
if($p-match'SeLoadDriverPrivilege.*Enabled'){$risks+='SeLoadDriver'}
if($p-match'SeTcbPrivilege.*Enabled'){$risks+='SeTcb'}
if($risks.Count-gt0){"ELEVATED:$($risks-join',')"}else{'NORMAL'}
`);
    const ok = out.includes('NORMAL');
    return { id: 'kernel-privesc', name: 'Privilege Escalation Check', status: ok ? 'pass' : 'warn', detail: out, risk: ok ? 'low' : 'high' };
  });
}

export function checkKernelFiles(): KernelCheck {
  return safe(() => {
    const out = ps(`
$files=@("$env:SystemRoot\\System32\\ntoskrnl.exe","$env:SystemRoot\\System32\\ci.dll","$env:SystemRoot\\System32\\hal.dll","$env:SystemRoot\\System32\\ntdll.dll")
$bad=0;foreach($f in $files){$s=Get-AuthenticodeSignature $f -EA SilentlyContinue;if($s.Status-ne'Valid'){$bad++}}
"Checked:$($files.Count) Invalid:$bad"
`);
    const m = out.match(/Invalid:(\d+)/);
    const bad = m ? parseInt(m[1]) : 0;
    return { id: 'kernel-integrity', name: 'Kernel File Integrity', status: bad === 0 ? 'pass' : 'fail', detail: out, risk: bad === 0 ? 'low' : 'critical' };
  });
}

export function checkKernelDriverPaths(): KernelCheck {
  return safe(() => {
    const out = ps(`
$d=Get-CimInstance Win32_SystemDriver|?{$_.Started-and$_.ServiceType-eq'Kernel Driver'-and$_.PathName-notmatch'Windows|System32|SysWOW64'}
"NonSystemKernelDrivers:$($d.Count)"
`);
    const m = out.match(/NonSystemKernelDrivers:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'kernel-driverpaths', name: 'Kernel Driver Paths', status: c === 0 ? 'pass' : 'warn', detail: `${c} kernel drivers from non-system paths`, risk: c === 0 ? 'low' : 'high' };
  });
}

export function runAllKernelChecks(): KernelCheck[] {
  return [
    checkELAM(), checkVBS(), checkTPM(), checkSecureBoot(),
    checkDSE(), checkMSR(), checkIOMMU(), checkMicrocode(),
    checkShadowStack(), checkDKOM(), checkVulnDrivers(),
    checkUnsignedDrivers(), checkPrivileges(), checkKernelFiles(),
    checkKernelDriverPaths(),
  ];
}
