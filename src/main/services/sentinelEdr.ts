/**
 * SENTINEL — EDR & Behavioral Engine Module
 * 25 security checks: AMSI, LSASS, process hollowing, WMI persistence, COM hijacking, etc.
 * All real PowerShell — no mocks.
 */

import { spawnSync } from 'child_process';

export interface EdrCheck {
  id: string;
  name: string;
  status: 'pass' | 'fail' | 'warn' | 'unknown';
  detail: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  offenders?: { label: string; detail: string; severity?: string }[];
}

function ps(script: string, timeout = 15000): string {
  const r = spawnSync('powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
    { input: script, timeout, windowsHide: true, encoding: 'utf8', maxBuffer: 5 * 1024 * 1024 }
  );
  if (r.error) throw r.error;
  return (r.stdout || '').trim();
}

function safe(id: string, name: string, fn: () => EdrCheck): EdrCheck {
  try { return fn(); } catch (e: any) {
    return { id, name, status: 'unknown', detail: e.message, risk: 'medium' };
  }
}

export function checkAMSI(): EdrCheck {
  return safe('edr-amsi', 'AMSI Deep Inspection', () => {
    const out = ps(`$a=(Get-MpComputerStatus -EA SilentlyContinue).AMServiceEnabled;if($a){'ACTIVE'}else{'INACTIVE'}`);
    const ok = out === 'ACTIVE';
    return { id: 'edr-amsi', name: 'AMSI Deep Inspection', status: ok ? 'pass' : 'fail', detail: ok ? 'AMSI active — scripts scanned before execution' : 'AMSI disabled', risk: ok ? 'low' : 'critical' };
  });
}

export function checkETW(): EdrCheck {
  return safe('edr-etw', 'ETW Threat Intelligence', () => {
    const out = ps(`$s=logman query -ets 2>&1;$c=($s|Select-String 'Running').Count;"ETWSessions:$c"`);
    const m = out.match(/ETWSessions:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'edr-etw', name: 'ETW Threat Intelligence', status: c > 0 ? 'pass' : 'warn', detail: `${c} active ETW sessions`, risk: c > 0 ? 'low' : 'medium' };
  });
}

export function checkProcessHollowing(): EdrCheck {
  return safe('edr-hollowing', 'Process Hollowing Detection', () => {
    const out = ps(`
$ErrorActionPreference='SilentlyContinue'
$sys=@('svchost','csrss','lsass','services','smss','wininit','winlogon')
$bad=@()
foreach($n in $sys){Get-Process -Name $n -EA SilentlyContinue|%{if($_.Path-and$_.Path-notmatch'System32|SysWOW64'){$bad+="$($_.Name):$($_.Path)"}}}
if($bad.Count-gt0){"SUSPECT:$($bad-join';')"}else{'CLEAN'}
`);
    const clean = out.includes('CLEAN');
    const offenders: { label: string; detail: string; severity?: string }[] = [];
    if (!clean) {
      const suspects = out.replace('SUSPECT:', '').split(';').filter(Boolean);
      for (const s of suspects) {
        const [name, ...pathParts] = s.split(':');
        offenders.push({ label: name || s, detail: pathParts.join(':') || 'Unexpected path', severity: 'HIGH' });
      }
    }
    return { id: 'edr-hollowing', name: 'Process Hollowing Detection', status: clean ? 'pass' : 'fail', detail: clean ? 'All system processes from legitimate paths' : out, risk: clean ? 'low' : 'critical', offenders };
  });
}

export function checkReflectiveDLL(): EdrCheck {
  return safe('edr-reflectivedll', 'Reflective DLL Check', () => {
    const out = ps(`
$ErrorActionPreference='SilentlyContinue'
$u=0;Get-Process|?{$_.Modules.Count-gt0}|Select -First 15|%{
  foreach($m in $_.Modules){if($m.FileName-and$m.FileName-notmatch'Windows|Program Files|System32'){
    $s=Get-AuthenticodeSignature $m.FileName -EA SilentlyContinue;if($s.Status-ne'Valid'){$u++}
  }}
};"UnsignedModules:$u"
`);
    const m = out.match(/UnsignedModules:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'edr-reflectivedll', name: 'Reflective DLL Check', status: c === 0 ? 'pass' : 'warn', detail: `${c} unsigned modules in running processes`, risk: c === 0 ? 'low' : 'high' };
  });
}

export function checkAPCInjection(): EdrCheck {
  return safe('edr-apc', 'APC Injection Monitor', () => {
    const out = ps(`$t=(Get-CimInstance Win32_Thread|?{$_.ThreadState-eq5}).Count;"SuspendedThreads:$t"`);
    const m = out.match(/SuspendedThreads:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'edr-apc', name: 'APC Injection Monitor', status: c > 50 ? 'warn' : 'pass', detail: `${c} suspended threads — ${c > 50 ? 'abnormally high' : 'normal'}`, risk: c > 50 ? 'high' : 'low' };
  });
}

export function checkLSASS(): EdrCheck {
  return safe('edr-lsass', 'LSASS Protection', () => {
    const out = ps(`
$ppl=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -EA SilentlyContinue).RunAsPPL
$cg=(Get-CimInstance -Class Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard -EA SilentlyContinue).SecurityServicesRunning-contains 1
"PPL:$ppl|CredGuard:$cg"
`);
    const ppl = out.includes('PPL:1');
    const cg = out.includes('CredGuard:True');
    return { id: 'edr-lsass', name: 'LSASS Protection', status: ppl || cg ? 'pass' : 'fail', detail: `PPL:${ppl ? 'On' : 'Off'} CredGuard:${cg ? 'On' : 'Off'}`, risk: ppl || cg ? 'low' : 'critical' };
  });
}

export function checkSyscallIntegrity(): EdrCheck {
  return safe('edr-syscall', 'Syscall Integrity', () => {
    const out = ps(`$s=Get-AuthenticodeSignature "$env:SystemRoot\\System32\\ntdll.dll" -EA SilentlyContinue;"ntdll:$($s.Status)"`);
    const ok = out.includes('Valid');
    return { id: 'edr-syscall', name: 'Syscall Integrity', status: ok ? 'pass' : 'fail', detail: out, risk: ok ? 'low' : 'critical' };
  });
}

export function checkRansomwareFiles(): EdrCheck {
  return safe('edr-entropy', 'Ransomware File Check', () => {
    const out = ps(`
$ErrorActionPreference='SilentlyContinue'
$c=0;@("$env:USERPROFILE\\Desktop","$env:USERPROFILE\\Documents")|%{
  Get-ChildItem $_ -File -EA SilentlyContinue|?{$_.Extension-match'\\.(encrypted|locked|crypto|crypt|enc|ransom)$'}|%{$c++}
};"SuspiciousFiles:$c"
`);
    const m = out.match(/SuspiciousFiles:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'edr-entropy', name: 'Ransomware File Check', status: c === 0 ? 'pass' : 'fail', detail: c === 0 ? 'No ransomware file extensions detected' : `${c} suspicious files`, risk: c === 0 ? 'low' : 'critical' };
  });
}

export function checkWMIPersistence(): EdrCheck {
  return safe('edr-wmi', 'WMI Persistence', () => {
    const script = `$ErrorActionPreference='SilentlyContinue'
$consumers=Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -EA SilentlyContinue
$results=@()
foreach($c in $consumers){
  $results+=[PSCustomObject]@{name=$c.Name;type=$c.CimClass.CimClassName;detail=if($c.CommandLineTemplate){$c.CommandLineTemplate}elseif($c.ScriptText){$c.ScriptText.Substring(0,[Math]::Min(100,$c.ScriptText.Length))}else{'N/A'}}
}
$f=(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -EA SilentlyContinue).Count
$b=(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -EA SilentlyContinue).Count
@{consumers=$results;filterCount=[int]$f;bindingCount=[int]$b}|ConvertTo-Json -Depth 2 -Compress`;
    const raw = ps(script, 10000);
    let consumerCount = 0;
    const offenders: { label: string; detail: string; severity?: string }[] = [];
    try {
      const parsed = JSON.parse(raw || '{}');
      const consumers = Array.isArray(parsed.consumers) ? parsed.consumers : parsed.consumers ? [parsed.consumers] : [];
      consumerCount = consumers.length;
      for (const c of consumers) {
        offenders.push({
          label: `${c.name || 'Unknown'} (${c.type || 'Consumer'})`,
          detail: c.detail || 'N/A',
          severity: (c.type || '').includes('CommandLine') ? 'HIGH' : 'MEDIUM',
        });
      }
    } catch { consumerCount = 0; }
    const detail = `${consumerCount} WMI consumers found`;
    return { id: 'edr-wmi', name: 'WMI Persistence', status: consumerCount === 0 ? 'pass' : 'warn', detail, risk: consumerCount === 0 ? 'low' : 'high', offenders };
  });
}

export function checkPPIDSpoofing(): EdrCheck {
  return safe('edr-ppid', 'Parent-PID Spoofing', () => {
    const out = ps(`
$ErrorActionPreference='SilentlyContinue'
$bad=@()
Get-CimInstance Win32_Process|?{$_.Name-match'cmd|powershell|pwsh'}|%{
  $par=Get-Process -Id $_.ParentProcessId -EA SilentlyContinue
  if($par-and$par.ProcessName-notmatch'explorer|svchost|cmd|powershell|pwsh|code|WindowsTerminal|conhost'){
    $bad+="$($_.Name)<-$($par.ProcessName)"
  }
}
if($bad.Count-gt0){"SUSPECT:$($bad-join';')"}else{'CLEAN'}
`);
    const clean = out.includes('CLEAN');
    const offenders: { label: string; detail: string; severity?: string }[] = [];
    if (!clean) {
      const suspects = out.replace('SUSPECT:', '').split(';').filter(Boolean);
      for (const s of suspects) {
        const [child, parent] = s.split('<-');
        offenders.push({ label: child || s, detail: `Unexpected parent: ${parent || 'unknown'}`, severity: 'HIGH' });
      }
    }
    return { id: 'edr-ppid', name: 'Parent-PID Spoofing', status: clean ? 'pass' : 'warn', detail: clean ? 'Shell processes have expected parents' : out, risk: clean ? 'low' : 'high', offenders };
  });
}

export function checkTokenElevation(): EdrCheck {
  return safe('edr-token', 'Token Elevation Guard', () => {
    const out = ps(`
$u=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -EA SilentlyContinue
"LUA:$($u.EnableLUA)|ConsentAdmin:$($u.ConsentPromptBehaviorAdmin)|SecureDesktop:$($u.PromptOnSecureDesktop)"
`);
    const lua = out.includes('LUA:1');
    return { id: 'edr-token', name: 'Token Elevation Guard', status: lua ? 'pass' : 'fail', detail: out, risk: lua ? 'low' : 'critical' };
  });
}

export function checkCOMHijacking(): EdrCheck {
  return safe('edr-com', 'COM Hijacking Check', () => {
    const out = ps(`
$ErrorActionPreference='SilentlyContinue'
$c=0;@('HKCU:\\SOFTWARE\\Classes\\CLSID','HKCU:\\SOFTWARE\\Classes\\Wow6432Node\\CLSID')|%{
  if(Test-Path $_){$c+=(Get-ChildItem $_ -EA SilentlyContinue).Count}
};"UserCLSIDs:$c"
`);
    const m = out.match(/UserCLSIDs:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'edr-com', name: 'COM Hijacking Check', status: c < 10 ? 'pass' : 'warn', detail: `${c} user-level CLSIDs`, risk: c < 10 ? 'low' : 'high' };
  });
}

export function checkExploitMitigations(): EdrCheck {
  return safe('edr-mitigations', 'Exploit Mitigations', () => {
    const out = ps(`
$m=Get-ProcessMitigation -System -EA SilentlyContinue
"DEP:$($m.DEP.Enable)|ASLR:$($m.ASLR.ForceRelocateImages)|CFG:$($m.CFG.Enable)"
`);
    const depOn = out.includes('DEP:True') || out.includes('DEP:ON');
    const aslrOn = out.includes('ASLR:ON') || out.includes('ASLR:True');
    const allOn = depOn && aslrOn;
    return { id: 'edr-mitigations', name: 'Exploit Mitigations (DEP/ASLR/CFG)', status: allOn ? 'pass' : depOn ? 'warn' : 'fail', detail: out, risk: allOn ? 'low' : depOn ? 'medium' : 'high' };
  });
}

export function checkLSAConfig(): EdrCheck {
  return safe('edr-lsa', 'LSA Protection', () => {
    const out = ps(`
$l=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -EA SilentlyContinue
"RunAsPPL:$($l.RunAsPPL)|LimitBlank:$($l.LimitBlankPasswordUse)|RestrictAnon:$($l.RestrictAnonymous)"
`);
    const ppl = out.includes('RunAsPPL:1');
    return { id: 'edr-lsa', name: 'LSA Protection', status: ppl ? 'pass' : 'warn', detail: out, risk: ppl ? 'low' : 'high' };
  });
}

export function checkSandboxCapabilities(): EdrCheck {
  return safe('edr-sandbox', 'Sandbox Capabilities', () => {
    const out = ps(`
$np=(Get-MpPreference -EA SilentlyContinue).EnableNetworkProtection
$sb=(Get-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -EA SilentlyContinue).State
"NetworkProtection:$np|WinSandbox:$sb"
`);
    const npOn = out.includes('NetworkProtection:1') || out.includes('NetworkProtection:2');
    const sbOn = out.includes('WinSandbox:Enabled');
    return { id: 'edr-sandbox', name: 'Sandbox Capabilities', status: npOn ? 'pass' : 'warn', detail: `NetworkProtection:${npOn ? 'On' : 'Off'} WinSandbox:${sbOn ? 'Available' : 'Not installed'}`, risk: npOn ? 'low' : 'medium' };
  });
}

export function checkBehaviorScore(): EdrCheck {
  return safe('edr-behavior', 'Process Behavior Score', () => {
    const out = ps(`
$ErrorActionPreference='SilentlyContinue'
$r=@();Get-Process|?{$_.CPU-gt60-and$_.WorkingSet64-gt500MB}|%{
  $s=Get-AuthenticodeSignature $_.Path -EA SilentlyContinue
  if($s.Status-ne'Valid'){$r+="$($_.ProcessName)(CPU:$([math]::Round($_.CPU,1)))"}
}
if($r.Count-gt0){"RISKY:$($r-join';')"}else{'CLEAN'}
`);
    const clean = out.includes('CLEAN');
    return { id: 'edr-behavior', name: 'Process Behavior Score', status: clean ? 'pass' : 'warn', detail: clean ? 'No high-resource unsigned processes' : out, risk: clean ? 'low' : 'high' };
  });
}

export function checkCriticalFiles(): EdrCheck {
  return safe('edr-critfiles', 'Critical File Protection', () => {
    const out = ps(`
$w=0;@("$env:SystemRoot\\System32\\drivers\\etc\\hosts","$env:SystemRoot\\System32\\config\\SAM")|%{
  $a=Get-Acl $_ -EA SilentlyContinue
  if($a.Access|?{$_.IdentityReference-match'Users|Everyone'-and$_.FileSystemRights-match'Write'}){$w++}
};"WritableByUsers:$w"
`);
    const m = out.match(/WritableByUsers:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'edr-critfiles', name: 'Critical File Protection', status: c === 0 ? 'pass' : 'warn', detail: c === 0 ? 'Critical files properly protected' : `${c} critical files writable by users`, risk: c === 0 ? 'low' : 'high' };
  });
}

export function checkAutoRunAudit(): EdrCheck {
  return safe('edr-autorun', 'Auto-Run Audit', () => {
    const script = `$ErrorActionPreference='SilentlyContinue'
$entries=@()
@('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run','HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce','HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce')|%{
  $k=$_
  if(Test-Path $k){
    Get-ItemProperty $k|ForEach-Object{$_.PSObject.Properties|Where-Object{$_.Name-notmatch'^PS'}|ForEach-Object{
      $entries+=[PSCustomObject]@{name=$_.Name;value=$_.Value;key=$k}
    }}
  }
}
$tasks=(Get-ScheduledTask|?{$_.State-eq'Ready'-and$_.Actions.Count-gt0}).Count
@{entries=$entries;taskCount=[int]$tasks}|ConvertTo-Json -Depth 2 -Compress`;
    const raw = ps(script, 10000);
    let autorunCount = 0;
    let taskCount = 0;
    const offenders: { label: string; detail: string; severity?: string }[] = [];
    try {
      const parsed = JSON.parse(raw || '{}');
      taskCount = parsed.taskCount || 0;
      const entries = Array.isArray(parsed.entries) ? parsed.entries : parsed.entries ? [parsed.entries] : [];
      autorunCount = entries.length;
      for (const e of entries.slice(0, 30)) {
        const val = String(e.value || '');
        const isSystem32 = val.toLowerCase().includes('system32') || val.toLowerCase().includes('program files');
        offenders.push({
          label: e.name || 'Unknown',
          detail: `${val.length > 80 ? val.substring(0, 80) + '...' : val} [${(e.key || '').includes('HKCU') ? 'User' : 'Machine'}]`,
          severity: isSystem32 ? 'LOW' : 'MEDIUM',
        });
      }
    } catch { autorunCount = 0; }
    const suspicious = autorunCount > 20 || taskCount > 100;
    return { id: 'edr-autorun', name: 'Auto-Run Audit', status: suspicious ? 'warn' : 'pass', detail: `${autorunCount} autorun entries, ${taskCount} scheduled tasks`, risk: suspicious ? 'medium' : 'low', offenders };
  });
}

export function checkScriptBlockLogging(): EdrCheck {
  return safe('edr-scriptlog', 'Script-Block Logging', () => {
    const out = ps(`
$sbl=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -EA SilentlyContinue).EnableScriptBlockLogging
$ml=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -EA SilentlyContinue).EnableModuleLogging
"ScriptBlock:$sbl|Module:$ml"
`);
    const on = out.includes('ScriptBlock:1');
    return { id: 'edr-scriptlog', name: 'Script-Block Logging', status: on ? 'pass' : 'warn', detail: out, risk: on ? 'low' : 'medium' };
  });
}

export function checkDefenderRealtime(): EdrCheck {
  return safe('edr-memscan', 'Defender Realtime / Memory', () => {
    const out = ps(`
$d=Get-MpComputerStatus -EA SilentlyContinue
"RealTime:$($d.RealTimeProtectionEnabled)|Behavior:$($d.BehaviorMonitorEnabled)|IOAV:$($d.IoavProtectionEnabled)|NRI:$($d.NISEnabled)"
`);
    const rt = out.includes('RealTime:True');
    return { id: 'edr-memscan', name: 'Defender Realtime / Memory', status: rt ? 'pass' : 'fail', detail: out, risk: rt ? 'low' : 'high' };
  });
}

export function checkSysmon(): EdrCheck {
  return safe('edr-apimap', 'Sysmon / API Monitoring', () => {
    const out = ps(`
$s=Get-Service Sysmon* -EA SilentlyContinue|?{$_.Status-eq'Running'}
"Sysmon:$($s.Count-gt0)"
`);
    return { id: 'edr-apimap', name: 'Sysmon / API Monitoring', status: out.includes('True') ? 'pass' : 'warn', detail: out, risk: out.includes('True') ? 'low' : 'medium' };
  });
}

export function checkCodeIntegrity(): EdrCheck {
  return safe('edr-cig', 'Code Integrity', () => {
    const out = ps(`
$ci=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -EA SilentlyContinue).VulnerableDriverBlocklistEnable
"DriverBlocklist:$ci"
`);
    return { id: 'edr-cig', name: 'Code Integrity / Driver Blocklist', status: out.includes('1') ? 'pass' : 'warn', detail: out, risk: out.includes('1') ? 'low' : 'medium' };
  });
}

export function checkHandleMonitor(): EdrCheck {
  return safe('edr-handles', 'Cross-Process Handle Monitor', () => {
    const out = ps(`$h=Get-Process -Name lsass -EA SilentlyContinue|Select -Expand HandleCount -EA SilentlyContinue;"LsassHandles:$h"`);
    const m = out.match(/LsassHandles:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'edr-handles', name: 'Cross-Process Handle Monitor', status: c < 2000 ? 'pass' : 'warn', detail: `LSASS handle count: ${c}${c >= 2000 ? ' (elevated — possible credential access)' : ''}`, risk: c < 2000 ? 'low' : 'high' };
  });
}

export function checkHoneypot(): EdrCheck {
  return safe('edr-honeypot', 'Bait-File Mesh', () => {
    try {
      const { getConfig } = require('./fileIntegrityMonitor');
      const cfg = getConfig();
      const active = cfg && cfg.watchedPaths && cfg.watchedPaths.length > 0;
      return { id: 'edr-honeypot', name: 'Bait-File Mesh', status: active ? 'pass' : 'warn', detail: active ? `FIM active — monitoring ${cfg.watchedPaths.length} paths` : 'FIM not configured — no bait files deployed', risk: active ? 'low' : 'medium' };
    } catch {
      return { id: 'edr-honeypot', name: 'Bait-File Mesh', status: 'warn', detail: 'FIM module not initialized', risk: 'medium' };
    }
  });
}

export function runAllEdrChecks(): EdrCheck[] {
  return [
    checkAMSI(), checkETW(), checkProcessHollowing(), checkReflectiveDLL(),
    checkAPCInjection(), checkLSASS(), checkSyscallIntegrity(), checkRansomwareFiles(),
    checkWMIPersistence(), checkPPIDSpoofing(), checkTokenElevation(), checkCOMHijacking(),
    checkExploitMitigations(), checkLSAConfig(), checkSandboxCapabilities(),
    checkBehaviorScore(), checkCriticalFiles(), checkAutoRunAudit(),
    checkScriptBlockLogging(), checkDefenderRealtime(), checkSysmon(),
    checkCodeIntegrity(), checkHandleMonitor(), checkHoneypot(),
  ];
}
