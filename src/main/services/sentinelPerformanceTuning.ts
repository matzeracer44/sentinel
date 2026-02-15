/**
 * SENTINEL — Extreme Performance & Kernel Tuning Module
 * 25 performance checks & actions: DPC latency, timer resolution, core parking,
 * HAGS, thermal, pagefile, memory compression, bcdedit, etc.
 */

import { spawnSync } from 'child_process';

export interface PerfCheck {
  id: string;
  name: string;
  status: 'pass' | 'fail' | 'warn' | 'unknown';
  detail: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  actionable?: boolean;
}

function ps(script: string, timeout = 12000): string {
  const r = spawnSync('powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
    { input: script, timeout, windowsHide: true, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }
  );
  if (r.error) throw r.error;
  return (r.stdout || '').trim();
}

function safe(id: string, name: string, fn: () => PerfCheck): PerfCheck {
  try { return fn(); } catch (e: any) { return { id, name, status: 'unknown', detail: e.message, risk: 'medium' }; }
}

export function checkDPCLatency(): PerfCheck {
  return safe('perf-dpc', 'DPC Latency', () => {
    const out = ps(`$d=Get-Counter '\\Processor(_Total)\\% DPC Time' -EA SilentlyContinue;$v=if($d){[math]::Round($d.CounterSamples[0].CookedValue,2)}else{-1};"DPCTime:$v%"`);
    const m = out.match(/DPCTime:([\d.-]+)/);
    const v = m ? parseFloat(m[1]) : -1;
    return { id: 'perf-dpc', name: 'DPC Latency', status: v < 5 ? 'pass' : v < 15 ? 'warn' : 'fail', detail: `DPC Time: ${v}%`, risk: v < 5 ? 'low' : 'high' };
  });
}

export function checkTimerResolution(): PerfCheck {
  return safe('perf-timer', 'Timer Resolution', () => {
    const out = ps(`$t=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel' -EA SilentlyContinue).GlobalTimerResolutionRequests;"TimerRequests:$t"`);
    const m = out.match(/TimerRequests:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'perf-timer', name: 'Timer Resolution', status: c > 0 ? 'pass' : 'warn', detail: `${c} high-precision timer requests active`, risk: 'low', actionable: true };
  });
}

export function checkLargePages(): PerfCheck {
  return safe('perf-largepages', 'Large Pages Support', () => {
    const out = ps(`$lp=whoami /priv 2>&1|Select-String 'SeLockMemoryPrivilege';if($lp-and$lp-match'Enabled'){'ENABLED'}else{'DISABLED'}`);
    return { id: 'perf-largepages', name: 'Large Pages Support', status: out.includes('ENABLED') ? 'pass' : 'warn', detail: out, risk: 'low', actionable: true };
  });
}

export function checkVRAM(): PerfCheck {
  return safe('perf-vram', 'GPU / VRAM Status', () => {
    const out = ps('$g=Get-CimInstance Win32_VideoController|Select -First 1;$mb=[math]::Round($g.AdapterRAM/1MB);"GPU:$($g.Name)|VRAM:$($mb)MB"');
    const m = out.match(/VRAM:(\d+)MB/);
    const mb = m ? parseInt(m[1]) : 0;
    return { id: 'perf-vram', name: 'GPU / VRAM Status', status: mb >= 512 ? 'pass' : mb > 0 ? 'warn' : 'pass', detail: out, risk: mb < 512 && mb > 0 ? 'medium' : 'low' };
  });
}

export function checkStandbyList(): PerfCheck {
  return safe('perf-standby', 'Standby List / RAM Cache', () => {
    const out = ps('$os=Get-CimInstance Win32_OperatingSystem;$free=[math]::Round($os.FreePhysicalMemory/1MB,1);$total=[math]::Round($os.TotalVisibleMemorySize/1MB,1);"Free:$($free)GB/$($total)GB"');
    const m = out.match(/Free:([\d.]+)GB\/([\d.]+)GB/);
    const free = m ? parseFloat(m[1]) : 0;
    const total = m ? parseFloat(m[2]) : 1;
    const pct = (free / total) * 100;
    return { id: 'perf-standby', name: 'Standby List / RAM Cache', status: pct > 15 ? 'pass' : pct > 5 ? 'warn' : 'fail', detail: `${free.toFixed(1)}GB free / ${total.toFixed(1)}GB total (${pct.toFixed(0)}%)`, risk: pct <= 5 ? 'high' : pct <= 15 ? 'medium' : 'low', actionable: true };
  });
}

export function checkIOPriority(): PerfCheck {
  return safe('perf-ioprio', 'I/O Priority Management', () => {
    const out = ps(`$wu=(Get-Service wuauserv -EA SilentlyContinue).Status;$bits=(Get-Service BITS -EA SilentlyContinue).Status;"WindowsUpdate:$wu|BITS:$bits"`);
    const wuRunning = out.includes('WindowsUpdate:Running');
    const bitsRunning = out.includes('BITS:Running');
    const bothActive = wuRunning && bitsRunning;
    return { id: 'perf-ioprio', name: 'I/O Priority Management', status: bothActive ? 'warn' : 'pass', detail: `WU:${wuRunning ? 'Active' : 'Idle'} BITS:${bitsRunning ? 'Active' : 'Idle'}${bothActive ? ' — background I/O may impact performance' : ''}`, risk: bothActive ? 'medium' : 'low', actionable: true };
  });
}

export function checkMFT(): PerfCheck {
  return safe('perf-mft', 'NTFS MFT Status', () => {
    const out = ps(`$v=Get-Volume -DriveLetter C -EA SilentlyContinue;$frag=if($v){"Health:$($v.HealthStatus)|Size:$([math]::Round($v.Size/1GB))GB|Free:$([math]::Round($v.SizeRemaining/1GB))GB"}else{'N/A'};$frag`);
    const healthy = out.includes('Health:Healthy');
    const freeMatch = out.match(/Free:(\d+)GB/);
    const sizeMatch = out.match(/Size:(\d+)GB/);
    const freeGB = freeMatch ? parseInt(freeMatch[1]) : 0;
    const sizeGB = sizeMatch ? parseInt(sizeMatch[1]) : 1;
    const pctFree = (freeGB / sizeGB) * 100;
    return { id: 'perf-mft', name: 'NTFS / Volume Health', status: healthy && pctFree > 10 ? 'pass' : healthy ? 'warn' : 'fail', detail: out, risk: !healthy ? 'high' : pctFree <= 10 ? 'medium' : 'low' };
  });
}

export function checkStorageSense(): PerfCheck {
  return safe('perf-storage', 'Storage Sense', () => {
    const out = ps(`$ss=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy' -EA SilentlyContinue).'01';if($ss-eq1){'ENABLED'}else{'DISABLED'}`);
    return { id: 'perf-storage', name: 'Storage Sense', status: out.includes('ENABLED') ? 'pass' : 'warn', detail: out, risk: 'low', actionable: true };
  });
}

export function checkWinSxS(): PerfCheck {
  return safe('perf-winsxs', 'WinSxS Component Store', () => {
    const out = ps('$w=Get-ChildItem "$env:SystemRoot\WinSxS" -EA SilentlyContinue|Measure;$s=[math]::Round((Get-ChildItem "$env:SystemRoot\WinSxS" -Recurse -EA SilentlyContinue|Measure -Property Length -Sum).Sum/1GB,2);"Items:$($w.Count)|Size:$($s)GB"');
    const m = out.match(/Size:([\d.]+)GB/);
    const gb = m ? parseFloat(m[1]) : 0;
    return { id: 'perf-winsxs', name: 'WinSxS Component Store', status: gb < 15 ? 'pass' : gb < 25 ? 'warn' : 'fail', detail: `Component store: ${gb}GB${gb >= 15 ? ' — consider DISM cleanup' : ''}`, risk: gb >= 25 ? 'medium' : 'low', actionable: true };
  });
}

export function checkRegistrySize(): PerfCheck {
  return safe('perf-regcomp', 'Registry Size', () => {
    const out = ps(`$r=Get-ChildItem 'HKLM:\\SOFTWARE' -EA SilentlyContinue|Measure;$u=Get-ChildItem 'HKCU:\\SOFTWARE' -EA SilentlyContinue|Measure;"HKLM_Keys:$($r.Count)|HKCU_Keys:$($u.Count)"`);
    const hklm = out.match(/HKLM_Keys:(\d+)/);
    const hkcu = out.match(/HKCU_Keys:(\d+)/);
    const total = (hklm ? parseInt(hklm[1]) : 0) + (hkcu ? parseInt(hkcu[1]) : 0);
    return { id: 'perf-regcomp', name: 'Registry Size', status: total < 2000 ? 'pass' : 'warn', detail: `${total} top-level keys (HKLM+HKCU)`, risk: total >= 2000 ? 'medium' : 'low' };
  });
}

export function checkSuperfetch(): PerfCheck {
  return safe('perf-superfetch', 'Superfetch / SysMain', () => {
    const out = ps(`$s=(Get-Service SysMain -EA SilentlyContinue).Status;$ssd=$false;Get-PhysicalDisk -EA SilentlyContinue|%{if($_.MediaType-eq'SSD'){$ssd=$true}};"SysMain:$s|HasSSD:$ssd"`);
    const hasSSD = out.includes('HasSSD:True');
    const running = out.includes('SysMain:Running');
    const wasteful = hasSSD && running;
    return { id: 'perf-superfetch', name: 'Superfetch / SysMain', status: wasteful ? 'warn' : 'pass', detail: `SysMain:${running ? 'Running' : 'Stopped'} SSD:${hasSSD ? 'Yes' : 'No'}${wasteful ? ' — SysMain unnecessary on SSD' : ''}`, risk: 'low', actionable: true };
  });
}

export function checkUltimatePowerPlan(): PerfCheck {
  return safe('perf-ultimate', 'Ultimate Performance Plan', () => {
    const out = ps(`$p=powercfg /getactivescheme 2>&1;$p`);
    const isUltimate = out.toLowerCase().includes('ultimate');
    return { id: 'perf-ultimate', name: 'Power Plan', status: isUltimate ? 'pass' : 'warn', detail: out, risk: 'low', actionable: true };
  });
}

export function checkCoreParking(): PerfCheck {
  return safe('perf-coreparking', 'Core Parking', () => {
    const out = ps(`$cp=powercfg /query SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 2>&1;$m=$cp|Select-String 'Current.*Index';if($m){"$m"}else{'N/A'}`);
    const indexMatch = out.match(/0x([0-9a-fA-F]+)/);
    const minCores = indexMatch ? parseInt(indexMatch[1], 16) : 100;
    return { id: 'perf-coreparking', name: 'Core Parking', status: minCores >= 100 ? 'pass' : 'warn', detail: `Min active cores: ${minCores}%${minCores < 100 ? ' — cores may park under load' : ' — all cores always active'}`, risk: minCores < 50 ? 'medium' : 'low', actionable: true };
  });
}

export function checkPagefile(): PerfCheck {
  return safe('perf-pagefile', 'Paging File', () => {
    const out = ps(`$pf=Get-CimInstance Win32_PageFileUsage -EA SilentlyContinue|Select -First 1;"Name:$($pf.Name)|Alloc:$($pf.AllocatedBaseSize)MB|Current:$($pf.CurrentUsage)MB|Peak:$($pf.PeakUsage)MB"`);
    const allocMatch = out.match(/Alloc:(\d+)MB/);
    const peakMatch = out.match(/Peak:(\d+)MB/);
    const alloc = allocMatch ? parseInt(allocMatch[1]) : 0;
    const peak = peakMatch ? parseInt(peakMatch[1]) : 0;
    const highUsage = alloc > 0 && peak > alloc * 0.8;
    return { id: 'perf-pagefile', name: 'Paging File', status: highUsage ? 'warn' : 'pass', detail: `Allocated: ${alloc}MB Peak: ${peak}MB${highUsage ? ' — pagefile near capacity' : ''}`, risk: highUsage ? 'medium' : 'low', actionable: true };
  });
}

export function checkMemoryCompression(): PerfCheck {
  return safe('perf-memcomp', 'Memory Compression', () => {
    const out = ps('$mc=Get-Process -Name "Memory Compression" -EA SilentlyContinue;$ws=if($mc){[math]::Round($mc.WorkingSet64/1MB)}else{0};"MemCompression:$($ws)MB"');
    const m = out.match(/MemCompression:(\d+)MB/);
    const mb = m ? parseInt(m[1]) : 0;
    return { id: 'perf-memcomp', name: 'Memory Compression', status: mb < 1024 ? 'pass' : 'warn', detail: `${mb}MB in compressed memory${mb >= 1024 ? ' — system under memory pressure' : ''}`, risk: mb >= 2048 ? 'high' : mb >= 1024 ? 'medium' : 'low' };
  });
}

export function checkWriteCache(): PerfCheck {
  return safe('perf-writecache', 'Disk Write-Cache', () => {
    const out = ps(`$d=Get-PhysicalDisk -EA SilentlyContinue|Select -First 1;$p=Get-Disk -Number 0 -EA SilentlyContinue;"Disk:$($d.FriendlyName)|Media:$($d.MediaType)|Bus:$($d.BusType)|Cache:$($p.IsCacheEnabled)"`);
    const cacheOn = out.includes('Cache:True');
    const isSSD = out.includes('Media:SSD') || out.includes('Bus:NVMe');
    return { id: 'perf-writecache', name: 'Disk Write-Cache', status: cacheOn || isSSD ? 'pass' : 'warn', detail: `${out}${!cacheOn && !isSSD ? ' — write cache disabled on HDD' : ''}`, risk: !cacheOn && !isSSD ? 'medium' : 'low' };
  });
}

export function checkBcdedit(): PerfCheck {
  return safe('perf-bcdedit', 'Bcdedit Tuning', () => {
    const out = ps(`$b=bcdedit /enum '{current}' 2>&1;$dt=$b-match'disabledynamictick\\s+Yes';$hpet=$b-match'useplatformtick\\s+Yes';"DynTickDisabled:$($dt.Count-gt0)|PlatformTick:$($hpet.Count-gt0)"`);
    const dynTickOff = out.includes('DynTickDisabled:True');
    const platTick = out.includes('PlatformTick:True');
    return { id: 'perf-bcdedit', name: 'Bcdedit Tuning', status: dynTickOff && platTick ? 'pass' : 'warn', detail: `DynamicTick:${dynTickOff ? 'Disabled' : 'Default'} PlatformTick:${platTick ? 'Forced' : 'Default'}${!dynTickOff ? ' — timer precision not optimized' : ''}`, risk: 'low', actionable: true };
  });
}

export function checkBackgroundApps(): PerfCheck {
  return safe('perf-bgapps', 'Background Apps', () => {
    const out = ps(`$bg=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications' -EA SilentlyContinue).GlobalUserDisabled;if($bg-eq1){'DISABLED'}else{'ENABLED'}`);
    return { id: 'perf-bgapps', name: 'Background UWP Apps', status: out.includes('DISABLED') ? 'pass' : 'warn', detail: out, risk: 'low', actionable: true };
  });
}

export function checkTelemetryServices(): PerfCheck {
  return safe('perf-telemetry', 'Telemetry Services', () => {
    const out = ps(`$dt=(Get-Service DiagTrack -EA SilentlyContinue).Status;$dm=(Get-Service dmwappushservice -EA SilentlyContinue).Status;"DiagTrack:$dt|dmwappush:$dm"`);
    const stopped = out.includes('DiagTrack:Stopped');
    return { id: 'perf-telemetry', name: 'Telemetry Services', status: stopped ? 'pass' : 'warn', detail: out, risk: 'low', actionable: true };
  });
}

export function checkContextSwitches(): PerfCheck {
  return safe('perf-ctxswitch', 'Context Switches', () => {
    const out = ps(`$c=Get-Counter '\\System\\Context Switches/sec' -EA SilentlyContinue;$v=if($c){[math]::Round($c.CounterSamples[0].CookedValue)}else{-1};"CtxSwitches:$v/sec"`);
    const m = out.match(/CtxSwitches:(\d+)/);
    const v = m ? parseInt(m[1]) : 0;
    return { id: 'perf-ctxswitch', name: 'Context Switches', status: v < 50000 ? 'pass' : 'warn', detail: out, risk: v < 50000 ? 'low' : 'medium' };
  });
}

export function checkHAGS(): PerfCheck {
  return safe('perf-hags', 'GPU Scheduling (HAGS)', () => {
    const out = ps(`$h=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers' -EA SilentlyContinue).HwSchMode;if($h-eq2){'ENABLED'}else{'DISABLED'}`);
    return { id: 'perf-hags', name: 'GPU Scheduling (HAGS)', status: out.includes('ENABLED') ? 'pass' : 'warn', detail: out, risk: 'low', actionable: true };
  });
}

export function checkRAMStability(): PerfCheck {
  return safe('perf-ramstab', 'RAM Stability', () => {
    const out = ps(`$m=Get-CimInstance Win32_PhysicalMemory|%{"$($_.Manufacturer) $($_.Speed)MHz $([math]::Round($_.Capacity/1GB))GB"};$m-join' | '`);
    return { id: 'perf-ramstab', name: 'RAM Info', status: out.length > 5 ? 'pass' : 'warn', detail: out || 'Could not read RAM info', risk: 'low' };
  });
}

export function checkThermal(): PerfCheck {
  return safe('perf-thermal', 'Thermal Throttle Alert', () => {
    const out = ps(`
$ErrorActionPreference='SilentlyContinue'
$tz=Get-CimInstance MSAcpi_ThermalZoneTemperature -Namespace root/wmi -EA SilentlyContinue|Select -First 1
$temp=if($tz){[math]::Round(($tz.CurrentTemperature-2732)/10,1)}else{-1}
"CPU_Temp:$($temp)C"
`);
    const m = out.match(/CPU_Temp:([\d.-]+)/);
    const t = m ? parseFloat(m[1]) : -1;
    return { id: 'perf-thermal', name: 'Thermal Status', status: t < 80 ? 'pass' : t < 95 ? 'warn' : 'fail', detail: `${t > 0 ? t + 'C' : 'Sensor unavailable'}`, risk: t >= 95 ? 'critical' : t >= 80 ? 'high' : 'low' };
  });
}

export function checkInterruptSteering(): PerfCheck {
  return safe('perf-irq', 'Interrupt Steering', () => {
    const out = ps(`$rss=(Get-NetAdapterRss -EA SilentlyContinue|Select -First 1).Enabled;"RSS:$rss"`);
    return { id: 'perf-irq', name: 'Interrupt Steering / RSS', status: out.includes('True') ? 'pass' : 'warn', detail: out, risk: 'low' };
  });
}

export function checkThreadAffinity(): PerfCheck {
  return safe('perf-dta', 'Thread Affinity', () => {
    const out = ps(`$c=(Get-CimInstance Win32_Processor|Select -First 1);$cores=$c.NumberOfCores;$threads=$c.NumberOfLogicalProcessors;"Cores:$cores|Threads:$threads"`);
    const coreMatch = out.match(/Cores:(\d+)/);
    const threadMatch = out.match(/Threads:(\d+)/);
    const cores = coreMatch ? parseInt(coreMatch[1]) : 0;
    const threads = threadMatch ? parseInt(threadMatch[1]) : 0;
    return { id: 'perf-dta', name: 'CPU Topology', status: cores > 0 ? 'pass' : 'warn', detail: `${cores}C/${threads}T${threads > cores ? ' (SMT/HT active)' : ''}`, risk: 'low' };
  });
}

export function runAllPerformanceChecks(): PerfCheck[] {
  return [
    checkThreadAffinity(), checkDPCLatency(), checkInterruptSteering(),
    checkTimerResolution(), checkLargePages(), checkVRAM(),
    checkStandbyList(), checkIOPriority(), checkMFT(),
    checkStorageSense(), checkWinSxS(), checkRegistrySize(),
    checkSuperfetch(), checkUltimatePowerPlan(), checkCoreParking(),
    checkPagefile(), checkMemoryCompression(), checkWriteCache(),
    checkBcdedit(), checkBackgroundApps(), checkTelemetryServices(),
    checkContextSwitches(), checkHAGS(), checkRAMStability(),
    checkThermal(),
  ];
}
