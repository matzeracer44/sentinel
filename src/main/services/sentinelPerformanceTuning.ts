/**
 * SENTINEL — Extreme Performance & Kernel Tuning Module
 * 25 performance checks & actions: DPC latency, timer resolution, core parking,
 * HAGS, thermal, pagefile, memory compression, bcdedit, etc.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
const execFileAsync = promisify(execFile);

export interface PerfCheck {
  id: string;
  name: string;
  status: 'pass' | 'fail' | 'warn' | 'unknown';
  detail: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  actionable?: boolean;
}

async function ps(script: string, timeout = 12000): Promise<string> {
  const { stdout } = await execFileAsync('powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    { timeout, windowsHide: true, maxBuffer: 4 * 1024 * 1024 }
  );
  return (stdout || '').trim();
}

async function safe(id: string, name: string, fn: () => Promise<PerfCheck>): Promise<PerfCheck> {
  try { return await fn(); } catch (e: any) { return { id, name, status: 'unknown', detail: e.message, risk: 'medium' }; }
}

export async function checkDPCLatency(): Promise<PerfCheck> {
  return safe('perf-dpc', 'DPC Latency', async () => {
    const out = await ps(`$d=Get-Counter '\\Processor(_Total)\\% DPC Time' -EA SilentlyContinue;$v=if($d){[math]::Round($d.CounterSamples[0].CookedValue,2)}else{-1};"DPCTime:$v%"`);
    const m = out.match(/DPCTime:([\d.-]+)/);
    const v = m ? parseFloat(m[1]) : -1;
    return { id: 'perf-dpc', name: 'DPC Latency', status: v < 5 ? 'pass' : v < 15 ? 'warn' : 'fail', detail: `DPC Time: ${v}%`, risk: v < 5 ? 'low' : 'high' };
  });
}

export async function checkTimerResolution(): Promise<PerfCheck> {
  return safe('perf-timer', 'Timer Resolution', async () => {
    const out = await ps(`$t=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel' -EA SilentlyContinue).GlobalTimerResolutionRequests;"TimerRequests:$t"`);
    const m = out.match(/TimerRequests:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'perf-timer', name: 'Timer Resolution', status: c > 0 ? 'pass' : 'warn', detail: `${c} high-precision timer requests active`, risk: 'low', actionable: true };
  });
}

export async function checkLargePages(): Promise<PerfCheck> {
  return safe('perf-largepages', 'Large Pages Support', async () => {
    const out = await ps(`$lp=whoami /priv 2>&1|Select-String 'SeLockMemoryPrivilege';if($lp-and$lp-notmatch'Disabled|Deaktiviert'){'ENABLED'}else{'DISABLED'}`);
    return { id: 'perf-largepages', name: 'Large Pages Support', status: out.includes('ENABLED') ? 'pass' : 'warn', detail: out, risk: 'low', actionable: true };
  });
}

export async function checkVRAM(): Promise<PerfCheck> {
  return safe('perf-vram', 'GPU / VRAM Status', async () => {
    const out = await ps('$g=Get-CimInstance Win32_VideoController|Select -First 1;$mb=[math]::Round($g.AdapterRAM/1MB);"GPU:$($g.Name)|VRAM:$($mb)MB"');
    const m = out.match(/VRAM:(\d+)MB/);
    const mb = m ? parseInt(m[1]) : 0;
    return { id: 'perf-vram', name: 'GPU / VRAM Status', status: mb >= 512 ? 'pass' : mb > 0 ? 'warn' : 'pass', detail: out, risk: mb < 512 && mb > 0 ? 'medium' : 'low' };
  });
}

export async function checkStandbyList(): Promise<PerfCheck> {
  return safe('perf-standby', 'Standby List / RAM Cache', async () => {
    const out = await ps('$os=Get-CimInstance Win32_OperatingSystem;$free=[math]::Round($os.FreePhysicalMemory/1MB,1);$total=[math]::Round($os.TotalVisibleMemorySize/1MB,1);"Free:$($free)GB/$($total)GB"');
    const m = out.match(/Free:([\d.]+)GB\/([\d.]+)GB/);
    const free = m ? parseFloat(m[1]) : 0;
    const total = m ? parseFloat(m[2]) : 1;
    const pct = (free / total) * 100;
    return { id: 'perf-standby', name: 'Standby List / RAM Cache', status: pct > 15 ? 'pass' : pct > 5 ? 'warn' : 'fail', detail: `${free.toFixed(1)}GB free / ${total.toFixed(1)}GB total (${pct.toFixed(0)}%)`, risk: pct <= 5 ? 'high' : pct <= 15 ? 'medium' : 'low', actionable: true };
  });
}

export async function checkIOPriority(): Promise<PerfCheck> {
  return safe('perf-ioprio', 'I/O Priority Management', async () => {
    const out = await ps(`$wu=(Get-Service wuauserv -EA SilentlyContinue).Status;$bits=(Get-Service BITS -EA SilentlyContinue).Status;"WindowsUpdate:$wu|BITS:$bits"`);
    const wuRunning = out.includes('WindowsUpdate:Running');
    const bitsRunning = out.includes('BITS:Running');
    const bothActive = wuRunning && bitsRunning;
    return { id: 'perf-ioprio', name: 'I/O Priority Management', status: bothActive ? 'warn' : 'pass', detail: `WU:${wuRunning ? 'Active' : 'Idle'} BITS:${bitsRunning ? 'Active' : 'Idle'}${bothActive ? ' — background I/O may impact performance' : ''}`, risk: bothActive ? 'medium' : 'low', actionable: true };
  });
}

export async function checkMFT(): Promise<PerfCheck> {
  return safe('perf-mft', 'NTFS MFT Status', async () => {
    const out = await ps(`$v=Get-Volume -DriveLetter C -EA SilentlyContinue;$frag=if($v){"Health:$($v.HealthStatus)|Size:$([math]::Round($v.Size/1GB))GB|Free:$([math]::Round($v.SizeRemaining/1GB))GB"}else{'N/A'};$frag`);
    const healthy = out.includes('Health:Healthy');
    const freeMatch = out.match(/Free:(\d+)GB/);
    const sizeMatch = out.match(/Size:(\d+)GB/);
    const freeGB = freeMatch ? parseInt(freeMatch[1]) : 0;
    const sizeGB = sizeMatch ? parseInt(sizeMatch[1]) : 1;
    const pctFree = (freeGB / sizeGB) * 100;
    return { id: 'perf-mft', name: 'NTFS / Volume Health', status: healthy && pctFree > 10 ? 'pass' : healthy ? 'warn' : 'fail', detail: out, risk: !healthy ? 'high' : pctFree <= 10 ? 'medium' : 'low' };
  });
}

export async function checkStorageSense(): Promise<PerfCheck> {
  return safe('perf-storage', 'Storage Sense', async () => {
    const out = await ps(`$ss=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy' -EA SilentlyContinue).'01';if($ss-eq1){'ENABLED'}else{'DISABLED'}`);
    return { id: 'perf-storage', name: 'Storage Sense', status: out.includes('ENABLED') ? 'pass' : 'warn', detail: out, risk: 'low', actionable: true };
  });
}

export async function checkWinSxS(): Promise<PerfCheck> {
  return safe('perf-winsxs', 'WinSxS Component Store', async () => {
    const out = await ps('$w=Get-ChildItem "$env:SystemRoot\WinSxS" -EA SilentlyContinue|Measure;$s=[math]::Round((Get-ChildItem "$env:SystemRoot\WinSxS" -Recurse -EA SilentlyContinue|Measure -Property Length -Sum).Sum/1GB,2);"Items:$($w.Count)|Size:$($s)GB"');
    const m = out.match(/Size:([\d.]+)GB/);
    const gb = m ? parseFloat(m[1]) : 0;
    return { id: 'perf-winsxs', name: 'WinSxS Component Store', status: gb < 15 ? 'pass' : gb < 25 ? 'warn' : 'fail', detail: `Component store: ${gb}GB${gb >= 15 ? ' — consider DISM cleanup' : ''}`, risk: gb >= 25 ? 'medium' : 'low', actionable: true };
  });
}

export async function checkRegistrySize(): Promise<PerfCheck> {
  return safe('perf-regcomp', 'Registry Size', async () => {
    const out = await ps(`$r=Get-ChildItem 'HKLM:\\SOFTWARE' -EA SilentlyContinue|Measure;$u=Get-ChildItem 'HKCU:\\SOFTWARE' -EA SilentlyContinue|Measure;"HKLM_Keys:$($r.Count)|HKCU_Keys:$($u.Count)"`);
    const hklm = out.match(/HKLM_Keys:(\d+)/);
    const hkcu = out.match(/HKCU_Keys:(\d+)/);
    const total = (hklm ? parseInt(hklm[1]) : 0) + (hkcu ? parseInt(hkcu[1]) : 0);
    return { id: 'perf-regcomp', name: 'Registry Size', status: total < 2000 ? 'pass' : 'warn', detail: `${total} top-level keys (HKLM+HKCU)`, risk: total >= 2000 ? 'medium' : 'low' };
  });
}

export async function checkSuperfetch(): Promise<PerfCheck> {
  return safe('perf-superfetch', 'Superfetch / SysMain', async () => {
    const out = await ps(`$s=(Get-Service SysMain -EA SilentlyContinue).Status;$ssd=$false;Get-PhysicalDisk -EA SilentlyContinue|%{if($_.MediaType-eq'SSD'){$ssd=$true}};"SysMain:$s|HasSSD:$ssd"`);
    const hasSSD = out.includes('HasSSD:True');
    const running = out.includes('SysMain:Running');
    const wasteful = hasSSD && running;
    return { id: 'perf-superfetch', name: 'Superfetch / SysMain', status: wasteful ? 'warn' : 'pass', detail: `SysMain:${running ? 'Running' : 'Stopped'} SSD:${hasSSD ? 'Yes' : 'No'}${wasteful ? ' — SysMain unnecessary on SSD' : ''}`, risk: 'low', actionable: true };
  });
}

export async function checkUltimatePowerPlan(): Promise<PerfCheck> {
  return safe('perf-ultimate', 'Ultimate Performance Plan', async () => {
    const out = await ps(`$p=powercfg /getactivescheme 2>&1;$p`);
    const low = out.toLowerCase();
    // Accept Ultimate Performance, High Performance, or German "Höchstleistung"
    const HIGH_PERF_GUID = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c';
    const ULTIMATE_GUID = 'e9a42b02-d5df-448d-aa00-03f14749eb61';
    const isHighPerf = low.includes('ultimate') || low.includes('high performance') ||
      low.includes('h\u00f6chstleistung') || low.includes('hochleistung') ||
      out.includes(HIGH_PERF_GUID) || out.includes(ULTIMATE_GUID);
    return { id: 'perf-ultimate', name: 'Power Plan', status: isHighPerf ? 'pass' : 'warn', detail: out, risk: 'low', actionable: !isHighPerf };
  });
}

export async function checkCoreParking(): Promise<PerfCheck> {
  return safe('perf-coreparking', 'Core Parking', async () => {
    const out = await ps(`$cp=powercfg /query SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 2>&1;$m=$cp|Select-String 'Current.*Index';if($m){"$m"}else{'N/A'}`);
    const indexMatch = out.match(/0x([0-9a-fA-F]+)/);
    const minCores = indexMatch ? parseInt(indexMatch[1], 16) : 100;
    return { id: 'perf-coreparking', name: 'Core Parking', status: minCores >= 100 ? 'pass' : 'warn', detail: `Min active cores: ${minCores}%${minCores < 100 ? ' — cores may park under load' : ' — all cores always active'}`, risk: minCores < 50 ? 'medium' : 'low', actionable: true };
  });
}

export async function checkPagefile(): Promise<PerfCheck> {
  return safe('perf-pagefile', 'Paging File', async () => {
    const out = await ps(`$pf=Get-CimInstance Win32_PageFileUsage -EA SilentlyContinue|Select -First 1;"Name:$($pf.Name)|Alloc:$($pf.AllocatedBaseSize)MB|Current:$($pf.CurrentUsage)MB|Peak:$($pf.PeakUsage)MB"`);
    const allocMatch = out.match(/Alloc:(\d+)MB/);
    const peakMatch = out.match(/Peak:(\d+)MB/);
    const alloc = allocMatch ? parseInt(allocMatch[1]) : 0;
    const peak = peakMatch ? parseInt(peakMatch[1]) : 0;
    const highUsage = alloc > 0 && peak > alloc * 0.8;
    return { id: 'perf-pagefile', name: 'Paging File', status: highUsage ? 'warn' : 'pass', detail: `Allocated: ${alloc}MB Peak: ${peak}MB${highUsage ? ' — pagefile near capacity' : ''}`, risk: highUsage ? 'medium' : 'low', actionable: true };
  });
}

export async function checkMemoryCompression(): Promise<PerfCheck> {
  return safe('perf-memcomp', 'Memory Compression', async () => {
    const out = await ps('$mc=Get-Process -Name "Memory Compression" -EA SilentlyContinue;$ws=if($mc){[math]::Round($mc.WorkingSet64/1MB)}else{0};"MemCompression:$($ws)MB"');
    const m = out.match(/MemCompression:(\d+)MB/);
    const mb = m ? parseInt(m[1]) : 0;
    return { id: 'perf-memcomp', name: 'Memory Compression', status: mb < 1024 ? 'pass' : 'warn', detail: `${mb}MB in compressed memory${mb >= 1024 ? ' — system under memory pressure' : ''}`, risk: mb >= 2048 ? 'high' : mb >= 1024 ? 'medium' : 'low' };
  });
}

export async function checkWriteCache(): Promise<PerfCheck> {
  return safe('perf-writecache', 'Disk Write-Cache', async () => {
    const out = await ps(`$d=Get-PhysicalDisk -EA SilentlyContinue|Select -First 1;$p=Get-Disk -Number 0 -EA SilentlyContinue;"Disk:$($d.FriendlyName)|Media:$($d.MediaType)|Bus:$($d.BusType)|Cache:$($p.IsCacheEnabled)"`);
    const cacheOn = out.includes('Cache:True');
    const isSSD = out.includes('Media:SSD') || out.includes('Bus:NVMe');
    return { id: 'perf-writecache', name: 'Disk Write-Cache', status: cacheOn || isSSD ? 'pass' : 'warn', detail: `${out}${!cacheOn && !isSSD ? ' — write cache disabled on HDD' : ''}`, risk: !cacheOn && !isSSD ? 'medium' : 'low' };
  });
}

export async function checkBcdedit(): Promise<PerfCheck> {
  return safe('perf-bcdedit', 'Bcdedit Tuning', async () => {
    const out = await ps(`$b=bcdedit /enum '{current}' 2>&1;$dt=$b-match'disabledynamictick\\s+Yes';$hpet=$b-match'useplatformtick\\s+Yes';"DynTickDisabled:$($dt.Count-gt0)|PlatformTick:$($hpet.Count-gt0)"`);
    const dynTickOff = out.includes('DynTickDisabled:True');
    const platTick = out.includes('PlatformTick:True');
    return { id: 'perf-bcdedit', name: 'Bcdedit Tuning', status: dynTickOff && platTick ? 'pass' : 'warn', detail: `DynamicTick:${dynTickOff ? 'Disabled' : 'Default'} PlatformTick:${platTick ? 'Forced' : 'Default'}${!dynTickOff ? ' — timer precision not optimized' : ''}`, risk: 'low', actionable: true };
  });
}

export async function checkBackgroundApps(): Promise<PerfCheck> {
  return safe('perf-bgapps', 'Background Apps', async () => {
    const out = await ps(`$bg=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications' -EA SilentlyContinue).GlobalUserDisabled;if($bg-eq1){'DISABLED'}else{'ENABLED'}`);
    return { id: 'perf-bgapps', name: 'Background UWP Apps', status: out.includes('DISABLED') ? 'pass' : 'warn', detail: out, risk: 'low', actionable: true };
  });
}

export async function checkTelemetryServices(): Promise<PerfCheck> {
  return safe('perf-telemetry', 'Telemetry Services', async () => {
    const out = await ps(`$dt=(Get-Service DiagTrack -EA SilentlyContinue).Status;$dm=(Get-Service dmwappushservice -EA SilentlyContinue).Status;"DiagTrack:$dt|dmwappush:$dm"`);
    const stopped = out.includes('DiagTrack:Stopped');
    return { id: 'perf-telemetry', name: 'Telemetry Services', status: stopped ? 'pass' : 'warn', detail: out, risk: 'low', actionable: true };
  });
}

export async function checkContextSwitches(): Promise<PerfCheck> {
  return safe('perf-ctxswitch', 'Context Switches', async () => {
    const out = await ps(`$c=Get-Counter '\\System\\Context Switches/sec' -EA SilentlyContinue;$v=if($c){[math]::Round($c.CounterSamples[0].CookedValue)}else{-1};"CtxSwitches:$v/sec"`);
    const m = out.match(/CtxSwitches:(\d+)/);
    const v = m ? parseInt(m[1]) : 0;
    return { id: 'perf-ctxswitch', name: 'Context Switches', status: v < 50000 ? 'pass' : 'warn', detail: out, risk: v < 50000 ? 'low' : 'medium' };
  });
}

export async function checkHAGS(): Promise<PerfCheck> {
  return safe('perf-hags', 'GPU Scheduling (HAGS)', async () => {
    const out = await ps(`$h=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers' -EA SilentlyContinue).HwSchMode;if($h-eq2){'ENABLED'}else{'DISABLED'}`);
    return { id: 'perf-hags', name: 'GPU Scheduling (HAGS)', status: out.includes('ENABLED') ? 'pass' : 'warn', detail: out, risk: 'low', actionable: true };
  });
}

export async function checkRAMStability(): Promise<PerfCheck> {
  return safe('perf-ramstab', 'RAM Stability', async () => {
    const out = await ps(`$m=Get-CimInstance Win32_PhysicalMemory|%{"$($_.Manufacturer) $($_.Speed)MHz $([math]::Round($_.Capacity/1GB))GB"};$m-join' | '`);
    return { id: 'perf-ramstab', name: 'RAM Info', status: out.length > 5 ? 'pass' : 'warn', detail: out || 'Could not read RAM info', risk: 'low' };
  });
}

export async function checkThermal(): Promise<PerfCheck> {
  return safe('perf-thermal', 'Thermal Throttle Alert', async () => {
    const out = await ps(`
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

export async function checkInterruptSteering(): Promise<PerfCheck> {
  return safe('perf-irq', 'Interrupt Steering', async () => {
    const out = await ps(`$rss=(Get-NetAdapterRss -EA SilentlyContinue|Select -First 1).Enabled;"RSS:$rss"`);
    return { id: 'perf-irq', name: 'Interrupt Steering / RSS', status: out.includes('True') ? 'pass' : 'warn', detail: out, risk: 'low' };
  });
}

export async function checkThreadAffinity(): Promise<PerfCheck> {
  return safe('perf-dta', 'Thread Affinity', async () => {
    const out = await ps(`$c=(Get-CimInstance Win32_Processor|Select -First 1);$cores=$c.NumberOfCores;$threads=$c.NumberOfLogicalProcessors;"Cores:$cores|Threads:$threads"`);
    const coreMatch = out.match(/Cores:(\d+)/);
    const threadMatch = out.match(/Threads:(\d+)/);
    const cores = coreMatch ? parseInt(coreMatch[1]) : 0;
    const threads = threadMatch ? parseInt(threadMatch[1]) : 0;
    return { id: 'perf-dta', name: 'CPU Topology', status: cores > 0 ? 'pass' : 'warn', detail: `${cores}C/${threads}T${threads > cores ? ' (SMT/HT active)' : ''}`, risk: 'low' };
  });
}

const _yield = () => new Promise<void>(r => setImmediate(r));

export async function runAllPerformanceChecks(): Promise<PerfCheck[]> {
  const fns: (() => Promise<PerfCheck>)[] = [
    checkThreadAffinity, checkDPCLatency, checkInterruptSteering,
    checkTimerResolution, checkLargePages, checkVRAM,
    checkStandbyList, checkIOPriority, checkMFT,
    checkStorageSense, checkWinSxS, checkRegistrySize,
    checkSuperfetch, checkUltimatePowerPlan, checkCoreParking,
    checkPagefile, checkMemoryCompression, checkWriteCache,
    checkBcdedit, checkBackgroundApps, checkTelemetryServices,
    checkContextSwitches, checkHAGS, checkRAMStability,
    checkThermal,
  ];
  const results: PerfCheck[] = [];
  for (const fn of fns) {
    results.push(await fn());
    await _yield();
  }
  return results;
}
