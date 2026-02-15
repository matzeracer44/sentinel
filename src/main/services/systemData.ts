import { exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

/**
 * Get adaptive execution options from the performance profile.
 * Falls back to safe defaults if the profile isn't initialized yet.
 */
function getExecOptions(): { timeout: number; maxBuffer: number; encoding: BufferEncoding; windowsHide: boolean; stdio: 'pipe' } {
  let timeout = 15000;
  let maxBuffer = 4 * 1024 * 1024;
  try {
    const { getPerfSettings } = require('./performanceProfile');
    const s = getPerfSettings();
    timeout = s.powershellTimeout ?? timeout;
    maxBuffer = s.maxBuffer ?? maxBuffer;
  } catch {
    // Profile not yet initialized — use safe defaults
  }
  return { timeout, maxBuffer, encoding: 'utf8' as BufferEncoding, windowsHide: true, stdio: 'pipe' as const };
}

/**
 * CRITICAL: Async PowerShell helper with adaptive timeout
 * Always uses -ExecutionPolicy Bypass for German Windows compatibility
 */
async function execPowerShellAsync(cmd: string): Promise<string> {
  const opts = getExecOptions();
  try {
    const { stdout } = await execPromise(`powershell -ExecutionPolicy Bypass -NoProfile -Command "${cmd}"`, {
      timeout: opts.timeout,
      maxBuffer: opts.maxBuffer,
      encoding: 'utf8',
      windowsHide: true,
    });
    return (stdout || '').trim();
  } catch (error: any) {
    console.error(`PowerShell error: ${error.message}`);
    return '';
  }
}

/**
 * CRITICAL: WMIC helper - MUCH FASTER than Get-WmiObject
 * Returns parsed KEY=VALUE pairs from WMIC /format:list output
 * Works on all Windows locales, no PowerShell escaping issues
 */
async function execWMIC(query: string): Promise<Record<string, string>> {
  try {
    const { stdout } = await execPromise(`wmic ${query} /format:list`, {
      timeout: 10000,
      encoding: 'utf8',
      windowsHide: true,
    });
    const output = (stdout || '').trim();

    // Parse KEY=VALUE format
    const result: Record<string, string> = {};
    output.split('\n').forEach((line) => {
      const [key, value] = line.split('=');
      if (key && value) {
        result[key.trim()] = value.trim();
      }
    });
    return result;
  } catch (error: any) {
    console.error(`WMIC error: ${error.message}`);
    return {};
  }
}

/**
 * Parse multiple WMIC results (for drives, network adapters, etc.)
 */
async function execWMICMultiple(query: string): Promise<Record<string, string>[]> {
  try {
    const { stdout } = await execPromise(`wmic ${query} /format:list`, {
      timeout: 10000,
      encoding: 'utf8',
      windowsHide: true,
    });
    const output = (stdout || '').trim();

    const results: Record<string, string>[] = [];
    let current: Record<string, string> = {};

    output.split('\n').forEach((line) => {
      if (line.trim() === '') {
        if (Object.keys(current).length > 0) {
          results.push(current);
          current = {};
        }
      } else {
        const [key, value] = line.split('=');
        if (key && value) {
          current[key.trim()] = value.trim();
        }
      }
    });

    // Add last item if exists
    if (Object.keys(current).length > 0) {
      results.push(current);
    }

    return results;
  } catch (error: any) {
    console.error(`WMIC multiple error: ${error.message}`);
    return [];
  }
}

/**
 * Async wrapper for execPowerShell (for backward compatibility)
 */
async function execPowerShell(command: string): Promise<string> {
  return execPowerShellAsync(command);
}

export interface RAMData {
  totalGB: number;
  usedGB: number;
  freeGB: number;
  usagePercent: number;
}

export interface CPUData {
  name: string;
  cores: number;
  threads: number;
  currentLoad: number;
}

export interface DiskData {
  drive: string;
  totalGB: number;
  freeGB: number;
  usedGB: number;
  usagePercent: number;
}

export interface SystemInfo {
  manufacturer: string;
  model: string;
  computerName: string;
  userName: string;
}

export interface OSInfo {
  caption: string;
  version: string;
  buildNumber: string;
  installDate: string;
  lastBootUpTime: string;
}

export interface NetworkInfo {
  adapterName: string;
  ipAddress: string;
  macAddress: string;
}

/**
 * CRITICAL: Get RAM information using WMIC - NO FALLBACKS
 * Throws error if data cannot be retrieved - app will not start
 */
export async function getRealRAM(): Promise<RAMData> {
  const data = await execWMIC('OS get TotalVisibleMemorySize,FreePhysicalMemory');

  if (!data || !data.TotalVisibleMemorySize || !data.FreePhysicalMemory) {
    throw new Error(
      'CRITICAL: Cannot read RAM data. WMIC command failed.\n\n' +
        'Possible fixes:\n' +
        '1. Ensure WMI service (winmgmt) is running\n' +
        '2. Run as Administrator\n' +
        '3. Check if antivirus is blocking WMIC'
    );
  }

  const totalKB = parseInt(data.TotalVisibleMemorySize);
  const freeKB = parseInt(data.FreePhysicalMemory);

  if (isNaN(totalKB) || isNaN(freeKB) || totalKB === 0) {
    throw new Error(
      'CRITICAL: Invalid RAM data returned from WMIC.\n\n' +
        `Received: Total=${data.TotalVisibleMemorySize}, Free=${data.FreePhysicalMemory}\n\n` +
        'WMI may be corrupted. Try: "winmgmt /resetrepository" as admin'
    );
  }

  const totalGB = Math.round((totalKB / 1024 / 1024) * 100) / 100;
  const freeGB = Math.round((freeKB / 1024 / 1024) * 100) / 100;
  const usedGB = Math.round((totalGB - freeGB) * 100) / 100;
  const usagePercent = Math.round((usedGB / totalGB) * 100);

  console.log(`✓ RAM Data: ${totalGB}GB total, ${usedGB}GB used (${usagePercent}%)`);

  return {
    totalGB,
    usedGB,
    freeGB,
    usagePercent,
  };
}

/**
 * CRITICAL: Get CPU information using WMIC - NO FALLBACKS
 * Throws error if data cannot be retrieved - app will not start
 */
export async function getRealCPU(): Promise<CPUData> {
  const data = await execWMIC('cpu get Name,NumberOfCores,NumberOfLogicalProcessors,LoadPercentage');

  if (!data || !data.Name) {
    throw new Error(
      'CRITICAL: Cannot read CPU data. WMIC command failed.\n\n' +
        'Possible fixes:\n' +
        '1. Ensure WMI service (winmgmt) is running\n' +
        '2. Run as Administrator\n' +
        '3. Check if antivirus is blocking WMIC'
    );
  }

  const cores = parseInt(data.NumberOfCores);
  const threads = parseInt(data.NumberOfLogicalProcessors);
  const currentLoad = parseInt(data.LoadPercentage);

  if (isNaN(cores) || isNaN(threads)) {
    throw new Error(
      'CRITICAL: Invalid CPU data returned from WMIC.\n\n' +
        `Received: Cores=${data.NumberOfCores}, Threads=${data.NumberOfLogicalProcessors}\n\n` +
        'WMI may be corrupted. Try: "winmgmt /resetrepository" as admin'
    );
  }

  console.log(`✓ CPU Data: ${data.Name.trim()}, ${cores} cores, ${threads} threads, ${currentLoad}% load`);

  return {
    name: data.Name.trim(),
    cores,
    threads,
    currentLoad: isNaN(currentLoad) ? 0 : currentLoad,
  };
}

/**
 * CRITICAL: Get disk information using WMIC - NO FALLBACKS
 * Throws error if data cannot be retrieved - app will not start
 */
export async function getRealDiskInfo(): Promise<DiskData[]> {
  const diskData = await execWMICMultiple('logicaldisk where DriveType=3 get DeviceID,Size,FreeSpace');

  if (!diskData || diskData.length === 0) {
    throw new Error(
      'CRITICAL: Cannot read disk data. WMIC command failed.\n\n' +
        'Possible fixes:\n' +
        '1. Ensure WMI service (winmgmt) is running\n' +
        '2. Run as Administrator\n' +
        '3. Check if antivirus is blocking WMIC'
    );
  }

  const disks: DiskData[] = [];

  for (const disk of diskData) {
    if (disk.DeviceID && disk.Size) {
      const totalBytes = parseInt(disk.Size);
      const freeBytes = parseInt(disk.FreeSpace);

      if (isNaN(totalBytes) || isNaN(freeBytes)) {
        console.warn(`⚠ Skipping invalid disk data: ${disk.DeviceID}`);
        continue;
      }

      const totalGB = Math.round((totalBytes / 1024 / 1024 / 1024) * 100) / 100;
      const freeGB = Math.round((freeBytes / 1024 / 1024 / 1024) * 100) / 100;
      const usedGB = Math.round((totalGB - freeGB) * 100) / 100;
      const usagePercent = totalGB > 0 ? Math.round((usedGB / totalGB) * 100) : 0;

      disks.push({
        drive: disk.DeviceID,
        totalGB,
        freeGB,
        usedGB,
        usagePercent,
      });

      console.log(`✓ Disk ${disk.DeviceID}: ${totalGB}GB total, ${usedGB}GB used (${usagePercent}%)`);
    }
  }

  if (disks.length === 0) {
    throw new Error(
      'CRITICAL: No valid disk data found.\n\n' +
        'WMIC returned data but all drives have invalid values.\n' +
        'WMI may be corrupted. Try: "winmgmt /resetrepository" as admin'
    );
  }

  return disks;
}

/**
 * Get system manufacturer and model information using Get-WmiObject (locale-independent)
 * Returns fallback values on error instead of throwing
 */
export async function getSystemInfo(): Promise<SystemInfo> {
  const command = `Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer,Model,Name,UserName | ConvertTo-Json`;
  const stdout = await execPowerShell(command);

  if (!stdout) {
    throw new Error('CRITICAL: Failed to retrieve computer system information via WMI');
  }

  const data = JSON.parse(stdout);

  if (!data || !data.Manufacturer) {
    throw new Error('CRITICAL: Invalid system info returned from WMI');
  }

  return {
    manufacturer: data.Manufacturer,
    model: data.Model,
    computerName: data.Name,
    userName: data.UserName,
  };
}

/**
 * Get operating system information using Get-WmiObject (locale-independent)
 * Returns fallback values on error instead of throwing
 */
export async function getOSInfo(): Promise<OSInfo> {
  const command = `Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,InstallDate,LastBootUpTime | ConvertTo-Json`;
  const stdout = await execPowerShell(command);

  if (!stdout) {
    throw new Error('CRITICAL: Failed to retrieve OS information via WMI');
  }

  const data = JSON.parse(stdout);

  const parseWmiDate = (wmiDate: string): string => {
    const year = wmiDate.substring(0, 4);
    const month = wmiDate.substring(4, 6);
    const day = wmiDate.substring(6, 8);
    const hour = wmiDate.substring(8, 10);
    const minute = wmiDate.substring(10, 12);
    const second = wmiDate.substring(12, 14);
    const date = new Date(`${year}-${month}-${day}T${hour}:${minute}:${second}`);
    return date.toLocaleString();
  };

  if (!data || !data.Caption) {
    throw new Error('CRITICAL: Invalid OS info returned from WMI');
  }

  return {
    caption: data.Caption,
    version: data.Version,
    buildNumber: data.BuildNumber,
    installDate: parseWmiDate(data.InstallDate),
    lastBootUpTime: parseWmiDate(data.LastBootUpTime),
  };
}

/**
 * Get network adapter information using Get-WmiObject (locale-independent)
 * Returns fallback values on error instead of throwing
 */
export async function getNetworkInfo(): Promise<NetworkInfo[]> {
  const command = `Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true} | Select-Object Description,IPAddress,MACAddress | ConvertTo-Json`;
  const stdout = await execPowerShell(command);

  if (!stdout) {
    throw new Error('CRITICAL: Failed to retrieve network adapter information via WMI');
  }

  let adapters = JSON.parse(stdout);

  if (!Array.isArray(adapters)) {
    adapters = [adapters];
  }

  return adapters.map((adapter: any) => ({
    adapterName: adapter.Description,
    ipAddress: Array.isArray(adapter.IPAddress) ? adapter.IPAddress[0] : adapter.IPAddress,
    macAddress: adapter.MACAddress,
  }));
}

export interface NetworkDiagnostics {
  activeConnections: number;
  openPorts: number;
  dnsWorking: boolean;
  dnsServer: string;
  vpnActive: boolean;
  vpnName: string;
  bandwidthBytesPerSec: number;
}

export interface TemperatureData {
  cpuTemp: number;
  gpuTemp: number;
}

/**
 * Get network diagnostics information
 * Returns detailed network health and connectivity status
 */
export async function getNetworkDiagnostics(): Promise<NetworkDiagnostics> {
  try {
    // Count established connections
    const connectionsCmd = `(netstat -ano | findstr ESTABLISHED | Measure-Object -Line).Lines`;
    const connectionsStr = await execPowerShell(connectionsCmd);
    const activeConnections = parseInt(connectionsStr) || 0;

    // Count listening ports
    const portsCmd = `(netstat -an | findstr LISTENING | Measure-Object -Line).Lines`;
    const portsStr = await execPowerShell(portsCmd);
    const openPorts = parseInt(portsStr) || 0;

    // Test DNS resolution
    const dnsCmd = `$result = Resolve-DnsName google.com -ErrorAction SilentlyContinue; if($result){$result.IPAddress}else{""}`;
    const dnsResult = await execPowerShell(dnsCmd);
    const dnsWorking = dnsResult.length > 0;

    // Get DNS server
    const dnsServerCmd = `(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | Select-Object -First 1).ServerAddresses[0]`;
    const dnsServer = await execPowerShell(dnsServerCmd);

    // Check for VPN
    const vpnCmd = `(Get-WmiObject Win32_NetworkAdapter | Where-Object {$_.Name -like "*VPN*" -or $_.Name -like "*TAP*" -or $_.Name -like "*TUN*"} | Select-Object -First 1).Name`;
    const vpnName = await execPowerShell(vpnCmd);
    const vpnActive = vpnName.length > 0;

    // Get bandwidth (bytes per second)
    const bandwidthCmd = `(Get-Counter "\\Network Interface(*)\\Bytes Total/sec" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Measure-Object -Property CookedValue -Sum).Sum`;
    const bandwidthStr = await execPowerShell(bandwidthCmd);
    const bandwidthBytesPerSec = Math.round(parseFloat(bandwidthStr)) || 0;

    return {
      activeConnections,
      openPorts,
      dnsWorking,
      dnsServer: dnsServer || 'Unknown',
      vpnActive,
      vpnName: vpnName || 'None',
      bandwidthBytesPerSec,
    };
  } catch (error: any) {
    console.error('Error getting network diagnostics:', error);
    throw new Error('CRITICAL: Failed to retrieve network diagnostics: ' + (error.message || String(error)));
  }
}

/**
 * Get hardware temperature information
 * Returns CPU and GPU temperatures in Celsius
 */
export async function getTemperatures(): Promise<TemperatureData> {
  try {
    // Get CPU temperature from thermal zone
    const cpuCmd = `$temp = (Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace root/wmi -ErrorAction SilentlyContinue | Select-Object -First 1).CurrentTemperature; if($temp){[math]::Round(($temp - 2732) / 10, 1)}else{0}`;
    const cpuTempStr = await execPowerShell(cpuCmd);
    const cpuTemp = parseFloat(cpuTempStr) || 0;

    // Get GPU temperature (may not be available on all systems)
    const gpuCmd = `(Get-WmiObject Win32_VideoController | Select-Object -First 1).CurrentTemperature`;
    const gpuTempStr = await execPowerShell(gpuCmd);
    const gpuTemp = parseFloat(gpuTempStr) || 0;

    return {
      cpuTemp,
      gpuTemp,
    };
  } catch (error: any) {
    console.error('Error getting temperatures:', error);
    throw new Error('CRITICAL: Failed to read temperature sensors: ' + (error.message || String(error)));
  }
}

/**
 * Get comprehensive real-time system data
 */
export async function getRealSystemData() {
  try {
    const [ram, cpu, disks, systemInfo, osInfo, networkInfo] = await Promise.all([
      getRealRAM(),
      getRealCPU(),
      getRealDiskInfo(),
      getSystemInfo(),
      getOSInfo(),
      getNetworkInfo(),
    ]);

    return {
      success: true,
      data: {
        ram,
        cpu,
        disks,
        system: systemInfo,
        os: osInfo,
        network: networkInfo,
      },
    };
  } catch (error: any) {
    console.error('Error getting system data:', error);
    throw new Error('CRITICAL: Failed to retrieve complete system data: ' + (error.message || String(error)));
  }
}
