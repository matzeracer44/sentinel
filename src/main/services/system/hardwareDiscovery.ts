/**
 * SENTINEL — Full Hardware Discovery Service
 * Single PowerShell call retrieves GPU, RAM slots, storage, network adapters,
 * motherboard, TPM, battery, audio, bluetooth, and display info.
 * Avoids spawning 15+ separate PS processes.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

const PS_TIMEOUT = 30000;
const PS_MAX_BUFFER = 8 * 1024 * 1024;

export interface GpuInfo {
  name: string;
  driver: string;
  driverDate: string;
  vramMB: number;
  resolution: string;
  refreshRate: number;
}

export interface RamSlot {
  bank: string;
  capacityGB: number;
  speed: string;
  type: string;
  manufacturer: string;
}

export interface StorageDrive {
  model: string;
  sizeGB: number;
  mediaType: string;
  busType: string;
  health: string;
}

export interface StorageVolume {
  letter: string;
  label: string;
  totalGB: number;
  freeGB: number;
  filesystem: string;
}

export interface NetworkAdapter {
  name: string;
  description: string;
  mac: string;
  speed: string;
  status: string;
  type: string;
}

export interface BatteryInfo {
  present: boolean;
  chargePercent: number;
  isCharging: boolean;
  estimatedRuntime: string;
  designCapacity: number;
  fullChargeCapacity: number;
  healthPercent: number;
  powerPlan: string;
}

export interface HardwareReport {
  gpu: GpuInfo[];
  ram: { totalGB: number; usedGB: number; freeGB: number; slots: RamSlot[] };
  storage: { drives: StorageDrive[]; volumes: StorageVolume[] };
  network: { adapters: NetworkAdapter[] };
  motherboard: { manufacturer: string; product: string; biosVersion: string; biosDate: string };
  security: { tpmPresent: boolean; tpmVersion: string; secureBoot: boolean };
  battery: BatteryInfo | null;
  audio: { devices: { name: string; status: string }[] };
  bluetooth: { available: boolean; devices: { name: string; status: string }[] };
  thermal: { available: boolean; sensors: { name: string; tempC: number; critical?: number }[] };
  display: { monitors: { name: string; resolution: string; refreshRate: number; connection: string }[] };
  usb: { devices: { name: string; type: string; status: string }[] };
  bitlocker: { enabled: boolean; volumes: { letter: string; status: string; method: string }[] };
  timestamp: string;
}

const PS_SCRIPT = `
$ErrorActionPreference='SilentlyContinue'

try { $gpu = @(Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,DriverDate,AdapterRAM,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate) } catch { $gpu = @() }

try { $ram = @(Get-CimInstance Win32_PhysicalMemory | Select-Object BankLabel,Capacity,Speed,SMBIOSMemoryType,Manufacturer) } catch { $ram = @() }

try { $os_mem = Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory } catch { $os_mem = $null }

try { $disks = @(Get-PhysicalDisk | Select-Object FriendlyName,MediaType,@{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}},BusType,HealthStatus) } catch { $disks = @() }

try { $volumes = @(Get-Volume | Where-Object {$_.DriveLetter} | Select-Object DriveLetter,FileSystemLabel,@{N='TotalGB';E={[math]::Round($_.Size/1GB,1)}},@{N='FreeGB';E={[math]::Round($_.SizeRemaining/1GB,1)}},FileSystem) } catch { $volumes = @() }

try { $adapters = @(Get-NetAdapter | Select-Object Name,InterfaceDescription,MacAddress,LinkSpeed,Status,@{N='AdapterType';E={if($_.InterfaceDescription -match 'Wi-Fi|Wireless'){'WiFi'}elseif($_.InterfaceDescription -match 'VPN|NordLynx|WireGuard|TAP|TUN'){'VPN'}elseif($_.InterfaceDescription -match 'Hyper-V|Virtual|vEthernet'){'Virtual'}else{'Ethernet'}}}) } catch { $adapters = @() }

try { $board = Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product } catch { $board = $null }
try { $bios = Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion,ReleaseDate } catch { $bios = $null }

$tpmPresent = $false; $tpmVer = ''
try { $t = Get-Tpm -EA Stop; $tpmPresent = $t.TpmPresent; $tpmVer = $t.ManufacturerVersion } catch { <# TPM may not be present #> }

$secBoot = $false
try { $secBoot = Confirm-SecureBootUEFI -EA Stop } catch { <# SecureBoot unavailable on legacy BIOS #> }

try { $battery = Get-CimInstance Win32_Battery | Select-Object EstimatedChargeRemaining,EstimatedRunTime,BatteryStatus,DesignCapacity,FullChargeCapacity } catch { $battery = $null }
$powerPlan = ''
try { $pp = powercfg /getactivescheme 2>&1; if($pp -match '\\((.+)\\)'){$powerPlan=$Matches[1]} } catch { <# powercfg may fail without admin #> }

try { $audio = @(Get-CimInstance Win32_SoundDevice | Select-Object Name,Status) } catch { $audio = @() }
try { $bt = @(Get-PnpDevice -Class Bluetooth -Status OK -EA SilentlyContinue | Select-Object FriendlyName,Status) } catch { $bt = @() }

$monitors = @()
try {
  $mon = Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorID -EA SilentlyContinue
  if($mon){foreach($m in $mon){$name=[System.Text.Encoding]::ASCII.GetString($m.UserFriendlyName).Trim([char]0);$conn=switch($m.VideoOutputTechnology){0{'VGA'}4{'DVI'}5{'HDMI'}10{'DP'}11{'DP'}default{'Other'}};$monitors+=@{Name=$name;Connection=$conn}}}
} catch { <# WMI monitor data may be unavailable #> }

try { $usbDevices = @(Get-PnpDevice -Class USB -Status OK -EA SilentlyContinue | Select-Object FriendlyName,Class,Status) } catch { $usbDevices = @() }

$bitlocker = @()
try { $bitlocker = @(Get-BitLockerVolume -EA Stop | Select-Object MountPoint,ProtectionStatus,VolumeStatus,EncryptionMethod) } catch { <# BitLocker may not be available #> }

$thermal = @()
try {
  $tz = Get-CimInstance MSAcpi_ThermalZoneTemperature -Namespace root/wmi -EA Stop
  if($tz){foreach($t in $tz){$crit=0;if($t.CriticalTripPoint){$crit=[math]::Round(($t.CriticalTripPoint-2732)/10,1)};$thermal+=@{Name=$t.InstanceName;TempC=[math]::Round(($t.CurrentTemperature-2732)/10,1);Critical=$crit}}}
} catch { <# thermal WMI class may not exist #> }
if($thermal.Count -eq 0){
  try {
    $cpuTemp = (Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation -EA SilentlyContinue | Select -First 1).Temperature
    if($cpuTemp -and $cpuTemp -gt 0){$thermal+=@{Name='CPU Package';TempC=[math]::Round($cpuTemp-273.15,1);Critical=0}}
  } catch { <# thermal fallback may fail #> }
}

[PSCustomObject]@{
  GPU = $gpu
  RAM = $ram
  OSMem = $os_mem
  Disks = $disks
  Volumes = $volumes
  Adapters = $adapters
  Board = $board
  BIOS = $bios
  TPM = @{ Present = $tpmPresent; Version = $tpmVer }
  SecureBoot = $secBoot
  Battery = $battery
  PowerPlan = $powerPlan
  Audio = $audio
  Bluetooth = $bt
  Thermal = $thermal
  Monitors = $monitors
  USB = $usbDevices
  BitLocker = $bitlocker
} | ConvertTo-Json -Depth 4 -Compress
`;

function toArr<T>(v: T | T[] | null | undefined): T[] {
  if (!v) return [];
  return Array.isArray(v) ? v : [v];
}

export async function getFullHardwareReport(): Promise<HardwareReport> {
  const report: HardwareReport = {
    gpu: [], ram: { totalGB: 0, usedGB: 0, freeGB: 0, slots: [] },
    storage: { drives: [], volumes: [] }, network: { adapters: [] },
    motherboard: { manufacturer: '', product: '', biosVersion: '', biosDate: '' },
    security: { tpmPresent: false, tpmVersion: '', secureBoot: false },
    battery: null, audio: { devices: [] }, bluetooth: { available: false, devices: [] },
    thermal: { available: false, sensors: [] },
    display: { monitors: [] }, usb: { devices: [] }, bitlocker: { enabled: false, volumes: [] },
    timestamp: new Date().toISOString(),
  };

  try {
    const encoded = Buffer.from(PS_SCRIPT, 'utf16le').toString('base64');
    const { stdout, stderr } = await execFileAsync('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
      { timeout: PS_TIMEOUT, windowsHide: true, encoding: 'utf8', maxBuffer: PS_MAX_BUFFER }
    );
    if (stderr) console.warn('[HardwareDiscovery] PS stderr:', stderr.substring(0, 500));
    const raw = (stdout || '').trim();
    if (!raw) {
      console.error('[HardwareDiscovery] Empty PS output');
      throw new Error('Empty PS output');
    }
    const d = JSON.parse(raw);

    // GPU
    for (const g of toArr(d.GPU)) {
      report.gpu.push({
        name: g.Name || 'Unknown',
        driver: g.DriverVersion || '',
        driverDate: g.DriverDate ? new Date(g.DriverDate).toLocaleDateString('de-DE') : '',
        vramMB: g.AdapterRAM ? Math.round(g.AdapterRAM / (1024 * 1024)) : 0,
        resolution: `${g.CurrentHorizontalResolution || 0}x${g.CurrentVerticalResolution || 0}`,
        refreshRate: g.CurrentRefreshRate || 0,
      });
    }

    // RAM — WMI primary, Node.js os fallback
    const osMem = Array.isArray(d.OSMem) ? d.OSMem[0] : d.OSMem;
    if (osMem && (osMem.TotalVisibleMemorySize || osMem.totalvisiblemorysize)) {
      const total = osMem.TotalVisibleMemorySize || osMem.totalvisiblemorysize || 0;
      const free = osMem.FreePhysicalMemory || osMem.freephysicalmemory || 0;
      report.ram.totalGB = Math.round(total / (1024 * 1024) * 10) / 10;
      report.ram.freeGB = Math.round(free / (1024 * 1024) * 10) / 10;
      report.ram.usedGB = Math.round((report.ram.totalGB - report.ram.freeGB) * 10) / 10;
    }
    if (report.ram.totalGB === 0) {
      const os = await import('os');
      report.ram.totalGB = Math.round(os.totalmem() / (1024 ** 3) * 10) / 10;
      report.ram.freeGB = Math.round(os.freemem() / (1024 ** 3) * 10) / 10;
      report.ram.usedGB = Math.round((report.ram.totalGB - report.ram.freeGB) * 10) / 10;
    }
    for (const r of toArr(d.RAM)) {
      const memTypeMap: Record<number, string> = { 20: 'DDR', 21: 'DDR2', 22: 'DDR2', 24: 'DDR3', 26: 'DDR4', 34: 'DDR5' };
      report.ram.slots.push({
        bank: r.BankLabel || 'Unknown',
        capacityGB: r.Capacity ? Math.round(r.Capacity / (1024 * 1024 * 1024)) : 0,
        speed: r.Speed ? `${r.Speed} MHz` : '',
        type: memTypeMap[r.SMBIOSMemoryType] || `Type ${r.SMBIOSMemoryType || '?'}`,
        manufacturer: r.Manufacturer || 'Unknown',
      });
    }

    // Storage
    for (const dk of toArr(d.Disks)) {
      report.storage.drives.push({
        model: dk.FriendlyName || 'Unknown',
        sizeGB: dk.SizeGB || 0,
        mediaType: typeof dk.MediaType === 'number' ? ['Unspecified', 'HDD', 'SSD', 'SCM'][dk.MediaType] || 'Unknown' : String(dk.MediaType || 'Unknown'),
        busType: dk.BusType || '',
        health: dk.HealthStatus || 'Unknown',
      });
    }
    for (const v of toArr(d.Volumes)) {
      report.storage.volumes.push({
        letter: v.DriveLetter || '',
        label: v.FileSystemLabel || '',
        totalGB: v.TotalGB || 0,
        freeGB: v.FreeGB || 0,
        filesystem: v.FileSystem || '',
      });
    }

    // Network
    for (const a of toArr(d.Adapters)) {
      report.network.adapters.push({
        name: a.Name || '', description: a.InterfaceDescription || '',
        mac: a.MacAddress || '', speed: a.LinkSpeed || '', status: a.Status || '',
        type: a.AdapterType || 'Ethernet',
      });
    }

    // Motherboard
    const board = Array.isArray(d.Board) ? d.Board[0] : d.Board;
    const bios = Array.isArray(d.BIOS) ? d.BIOS[0] : d.BIOS;
    report.motherboard = {
      manufacturer: board?.Manufacturer || '',
      product: board?.Product || '',
      biosVersion: bios?.SMBIOSBIOSVersion || '',
      biosDate: bios?.ReleaseDate ? new Date(bios.ReleaseDate).toLocaleDateString('de-DE') : '',
    };

    // Security
    report.security = {
      tpmPresent: d.TPM?.Present === true,
      tpmVersion: d.TPM?.Version || '',
      secureBoot: d.SecureBoot === true,
    };

    // Battery
    const bat = Array.isArray(d.Battery) ? d.Battery[0] : d.Battery;
    if (bat && bat.EstimatedChargeRemaining != null) {
      const design = bat.DesignCapacity || 1;
      const full = bat.FullChargeCapacity || design;
      report.battery = {
        present: true,
        chargePercent: bat.EstimatedChargeRemaining || 0,
        isCharging: bat.BatteryStatus === 2 || bat.BatteryStatus === 6,
        estimatedRuntime: bat.EstimatedRunTime ? `${Math.floor(bat.EstimatedRunTime / 60)}h ${bat.EstimatedRunTime % 60}m` : 'N/A',
        designCapacity: design,
        fullChargeCapacity: full,
        healthPercent: Math.round((full / design) * 100),
        powerPlan: d.PowerPlan || '',
      };
    }

    // Audio
    for (const au of toArr(d.Audio)) {
      report.audio.devices.push({ name: au.Name || 'Unknown', status: au.Status || '' });
    }

    // Bluetooth
    const btDevices = toArr(d.Bluetooth);
    report.bluetooth = {
      available: btDevices.length > 0,
      devices: btDevices.map((b: { FriendlyName?: string; Status?: string }) => ({
        name: b.FriendlyName || '', status: b.Status || '',
      })),
    };

    // Thermal
    const thermalSensors = toArr(d.Thermal);
    if (thermalSensors.length > 0) {
      report.thermal = {
        available: true,
        sensors: thermalSensors.map((t: { Name?: string; TempC?: number; Critical?: number }) => ({
          name: (t.Name || 'Unknown').replace(/\\_/g, ' ').replace(/ACPI\\ThermalZone\\/, ''),
          tempC: typeof t.TempC === 'number' ? t.TempC : 0,
          critical: typeof t.Critical === 'number' && t.Critical > 0 ? t.Critical : undefined,
        })),
      };
    }

    // Display monitors
    const monitors = toArr(d.Monitors);
    report.display = {
      monitors: monitors.map((m: { Name?: string; Connection?: string }) => {
        // Get resolution/refresh from GPU data (first GPU with resolution)
        const gpuWithRes = toArr(d.GPU).find((g: any) => g.CurrentHorizontalResolution > 0);
        return {
          name: m.Name || 'Unknown Monitor',
          resolution: gpuWithRes ? `${gpuWithRes.CurrentHorizontalResolution}x${gpuWithRes.CurrentVerticalResolution}` : 'N/A',
          refreshRate: gpuWithRes?.CurrentRefreshRate || 0,
          connection: m.Connection || 'Unknown',
        };
      }),
    };

    // USB devices — deduplicate by name
    const usbDevices = toArr(d.USB);
    const seenUsb = new Set<string>();
    report.usb = {
      devices: usbDevices
        .map((u: { FriendlyName?: string; Class?: string; Status?: string }) => ({
          name: u.FriendlyName || 'Unknown Device',
          type: u.Class || 'USB',
          status: u.Status || 'OK',
        }))
        .filter((u) => {
          const key = u.name.toLowerCase();
          if (seenUsb.has(key)) return false;
          seenUsb.add(key);
          return true;
        }),
    };

    // BitLocker
    const blVolumes = toArr(d.BitLocker);
    const hasProtected = blVolumes.some((v: any) => v.ProtectionStatus === 1);
    report.bitlocker = {
      enabled: hasProtected,
      volumes: blVolumes.map((v: { MountPoint?: string; ProtectionStatus?: number; VolumeStatus?: string; EncryptionMethod?: string }) => ({
        letter: (v.MountPoint || '').replace(':', ''),
        status: v.ProtectionStatus === 1 ? 'Protected' : v.ProtectionStatus === 0 ? 'Unprotected' : 'Unknown',
        method: v.EncryptionMethod || 'None',
      })),
    };
  } catch (err) {
    console.error('[HardwareDiscovery] Failed:', err instanceof Error ? err.message : err);
  }

  return report;
}
