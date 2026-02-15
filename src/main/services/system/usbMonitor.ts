/**
 * SENTINEL — USB Device Monitor Service
 * Enumerates connected USB devices and queries USB connection history from registry.
 * Alerts on new USB mass storage devices.
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const PS_TIMEOUT = 8000;
const PS_MAX_BUFFER = 4 * 1024 * 1024;

export interface UsbDevice {
  name: string;
  deviceId: string;
  manufacturer: string;
  status: string;
  classType: string;
  isMassStorage: boolean;
}

export interface UsbHistoryEntry {
  friendlyName: string;
  deviceId: string;
  lastConnected: string | null;
  serialNumber: string;
}

export interface UsbMonitorResult {
  connected: UsbDevice[];
  history: UsbHistoryEntry[];
  massStorageCount: number;
  timestamp: string;
}

export async function getUsbDevices(): Promise<UsbMonitorResult> {
  const result: UsbMonitorResult = {
    connected: [],
    history: [],
    massStorageCount: 0,
    timestamp: new Date().toISOString(),
  };

  try {
    const psScript = `
      Get-PnpDevice -Class USB -Status OK -ErrorAction SilentlyContinue |
      Select-Object FriendlyName, InstanceId, Manufacturer, Status, Class |
      ConvertTo-Json -Compress
    `;
    const { stdout } = await execAsync(
      `powershell -NoProfile -NonInteractive -Command "${psScript.replace(/\n/g, ' ')}"`,
      { timeout: PS_TIMEOUT, maxBuffer: PS_MAX_BUFFER }
    );

    const raw = JSON.parse(stdout.trim() || '[]');
    const devices = Array.isArray(raw) ? raw : [raw];

    for (const d of devices) {
      const classType = (d.Class || '').toLowerCase();
      const isMassStorage = classType.includes('disk') || classType.includes('storage') ||
        classType.includes('usbstor') || (d.FriendlyName || '').toLowerCase().includes('mass storage');

      result.connected.push({
        name: d.FriendlyName || 'Unknown USB Device',
        deviceId: d.InstanceId || '',
        manufacturer: d.Manufacturer || 'Unknown',
        status: d.Status || 'Unknown',
        classType: d.Class || 'USB',
        isMassStorage,
      });

      if (isMassStorage) result.massStorageCount++;
    }
  } catch (err) {
    console.error('[UsbMonitor] Device enumeration failed:', err instanceof Error ? err.message : err);
  }

  try {
    const histScript = `
      Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*' -ErrorAction SilentlyContinue |
      Select-Object FriendlyName, PSChildName, @{N='DeviceId';E={$_.PSPath -replace '.*USBSTOR\\\\',''}} |
      Where-Object { $_.FriendlyName } |
      Select-Object -First 50 |
      ConvertTo-Json -Compress
    `;
    const { stdout: histOut } = await execAsync(
      `powershell -NoProfile -NonInteractive -Command "${histScript.replace(/\n/g, ' ')}"`,
      { timeout: PS_TIMEOUT, maxBuffer: PS_MAX_BUFFER }
    );

    const histRaw = JSON.parse(histOut.trim() || '[]');
    const histList = Array.isArray(histRaw) ? histRaw : [histRaw];

    for (const h of histList) {
      result.history.push({
        friendlyName: h.FriendlyName || 'Unknown',
        deviceId: h.DeviceId || '',
        lastConnected: null,
        serialNumber: h.PSChildName || '',
      });
    }
  } catch {
    // Registry query failed — non-critical
  }

  return result;
}
