import { exec } from 'child_process';
import { promisify } from 'util';
import { getExecOptions } from './execOptions';

const execAsync = promisify(exec);

async function execPowerShell(command: string): Promise<string> {
  try {
    const opts = getExecOptions();
    const { stdout } = await execAsync(`powershell -ExecutionPolicy Bypass -NoProfile -Command "${command}"`, {
      timeout: opts.timeout, maxBuffer: opts.maxBuffer, encoding: 'utf8', windowsHide: true,
    });
    return (stdout || '').trim();
  } catch (error: any) {
    console.error('PowerShell execution error:', error.message);
    return '';
  }
}

export interface RegistryTweak {
  id: string;
  name: string;
  description: string;
  category: 'privacy' | 'performance' | 'gaming' | 'system';
  path: string;
  key: string;
  enabledValue: number | string;
  disabledValue: number | string;
  requiresRestart: boolean;
}

export interface TweakStatus extends RegistryTweak {
  currentValue: string;
  isEnabled: boolean;
}

/**
 * Registry tweaks database
 */
export const TWEAKS: RegistryTweak[] = [
  // Privacy tweaks
  {
    id: 'disable-telemetry',
    name: 'Disable Telemetry',
    description: 'Disable Windows telemetry and diagnostic data collection',
    category: 'privacy',
    path: 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection',
    key: 'AllowTelemetry',
    enabledValue: 0,
    disabledValue: 3,
    requiresRestart: true,
  },
  {
    id: 'disable-cortana',
    name: 'Disable Cortana',
    description: 'Disable Cortana voice assistant',
    category: 'privacy',
    path: 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search',
    key: 'AllowCortana',
    enabledValue: 0,
    disabledValue: 1,
    requiresRestart: false,
  },
  {
    id: 'disable-activity-history',
    name: 'Disable Activity History',
    description: 'Prevent Windows from collecting activity history',
    category: 'privacy',
    path: 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System',
    key: 'EnableActivityFeed',
    enabledValue: 0,
    disabledValue: 1,
    requiresRestart: false,
  },
  {
    id: 'disable-advertising-id',
    name: 'Disable Advertising ID',
    description: 'Disable Windows advertising ID for personalized ads',
    category: 'privacy',
    path: 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo',
    key: 'Enabled',
    enabledValue: 0,
    disabledValue: 1,
    requiresRestart: false,
  },

  // Performance tweaks
  {
    id: 'disable-animations',
    name: 'Disable Animations',
    description: 'Disable Windows animations for faster performance',
    category: 'performance',
    path: 'HKCU:\\Control Panel\\Desktop\\WindowMetrics',
    key: 'MinAnimate',
    enabledValue: 0,
    disabledValue: 1,
    requiresRestart: false,
  },
  {
    id: 'disable-transparency',
    name: 'Disable Transparency',
    description: 'Disable transparency effects for better performance',
    category: 'performance',
    path: 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize',
    key: 'EnableTransparency',
    enabledValue: 0,
    disabledValue: 1,
    requiresRestart: false,
  },
  {
    id: 'disable-startup-delay',
    name: 'Disable Startup Delay',
    description: 'Remove 10-second delay for startup programs',
    category: 'performance',
    path: 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Serialize',
    key: 'StartupDelayInMSec',
    enabledValue: 0,
    disabledValue: 10000,
    requiresRestart: true,
  },

  // Gaming tweaks
  {
    id: 'game-mode',
    name: 'Game Mode',
    description: 'Enable Windows Game Mode for better gaming performance',
    category: 'gaming',
    path: 'HKCU:\\Software\\Microsoft\\GameBar',
    key: 'AutoGameModeEnabled',
    enabledValue: 1,
    disabledValue: 0,
    requiresRestart: false,
  },
  {
    id: 'hardware-acceleration',
    name: 'Hardware GPU Scheduling',
    description: 'Enable hardware-accelerated GPU scheduling',
    category: 'gaming',
    path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers',
    key: 'HwSchMode',
    enabledValue: 2,
    disabledValue: 1,
    requiresRestart: true,
  },
  {
    id: 'disable-game-dvr',
    name: 'Disable Game DVR',
    description: 'Disable Xbox Game DVR (can improve FPS)',
    category: 'gaming',
    path: 'HKCU:\\System\\GameConfigStore',
    key: 'GameDVR_Enabled',
    enabledValue: 0,
    disabledValue: 1,
    requiresRestart: false,
  },

  // System tweaks
  {
    id: 'show-file-extensions',
    name: 'Show File Extensions',
    description: 'Show file extensions in File Explorer',
    category: 'system',
    path: 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced',
    key: 'HideFileExt',
    enabledValue: 0,
    disabledValue: 1,
    requiresRestart: false,
  },
  {
    id: 'show-hidden-files',
    name: 'Show Hidden Files',
    description: 'Show hidden files and folders in File Explorer',
    category: 'system',
    path: 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced',
    key: 'Hidden',
    enabledValue: 1,
    disabledValue: 2,
    requiresRestart: false,
  },
  {
    id: 'dark-mode',
    name: 'Dark Mode',
    description: 'Enable Windows dark theme',
    category: 'system',
    path: 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize',
    key: 'AppsUseLightTheme',
    enabledValue: 0,
    disabledValue: 1,
    requiresRestart: false,
  },
];

/**
 * Get current status of a tweak
 */
export async function getTweakStatus(tweak: RegistryTweak): Promise<TweakStatus> {
  try {
    const cmd = `(Get-ItemProperty -Path "${tweak.path}" -Name "${tweak.key}" -ErrorAction SilentlyContinue).${tweak.key}`;
    const currentValue = await execPowerShell(cmd);

    const isEnabled = currentValue === String(tweak.enabledValue);

    return {
      ...tweak,
      currentValue: currentValue || 'Not Set',
      isEnabled,
    };
  } catch (error: any) {
    console.error(`Error getting tweak status for ${tweak.id}:`, error);
    return {
      ...tweak,
      currentValue: 'Error',
      isEnabled: false,
    };
  }
}

/**
 * Get status of all tweaks
 */
export async function getAllTweaksStatus(): Promise<TweakStatus[]> {
  const promises = TWEAKS.map((tweak) => getTweakStatus(tweak));
  return Promise.all(promises);
}

/**
 * Apply a tweak (enable or disable)
 */
export async function applyTweak(tweakId: string, enable: boolean): Promise<boolean> {
  try {
    const tweak = TWEAKS.find((t) => t.id === tweakId);
    if (!tweak) {
      console.error(`Tweak not found: ${tweakId}`);
      return false;
    }

    const value = enable ? tweak.enabledValue : tweak.disabledValue;
    const valueType = typeof value === 'number' ? 'DWord' : 'String';

    // Create registry path if it doesn't exist
    const createPathCmd = `New-Item -Path "${tweak.path}" -Force -ErrorAction SilentlyContinue | Out-Null`;
    await execPowerShell(createPathCmd);

    // Set registry value
    const setValueCmd = `Set-ItemProperty -Path "${tweak.path}" -Name "${tweak.key}" -Value ${value} -Type ${valueType} -Force`;
    await execPowerShell(setValueCmd);

    console.log(`✓ Tweak ${tweakId} ${enable ? 'enabled' : 'disabled'}`);
    return true;
  } catch (error: any) {
    console.error(`Error applying tweak ${tweakId}:`, error);
    return false;
  }
}

/**
 * Apply multiple tweaks at once
 */
export async function applyMultipleTweaks(tweakIds: string[], enable: boolean): Promise<{ [key: string]: boolean }> {
  const results: { [key: string]: boolean } = {};

  for (const tweakId of tweakIds) {
    results[tweakId] = await applyTweak(tweakId, enable);
  }

  return results;
}

/**
 * Reset a tweak to default Windows value
 */
export async function resetTweak(tweakId: string): Promise<boolean> {
  return applyTweak(tweakId, false);
}

/**
 * Get tweaks by category
 */
export function getTweaksByCategory(category: 'privacy' | 'performance' | 'gaming' | 'system'): RegistryTweak[] {
  return TWEAKS.filter((tweak) => tweak.category === category);
}
