import { exec, execFile } from 'child_process';
import { promisify } from 'util';
import { getExecOptions } from './execOptions';
const execFileP = promisify(execFile);
const execAsync = promisify(exec);

/**
 * Helper function to execute PowerShell commands with proper error handling
 */
async function execPowerShell(command: string): Promise<string> {
  try {
    // Encode command as UTF-16LE base64 to avoid cmd.exe/quotes parsing issues
    const encoded = Buffer.from(command, 'utf16le').toString('base64');
    // Use execFile with argument array to avoid shell quoting and parsing issues
    const args = ['-NoLogo', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-EncodedCommand', encoded];
    const { stdout } = await execFileP('powershell', args, getExecOptions()) as { stdout: string };

    if (!stdout) return '';

    // Filter out CLIXML/progress noise and other non-command output that can break parsing
    const cleaned = stdout
      .split(/\r?\n/)
      .filter((line) => {
        return (
          !line.startsWith('#<') &&
          !line.startsWith('<Objs') &&
          !line.startsWith('<Obj') &&
          !line.includes('Module werden')
        );
      })
      .join('\n')
      .trim();

    return cleaned;
  } catch (error: any) {
    if (error.killed || error.code === 'ETIMEDOUT') {
      console.error('PowerShell execution timed out:', error.message);
    } else {
      console.error('PowerShell execution error:', error.message);
    }
    return '';
  }
} 

export interface AntivirusProduct {
  displayName: string;
  productState: string;
  pathToSignedProductExe: string;
}

export interface SuspiciousTask {
  taskName: string;
  author: string;
}

export interface SecurityStatus {
  firewallEnabled: boolean;
  antivirusProducts: AntivirusProduct[];
  antivirusActive: boolean;
  smbv1Enabled: boolean;
  suspiciousTasks: SuspiciousTask[];
  defenderEnabled: boolean;
  uacEnabled: boolean;
}

/**
 * Get comprehensive security status
 * Checks firewall, antivirus, SMBv1, suspicious tasks, Windows Defender, and UAC
 */
export async function getSecurityStatus(): Promise<SecurityStatus> {
  try {
    // Check firewall status (all profiles)
    const firewallCmd = `(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }).Count -gt 0`;
    const firewallStr = await execPowerShell(firewallCmd);
    const firewallEnabled = firewallStr === 'True';

    // Get antivirus products from Security Center
    const avCmd = `Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object displayName,productState,pathToSignedProductExe | ConvertTo-Json`;
    const avStr = await execPowerShell(avCmd);
    let antivirusProducts: AntivirusProduct[] = [];
    let antivirusActive = false;

    try {
      if (avStr) {
        const avData = JSON.parse(avStr);
        antivirusProducts = Array.isArray(avData) ? avData : [avData];
        // Product state is a hex value - check if any AV is active
        antivirusActive = antivirusProducts.some((av) => av.productState && parseInt(av.productState) > 0);
      }
    } catch (e) {
      console.log('Could not parse antivirus data');
    }

    // Check SMBv1 status
    const smbCmd = `(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State`;
    const smbStr = await execPowerShell(smbCmd);
    const smbv1Enabled = smbStr === 'Enabled';

    // Get suspicious scheduled tasks (non-Microsoft tasks)
    const tasksCmd = `Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.Author -and $_.Author -notlike '*Microsoft*' -and $_.TaskPath -notlike '\\Microsoft\\*' } | Select-Object @{N='TaskName';E={$_.TaskName}},@{N='Author';E={$_.Author}} | ConvertTo-Json -Compress`;
    const tasksStr = await execPowerShell(tasksCmd);
    let suspiciousTasks: SuspiciousTask[] = [];

    try {
      if (tasksStr) {
        const tasksData = JSON.parse(tasksStr);
        suspiciousTasks = Array.isArray(tasksData) ? tasksData : [tasksData];
      }
    } catch (e) {
      console.log('Could not parse scheduled tasks');
    }

    // Check Windows Defender status
    const defenderCmd = `(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled`;
    const defenderStr = await execPowerShell(defenderCmd);
    const defenderEnabled = defenderStr === 'True';

    // Check UAC status
    const uacCmd = `(Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA`;
    const uacStr = await execPowerShell(uacCmd);
    const uacEnabled = uacStr === '1';

    return {
      firewallEnabled,
      antivirusProducts,
      antivirusActive,
      smbv1Enabled,
      suspiciousTasks,
      defenderEnabled,
      uacEnabled,
    };
  } catch (error: any) {
    console.error('Error getting security status:', error);
    return {
      firewallEnabled: false,
      antivirusProducts: [],
      antivirusActive: false,
      smbv1Enabled: false,
      suspiciousTasks: [],
      defenderEnabled: false,
      uacEnabled: false,
    };
  }
}

/**
 * Enable Windows Firewall for all profiles
 */
export async function enableFirewall(): Promise<boolean> {
  try {
    await execAsync('netsh advfirewall set allprofiles state on', { windowsHide: true, timeout: 10000 });
    return true;
  } catch (error: any) {
    console.error('Error enabling firewall:', error);
    return false;
  }
}

/**
 * Disable SMBv1 protocol (security risk)
 */
export async function disableSMBv1(): Promise<boolean> {
  try {
    await execPowerShell('Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart');
    return true;
  } catch (error: any) {
    console.error('Error disabling SMBv1:', error);
    return false;
  }
}

/**
 * Enable Windows Defender
 */
export async function enableDefender(): Promise<boolean> {
  try {
    await execPowerShell('Set-MpPreference -DisableRealtimeMonitoring $false');
    return true;
  } catch (error: any) {
    console.error('Error enabling Defender:', error);
    return false;
  }
}

/**
 * Enable UAC (User Account Control)
 */
export async function enableUAC(): Promise<boolean> {
  try {
    await execPowerShell('Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name EnableLUA -Value 1');
    return true;
  } catch (error: any) {
    console.error('Error enabling UAC:', error);
    return false;
  }
}
