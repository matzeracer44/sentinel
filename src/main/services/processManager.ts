import { execFile, execSync } from 'child_process';
import { promisify } from 'util';
import { getExecOptions } from './execOptions';

const execFileAsync = promisify(execFile);

/**
 * Sanitize a string for safe embedding in a PowerShell double-quoted context.
 * Strips characters that can break out of quotes or inject commands.
 */
function sanitizePSArg(input: string): string {
  return input.replace(/["`$();|&><{}\\]/g, '');
}

async function execPowerShell(command: string): Promise<string> {
  const encoded = Buffer.from(command, 'utf16le').toString('base64');
  const opts = getExecOptions();
  try {
    const { stdout } = await execFileAsync(
      'powershell',
      ['-NoLogo', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-EncodedCommand', encoded],
      opts,
    ) as { stdout: string };
    return (stdout || '').trim();
  } catch (error: any) {
    console.error('PowerShell execution error:', error.message);
    throw new Error(`PowerShell execution error: ${error.message}`);
  }
}

export interface ProcessInfo {
  name: string;
  id: number;
  ramMB: number;
  cpu: number;
  path: string;
}

export interface StartupProgram {
  name: string;
  command: string;
  location: string;
  impact: 'Low' | 'Medium' | 'High';
}

export async function getProcessesEnhanced(): Promise<ProcessInfo[]> {
  const cmd = `Get-Process | Select-Object Name,Id,@{n="RAM_MB";e={[math]::Round($_.WorkingSet64/1MB,2)}},@{n="CPU";e={$_.CPU}},Path | Sort-Object RAM_MB -Descending | Select-Object -First 20 | ConvertTo-Json`;
  const result = await execPowerShell(cmd);

  const processes = JSON.parse(result);
  return Array.isArray(processes) ? processes.map((p: any) => ({
    name: p.Name || 'Unknown',
    id: p.Id || 0,
    ramMB: p.RAM_MB || 0,
    cpu: Math.round(p.CPU || 0),
    path: p.Path || 'N/A',
  })) : [];
}

export async function killProcess(pid: number): Promise<boolean> {
  const safePid = Math.floor(Number(pid));
  if (!Number.isFinite(safePid) || safePid < 0 || safePid > 999999) return false;
  try {
    execSync(`taskkill /F /PID ${safePid}`, { windowsHide: true });
    console.log(`✓ Process ${pid} killed`);
    return true;
  } catch (error: any) {
    console.error(`Error killing process ${pid}:`, error);
    return false;
  }
}

export async function getStartupPrograms(): Promise<StartupProgram[]> {
  const cmd = `Get-WmiObject Win32_StartupCommand | Select-Object Name,Command,Location | ConvertTo-Json`;
  const result = await execPowerShell(cmd);

  const programs = JSON.parse(result);
  const programArray = Array.isArray(programs) ? programs : [programs];

  return programArray.map((p: any) => {
    let impact: 'Low' | 'Medium' | 'High' = 'Low';
    const cmd = (p.Command || '').toLowerCase();

    if (cmd.includes('chrome') || cmd.includes('discord') || cmd.includes('spotify')) {
      impact = 'High';
    } else if (cmd.includes('steam') || cmd.includes('epic')) {
      impact = 'Medium';
    }

    return {
      name: p.Name || 'Unknown',
      command: p.Command || '',
      location: p.Location || '',
      impact,
    };
  });
}

export async function disableStartupProgram(name: string): Promise<boolean> {
  try {
    const safeName = sanitizePSArg(name);
    if (!safeName) return false;
    const cmd = `Disable-ScheduledTask -TaskName "${safeName}" -ErrorAction SilentlyContinue`;
    await execPowerShell(cmd);
    console.log(`✓ Startup program disabled: ${safeName}`);
    return true;
  } catch (error: any) {
    console.error(`Error disabling startup program ${name}:`, error);
    return false;
  }
}

export async function enableStartupProgram(name: string, command?: string): Promise<boolean> {
  try {
    const safeName = sanitizePSArg(name);
    if (!safeName) return false;
    const enableCmd = `Enable-ScheduledTask -TaskName "${safeName}" -ErrorAction SilentlyContinue`;
    await execPowerShell(enableCmd);

    // If the scheduled task enabling did nothing and a command is provided,
    // fall back to creating a registry Run entry for the current user.
    if (command && command.trim().length > 0) {
      const safeCommand = sanitizePSArg(command);
      const regCmd = `New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '${safeName}' -Value '${safeCommand}' -PropertyType String -Force`;
      await execPowerShell(regCmd);
    }

    console.log(`✓ Startup program enabled: ${safeName}`);
    return true;
  } catch (error: any) {
    console.error(`Error enabling startup program ${name}:`, error);
    return false;
  }
}
