import { exec } from 'child_process';
import { promisify } from 'util';
import { app } from 'electron';
import { getExecOptions } from './execOptions';

const execPromise = promisify(exec);

/**
 * Check if the application is running with administrator privileges
 * Compatible with all Windows language versions and Restricted ExecutionPolicy
 */
export async function checkIsAdmin(): Promise<boolean> {
  try {
    // Method 1: Use PowerShell with ExecutionPolicy Bypass
    const command = `powershell -ExecutionPolicy Bypass -Command "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"`;

    const { stdout } = await execPromise(command, getExecOptions());
    const result = stdout.trim().toLowerCase();
    const isAdmin = result === 'true';

    console.log(`Admin status: ${isAdmin} (output: ${result})`);
    return isAdmin;
  } catch (error) {
    console.error('Error checking admin status:', error);

    // Fallback method: Try using net session (works on all Windows versions/languages)
    try {
      await execPromise('net session', { timeout: 10000, maxBuffer: 1024 * 1024 });
      // If net session succeeds, user is admin
      console.log('Admin status: true (via net session)');
      return true;
    } catch {
      // If net session fails, user is not admin
      console.log('Admin status: false (via net session)');
      return false;
    }
  }
}

/**
 * Restart the application with administrator privileges
 * Uses PowerShell Start-Process with -Verb RunAs to trigger UAC prompt
 */
export async function requestElevation(): Promise<{ success: boolean; message: string }> {
  try {
    const appPath = process.execPath;
    const args = process.argv.slice(1).join(' ');

    // Use PowerShell with ExecutionPolicy Bypass to restart the app with admin rights
    const command = `powershell -ExecutionPolicy Bypass -Command "Start-Process '${appPath}' ${args ? `'-ArgumentList \\"${args}\\"'` : ''} -Verb RunAs"`;

    await execPromise(command, getExecOptions());

    // If successful, quit the current instance
    // The new elevated instance will start
    setTimeout(() => {
      app.quit();
    }, 500);

    return {
      success: true,
      message: 'Restarting with administrator privileges...',
    };
  } catch (error: any) {
    console.error('Error requesting elevation:', error);

    // User might have declined the UAC prompt
    if (error.message.includes('user declined')) {
      return {
        success: false,
        message: 'User declined administrator privileges',
      };
    }

    return {
      success: false,
      message: 'Failed to restart as administrator',
    };
  }
}

/**
 * Check if elevation is possible (Windows only)
 */
export function canElevate(): boolean {
  return process.platform === 'win32';
}
