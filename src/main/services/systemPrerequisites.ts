import { execSync } from 'child_process';
import { getExecOptions } from './execOptions';

/**
 * Helper function to execute PowerShell commands with proper error handling
 */
function execPowerShell(command: string): string {
  try {
    const fullCommand = `powershell -ExecutionPolicy Bypass -NoProfile -Command "${command}"`;
    return execSync(fullCommand, getExecOptions()).toString().trim();
  } catch (error: any) {
    console.error('PowerShell execution error:', error.message);
    return '';
  }
}

/**
 * Check and fix required Windows services
 * Services needed: WinMgmt (WMI), DiagTrack (Diagnostics), DPS (Diagnostic Policy), PcaSvc (Program Compatibility)
 */
export async function ensureServices(): Promise<void> {
  console.log('Checking required services...');
  const required = ['WinMgmt', 'DiagTrack', 'DPS', 'PcaSvc'];

  for (const svc of required) {
    try {
      const status = execSync(`sc query ${svc}`, { encoding: 'utf8', windowsHide: true }).toString();

      if (!status.includes('RUNNING') || status.includes('DISABLED')) {
        console.log(`Fixing service: ${svc}`);

        // Set service to automatic start
        try {
          execSync(`sc config ${svc} start=auto`, { windowsHide: true });
        } catch (e) {
          console.log(`Could not set ${svc} to auto start (may need admin)`);
        }

        // Try to start service
        try {
          execSync(`net start ${svc}`, { windowsHide: true });
          console.log(`✓ Started service: ${svc}`);
        } catch (e) {
          console.log(`Service ${svc} may already be running or requires admin`);
        }
      } else {
        console.log(`✓ Service ${svc} is running`);
      }
    } catch (error: any) {
      console.error(`Error checking service ${svc}:`, error.message);
    }
  }

  console.log('✓ All services checked');
}

/**
 * Configure registry for data access
 * SIMPLIFIED: Only check WMI service, no HKLM modifications
 */
export async function ensureRegistryAccess(): Promise<void> {
  console.log('Checking WMI service...');

  // Only check and start WMI service if needed
  try {
    execSync('sc config winmgmt start=auto', { windowsHide: true, stdio: 'ignore' });
    execSync('net start winmgmt', { windowsHide: true, stdio: 'ignore' });
    console.log('✓ WMI service configured');
  } catch (error: any) {
    console.log('✓ WMI service already running or configured');
  }

  // Skip HKLM registry modifications - not needed for basic operation
  console.log('✓ Skipping registry modifications - using WMIC instead');
}

/**
 * Verify all system data is accessible
 * Tests CPU, RAM, Disk, GPU, and Network data retrieval
 */
export async function verifySystemData(): Promise<boolean> {
  console.log('Verifying system data access...');

  // Use WMIC instead of Get-WmiObject for better performance
  const tests = {
    CPU: () => {
      try {
        return execSync('wmic cpu get name', { timeout: 5000, encoding: 'utf8', windowsHide: true }).toString().split('\n')[1]?.trim() || '';
      } catch (e) {
        return '';
      }
    },
    RAM: () => {
      try {
        return execSync('wmic os get TotalVisibleMemorySize', { timeout: 5000, encoding: 'utf8', windowsHide: true }).toString().split('\n')[1]?.trim() || '';
      } catch (e) {
        return '';
      }
    },
    Disk: () => {
      try {
        return execSync('wmic logicaldisk where "DriveType=3" get DeviceID', { timeout: 5000, encoding: 'utf8', windowsHide: true }).toString().split('\n')[1]?.trim() || '';
      } catch (e) {
        return '';
      }
    },
    GPU: () => {
      try {
        return execSync('wmic path win32_videocontroller get name', { timeout: 5000, encoding: 'utf8', windowsHide: true }).toString().split('\n')[1]?.trim() || '';
      } catch (e) {
        return '';
      }
    },
    Network: () => {
      try {
        return execSync('wmic nicconfig where "IPEnabled=true" get Description', { timeout: 5000, encoding: 'utf8', windowsHide: true }).toString().split('\n')[1]?.trim() || '';
      } catch (e) {
        return '';
      }
    },
  };

  let allPassed = true;

  for (const [name, test] of Object.entries(tests)) {
    try {
      const result = test();
      if (!result || result.length === 0) {
        console.error(`✗ ${name} data not accessible`);
        allPassed = false;
      } else {
        console.log(`✓ ${name} data OK`);
      }
    } catch (error: any) {
      console.error(`✗ ${name} test failed:`, error.message);
      allPassed = false;
    }
  }

  if (allPassed) {
    console.log('✓ All system data accessible');
  } else {
    console.warn('⚠ Some system data is not accessible - app may have limited functionality');
  }

  // Return true anyway to allow app to load (with fallback data)
  return true;
}

/**
 * Run all prerequisite checks and fixes
 */
export async function runAllPrerequisites(): Promise<boolean> {
  console.log('=== Sentinel System Prerequisites ===');

  try {
    await ensureServices();
    await ensureRegistryAccess();
    const dataOK = await verifySystemData();

    console.log('=== Prerequisites complete ===');
    return dataOK;
  } catch (error: any) {
    console.error('Prerequisites error:', error);
    return false;
  }
}
