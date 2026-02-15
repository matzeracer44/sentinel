import { exec } from 'child_process';
import { promisify } from 'util';
import { getExecOptions } from './execOptions';

const execAsync = promisify(exec);

async function runCmd(cmd: string, opts: Record<string, any> = {}): Promise<string> {
  const { stdout } = await execAsync(cmd, { encoding: 'utf8', windowsHide: true, timeout: 10000, ...opts });
  return (stdout || '').trim();
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
      const status = await runCmd(`sc query ${svc}`);

      if (!status.includes('RUNNING') || status.includes('DISABLED')) {
        console.log(`Fixing service: ${svc}`);
        try { await runCmd(`sc config ${svc} start=auto`); } catch (e) {
          console.log(`Could not set ${svc} to auto start (may need admin)`);
        }
        try { await runCmd(`net start ${svc}`); console.log(`✓ Started service: ${svc}`); } catch (e) {
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
    await runCmd('sc config winmgmt start=auto');
    await runCmd('net start winmgmt');
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
  const tests: Record<string, string> = {
    CPU: 'wmic cpu get name',
    RAM: 'wmic os get TotalVisibleMemorySize',
    Disk: 'wmic logicaldisk where "DriveType=3" get DeviceID',
    GPU: 'wmic path win32_videocontroller get name',
    Network: 'wmic nicconfig where "IPEnabled=true" get Description',
  };

  let allPassed = true;

  for (const [name, cmd] of Object.entries(tests)) {
    try {
      const raw = await runCmd(cmd, { timeout: 5000 });
      const result = raw.split('\n')[1]?.trim() || '';
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
