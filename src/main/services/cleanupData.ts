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

export interface CleanupData {
  tempSizeGB: number;
  windowsOldSizeGB: number;
  downloadSizeGB: number;
  recycleBinSizeGB: number;
  browserCacheSizeGB: number;
  totalCleanableGB: number;
}

/**
 * Get cleanup data showing reclaimable disk space
 */
export async function getCleanupData(): Promise<CleanupData> {
  try {
    // Get temp folder size
    const tempCmd = `$size = (Get-ChildItem $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; if($size){[math]::Round($size / 1GB, 2)}else{0}`;
    const tempSizeStr = execPowerShell(tempCmd);
    const tempSizeGB = parseFloat(tempSizeStr) || 0;

    // Get Windows.old folder size
    const windowsOldCmd = `if(Test-Path C:\\Windows.old){$size = (Get-ChildItem C:\\Windows.old -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; [math]::Round($size / 1GB, 2)}else{0}`;
    const windowsOldSizeStr = execPowerShell(windowsOldCmd);
    const windowsOldSizeGB = parseFloat(windowsOldSizeStr) || 0;

    // Get Downloads folder size
    const downloadCmd = `$size = (Get-ChildItem $env:USERPROFILE\\Downloads -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; if($size){[math]::Round($size / 1GB, 2)}else{0}`;
    const downloadSizeStr = execPowerShell(downloadCmd);
    const downloadSizeGB = parseFloat(downloadSizeStr) || 0;

    // Get Recycle Bin size
    const recycleBinCmd = `$size = (Get-ChildItem 'C:\\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; if($size){[math]::Round($size / 1GB, 2)}else{0}`;
    const recycleBinSizeStr = execPowerShell(recycleBinCmd);
    const recycleBinSizeGB = parseFloat(recycleBinSizeStr) || 0;

    // Get browser cache size (Chrome, Edge, Firefox)
    const browserCacheCmd = `
      $total = 0;
      $paths = @(
        "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Cache",
        "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Cache",
        "$env:APPDATA\\Mozilla\\Firefox\\Profiles"
      );
      foreach($path in $paths){
        if(Test-Path $path){
          $size = (Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum;
          if($size){$total += $size}
        }
      }
      [math]::Round($total / 1GB, 2)
    `;
    const browserCacheSizeStr = execPowerShell(browserCacheCmd);
    const browserCacheSizeGB = parseFloat(browserCacheSizeStr) || 0;

    const totalCleanableGB = tempSizeGB + windowsOldSizeGB + recycleBinSizeGB + browserCacheSizeGB;

    return {
      tempSizeGB,
      windowsOldSizeGB,
      downloadSizeGB,
      recycleBinSizeGB,
      browserCacheSizeGB,
      totalCleanableGB,
    };
  } catch (error: any) {
    console.error('Error getting cleanup data:', error);
    return {
      tempSizeGB: 0,
      windowsOldSizeGB: 0,
      downloadSizeGB: 0,
      recycleBinSizeGB: 0,
      browserCacheSizeGB: 0,
      totalCleanableGB: 0,
    };
  }
}

/**
 * Clean temporary files
 */
export async function cleanTemp(): Promise<boolean> {
  try {
    console.log('Cleaning temp files...');

    // Clean user temp
    execPowerShell('Remove-Item $env:TEMP\\* -Recurse -Force -ErrorAction SilentlyContinue');

    // Clean Windows temp
    execPowerShell('Remove-Item C:\\Windows\\Temp\\* -Recurse -Force -ErrorAction SilentlyContinue');

    // Clean prefetch
    execPowerShell('Remove-Item C:\\Windows\\Prefetch\\* -Force -ErrorAction SilentlyContinue');

    console.log('✓ Temp files cleaned');
    return true;
  } catch (error: any) {
    console.error('Error cleaning temp files:', error);
    return false;
  }
}

/**
 * Clean Windows.old folder
 */
export async function cleanWindowsOld(): Promise<boolean> {
  try {
    console.log('Cleaning Windows.old...');
    execPowerShell('if(Test-Path C:\\Windows.old){Remove-Item C:\\Windows.old -Recurse -Force -ErrorAction SilentlyContinue}');
    console.log('✓ Windows.old cleaned');
    return true;
  } catch (error: any) {
    console.error('Error cleaning Windows.old:', error);
    return false;
  }
}

/**
 * Empty Recycle Bin
 */
export async function emptyRecycleBin(): Promise<boolean> {
  try {
    console.log('Emptying Recycle Bin...');
    execPowerShell('Clear-RecycleBin -Force -ErrorAction SilentlyContinue');
    console.log('✓ Recycle Bin emptied');
    return true;
  } catch (error: any) {
    console.error('Error emptying Recycle Bin:', error);
    return false;
  }
}

/**
 * Clean browser caches
 */
export async function cleanBrowserCache(): Promise<boolean> {
  try {
    console.log('Cleaning browser caches...');

    // Clean Chrome cache
    execPowerShell('Remove-Item "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Cache\\*" -Recurse -Force -ErrorAction SilentlyContinue');

    // Clean Edge cache
    execPowerShell('Remove-Item "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Cache\\*" -Recurse -Force -ErrorAction SilentlyContinue');

    // Clean Firefox cache
    execPowerShell('Get-ChildItem "$env:APPDATA\\Mozilla\\Firefox\\Profiles" -Directory -ErrorAction SilentlyContinue | ForEach-Object {Remove-Item "$($_.FullName)\\cache2\\*" -Recurse -Force -ErrorAction SilentlyContinue}');

    console.log('✓ Browser caches cleaned');
    return true;
  } catch (error: any) {
    console.error('Error cleaning browser caches:', error);
    return false;
  }
}

/**
 * Run Disk Cleanup utility
 */
export async function runDiskCleanup(): Promise<boolean> {
  try {
    console.log('Running Disk Cleanup...');
    execSync('cleanmgr /sagerun:1', { windowsHide: true });
    console.log('✓ Disk Cleanup started');
    return true;
  } catch (error: any) {
    console.error('Error running Disk Cleanup:', error);
    return false;
  }
}

/**
 * Clean all at once
 */
export async function cleanAll(): Promise<{
  temp: boolean;
  windowsOld: boolean;
  recycleBin: boolean;
  browserCache: boolean;
}> {
  const results = {
    temp: await cleanTemp(),
    windowsOld: await cleanWindowsOld(),
    recycleBin: await emptyRecycleBin(),
    browserCache: await cleanBrowserCache(),
  };

  return results;
}
