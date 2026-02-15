/**
 * SENTINEL UNIFIED — Adaptive Exec Options
 *
 * Shared helper that provides PowerShell/child_process execution options
 * derived from the auto-detected performance profile. All services should
 * import getExecOptions() instead of defining their own hardcoded constants.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
const execFileAsync = promisify(execFile);

export interface ExecOpts {
  timeout: number;
  maxBuffer: number;
  encoding: BufferEncoding;
  windowsHide: boolean;
}

/**
 * Execute a PowerShell script safely using -Command (not -EncodedCommand).
 * Uses execFile (no shell) so multi-line scripts with special chars are safe.
 * -EncodedCommand is blocked by some security policies / AMSI / enterprise AV.
 */
export async function runPowerShellSafe(
  script: string,
  opts?: Partial<ExecOpts>,
): Promise<string> {
  const defaults = getExecOptions();
  const merged = { ...defaults, ...opts };
  const { stdout } = await execFileAsync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    {
      timeout: merged.timeout,
      maxBuffer: merged.maxBuffer,
      encoding: merged.encoding,
      windowsHide: merged.windowsHide,
    },
  );
  return (stdout || '').trim();
}

export function getExecOptions(): ExecOpts {
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
  return {
    timeout,
    maxBuffer,
    encoding: 'utf8' as BufferEncoding,
    windowsHide: true,
  };
}
