/**
 * SENTINEL UNIFIED — Adaptive Exec Options
 *
 * Shared helper that provides PowerShell/child_process execution options
 * derived from the auto-detected performance profile. All services should
 * import getExecOptions() instead of defining their own hardcoded constants.
 */

export interface ExecOpts {
  timeout: number;
  maxBuffer: number;
  encoding: BufferEncoding;
  windowsHide: boolean;
}

/**
 * Returns adaptive execution options based on detected hardware.
 * Falls back to safe mid-tier defaults if the profile isn't initialized yet.
 */
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
