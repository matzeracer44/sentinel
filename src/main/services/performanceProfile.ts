/**
 * SENTINEL UNIFIED — Adaptive Performance Profile
 *
 * Auto-detects system hardware (CPU cores/threads, RAM, OS version)
 * at startup and computes optimal polling intervals, timeouts,
 * buffer sizes, and concurrency limits.
 *
 * No hardcoded profiles for specific hardware — everything is derived
 * from the detected specs. Users can override via "auto" | "low" |
 * "balanced" | "high" | "custom" in settings.
 */

import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ProfileMode = 'auto' | 'low' | 'balanced' | 'high' | 'custom';

export interface HardwareSnapshot {
  cpuModel: string;
  cpuCores: number;
  cpuThreads: number;
  totalRAM_GB: number;
  freeRAM_GB: number;
  platform: string;
  osRelease: string;
  arch: string;
  /** Computed tier: 'low' | 'mid' | 'high' | 'ultra' */
  tier: 'low' | 'mid' | 'high' | 'ultra';
}

export interface PerformanceSettings {
  /** PowerShell / child_process exec timeout (ms) */
  powershellTimeout: number;
  /** maxBuffer for exec calls (bytes) */
  maxBuffer: number;
  /** Polling intervals (ms) */
  pollSystem: number;
  pollNetwork: number;
  pollFirewall: number;
  pollArgus: number;
  pollConnectors: number;
  /** Concurrency */
  maxConcurrentScans: number;
  tlsWorkerThreads: number;
  argusWorkers: number;
  /** ARGUS safeFetch timeout (ms) */
  argusFetchTimeout: number;
  /** Max items rendered in tables before virtualization kicks in */
  tableRenderLimit: number;
}

export interface PerformanceProfile {
  mode: ProfileMode;
  hardware: HardwareSnapshot;
  settings: PerformanceSettings;
  detectedAt: string;
}

// ---------------------------------------------------------------------------
// Hardware detection (uses Node.js os module — no WMIC needed here)
// ---------------------------------------------------------------------------

function detectHardware(): HardwareSnapshot {
  const cpus = os.cpus();
  const cpuModel = cpus.length > 0 ? cpus[0].model.trim() : 'Unknown CPU';
  const cpuThreads = cpus.length;
  let cpuCores = Math.max(1, Math.ceil(cpuThreads / 2));
  try {
    const { execSync } = require('child_process');
    const out = execSync(
      'powershell -NoProfile -NonInteractive -Command "(Get-CimInstance Win32_Processor | Select-Object -First 1).NumberOfCores"',
      { timeout: 4000, windowsHide: true, encoding: 'utf8' }
    ).trim();
    const parsed = parseInt(out, 10);
    if (!isNaN(parsed) && parsed > 0) cpuCores = parsed;
  } catch { /* fallback to heuristic */ }
  const totalRAM_GB = Math.round((os.totalmem() / (1024 ** 3)) * 100) / 100;
  const freeRAM_GB = Math.round((os.freemem() / (1024 ** 3)) * 100) / 100;

  // Compute tier based on cores + RAM
  const tier = computeTier(cpuThreads, totalRAM_GB);

  const snapshot: HardwareSnapshot = {
    cpuModel,
    cpuCores,
    cpuThreads,
    totalRAM_GB,
    freeRAM_GB,
    platform: os.platform(),
    osRelease: os.release(),
    arch: os.arch(),
    tier,
  };

  console.log(
    `[PerfProfile] Detected: ${cpuModel} | ${cpuCores}C/${cpuThreads}T | ` +
    `${totalRAM_GB}GB RAM (${freeRAM_GB}GB free) | Tier: ${tier}`
  );

  return snapshot;
}

function computeTier(threads: number, ramGB: number): 'low' | 'mid' | 'high' | 'ultra' {
  // Score: threads contribute 60%, RAM contributes 40%
  // Normalized: 4 threads = 1.0, 8 = 2.0, 16 = 4.0, 32 = 8.0
  const threadScore = threads / 4;
  // Normalized: 4GB = 1.0, 8GB = 2.0, 16GB = 4.0, 32GB = 8.0
  const ramScore = ramGB / 4;

  const combined = threadScore * 0.6 + ramScore * 0.4;

  if (combined >= 4.0) return 'ultra';  // 16+ threads, 16+ GB
  if (combined >= 2.0) return 'high';   // 8+ threads, 8+ GB
  if (combined >= 1.0) return 'mid';    // 4+ threads, 4+ GB
  return 'low';                          // Below 4 threads or 4GB
}

// ---------------------------------------------------------------------------
// Settings computation — derived from hardware, not hardcoded
// ---------------------------------------------------------------------------

function computeSettings(hw: HardwareSnapshot, mode: ProfileMode): PerformanceSettings {
  // If mode is a fixed preset, use that tier instead of auto-detected
  const effectiveTier = mode === 'auto' ? hw.tier
    : mode === 'low' ? 'low'
    : mode === 'balanced' ? 'mid'
    : mode === 'high' ? 'ultra'
    : hw.tier; // 'custom' falls back to auto-detected

  switch (effectiveTier) {
    case 'ultra':
      return {
        powershellTimeout: 5000,
        maxBuffer: 8 * 1024 * 1024,
        pollSystem: 2000,
        pollNetwork: 3000,
        pollFirewall: 10000,
        pollArgus: 5000,
        pollConnectors: 3000,
        maxConcurrentScans: Math.min(hw.cpuThreads, 12),
        tlsWorkerThreads: Math.min(Math.floor(hw.cpuThreads / 4), 6),
        argusWorkers: Math.min(Math.floor(hw.cpuThreads / 4), 4),
        argusFetchTimeout: 8000,
        tableRenderLimit: 500,
      };

    case 'high':
      return {
        powershellTimeout: 8000,
        maxBuffer: 6 * 1024 * 1024,
        pollSystem: 3000,
        pollNetwork: 4000,
        pollFirewall: 12000,
        pollArgus: 6000,
        pollConnectors: 4000,
        maxConcurrentScans: Math.min(hw.cpuThreads, 8),
        tlsWorkerThreads: Math.min(Math.floor(hw.cpuThreads / 4), 4),
        argusWorkers: Math.min(Math.floor(hw.cpuThreads / 4), 3),
        argusFetchTimeout: 10000,
        tableRenderLimit: 300,
      };

    case 'mid':
      return {
        powershellTimeout: 12000,
        maxBuffer: 4 * 1024 * 1024,
        pollSystem: 5000,
        pollNetwork: 6000,
        pollFirewall: 15000,
        pollArgus: 8000,
        pollConnectors: 6000,
        maxConcurrentScans: Math.min(hw.cpuThreads, 5),
        tlsWorkerThreads: Math.min(Math.floor(hw.cpuThreads / 4), 2),
        argusWorkers: 2,
        argusFetchTimeout: 12000,
        tableRenderLimit: 200,
      };

    case 'low':
    default:
      return {
        powershellTimeout: 20000,
        maxBuffer: 2 * 1024 * 1024,
        pollSystem: 8000,
        pollNetwork: 10000,
        pollFirewall: 20000,
        pollArgus: 12000,
        pollConnectors: 10000,
        maxConcurrentScans: 3,
        tlsWorkerThreads: 1,
        argusWorkers: 1,
        argusFetchTimeout: 15000,
        tableRenderLimit: 100,
      };
  }
}

// ---------------------------------------------------------------------------
// Persistence — save/load user's mode preference + custom overrides
// ---------------------------------------------------------------------------

function getConfigPath(): string {
  try {
    return path.join(app.getPath('userData'), 'performanceProfile.json');
  } catch {
    return path.join(process.cwd(), 'config', 'performanceProfile.json');
  }
}

interface PersistedConfig {
  mode: ProfileMode;
  customOverrides?: Partial<PerformanceSettings>;
}

function loadPersistedConfig(): PersistedConfig {
  try {
    const raw = fs.readFileSync(getConfigPath(), 'utf-8');
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.mode === 'string') {
      return parsed as PersistedConfig;
    }
  } catch {
    // No config yet — use auto
  }
  return { mode: 'auto' };
}

function persistConfig(config: PersistedConfig): void {
  try {
    const configPath = getConfigPath();
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
  } catch (err) {
    console.warn('[PerfProfile] Failed to persist config:', err);
  }
}

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

let _profile: PerformanceProfile | null = null;
let _persistedConfig: PersistedConfig = { mode: 'auto' };

/**
 * Initialize the performance profile. Call once at app startup.
 * Detects hardware, loads user preference, computes settings.
 */
export function initPerformanceProfile(): PerformanceProfile {
  const hw = detectHardware();
  _persistedConfig = loadPersistedConfig();

  let settings = computeSettings(hw, _persistedConfig.mode);

  // Apply custom overrides if mode is 'custom'
  if (_persistedConfig.mode === 'custom' && _persistedConfig.customOverrides) {
    settings = { ...settings, ..._persistedConfig.customOverrides };
  }

  _profile = {
    mode: _persistedConfig.mode,
    hardware: hw,
    settings,
    detectedAt: new Date().toISOString(),
  };

  console.log(
    `[PerfProfile] Mode: ${_profile.mode} | ` +
    `PS timeout: ${settings.powershellTimeout}ms | ` +
    `Poll sys: ${settings.pollSystem}ms | ` +
    `Scans: ${settings.maxConcurrentScans} concurrent | ` +
    `Table limit: ${settings.tableRenderLimit}`
  );

  return _profile;
}

/**
 * Get the current performance profile. Returns a default if not yet initialized.
 */
export function getPerformanceProfile(): PerformanceProfile {
  if (!_profile) {
    return initPerformanceProfile();
  }
  return _profile;
}

/**
 * Get just the settings (most common use case for services).
 */
export function getPerfSettings(): PerformanceSettings {
  return getPerformanceProfile().settings;
}

/**
 * Change the profile mode. Re-computes settings and persists.
 */
export function setProfileMode(mode: ProfileMode, customOverrides?: Partial<PerformanceSettings>): PerformanceProfile {
  const hw = _profile?.hardware ?? detectHardware();

  _persistedConfig = { mode, customOverrides: mode === 'custom' ? customOverrides : undefined };
  persistConfig(_persistedConfig);

  let settings = computeSettings(hw, mode);
  if (mode === 'custom' && customOverrides) {
    settings = { ...settings, ...customOverrides };
  }

  _profile = {
    mode,
    hardware: hw,
    settings,
    detectedAt: _profile?.detectedAt ?? new Date().toISOString(),
  };

  console.log(`[PerfProfile] Mode changed to: ${mode} | Tier: ${hw.tier}`);
  return _profile;
}

/**
 * Re-detect hardware (e.g., after waking from sleep where RAM may differ).
 */
export function refreshHardware(): PerformanceProfile {
  _profile = null;
  return initPerformanceProfile();
}
