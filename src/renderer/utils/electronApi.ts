/**
 * SENTINEL UNIFIED — Electron API Bridge
 * Type-safe accessor for window.electronAPI exposed by preload.
 * All renderer pages import this instead of casting window directly.
 */

export interface ElectronApiProxy {
  // Top-level
  getSystemHealth: Function;
  getSystemStats: Function;
  getActivityLog: Function;
  clearActivityLog: Function;
  executeQuickAction: Function;
  getRealSystemData: Function;
  saveSettings: Function;
  getSettings: Function;
  toggleDevTools: Function;

  // Shield cluster
  shield: Record<string, Function>;

  // Ghost (DNS/Privacy)
  ghost: Record<string, Function>;

  // Forge (System/Performance)
  forge: Record<string, Function>;

  // Admin
  admin: Record<string, Function>;

  // Vault
  vault: Record<string, Function>;

  // ARGUS
  argus: Record<string, Function>;

  // Sentinel Config
  sentinelConfig: Record<string, Function>;

  // Renderer management
  renderer: Record<string, Function>;

  // Catch-all for dynamic access
  [key: string]: unknown;
}

let _cached: ElectronApiProxy | null = null;

export function getElectronApi(): ElectronApiProxy | null {
  if (_cached) return _cached;
  try {
    const w = window as unknown as Record<string, unknown>;
    if (w.electronAPI && typeof w.electronAPI === 'object') {
      _cached = w.electronAPI as unknown as ElectronApiProxy;
      return _cached;
    }
  } catch { /* not in Electron context */ }
  return null;
}

/** Shorthand: invoke a top-level electronAPI method safely */
export async function invokeApi<T = unknown>(method: string, ...args: unknown[]): Promise<T | null> {
  const api = getElectronApi();
  if (!api) return null;
  const fn = api[method];
  if (typeof fn === 'function') {
    return (fn as Function)(...args) as T;
  }
  return null;
}

/** Shorthand: invoke a nested electronAPI method safely (e.g. 'shield.getFirewallRules') */
export async function invokeNested<T = unknown>(path: string, ...args: unknown[]): Promise<T | null> {
  const api = getElectronApi();
  if (!api) return null;
  const parts = path.split('.');
  let target: unknown = api;
  for (const part of parts) {
    if (target && typeof target === 'object') {
      target = (target as Record<string, unknown>)[part];
    } else {
      return null;
    }
  }
  if (typeof target === 'function') {
    return (target as Function)(...args) as T;
  }
  return null;
}
