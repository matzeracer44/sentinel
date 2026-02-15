import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';

const CONFIG_PATH = path.join(app.getPath('userData'), 'sentinelConfig.json');
const DEFAULT_CONFIG: SentinelConfig = {
  autonomousMode: false,
  whitelist: ['8.8.8.8', '1.1.1.1'],
  allowExternalIpLookup: true,
};

export interface SentinelConfig {
  autonomousMode: boolean;
  whitelist: string[];
  allowExternalIpLookup: boolean;
}

let cachedConfig: SentinelConfig | null = null;
let loaded = false;

function ensureConfig(): void {
  if (loaded) {
    return;
  }
  loaded = true;
  try {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf-8');
    cachedConfig = normalizeConfig(JSON.parse(raw));
  } catch (error) {
    cachedConfig = { ...DEFAULT_CONFIG };
    try {
      fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(cachedConfig, null, 2));
    } catch (writeErr) {
      console.warn('[SentinelConfig] Failed to persist default config:', writeErr);
    }
  }
}

function normalizeConfig(input: Partial<SentinelConfig> | null): SentinelConfig {
  return {
    autonomousMode: Boolean(input?.autonomousMode),
    whitelist: Array.isArray(input?.whitelist) && input!.whitelist!.length
      ? Array.from(new Set(input!.whitelist!.map((ip) => String(ip).trim()).filter(Boolean)))
      : [...DEFAULT_CONFIG.whitelist],
    allowExternalIpLookup: input?.allowExternalIpLookup !== undefined ? Boolean(input.allowExternalIpLookup) : DEFAULT_CONFIG.allowExternalIpLookup,
  };
}

export function getSentinelConfig(): SentinelConfig {
  ensureConfig();
  return cachedConfig!;
}

export function isAutonomousModeEnabled(): boolean {
  return getSentinelConfig().autonomousMode;
}

export function updateAutonomousMode(enabled: boolean): SentinelConfig {
  ensureConfig();
  cachedConfig = {
    ...(cachedConfig ?? DEFAULT_CONFIG),
    autonomousMode: Boolean(enabled),
  };
  persistConfig();
  return cachedConfig;
}

export function addWhitelistEntry(ip: string): SentinelConfig {
  ensureConfig();
  const clean = ip.trim();
  if (!clean) return cachedConfig!;
  if (!cachedConfig!.whitelist.includes(clean)) {
    cachedConfig!.whitelist.push(clean);
    persistConfig();
  }
  return cachedConfig!;
}

export function removeWhitelistEntry(ip: string): SentinelConfig {
  ensureConfig();
  const clean = ip.trim();
  if (!clean) return cachedConfig!;
  const idx = cachedConfig!.whitelist.indexOf(clean);
  if (idx !== -1) {
    cachedConfig!.whitelist.splice(idx, 1);
    persistConfig();
  }
  return cachedConfig!;
}

export function setWhitelist(ips: string[]): SentinelConfig {
  ensureConfig();
  cachedConfig!.whitelist = Array.from(new Set(ips.map((ip) => ip.trim()).filter(Boolean)));
  persistConfig();
  return cachedConfig!;
}

export function isExternalIpLookupAllowed(): boolean {
  return getSentinelConfig().allowExternalIpLookup;
}

export function setExternalIpLookup(enabled: boolean): SentinelConfig {
  ensureConfig();
  cachedConfig = {
    ...(cachedConfig ?? DEFAULT_CONFIG),
    allowExternalIpLookup: Boolean(enabled),
  };
  persistConfig();
  return cachedConfig;
}

export function reloadConfig(): SentinelConfig {
  loaded = false;
  cachedConfig = null;
  ensureConfig();
  return cachedConfig!;
}

function persistConfig(): void {
  try {
    fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(cachedConfig, null, 2));
  } catch (error) {
    console.error('[SentinelConfig] Failed to save configuration:', error);
  }
}
