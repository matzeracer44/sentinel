/**
 * SENTINEL — Central Environment / API Key Loader
 * Loads keys from .env file, process.env, or defaults.
 * Hot-reloads every 60 seconds. Never exposes keys to renderer.
 */

import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';

export interface EnvConfig {
  IPINFO_TOKEN: string;
  VIRUSTOTAL_API_KEY: string;
  ABUSEIPDB_API_KEY: string;
  SHODAN_API_KEY: string;
  MAXMIND_LICENSE_KEY: string;
}

const defaults: EnvConfig = {
  IPINFO_TOKEN: '',
  VIRUSTOTAL_API_KEY: '',
  ABUSEIPDB_API_KEY: '',
  SHODAN_API_KEY: '',
  MAXMIND_LICENSE_KEY: '',
};

let _config: EnvConfig | null = null;
let _lastLoad = 0;

function findEnvFile(): string | null {
  const candidates = [
    path.join(process.cwd(), '.env'),
    path.join(app.getAppPath(), '.env'),
    path.join(app.getPath('userData'), '.env'),
  ];
  for (const p of candidates) {
    try { if (fs.existsSync(p)) return p; } catch { /* skip */ }
  }
  return null;
}

function parseEnvFile(filePath: string): Partial<EnvConfig> {
  const content = fs.readFileSync(filePath, 'utf-8');
  const result: Record<string, string> = {};

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    const key = trimmed.slice(0, eqIndex).trim();
    let value = trimmed.slice(eqIndex + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }

  return result as Partial<EnvConfig>;
}

/** Load all env config, cached for 60s with hot-reload. */
export function loadEnv(): EnvConfig {
  if (_config && Date.now() - _lastLoad < 60000) return _config;

  const envFile = findEnvFile();
  const fileVars = envFile ? parseEnvFile(envFile) : {};

  _config = { ...defaults };
  for (const key of Object.keys(defaults) as (keyof EnvConfig)[]) {
    if (fileVars[key]) _config[key] = fileVars[key]!;
    else if (process.env[key]) _config[key] = process.env[key]!;
  }

  _lastLoad = Date.now();
  return _config;
}

/** Get a single API key by name. */
export function getApiKey(key: keyof EnvConfig): string {
  return loadEnv()[key] || '';
}

/** Check if a key is actually configured (not empty / not placeholder). */
export function hasApiKey(key: keyof EnvConfig): boolean {
  const val = getApiKey(key);
  return val !== '' && val !== 'your_token_here' && val !== 'your_key_here';
}
