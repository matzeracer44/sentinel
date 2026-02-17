/**
 * SENTINEL — Adaptive Access Control (Zero Trust / NIST SP 1800-35)
 * When system health score drops below threshold, restricts network to prevent exfiltration.
 * Monitors health score periodically and applies graduated response.
 * Reversible — auto-lifts restrictions when health recovers.
 */

import { app } from 'electron';
import * as fs from 'fs';
import * as path from 'path';
import { addActivityLog } from './activityLog';

export interface AdaptiveAccessConfig {
  enabled: boolean;
  healthThreshold: number;
  pollIntervalMs: number;
  autoRestrict: boolean;
}

export interface AdaptiveAccessState {
  restricted: boolean;
  lastHealthScore: number | null;
  lastCheckAt: string | null;
  restrictedSince: string | null;
  liftedAt: string | null;
}

let _cfg: AdaptiveAccessConfig = {
  enabled: false,
  healthThreshold: 40,
  pollIntervalMs: 60_000,
  autoRestrict: false,
};

let _state: AdaptiveAccessState = {
  restricted: false,
  lastHealthScore: null,
  lastCheckAt: null,
  restrictedSince: null,
  liftedAt: null,
};

let _pollTimer: ReturnType<typeof setInterval> | null = null;
let _getHealthScore: (() => Promise<number>) | null = null;
let _applyRestriction: ((restrict: boolean) => Promise<void>) | null = null;

function cfgPath(): string { return path.join(app.getPath('userData'), 'adaptive-access.json'); }

function loadCfg(): void {
  try {
    const p = cfgPath();
    if (fs.existsSync(p)) _cfg = { ..._cfg, ...JSON.parse(fs.readFileSync(p, 'utf8')) };
  } catch { /* first run */ }
}

function saveCfg(): void {
  try {
    const dir = path.dirname(cfgPath());
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(cfgPath(), JSON.stringify(_cfg, null, 2), 'utf8');
  } catch { /* non-fatal */ }
}

async function restrictNetwork(): Promise<void> {
  if (_applyRestriction) {
    await _applyRestriction(true);
  } else {
    try {
      const { execSync } = require('child_process');
      execSync(
        'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound',
        { windowsHide: true, timeout: 10000 }
      );
    } catch (e: any) {
      console.warn('[AdaptiveAccess] Restriction failed:', e?.message);
    }
  }
  _state.restricted = true;
  _state.restrictedSince = new Date().toISOString();
  addActivityLog('AdaptiveAccess', 'Restrict', `Network restricted — health score ${_state.lastHealthScore}% below threshold ${_cfg.healthThreshold}%`, 'error');
}

async function liftRestriction(): Promise<void> {
  if (_applyRestriction) {
    await _applyRestriction(false);
  } else {
    try {
      const { execSync } = require('child_process');
      execSync(
        'netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound',
        { windowsHide: true, timeout: 10000 }
      );
    } catch (e: any) {
      console.warn('[AdaptiveAccess] Lift failed:', e?.message);
    }
  }
  _state.restricted = false;
  _state.liftedAt = new Date().toISOString();
  addActivityLog('AdaptiveAccess', 'Lift', `Restriction lifted — health score recovered to ${_state.lastHealthScore}%`, 'success');
}

async function pollHealth(): Promise<void> {
  if (!_cfg.enabled || !_getHealthScore) return;

  try {
    const score = await _getHealthScore();
    _state.lastHealthScore = score;
    _state.lastCheckAt = new Date().toISOString();

    if (score < _cfg.healthThreshold && !_state.restricted && _cfg.autoRestrict) {
      await restrictNetwork();
    } else if (score >= _cfg.healthThreshold + 10 && _state.restricted) {
      await liftRestriction();
    }
  } catch (e: any) {
    console.warn('[AdaptiveAccess] Poll error:', e?.message);
  }
}

export function initAdaptiveAccess(
  healthScoreFn: () => Promise<number>,
  restrictFn?: (restrict: boolean) => Promise<void>
): void {
  loadCfg();
  _getHealthScore = healthScoreFn;
  if (restrictFn) _applyRestriction = restrictFn;

  if (_cfg.enabled) startPolling();
  console.log(`[AdaptiveAccess] Init — enabled=${_cfg.enabled}, threshold=${_cfg.healthThreshold}%`);
}

function startPolling(): void {
  if (_pollTimer) clearInterval(_pollTimer);
  _pollTimer = setInterval(() => pollHealth(), _cfg.pollIntervalMs);
}

export function stopAdaptiveAccess(): void {
  if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
}

export function getAdaptiveConfig(): AdaptiveAccessConfig { return { ..._cfg }; }

export function setAdaptiveConfig(update: Partial<AdaptiveAccessConfig>): AdaptiveAccessConfig {
  const wasEnabled = _cfg.enabled;
  _cfg = { ..._cfg, ...update };
  saveCfg();
  if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
  if (_cfg.enabled) startPolling();
  if (update.enabled !== undefined && update.enabled !== wasEnabled) {
    addActivityLog('AdaptiveAccess', update.enabled ? 'Aktiviert' : 'Deaktiviert',
      update.enabled
        ? `Adaptiver Zugriffsschutz aktiviert — Schwellenwert ${_cfg.healthThreshold}%, Intervall ${Math.round(_cfg.pollIntervalMs / 1000)}s`
        : 'Adaptiver Zugriffsschutz deaktiviert',
      update.enabled ? 'success' : 'warning');
  }
  return { ..._cfg };
}

export function getAdaptiveState(): AdaptiveAccessState { return { ..._state }; }

export async function manualRestrict(): Promise<{ success: boolean }> {
  await restrictNetwork();
  return { success: true };
}

export async function manualLift(): Promise<{ success: boolean }> {
  await liftRestriction();
  return { success: true };
}
