/**
 * SENTINEL — Fix Undo Store
 * Stores the state BEFORE each fix so it can be reverted.
 * Entries expire after 24 hours.
 * Born from a real incident: no undo was available after a fix killed internet.
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const EXEC_OPTIONS = { timeout: 15000, windowsHide: true, encoding: 'utf8' as const, maxBuffer: 4 * 1024 * 1024 };
const UNDO_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

export interface FixUndoEntry {
  checkId: string;
  checkName: string;
  appliedAt: number;
  expiresAt: number;
  undoCommand: string;
  undoDescription: string;
  affectsConnectivity: boolean;
}

const undoStore: Map<string, FixUndoEntry> = new Map();

/** Store an undo entry for a fix that was just applied. */
export function storeUndo(entry: FixUndoEntry): void {
  undoStore.set(entry.checkId, entry);
  // Schedule cleanup
  setTimeout(() => {
    const stored = undoStore.get(entry.checkId);
    if (stored && stored.appliedAt === entry.appliedAt) {
      undoStore.delete(entry.checkId);
    }
  }, UNDO_EXPIRY_MS);
}

/** Get a stored undo entry if it still exists and hasn't expired. */
export function getUndo(checkId: string): FixUndoEntry | null {
  const entry = undoStore.get(checkId);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    undoStore.delete(checkId);
    return null;
  }
  return entry;
}

/** Get all active undo entries. */
export function getAllUndos(): FixUndoEntry[] {
  const now = Date.now();
  const result: FixUndoEntry[] = [];
  for (const [key, entry] of undoStore) {
    if (now > entry.expiresAt) {
      undoStore.delete(key);
    } else {
      result.push(entry);
    }
  }
  return result;
}

/** Execute an undo by running the stored PowerShell command. */
export async function executeUndo(checkId: string): Promise<{ success: boolean; error?: string }> {
  const entry = getUndo(checkId);
  if (!entry) {
    return { success: false, error: 'No undo available for this fix (expired or not found).' };
  }
  if (!entry.undoCommand) {
    return { success: false, error: 'This fix has no automated undo command.' };
  }

  try {
    await execAsync(
      `powershell -ExecutionPolicy Bypass -NoProfile -Command "${entry.undoCommand.replace(/"/g, '\\"')}"`,
      EXEC_OPTIONS,
    );
    undoStore.delete(checkId);
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err?.message || 'Undo command failed' };
  }
}

/**
 * Post-fix connectivity check.
 * Runs after any fix that affects connectivity/firewall/DNS.
 * Returns internet + dns + firewall outbound status.
 */
export async function postFixConnectivityCheck(): Promise<{
  internet: boolean;
  dns: boolean;
  firewallOutbound: string;
}> {
  let internet = false;
  let dns = false;
  let firewallOutbound = 'unknown';

  // 1. Ping test (internet reachable?)
  try {
    const { stdout } = await execAsync('ping -n 1 -w 3000 8.8.8.8', { timeout: 5000, windowsHide: true, encoding: 'utf8' });
    internet = !stdout.includes('100%') && !stdout.includes('Fehler') && !stdout.includes('Request timed out');
  } catch { internet = false; }

  // 2. DNS test (name resolution works?)
  try {
    const { stdout } = await execAsync('nslookup google.com 8.8.8.8', { timeout: 5000, windowsHide: true, encoding: 'utf8' });
    dns = stdout.includes('Address') && !stdout.includes('UnKnown');
  } catch { dns = false; }

  // 3. Firewall outbound policy check
  try {
    const { stdout } = await execAsync(
      'powershell -NoProfile -Command "Get-NetFirewallProfile | Select-Object Name,DefaultOutboundAction | ConvertTo-Json -Compress"',
      { timeout: 5000, windowsHide: true, encoding: 'utf8' }
    );
    const profiles = JSON.parse(stdout.trim());
    const arr = Array.isArray(profiles) ? profiles : [profiles];
    const blocked = arr.some((p: any) => p.DefaultOutboundAction === 1 || p.DefaultOutboundAction === 'Block');
    firewallOutbound = blocked ? 'BLOCK' : 'ALLOW';
  } catch { firewallOutbound = 'unknown'; }

  return { internet, dns, firewallOutbound };
}

/**
 * Auto-revert a fix by running its undo command directly (not from store).
 * Used when connectivity check fails immediately after fix execution.
 */
export async function autoRevert(undoCommand: string): Promise<boolean> {
  if (!undoCommand) return false;
  try {
    await execAsync(
      `powershell -ExecutionPolicy Bypass -NoProfile -Command "${undoCommand.replace(/"/g, '\\"')}"`,
      EXEC_OPTIONS,
    );
    return true;
  } catch {
    return false;
  }
}
