import { ClassicLevel } from 'classic-level';
import * as fs from 'fs';
import * as path from 'path';
import type { FirewallAction } from './firewallSafety';

const STACKS_KEY = 'firewall:stacks';

let db: ClassicLevel<string, unknown> | null = null;
let currentPath: string | null = null;

function resolveStorePath(baseDir?: string): string {
  const base = baseDir ? path.resolve(baseDir) : path.join(process.cwd(), '.sentinel');
  return path.join(base, 'firewall-history-db');
}

export async function initFirewallHistoryStore(baseDir?: string): Promise<void> {
  const targetPath = resolveStorePath(baseDir);
  if (db && currentPath === targetPath) {
    return;
  }
  if (db) {
    await db.close();
    db = null;
    currentPath = null;
  }
  fs.mkdirSync(targetPath, { recursive: true });
  db = new ClassicLevel(targetPath, { valueEncoding: 'json' });
  currentPath = targetPath;
}

export function isFirewallHistoryStoreReady(): boolean {
  return Boolean(db);
}

export async function closeFirewallHistoryStore(): Promise<void> {
  if (!db) {
    return;
  }
  await db.close();
  db = null;
  currentPath = null;
}

async function ensureDb(): Promise<ClassicLevel<string, unknown>> {
  if (!db) {
    throw new Error('Firewall history store not initialized');
  }
  return db;
}

export interface PersistedStacks {
  undo: FirewallAction[];
  redo: FirewallAction[];
}

export async function loadFirewallStacks(): Promise<PersistedStacks> {
  if (!db) {
    return { undo: [], redo: [] };
  }
  try {
    const value = (await db.get(STACKS_KEY)) as PersistedStacks;
    return {
      undo: Array.isArray(value?.undo) ? value.undo : [],
      redo: Array.isArray(value?.redo) ? value.redo : [],
    };
  } catch (err: any) {
    if (err?.code === 'LEVEL_NOT_FOUND') {
      return { undo: [], redo: [] };
    }
    throw err;
  }
}

export async function persistFirewallStacks(stacks: PersistedStacks): Promise<void> {
  if (!db) {
    return;
  }
  const store = await ensureDb();
  await store.put(STACKS_KEY, {
    undo: stacks.undo,
    redo: stacks.redo,
  });
}
