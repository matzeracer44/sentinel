/**
 * SENTINEL — Scan Result Persistence Store
 * Persists scan results to disk so they survive page navigation and app restarts.
 * Stores each scan type (fullScan, network, edr, kernel, performance, privacy) separately.
 */

import { app } from 'electron';
import * as fs from 'fs';
import * as path from 'path';

const STORE_FILE = 'scan-results.json';
let storePath: string | null = null;

function getStorePath(): string {
  if (!storePath) {
    storePath = path.join(app.getPath('userData'), STORE_FILE);
  }
  return storePath;
}

interface ScanStore {
  [scanType: string]: {
    data: unknown;
    timestamp: number;
  };
}

function readStore(): ScanStore {
  try {
    const filePath = getStorePath();
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(raw) as ScanStore;
    }
  } catch (e: any) {
    console.warn('[ScanResultStore] Failed to read store:', e?.message);
  }
  return {};
}

function writeStore(store: ScanStore): void {
  try {
    fs.writeFileSync(getStorePath(), JSON.stringify(store), 'utf8');
  } catch (e: any) {
    console.warn('[ScanResultStore] Failed to write store:', e?.message);
  }
}

/** Save a scan result for a given scan type */
export function saveScanResult(scanType: string, data: unknown): void {
  const store = readStore();
  store[scanType] = { data, timestamp: Date.now() };
  writeStore(store);
}

/** Load a scan result for a given scan type. Returns null if not found. */
export function loadScanResult(scanType: string): { data: unknown; timestamp: number } | null {
  const store = readStore();
  return store[scanType] || null;
}

/** Load all persisted scan results */
export function loadAllScanResults(): ScanStore {
  return readStore();
}

/** Clear a specific scan result */
export function clearScanResult(scanType: string): void {
  const store = readStore();
  delete store[scanType];
  writeStore(store);
}

/** Clear all scan results */
export function clearAllScanResults(): void {
  writeStore({});
}
