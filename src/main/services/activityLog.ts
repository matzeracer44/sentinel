import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';

export interface ActivityLogEntry {
  id: number;
  timestamp: string;
  module: string;
  action: string;
  details: string;
  severity: 'info' | 'success' | 'warning' | 'error';
}

let LOG_FILE_PATH: string | null = null;

function getLogFilePath(): string {
  if (!LOG_FILE_PATH) {
    LOG_FILE_PATH = path.join(app.getPath('userData'), 'activity.log');
  }
  return LOG_FILE_PATH;
}
let MAX_LOG_ENTRIES = 1000; // Keep last 1000 entries
let LOG_RETENTION_DAYS = 30; // Remove entries older than this (days)
const CLEANUP_INTERVAL_MS = 24 * 60 * 60 * 1000; // Run cleanup once per day

// Batched async write buffer to avoid sync IO on hot paths
const FLUSH_INTERVAL_MS = 1000; // flush every 1 second
const MAX_WRITE_BUFFER = 50; // flush when this many entries are queued
let writeBuffer: ActivityLogEntry[] = [];
let flushTimer: NodeJS.Timeout | null = null;
let _isFlushing = false;

let logCache: ActivityLogEntry[] = [];
let nextId = 1;

/**
 * Initialize the activity log system
 */
export function initActivityLog() {
  // Perform async initialization — don't block app startup
  (async () => {
    try {
      const logPath = getLogFilePath();
      if (!fs.existsSync(logPath)) return;

      const data = await fs.promises.readFile(logPath, 'utf8');
      const lines = data.split('\n').filter(line => line.trim());

      const diskEntries = lines.map((line) => {
        try { return JSON.parse(line); } catch { return null; }
      }).filter(Boolean) as ActivityLogEntry[];

      // Merge disk entries and current in-memory cache, dedupe by id
      const map = new Map<number, ActivityLogEntry>();
      [...diskEntries, ...logCache].forEach((e) => map.set(e.id, e));

      let merged = Array.from(map.values()).sort((a, b) => a.id - b.id);

      // Keep only last MAX_LOG_ENTRIES
      if (merged.length > MAX_LOG_ENTRIES) merged = merged.slice(-MAX_LOG_ENTRIES);

      logCache = merged;

      // Set next ID
      if (logCache.length > 0) {
        nextId = Math.max(...logCache.map(entry => entry.id)) + 1;
      }
    } catch (error) {
      console.error('Error initializing activity log:', error);
      // keep existing in-memory cache if present
    }

    // Perform initial cleanup to enforce retention and trimming on disk
    try { await cleanupLogs(); } catch (e) { /* ignore */ }
  })();

  // Schedule periodic cleanup
  setInterval(() => {
    try { cleanupLogs().catch(() => {}); } catch (e) { /* ignore */ }
  }, CLEANUP_INTERVAL_MS);
} 


/**
 * Add a new activity log entry
 */
export function addActivityLog(
  module: string,
  action: string,
  details: string,
  severity: 'info' | 'success' | 'warning' | 'error' = 'info'
) {
  const entry: ActivityLogEntry = {
    id: nextId++,
    timestamp: new Date().toISOString(),
    module,
    action,
    details,
    severity,
  };

  logCache.push(entry);

  // Keep only last MAX_LOG_ENTRIES in memory
  if (logCache.length > MAX_LOG_ENTRIES) {
    logCache = logCache.slice(-MAX_LOG_ENTRIES);
  }

  // Add to async write buffer
  writeBuffer.push(entry);

  // Flush immediately if buffer grows large
  if (writeBuffer.length >= MAX_WRITE_BUFFER) {
    flushBuffer().catch((e) => { console.error('Error flushing activity log buffer:', e); });
  } else {
    scheduleFlush();
  }
}

/**
 * Get recent activity log entries
 */
export function getActivityLog(limit: number = 20): ActivityLogEntry[] {
  return logCache.slice(-limit).reverse();
}

/**
 * Clear all activity log entries
 */
export async function clearActivityLog() {
  logCache = [];
  nextId = 1;

  try {
    writeBuffer = [];
    if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
    const logPath = getLogFilePath();
    if (fs.existsSync(logPath)) {
      await fs.promises.unlink(logPath);
    }
  } catch (error) {
    console.error('Error clearing activity log:', error);
  }
}

/**
 * Write the in-memory cache to disk (overwrites existing file)
 */
function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    flushBuffer().catch((e) => console.error('Error flushing activity log buffer:', e));
  }, FLUSH_INTERVAL_MS);
}

async function flushBuffer() {
  if (_isFlushing) return;
  if (writeBuffer.length === 0) return;

  _isFlushing = true;
  const items = writeBuffer.splice(0, writeBuffer.length);

  try {
    const lines = items.map((e) => JSON.stringify(e)).join('\n') + '\n';
    await fs.promises.appendFile(getLogFilePath(), lines, 'utf8');
  } catch (error) {
    // If append fails (e.g., file doesn't exist), try to rewrite from cache
    console.error('Error appending activity log buffer:', error);
    try {
      await writeLogFileFromCacheAsync();
    } catch (e) {
      console.error('Error writing activity log fallback:', e);
    }
  } finally {
    _isFlushing = false;
  }
}

/** Flush any pending writes immediately (useful on app exit) */
export async function flushAllLogs() {
  // cancel scheduled timer and flush
  if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
  await flushBuffer();
}
async function writeLogFileFromCacheAsync() {
  try {
    const lines = logCache.map((e) => JSON.stringify(e)).join('\n') + '\n';
    await fs.promises.writeFile(getLogFilePath(), lines, 'utf8');
  } catch (error) {
    console.error('Error writing trimmed activity log:', error);
  }
} 

/**
 * Cleanup on-disk log according to retention and max entries
 */
export async function cleanupLogs() {
  try {
    const cleanupLogPath = getLogFilePath();
    if (!fs.existsSync(cleanupLogPath)) return;

    const data = await fs.promises.readFile(cleanupLogPath, 'utf8');
    const lines = data.split('\n').filter((l) => l.trim());

    let entries = lines
      .map((line) => {
        try { return JSON.parse(line); } catch { return null; }
      })
      .filter(Boolean) as ActivityLogEntry[];

    const cutoff = Date.now() - LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;

    // Remove entries older than retention period
    entries = entries.filter((e) => new Date(e.timestamp).getTime() >= cutoff);

    // Keep only the newest MAX_LOG_ENTRIES
    if (entries.length > MAX_LOG_ENTRIES) {
      entries = entries.slice(-MAX_LOG_ENTRIES);
    }

    // Persist cleaned entries
    logCache = entries;

    if (logCache.length > 0) {
      nextId = Math.max(...logCache.map((entry) => entry.id)) + 1;
    } else {
      nextId = 1;
    }

    await writeLogFileFromCacheAsync();
  } catch (error) {
    console.error('Error cleaning activity log:', error);
  }
} 

/**
 * Adjust retention and trimming parameters at runtime
 */
export function setLogRetentionDays(days: number) {
  if (typeof days === 'number' && days >= 0) LOG_RETENTION_DAYS = Math.floor(days);
}

export function setMaxLogEntries(max: number) {
  if (typeof max === 'number' && max > 0) MAX_LOG_ENTRIES = Math.floor(max);
}

// Optional: auto-capture console messages into activity log
let _autoLoggingEnabled = false;
const _originalConsole = {
  error: console.error,
  warn: console.warn,
  info: console.info,
  log: console.log,
};

export function enableAutoActivityLogging(levels: ('error'|'warn'|'info'|'log')[] = ['error','warn']) {
  if (_autoLoggingEnabled) return;
  _autoLoggingEnabled = true;

  if (levels.includes('error')) {
    console.error = (...args: any[]) => {
      try { addActivityLog('Console', 'error', args.map(String).join(' '), 'error'); } catch {}
      _originalConsole.error.apply(console, args);
    };
  }

  if (levels.includes('warn')) {
    console.warn = (...args: any[]) => {
      try { addActivityLog('Console', 'warn', args.map(String).join(' '), 'warning'); } catch {}
      _originalConsole.warn.apply(console, args);
    };
  }

  if (levels.includes('info')) {
    console.info = (...args: any[]) => {
      try { addActivityLog('Console', 'info', args.map(String).join(' '), 'info'); } catch {}
      _originalConsole.info.apply(console, args);
    };
  }

  if (levels.includes('log')) {
    console.log = (...args: any[]) => {
      try { addActivityLog('Console', 'log', args.map(String).join(' '), 'info'); } catch {}
      _originalConsole.log.apply(console, args);
    };
  }
}

export function disableAutoActivityLogging() {
  if (!_autoLoggingEnabled) return;
  _autoLoggingEnabled = false;
  console.error = _originalConsole.error;
  console.warn = _originalConsole.warn;
  console.info = _originalConsole.info;
  console.log = _originalConsole.log;
}

export function isAutoActivityLoggingEnabled() {
  return _autoLoggingEnabled;
}
