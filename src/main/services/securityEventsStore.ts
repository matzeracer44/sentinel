import * as path from 'path';
import * as fs from 'fs';
import Database from 'better-sqlite3';
import { appendThreatEvent } from './telemetryStore';
import { recordGuardianEvent } from '@main/services/guardianPlaybookEngine';

export type SecurityEventAction = 'Blocked' | 'Alerted' | 'Throttled';

export interface SecurityEventRecord {
  pid: number;
  processName: string;
  processCompany?: string;
  processPath?: string;
  localPort: number;
  remoteSubnet: string;
  remoteIP: string;
  riskScore: number;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  tlsStatus?: 'pending' | 'ready' | 'error' | 'unknown';
  reason?: string;
  actionTaken: SecurityEventAction;
  timestamp?: number;
}

function resolveBetterSqlite3Binding(): string | null {
  const candidates = [
    path.resolve(__dirname, '../node_modules/better-sqlite3/build/Release/better_sqlite3.node'),
    path.resolve(__dirname, '../../node_modules/better-sqlite3/build/Release/better_sqlite3.node'),
    path.resolve(process.cwd(), 'node_modules/better-sqlite3/build/Release/better_sqlite3.node'),
    process.resourcesPath
      ? path.resolve(process.resourcesPath, 'node_modules/better-sqlite3/build/Release/better_sqlite3.node')
      : null,
  ].filter((candidate): candidate is string => Boolean(candidate));

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  console.warn('[SecurityEventsStore] Unable to locate better-sqlite3 native binding');
  return null;
}

export type StoredSecurityEvent = SecurityEventRecord & { id: number; timestamp: number };

const BETTER_SQLITE3_BINDING = resolveBetterSqlite3Binding();
const BATCH_INTERVAL_MS = 100;
const BATCH_MAX_SIZE = 50;

let db: Database.Database | null = null;
let insertStmt: Database.Statement | null = null;
let walConfigured = false;
let flushTimer: NodeJS.Timeout | null = null;
const buffer: SecurityEventRecord[] = [];
let dbPath = resolveDefaultDbPath();

function resolveDefaultDbPath(): string {
  const explicit = process.env.SENTINEL_SECURITY_DB;
  if (explicit) {
    return path.resolve(explicit);
  }
  return path.resolve(process.cwd(), 'security_events.db');
}

export function configureSecurityEventsStore(options: { baseDir?: string; filename?: string } = {}): void {
  const filename = options.filename?.trim() || 'security_events.db';
  const targetBase = options.baseDir ? path.resolve(options.baseDir) : path.dirname(resolveDefaultDbPath());
  const nextPath = path.join(targetBase, filename);
  if (db && dbPath !== nextPath) {
    db.close();
    db = null;
    insertStmt = null;
    walConfigured = false;
  }
  dbPath = nextPath;
}

function ensureDatabase(): void {
  if (db) return;

  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  db = new Database(dbPath, BETTER_SQLITE3_BINDING ? { nativeBinding: BETTER_SQLITE3_BINDING } : undefined);
  if (!walConfigured) {
    db.pragma('journal_mode = WAL');
    db.pragma('synchronous = NORMAL');
    walConfigured = true;
  }

  db.exec(`
    CREATE TABLE IF NOT EXISTS security_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp INTEGER NOT NULL,
      pid INTEGER NOT NULL,
      process_name TEXT NOT NULL,
      process_company TEXT,
      process_path TEXT,
      local_port INTEGER,
      remote_subnet TEXT NOT NULL,
      remote_ip TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      risk_level TEXT NOT NULL,
      action_taken TEXT NOT NULL,
      tls_status TEXT,
      reason TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_security_events_pid ON security_events(pid);
    CREATE INDEX IF NOT EXISTS idx_security_events_remote_subnet ON security_events(remote_subnet);
  `);

  insertStmt = db.prepare(`
    INSERT INTO security_events (
      timestamp,
      pid,
      process_name,
      process_company,
      process_path,
      local_port,
      remote_subnet,
      remote_ip,
      risk_score,
      risk_level,
      action_taken,
      tls_status,
      reason
    ) VALUES (@timestamp, @pid, @process_name, @process_company, @process_path, @local_port, @remote_subnet, @remote_ip, @risk_score, @risk_level, @action_taken, @tls_status, @reason)
  `);
}

function scheduleFlush(): void {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    flushBuffer();
  }, BATCH_INTERVAL_MS);
}

function flushBuffer(): void {
  if (!buffer.length) return;
  ensureDatabase();
  if (!db || !insertStmt) return;

  const records = buffer.splice(0, BATCH_MAX_SIZE);
  const transaction = db.transaction((rows: SecurityEventRecord[]) => {
    for (const row of rows) {
      insertStmt!.run({
        timestamp: row.timestamp ?? Date.now(),
        pid: row.pid,
        process_name: row.processName,
        process_company: row.processCompany,
        process_path: row.processPath,
        local_port: row.localPort,
        remote_subnet: row.remoteSubnet,
        remote_ip: row.remoteIP,
        risk_score: Math.round(row.riskScore),
        risk_level: row.riskLevel,
        action_taken: row.actionTaken,
        tls_status: row.tlsStatus ?? 'unknown',
        reason: row.reason ?? null,
      });
    }
  });

  transaction(records);

  if (buffer.length) {
    scheduleFlush();
  }
}

export async function logSecurityEventAsync(event: SecurityEventRecord): Promise<StoredSecurityEvent> {
  return new Promise<StoredSecurityEvent>((resolve, reject) => {
    try {
      logSecurityEvent(event, resolve);
    } catch (err) {
      reject(err);
    }
  });
}

export function logSecurityEvent(event: SecurityEventRecord, onStored?: (record: StoredSecurityEvent) => void): void {
  buffer.push(event);
  if (buffer.length >= BATCH_MAX_SIZE) {
    flushBuffer();
  } else {
    scheduleFlush();
  }

  const timestamp = event.timestamp ?? Date.now();
  void appendThreatEvent({
    pid: event.pid,
    processName: event.processName,
    remoteIP: event.remoteIP,
    remoteSubnet: event.remoteSubnet,
    riskScore: event.riskScore,
    riskLevel: event.riskLevel,
    actionTaken: event.actionTaken,
    reason: event.reason,
    timestamp,
  })
    .then((threat) => {
      return recordGuardianEvent(
        {
          module: 'security-events',
          pid: event.pid,
          processName: event.processName,
          remoteIP: event.remoteIP,
          remoteSubnet: event.remoteSubnet,
          riskScore: event.riskScore,
          riskLevel: event.riskLevel,
          action: event.actionTaken,
          fingerprint: event.processName?.toLowerCase(),
          metadata: {
            linkedThreatIds: [threat.id],
            reason: event.reason,
            source: 'securityEventsStore',
          },
          timestamp,
        },
        { dryRun: false },
      );
    })
    .catch((err) => {
      console.warn('[SecurityEventsStore] Failed to append threat/guardian event:', err);
    });

  if (onStored) {
    const record: StoredSecurityEvent = {
      id: Date.now(),
      timestamp: event.timestamp ?? Date.now(),
      pid: event.pid,
      processName: event.processName,
      processCompany: event.processCompany,
      processPath: event.processPath,
      localPort: event.localPort,
      remoteSubnet: event.remoteSubnet,
      remoteIP: event.remoteIP,
      riskScore: Math.round(event.riskScore),
      riskLevel: event.riskLevel,
      actionTaken: event.actionTaken,
      tlsStatus: event.tlsStatus ?? 'unknown',
      reason: event.reason,
    };
    onStored(record);
  }
}

export function getRecentSecurityEvents(limit = 50, pid?: number): StoredSecurityEvent[] {
  ensureDatabase();
  if (!db) return [];

  const baseSelect = `
    SELECT
      id,
      timestamp,
      pid,
      process_name AS processName,
      process_company AS processCompany,
      process_path AS processPath,
      local_port AS localPort,
      remote_subnet AS remoteSubnet,
      remote_ip AS remoteIP,
      risk_score AS riskScore,
      risk_level AS riskLevel,
      action_taken AS actionTaken,
      tls_status AS tlsStatus,
      reason
    FROM security_events
  `;

  const rows = pid !== undefined && pid !== null
    ? db!.prepare(`${baseSelect} WHERE pid = ? ORDER BY timestamp DESC LIMIT ?`).all(pid, limit)
    : db!.prepare(`${baseSelect} ORDER BY timestamp DESC LIMIT ?`).all(limit);

  return rows.map((row: any) => ({
    id: Number(row.id),
    timestamp: Number(row.timestamp),
    pid: Number(row.pid),
    processName: row.processName,
    processCompany: row.processCompany || undefined,
    processPath: row.processPath || undefined,
    localPort: Number(row.localPort) || 0,
    remoteSubnet: row.remoteSubnet,
    remoteIP: row.remoteIP,
    riskScore: Number(row.riskScore) || 0,
    riskLevel: row.riskLevel,
    actionTaken: row.actionTaken,
    tlsStatus: row.tlsStatus || 'unknown',
    reason: row.reason || undefined,
  }));
}

export function shutdownSecurityEvents(): void {
  flushBuffer();
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
  if (db) {
    db.close();
    db = null;
    insertStmt = null;
  }
}

export function checkSecurityEventsStoreHealth(): { ok: boolean; message?: string } {
  try {
    ensureDatabase();
    if (!db) {
      return { ok: false, message: 'Database handle unavailable' };
    }
    db.prepare('SELECT 1').get();
    return { ok: true };
  } catch (err: any) {
    return { ok: false, message: err?.message || String(err) };
  }
}
