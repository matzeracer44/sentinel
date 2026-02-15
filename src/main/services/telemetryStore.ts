import { ClassicLevel } from 'classic-level';
import { randomUUID } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  ShieldStageFirewallRuleRequest,
  ThreatTimelineFilters,
  PolicyIntel,
  GuardianEvent as GuardianEventPayload,
  GuardianStory as GuardianStoryPayload,
  GuardianPlaybook,
  GuardianPlaybookRun,
  GuardianAnomalyConfig,
  GuardianThreatIntelRecord,
} from '../../shared/ipcSchemas';

const MAX_KEY_INT = Number.MAX_SAFE_INTEGER;
const REVERSE_PAD_LENGTH = 16;
const DEFAULT_PENDING_RULE_TTL_MS = 5 * 60 * 1000;

const PREFIX = {
  threat: 'threat',
  pendingRules: 'pendingRules',
  pendingIndex: 'pendingRulesIndex',
  policies: 'policies',
  cspReports: 'cspReports',
  guardianEvents: 'guardianEvents',
  guardianStories: 'guardianStories',
  guardianStoryIndex: 'guardianStoriesIndex',
  guardianPlaybooks: 'guardianPlaybooks',
  guardianPlaybookRuns: 'guardianPlaybookRuns',
  guardianAnomalyConfig: 'guardianAnomalyConfig',
  guardianThreatIntel: 'guardianThreatIntel',
} as const;

let db: ClassicLevel<string, unknown> | null = null;
let dbPath: string | null = null;

export interface ThreatEventRecord {
  id: string;
  timestamp: number;
  pid: number;
  processName: string;
  remoteIP?: string;
  remoteSubnet?: string;
  riskScore: number;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  actionTaken: 'Blocked' | 'Alerted' | 'Throttled';
  reason?: string;
}

export interface PendingRuleRecord extends ShieldStageFirewallRuleRequest {
  id: string;
  createdAt: number;
  expiresAt: number;
  status: 'pending' | 'committed' | 'expired' | 'dismissed';
}

export interface PolicySuggestionRecord {
  id: string;
  createdAt: number;
  recommendation: string;
  confidence: number;
  evidenceCount: number;
  remoteIP?: string;
  processName?: string;
  status: 'pending' | 'accepted' | 'dismissed';
  updatedAt: number;
  fingerprint?: string;
  intel?: PolicyIntel;
}

export interface CspReportEntry {
  id: string;
  createdAt: number;
  report: Record<string, unknown>;
}

export interface GuardianEventRecord extends GuardianEventPayload {}

export interface GuardianStoryRecord extends GuardianStoryPayload {
  correlationKey: string;
}

export interface GuardianPlaybookRecord extends GuardianPlaybook {}

export interface GuardianPlaybookRunRecord extends GuardianPlaybookRun {}

export interface GuardianThreatIntelRecordEntry extends GuardianThreatIntelRecord {
  updatedAt: number;
}

export interface PageResult<T> {
  entries: T[];
  nextCursor: string | null;
}

export interface ThreatPageOptions {
  cursor?: string;
  limit?: number;
  filters?: ThreatTimelineFilters;
}

export interface PolicyPageOptions {
  cursor?: string;
  limit?: number;
  status?: PolicySuggestionRecord['status'];
}

export interface GuardianStoryPageFilters {
  pid?: number;
  processName?: string;
  remoteIP?: string;
  module?: GuardianEventRecord['module'];
}

export interface GuardianStoryPageOptions {
  cursor?: string;
  limit?: number;
  filters?: GuardianStoryPageFilters;
}

function resolveBaseDir(baseDir?: string): string {
  if (baseDir) {
    return path.resolve(baseDir);
  }
  const envDir = process.env.SENTINEL_TELEMETRY_DIR;
  if (envDir && envDir.trim().length > 0) {
    return path.resolve(envDir);
  }
  return path.join(process.cwd(), '.sentinel');
}

export function configureTelemetryStore(options: { baseDir?: string } = {}): string {
  const resolvedBase = resolveBaseDir(options.baseDir);
  const nextPath = path.join(resolvedBase, 'telemetry-db');
  if (db && dbPath && dbPath !== nextPath) {
    void db.close();
    db = null;
    dbPath = null;
  }
  dbPath = nextPath;
  return nextPath;
}

export function isTelemetryStoreReady(): boolean {
  return Boolean(db);
}

export async function initTelemetryStore(baseDir?: string): Promise<void> {
  const targetPath = configureTelemetryStore({ baseDir });
  if (db) {
    return;
  }
  fs.mkdirSync(targetPath, { recursive: true });
  db = new ClassicLevel(targetPath, { valueEncoding: 'json' });
}

export async function closeTelemetryStore(): Promise<void> {
  if (!db) return;
  await db.close();
  db = null;
  dbPath = null;
}

function ensureDb(): ClassicLevel<string, unknown> {
  if (!db) {
    throw new Error('Telemetry store not initialized');
  }
  return db;
}

function reverseTimestampKey(prefix: string, timestamp: number, id?: string): string {
  const reverse = MAX_KEY_INT - timestamp;
  const padded = reverse.toString().padStart(REVERSE_PAD_LENGTH, '0');
  return `${prefix}:${padded}:${id ?? randomUUID()}`;
}

function ascendingTimestampKey(prefix: string, timestamp: number, id?: string): string {
  const padded = timestamp.toString().padStart(REVERSE_PAD_LENGTH, '0');
  return `${prefix}:${padded}:${id ?? randomUUID()}`;
}

function prefixUpperBound(prefix: string): string {
  return `${prefix};`;
}

function matchesThreatFilters(record: ThreatEventRecord, filters?: ThreatPageOptions['filters']): boolean {
  if (!filters) return true;
  if (typeof filters.pid === 'number' && record.pid !== filters.pid) return false;
  if (filters.processName && record.processName.toLowerCase() !== filters.processName.toLowerCase()) return false;
  if (filters.range) {
    if (record.timestamp < filters.range.from || record.timestamp > filters.range.to) return false;
  }
  return true;
}

export async function appendThreatEvent(event: Omit<ThreatEventRecord, 'id'> & { id?: string }): Promise<ThreatEventRecord> {
  const store = ensureDb();
  const id = event.id ?? randomUUID();
  const timestamp = event.timestamp ?? Date.now();
  const record: ThreatEventRecord = { ...event, id, timestamp };
  const key = reverseTimestampKey(PREFIX.threat, timestamp, id);
  await store.put(key, record);
  return record;
}

export async function getThreatEventsPage(options: ThreatPageOptions): Promise<PageResult<ThreatEventRecord>> {
  const store = ensureDb();
  const limit = options.limit ?? 50;
  const events: ThreatEventRecord[] = [];
  let lastKey: string | null = null;
  const iterator = store.iterator<ThreatEventRecord>({
    gte: `${PREFIX.threat}:`,
    lt: options.cursor ?? prefixUpperBound(PREFIX.threat),
    reverse: true,
  });
  try {
    for await (const [key, value] of iterator) {
      const record = value as ThreatEventRecord;
      if (!matchesThreatFilters(record, options.filters)) {
        continue;
      }
      events.push(record);
      lastKey = key;
      if (events.length >= limit) {
        break;
      }
    }
  } finally {
    await iterator.close();
  }
  return {
    entries: events,
    nextCursor: events.length === limit && lastKey ? lastKey : null,
  };
}

/**
 * DSGVO Art. 17 — Recht auf Löschung: Purge all stored threat events.
 */
export async function clearAllThreatEvents(): Promise<{ deleted: number }> {
  const store = ensureDb();
  let deleted = 0;
  const keysToDelete: string[] = [];
  const iterator = store.iterator({
    gte: `${PREFIX.threat}:`,
    lt: prefixUpperBound(PREFIX.threat),
  });
  try {
    for await (const [key] of iterator) {
      keysToDelete.push(key);
    }
  } finally {
    await iterator.close();
  }
  for (const key of keysToDelete) {
    await store.del(key);
    deleted++;
  }
  return { deleted };
}

export async function stagePendingRule(payload: ShieldStageFirewallRuleRequest & { requestedAt?: number; expiresAt?: number }): Promise<PendingRuleRecord> {
  const store = ensureDb();
  const now = payload.requestedAt ?? Date.now();
  const ttlMs = payload.ttlSeconds ? payload.ttlSeconds * 1000 : DEFAULT_PENDING_RULE_TTL_MS;
  const expiresAt = payload.expiresAt ?? now + ttlMs;
  const record: PendingRuleRecord = {
    ...payload,
    id: randomUUID(),
    createdAt: now,
    expiresAt,
    status: 'pending',
  };
  const compositeKey = ascendingTimestampKey(PREFIX.pendingRules, record.expiresAt, record.id);
  await store.put(compositeKey, record);
  await store.put(`${PREFIX.pendingIndex}:${record.id}`, compositeKey);
  return record;
}

export async function setPendingRuleStatus(id: string, status: PendingRuleRecord['status']): Promise<PendingRuleRecord | null> {
  const store = ensureDb();
  try {
    const compositeKey = (await store.get(`${PREFIX.pendingIndex}:${id}`)) as string;
    const record = (await store.get(compositeKey)) as PendingRuleRecord;
    const updated: PendingRuleRecord = { ...record, status };
    await store.put(compositeKey, updated);
    return updated;
  } catch (err: any) {
    if (err?.code === 'LEVEL_NOT_FOUND') {
      return null;
    }
    throw err;
  }
}

export async function getPendingRuleById(id: string): Promise<PendingRuleRecord | null> {
  const store = ensureDb();
  try {
    const compositeKey = (await store.get(`${PREFIX.pendingIndex}:${id}`)) as string;
    const record = (await store.get(compositeKey)) as PendingRuleRecord;
    return record;
  } catch (err: any) {
    if (err?.code === 'LEVEL_NOT_FOUND') {
      return null;
    }
    throw err;
  }
}

export async function deletePendingRule(id: string): Promise<void> {
  const store = ensureDb();
  try {
    const compositeKey = (await store.get(`${PREFIX.pendingIndex}:${id}`)) as string;
    await Promise.all([
      store.del(compositeKey),
      store.del(`${PREFIX.pendingIndex}:${id}`),
    ]);
  } catch (err: any) {
    if (err?.code === 'LEVEL_NOT_FOUND') {
      return;
    }
    throw err;
  }
}

export async function listPendingRules(limit = 100): Promise<PendingRuleRecord[]> {
  const store = ensureDb();
  const results: PendingRuleRecord[] = [];
  const iterator = store.iterator<PendingRuleRecord>({
    gte: `${PREFIX.pendingRules}:`,
    lt: prefixUpperBound(PREFIX.pendingRules),
    limit,
  });
  try {
    for await (const [, value] of iterator) {
      results.push(value as PendingRuleRecord);
      if (results.length >= limit) {
        break;
      }
    }
  } finally {
    await iterator.close();
  }
  return results;
}

export async function purgeExpiredPendingRules(now = Date.now()): Promise<PendingRuleRecord[]> {
  const store = ensureDb();
  const expired: PendingRuleRecord[] = [];
  const iterator = store.iterator<PendingRuleRecord>({
    gte: `${PREFIX.pendingRules}:`,
    lt: prefixUpperBound(PREFIX.pendingRules),
  });
  try {
    for await (const [key, value] of iterator) {
      const record = value as PendingRuleRecord;
      if (record.expiresAt > now) {
        break;
      }
      expired.push(record);
      await store.del(key);
      await store.del(`${PREFIX.pendingIndex}:${record.id}`);
    }
  } finally {
    await iterator.close();
  }
  return expired;
}

export async function writePolicySuggestion(entry: Omit<PolicySuggestionRecord, 'id' | 'createdAt' | 'updatedAt' | 'status'> & { status?: PolicySuggestionRecord['status'] }): Promise<PolicySuggestionRecord> {
  const store = ensureDb();
  const now = Date.now();
  const record: PolicySuggestionRecord = {
    id: randomUUID(),
    createdAt: now,
    updatedAt: now,
    recommendation: entry.recommendation,
    confidence: entry.confidence,
    evidenceCount: entry.evidenceCount,
    remoteIP: entry.remoteIP,
    processName: entry.processName,
    status: entry.status ?? 'pending',
    fingerprint: entry.fingerprint,
    intel: entry.intel,
  };
  const key = reverseTimestampKey(PREFIX.policies, record.createdAt, record.id);
  await store.put(key, record);
  return record;
}

export async function upsertPolicySuggestionByFingerprint(
  fingerprint: string,
  payload: Omit<PolicySuggestionRecord, 'id' | 'createdAt' | 'updatedAt' | 'status' | 'fingerprint'> & {
    status?: PolicySuggestionRecord['status'];
    confidence?: number;
    evidenceCount?: number;
  }
): Promise<PolicySuggestionRecord> {
  const store = ensureDb();
  const iterator = store.iterator<PolicySuggestionRecord>({
    gte: `${PREFIX.policies}:`,
    lt: prefixUpperBound(PREFIX.policies),
  });
  try {
    for await (const [key, value] of iterator) {
      const record = value as PolicySuggestionRecord;
      if (record.fingerprint !== fingerprint) continue;
      const updated: PolicySuggestionRecord = {
        ...record,
        recommendation: payload.recommendation ?? record.recommendation,
        confidence: payload.confidence ?? record.confidence,
        evidenceCount: payload.evidenceCount ?? record.evidenceCount,
        remoteIP: payload.remoteIP ?? record.remoteIP,
        processName: payload.processName ?? record.processName,
        intel: payload.intel ?? record.intel,
        status: payload.status ?? record.status,
        updatedAt: Date.now(),
      };
      await store.put(key, updated);
      return updated;
    }
  } finally {
    await iterator.close();
  }

  return writePolicySuggestion({
    ...payload,
    fingerprint,
    recommendation: payload.recommendation ?? 'Policy suggestion',
    confidence: payload.confidence ?? 0.5,
    evidenceCount: payload.evidenceCount ?? 1,
    status: payload.status,
  });
}

export async function updatePolicySuggestionStatus(id: string, status: PolicySuggestionRecord['status']): Promise<PolicySuggestionRecord | null> {
  const store = ensureDb();
  const iterator = store.iterator<PolicySuggestionRecord>({
    gte: `${PREFIX.policies}:`,
    lt: prefixUpperBound(PREFIX.policies),
  });
  try {
    for await (const [key, value] of iterator) {
      const record = value as PolicySuggestionRecord;
      if (record.id !== id) continue;
      const next: PolicySuggestionRecord = { ...record, status, updatedAt: Date.now() };
      await store.put(key, next);
      return next;
    }
  } finally {
    await iterator.close();
  }
  return null;
}

export async function getPolicySuggestionsPage(options: PolicyPageOptions): Promise<PageResult<PolicySuggestionRecord>> {
  const store = ensureDb();
  const limit = options.limit ?? 20;
  const entries: PolicySuggestionRecord[] = [];
  let lastKey: string | null = null;
  const iterator = store.iterator<PolicySuggestionRecord>({
    gte: `${PREFIX.policies}:`,
    lt: options.cursor ?? prefixUpperBound(PREFIX.policies),
    reverse: true,
  });
  try {
    for await (const [key, value] of iterator) {
      const suggestion = value as PolicySuggestionRecord;
      if (options.status && suggestion.status !== options.status) {
        continue;
      }
      entries.push(suggestion);
      lastKey = key;
      if (entries.length >= limit) {
        break;
      }
    }
  } finally {
    await iterator.close();
  }
  return {
    entries,
    nextCursor: entries.length === limit && lastKey ? lastKey : null,
  };
}

function guardianPlaybookKey(id: string): string {
  return `${PREFIX.guardianPlaybooks}:${id}`;
}

function guardianThreatIntelKey(indicator: string): string {
  return `${PREFIX.guardianThreatIntel}:${indicator.trim().toLowerCase()}`;
}

export async function listGuardianPlaybooks(): Promise<GuardianPlaybookRecord[]> {
  const store = ensureDb();
  const results: GuardianPlaybookRecord[] = [];
  const iterator = store.iterator<GuardianPlaybookRecord>({
    gte: `${PREFIX.guardianPlaybooks}:`,
    lt: prefixUpperBound(PREFIX.guardianPlaybooks),
  });
  try {
    for await (const [, value] of iterator) {
      results.push(value as GuardianPlaybookRecord);
    }
  } finally {
    await iterator.close();
  }
  return results.sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
}

export async function getGuardianPlaybookById(id: string): Promise<GuardianPlaybookRecord | null> {
  const store = ensureDb();
  try {
    return (await store.get(guardianPlaybookKey(id))) as GuardianPlaybookRecord;
  } catch (err: any) {
    if (err?.code === 'LEVEL_NOT_FOUND') {
      return null;
    }
    throw err;
  }
}

export async function saveGuardianPlaybook(record: Omit<GuardianPlaybook, 'id' | 'createdAt' | 'updatedAt'> & { id?: string }): Promise<GuardianPlaybookRecord> {
  const store = ensureDb();
  const now = Date.now();
  const existing = record.id ? await getGuardianPlaybookById(record.id) : null;
  const id = record.id ?? randomUUID();
  const createdAt = existing?.createdAt ?? now;
  const payload: GuardianPlaybookRecord = {
    id,
    name: record.name,
    description: record.description,
    enabled: record.enabled,
    priority: record.priority ?? 0,
    tags: record.tags,
    conditions: record.conditions,
    actions: record.actions,
    createdAt,
    updatedAt: now,
  };
  await store.put(guardianPlaybookKey(id), payload);
  return payload;
}

export async function deleteGuardianPlaybook(id: string): Promise<void> {
  const store = ensureDb();
  await store.del(guardianPlaybookKey(id)).catch((err: any) => {
    if (err?.code !== 'LEVEL_NOT_FOUND') {
      throw err;
    }
  });
}

export async function getGuardianThreatIntelRecord(indicator: string): Promise<GuardianThreatIntelRecordEntry | null> {
  const store = ensureDb();
  const key = guardianThreatIntelKey(indicator);
  try {
    return (await store.get(key)) as GuardianThreatIntelRecordEntry;
  } catch (err: any) {
    if (err?.code === 'LEVEL_NOT_FOUND') {
      return null;
    }
    throw err;
  }
}

export async function upsertGuardianThreatIntelRecord(
  record: GuardianThreatIntelRecord & { updatedAt?: number },
): Promise<GuardianThreatIntelRecordEntry> {
  const store = ensureDb();
  const updatedAt = record.lastSeen ?? record.metadata?.lastSeen ?? record.metadata?.timestamp ?? Date.now();
  const entry: GuardianThreatIntelRecordEntry = {
    ...record,
    updatedAt,
  };
  await store.put(guardianThreatIntelKey(record.indicator), entry);
  return entry;
}

export interface GuardianThreatIntelQueryOptions {
  indicator?: string;
  type?: GuardianThreatIntelRecord['type'];
  cursor?: string;
  limit?: number;
}

export async function listGuardianThreatIntelRecords(
  options: GuardianThreatIntelQueryOptions = {},
): Promise<PageResult<GuardianThreatIntelRecordEntry>> {
  const store = ensureDb();
  const iterator = store.iterator<GuardianThreatIntelRecordEntry>({
    gte: `${PREFIX.guardianThreatIntel}:`,
    lt: prefixUpperBound(PREFIX.guardianThreatIntel),
  });
  const collected: GuardianThreatIntelRecordEntry[] = [];
  try {
    for await (const [, value] of iterator) {
      collected.push(value as GuardianThreatIntelRecordEntry);
    }
  } finally {
    await iterator.close();
  }

  const normalizedIndicator = options.indicator?.trim().toLowerCase();
  const filtered = collected
    .filter((entry) => {
      if (normalizedIndicator && entry.indicator.trim().toLowerCase() !== normalizedIndicator) {
        return false;
      }
      if (options.type && entry.type !== options.type) {
        return false;
      }
      return true;
    })
    .sort((a, b) => {
      const scoreA = a.lastSeen ?? a.metadata?.lastSeen ?? a.updatedAt;
      const scoreB = b.lastSeen ?? b.metadata?.lastSeen ?? b.updatedAt;
      return (scoreB ?? 0) - (scoreA ?? 0);
    });

  const limit = options.limit ?? 25;
  let startIndex = 0;
  if (options.cursor) {
    const cursorIndex = filtered.findIndex((entry) => entry.indicator === options.cursor);
    if (cursorIndex >= 0) {
      startIndex = cursorIndex + 1;
    }
  }

  const entries = filtered.slice(startIndex, startIndex + limit);
  const next = filtered[startIndex + limit];
  return {
    entries,
    nextCursor: next ? next.indicator : null,
  };
}

function guardianPlaybookRunKey(timestamp: number, id: string): string {
  return reverseTimestampKey(PREFIX.guardianPlaybookRuns, timestamp, id);
}

export async function logGuardianPlaybookRun(run: GuardianPlaybookRun): Promise<void> {
  const store = ensureDb();
  const timestamp = run.triggeredAt ?? Date.now();
  const record: GuardianPlaybookRunRecord = {
    ...run,
    triggeredAt: timestamp,
  };
  const key = guardianPlaybookRunKey(timestamp, record.id);
  await store.put(key, record);
}

export async function getGuardianPlaybookRuns(limit = 50): Promise<GuardianPlaybookRunRecord[]> {
  const store = ensureDb();
  const results: GuardianPlaybookRunRecord[] = [];
  const iterator = store.iterator<GuardianPlaybookRunRecord>({
    gte: `${PREFIX.guardianPlaybookRuns}:`,
    lt: prefixUpperBound(PREFIX.guardianPlaybookRuns),
    reverse: true,
  });
  try {
    for await (const [, value] of iterator) {
      results.push(value as GuardianPlaybookRunRecord);
      if (results.length >= limit) {
        break;
      }
    }
  } finally {
    await iterator.close();
  }
  return results;
}

const DEFAULT_GUARDIAN_ANOMALY_CONFIG: GuardianAnomalyConfig = {
  enabled: false,
  sensitivity: 'medium',
  windowMinutes: 60,
  minSamples: 50,
};

export async function getGuardianAnomalyConfig(): Promise<GuardianAnomalyConfig> {
  const store = ensureDb();
  try {
    return (await store.get(PREFIX.guardianAnomalyConfig)) as GuardianAnomalyConfig;
  } catch (err: any) {
    if (err?.code === 'LEVEL_NOT_FOUND') {
      await store.put(PREFIX.guardianAnomalyConfig, DEFAULT_GUARDIAN_ANOMALY_CONFIG);
      return DEFAULT_GUARDIAN_ANOMALY_CONFIG;
    }
    throw err;
  }
}

export async function updateGuardianAnomalyConfig(config: GuardianAnomalyConfig): Promise<GuardianAnomalyConfig> {
  const store = ensureDb();
  await store.put(PREFIX.guardianAnomalyConfig, config);
  return config;
}

export async function logCspReport(report: Record<string, unknown>): Promise<CspReportEntry> {
  const store = ensureDb();
  const entry: CspReportEntry = {
    id: randomUUID(),
    createdAt: Date.now(),
    report,
  };
  const key = reverseTimestampKey(PREFIX.cspReports, entry.createdAt, entry.id);
  await store.put(key, entry);
  return entry;
}

export function getTelemetryStorePath(): string | null {
  return dbPath;
}

function buildGuardianCorrelationKey(event: GuardianEventRecord): string {
  const pid = typeof event.pid === 'number' ? event.pid : -1;
  const remote = event.remoteIP ?? event.remoteSubnet ?? 'unknown';
  const fingerprint = event.fingerprint ?? 'unfingerprinted';
  return `${pid}:${remote}:${fingerprint}`;
}

function matchesGuardianFilters(story: GuardianStoryRecord, filters?: GuardianStoryPageFilters): boolean {
  if (!filters) return true;
  if (typeof filters.pid === 'number' && story.pid !== filters.pid) return false;
  if (filters.processName && story.processName?.toLowerCase() !== filters.processName.toLowerCase()) return false;
  if (filters.remoteIP && story.remoteIP !== filters.remoteIP) return false;
  if (filters.module && !story.modules.includes(filters.module)) return false;
  return true;
}

async function writeGuardianStory(record: GuardianStoryRecord): Promise<void> {
  const store = ensureDb();
  const key = reverseTimestampKey(PREFIX.guardianStories, record.lastSeen, record.id);
  await store.put(key, record);
  await store.put(`${PREFIX.guardianStoryIndex}:${record.correlationKey}`, key);
}

async function loadGuardianStoryByCorrelation(correlationKey: string): Promise<GuardianStoryRecord | null> {
  const store = ensureDb();
  try {
    const compositeKey = (await store.get(`${PREFIX.guardianStoryIndex}:${correlationKey}`)) as string;
    const record = (await store.get(compositeKey)) as GuardianStoryRecord;
    return record;
  } catch (err: any) {
    if (err?.code === 'LEVEL_NOT_FOUND') {
      return null;
    }
    throw err;
  }
}

export async function appendGuardianEvent(event: Omit<GuardianEventRecord, 'id' | 'timestamp'> & { id?: string; timestamp?: number }): Promise<GuardianEventRecord> {
  const store = ensureDb();
  const timestamp = event.timestamp ?? Date.now();
  const record: GuardianEventRecord = {
    ...event,
    id: event.id ?? randomUUID(),
    timestamp,
  };
  const key = reverseTimestampKey(PREFIX.guardianEvents, timestamp, record.id);
  await store.put(key, record);

  const correlationKey = buildGuardianCorrelationKey(record);
  const existing = await loadGuardianStoryByCorrelation(correlationKey);
  const modules = new Set(existing?.modules ?? []);
  modules.add(record.module);
  const updated: GuardianStoryRecord = {
    id: existing?.id ?? randomUUID(),
    correlationKey,
    firstSeen: existing?.firstSeen ?? timestamp,
    lastSeen: Math.max(existing?.lastSeen ?? timestamp, timestamp),
    modules: Array.from(modules),
    maxRiskScore: Math.max(existing?.maxRiskScore ?? 0, record.riskScore ?? 0),
    maxRiskLevel: ((): GuardianStoryRecord['maxRiskLevel'] => {
      const levelOrder: Record<GuardianEventRecord['riskLevel'] | undefined, number> = { Low: 0, Medium: 1, High: 2, Critical: 3 };
      const current = existing?.maxRiskLevel ?? 'Low';
      const candidate = record.riskLevel ?? current;
      return (levelOrder[candidate] ?? 0) >= (levelOrder[current] ?? 0) ? candidate : current;
    })(),
    pid: record.pid ?? existing?.pid,
    processName: record.processName ?? existing?.processName,
    remoteIP: record.remoteIP ?? existing?.remoteIP,
    remoteSubnet: record.remoteSubnet ?? existing?.remoteSubnet,
    policyFingerprint: record.fingerprint ?? existing?.policyFingerprint,
    linkedThreatIds: Array.from(new Set([...(existing?.linkedThreatIds ?? []), ...(record.metadata?.linkedThreatIds ?? [])])),
    linkedPolicyIds: Array.from(new Set([...(existing?.linkedPolicyIds ?? []), ...(record.metadata?.linkedPolicyIds ?? [])])),
    summary: existing?.summary ?? record.metadata?.summary,
  };
  await writeGuardianStory(updated);
  return record;
}

export async function getGuardianStoriesPage(options: GuardianStoryPageOptions): Promise<PageResult<GuardianStoryRecord>> {
  const store = ensureDb();
  const limit = options.limit ?? 25;
  const entries: GuardianStoryRecord[] = [];
  let lastKey: string | null = null;
  const iterator = store.iterator<GuardianStoryRecord>({
    gte: `${PREFIX.guardianStories}:`,
    lt: options.cursor ?? prefixUpperBound(PREFIX.guardianStories),
    reverse: true,
  });
  try {
    for await (const [key, value] of iterator) {
      const story = value as GuardianStoryRecord;
      if (!matchesGuardianFilters(story, options.filters)) {
        continue;
      }
      entries.push(story);
      lastKey = key;
      if (entries.length >= limit) {
        break;
      }
    }
  } finally {
    await iterator.close();
  }
  return {
    entries,
    nextCursor: entries.length === limit && lastKey ? lastKey : null,
  };
}
