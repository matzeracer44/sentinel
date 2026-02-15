import React, { useState, useEffect, useCallback, useMemo, memo, useRef } from 'react';
import { notify } from '../Common/SentinelNotification';
import { useAdmin } from '../../contexts/AdminContext';
import type {
  GuardianStory,
  GuardianThreatIntelRecord,
  GuardianAnomalyConfig,
  ThreatEvent as ThreatEventPayload,
  ThreatTimelineFilters,
} from '../../../shared/ipcSchemas';
import type { ShieldAPI, ElectronAPI } from '../../../preload/preload';
import InfoHint from '../Common/InfoHint';

const getElectronApi = (): ElectronAPI | undefined =>
  (window as Window & { electronAPI?: ElectronAPI }).electronAPI;
const getShieldApi = (): ShieldAPI | undefined => getElectronApi()?.shield;

type FilterState = Partial<ThreatTimelineFilters>;
interface TimelineEvent extends ThreatEventPayload {
  remoteIP: string;
  remoteSubnet: string;
  isManual?: boolean;
}

interface ThreatTimelineProps {
  maxItems?: number;
  onSelectTarget?: (target: { ip: string; subnet?: string; process?: string; pid?: number }) => void;
}

const REFRESH_INTERVAL_MS = 5000;
const DEFAULT_PAGE_SIZE = 25;
const SETTINGS_KEY = 'threatTimeline.filters';
const MANUAL_EVENTS_KEY = 'threatTimeline.manualEvents';

const severityOrder: Record<TimelineEvent['riskLevel'], number> = {
  Critical: 3,
  High: 2,
  Medium: 1,
  Low: 0,
};

const normalizeThreatEvent = (evt: ThreatEventPayload): TimelineEvent => ({
  ...evt,
  remoteIP: evt.remoteIP ?? '—',
  remoteSubnet: evt.remoteSubnet ?? '—',
});

const DEFAULT_RISK_SCORE = 60;
const MAX_MANUAL_EVENTS = 100;
const RISK_LEVELS: TimelineEvent['riskLevel'][] = ['Critical', 'High', 'Medium', 'Low'];

type ManualFormState = {
  processName: string;
  pid: string;
  remoteIP: string;
  remoteSubnet: string;
  reason: string;
  riskLevel: TimelineEvent['riskLevel'];
  riskScore: string;
};

const createManualFormState = (): ManualFormState => ({
  processName: '',
  pid: '',
  remoteIP: '',
  remoteSubnet: '',
  reason: '',
  riskLevel: 'Medium',
  riskScore: DEFAULT_RISK_SCORE.toString(),
});

type TimelineGroup = {
  groupKey: string;
  pid: number;
  processName: string;
  events: TimelineEvent[];
  maxSeverity: number;
  maxScore: number;
  latestTimestamp: number;
};

const createManualEvent = (
  input: {
    processName: string;
    pid?: number | null;
    remoteIP?: string;
    remoteSubnet?: string;
    reason?: string;
    riskLevel: TimelineEvent['riskLevel'];
    riskScore: number;
  }
): TimelineEvent => {
  const timestamp = Date.now();
  return {
    id: `manual-${timestamp}`,
    timestamp,
    processName: input.processName || 'Manual process',
    pid: typeof input.pid === 'number' && Number.isFinite(input.pid) ? input.pid : -1,
    remoteIP: input.remoteIP?.trim() || '—',
    remoteSubnet: input.remoteSubnet?.trim() || '—',
    actionTaken: 'Alerted',
    reason: input.reason || 'Manual intel entry',
    riskLevel: input.riskLevel,
    riskScore: Number.isFinite(input.riskScore) ? input.riskScore : DEFAULT_RISK_SCORE,
    isManual: true,
  } as TimelineEvent;
};

const normalizeManualEventRecord = (raw: any): TimelineEvent | null => {
  if (!raw || typeof raw !== 'object') {
    return null;
  }
  const timestamp = typeof raw.timestamp === 'number' ? raw.timestamp : Date.now();
  const riskLevel = RISK_LEVELS.includes(raw.riskLevel) ? raw.riskLevel : 'Medium';
  const riskScore = Number.isFinite(raw.riskScore) ? raw.riskScore : DEFAULT_RISK_SCORE;
  const pid = typeof raw.pid === 'number' ? raw.pid : -1;
  return {
    id: typeof raw.id === 'string' ? raw.id : `manual-${timestamp}`,
    timestamp,
    processName: typeof raw.processName === 'string' && raw.processName.trim() ? raw.processName : 'Manual process',
    pid,
    remoteIP: typeof raw.remoteIP === 'string' && raw.remoteIP.trim() ? raw.remoteIP : '—',
    remoteSubnet: typeof raw.remoteSubnet === 'string' && raw.remoteSubnet.trim() ? raw.remoteSubnet : '—',
    actionTaken: 'Alerted',
    reason: typeof raw.reason === 'string' && raw.reason.trim() ? raw.reason : 'Manual intel entry',
    riskLevel,
    riskScore,
    isManual: true,
  } as TimelineEvent;
};

const classifyThreat = (evt: TimelineEvent) => {
  const reason = (evt.reason || '').toLowerCase();
  if (reason.includes('tls') || reason.includes('certificate')) {
    return { label: 'TLS Failure', icon: '🔐', accent: 'bg-indigo-500/20 text-indigo-200 border-indigo-400/40' };
  }
  if (reason.includes('c2') || reason.includes('command')) {
    return { label: 'Command & Control', icon: '🕸️', accent: 'bg-purple-600/20 text-purple-200 border-purple-500/40' };
  }
  if (reason.includes('scan') || reason.includes('port')) {
    return { label: 'Port Scan', icon: '📡', accent: 'bg-orange-500/10 text-orange-200 border-orange-400/40' };
  }
  if (reason.includes('exfil') || reason.includes('upload')) {
    return { label: 'Data Exfil', icon: '📤', accent: 'bg-red-600/10 text-red-200 border-red-400/40' };
  }
  return { label: 'Suspicious', icon: '⚠️', accent: 'bg-yellow-500/10 text-yellow-200 border-yellow-400/40' };
};

const levelColor = (level: TimelineEvent['riskLevel']): string => {
  switch (level) {
    case 'Critical':
      return 'border-red-500 bg-red-500/10 text-red-300';
    case 'High':
      return 'border-orange-500 bg-orange-500/10 text-orange-300';
    case 'Medium':
      return 'border-yellow-500 bg-yellow-500/10 text-yellow-300';
    default:
      return 'border-green-500 bg-green-500/10 text-green-300';
  }
};

const actionBadge = (action: TimelineEvent['actionTaken']): string => {
  switch (action) {
    case 'Blocked':
      return 'bg-red-600/80 text-white';
    case 'Throttled':
      return 'bg-yellow-600/80 text-white';
    default:
      return 'bg-blue-600/80 text-white';
  }
};

const clampNumber = (value: number, min: number, max: number) => Math.min(Math.max(value, min), max);
const formatCompactDate = (timestamp?: number | null) => {
  if (!timestamp) {
    return 'Unknown';
  }
  return new Date(timestamp).toLocaleTimeString();
};

const isPrivateIP = (ip?: string): boolean => {
  if (!ip) return false;
  const normalized = ip.trim();
  if (!normalized || normalized === '—') return false;
  return (
    normalized.startsWith('192.168.') ||
    normalized.startsWith('10.') ||
    normalized.startsWith('172.16.') || normalized.startsWith('172.17.') ||
    normalized.startsWith('172.18.') || normalized.startsWith('172.19.') ||
    normalized.startsWith('172.20.') || normalized.startsWith('172.21.') ||
    normalized.startsWith('172.22.') || normalized.startsWith('172.23.') ||
    normalized.startsWith('172.24.') || normalized.startsWith('172.25.') ||
    normalized.startsWith('172.26.') || normalized.startsWith('172.27.') ||
    normalized.startsWith('172.28.') || normalized.startsWith('172.29.') ||
    normalized.startsWith('172.30.') || normalized.startsWith('172.31.') ||
    normalized.startsWith('127.') ||
    normalized.startsWith('0.') ||
    normalized === '::' ||
    normalized === '::1'
  );
};

const ThreatTimeline: React.FC<ThreatTimelineProps> = memo(({ maxItems = 50, onSelectTarget }) => {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [manualEvents, setManualEvents] = useState<TimelineEvent[]>([]);
  const [guardianSummaries, setGuardianSummaries] = useState<Record<string, GuardianStory | null>>({});
  const [guardianThreatIntel, setGuardianThreatIntel] = useState<GuardianThreatIntelRecord[]>([]);
  const [guardianThreatIntelLoading, setGuardianThreatIntelLoading] = useState(false);
  const [guardianThreatIntelError, setGuardianThreatIntelError] = useState<string | null>(null);
  const [guardianAnomalyConfig, setGuardianAnomalyConfig] = useState<GuardianAnomalyConfig | null>(null);
  const [guardianAnomalyError, setGuardianAnomalyError] = useState<string | null>(null);
  const [blockingId, setBlockingId] = useState<string | null>(null);
  const [whitelistingId, setWhitelistingId] = useState<string | null>(null);
  const [filters, setFilters] = useState<FilterState>({});
  const [loading, setLoading] = useState(false);
  const [isPaginating, setIsPaginating] = useState(false);
  const [filtersHydrated, setFiltersHydrated] = useState(false);
  const [manualHydrated, setManualHydrated] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const nextCursorRef = useRef<string | null>(null);
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);
  const { isAdmin } = useAdmin();
  const [filterQuery, setFilterQuery] = useState('');
  const normalizedQuery = filterQuery.trim().toLowerCase();
  const [manualForm, setManualForm] = useState<ManualFormState>(() => createManualFormState());
  const manualLimitReached = manualEvents.length >= MAX_MANUAL_EVENTS;
  const [scopeFilter, setScopeFilter] = useState<'all' | 'external' | 'local'>('external');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [groupPageSize, setGroupPageSize] = useState(40);

  const basePageSize = maxItems || DEFAULT_PAGE_SIZE;
  const pageSize = Math.min(Math.max(basePageSize, 10), 200);
  const pidFilter = typeof filters.pid === 'number' ? filters.pid : null;
  const pidFilterLabel = pidFilter !== null
    ? filters.processName
      ? `${filters.processName} (PID ${pidFilter})`
      : `PID ${pidFilter}`
    : '';
  const guardianIntelIndex = useMemo(() => {
    const map = new Map<string, GuardianThreatIntelRecord[]>();
    guardianThreatIntel.forEach((record) => {
      const key = record.indicator?.trim().toLowerCase();
      if (!key) return;
      if (!map.has(key)) {
        map.set(key, []);
      }
      map.get(key)!.push(record);
    });
    return map;
  }, [guardianThreatIntel]);

  const guardianIntelStats = useMemo(() => {
    if (!guardianThreatIntel.length) {
      return null;
    }
    const typeCounts: Record<string, number> = {};
    const tagCounts: Record<string, number> = {};
    let latest: number | null = null;
    guardianThreatIntel.forEach((record) => {
      typeCounts[record.type] = (typeCounts[record.type] ?? 0) + 1;
      record.tags?.forEach((tag) => {
        const key = tag.toLowerCase();
        tagCounts[key] = (tagCounts[key] ?? 0) + 1;
      });
      if (typeof record.lastSeen === 'number') {
        latest = latest === null ? record.lastSeen : Math.max(latest, record.lastSeen);
      }
    });
    const topTags = Object.entries(tagCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([tag, count]) => ({ tag, count }));
    return { total: guardianThreatIntel.length, typeCounts, topTags, lastSeen: latest };
  }, [guardianThreatIntel]);

  const guardianIntelForIndicator = useCallback(
    (indicator?: string | null) => {
      if (!indicator) {
        return [];
      }
      const key = indicator.trim().toLowerCase();
      if (!key) {
        return [];
      }
      return guardianIntelIndex.get(key) ?? [];
    },
    [guardianIntelIndex],
  );

  const guardianAnomalySummary = useMemo(() => {
    if (!guardianAnomalyConfig) {
      return null;
    }
    return {
      enabled: guardianAnomalyConfig.enabled,
      sensitivity: guardianAnomalyConfig.sensitivity,
      windowHours: guardianAnomalyConfig.windowMinutes / 60,
      minSamples: guardianAnomalyConfig.minSamples,
    };
  }, [guardianAnomalyConfig]);

  const persistFilters = useCallback(
    (updater: FilterState | ((prev: FilterState) => FilterState)) => {
      setFilters((prev) => {
        const next = typeof updater === 'function' ? (updater as (prev: FilterState) => FilterState)(prev) : updater;
        const electronApi = getElectronApi();
        if (electronApi?.saveSettings && filtersHydrated) {
          electronApi.saveSettings(SETTINGS_KEY, next).catch((err: unknown) =>
            console.warn('[ThreatTimeline] Failed to persist filters', err)
          );
        }
        return next;
      });
    },
    [filtersHydrated]
  );

  const persistManuals = useCallback(
    (updater: TimelineEvent[] | ((prev: TimelineEvent[]) => TimelineEvent[])) => {
      setManualEvents((prev) => {
        const resolved = typeof updater === 'function' ? (updater as (prev: TimelineEvent[]) => TimelineEvent[])(prev) : updater;
        const normalized = resolved
          .map((evt) => ({ ...evt, isManual: true }))
          .slice(0, MAX_MANUAL_EVENTS);
        if (manualHydrated) {
          const electronApi = getElectronApi();
          electronApi?.saveSettings?.(MANUAL_EVENTS_KEY, normalized).catch((err: unknown) =>
            console.warn('[ThreatTimeline] Failed to persist manual events', err)
          );
        }
        return normalized;
      });
    },
    [manualHydrated]
  );

  const fetchGuardianThreatIntel = useCallback(async () => {
    const shield = getShieldApi();
    if (!shield?.getGuardianThreatIntel) {
      setGuardianThreatIntelError('Guardian intel API unavailable');
      return;
    }
    setGuardianThreatIntelLoading(true);
    setGuardianThreatIntelError(null);
    try {
      const response = await shield.getGuardianThreatIntel({ limit: 50 });
      if (!response?.success || !Array.isArray(response.records)) {
        const errMsg = 'error' in response ? response.error : 'Unable to load Guardian intel';
        throw new Error(errMsg || 'Unable to load Guardian intel');
      }
      const records = response.records as GuardianThreatIntelRecord[];
      records.sort((a, b) => (b.lastSeen ?? 0) - (a.lastSeen ?? 0));
      setGuardianThreatIntel(records);
    } catch (err: any) {
      setGuardianThreatIntelError(err?.message || 'Failed to fetch Guardian intel');
    } finally {
      setGuardianThreatIntelLoading(false);
    }
  }, []);

  const refreshGuardianIntelForIndicator = useCallback(async (indicator: string) => {
    const trimmed = indicator?.trim();
    if (!trimmed) {
      return;
    }
    const shield = getShieldApi();
    if (!shield?.refreshGuardianThreatIntel) {
      setGuardianThreatIntelError('Guardian intel refresh API unavailable');
      return;
    }
    try {
      const response = await shield.refreshGuardianThreatIntel({ indicator: trimmed, source: 'threat-timeline' });
      if (!response?.success) {
        const errMsg = 'error' in response ? response.error : 'Unable to refresh Guardian intel';
        throw new Error(errMsg || 'Unable to refresh Guardian intel');
      }
      const refreshed = (response.records ?? []) as GuardianThreatIntelRecord[];
      if (refreshed.length) {
        setGuardianThreatIntel((prev) => {
          const filtered = prev.filter((record) => {
            const key = record.indicator.trim().toLowerCase();
            return !refreshed.some((incoming) => incoming.indicator.trim().toLowerCase() === key);
          });
          return [...refreshed, ...filtered].slice(0, 200);
        });
      }
    } catch (err: any) {
      setGuardianThreatIntelError(err?.message || `Intel refresh failed for ${trimmed}`);
    }
  }, []);

  const loadGuardianAnomalyConfig = useCallback(async () => {
    const shield = getShieldApi();
    if (!shield?.getGuardianAnomalyConfig) {
      setGuardianAnomalyError('Guardian anomaly API unavailable');
      return;
    }
    setGuardianAnomalyError(null);
    try {
      const response = await shield.getGuardianAnomalyConfig();
      if (!response?.success || !response.config) {
        const errMsg = 'error' in response ? response.error : 'Unable to load Guardian anomaly config';
        throw new Error(errMsg || 'Unable to load Guardian anomaly config');
      }
      setGuardianAnomalyConfig(response.config as GuardianAnomalyConfig);
    } catch (err: any) {
      setGuardianAnomalyError(err?.message || 'Failed to load anomaly config');
    }
  }, []);

  const fetchEvents = useCallback(
    async ({ reset = false, cursor }: { reset?: boolean; cursor?: string | null } = {}) => {
      const shield = getShieldApi();
      if (!shield?.getThreatEvents) {
        setError('Threat event API unavailable');
        return;
      }
      if (!filtersHydrated) {
        return;
      }
      if (reset) {
        setLoading(true);
        setNextCursor(null);
        nextCursorRef.current = null;
      } else {
        const effectiveCursor = cursor ?? nextCursorRef.current;
        if (!effectiveCursor) {
          setIsPaginating(false);
          return;
        }
        setIsPaginating(true);
      }
      setError(null);
      try {
        const effectiveCursor = reset ? undefined : cursor ?? nextCursorRef.current ?? undefined;
        const response = await shield.getThreatEvents({
          limit: pageSize,
          cursor: effectiveCursor,
          filters: Object.keys(filters).length ? filters : undefined,
        } as Record<string, unknown>);
        if (!response?.success || !Array.isArray(response.events)) {
          throw new Error(response?.error || 'Unable to fetch threat events');
        }
        const mapped = response.events.map(normalizeThreatEvent);
        const newCursor = response.nextCursor ?? null;
        setNextCursor(newCursor);
        nextCursorRef.current = newCursor;
        setEvents((prev) => {
          if (reset) {
            return mapped;
          }
          const existingIds = new Set(prev.map((evt) => evt.id));
          const merged = mapped.filter((evt) => !existingIds.has(evt.id));
          return [...prev, ...merged];
        });
      } catch (err: any) {
        console.error('[ThreatTimeline] Failed to fetch events', err);
        setError(err?.message || 'Failed to load threat events');
      } finally {
        if (reset) {
          setLoading(false);
        } else {
          setIsPaginating(false);
        }
      }
    },
    [filters, filtersHydrated, pageSize]
  );

  useEffect(() => {
    let mounted = true;
    const electronApi = getElectronApi();
    (async () => {
      try {
        const res = await electronApi?.getSettings?.();
        const settings = res?.settings ?? {};
        const savedFilters = settings[SETTINGS_KEY];
        if (mounted && savedFilters && typeof savedFilters === 'object') {
          setFilters(savedFilters);
        }
        const savedManuals = settings[MANUAL_EVENTS_KEY];
        if (mounted && Array.isArray(savedManuals)) {
          const hydratedManuals = savedManuals
            .map((evt: any) => normalizeManualEventRecord(evt))
            .filter(Boolean) as TimelineEvent[];
          setManualEvents(hydratedManuals);
        }
      } catch (err) {
        console.warn('[ThreatTimeline] Failed to hydrate filters/manual entries', err);
      } finally {
        if (mounted) {
          setFiltersHydrated(true);
          setManualHydrated(true);
        }
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    fetchGuardianThreatIntel();
    loadGuardianAnomalyConfig();
  }, [fetchGuardianThreatIntel, loadGuardianAnomalyConfig]);

  useEffect(() => {
    if (!filtersHydrated) {
      return;
    }
    fetchEvents({ reset: true });
  }, [fetchEvents, filtersHydrated]);

  useEffect(() => {
    if (!filtersHydrated || !autoRefresh) {
      return;
    }
    const interval = setInterval(() => fetchEvents({ reset: true }), REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchEvents, filtersHydrated]);

  const handleQuickBlock = useCallback(async (evt: TimelineEvent) => {
    if (!isAdmin) {
      notify.error('Admin privileges are required for quick block actions.');
      return;
    }
    if (!evt.remoteSubnet || evt.remoteSubnet === '—') {
      notify.error('No valid subnet to block');
      return;
    }
    setBlockingId(evt.id);
    try {
      const shield = getShieldApi();
      const res = await shield?.quickBlockSubnet?.(evt.remoteSubnet, `Quick block: ${evt.processName} (${evt.reason || 'threat detected'})`);
      if (res?.success) {
        notify.success(res.message || `Blocked ${evt.remoteSubnet}`);
      } else {
        notify.error(typeof res?.error === 'string' ? res.error : 'Failed to block subnet');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      notify.error(`Error: ${msg}`);
    } finally {
      setBlockingId(null);
    }
  }, [isAdmin]);

  const handleSendToFirewall = useCallback((evt: TimelineEvent) => {
    if (!onSelectTarget) return;
    onSelectTarget({
      ip: evt.remoteIP,
      subnet: evt.remoteSubnet,
      process: evt.processName,
      pid: evt.pid,
    });
  }, [onSelectTarget]);

  const handleWhitelist = useCallback(async (evt: TimelineEvent) => {
    if (evt.isManual) {
      persistManuals((prev) => prev.filter((item) => item.id !== evt.id));
      notify.success('Manual entry removed');
      return;
    }
    if (!isAdmin) {
      notify.error('Admin privileges are required to whitelist threats.');
      return;
    }
    const shield = getShieldApi();
    if (!shield?.whitelistThreat) {
      notify.error('Whitelist API not available.');
      return;
    }
    setWhitelistingId(evt.id);
    try {
      const payload = {
        ip: evt.remoteIP !== '—' ? evt.remoteIP : undefined,
        subnet: evt.remoteSubnet !== '—' ? evt.remoteSubnet : undefined,
        processName: evt.processName,
        pid: evt.pid,
        reason: evt.reason,
      };
      const res = await shield.whitelistThreat(payload);
      if (!res?.success) {
        throw new Error(res?.error || 'Whitelist call failed');
      }
      setEvents((prev) => prev.filter((item) => item.id !== evt.id));
      notify.success(`Whitelisted ${payload.subnet || payload.ip || 'target'}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      notify.error(`Failed to whitelist threat: ${msg}`);
    } finally {
      setWhitelistingId(null);
    }
  }, [isAdmin, persistManuals]);

  const combinedEvents = useMemo(() => {
    const merged = [...manualEvents, ...events];
    return merged.sort((a, b) => b.timestamp - a.timestamp);
  }, [events, manualEvents]);

  const scopedEvents = useMemo(() => {
    if (scopeFilter === 'all') return combinedEvents;
    const predicate = scopeFilter === 'external' ? (evt: TimelineEvent) => !isPrivateIP(evt.remoteIP) : (evt: TimelineEvent) => isPrivateIP(evt.remoteIP);
    return combinedEvents.filter(predicate);
  }, [combinedEvents, scopeFilter]);

  const groupedEvents = useMemo(() => {
    const groups = new Map<string, TimelineGroup>();
    scopedEvents.forEach((evt) => {
      const pid = typeof evt.pid === 'number' && Number.isFinite(evt.pid) ? evt.pid : -1;
      const processName = evt.processName || 'Unknown process';
      const key = pid >= 0 ? `pid:${pid}` : `proc:${processName.toLowerCase()}${evt.isManual ? ':manual' : ''}`;
      if (!groups.has(key)) {
        groups.set(key, {
          groupKey: key,
          pid,
          processName,
          events: [],
          maxSeverity: severityOrder[evt.riskLevel],
          maxScore: evt.riskScore,
          latestTimestamp: evt.timestamp,
        });
      }
      const bucket = groups.get(key)!;
      bucket.events.push(evt);
      bucket.processName = processName;
      bucket.maxSeverity = Math.max(bucket.maxSeverity, severityOrder[evt.riskLevel]);
      bucket.maxScore = Math.max(bucket.maxScore, evt.riskScore);
      bucket.latestTimestamp = Math.max(bucket.latestTimestamp, evt.timestamp);
    });

    const list = Array.from(groups.values());
    list.forEach((bucket) => {
      bucket.events.sort((a, b) => b.timestamp - a.timestamp);
    });

    return list.sort((a, b) => {
      if (b.maxSeverity !== a.maxSeverity) return b.maxSeverity - a.maxSeverity;
      if (b.maxScore !== a.maxScore) return b.maxScore - a.maxScore;
      return b.latestTimestamp - a.latestTimestamp;
    });
  }, [scopedEvents]);

  const filteredGroups = useMemo(() => {
    if (!normalizedQuery) return groupedEvents;
    return groupedEvents.filter((group) => {
      const tokens = [
        group.processName,
        group.pid > 0 ? String(group.pid) : undefined,
        ...group.events.flatMap((evt) => [
          evt.remoteIP,
          evt.remoteSubnet,
          evt.reason,
          evt.actionTaken,
          evt.isManual ? 'manual' : undefined,
        ]),
      ]
        .filter(Boolean)
        .map((token) => token!.toLowerCase());
      return tokens.some((token) => token.includes(normalizedQuery));
    });
  }, [groupedEvents, normalizedQuery]);

  const visibleGroups = useMemo(() => filteredGroups.slice(0, groupPageSize), [filteredGroups, groupPageSize]);
  const hasMoreGroups = filteredGroups.length > groupPageSize;
  const hasMoreServerPages = Boolean(nextCursor);

  const handleLoadMoreGroups = useCallback(() => {
    setGroupPageSize((prev) => prev + 30);
  }, []);

  const handleLoadMoreServer = useCallback(() => {
    if (!nextCursor) return;
    fetchEvents({ cursor: nextCursor });
  }, [fetchEvents, nextCursor]);

  useEffect(() => {
    setGroupPageSize(40);
  }, [scopeFilter, normalizedQuery]);

  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());

  const guardianRequestKeys = useRef<Set<string>>(new Set());

  const fetchGuardianSummary = useCallback(async (group: TimelineGroup) => {
    const shield = getShieldApi();
    if (!shield?.getGuardianStories) {
      return;
    }
    const correlationKey = group.groupKey;
    if (guardianRequestKeys.current.has(correlationKey)) {
      return;
    }
    guardianRequestKeys.current.add(correlationKey);
    try {
      const response = await shield.getGuardianStories({
        limit: 1,
        pid: group.pid >= 0 ? group.pid : undefined,
        processName: group.processName,
        remoteIP: group.events[0]?.remoteIP !== '—' ? group.events[0].remoteIP : undefined,
      });
      const summary = response?.success && Array.isArray(response.stories) ? response.stories[0] ?? null : null;
      setGuardianSummaries((prev) => ({ ...prev, [correlationKey]: summary }));
    } catch (err) {
      console.warn('[ThreatTimeline] Guardian summary fetch failed', err);
      setGuardianSummaries((prev) => ({ ...prev, [correlationKey]: null }));
    } finally {
      guardianRequestKeys.current.delete(correlationKey);
    }
  }, []);

  useEffect(() => {
    groupedEvents.forEach((group) => {
      if (guardianSummaries[group.groupKey] === undefined) {
        void fetchGuardianSummary(group);
      }
    });
  }, [groupedEvents, guardianSummaries, fetchGuardianSummary]);

  const toggleGroup = useCallback((groupKey: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(groupKey)) {
        next.delete(groupKey);
      } else {
        next.add(groupKey);
      }
      return next;
    });
  }, []);

  useEffect(() => {
    setExpandedGroups((prev) => {
      const validKeys = new Set(filteredGroups.map((group) => group.groupKey));
      let mutated = false;
      const next = new Set<string>();
      prev.forEach((key) => {
        if (validKeys.has(key)) {
          next.add(key);
        } else {
          mutated = true;
        }
      });
      return mutated ? next : prev;
    });
  }, [filteredGroups]);

  const handleManualFieldChange = useCallback(<K extends keyof ManualFormState>(field: K, value: ManualFormState[K]) => {
    setManualForm((prev) => ({ ...prev, [field]: value }));
  }, []);

  const resetManualForm = useCallback(() => {
    setManualForm(createManualFormState());
  }, []);

  const handleCreateManualEntry = useCallback(
    (event?: React.FormEvent) => {
      event?.preventDefault();
      const trimmedProcess = manualForm.processName.trim();
      if (!trimmedProcess) {
        notify.error('Process or binary name is required.');
        return;
      }
      if (manualLimitReached) {
        notify.error(`Manual entry limit reached (${MAX_MANUAL_EVENTS}). Remove existing entries to add more.`);
        return;
      }
      const parsedPid = manualForm.pid.trim() ? Number(manualForm.pid.trim()) : undefined;
      const parsedScore = Number(manualForm.riskScore.trim());
      const manualEntry = createManualEvent({
        processName: trimmedProcess,
        pid: typeof parsedPid === 'number' && Number.isFinite(parsedPid) ? parsedPid : undefined,
        remoteIP: manualForm.remoteIP.trim() || undefined,
        remoteSubnet: manualForm.remoteSubnet.trim() || undefined,
        reason: manualForm.reason.trim() || undefined,
        riskLevel: manualForm.riskLevel,
        riskScore: Number.isFinite(parsedScore) ? parsedScore : DEFAULT_RISK_SCORE,
      });
      persistManuals((prev) => [manualEntry, ...prev]);
      resetManualForm();
    },
    [manualForm, manualLimitReached, persistManuals, resetManualForm]
  );

  const handleRemoveManualEntry = useCallback(
    (id: string) => {
      persistManuals((prev) => prev.filter((evt) => evt.id !== id));
    },
    [persistManuals]
  );

  const clearManualEntries = useCallback(() => {
    if (!manualEvents.length) {
      return;
    }
    persistManuals([]);
    notify.success('Manual entries cleared');
  }, [manualEvents.length, persistManuals]);

  const handleManualRefresh = useCallback(() => {
    fetchEvents({ reset: true });
  }, [fetchEvents]);

  return (
    <div className="h-full flex flex-col bg-[var(--sentinel-bg)] text-white overflow-hidden">
      <div className="flex-shrink-0 p-4 border-b border-gray-800">
        <h2 className="text-xl font-bold bg-gradient-to-r from-red-400 to-orange-500 bg-clip-text text-transparent">
          Threat Timeline
        </h2>
        <p className="text-gray-400 text-xs max-w-3xl">
          Real-time feed of Medium+ risk events with Sentinel transparency overlays—tap the "?" badges to see what each control
          means before taking action.
        </p>
        <div className="flex items-center justify-between mt-3 text-xs text-gray-400 flex-wrap gap-2">
          {pidFilter !== null ? (
            <span className="px-2 py-0.5 rounded border border-purple-500/40 text-purple-200">
              PID filter: {pidFilterLabel || `PID ${pidFilter}`}
              <button
                className="ml-2 text-[10px] text-gray-400 hover:text-white"
                onClick={() => {
                  persistFilters((prev) => {
                    const next = { ...prev };
                    delete next.pid;
                    delete next.processName;
                    return next;
                  });
                }}
              >
                Clear
              </button>
            </span>
          ) : (
            <span>No PID filter</span>
          )}
          <div className="flex items-center gap-3">
            {loading && <span className="text-cyan-400">Refreshing…</span>}
            {error && <span className="text-red-400">{error}</span>}
          </div>
        </div>
        <div className="mt-3 flex gap-3 flex-wrap md:flex-nowrap">
          <input
            type="text"
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            placeholder="Filter threats by name, PID, IP, subnet, reason…"
            className="flex-1 min-w-[220px] px-3 py-2 bg-[#12121a] border border-gray-800 rounded-lg text-sm text-white placeholder-gray-600 focus:border-red-500 focus:outline-none"
          />
          <span className="text-[11px] text-gray-500 self-center">
            Showing {filteredGroups.length} PID bundle{filteredGroups.length === 1 ? '' : 's'}
          </span>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-4 text-[11px] text-gray-400">
          <InfoHint
            label="Why bundle by PID?"
            title="PID bundles"
            description="Every process ID becomes a capsule so you can reason about all alerts from the same executable without scrolling through noise."
            details={[{ label: 'Grouping key', value: 'PID or process name' }, { label: 'Refresh rate', value: '5 seconds' }]}
          />
          <InfoHint
            label="Auto-refresh"
            title="Live polling"
            description="Sentinel polls the telemetry store every 5 seconds. Disable auto-refresh if you want to inspect a snapshot or reduce CPU usage."
          />
          <InfoHint
            label="Scope filter"
            title="Local vs external"
            description="Switch between external/public IP traffic, LAN chatter, or everything. Helpful when localhost noise is drowning out remote threats."
          />
        </div>
        <div className="mt-3 flex flex-wrap gap-3 items-center text-[11px] text-gray-400">
          <div className="flex rounded-lg overflow-hidden border border-gray-800">
            {[
              { key: 'all', label: 'All' },
              { key: 'external', label: 'External' },
              { key: 'local', label: 'Local' },
            ].map(({ key, label }) => (
              <button
                key={key}
                className={`px-3 py-1 text-xs transition ${
                  scopeFilter === key
                    ? 'bg-red-500/20 text-red-200'
                    : 'bg-[#12121a] text-gray-500 hover:text-gray-300'
                }`}
                onClick={() => setScopeFilter(key as typeof scopeFilter)}
              >
                {label}
              </button>
            ))}
          </div>
          <button
            type="button"
            className={`px-3 py-1 rounded border text-xs font-semibold transition ${
              autoRefresh ? 'border-green-500/40 text-green-200 bg-green-500/10' : 'border-gray-700 text-gray-400'
            }`}
            onClick={() => setAutoRefresh((prev) => !prev)}
          >
            {autoRefresh ? 'Auto-refresh ON' : 'Auto-refresh OFF'}
          </button>
          <button
            type="button"
            className="px-3 py-1 rounded border border-gray-700 text-gray-300 hover:border-gray-500 text-xs"
            onClick={handleManualRefresh}
          >
            Manual Refresh
          </button>
          <button
            type="button"
            className={`px-3 py-1 rounded border text-xs transition ${guardianThreatIntelLoading ? 'border-cyan-500/40 text-cyan-200 bg-cyan-500/10' : 'border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/10'}`}
            onClick={fetchGuardianThreatIntel}
            disabled={guardianThreatIntelLoading}
          >
            {guardianThreatIntelLoading ? 'Guardian Intel…' : 'Refresh Guardian Intel'}
          </button>
          <button
            type="button"
            className="px-3 py-1 rounded border border-indigo-500/50 text-indigo-200 hover:bg-indigo-500/10 text-xs"
            onClick={loadGuardianAnomalyConfig}
          >
            Sync Anomaly Baseline
          </button>
        </div>
        {(guardianThreatIntelError || guardianAnomalyError) && (
          <div className="mt-2 text-xs text-red-400 flex flex-col gap-1">
            {guardianThreatIntelError && <span>{guardianThreatIntelError}</span>}
            {guardianAnomalyError && <span>{guardianAnomalyError}</span>}
          </div>
        )}
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-3 text-xs text-gray-200">
            <div className="flex items-center justify-between">
              <p className="font-semibold text-cyan-200">Guardian Intel Cache</p>
              <span className="text-[10px] text-gray-400">{guardianThreatIntel.length} indicators</span>
            </div>
            {guardianIntelStats ? (
              <div className="mt-2 flex flex-wrap gap-2">
                {Object.entries(guardianIntelStats.typeCounts).map(([type, count]) => (
                  <span key={type} className="px-2 py-0.5 rounded-full border border-gray-700">
                    {type} • {count}
                  </span>
                ))}
                {guardianIntelStats.lastSeen && (
                  <span className="text-gray-400">Updated {formatCompactDate(guardianIntelStats.lastSeen)}</span>
                )}
              </div>
            ) : (
              <p className="mt-2 text-gray-400">No cached intel yet.</p>
            )}
            {guardianIntelStats?.topTags?.length ? (
              <div className="mt-2 flex flex-wrap gap-1 text-[10px] text-gray-300">
                {guardianIntelStats.topTags.map(({ tag, count }) => (
                  <span key={tag} className="px-2 py-0.5 rounded-full border border-gray-700">
                    #{tag} ({count})
                  </span>
                ))}
              </div>
            ) : null}
          </div>
          <div className="rounded-lg border border-indigo-500/30 bg-indigo-500/5 p-3 text-xs text-gray-200">
            <div className="flex items-center justify-between">
              <p className="font-semibold text-indigo-200">Anomaly Baseline</p>
              {guardianAnomalySummary ? (
                <span className="text-[10px] text-gray-400">
                  Window {guardianAnomalySummary.windowHours.toFixed(1)}h
                </span>
              ) : null}
            </div>
            {guardianAnomalySummary ? (
              <div className="mt-2 flex flex-wrap gap-2">
                <span className={`px-2 py-0.5 rounded-full border ${guardianAnomalySummary.enabled ? 'border-emerald-500/40 text-emerald-200' : 'border-gray-700 text-gray-400'}`}>
                  {guardianAnomalySummary.enabled ? 'Enabled' : 'Paused'}
                </span>
                <span className="px-2 py-0.5 rounded-full border border-indigo-500/40 text-indigo-200">
                  Sensitivity {guardianAnomalySummary.sensitivity}
                </span>
                <span className="px-2 py-0.5 rounded-full border border-gray-700 text-gray-300">
                  Min samples {guardianAnomalySummary.minSamples}
                </span>
              </div>
            ) : (
              <p className="mt-2 text-gray-400">Baseline will load after Guardian sync.</p>
            )}
          </div>
        </div>
        <div className="mt-4 sentinel-panel p-4 space-y-3">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <div className="flex items-center gap-2">
              <span className="text-white font-semibold">Manual Intel Injection</span>
              <span className="text-[10px] text-gray-500 tracking-wide">
                {manualEvents.length}/{MAX_MANUAL_EVENTS} stored
              </span>
              <InfoHint
                title="Manual events"
                description="Use this when you spot suspicious behaviour outside Sentinel (e.g., SOC alert) and want to annotate the timeline with your own notes."
                details={[{ label: 'Storage limit', value: `${MAX_MANUAL_EVENTS}` }, { label: 'Action taken', value: 'Alerted only' }]}
              />
            </div>
            <button
              type="button"
              className="text-[10px] text-gray-400 hover:text-white disabled:opacity-40"
              onClick={clearManualEntries}
              disabled={!manualEvents.length}
            >
              Clear saved
            </button>
          </div>
          <form className="space-y-2" onSubmit={handleCreateManualEntry}>
            <div className="grid gap-2 md:grid-cols-3">
              <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-gray-500">
                Process / Binary*
                <input
                  type="text"
                  value={manualForm.processName}
                  onChange={(e) => handleManualFieldChange('processName', e.target.value)}
                  className="px-3 py-2 rounded bg-black/40 border border-gray-800 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
                  placeholder="powershell.exe"
                  required
                />
              </label>
              <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-gray-500">
                PID
                <input
                  type="text"
                  inputMode="numeric"
                  value={manualForm.pid}
                  onChange={(e) => handleManualFieldChange('pid', e.target.value.replace(/[^0-9-]/g, ''))}
                  className="px-3 py-2 rounded bg-black/40 border border-gray-800 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
                  placeholder="1234"
                />
              </label>
              <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-gray-500">
                Risk Level
                <select
                  value={manualForm.riskLevel}
                  onChange={(e) => handleManualFieldChange('riskLevel', e.target.value as TimelineEvent['riskLevel'])}
                  className="px-3 py-2 rounded bg-black/40 border border-gray-800 text-white focus:border-red-500 focus:outline-none"
                >
                  {RISK_LEVELS.map((level) => (
                    <option key={level} value={level} className="bg-black">
                      {level}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="grid gap-2 md:grid-cols-3">
              <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-gray-500">
                Remote IP
                <input
                  type="text"
                  value={manualForm.remoteIP}
                  onChange={(e) => handleManualFieldChange('remoteIP', e.target.value)}
                  className="px-3 py-2 rounded bg-black/40 border border-gray-800 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
                  placeholder="185.33.44.11"
                />
              </label>
              <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-gray-500">
                Remote Subnet
                <input
                  type="text"
                  value={manualForm.remoteSubnet}
                  onChange={(e) => handleManualFieldChange('remoteSubnet', e.target.value)}
                  className="px-3 py-2 rounded bg-black/40 border border-gray-800 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
                  placeholder="185.33.44.0/24"
                />
              </label>
              <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-gray-500">
                Risk Score
                <input
                  type="text"
                  inputMode="numeric"
                  value={manualForm.riskScore}
                  onChange={(e) => handleManualFieldChange('riskScore', e.target.value.replace(/[^0-9]/g, ''))}
                  className="px-3 py-2 rounded bg-black/40 border border-gray-800 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
                  placeholder="60"
                />
              </label>
            </div>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-gray-500">
              Reason / Intel Summary
              <textarea
                value={manualForm.reason}
                onChange={(e) => handleManualFieldChange('reason', e.target.value)}
                rows={2}
                className="px-3 py-2 rounded bg-black/40 border border-gray-800 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
                placeholder="Detected credential stuffing activity"
              />
            </label>
            <div className="flex flex-wrap gap-2 text-[11px] text-gray-400">
              <button
                type="submit"
                className="px-4 py-2 rounded bg-red-600/80 hover:bg-red-600 text-white text-xs font-semibold disabled:opacity-50"
                disabled={manualLimitReached}
              >
                {manualLimitReached ? 'Manual Capacity Reached' : 'Inject Threat Event'}
              </button>
              <button
                type="button"
                className="px-4 py-2 rounded border border-gray-700 text-gray-300 hover:border-gray-500"
                onClick={resetManualForm}
              >
                Reset Form
              </button>
            </div>
          </form>
          {manualEvents.length > 0 && (
            <div className="text-[11px] text-gray-400">
              <span className="uppercase tracking-wide text-[10px] text-gray-500">Recent manual inserts</span>
              <div className="mt-2 flex flex-wrap gap-2">
                {manualEvents.slice(0, 6).map((evt) => (
                  <span
                    key={evt.id}
                    className="inline-flex items-center gap-2 px-2 py-1 rounded-full border border-sky-600/40 text-sky-200 bg-sky-500/5"
                  >
                    {evt.processName} • {evt.riskLevel}
                    <button
                      type="button"
                      className="text-[10px] text-gray-400 hover:text-white"
                      onClick={() => handleRemoveManualEntry(evt.id)}
                    >
                      ✕
                    </button>
                  </span>
                ))}
                {manualEvents.length > 6 && (
                  <span className="px-2 py-1 rounded-full border border-gray-700 text-gray-400 text-[10px]">
                    +{manualEvents.length - 6} more
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
      <div ref={scrollContainerRef} className="flex-1 min-h-0 overflow-y-auto p-4 space-y-2">
        {visibleGroups.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-gray-500 text-sm gap-2">
            <span>No threats detected</span>
            {pidFilter !== null && <span className="text-xs text-gray-600">PID filter may be hiding other events.</span>}
          </div>
        ) : (
          <>
            {visibleGroups.map((bundle) => {
              if (!bundle.events.length) {
                return null;
              }
              const topEvent = bundle.events[0];
              const classification = classifyThreat(topEvent);
              const isExpanded = expandedGroups.has(bundle.groupKey);
              const pidLabel = bundle.pid > 0 ? `PID ${bundle.pid}` : 'PID unknown';
              const hasManual = bundle.events.some((evt) => evt.isManual);
              const guardianSummary = guardianSummaries[bundle.groupKey];
              const guardianIntelMatches = guardianIntelForIndicator(topEvent.remoteIP);
              return (
                <div
                  key={bundle.groupKey}
                  className={`rounded-lg border p-3 text-xs ${levelColor(topEvent.riskLevel)} bg-[var(--sentinel-panel)]/60 backdrop-blur`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-white">
                        {bundle.processName} ({pidLabel}) • {bundle.events.length} alert{bundle.events.length === 1 ? '' : 's'}
                      </span>
                      {hasManual && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold border border-sky-500/60 bg-sky-500/10 text-sky-200">
                          Manual
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border ${classification.accent}`}>
                        <span>{classification.icon}</span>
                        {classification.label}
                      </span>
                      {guardianIntelMatches.length ? (
                        <span className="px-2 py-0.5 rounded-full border border-cyan-500/60 text-cyan-100 text-[10px]">
                          Guardian intel {guardianIntelMatches.length}
                        </span>
                      ) : null}
                      <button
                        type="button"
                        className="px-2 py-0.5 rounded border border-blue-500/50 text-blue-300 hover:bg-blue-500/10"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleSendToFirewall(topEvent);
                        }}
                      >
                        Send to Firewall
                      </button>
                      <button
                        type="button"
                        className="px-2 py-0.5 rounded border border-cyan-500/50 text-cyan-200 hover:bg-cyan-500/10"
                        onClick={(e) => {
                          e.stopPropagation();
                          refreshGuardianIntelForIndicator(topEvent.remoteIP);
                        }}
                      >
                        Refresh intel
                      </button>
                      <button
                        type="button"
                        className="px-2 py-0.5 rounded border border-gray-800/70 text-gray-200 hover:bg-gray-700"
                        onClick={() => toggleGroup(bundle.groupKey)}
                      >
                        {isExpanded ? 'Collapse' : 'Expand'}
                      </button>
                    </div>
                  </div>
                  <div className="text-[11px] text-gray-300 flex flex-wrap gap-3 mt-1">
                    <span className="text-white font-semibold">
                      Top Risk: {topEvent.riskLevel} • Score {topEvent.riskScore}
                    </span>
                    <span>
                      Last action: <span className={`px-2 py-0.5 rounded ${actionBadge(topEvent.actionTaken)}`}>{topEvent.actionTaken || 'Observed'}</span>
                    </span>
                    <span>Latest remote: <span className="font-mono text-gray-100">{topEvent.remoteIP}</span></span>
                    <span>Subnet: <span className="font-mono text-gray-100">{topEvent.remoteSubnet}</span></span>
                  </div>

                  {guardianSummary && (
                    <div className="mt-3 rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-3 text-[11px] text-gray-200">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="text-xs font-semibold text-cyan-200">Guardian Story</p>
                        <span className="px-2 py-0.5 rounded-full border border-cyan-500/40 text-cyan-100">
                          {guardianSummary.modules?.join(', ') || 'Multi-module'}
                        </span>
                      </div>
                      <p className="mt-1 text-gray-300">
                        {guardianSummary.summary || 'Correlated telemetry from Guardian correlator.'}
                      </p>
                      <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-gray-400">
                        {guardianSummary.firstSeen && (
                          <span>First seen: {new Date(guardianSummary.firstSeen).toLocaleString()}</span>
                        )}
                        {guardianSummary.lastSeen && (
                          <span>Last seen: {new Date(guardianSummary.lastSeen).toLocaleString()}</span>
                        )}
                        {guardianSummary.maxRiskLevel && (
                          <span className="px-2 py-0.5 rounded-full border border-red-500/40 text-red-200">
                            Risk: {guardianSummary.maxRiskLevel}
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {guardianIntelMatches.length > 0 && (
                    <div className="mt-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 text-[11px] text-gray-200">
                      <div className="flex items-center justify-between">
                        <p className="text-xs font-semibold text-cyan-200">Indicator reputation</p>
                        <span className="text-[10px] text-gray-400">
                          {guardianIntelMatches.length} record{guardianIntelMatches.length === 1 ? '' : 's'}
                        </span>
                      </div>
                      <div className="mt-2 grid gap-2 md:grid-cols-guardian-2">
                        {guardianIntelMatches.map((intel) => (
                          <div key={`${bundle.groupKey}-${intel.type}-${intel.indicator}`} className="rounded border border-gray-800 bg-black/30 p-2">
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono text-white text-xs break-all">{intel.indicator}</span>
                              <span className="px-2 py-0.5 rounded-full border border-cyan-500/40 text-cyan-100 text-[10px] uppercase">
                                {intel.type}
                              </span>
                            </div>
                            <div className="mt-1 flex flex-wrap gap-2 text-[10px] text-gray-400">
                              {typeof intel.reputation === 'number' && (
                                <span className="px-2 py-0.5 rounded border border-red-500/30 text-red-200">
                                  Rep {intel.reputation}
                                </span>
                              )}
                              {typeof intel.confidence === 'number' && (
                                <span className="px-2 py-0.5 rounded border border-amber-500/30 text-amber-200">
                                  Confidence {intel.confidence}
                                </span>
                              )}
                              <span className="px-2 py-0.5 rounded border border-gray-700 text-gray-300">
                                Sources {intel.sources.length}
                              </span>
                              {intel.lastSeen && <span>Seen {formatCompactDate(intel.lastSeen)}</span>}
                            </div>
                            {intel.tags?.length ? (
                              <div className="mt-1 flex flex-wrap gap-1 text-[10px] text-gray-300">
                                {intel.tags.map((tag) => (
                                  <span key={`${intel.indicator}-${tag}`} className="px-2 py-0.5 rounded-full border border-gray-700">
                                    #{tag}
                                  </span>
                                ))}
                              </div>
                            ) : null}
                            {intel.metadata?.summary && (
                              <p className="mt-1 text-gray-300 text-[11px]">{intel.metadata.summary}</p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {isExpanded && (
                    <div className="mt-3 space-y-2">
                      {bundle.events.map((evt) => (
                        <div
                          key={evt.id}
                          className="rounded bg-black/20 border border-white/5 p-3 text-[11px] flex flex-col gap-2"
                        >
                          <div className="flex flex-wrap items-center gap-2 text-gray-200">
                            <span className="text-white font-semibold">{evt.riskLevel} • {evt.riskScore}</span>
                            <span className="font-mono text-gray-300">{new Date(evt.timestamp).toLocaleTimeString()}</span>
                            <span>Remote: <span className="font-mono text-gray-100">{evt.remoteIP}</span></span>
                            <span>Subnet: <span className="font-mono text-gray-100">{evt.remoteSubnet}</span></span>
                            <span>
                              Action: <span className={`px-2 py-0.5 rounded ${actionBadge(evt.actionTaken)}`}>{evt.actionTaken || 'Observed'}</span>
                            </span>
                          </div>
                          <p className="text-gray-300">
                            {evt.reason || 'No additional details provided.'}
                          </p>
                          <div className="flex flex-wrap gap-2">
                            <button
                              type="button"
                              className="px-3 py-1 rounded border border-red-500/50 text-red-300 hover:bg-red-500/10 disabled:opacity-50"
                              disabled={blockingId === evt.id}
                              onClick={() => handleQuickBlock(evt)}
                            >
                              {blockingId === evt.id ? 'Blocking…' : 'Quick Block'}
                            </button>
                            <button
                              type="button"
                              className="px-3 py-1 rounded border border-purple-500/50 text-purple-300 hover:bg-purple-500/10"
                              onClick={() => handleSendToFirewall(evt)}
                            >
                              Stage Rule
                            </button>
                            <button
                              type="button"
                              className="px-3 py-1 rounded border border-green-500/50 text-green-300 hover:bg-green-500/10 disabled:opacity-50"
                              disabled={whitelistingId === evt.id}
                              onClick={() => handleWhitelist(evt)}
                            >
                              {whitelistingId === evt.id ? 'Whitelisting…' : 'Whitelist'}
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
            {(hasMoreGroups || hasMoreServerPages) && (
              <div className="flex flex-wrap gap-3 justify-center py-4 text-xs text-gray-400">
                {hasMoreGroups && (
                  <button
                    type="button"
                    className="px-4 py-2 rounded border border-gray-700 text-gray-300 hover:border-gray-500"
                    onClick={handleLoadMoreGroups}
                  >
                    Load more bundles
                  </button>
                )}
                {hasMoreServerPages && (
                  <button
                    type="button"
                    className="px-4 py-2 rounded border border-red-600/60 text-red-200 hover:bg-red-600/10 disabled:opacity-50"
                    onClick={handleLoadMoreServer}
                    disabled={isPaginating}
                  >
                    {isPaginating ? 'Loading…' : 'Load more from store'}
                  </button>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
});

ThreatTimeline.displayName = 'ThreatTimeline';

export default ThreatTimeline;
