import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { z } from 'zod';
import type {
  GuardianEvent,
  GuardianPlaybook,
  GuardianPlaybookRun,
  GuardianStory,
  GuardianThreatIntelRecord,
  GuardianAnomalyConfig,
  PolicySuggestion,
} from '@/shared/ipcSchemas';
import {
  GuardianGetThreatIntelResponseSchema,
  GuardianRefreshThreatIntelResponseSchema,
  GuardianAnomalyConfigSchema,
} from '@/shared/ipcSchemas';
import type { ElectronAPI, ShieldAPI } from '@/preload/preload';
import { useAdmin } from '@/renderer/contexts/AdminContext';

type WindowWithElectron = Window & { electronAPI?: ElectronAPI };

const expectElectronAPI = (): ElectronAPI => {
  const api = (window as WindowWithElectron).electronAPI;
  if (!api) {
    throw new Error('electronAPI unavailable');
  }
  return api;
};

const expectShieldApi = (): ShieldAPI => {
  const shield = expectElectronAPI().shield;
  if (!shield) {
    throw new Error('shield API unavailable');
  }
  return shield;
};

type GuardianThreatIntelWireResponse = {
  success: boolean;
  records?: GuardianThreatIntelRecord[];
  nextCursor?: string | null;
  error?: string;
};

type GuardianThreatIntelRefreshWireResponse = {
  success: boolean;
  refreshed?: boolean;
  records?: GuardianThreatIntelRecord[];
  error?: string;
};

async function safeGuardianThreatIntelRequest(options: { cursor?: string | null; limit?: number } = {}) {
  const shield = expectShieldApi();
  const payload = {
    limit: options.limit ?? 25,
    cursor: options.cursor ?? undefined,
  };
  const response = (await shield.getGuardianThreatIntel(payload)) as GuardianThreatIntelWireResponse;
  if (!response?.success) {
    throw new Error(response?.error || 'Unable to load Guardian threat intel');
  }
  const parsed = GuardianGetThreatIntelResponseSchema.safeParse({
    records: response.records,
    nextCursor: response.nextCursor ?? null,
  });
  if (!parsed.success) {
    throw new Error('Guardian threat intel response invalid');
  }
  return parsed.data;
}

async function safeGuardianThreatIntelRefresh(indicator: string) {
  const shield = expectShieldApi();
  const response = (await shield.refreshGuardianThreatIntel({ indicator, source: 'policy-composer' })) as GuardianThreatIntelRefreshWireResponse;
  if (!response?.success) {
    throw new Error(response?.error || `Failed to refresh intel for ${indicator}`);
  }
  const parsed = GuardianRefreshThreatIntelResponseSchema.safeParse({
    refreshed: response.refreshed,
    records: response.records,
  });
  if (!parsed.success) {
    throw new Error('Guardian intel refresh response invalid');
  }
  return parsed.data;
}

const PAGE_SIZE = 15;
const SETTINGS_KEY = 'policyComposer.settings';
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

interface ComposerSettings {
  rateLimit: number; // decisions per minute
  defaultTtlSeconds: number;
  sensitiveProcesses: string[];
  enableCspReporting: boolean;
}

const DEFAULT_SETTINGS: ComposerSettings = {
  rateLimit: 20,
  defaultTtlSeconds: 15 * 60,
  sensitiveProcesses: ['lsass.exe', 'csrss.exe'],
  enableCspReporting: true,
};

const ComposerSettingsSchema = z.object({
  rateLimit: z.number().int().min(1).max(500),
  defaultTtlSeconds: z.number().int().min(30).max(24 * 60 * 60),
  sensitiveProcesses: z.array(z.string()).default([]),
  enableCspReporting: z.boolean(),
});

const SettingsResponseSchema = z.object({
  success: z.boolean(),
  settings: z.record(z.any()).optional(),
  error: z.string().optional(),
});

const SaveSettingsResponseSchema = z.object({
  success: z.boolean(),
  message: z.string().optional(),
  error: z.string().optional(),
});

const GuardianAnomalyConfigSuccessSchema = z.object({
  success: z.literal(true),
  config: GuardianAnomalyConfigSchema,
  error: z.string().optional(),
});

const GuardianAnomalyConfigErrorSchema = z.object({
  success: z.literal(false),
  error: z.string().optional(),
});

async function safeLoadGuardianAnomalyConfig(): Promise<GuardianAnomalyConfig> {
  const shield = expectShieldApi();
  if (!shield.getGuardianAnomalyConfig) {
    throw new Error('Guardian anomaly API unavailable');
  }
  const response = await shield.getGuardianAnomalyConfig();
  const parsed = GuardianAnomalyConfigSuccessSchema.or(GuardianAnomalyConfigErrorSchema).safeParse(response);
  if (!parsed.success) {
    throw new Error('Guardian anomaly response invalid');
  }
  if (!parsed.data.success) {
    throw new Error(parsed.data.error || 'Unable to load Guardian anomaly config');
  }
  return parsed.data.config;
}

async function safeUpdateGuardianAnomalyConfig(config: GuardianAnomalyConfig): Promise<GuardianAnomalyConfig> {
  const shield = expectShieldApi();
  if (!shield.updateGuardianAnomalyConfig) {
    throw new Error('Guardian anomaly update API unavailable');
  }
  const payload = GuardianAnomalyConfigSchema.parse(config);
  const response = await shield.updateGuardianAnomalyConfig(payload);
  const parsed = GuardianAnomalyConfigSuccessSchema.or(GuardianAnomalyConfigErrorSchema).safeParse(response);
  if (!parsed.success) {
    throw new Error('Guardian anomaly update response invalid');
  }
  if (!parsed.data.success) {
    throw new Error(parsed.data.error || 'Failed to update Guardian anomaly config');
  }
  return parsed.data.config;
}

async function safeLoadComposerSettings(): Promise<ComposerSettings | null> {
  const api = expectElectronAPI();
  if (!api.getSettings) {
    throw new Error('Settings API unavailable');
  }
  const response = await api.getSettings();
  const parsed = SettingsResponseSchema.safeParse(response);
  if (!parsed.success) {
    throw new Error('Settings response invalid');
  }
  if (!parsed.data.success) {
    throw new Error(parsed.data.error || 'Failed to load settings');
  }
  const stored = parsed.data.settings?.[SETTINGS_KEY];
  if (!stored || typeof stored !== 'object') {
    return null;
  }
  const normalized = ComposerSettingsSchema.partial().safeParse(stored);
  if (!normalized.success) {
    throw new Error('Composer settings payload invalid');
  }
  return {
    ...DEFAULT_SETTINGS,
    ...normalized.data,
    sensitiveProcesses: Array.isArray(normalized.data.sensitiveProcesses)
      ? normalized.data.sensitiveProcesses
      : DEFAULT_SETTINGS.sensitiveProcesses,
  };
}

async function safeSaveComposerSettings(settings: ComposerSettings): Promise<void> {
  const api = expectElectronAPI();
  if (!api.saveSettings) {
    throw new Error('Settings API unavailable');
  }
  const payload = ComposerSettingsSchema.parse(settings);
  const response = await api.saveSettings(SETTINGS_KEY, payload);
  const parsed = SaveSettingsResponseSchema.safeParse(response);
  if (!parsed.success) {
    throw new Error('Save settings response invalid');
  }
  if (!parsed.data.success) {
    throw new Error(parsed.data.error || 'Failed to persist settings');
  }
}

const sanitizeProcessList = (rawValue: string) =>
  rawValue
    .split(/(?:,|;|\r?\n)+/)
    .map((entry) => entry.trim())
    .filter(Boolean);

const dedupeProcesses = (entries: string[]) => {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const entry of entries) {
    const key = entry.toLowerCase();
    if (key && !seen.has(key)) {
      seen.add(key);
      result.push(entry);
    }
  }
  return result;
};

type StatusFilter = 'all' | PolicySuggestion['status'];
type SortOption = 'recent' | 'confidence' | 'evidence';

const sortLabels: Record<SortOption, string> = {
  recent: 'Most recent',
  confidence: 'Highest confidence',
  evidence: 'Evidence hits',
};

const statusStyles: Record<PolicySuggestion['status'], string> = {
  pending: 'bg-yellow-500/15 text-yellow-200 border-yellow-500/40',
  accepted: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/40',
  dismissed: 'bg-gray-500/15 text-gray-300 border-gray-500/40',
};

const statusLabels: Record<StatusFilter, string> = {
  all: 'All',
  pending: 'Pending',
  accepted: 'Accepted',
  dismissed: 'Dismissed',
};

const DATA_PIPELINE_STEPS = [
  {
    title: '1. Sensors collect signals',
    detail: 'Sentinel watches running processes, open network connections, and firewall hits locally on your PC. Nothing is sent to the cloud.',
    accent: 'from-cyan-500/30 to-blue-500/20',
  },
  {
    title: '2. Evidence is scored',
    detail: 'For every suspicious IP or process, Sentinel tallies how many times it misbehaved, whether it touched sensitive apps, and if other defences flagged it.',
    accent: 'from-amber-500/30 to-orange-500/20',
  },
  {
    title: '3. You stay in control',
    detail: 'Policy Composer never writes firewall rules automatically. You decide if a suggestion becomes a rule, and you can undo it at any time.',
    accent: 'from-emerald-500/30 to-lime-500/20',
  },
];

const PRIVACY_QA = [
  {
    question: 'Where is my data stored?',
    answer: 'All policy logs live in the Sentinel telemetry store on this computer (c:/Users/<you>/AppData/Local/Sentinel). No remote upload occurs.',
  },
  {
    question: 'What happens when I press "Promote to rule"?',
    answer: 'Sentinel stages a firewall rule with the IP and process shown, applies the TTL you set, and records that action in the local activity log.',
  },
  {
    question: 'Can I review or delete this information?',
    answer: 'Yes. Use the Activity Log to audit actions, clear stored suggestions via the telemetry folder, or dismiss items to hide them from Policy Composer.',
  },
];

const GLOSSARY_ENTRIES = [
  {
    term: 'Policy Suggestion',
    description: 'A plain-language recommendation generated from repeated network behaviour. Think of it as Sentinel saying “this IP looks risky, consider blocking it.”',
  },
  {
    term: 'Evidence Hits',
    description: 'How many times the same behaviour was observed (e.g., repeat port scans, failed TLS handshakes). More hits usually means higher confidence.',
  },
  {
    term: 'TTL (Time To Live)',
    description: 'How long Sentinel keeps a rule active before removing it. Short TTLs are useful for testing, longer TTLs lock in the protection.',
  },
];

const ZERO_RISK_POLICIES = [
  {
    title: 'Beacon watchdog',
    description: 'Correlates DNS, TLS and socket telemetry per process to flag implants that beacon on a schedule.',
  },
  {
    title: 'Privilege bleed',
    description: 'Alerts when low-privilege apps start talking to admin-only services or protected ports.',
  },
  {
    title: 'Sensitive process cloaking',
    description: 'Compares every policy hit against the Sensitive watch list so lsass.exe, csrss.exe, etc. stay under sentinel scrutiny.',
  },
  {
    title: 'Reoffender memory',
    description: 'When an IP or binary reappears after dismissal, the suggestion returns with elevated severity and provenance trail.',
  },
];

type PlaybookExecutionSummary = {
  playbookId: string;
  playbookName: string;
  success: boolean;
  actionsExecuted: number;
  timestamp: number;
  dryRun?: boolean;
  log?: string[];
  error?: string;
};

const confidenceToRiskLevel = (confidence: number): GuardianEvent['riskLevel'] => {
  if (confidence >= 0.9) return 'Critical';
  if (confidence >= 0.7) return 'High';
  if (confidence >= 0.4) return 'Medium';
  if (confidence > 0) return 'Low';
  return undefined;
};

const buildGuardianContextFromSuggestion = (suggestion: PolicySuggestion): Partial<GuardianEvent> => {
  const riskScore = Math.round((suggestion.confidence ?? 0) * 100);
  return {
    module: 'policy-composer',
    processName: suggestion.processName ?? undefined,
    remoteIP: suggestion.remoteIP ?? undefined,
    fingerprint: suggestion.fingerprint,
    riskScore,
    riskLevel: confidenceToRiskLevel(suggestion.confidence ?? 0),
    metadata: {
      source: 'policy-composer',
      policySuggestionId: suggestion.id,
      evidenceCount: suggestion.evidenceCount ?? 0,
      status: suggestion.status,
    },
  } satisfies Partial<GuardianEvent>;
};

const doesPlaybookMatchSuggestion = (
  playbook: GuardianPlaybook,
  suggestion: PolicySuggestion | null,
): boolean => {
  if (!suggestion) {
    return false;
  }
  if (!playbook.conditions?.length) {
    return true;
  }
  return playbook.conditions.some((condition) => {
    if (condition.modules && !condition.modules.includes('policy-composer')) {
      return false;
    }
    if (condition.processName) {
      if (!suggestion.processName || condition.processName.toLowerCase() !== suggestion.processName.toLowerCase()) {
        return false;
      }
    }
    if (condition.remoteIP && condition.remoteIP !== suggestion.remoteIP) {
      return false;
    }
    if (condition.fingerprint && condition.fingerprint !== suggestion.fingerprint) {
      return false;
    }
    return true;
  });
};

const PolicyComposer: React.FC = () => {
  const [suggestions, setSuggestions] = useState<PolicySuggestion[]>([]);
  const [guardianStories, setGuardianStories] = useState<Record<string, GuardianStory | null>>({});
  const [guardianPlaybooks, setGuardianPlaybooks] = useState<GuardianPlaybook[]>([]);
  const [guardianPlaybooksLoading, setGuardianPlaybooksLoading] = useState(false);
  const [guardianPlaybooksError, setGuardianPlaybooksError] = useState<string | null>(null);
  const [guardianPlaybookRuns, setGuardianPlaybookRuns] = useState<GuardianPlaybookRun[]>([]);
  const [guardianPlaybookRunsLoading, setGuardianPlaybookRunsLoading] = useState(false);
  const [guardianPlaybookRunsError, setGuardianPlaybookRunsError] = useState<string | null>(null);
  const [guardianThreatIntel, setGuardianThreatIntel] = useState<GuardianThreatIntelRecord[]>([]);
  const [guardianThreatIntelLoading, setGuardianThreatIntelLoading] = useState(false);
  const [guardianThreatIntelError, setGuardianThreatIntelError] = useState<string | null>(null);
  const [guardianThreatIntelCursor, setGuardianThreatIntelCursor] = useState<string | null>(null);
  const [guardianAnomalyConfig, setGuardianAnomalyConfig] = useState<GuardianAnomalyConfig | null>(null);
  const [guardianAnomalyConfigLoading, setGuardianAnomalyConfigLoading] = useState(false);
  const [guardianAnomalyConfigError, setGuardianAnomalyConfigError] = useState<string | null>(null);
  const [guardianIntelLookup, setGuardianIntelLookup] = useState('');
  const [playbookActionState, setPlaybookActionState] = useState<Record<string, 'idle' | 'running'>>({});
  const [lastPlaybookExecution, setLastPlaybookExecution] = useState<PlaybookExecutionSummary | null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('pending');
  const [sortOption, setSortOption] = useState<SortOption>('recent');
  const [searchTerm, setSearchTerm] = useState('');
  const [onlySensitive, setOnlySensitive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [isPaginating, setIsPaginating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [selectedSuggestionId, setSelectedSuggestionId] = useState<string | null>(null);
  const [settings, setSettings] = useState<ComposerSettings>(DEFAULT_SETTINGS);
  const [settingsHydrated, setSettingsHydrated] = useState(false);
  const [decisionLog, setDecisionLog] = useState<number[]>([]);
  const [sensitiveInput, setSensitiveInput] = useState('');
  const [newSensitiveProcess, setNewSensitiveProcess] = useState('');
  const [sensitiveDraftDirty, setSensitiveDraftDirty] = useState(false);
  const loadMoreRef = useRef<HTMLDivElement | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const paginationCleanup = useRef<() => void>();
  const sensitiveInputHydrated = useRef(false);
  const { isAdmin } = useAdmin();

  const statusCounts = useMemo(() => {
    return suggestions.reduce(
      (acc, suggestion) => {
        acc[suggestion.status] += 1;
        return acc;
      },
      { pending: 0, accepted: 0, dismissed: 0 }
    );
  }, [suggestions]);

  const sensitiveProcessSet = useMemo(() => {
    return new Set(settings.sensitiveProcesses.map((proc) => proc.toLowerCase()).filter(Boolean));
  }, [settings.sensitiveProcesses]);

  const rateLimited = useMemo(() => {
    const now = Date.now();
    const recent = decisionLog.filter((ts) => now - ts < RATE_LIMIT_WINDOW_MS);
    return recent.length >= settings.rateLimit;
  }, [decisionLog, settings.rateLimit]);

  const filteredSuggestions = useMemo(() => {
    const query = searchTerm.trim().toLowerCase();
    const matchesQuery = (suggestion: PolicySuggestion) => {
      if (!query) {
        return true;
      }
      const haystack = [
        suggestion.recommendation,
        suggestion.remoteIP,
        suggestion.processName,
        suggestion.intel?.org,
        suggestion.intel?.country,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return haystack.includes(query);
    };
    const sensitiveFiltered = suggestions.filter((suggestion) => {
      if (onlySensitive) {
        const proc = suggestion.processName?.toLowerCase() ?? '';
        if (!proc || !sensitiveProcessSet.has(proc)) {
          return false;
        }
      }
      return matchesQuery(suggestion);
    });
    const sorted = [...sensitiveFiltered].sort((a, b) => {
      switch (sortOption) {
        case 'confidence':
          return b.confidence - a.confidence;
        case 'evidence':
          return (b.evidenceCount ?? 0) - (a.evidenceCount ?? 0);
        case 'recent':
        default:
          return (b.updatedAt ?? 0) - (a.updatedAt ?? 0);
      }
    });
    return sorted;
  }, [onlySensitive, searchTerm, sortOption, suggestions, sensitiveProcessSet]);

  const selectedSuggestion = useMemo(() => {
    if (selectedSuggestionId) {
      return filteredSuggestions.find((item) => item.id === selectedSuggestionId) ?? null;
    }
    return filteredSuggestions[0] ?? null;
  }, [filteredSuggestions, selectedSuggestionId]);

  const persistSettings = useCallback(
    (updater: ComposerSettings | ((prev: ComposerSettings) => ComposerSettings)) => {
      setSettings((prev) => {
        const next = typeof updater === 'function' ? (updater as (p: ComposerSettings) => ComposerSettings)(prev) : updater;
        if (settingsHydrated) {
          void safeSaveComposerSettings(next).catch((err) =>
            console.warn('[PolicyComposer] Failed to persist settings', err)
          );
        }
        return next;
      });
    },
    [settingsHydrated]
  );

  useEffect(() => {
    let mounted = true;
    const hydrateSettings = async () => {
      try {
        const saved = await safeLoadComposerSettings();
        if (mounted && saved) {
          setSettings(saved);
        }
      } catch (err) {
        console.warn('[PolicyComposer] Failed to hydrate settings', err);
      } finally {
        if (mounted) {
          setSettingsHydrated(true);
        }
      }
    };
    hydrateSettings();
    return () => {
      mounted = false;
    };
  }, []);

  const fetchGuardianThreatIntel = useCallback(
    async ({ reset = false, cursor }: { reset?: boolean; cursor?: string | null } = {}) => {
      if (!reset && !cursor) {
        return;
      }
      if (reset) {
        setGuardianThreatIntelCursor(null);
      }
      setGuardianThreatIntelLoading(true);
      setGuardianThreatIntelError(null);
      try {
        const { records, nextCursor } = await safeGuardianThreatIntelRequest({
          cursor: reset ? undefined : cursor ?? undefined,
        });
        setGuardianThreatIntelCursor(nextCursor);
        if (reset) {
          setGuardianThreatIntel(records);
        } else {
          setGuardianThreatIntel((prev) => {
            const seen = new Set(prev.map((entry) => entry.indicator.toLowerCase()));
            const merged = [...prev];
            records.forEach((record) => {
              const key = record.indicator.toLowerCase();
              if (!seen.has(key)) {
                merged.push(record);
                seen.add(key);
              }
            });
            return merged;
          });
        }
      } catch (err: any) {
        setGuardianThreatIntelError(err?.message || 'Failed to load Guardian threat intel');
      } finally {
        setGuardianThreatIntelLoading(false);
      }
    },
    [],
  );

  const handleLoadMoreGuardianThreatIntel = useCallback(() => {
    if (!guardianThreatIntelCursor || guardianThreatIntelLoading) {
      return;
    }
    fetchGuardianThreatIntel({ cursor: guardianThreatIntelCursor });
  }, [fetchGuardianThreatIntel, guardianThreatIntelCursor, guardianThreatIntelLoading]);

  const refreshGuardianThreatIntelList = useCallback(() => {
    fetchGuardianThreatIntel({ reset: true });
  }, [fetchGuardianThreatIntel]);

  const refreshGuardianThreatIntelForIndicator = useCallback(
    async (indicatorOverride?: string | null) => {
      const target = indicatorOverride?.trim() || selectedSuggestion?.remoteIP?.trim();
      if (!target) {
        return;
      }
      setGuardianThreatIntelLoading(true);
      setGuardianThreatIntelError(null);
      try {
        const response = await safeGuardianThreatIntelRefresh(target);
        const refreshed = response.records ?? [];
        if (refreshed.length) {
          setGuardianThreatIntel((prev) => {
            const filtered = prev.filter(
              (record) => !refreshed.some((incoming) => incoming.indicator.toLowerCase() === record.indicator.toLowerCase()),
            );
            return [...refreshed, ...filtered];
          });
        }
      } catch (err: any) {
        setGuardianThreatIntelError(err?.message || `Failed to refresh intel for ${target}`);
      } finally {
        setGuardianThreatIntelLoading(false);
      }
    },
    [selectedSuggestion],
  );

  const loadGuardianAnomalyConfig = useCallback(async () => {
    setGuardianAnomalyConfigLoading(true);
    setGuardianAnomalyConfigError(null);
    try {
      const config = await safeLoadGuardianAnomalyConfig();
      setGuardianAnomalyConfig(config);
    } catch (err: any) {
      setGuardianAnomalyConfigError(err?.message || 'Failed to load Guardian anomaly config');
    } finally {
      setGuardianAnomalyConfigLoading(false);
    }
  }, []);

  const submitGuardianAnomalyConfig = useCallback(async (nextConfig: GuardianAnomalyConfig) => {
    setGuardianAnomalyConfigLoading(true);
    setGuardianAnomalyConfigError(null);
    try {
      const updated = await safeUpdateGuardianAnomalyConfig(nextConfig);
      setGuardianAnomalyConfig(updated);
    } catch (err: any) {
      setGuardianAnomalyConfigError(err?.message || 'Failed to update Guardian anomaly config');
    } finally {
      setGuardianAnomalyConfigLoading(false);
    }
  }, []);

  const mutateGuardianAnomalyConfig = useCallback(
    (patch: Partial<GuardianAnomalyConfig>) => {
      setGuardianAnomalyConfig((prev) => {
        if (!prev) {
          return prev;
        }
        const next: GuardianAnomalyConfig = {
          ...prev,
          ...patch,
        };
        next.windowMinutes = Math.min(Math.max(next.windowMinutes, 5), 24 * 60);
        next.minSamples = Math.min(Math.max(next.minSamples, 10), 10000);
        void submitGuardianAnomalyConfig(next);
        return next;
      });
    },
    [submitGuardianAnomalyConfig],
  );

  useEffect(() => {
    if (!settingsHydrated) {
      return;
    }
    window.dispatchEvent(
      new CustomEvent('sentinel:csp-reporting-toggle', {
        detail: { enabled: settings.enableCspReporting },
      })
    );
  }, [settings.enableCspReporting, settingsHydrated]);

  const guardianRequestsRef = useRef<Set<string>>(new Set());

  const fetchGuardianStoryForSuggestion = useCallback(
    async (suggestion: PolicySuggestion) => {
      const shield = expectShieldApi();
      if (!shield.getGuardianStories) {
        return;
      }
      if (!suggestion.processName && !suggestion.remoteIP) {
        setGuardianStories((prev) => ({ ...prev, [suggestion.id]: null }));
        return;
      }
      if (guardianRequestsRef.current.has(suggestion.id)) {
        return;
      }
      guardianRequestsRef.current.add(suggestion.id);
      try {
        const response = await shield.getGuardianStories({
          limit: 1,
          processName: suggestion.processName ?? undefined,
          remoteIP: suggestion.remoteIP ?? undefined,
        });
        const story = response?.success && Array.isArray(response.stories) ? response.stories[0] ?? null : null;
        setGuardianStories((prev) => ({ ...prev, [suggestion.id]: story }));
      } catch (err) {
        console.warn('[PolicyComposer] Failed to fetch guardian story', err);
        setGuardianStories((prev) => ({ ...prev, [suggestion.id]: null }));
      } finally {
        guardianRequestsRef.current.delete(suggestion.id);
      }
    },
    []
  );

  const refreshGuardianPlaybooks = useCallback(async () => {
    const shield = expectShieldApi();
    if (!shield.listGuardianPlaybooks) {
      setGuardianPlaybooksError('Guardian playbook API unavailable');
      return;
    }
    setGuardianPlaybooksLoading(true);
    setGuardianPlaybooksError(null);
    try {
      const response = await shield.listGuardianPlaybooks();
      if (!response?.success) {
        throw new Error(response?.error || 'Unable to load Guardian playbooks');
      }
      setGuardianPlaybooks(Array.isArray(response.playbooks) ? response.playbooks : []);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load Guardian playbooks';
      setGuardianPlaybooksError(message);
    } finally {
      setGuardianPlaybooksLoading(false);
    }
  }, []);

  const refreshGuardianPlaybookRuns = useCallback(async () => {
    const shield = expectShieldApi();
    if (!shield.getGuardianPlaybookRuns) {
      setGuardianPlaybookRunsError('Guardian playbook runs API unavailable');
      return;
    }
    setGuardianPlaybookRunsLoading(true);
    setGuardianPlaybookRunsError(null);
    try {
      const response = await shield.getGuardianPlaybookRuns(50);
      if (!response?.success) {
        throw new Error(response?.error || 'Unable to load Guardian playbook runs');
      }
      setGuardianPlaybookRuns(Array.isArray(response.runs) ? response.runs : []);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load Guardian playbook runs';
      setGuardianPlaybookRunsError(message);
    } finally {
      setGuardianPlaybookRunsLoading(false);
    }
  }, []);

  const fetchSuggestions = useCallback(
    async ({ reset = false }: { reset?: boolean } = {}) => {
      if (!settingsHydrated) {
        return;
      }
      const shield = expectShieldApi();
      if (!shield.getPolicySuggestions) {
        setError('Policy suggestions API unavailable');
        return;
      }
      if (reset) {
        setLoading(true);
        setError(null);
      } else {
        if (!nextCursor) {
          return;
        }
        setIsPaginating(true);
      }
      try {
        const response = await shield.getPolicySuggestions({
          cursor: reset ? undefined : nextCursor ?? undefined,
          limit: PAGE_SIZE,
          status: statusFilter === 'all' ? undefined : statusFilter,
        });
        if (!response?.success) {
          throw new Error(response?.error || 'Unable to load policy suggestions');
        }
        const mapped: PolicySuggestion[] = Array.isArray(response.suggestions) ? response.suggestions : [];
        setNextCursor(response.nextCursor ?? null);
        if (reset) {
          setSuggestions(mapped);
          setGuardianStories({});
        } else {
          setSuggestions((prev) => {
            const ids = new Set(prev.map((item) => item.id));
            const merged = mapped.filter((item) => !ids.has(item.id));
            return [...prev, ...merged];
          });
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Failed to load suggestions';
        console.error('[PolicyComposer] Failed to fetch suggestions', err);
        setError(message);
      } finally {
        if (reset) {
          setLoading(false);
        } else {
          setIsPaginating(false);
        }
      }
    },
    [nextCursor, settingsHydrated, statusFilter]
  );

  useEffect(() => {
    if (!settingsHydrated) return;
    setNextCursor(null);
    setGuardianStories({});
    fetchSuggestions({ reset: true });
  }, [statusFilter, settingsHydrated, fetchSuggestions]);

  useEffect(() => {
    if (!scrollRef.current || !loadMoreRef.current) {
      return;
    }
    if (!nextCursor || isPaginating || loading) {
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            fetchSuggestions({ reset: false });
          }
        });
      },
      { root: scrollRef.current, threshold: 0.3 }
    );
    observer.observe(loadMoreRef.current);
    paginationCleanup.current = () => observer.disconnect();
    return () => observer.disconnect();
  }, [fetchSuggestions, isPaginating, loading, nextCursor]);

  useEffect(() => () => paginationCleanup.current?.(), []);

  const stageRuleFromSuggestion = useCallback(
    async (suggestion: PolicySuggestion) => {
      if (!suggestion.remoteIP) {
        return;
      }
      const shield = expectShieldApi();
      if (!shield.stageFirewallRule) {
        return;
      }
      try {
        await shield.stageFirewallRule({
          sessionKey: `policy-${suggestion.id}`,
          pid: 0,
          processName: suggestion.processName || 'Unknown',
          remoteIP: suggestion.remoteIP,
          reasons: [suggestion.recommendation],
          recommendsBlock: true,
          ttlSeconds: settings.defaultTtlSeconds,
        });
      } catch (err) {
        console.warn('[PolicyComposer] Failed to stage firewall rule', err);
      }
    },
    [settings.defaultTtlSeconds]
  );

  const mutateSuggestion = useCallback(
    async (suggestion: PolicySuggestion, action: 'accept' | 'dismiss') => {
      if (action === 'accept') {
        const now = Date.now();
        const recent = decisionLog.filter((ts) => now - ts < RATE_LIMIT_WINDOW_MS);
        if (recent.length >= settings.rateLimit) {
          setError('Rate limit reached. Please wait before promoting more policies.');
          return;
        }
      }
      const shield = expectShieldApi();
      const fn =
        action === 'accept' ? shield.acceptPolicySuggestion : shield.dismissPolicySuggestion;
      if (!fn) {
        setError(`${action === 'accept' ? 'Accept' : 'Dismiss'} API unavailable`);
        return;
      }
      try {
        const res = await fn(suggestion.id);
        if (!res?.success || !res.suggestion) {
          throw new Error(res?.error || `Failed to ${action} suggestion`);
        }
        if (action === 'accept') {
          void stageRuleFromSuggestion(suggestion);
          const now = Date.now();
          setDecisionLog((prev) => {
            const trimmed = prev.filter((ts) => now - ts < RATE_LIMIT_WINDOW_MS);
            return [...trimmed, now];
          });
        }
        setSuggestions((prev) =>
          prev.map((item) => (item.id === suggestion.id ? (res.suggestion as PolicySuggestion) : item))
        );
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : `Unable to ${action} suggestion`;
        console.error('[PolicyComposer] Mutation failed', err);
        setError(message);
      }
    },
    [decisionLog, settings.rateLimit, stageRuleFromSuggestion]
  );

  const handleRunPlaybook = useCallback(
    async (playbookId: string, options?: { dryRun?: boolean }) => {
      const shield = expectShieldApi();
      const playbook = guardianPlaybooks.find((entry) => entry.id === playbookId);
      setPlaybookActionState((prev) => ({ ...prev, [playbookId]: 'running' }));
      setLastPlaybookExecution(null);
      if (!shield.runGuardianPlaybook) {
        setLastPlaybookExecution({
          playbookId,
          playbookName: playbook?.name ?? playbookId,
          success: false,
          actionsExecuted: 0,
          timestamp: Date.now(),
          dryRun: options?.dryRun,
          error: 'Guardian run API unavailable',
        });
        setPlaybookActionState((prev) => ({ ...prev, [playbookId]: 'idle' }));
        return;
      }
      try {
        const context = selectedSuggestion ? buildGuardianContextFromSuggestion(selectedSuggestion) : undefined;
        const response = await shield.runGuardianPlaybook({ id: playbookId, context, dryRun: options?.dryRun });
        if (!response?.success) {
          throw new Error(response?.error || 'Failed to run Guardian playbook');
        }
        setLastPlaybookExecution({
          playbookId,
          playbookName: playbook?.name ?? playbookId,
          success: true,
          actionsExecuted: response.actionsExecuted ?? 0,
          log: response.log ?? [],
          timestamp: Date.now(),
          dryRun: options?.dryRun,
        });
        if (!options?.dryRun) {
          await refreshGuardianPlaybookRuns();
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Guardian playbook run failed';
        setLastPlaybookExecution({
          playbookId,
          playbookName: playbook?.name ?? playbookId,
          success: false,
          actionsExecuted: 0,
          timestamp: Date.now(),
          dryRun: options?.dryRun,
          error: message,
        });
      } finally {
        setPlaybookActionState((prev) => ({ ...prev, [playbookId]: 'idle' }));
      }
    },
    [guardianPlaybooks, refreshGuardianPlaybookRuns, selectedSuggestion],
  );

  const handleExport = useCallback(() => {
    const payload = suggestions.map((item) => ({
      id: item.id,
      recommendation: item.recommendation,
      status: item.status,
      remoteIP: item.remoteIP,
      processName: item.processName,
      confidence: item.confidence,
      evidenceCount: item.evidenceCount,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt,
    }));
    const serialized = JSON.stringify(payload, null, 2);
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(serialized).catch((err) => console.warn('Clipboard export failed', err));
    }
    const blob = new Blob([serialized], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-policy-export-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [suggestions]);

  useEffect(() => {
    if (!filteredSuggestions.length) {
      if (selectedSuggestionId !== null) {
        setSelectedSuggestionId(null);
      }
      return;
    }
    const stillVisible = selectedSuggestionId
      ? filteredSuggestions.some((item) => item.id === selectedSuggestionId)
      : false;
    if (!stillVisible) {
      setSelectedSuggestionId(filteredSuggestions[0].id);
    }
  }, [filteredSuggestions, selectedSuggestionId]);

  const guardianIntelMatchesForSelection = useMemo(() => {
    if (!selectedSuggestion?.remoteIP) {
      return [];
    }
    const target = selectedSuggestion.remoteIP.trim().toLowerCase();
    if (!target) {
      return [];
    }
    return guardianThreatIntel.filter((record) => record.indicator.trim().toLowerCase() === target);
  }, [guardianThreatIntel, selectedSuggestion?.remoteIP]);

  const guardianIntelStats = useMemo(() => {
    if (!guardianThreatIntel.length) {
      return null;
    }
    const typeCounts: Record<string, number> = {};
    const tagCounts: Record<string, number> = {};
    guardianThreatIntel.forEach((record) => {
      typeCounts[record.type] = (typeCounts[record.type] ?? 0) + 1;
      record.tags?.forEach((tag) => {
        const key = tag.toLowerCase();
        tagCounts[key] = (tagCounts[key] ?? 0) + 1;
      });
    });
    const topTags = Object.entries(tagCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([tag, count]) => ({ tag, count }));
    const lastSeen = guardianThreatIntel.reduce<number | null>((latest, record) => {
      if (!record.lastSeen) {
        return latest;
      }
      if (latest === null || record.lastSeen > latest) {
        return record.lastSeen;
      }
      return latest;
    }, null);
    return { total: guardianThreatIntel.length, typeCounts, topTags, lastSeen };
  }, [guardianThreatIntel]);

  const guardianIntelHasMore = Boolean(guardianThreatIntelCursor);

  const filtersActive = useMemo(() => Boolean(searchTerm.trim() || onlySensitive), [onlySensitive, searchTerm]);
  const playbookNameMap = useMemo(() => {
    return guardianPlaybooks.reduce<Record<string, string>>((acc, playbook) => {
      acc[playbook.id] = playbook.name;
      return acc;
    }, {});
  }, [guardianPlaybooks]);
  const matchedPlaybookCount = useMemo(() => {
    if (!selectedSuggestion) return 0;
    return guardianPlaybooks.reduce<number>((count, playbook) => {
      return count + (doesPlaybookMatchSuggestion(playbook, selectedSuggestion) ? 1 : 0);
    }, 0);
  }, [guardianPlaybooks, selectedSuggestion]);

  const handleSelectSuggestion = useCallback((id: string) => {
    setSelectedSuggestionId(id);
  }, []);

  const handleGuardianIntelLookup = useCallback(() => {
    const trimmed = guardianIntelLookup.trim();
    if (!trimmed) {
      return;
    }
    void refreshGuardianThreatIntelForIndicator(trimmed);
  }, [guardianIntelLookup, refreshGuardianThreatIntelForIndicator]);

  useEffect(() => {
    if (!selectedSuggestion?.remoteIP) {
      return;
    }
    const normalized = selectedSuggestion.remoteIP.trim().toLowerCase();
    if (!normalized) {
      return;
    }
    const hasMatch = guardianThreatIntel.some((record) => record.indicator.trim().toLowerCase() === normalized);
    if (!hasMatch && !guardianThreatIntelLoading) {
      void refreshGuardianThreatIntelForIndicator(normalized);
    }
  }, [guardianThreatIntel, guardianThreatIntelLoading, refreshGuardianThreatIntelForIndicator, selectedSuggestion?.remoteIP]);

  const clearFilters = useCallback(() => {
    setSearchTerm('');
    setOnlySensitive(false);
  }, []);

  const handleSensitiveInputChange = useCallback((value: string) => {
    setSensitiveInput(value);
    setSensitiveDraftDirty(true);
  }, []);

  const applySensitiveDraft = useCallback(() => {
    const normalized = dedupeProcesses(sanitizeProcessList(sensitiveInput));
    persistSettings((prev) => ({ ...prev, sensitiveProcesses: normalized }));
    setSensitiveInput(normalized.join('\n'));
    setSensitiveDraftDirty(false);
  }, [persistSettings, sensitiveInput]);

  const revertSensitiveDraft = useCallback(() => {
    setSensitiveInput(settings.sensitiveProcesses.join('\n'));
    setSensitiveDraftDirty(false);
  }, [settings.sensitiveProcesses]);

  const handleAddSensitiveProcess = useCallback(() => {
    const entries = sanitizeProcessList(newSensitiveProcess);
    if (!entries.length) {
      return;
    }
    const merged = dedupeProcesses([...settings.sensitiveProcesses, ...entries]);
    if (merged.length === settings.sensitiveProcesses.length) {
      setNewSensitiveProcess('');
      return;
    }
    persistSettings((prev) => ({ ...prev, sensitiveProcesses: merged }));
    setSensitiveInput(merged.join('\n'));
    setSensitiveDraftDirty(false);
    setNewSensitiveProcess('');
  }, [newSensitiveProcess, persistSettings, settings.sensitiveProcesses]);

  const handleRemoveSensitiveProcess = useCallback(
    (processName: string) => {
      const filtered = settings.sensitiveProcesses.filter(
        (entry) => entry.toLowerCase() !== processName.toLowerCase()
      );
      if (filtered.length === settings.sensitiveProcesses.length) {
        return;
      }
      persistSettings((prev) => ({ ...prev, sensitiveProcesses: filtered }));
      setSensitiveInput(filtered.join('\n'));
      setSensitiveDraftDirty(false);
    },
    [persistSettings, settings.sensitiveProcesses]
  );

  const handleNewSensitiveKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLInputElement>) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        handleAddSensitiveProcess();
      }
    },
    [handleAddSensitiveProcess]
  );

  const applySensitiveDisabled = !sensitiveDraftDirty;
  const addSensitiveDisabled = !newSensitiveProcess.trim();
  const visibleSuggestions = filteredSuggestions;
  const noVisibleSuggestions = visibleSuggestions.length === 0;
  const emptyStateMessage = filtersActive
    ? 'No policy suggestions match your filters.'
    : 'No policy suggestions available for this filter.';

  const formatTimestamp = (timestamp: number) => new Date(timestamp).toLocaleString();

  return (
    <div className="h-full flex flex-col bg-[#06060c] text-white">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 p-4 border-b border-gray-900">
        <div>
          <p className="text-xs tracking-[0.3em] text-gray-500">HUMAN + AI DEFENCE</p>
          <h2 className="text-2xl font-black">Policy Composer</h2>
          <p className="text-sm text-gray-400 max-w-3xl">
            Designed for non-experts: every suggestion spells out what Sentinel saw, how often it happened, and what promoting the rule will change.
            Your evidence never leaves this device.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            className="px-3 py-1.5 rounded-lg border border-gray-800 text-xs text-gray-300 hover:border-cyan-500/60"
            onClick={() => fetchSuggestions({ reset: true })}
            disabled={loading}
          >
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
          <button
            className="px-3 py-1.5 rounded-lg border border-cyan-500/60 text-xs text-cyan-200 hover:bg-cyan-500/10"
            onClick={handleExport}
          >
            Export JSON
          </button>
        </div>
      </div>

      <div className="px-4 py-3 border-b border-gray-900 bg-gradient-to-r from-cyan-900/30 to-blue-900/20 text-sm text-gray-200">
        <p className="font-semibold text-white">Where does my data go?</p>
        <p className="text-xs text-gray-300">
          Sentinel stores policy evidence inside <span className="font-mono text-white/90">{`c:/Users/<you>/AppData/Local/Sentinel/telemetry-db`}</span>.
          We read local hosts, firewall history, and process metadata only to generate the suggestions you see here. Nothing is uploaded.
        </p>
      </div>

      <div className="flex flex-col lg:flex-row flex-1 min-h-0">
        <div className="lg:w-2/3 border-r border-gray-900 flex flex-col">
          <div className="p-4 border-b border-gray-900 flex flex-col gap-4">
            <div className="flex flex-wrap gap-2">
              {(['all', 'pending', 'accepted', 'dismissed'] as StatusFilter[]).map((key) => (
                <button
                  key={key}
                  className={`px-3 py-1.5 rounded-full text-xs font-semibold border transition-all ${
                    statusFilter === key
                      ? 'border-cyan-500 text-cyan-200 bg-cyan-500/10'
                      : 'border-gray-800 text-gray-500 hover:border-gray-700'
                  }`}
                  onClick={() => {
                    setNextCursor(null);
                    setSuggestions([]);
                    setStatusFilter(key);
                  }}
                >
                  {statusLabels[key]}
                  {key !== 'all' && (
                    <span className="ml-1 text-[10px] text-gray-400">
                      ({statusCounts[key as keyof typeof statusCounts] || 0})
                    </span>
                  )}
                </button>
              ))}
            </div>
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
              <div className="flex-1 flex items-center gap-2 bg-[#0b0b14] border border-gray-800 rounded-lg px-3 py-2">
                <input
                  type="text"
                  className="flex-1 bg-transparent text-sm text-gray-200 placeholder:text-gray-500 focus:outline-none"
                  placeholder="Search recommendation, IP, process, or org"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
                {searchTerm && (
                  <button
                    className="text-[11px] text-gray-500 hover:text-gray-200"
                    onClick={() => setSearchTerm('')}
                  >
                    Clear
                  </button>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <label className="flex items-center gap-2 text-[11px] uppercase tracking-wide text-gray-500">
                  <input
                    type="checkbox"
                    className="accent-cyan-500"
                    checked={onlySensitive}
                    onChange={(e) => setOnlySensitive(e.target.checked)}
                  />
                  Watch matches only
                </label>
                <select
                  className="bg-[#0b0b14] border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 focus:border-cyan-500"
                  value={sortOption}
                  onChange={(e) => setSortOption(e.target.value as SortOption)}
                >
                  {Object.entries(sortLabels).map(([key, label]) => (
                    <option key={key} value={key}>
                      {label}
                    </option>
                  ))}
                </select>
                {filtersActive && (
                  <button
                    className="text-xs px-3 py-1 rounded-full border border-gray-700 text-gray-300 hover:border-cyan-500/60"
                    onClick={clearFilters}
                  >
                    Reset filters
                  </button>
                )}
              </div>
            </div>
          </div>

          <section className="px-4 pt-4 space-y-3">
            <header>
              <p className="text-[11px] uppercase tracking-wide text-gray-500">How Sentinel builds a recommendation</p>
              <h3 className="text-lg font-semibold text-white">Data journey for every policy</h3>
              <p className="text-xs text-gray-400">Follow the trail so you always know why an IP is flagged.</p>
            </header>
            <div className="grid gap-3 md:grid-cols-3">
              {DATA_PIPELINE_STEPS.map((step) => (
                <div
                  key={step.title}
                  className={`rounded-xl border border-gray-800 bg-gradient-to-b ${step.accent} p-3 text-xs text-gray-200`}
                >
                  <p className="text-sm font-semibold text-white">{step.title}</p>
                  <p className="mt-1 leading-snug text-gray-200/90">{step.detail}</p>
                </div>
              ))}
            </div>
          </section>

          <div ref={scrollRef} className="flex-1 min-h-0 overflow-y-auto p-4 space-y-4">
            {error && <div className="text-xs text-red-400">{error}</div>}
            {noVisibleSuggestions && !loading ? (
              <div className="text-sm text-gray-500 py-20 text-center">{emptyStateMessage}</div>
            ) : (
              visibleSuggestions.map((suggestion) => {
                const selected = selectedSuggestionId === suggestion.id;
                const intelBadges = [
                  suggestion.intel?.country,
                  suggestion.intel?.org,
                  suggestion.intel?.tlsGrade && `TLS ${suggestion.intel.tlsGrade}`,
                  typeof suggestion.intel?.watchHits === 'number'
                    ? `Watch hits ${suggestion.intel?.watchHits}`
                    : null,
                ].filter(Boolean) as string[];
                return (
                  <button
                    key={suggestion.id}
                    type="button"
                    onClick={() => handleSelectSuggestion(suggestion.id)}
                    className={`text-left rounded-xl border bg-[#0b0b14] p-4 shadow-inner shadow-black/30 transition-colors ${
                      selected ? 'border-cyan-500/70' : 'border-gray-800 hover:border-gray-700'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <p className="text-[11px] text-gray-500">{formatTimestamp(suggestion.createdAt)}</p>
                        <p className="font-semibold text-base text-white">{suggestion.recommendation}</p>
                        <p className="text-[11px] text-gray-400">
                          Process scope: <span className="text-gray-100">{suggestion.processName ?? 'Any process'}</span>
                        </p>
                      </div>
                      <span
                        className={`px-3 py-1 text-[11px] font-semibold rounded-full border ${statusStyles[suggestion.status]}`}
                      >
                        {suggestion.status.toUpperCase()}
                      </span>
                    </div>
                    <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-gray-400">
                      {suggestion.remoteIP && (
                        <span className="px-2 py-0.5 rounded-full border border-cyan-500/30 text-cyan-200 font-mono">
                          {suggestion.remoteIP}
                        </span>
                      )}
                      <span className="px-2 py-0.5 rounded-full border border-gray-700 text-gray-200">
                        {suggestion.processName ?? 'Any process'}
                      </span>
                      <span className="px-2 py-0.5 rounded-full border border-amber-500/30 text-amber-200">
                        Evidence {suggestion.evidenceCount ?? 0}
                      </span>
                      <span className="px-2 py-0.5 rounded-full border border-indigo-500/30 text-indigo-200">
                        {Math.round(suggestion.confidence * 100)}% confidence
                      </span>
                      {suggestion.processName && sensitiveProcessSet.has(suggestion.processName.toLowerCase()) && (
                        <span className="px-2 py-0.5 rounded-full border border-pink-500/50 text-pink-200">
                          Sensitive match
                        </span>
                      )}
                      {intelBadges.map((badge) => (
                        <span key={badge} className="px-2 py-0.5 rounded-full border border-gray-700 text-gray-300">
                          {badge}
                        </span>
                      ))}
                    </div>
                  </button>
                );
              })
            )}
            {!noVisibleSuggestions && selectedSuggestion && (
              <div className="rounded-2xl border border-gray-800 bg-[#07070f] p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="text-xs text-gray-500">Selected recommendation</p>
                    <h3 className="text-xl font-semibold text-white">{selectedSuggestion.recommendation}</h3>
                  </div>
                  <span
                    className={`px-3 py-1 text-[11px] font-semibold rounded-full border ${statusStyles[selectedSuggestion.status]}`}
                  >
                    {selectedSuggestion.status.toUpperCase()}
                  </span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs text-gray-300">
                  <div>
                    <p className="text-gray-500">Remote IP</p>
                    <p className="font-mono text-sm text-cyan-200">
                      {selectedSuggestion.remoteIP ?? 'Unspecified'}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-500">Process scope</p>
                    <p className="text-sm text-gray-100 font-mono">
                      {selectedSuggestion.processName ?? 'Any process'}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-500">Confidence</p>
                    <p className="text-sm text-gray-100">{Math.round(selectedSuggestion.confidence * 100)}%</p>
                  </div>
                  <div>
                    <p className="text-gray-500">Evidence hits</p>
                    <p className="text-sm text-gray-100">{selectedSuggestion.evidenceCount ?? 0}</p>
                  </div>
                  <div>
                    <p className="text-gray-500">Created</p>
                    <p className="text-sm text-gray-100">{formatTimestamp(selectedSuggestion.createdAt)}</p>
                  </div>
                  <div>
                    <p className="text-gray-500">Updated</p>
                    <p className="text-sm text-gray-100">{formatTimestamp(selectedSuggestion.updatedAt)}</p>
                  </div>
                </div>
                {selectedSuggestion.processName && sensitiveProcessSet.has(selectedSuggestion.processName.toLowerCase()) && (
                  <div className="text-xs text-pink-300 flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded-full border border-pink-500/50">Sensitive watch</span>
                    <span>{selectedSuggestion.processName} matches watch list</span>
                  </div>
                )}
                {guardianStories[selectedSuggestion.id] && (
                  <section className="rounded-xl border border-cyan-500/40 bg-cyan-500/5 p-4 text-xs text-gray-200">
                    {(() => {
                      const summary = guardianStories[selectedSuggestion.id];
                      if (!summary) {
                        return null;
                      }
                      return (
                        <>
                          <div className="flex items-center justify-between">
                            <p className="text-sm font-semibold text-cyan-200">Guardian Summary</p>
                            <span className="px-2 py-0.5 border border-cyan-500/40 rounded-full">
                              {summary.modules?.join(', ') || 'Multi-module'}
                            </span>
                          </div>
                          <p className="mt-2 text-gray-300">
                            {summary.summary || 'Correlated telemetry from Sentinel modules.'}
                          </p>
                          <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-gray-400">
                            {summary.firstSeen && (
                              <span>First seen: {new Date(summary.firstSeen).toLocaleString()}</span>
                            )}
                            {summary.lastSeen && (
                              <span>Last seen: {new Date(summary.lastSeen).toLocaleString()}</span>
                            )}
                            {summary.maxRiskLevel && (
                              <span className="px-2 py-0.5 rounded-full border border-red-500/40 text-red-200">
                                Risk: {summary.maxRiskLevel}
                              </span>
                            )}
                          </div>
                        </>
                      );
                    })()}
                  </section>
                )}
                {selectedSuggestion.intel && (
                  <div className="space-y-2">
                    <div className="flex flex-wrap gap-2 text-[11px]">
                      {selectedSuggestion.intel.country && (
                        <span className="px-2 py-0.5 rounded-full border border-blue-500/40 text-blue-200">
                          {selectedSuggestion.intel.country}
                        </span>
                      )}
                      {selectedSuggestion.intel.org && (
                        <span className="px-2 py-0.5 rounded-full border border-purple-500/40 text-purple-200">
                          {selectedSuggestion.intel.org}
                        </span>
                      )}
                      {typeof selectedSuggestion.intel.watchHits === 'number' && (
                        <span className="px-2 py-0.5 rounded-full border border-amber-500/40 text-amber-200">
                          Watch hits {selectedSuggestion.intel.watchHits}
                        </span>
                      )}
                      {selectedSuggestion.intel.tlsGrade && (
                        <span className="px-2 py-0.5 rounded-full border border-emerald-500/40 text-emerald-200">
                          TLS grade {selectedSuggestion.intel.tlsGrade}
                        </span>
                      )}
                      {selectedSuggestion.intel.leakSignals?.map((signal) => (
                        <span key={signal} className="px-2 py-0.5 rounded-full border border-red-500/40 text-red-200">
                          {signal}
                        </span>
                      ))}
                    </div>
                    <p className="text-sm text-gray-200 leading-snug">
                      {selectedSuggestion.intel.riskSummary || 'No risk summary available.'}
                    </p>
                    {selectedSuggestion.intel.lastSeen && (
                      <p className="text-[11px] text-gray-500">
                        Last seen: {new Date(selectedSuggestion.intel.lastSeen).toLocaleString()}
                      </p>
                    )}
                  </div>
                )}
                <div className="flex flex-wrap gap-2 text-xs">
                  <div className="px-3 py-1 rounded-full border border-indigo-500/40 text-indigo-200">
                    TTL {Math.round(settings.defaultTtlSeconds / 60)} min
                  </div>
                  <div className="px-3 py-1 rounded-full border border-pink-500/40 text-pink-200">
                    Rate limit {settings.rateLimit}/min
                  </div>
                  {selectedSuggestion.remoteIP && (
                    <div className="px-3 py-1 rounded-full border border-orange-500/40 text-orange-200">
                      Scoped to {selectedSuggestion.remoteIP}
                    </div>
                  )}
                </div>
                {selectedSuggestion.status === 'pending' ? (
                  <div className="flex flex-wrap gap-2">
                    <button
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold border border-emerald-500/60 text-emerald-200 hover:bg-emerald-500/10 ${
                        isAdmin && !rateLimited ? '' : 'opacity-60 cursor-not-allowed'
                      }`}
                      disabled={!isAdmin || rateLimited}
                      onClick={() => mutateSuggestion(selectedSuggestion, 'accept')}
                    >
                      Promote to rule
                    </button>
                    <button
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold border border-gray-700 text-gray-400 hover:text-gray-200"
                      onClick={() => mutateSuggestion(selectedSuggestion, 'dismiss')}
                    >
                      Dismiss
                    </button>
                  </div>
                ) : (
                  <p className="text-[11px] text-gray-500">This suggestion is {selectedSuggestion.status}.</p>
                )}
              </div>
            )}
            <div ref={loadMoreRef} className="h-8" />
            {isPaginating && <div className="text-center text-xs text-gray-500 pb-6">Loading more…</div>}
            {rateLimited && (
              <div className="text-[11px] text-amber-300 text-center pb-4">
                Rate limit reached — wait a few seconds before promoting more policies.
              </div>
            )}
          </div>
        </div>

        <div className="lg:w-1/3 flex flex-col">
          <div className="p-4 border-b border-gray-900">
            <h3 className="text-lg font-semibold">Automation + Transparency</h3>
            <p className="text-xs text-gray-500">Tune auto-response and learn exactly what Sentinel records.</p>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto p-4 space-y-4">
            <section className="rounded-xl border border-emerald-500/40 bg-[#07110f] p-4 space-y-3">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p className="text-sm font-semibold text-emerald-200">Guardian Playbooks</p>
                  <p className="text-xs text-gray-400">
                    {guardianPlaybooks.length
                      ? `${guardianPlaybooks.length} total • ${matchedPlaybookCount} aligned with selection`
                      : 'Connect Policy Composer evidence to Guardian automations.'}
                  </p>
                </div>
                <div className="flex gap-2">
                  <button
                    className="px-3 py-1 rounded-lg text-[11px] border border-gray-700 text-gray-300 hover:border-emerald-400/60"
                    onClick={refreshGuardianPlaybooks}
                    disabled={guardianPlaybooksLoading}
                  >
                    {guardianPlaybooksLoading ? 'Refreshing…' : 'Refresh'}
                  </button>
                  <button
                    className="px-3 py-1 rounded-lg text-[11px] border border-gray-700 text-gray-300 hover:border-cyan-400/60"
                    onClick={refreshGuardianPlaybookRuns}
                    disabled={guardianPlaybookRunsLoading}
                  >
                    Runs
                  </button>
                </div>
              </div>
              <p className="text-[11px] text-gray-500">
                {selectedSuggestion
                  ? 'Selected recommendation context will be passed to Guardian when you run a playbook.'
                  : 'Select a recommendation to feed Guardian with live context before running a playbook.'}
              </p>
              {lastPlaybookExecution && (
                <div
                  className={`rounded-lg border p-3 text-xs ${
                    lastPlaybookExecution.success
                      ? 'border-emerald-500/40 text-emerald-200'
                      : 'border-red-500/40 text-red-200'
                  }`}
                >
                  <p className="font-semibold text-sm">
                    {lastPlaybookExecution.success ? 'Playbook executed' : 'Playbook run failed'} •{' '}
                    {new Date(lastPlaybookExecution.timestamp).toLocaleTimeString()}
                  </p>
                  <p className="text-[11px] text-gray-200">
                    {lastPlaybookExecution.playbookName} • Actions {lastPlaybookExecution.actionsExecuted}
                    {lastPlaybookExecution.dryRun ? ' • Dry run' : ''}
                  </p>
                  {lastPlaybookExecution.log?.length ? (
                    <ul className="mt-2 space-y-1 text-[11px] text-gray-300">
                      {lastPlaybookExecution.log.slice(0, 4).map((line, idx) => (
                        <li key={`${lastPlaybookExecution.playbookId}-log-${idx}`}>{line}</li>
                      ))}
                      {lastPlaybookExecution.log.length > 4 && <li>…</li>}
                    </ul>
                  ) : null}
                  {lastPlaybookExecution.error && (
                    <p className="text-[11px] text-red-200 mt-1">{lastPlaybookExecution.error}</p>
                  )}
                </div>
              )}
              {guardianPlaybooksError && <p className="text-xs text-red-400">{guardianPlaybooksError}</p>}
              {guardianPlaybooksLoading ? (
                <p className="text-xs text-gray-400">Loading Guardian playbooks…</p>
              ) : guardianPlaybooks.length === 0 ? (
                <p className="text-xs text-gray-500">No Guardian playbooks saved yet.</p>
              ) : (
                <div className="space-y-3">
                  {guardianPlaybooks.map((playbook) => {
                    const running = playbookActionState[playbook.id] === 'running';
                    const matchesSelection = doesPlaybookMatchSuggestion(playbook, selectedSuggestion);
                    return (
                      <div
                        key={playbook.id}
                        className="rounded-lg border border-gray-800 bg-black/20 p-3 space-y-2"
                      >
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div>
                            <p className="text-sm font-semibold text-white">
                              {playbook.name}
                              {!playbook.enabled && (
                                <span className="ml-2 text-[10px] uppercase tracking-wide text-amber-300">
                                  Disabled
                                </span>
                              )}
                            </p>
                            {playbook.description && (
                              <p className="text-xs text-gray-400">{playbook.description}</p>
                            )}
                          </div>
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] border ${
                              matchesSelection
                                ? 'border-emerald-400/60 text-emerald-200'
                                : 'border-gray-700 text-gray-400'
                            }`}
                          >
                            {matchesSelection ? 'Matches selection' : 'Generic'}
                          </span>
                        </div>
                        <div className="flex flex-wrap gap-2 text-[11px] text-gray-400">
                          <span>Priority {playbook.priority ?? 0}</span>
                          <span>{playbook.conditions.length} conditions</span>
                          <span>{playbook.actions.length} actions</span>
                          {playbook.tags?.map((tag) => (
                            <span
                              key={tag}
                              className="px-2 py-0.5 rounded-full border border-gray-700 text-gray-300"
                            >
                              #{tag}
                            </span>
                          ))}
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <button
                            className={`px-3 py-1.5 rounded-lg text-xs font-semibold border ${
                              selectedSuggestion && !running
                                ? 'border-emerald-500/60 text-emerald-200 hover:bg-emerald-500/10'
                                : 'border-gray-700 text-gray-500'
                            }`}
                            disabled={!selectedSuggestion || running}
                            onClick={() => handleRunPlaybook(playbook.id)}
                          >
                            {running
                              ? 'Running…'
                              : selectedSuggestion
                              ? 'Run with selection'
                              : 'Select a recommendation'}
                          </button>
                          <button
                            className={`px-3 py-1.5 rounded-lg text-xs font-semibold border ${
                              running ? 'border-gray-700 text-gray-500' : 'border-cyan-500/60 text-cyan-200 hover:bg-cyan-500/10'
                            }`}
                            disabled={running}
                            onClick={() => handleRunPlaybook(playbook.id, { dryRun: true })}
                          >
                            {running ? 'Please wait…' : 'Dry run'}
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>

            <section className="rounded-xl border border-cyan-500/40 bg-[#041018] p-4 space-y-3">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p className="text-sm font-semibold text-cyan-200">Guardian Threat Intel</p>
                  <p className="text-xs text-gray-400">
                    Local indicator cache enriched by Guardian heuristics. Auto-populates from Policy Composer focus.
                  </p>
                </div>
                <button
                  className="px-3 py-1 rounded-lg text-[11px] border border-gray-700 text-gray-300 hover:border-cyan-400/60"
                  onClick={refreshGuardianThreatIntelList}
                  disabled={guardianThreatIntelLoading}
                >
                  {guardianThreatIntelLoading ? 'Refreshing…' : 'Refresh list'}
                </button>
              </div>
              {guardianThreatIntelError && <p className="text-xs text-red-400">{guardianThreatIntelError}</p>}
              {guardianIntelStats ? (
                <div className="flex flex-wrap gap-3 text-[11px] text-gray-300">
                  <span className="px-2 py-0.5 rounded-full border border-cyan-500/40 text-cyan-100">
                    Records {guardianIntelStats.total}
                  </span>
                  {Object.entries(guardianIntelStats.typeCounts).map(([type, count]) => (
                    <span key={type} className="px-2 py-0.5 rounded-full border border-gray-700 text-gray-300">
                      {type} • {count}
                    </span>
                  ))}
                  {guardianIntelStats.lastSeen && (
                    <span className="text-gray-400">
                      Last refresh {new Date(guardianIntelStats.lastSeen).toLocaleTimeString()}
                    </span>
                  )}
                </div>
              ) : (
                <p className="text-xs text-gray-500">No Guardian intel yet — refresh or select a suggestion.</p>
              )}
              {guardianIntelStats?.topTags?.length ? (
                <div className="flex flex-wrap gap-2 text-[11px] text-gray-400">
                  {guardianIntelStats.topTags.map(({ tag, count }) => (
                    <span key={tag} className="px-2 py-0.5 rounded-full border border-gray-700 text-gray-200">
                      #{tag} ({count})
                    </span>
                  ))}
                </div>
              ) : null}
              <div className="space-y-2">
                <label className="flex flex-col gap-1 text-[11px] text-gray-400">
                  Manual indicator lookup
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={guardianIntelLookup}
                      onChange={(e) => setGuardianIntelLookup(e.target.value)}
                      placeholder="IP, domain, hash"
                      className="flex-1 rounded-lg bg-black/30 border border-gray-800 px-3 py-2 text-xs text-gray-200 placeholder:text-gray-500 focus:border-cyan-500 focus:outline-none"
                    />
                    <button
                      className="px-3 py-2 rounded-lg border border-cyan-500/60 text-cyan-100 text-xs hover:bg-cyan-500/10 disabled:opacity-50"
                      disabled={!guardianIntelLookup.trim() || guardianThreatIntelLoading}
                      onClick={handleGuardianIntelLookup}
                    >
                      Enrich
                    </button>
                  </div>
                </label>
                {selectedSuggestion?.remoteIP && (
                  <div className="text-[11px] text-gray-400 flex flex-wrap items-center gap-2">
                    <span className="font-mono text-white text-sm">{selectedSuggestion.remoteIP}</span>
                    {guardianIntelMatchesForSelection.length ? (
                      <span className="px-2 py-0.5 rounded-full border border-emerald-500/60 text-emerald-200">
                        Intel match found
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full border border-gray-700 text-gray-400">
                        No cached intel
                      </span>
                    )}
                    <button
                      className="px-2 py-0.5 rounded border border-cyan-500/60 text-cyan-200 text-[10px] hover:bg-cyan-500/10"
                      onClick={() => refreshGuardianThreatIntelForIndicator(selectedSuggestion.remoteIP)}
                    >
                      Refresh indicator
                    </button>
                  </div>
                )}
              </div>
              <div className="max-h-64 overflow-y-auto pr-1 space-y-2">
                {guardianThreatIntel.length === 0 && !guardianThreatIntelLoading ? (
                  <p className="text-xs text-gray-500">No indicators cached yet.</p>
                ) : (
                  guardianThreatIntel.map((record) => (
                    <div key={`${record.type}-${record.indicator}`} className="rounded-lg border border-gray-800 bg-black/30 p-3 text-[11px] text-gray-200 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <div className="font-mono text-white text-sm break-all">{record.indicator}</div>
                        <span className="px-2 py-0.5 rounded-full border border-cyan-500/40 text-cyan-100 text-[10px] uppercase">
                          {record.type}
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-2 text-[10px] text-gray-400">
                        {typeof record.reputation === 'number' && (
                          <span className="px-2 py-0.5 rounded border border-red-500/30 text-red-200">
                            Rep {record.reputation}
                          </span>
                        )}
                        {typeof record.confidence === 'number' && (
                          <span className="px-2 py-0.5 rounded border border-amber-500/30 text-amber-200">
                            Confidence {record.confidence}
                          </span>
                        )}
                        <span className="px-2 py-0.5 rounded border border-gray-700 text-gray-300">
                          Sources {record.sources.length}
                        </span>
                        {record.lastSeen && (
                          <span>Last seen {new Date(record.lastSeen).toLocaleDateString()}</span>
                        )}
                      </div>
                      {record.tags?.length ? (
                        <div className="flex flex-wrap gap-1 text-[10px] text-gray-300">
                          {record.tags.map((tag) => (
                            <span key={`${record.indicator}-${tag}`} className="px-2 py-0.5 rounded-full border border-gray-700">
                              #{tag}
                            </span>
                          ))}
                        </div>
                      ) : null}
                      {record.metadata?.summary && (
                        <p className="text-gray-300 text-[11px]">{record.metadata.summary}</p>
                      )}
                    </div>
                  ))
                )}
              </div>
              {guardianIntelHasMore && (
                <button
                  className="w-full px-3 py-1.5 rounded-lg border border-gray-700 text-gray-300 text-xs hover:border-cyan-400/60"
                  onClick={handleLoadMoreGuardianThreatIntel}
                  disabled={guardianThreatIntelLoading}
                >
                  Load more intel
                </button>
              )}
            </section>

            <section className="rounded-xl border border-gray-800 p-4 bg-[#090910] space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold text-white">Guardian activity</p>
                  <p className="text-xs text-gray-500">Latest automation runs captured locally.</p>
                </div>
                <button
                  className="px-3 py-1 rounded-lg text-[11px] border border-gray-700 text-gray-300 hover:border-cyan-400/60"
                  onClick={refreshGuardianPlaybookRuns}
                  disabled={guardianPlaybookRunsLoading}
                >
                  {guardianPlaybookRunsLoading ? 'Refreshing…' : 'Refresh'}
                </button>
              </div>
              {guardianPlaybookRunsError && <p className="text-xs text-red-400">{guardianPlaybookRunsError}</p>}
              {guardianPlaybookRunsLoading ? (
                <p className="text-xs text-gray-400">Loading Guardian playbook activity…</p>
              ) : guardianPlaybookRuns.length === 0 ? (
                <p className="text-xs text-gray-500">No Guardian playbook runs recorded yet.</p>
              ) : (
                <div className="space-y-2">
                  {guardianPlaybookRuns.map((run) => {
                    const label = playbookNameMap[run.playbookId] ?? `Playbook ${run.playbookId.slice(0, 6)}`;
                    const statusStylesMap: Record<GuardianPlaybookRun['status'], string> = {
                      pending: 'border-amber-400/40 text-amber-200',
                      completed: 'border-emerald-400/40 text-emerald-200',
                      failed: 'border-red-500/40 text-red-200',
                    };
                    return (
                      <div key={run.id} className="rounded-lg border border-gray-800 bg-black/20 p-3 text-xs text-gray-300">
                        <div className="flex items-center justify-between">
                          <p className="font-semibold text-white">{label}</p>
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] uppercase border ${statusStylesMap[run.status]}`}
                          >
                            {run.status}
                          </span>
                        </div>
                        <p className="text-[11px] text-gray-500">{new Date(run.triggeredAt).toLocaleString()}</p>
                        <div className="flex flex-wrap gap-2 mt-2">
                          <span className="px-2 py-0.5 rounded-full border border-gray-700 text-gray-300">
                            Actions {run.actionsExecuted}
                          </span>
                          {run.error && (
                            <span className="px-2 py-0.5 rounded-full border border-red-500/40 text-red-200">
                              {run.error}
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>

            <section className="rounded-xl border border-indigo-500/40 bg-[#080916] p-4 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold text-indigo-200">Anomaly Baselines</p>
                  <p className="text-xs text-gray-400">Guardian sensitivity governs how easily anomalies trigger stories.</p>
                </div>
                <button
                  className="px-3 py-1 rounded-lg text-[11px] border border-gray-700 text-gray-300 hover:border-indigo-400/60"
                  onClick={loadGuardianAnomalyConfig}
                  disabled={guardianAnomalyConfigLoading}
                >
                  {guardianAnomalyConfigLoading ? 'Refreshing…' : 'Reload'}
                </button>
              </div>
              {guardianAnomalyConfigError && <p className="text-xs text-red-400">{guardianAnomalyConfigError}</p>}
              {guardianAnomalyConfig ? (
                <>
                  <div className="flex flex-wrap gap-3 text-[11px] text-gray-300">
                    <span className={`px-2 py-0.5 rounded-full border ${guardianAnomalyConfig.enabled ? 'border-emerald-500/50 text-emerald-200' : 'border-gray-700 text-gray-400'}`}>
                      {guardianAnomalyConfig.enabled ? 'Monitoring enabled' : 'Monitoring paused'}
                    </span>
                    <span className="px-2 py-0.5 rounded-full border border-indigo-400/40 text-indigo-200">
                      Sensitivity {guardianAnomalyConfig.sensitivity}
                    </span>
                    <span className="px-2 py-0.5 rounded-full border border-gray-700 text-gray-300">
                      Window {Math.round(guardianAnomalyConfig.windowMinutes / 60)}h
                    </span>
                    <span className="px-2 py-0.5 rounded-full border border-gray-700 text-gray-300">
                      Min samples {guardianAnomalyConfig.minSamples}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold border ${guardianAnomalyConfig.enabled ? 'border-emerald-500/60 text-emerald-200 hover:bg-emerald-500/10' : 'border-gray-700 text-gray-400'}`}
                      onClick={() => mutateGuardianAnomalyConfig({ enabled: !guardianAnomalyConfig.enabled })}
                    >
                      {guardianAnomalyConfig.enabled ? 'Disable monitoring' : 'Enable monitoring'}
                    </button>
                    <select
                      className="bg-black/30 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 focus:border-indigo-500 focus:outline-none"
                      value={guardianAnomalyConfig.sensitivity}
                      onChange={(e) => mutateGuardianAnomalyConfig({ sensitivity: e.target.value as GuardianAnomalyConfig['sensitivity'] })}
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                    </select>
                  </div>
                  <div className="space-y-3 text-[11px] text-gray-400">
                    <label className="flex flex-col gap-1">
                      Observation window ({guardianAnomalyConfig.windowMinutes} min)
                      <input
                        type="range"
                        min={5}
                        max={24 * 60}
                        value={guardianAnomalyConfig.windowMinutes}
                        onChange={(e) => mutateGuardianAnomalyConfig({ windowMinutes: Number(e.target.value) })}
                      />
                    </label>
                    <label className="flex flex-col gap-1">
                      Minimum samples ({guardianAnomalyConfig.minSamples})
                      <input
                        type="range"
                        min={10}
                        max={10000}
                        step={10}
                        value={guardianAnomalyConfig.minSamples}
                        onChange={(e) => mutateGuardianAnomalyConfig({ minSamples: Number(e.target.value) })}
                      />
                    </label>
                  </div>
                </>
              ) : (
                <p className="text-xs text-gray-500">Loading anomaly config…</p>
              )}
            </section>

            <section className="rounded-xl border border-gray-800 p-4 bg-[#090912] space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold">Rate limiting</p>
                  <p className="text-xs text-gray-500">Max promotions per minute</p>
                </div>
                <span className="text-cyan-200 font-mono">{settings.rateLimit}</span>
              </div>
              <input
                type="range"
                min={5}
                max={60}
                value={settings.rateLimit}
                onChange={(e) =>
                  persistSettings((prev) => ({ ...prev, rateLimit: Number(e.target.value) || prev.rateLimit }))
                }
              />
            </section>

            <section className="rounded-xl border border-gray-800 p-4 bg-[#090912] space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold">Default TTL</p>
                  <p className="text-xs text-gray-500">Applied to staged firewall rules</p>
                </div>
                <span className="text-amber-200 font-mono">
                  {Math.round(settings.defaultTtlSeconds / 60)}m
                </span>
              </div>
              <input
                type="range"
                min={5 * 60}
                max={60 * 60}
                step={5 * 60}
                value={settings.defaultTtlSeconds}
                onChange={(e) =>
                  persistSettings((prev) => ({ ...prev, defaultTtlSeconds: Number(e.target.value) || prev.defaultTtlSeconds }))
                }
              />
            </section>

            <section className="rounded-xl border border-gray-800 p-4 bg-[#090912] space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold">Sensitive watch list</p>
                  <p className="text-xs text-gray-500">Process names (comma or newline separated)</p>
                </div>
                <span className="text-xs text-gray-400">{settings.sensitiveProcesses.length} entries</span>
              </div>
              <textarea
                className="w-full rounded-lg bg-[#0e0e18] border border-gray-800 p-2 text-xs focus:border-cyan-500 outline-none"
                rows={3}
                value={sensitiveInput}
                onChange={(e) => handleSensitiveInputChange(e.target.value)}
              />
              <div className="flex flex-wrap gap-2 text-xs">
                <button
                  className={`px-3 py-1.5 rounded-lg border border-cyan-500/60 text-cyan-200 ${
                    applySensitiveDisabled ? 'opacity-60 cursor-not-allowed' : 'hover:bg-cyan-500/10'
                  }`}
                  disabled={applySensitiveDisabled}
                  onClick={applySensitiveDraft}
                >
                  Save watch list
                </button>
                <button
                  className={`px-3 py-1.5 rounded-lg border border-gray-700 text-gray-300 ${
                    applySensitiveDisabled ? 'opacity-60 cursor-not-allowed' : 'hover:border-cyan-500/60'
                  }`}
                  disabled={applySensitiveDisabled}
                  onClick={revertSensitiveDraft}
                >
                  Revert changes
                </button>
              </div>
              <div className="flex flex-col gap-2 sm:flex-row">
                <input
                  type="text"
                  className="flex-1 rounded-lg bg-[#0e0e18] border border-gray-800 px-3 py-2 text-xs text-gray-200 placeholder:text-gray-500 focus:border-cyan-500 focus:outline-none"
                  placeholder="Add new process (e.g. lsass.exe)"
                  value={newSensitiveProcess}
                  onChange={(e) => setNewSensitiveProcess(e.target.value)}
                  onKeyDown={handleNewSensitiveKeyDown}
                />
                <button
                  className={`px-3 py-2 rounded-lg text-xs font-semibold border border-emerald-500/60 text-emerald-200 ${
                    addSensitiveDisabled ? 'opacity-60 cursor-not-allowed' : 'hover:bg-emerald-500/10'
                  }`}
                  disabled={addSensitiveDisabled}
                  onClick={handleAddSensitiveProcess}
                >
                  Add process
                </button>
              </div>
              <div className="flex flex-wrap gap-2 text-[11px]">
                {settings.sensitiveProcesses.length === 0 && (
                  <span className="text-gray-500">No processes tracked yet.</span>
                )}
                {settings.sensitiveProcesses.map((proc) => (
                  <span
                    key={proc}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-gray-700 text-gray-200 bg-black/30"
                  >
                    {proc}
                    <button
                      className="text-gray-500 hover:text-red-400"
                      onClick={() => handleRemoveSensitiveProcess(proc)}
                      aria-label={`Remove ${proc}`}
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            </section>

            <section className="rounded-xl border border-gray-800 p-4 bg-[#090912] space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold">CSP violation reporting</p>
                  <p className="text-xs text-gray-500">Mirror renderer reports into telemetry store</p>
                </div>
                <span
                  className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                    settings.enableCspReporting ? 'bg-green-500/30 text-green-200' : 'bg-gray-600/30 text-gray-300'
                  }`}
                >
                  {settings.enableCspReporting ? 'Enabled' : 'Disabled'}
                </span>
              </div>
              <button
                className="px-3 py-1.5 rounded-lg border border-gray-700 text-xs text-gray-300 hover:border-cyan-500/50"
                onClick={() =>
                  persistSettings((prev) => ({ ...prev, enableCspReporting: !prev.enableCspReporting }))
                }
              >
                Toggle CSP reporting
              </button>
            </section>

            <section className="rounded-xl border border-gray-800 p-4 bg-[#090912] space-y-4">
              <div>
                <p className="text-sm font-semibold text-white">Privacy FAQs</p>
                <p className="text-xs text-gray-500">Short answers for the most common concerns.</p>
              </div>
              <div className="space-y-3">
                {PRIVACY_QA.map((item) => (
                  <div key={item.question} className="rounded-lg border border-gray-800 bg-black/20 p-3">
                    <p className="text-xs font-semibold text-cyan-200">{item.question}</p>
                    <p className="text-[11px] text-gray-300 mt-1">{item.answer}</p>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-xl border border-gray-800 p-4 bg-[#090912] space-y-3">
              <div>
                <p className="text-sm font-semibold text-white">Plain-language glossary</p>
                <p className="text-xs text-gray-500">Key terms you will see inside Sentinel.</p>
              </div>
              <dl className="space-y-2">
                {GLOSSARY_ENTRIES.map((entry) => (
                  <div key={entry.term}>
                    <dt className="text-xs font-semibold text-amber-200">{entry.term}</dt>
                    <dd className="text-[11px] text-gray-300">{entry.description}</dd>
                  </div>
                ))}
              </dl>
            </section>

            <section className="rounded-xl border border-gray-800 p-4 bg-[#090912] space-y-3">
              <div>
                <p className="text-sm font-semibold text-white">Zero-risk sentinel checks</p>
                <p className="text-xs text-gray-500">
                  Every suggestion is cross-compared against these internal policies before you ever see it.
                </p>
              </div>
              <ul className="space-y-2 text-[11px] text-gray-300">
                {ZERO_RISK_POLICIES.map((policy) => (
                  <li key={policy.title} className="rounded-lg border border-gray-800 bg-black/20 p-2">
                    <p className="text-xs font-semibold text-cyan-200">{policy.title}</p>
                    <p className="mt-1 text-gray-400 leading-snug">{policy.description}</p>
                  </li>
                ))}
              </ul>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PolicyComposer;
