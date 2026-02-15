import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { notify } from '../Common/SentinelNotification';
import { useNavigate } from 'react-router-dom';
import { getPortIntel, HTTPS_TRAFFIC_NOTE, getKnowledgeTopic } from '../../../shared/portIntel';
import { getProcessKillRisk } from '../../../shared/constants';
import { useAdmin } from '../../contexts/AdminContext';
import InfoHint from '../Common/InfoHint';
import type { ShieldAPI } from '../../../preload/preload';

const getShieldApi = (): ShieldAPI | undefined => {
  return window.electronAPI?.shield;
};

interface NetworkConnection {
  localIP: string;
  localPort: number;
  remoteIP: string;
  remotePort: number;
  protocol: string;
  state: string;
  process: string;
  pid: number;
  bandwidth: number;
  watchHitCount?: number;
  processPath?: string;
  processCompany?: string;
  processDescription?: string;
  ipTag?: 'loopback' | 'lan' | 'vpn-tunnel' | 'external';
}

interface IPMetadata {
  ip: string;
  type: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  isp: string;
  org: string;
  timezone: string;
  lat: number;
  lon: number;
  reputation: string;
  riskLevel: string;
  zip?: string;
  as?: string;
  raw?: any;
}

interface EnrichedConnection extends NetworkConnection {
  metadata?: IPMetadata;
  metadataLoading?: boolean;
  metadataError?: string;
  tlsState?: 'idle' | 'loading' | 'ready' | 'error';
  tlsSummary?: TLSInspectionSummary;
  tlsError?: string;
}

interface NetworkMonitorProps {
  onSelectTarget?: (target: { ip: string; port?: number; process?: string; pid?: number }) => void;
}

const POLLING_INTERVAL = 2000;
const FETCH_LIMIT = 600;
const MAX_DISPLAY = 200;
const VIRTUALIZATION_THRESHOLD = 140;
const VIRTUAL_ROW_HEIGHT = 182;
const VIRTUAL_OVERSCAN = 8;

const VPN_KEYWORDS = [
  'vpn',
  'm247',
  'nordvpn',
  'expressvpn',
  'proton',
  'private internet access',
  'surfshark',
  'ovh',
  'digital energy technologies',
  'datacamp limited'
];

const CLOUD_KEYWORDS = [
  'amazon',
  'aws',
  'google',
  'microsoft',
  'azure',
  'akamai',
  'oracle',
  'cloudflare',
  'digitalocean',
  'linode',
  'vultr',
  'hetzner',
  'ovhcloud'
];

const ENTERPRISE_SAFE_SUFFIXES = ['communications', 'telecom', 'telecommunications', 'communications llc'];

type ProviderCategory = 'vpn' | 'cloud' | 'isp' | 'enterprise' | 'unknown';

interface ProviderInfo {
  name: string;
  category: ProviderCategory;
  verified: boolean;
}

const analyzeProvider = (meta?: IPMetadata): ProviderInfo => {
  if (!meta) return { name: 'Unknown', category: 'unknown', verified: false };
  const org = (meta.org || meta.isp || '').trim();
  const asName = (meta.as || '').trim();
  const rawOrg = meta.raw?.org || meta.raw?.asn?.name || '';
  const combined = `${org} ${asName} ${rawOrg}`.toLowerCase();

  const matchesKeyword = (keywords: string[]) => keywords.some((kw) => kw && combined.includes(kw));

  if (matchesKeyword(VPN_KEYWORDS)) {
    return { name: org || rawOrg || 'VPN Provider', category: 'vpn', verified: true };
  }
  if (matchesKeyword(CLOUD_KEYWORDS)) {
    return { name: org || rawOrg || 'Cloud Provider', category: 'cloud', verified: true };
  }

  const ispMatch = ENTERPRISE_SAFE_SUFFIXES.some((suffix) => combined.includes(suffix));
  if (ispMatch || meta.isp) {
    return { name: org || meta.isp || 'ISP', category: 'isp', verified: Boolean(org || meta.isp) };
  }

  if (org) {
    return { name: org, category: 'enterprise', verified: true };
  }

  return { name: 'Unknown', category: 'unknown', verified: false };
};

const providerBadgeClass = (category: ProviderCategory) => {
  switch (category) {
    case 'vpn':
      return 'text-red-300 border-red-500/40 bg-red-500/10';
    case 'cloud':
      return 'text-orange-300 border-orange-500/40 bg-orange-500/10';
    case 'isp':
      return 'text-green-300 border-green-500/40 bg-green-500/10';
    case 'enterprise':
      return 'text-blue-300 border-blue-500/40 bg-blue-500/10';
    default:
      return 'text-gray-300 border-gray-600 bg-gray-800/60';
  }
};

const isPrivateIP = (ip?: string): boolean => {
  if (!ip) {
    return false;
  }
  const normalized = ip.trim();
  if (!normalized) {
    return false;
  }
  return normalized.startsWith('192.168.') || normalized.startsWith('10.') ||
    normalized.startsWith('172.16.') || normalized.startsWith('172.17.') ||
    normalized.startsWith('172.18.') || normalized.startsWith('172.19.') ||
    normalized.startsWith('172.20.') || normalized.startsWith('172.21.') ||
    normalized.startsWith('172.22.') || normalized.startsWith('172.23.') ||
    normalized.startsWith('172.24.') || normalized.startsWith('172.25.') ||
    normalized.startsWith('172.26.') || normalized.startsWith('172.27.') ||
    normalized.startsWith('172.28.') || normalized.startsWith('172.29.') ||
    normalized.startsWith('172.30.') || normalized.startsWith('172.31.') ||
    normalized.startsWith('127.') || normalized.startsWith('0.') ||
    normalized === '::' || normalized === '::1' || normalized === '0.0.0.0';
};

const getCountryFlag = (code: string): string => {
  if (!code || code.length !== 2 || code === '??') return '🌐';
  const codePoints = code.toUpperCase().split('').map(c => 127397 + c.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
};

const getRiskColor = (risk: string): string => {
  switch (risk) {
    case 'high': return 'text-red-400 bg-red-500/10 border-red-500/30';
    case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    case 'low': return 'text-green-400 bg-green-500/10 border-green-500/30';
    default: return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
  }
};

const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes.toFixed(0)} B/s`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB/s`;
};

interface AddressWatchRecord {
  ip: string;
  registeredAt: number;
  hits: number;
  lastSeen: number;
}

interface TLSInspectionSummary {
  host: string;
  status: string;
  grade?: string;
  protocols?: string[];
  issues: string[];
  fetchedAt: number;
}

const STATE_COLORS: Record<string, string> = {
  Established: 'text-emerald-400',
  Listen: 'text-blue-400',
  TimeWait: 'text-gray-500',
  CloseWait: 'text-yellow-400',
  SynSent: 'text-violet-400',
  SynReceived: 'text-violet-300',
  FinWait1: 'text-gray-400',
  FinWait2: 'text-gray-400',
  Closing: 'text-orange-400',
  LastAck: 'text-orange-300',
  Bound: 'text-blue-300',
};

const IP_TAG_CONFIG: Record<string, { label: string; color: string }> = {
  'loopback': { label: 'Loopback', color: 'text-gray-400 border-gray-600 bg-gray-800/40' },
  'lan': { label: 'LAN', color: 'text-blue-300 border-blue-500/40 bg-blue-500/10' },
  'vpn-tunnel': { label: 'via VPN', color: 'text-amber-300 border-amber-500/40 bg-amber-500/10' },
  'external': { label: 'External', color: 'text-cyan-300 border-cyan-500/40 bg-cyan-500/10' },
};

const WATCHLIST_EVENT = 'shield-watchlist-updated';

const NetworkMonitor: React.FC<NetworkMonitorProps> = ({ onSelectTarget }) => {
  const { isAdmin } = useAdmin();
  const navigate = useNavigate();
  const [connections, setConnections] = useState<EnrichedConnection[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedIP, setExpandedIP] = useState<string | null>(null);
  const [filterQuery, setFilterQuery] = useState('');
  const [ipFilter, setIpFilter] = useState<'all' | 'external' | 'local'>('all');
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const [killingPid, setKillingPid] = useState<number | null>(null);
  const [watchlist, setWatchlist] = useState<AddressWatchRecord[]>([]);
  const [watchLoading, setWatchLoading] = useState(false);
  const [metadataVersion, setMetadataVersion] = useState(0);
  const [respawnAlerts, setRespawnAlerts] = useState<Record<string, EnrichedConnection>>({});
  const [showSummary, setShowSummary] = useState(true);
  const processWatchRef = useRef<Set<string>>(new Set());
  const listRef = useRef<HTMLDivElement | null>(null);
  const [virtualWindow, setVirtualWindow] = useState<{ start: number; end: number }>({
    start: 0,
    end: MAX_DISPLAY,
  });

  
  const metadataCache = useRef<Map<string, IPMetadata>>(new Map());
  const pollingTimer = useRef<NodeJS.Timeout | null>(null);
  const connectionsController = useRef<AbortController | null>(null);
  const metadataControllers = useRef<Map<string, AbortController>>(new Map());

  const fetchConnections = useCallback(async () => {
    const controller = new AbortController();
    connectionsController.current?.abort();
    connectionsController.current = controller;
    try {
      console.log('[NetworkMonitor] Fetching connections...');
      
      const shield = getShieldApi();
      if (!shield?.getNetworkTraffic) {
        console.error('[NetworkMonitor] API not available');
        if (!controller.signal.aborted) {
          setLoading(false);
        }
        return;
      }

      const data = await shield.getNetworkTraffic(MAX_DISPLAY);
      if (controller.signal.aborted) {
        return;
      }
      
      console.log('[NetworkMonitor] Received:', Array.isArray(data) ? data.length : 0, 'connections');
      
      if (!Array.isArray(data) || data.length === 0) {
        console.warn('[NetworkMonitor] No valid data');
        setConnections([]);
        setLoading(false);
        return;
      }

      const enriched: EnrichedConnection[] = data.map((conn: NetworkConnection) => {
        const cached = metadataCache.current.get(conn.remoteIP);
        return {
          ...conn,
          metadata: cached,
          metadataLoading: false,
          metadataError: undefined
        };
      });
      
      console.log('[NetworkMonitor] Setting', enriched.length, 'connections');
      setConnections(prev => {
        if (prev.length === enriched.length) {
          let identical = true;
          for (let i = 0; i < prev.length; i++) {
            if (
              prev[i].remoteIP !== enriched[i].remoteIP ||
              prev[i].remotePort !== enriched[i].remotePort ||
              prev[i].pid !== enriched[i].pid ||
              prev[i].state !== enriched[i].state ||
              prev[i].bandwidth !== enriched[i].bandwidth
            ) {
              identical = false;
              break;
            }
          }
          if (identical) {
            return prev;
          }
        }
        return enriched;
      });
      setLastUpdate(new Date());
      setLoading(false);

      const alerts: Record<string, EnrichedConnection> = {};
      enriched.forEach((conn) => {
        if (processWatchRef.current.has(conn.process)) {
          alerts[conn.process] = conn;
        }
      });
      setRespawnAlerts(alerts);
      
    } catch (err: any) {
      if (controller.signal.aborted) {
        return;
      }
      console.error('[NetworkMonitor] Error:', err);
      setLoading(false);
    }
  }, []);

  const fetchMetadata = useCallback(async (ip: string) => {
    if (metadataCache.current.has(ip)) {
      return metadataCache.current.get(ip)!;
    }
    const controller = new AbortController();
    metadataControllers.current.set(ip, controller);

    console.log('[NetworkMonitor] Fetching metadata for', ip);
    setConnections(prev => prev.map(c => 
      c.remoteIP === ip ? { ...c, metadataLoading: true, metadataError: undefined } : c
    ));

    try {
      const shield = getShieldApi();
      const result = await shield?.getIpMetadata(ip);
      if (controller.signal.aborted) {
        return null;
      }

      if (result?.success && result.data) {
        const metadata = result.data as IPMetadata;
        if (metadataCache.current.size >= 500) {
          const firstKey = metadataCache.current.keys().next().value;
          if (firstKey) metadataCache.current.delete(firstKey);
        }
        metadataCache.current.set(ip, metadata);
        setMetadataVersion((prev) => prev + 1);

        setConnections(prev => prev.map(c => 
          c.remoteIP === ip ? { ...c, metadata, metadataLoading: false } : c
        ));
        
        metadataControllers.current.delete(ip);
        return metadata;
      } else {
        throw new Error(result.error || 'Failed to fetch');
      }
    } catch (err: any) {
      console.error(`[NetworkMonitor] Metadata error:`, err);
      if (!controller.signal.aborted) {
        setConnections(prev => prev.map(c => 
          c.remoteIP === ip ? { ...c, metadataLoading: false, metadataError: err.message } : c
        ));
      }
      metadataControllers.current.delete(ip);
      return null;
    }
  }, []);

  const prefetchWatchlistMetadata = useCallback(async (records: AddressWatchRecord[]) => {
    for (const record of records) {
      const targetIP = record.ip?.trim();
      if (!targetIP || isPrivateIP(targetIP) || metadataCache.current.has(targetIP)) {
        continue;
      }
      try {
        await fetchMetadata(targetIP);
      } catch (err) {
        console.warn('[NetworkMonitor] Prefetch metadata failed:', err);
      }
    }
  }, [fetchMetadata]);

  const emitWatchlistUpdate = useCallback(() => {
    try {
      window.dispatchEvent(new CustomEvent(WATCHLIST_EVENT, { detail: { source: 'NetworkMonitor' } }));
    } catch (err) {
      console.warn('[NetworkMonitor] Failed to emit watchlist update event', err);
    }
  }, []);

  const refreshWatchlist = useCallback(async () => {
    try {
      setWatchLoading(true);
      const shield = getShieldApi();
      const res = await shield?.getAddressWatch?.();
      if (res?.success) {
        const payload = res.data as unknown;
        const payloadObj = payload as Record<string, unknown> | undefined;
        const records = Array.isArray(payload)
          ? payload
          : Array.isArray(payloadObj?.tracked)
          ? (payloadObj.tracked as unknown[])
          : [];
        setWatchlist(records);
        prefetchWatchlistMetadata(records);
        emitWatchlistUpdate();
      }
    } catch (err) {
      console.error('[NetworkMonitor] Watchlist load failed:', err);
    } finally {
      setWatchLoading(false);
    }
  }, [prefetchWatchlistMetadata, emitWatchlistUpdate]);

  useEffect(() => {
    refreshWatchlist();
  }, [refreshWatchlist]);

  const handleRowClick = useCallback((ip: string) => {
    if (expandedIP === ip) {
      setExpandedIP(null);
    } else {
      setExpandedIP(ip);
      if (!metadataCache.current.has(ip) && !isPrivateIP(ip)) {
        fetchMetadata(ip);
      }
    }
  }, [expandedIP, fetchMetadata]);

  const handleCopyRaw = useCallback((raw?: any) => {
    if (!raw) return;
    try {
      navigator.clipboard?.writeText(JSON.stringify(raw, null, 2));
    } catch (err) {
      console.error('[NetworkMonitor] Copy failed', err);
    }
  }, []);

  const blockIP = useCallback(async (conn: NetworkConnection) => {
    const ip = conn.remoteIP?.trim();
    if (!ip) return;
    try {
      const shield = getShieldApi();
      const reason = `Blocked from Network Monitor — ${conn.process || 'Unknown'} PID ${conn.pid}`;
      const res = await shield?.blockIP?.(ip, reason);
      if (res?.success) {
        notify.success(`Blocked ${ip}. ${res.message || ''}`);
        await fetchConnections();
      } else {
        notify.error(res?.message || 'Failed to block IP');
      }
    } catch (err) {
      notify.error(`Block failed: ${err}`);
    }
  }, [fetchConnections]);

  const sendToFirewall = useCallback((conn: NetworkConnection) => {
    // Cross-link: navigate to Firewall page with IP pre-filled for blocking
    navigate('/firewall', { state: { prefillIP: conn.remoteIP, source: 'network', process: conn.process, pid: conn.pid } });
  }, [navigate]);

  const navigateToIntel = useCallback((ip: string) => {
    // Cross-link: navigate to Intel page with IP pre-filled for scanning
    navigate('/intel', { state: { scanUrl: ip, source: 'network' } });
  }, [navigate]);

  const killConnection = useCallback(async (conn: NetworkConnection) => {
    if (!conn?.pid) return;
    try {
      setKillingPid(conn.pid);
      const shield = getShieldApi();
      await shield?.killProcess?.(conn.pid, conn.process || `PID ${conn.pid}`);
      processWatchRef.current.add(conn.process);
      await fetchConnections();
    } catch (err) {
      console.error('[NetworkMonitor] Kill process failed', err);
    } finally {
      setKillingPid((prev) => (prev === conn.pid ? null : prev));
    }
  }, [fetchConnections]);

  const monitorIP = useCallback(async (ip: string) => {
    const target = (ip || '').trim();
    if (!target) return;
    try {
      const shield = getShieldApi();
      const res = await shield?.registerAddressWatch?.(target);
      if (res?.success) {
        refreshWatchlist();
        if (!isPrivateIP(target)) {
          fetchMetadata(target);
        }
        notify.success(`Monitoring ${target}. Sentinel will warn on repeated attempts.`);
        emitWatchlistUpdate();
      } else {
        notify.error(res?.error || 'Failed to monitor IP');
      }
    } catch (err) {
      notify.error(`Monitor error: ${err}`);
    }
  }, [fetchMetadata, refreshWatchlist, emitWatchlistUpdate]);

  const inspectTls = useCallback(async (ip: string) => {
    if (!ip) return;
    setConnections((prev) =>
      prev.map((conn) =>
        conn.remoteIP === ip
          ? { ...conn, tlsState: 'loading', tlsError: undefined }
          : conn
      )
    );
    try {
      const shield = getShieldApi();
      const res = await shield?.inspectTls?.(ip);
      setConnections((prev) =>
        prev.map((conn) =>
          conn.remoteIP === ip
            ? {
                ...conn,
                tlsState: res?.success ? 'ready' : 'error',
                tlsSummary: res?.data as TLSInspectionSummary | undefined,
                tlsError: res?.success ? undefined : res?.error || 'TLS inspection failed',
              }
            : conn
        )
      );
    } catch (err: any) {
      setConnections((prev) =>
        prev.map((conn) =>
          conn.remoteIP === ip
            ? { ...conn, tlsState: 'error', tlsError: err?.message || String(err) }
            : conn
        )
      );
    }
  }, []);

  const blockRespawnProcess = useCallback(
    async (conn: EnrichedConnection) => {
      try {
        const shield = getShieldApi();
        const res = await shield?.blockPid?.({ pid: conn.pid, direction: 'both' });
        if (!res?.success) {
          notify.error(res?.message || res?.error || 'Failed to re-block process');
        } else {
          notify.success(`Process ${conn.process} (PID ${conn.pid}) blocked again.`);
          processWatchRef.current.delete(conn.process);
          setRespawnAlerts((prev) => {
            const clone = { ...prev };
            delete clone[conn.process];
            return clone;
          });
        }
      } catch (err) {
        notify.error(`Block failed: ${err}`);
      }
    },
    []
  );

  const dismissRespawn = useCallback((processName: string) => {
    processWatchRef.current.delete(processName);
    setRespawnAlerts((prev) => {
      const clone = { ...prev };
      delete clone[processName];
      return clone;
    });
  }, []);

  useEffect(() => {
    fetchConnections();
    pollingTimer.current = setInterval(fetchConnections, POLLING_INTERVAL);
    return () => {
      if (pollingTimer.current) clearInterval(pollingTimer.current);
      connectionsController.current?.abort();
      metadataControllers.current.forEach((controller) => controller.abort());
      metadataControllers.current.clear();
    };
  }, [fetchConnections]);

  const normalizedFilter = filterQuery.trim().toLowerCase();

  const matchesFilter = (conn: NetworkConnection) => {
    if (!normalizedFilter) return true;
    const tokens = [
      conn.process,
      conn.pid?.toString(),
      conn.remoteIP,
      conn.remotePort?.toString(),
      conn.localIP,
      conn.localPort?.toString(),
    ];
    return tokens.some((token) => token?.toLowerCase().includes(normalizedFilter));
  };

  const filtered = connections
    .filter(matchesFilter)
    .filter((c) => {
      if (ipFilter === 'external') {
        return !isPrivateIP(c.remoteIP);
      }
      if (ipFilter === 'local') {
        return isPrivateIP(c.remoteIP);
      }
      return true;
    })
    .sort((a, b) => b.bandwidth - a.bandwidth)
    .slice(0, MAX_DISPLAY);

  const virtualizationEnabled = filtered.length > VIRTUALIZATION_THRESHOLD;

  const updateVirtualWindow = useCallback(
    (scrollTop: number, viewportHeight: number) => {
      if (!virtualizationEnabled) {
        return;
      }
      const start = Math.max(0, Math.floor(scrollTop / VIRTUAL_ROW_HEIGHT) - VIRTUAL_OVERSCAN);
      const visibleCount = Math.ceil(viewportHeight / VIRTUAL_ROW_HEIGHT) + VIRTUAL_OVERSCAN * 2;
      const end = Math.min(filtered.length, start + visibleCount);
      setVirtualWindow((prev) => (prev.start === start && prev.end === end ? prev : { start, end }));
    },
    [filtered.length, virtualizationEnabled]
  );

  useEffect(() => {
    if (!virtualizationEnabled) {
      setVirtualWindow({ start: 0, end: filtered.length });
      return;
    }
    const container = listRef.current;
    if (container) {
      updateVirtualWindow(container.scrollTop, container.clientHeight || VIRTUAL_ROW_HEIGHT);
    }
  }, [filtered.length, virtualizationEnabled, updateVirtualWindow]);

  useEffect(() => {
    if (!virtualizationEnabled) return;
    const handleResize = () => {
      if (!listRef.current) return;
      updateVirtualWindow(listRef.current.scrollTop, listRef.current.clientHeight || VIRTUAL_ROW_HEIGHT);
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [virtualizationEnabled, updateVirtualWindow]);

  const handleVirtualScroll = useCallback(
    (event: React.UIEvent<HTMLDivElement>) => {
      if (!virtualizationEnabled) return;
      const target = event.currentTarget;
      updateVirtualWindow(target.scrollTop, target.clientHeight || VIRTUAL_ROW_HEIGHT);
    },
    [updateVirtualWindow, virtualizationEnabled]
  );

  const visibleConnections = useMemo(() => {
    return virtualizationEnabled
      ? filtered.slice(virtualWindow.start, virtualWindow.end)
      : filtered;
  }, [filtered, virtualWindow, virtualizationEnabled]);

  const topSpacerHeight = virtualizationEnabled ? virtualWindow.start * VIRTUAL_ROW_HEIGHT : 0;
  const renderedHeight = visibleConnections.length * VIRTUAL_ROW_HEIGHT;
  const totalVirtualHeight = virtualizationEnabled ? filtered.length * VIRTUAL_ROW_HEIGHT : 0;
  const bottomSpacerHeight = virtualizationEnabled
    ? Math.max(totalVirtualHeight - topSpacerHeight - renderedHeight, 0)
    : 0;

  const stats = {
    total: filtered.length,
    uniqueIPs: new Set(filtered.map((c) => c.remoteIP)).size,
    uniqueProcesses: new Set(filtered.map((c) => c.process)).size,
    totalBandwidth: filtered.reduce((sum, c) => sum + c.bandwidth, 0),
    enriched: filtered.filter((c) => c.metadata).length,
  };

  const httpsShare = useMemo(() => {
    if (!filtered.length) return 0;
    const httpsCount = filtered.filter((c) => c.remotePort === 443).length;
    return Math.round((httpsCount / filtered.length) * 100);
  }, [filtered]);

  const respawnList = useMemo(() => Object.values(respawnAlerts), [respawnAlerts]);
  const watchlistDetails = useMemo(() => {
    return watchlist.map((record) => ({
      ...record,
      metadata: metadataCache.current.get(record.ip),
    }));
  }, [watchlist, metadataVersion]);
  const watchlistKnowledge = getKnowledgeTopic('addressWatch') ?? {
    title: 'Address Watchlist',
    summary: 'Sentinel tracks IPs you flag and surfaces repeated offenders to highlight stealthy beacons.',
  };

  const renderSummary = () => (
    <div className="p-5 space-y-4">
      <div className="flex items-center gap-3">
        <button
          onClick={fetchConnections}
          className="px-4 py-2 bg-[#12121a] border border-gray-700 rounded-lg text-sm text-gray-400 hover:border-cyan-500 hover:text-cyan-400 transition"
        >
          &#x21bb; Refresh
        </button>
        <InfoHint
          title="Bandwidth calculus"
          description="Stats refresh every poll. Bandwidth column sums both TX/RX bytes from netstat so spikes are obvious."
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-4">
        {[
          { label: 'Connections', value: stats.total, color: 'text-cyan-400' },
          { label: 'Unique IPs', value: stats.uniqueIPs, color: 'text-purple-400' },
          { label: 'Processes', value: stats.uniqueProcesses, color: 'text-green-400' },
          { label: 'Bandwidth', value: formatBytes(stats.totalBandwidth), color: 'text-orange-400' },
        ].map((card) => (
          <div key={card.label} className="sentinel-panel p-3">
            <p className="text-gray-500 text-xs">{card.label}</p>
            <p className={`text-xl font-bold ${card.color}`}>{card.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="sentinel-panel p-4">
          <div className="flex items-center gap-2">
            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wide">HTTPS Dominance</p>
              <p className="text-2xl font-semibold text-cyan-300">{httpsShare}% of remote ports</p>
            </div>
            <InfoHint
              title="Why HTTPS?"
              description="Most malware hides inside TLS tunnels. Sentinel highlights encrypted flows so you can focus on likely exfiltration."
            />
          </div>
          <p className="text-[11px] text-gray-400 mt-1">{HTTPS_TRAFFIC_NOTE}</p>
        </div>
        <div className="sentinel-panel p-4 space-y-2">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wide">Watchlisted IPs</p>
              <p className="text-2xl font-semibold text-purple-300">{watchlist.length}</p>
            </div>
            <button
              className="text-[11px] text-cyan-300 underline"
              onClick={refreshWatchlist}
              disabled={watchLoading}
            >
              Refresh
            </button>
          </div>
          <p className="text-[11px] text-gray-400">
            {watchLoading ? 'Loading watchlist…' : 'Sentinel tracks repeat offenders in real time.'}
          </p>
          {watchlistDetails.length > 0 && (
            <div className="mt-2 space-y-2 max-h-48 overflow-y-auto pr-1 custom-scroll-thin">
              {watchlistDetails.map((record) => {
                const meta = record.metadata;
                return (
                  <div
                    key={record.ip}
                    className={`p-3 rounded-lg border transition ${record.hits >= 2 ? 'border-red-500/40 bg-red-500/5 text-red-100' : 'border-gray-800 bg-black/20 text-gray-200'}`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="font-mono text-sm text-white flex items-center gap-2">
                          {meta ? (
                            <span className="text-lg">{getCountryFlag(meta.countryCode)}</span>
                          ) : (
                            <span className="text-lg">&#x1F310;</span>
                          )}
                          {record.ip}
                        </p>
                        <p className="text-[11px] text-gray-400">
                          {record.lastSeen ? `Last seen ${new Date(record.lastSeen).toLocaleString()}` : 'Awaiting activity'}
                        </p>
                        {meta && (
                          <p className="text-[11px] text-gray-300">
                            {meta.city}, {meta.country} • {meta.org || meta.isp || 'Unknown org'}
                          </p>
                        )}
                      </div>
                      <div className="text-right">
                        <p className="text-xs font-semibold">Hits {record.hits}</p>
                        <button
                          className="mt-1 px-2 py-1 text-[11px] rounded border border-purple-400 text-purple-200 hover:bg-purple-500/10"
                          onClick={(e) => {
                            e.stopPropagation();
                            monitorIP(record.ip);
                          }}
                        >
                          Refresh intel
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {respawnList.length > 0 && (
        <div className="mt-3 p-3 rounded-lg border border-orange-500/40 bg-orange-500/10 text-xs text-orange-200 space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-semibold">Process respawn detected</span>
            <span className="text-[11px]">Auto containment ready</span>
          </div>
          {respawnList.map((alert) => (
            <div key={`${alert.process}-${alert.pid}`} className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-white">{alert.process} (PID {alert.pid})</span>
              <button
                className="px-3 py-1 bg-red-500/20 text-red-300 rounded text-[11px]"
                onClick={() => blockRespawnProcess(alert)}
              >
                Block Again
              </button>
              <button
                className="px-3 py-1 bg-gray-500/20 text-gray-200 rounded text-[11px]"
                onClick={() => dismissRespawn(alert.process)}
              >
                Dismiss
              </button>
            </div>
          ))}
          <p className="text-[10px] text-gray-400">Processes reappearing after termination are strong persistence indicators.</p>
        </div>
      )}

      <div className="mt-3 p-3 rounded-lg border border-cyan-800/50 bg-cyan-500/5 text-xs text-cyan-200">
        <strong>{watchlistKnowledge.title}:</strong> {watchlistKnowledge.summary}
      </div>
    </div>
  );

  const renderConnectionCard = useCallback(
    (conn: EnrichedConnection, index: number) => {
      const meta = conn.metadata;
      const provider = analyzeProvider(meta);
      const portIntel = getPortIntel(conn.remotePort);
      const isExpanded = expandedIP === conn.remoteIP;
      const watchHit = watchlist.find((record) => record.ip === conn.remoteIP);

      return (
        <div
          key={`${conn.remoteIP}-${conn.remotePort}-${conn.pid}-${index}`}
          className={`sentinel-panel border border-gray-900/60 bg-[#05060d]/80 rounded-2xl p-4 transition hover:border-cyan-500/40 ${
            isExpanded ? 'border-cyan-500/70 shadow-[0_0_25px_rgba(0,255,255,0.15)]' : ''
          }`}
          onClick={() => handleRowClick(conn.remoteIP)}
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-xs tracking-[0.2em] text-gray-500 uppercase">{conn.protocol}</p>
              <p className="text-xl font-semibold">
                {conn.process || 'Unknown'} <span className="text-sm text-gray-500">PID {conn.pid ?? '—'}</span>
              </p>
              {conn.processCompany && (
                <p className="text-[11px] text-gray-400">{conn.processCompany}{conn.processDescription ? ` — ${conn.processDescription}` : ''}</p>
              )}
              {conn.processPath && (
                <p className="text-[10px] text-gray-600 font-mono truncate max-w-[400px]" title={conn.processPath}>{conn.processPath}</p>
              )}
              <p className="font-mono text-[13px] text-cyan-300 mt-1">
                {conn.remoteIP}:{conn.remotePort}
                <span className="text-gray-600 mx-1">←</span>
                <span className="text-gray-500">{conn.localIP}:{conn.localPort}</span>
              </p>
            </div>
            <div className="text-right">
              <p className="text-[11px] text-gray-500">State</p>
              <p className={`text-sm font-semibold ${STATE_COLORS[conn.state] || 'text-gray-200'}`}>{conn.state}</p>
              <p className="text-[11px] text-gray-500 mt-2">Bandwidth</p>
              <p className="text-sm text-orange-300">{formatBytes(conn.bandwidth)}</p>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px]">
            {conn.ipTag && IP_TAG_CONFIG[conn.ipTag] && (
              <span className={`px-2 py-0.5 rounded-full border ${IP_TAG_CONFIG[conn.ipTag].color}`}>
                {IP_TAG_CONFIG[conn.ipTag].label}
              </span>
            )}
            {portIntel && (
              <span className="px-2 py-0.5 rounded-full border border-purple-500/40 bg-purple-500/10 text-purple-200">
                {portIntel.label}
              </span>
            )}
            {provider && (
              <span className={`px-2 py-0.5 rounded-full border ${providerBadgeClass(provider.category)}`}>
                {provider.name}
              </span>
            )}
            {watchHit && (
              <span className="px-2 py-0.5 rounded-full border border-red-500/50 bg-red-500/10 text-red-200">
                Watchlisted ×{watchHit.hits}
              </span>
            )}
            {conn.metadataLoading && <span className="text-cyan-300">Fetching intel…</span>}
            {conn.metadataError && <span className="text-orange-300">{conn.metadataError}</span>}
          </div>

          <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
            <button
              className="px-3 py-1.5 bg-[#12121a] border border-orange-700/60 rounded-lg hover:border-orange-500 hover:text-orange-300 disabled:opacity-40"
              disabled={!isAdmin || isPrivateIP(conn.remoteIP)}
              title={isPrivateIP(conn.remoteIP) ? 'Cannot block private/loopback IPs' : `Block ${conn.remoteIP}`}
              onClick={(e) => {
                e.stopPropagation();
                blockIP(conn);
              }}
            >
              Block
            </button>
            <button
              className="px-3 py-1.5 bg-[#12121a] border border-gray-700 rounded-lg hover:border-cyan-500 hover:text-cyan-300"
              onClick={(e) => {
                e.stopPropagation();
                if (!meta && !conn.metadataLoading && !isPrivateIP(conn.remoteIP)) {
                  fetchMetadata(conn.remoteIP);
                } else {
                  handleRowClick(conn.remoteIP);
                }
              }}
            >
              {meta ? 'Collapse intel' : 'Lookup'}
            </button>
            {(() => {
              const killRisk = getProcessKillRisk(conn.process || '', conn.pid || 0);
              if (killRisk === 'forbidden') return (
                <span className="px-3 py-1.5 text-xs text-gray-600 flex items-center gap-1" title="System-critical process — cannot be terminated">🔒 Protected</span>
              );
              if (killRisk === 'dangerous') return (
                <span className="px-3 py-1.5 text-xs text-amber-500 flex items-center gap-1" title="Sentinel process">⚠ Sentinel</span>
              );
              return (
                <button
                  className="px-3 py-1.5 bg-[#12121a] border border-gray-700 rounded-lg hover:border-red-500 hover:text-red-200 disabled:opacity-40"
                  disabled={!isAdmin || !conn.pid || killingPid === conn.pid}
                  onClick={(e) => {
                    e.stopPropagation();
                    killConnection(conn);
                  }}
                >
                  {killingPid === conn.pid ? 'Killing…' : killRisk === 'caution' ? '⚠ Kill' : 'Kill Process'}
                </button>
              );
            })()}
            <button
              className="px-3 py-1.5 bg-[#12121a] border border-gray-700 rounded-lg hover:border-blue-500 hover:text-blue-200"
              onClick={(e) => {
                e.stopPropagation();
                inspectTls(conn.remoteIP);
              }}
            >
              {conn.tlsState === 'loading' ? 'Inspecting…' : 'TLS'}
            </button>
            <button
              className="px-3 py-1.5 bg-[#12121a] border border-gray-700 rounded-lg hover:border-purple-500 hover:text-purple-200"
              onClick={(e) => {
                e.stopPropagation();
                sendToFirewall(conn);
              }}
            >
              Firewall
            </button>
            <button
              className="px-3 py-1.5 bg-[#12121a] border border-gray-700 rounded-lg hover:border-yellow-500 hover:text-yellow-200"
              disabled={isPrivateIP(conn.remoteIP)}
              onClick={(e) => {
                e.stopPropagation();
                navigateToIntel(conn.remoteIP);
              }}
            >
              Scan Intel
            </button>
            <button
              className="px-3 py-1.5 bg-[#12121a] border border-gray-700 rounded-lg hover:border-emerald-500 hover:text-emerald-200"
              onClick={(e) => {
                e.stopPropagation();
                monitorIP(conn.remoteIP);
              }}
            >
              {watchHit ? 'Re-arm watch' : 'Watch IP'}
            </button>
          </div>

          {isExpanded && (
            <div className="mt-4 space-y-4 text-sm text-gray-200 border-t border-gray-800 pt-4">
              {meta ? (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div>
                    <p className="text-[11px] text-gray-500">Geolocation</p>
                    <p>{meta.city}, {meta.region}</p>
                    <p>{meta.country} ({meta.countryCode})</p>
                  </div>
                  <div>
                    <p className="text-[11px] text-gray-500">Org / ASN</p>
                    <p>{meta.org || meta.isp || 'Unknown org'}</p>
                    {meta.as && <p>{meta.as}</p>}
                  </div>
                  <div>
                    <p className="text-[11px] text-gray-500">Reputation</p>
                    <span className={`inline-flex items-center gap-2 px-2 py-1 rounded border ${getRiskColor(meta.riskLevel)}`}>
                      {meta.riskLevel.toUpperCase()}
                    </span>
                    <p className="text-[11px] text-gray-400">{meta.reputation || 'Unknown history'}</p>
                  </div>
                </div>
              ) : (
                <p className="text-[12px] text-gray-500">No intel yet. Fetch metadata to resolve this IP via the local cache.</p>
              )}

              {conn.tlsState && (
                <div className="rounded-xl border border-blue-500/40 bg-blue-500/5 p-4 text-[13px]">
                  <div className="flex items-center justify-between">
                    <strong className="text-blue-200">TLS Inspection</strong>
                    <span>
                      {conn.tlsState === 'loading'
                        ? 'Loading…'
                        : conn.tlsSummary?.grade || conn.tlsSummary?.status || conn.tlsState.toUpperCase()}
                    </span>
                  </div>
                  {conn.tlsError && <p className="text-orange-300 mt-2">{conn.tlsError}</p>}
                  {conn.tlsSummary && (
                    <div className="mt-2 space-y-1 text-gray-200">
                      <p>Status: {conn.tlsSummary.status}</p>
                      <p>Protocols: {conn.tlsSummary.protocols?.join(', ') || 'n/a'}</p>
                      {conn.tlsSummary.issues?.length ? (
                        <p className="text-red-300">Issues: {conn.tlsSummary.issues.join('; ')}</p>
                      ) : (
                        <p className="text-green-300">No major SSL Labs issues detected.</p>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      );
    },
    [
      expandedIP,
      fetchMetadata,
      handleRowClick,
      inspectTls,
      isAdmin,
      killConnection,
      killingPid,
      monitorIP,
      sendToFirewall,
      watchlist,
    ]
  );

  return (
    <div className="flex flex-col h-full bg-[var(--sentinel-bg)] text-white border border-gray-900/40 rounded-2xl overflow-hidden shadow-[0_30px_80px_rgba(3,8,41,0.65)]">
      <div className="p-5 border-b border-gray-900/60 bg-[var(--sentinel-panel)] flex flex-col gap-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <p className="text-[11px] text-gray-500 tracking-[0.4em]">SENTINEL SENSOR</p>
            <h2 className="text-2xl font-black">Network Monitor</h2>
            <p className="text-sm text-gray-400 max-w-2xl">
              Real-time socket inventory with provider intel, TLS inspection, and watchlist triggers. Tap "?" chips to learn what each
              metric means before reacting.
            </p>
          </div>
          <div className="flex items-center gap-2 text-[11px] text-gray-400">
            <span>Last update: {lastUpdate.toLocaleTimeString()}</span>
            {loading && <span className="text-cyan-300">Polling…</span>}
          </div>
        </div>

        <div className="flex flex-wrap gap-3 text-[11px] text-gray-400">
          <InfoHint
            label="Polling"
            title="2-second refresh"
            description="Sentinel samples netstat/Get-NetTCPConnection every 2 seconds. Pause by switching to manual mode if you need a frozen view."
          />
          <InfoHint
            label="Metadata"
            title="Local cache"
            description="IP metadata is cached locally to avoid leaking lookups. Clicking a row fetches intel only for that IP, then stores it on disk."
          />
          <InfoHint
            label="Watchlist"
            title="Two-hit alert"
            description="Add an IP to the watchlist to get alerted once it connects twice. Great for tracking persistent beacons."
          />
        </div>
      </div>

      <div className="p-5 border-b border-gray-900 bg-[var(--sentinel-panel)]">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex flex-wrap gap-2 flex-1">
            <input
              type="text"
              placeholder="Filter by process, IP, provider, PID…"
              className="flex-1 min-w-[220px] px-3 py-2 bg-[#12121a] border border-gray-800 rounded-lg text-sm text-white placeholder-gray-600 focus:border-cyan-500 focus:outline-none"
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
            />
            <div className="flex items-center gap-2 text-[11px] text-gray-400">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={ipFilter === 'external'}
                  onChange={(e) => setIpFilter(e.target.checked ? 'external' : 'all')}
                  className="rounded text-cyan-400"
                />
                External only
              </label>
              <InfoHint
                title="Scope"
                description="Flip between external, local, or everything. External mode hides noisy localhost chatter so you can focus on potential threats."
              />
            </div>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <button
              className="px-4 py-2 bg-[#12121a] border border-gray-700 rounded-lg text-sm text-gray-400 hover:border-cyan-500 hover:text-cyan-400 transition"
              onClick={() => setShowSummary(prev => !prev)}
            >
              {showSummary ? '▼' : '▶'} Summary
            </button>
          </div>
        </div>
      </div>

      {showSummary && (
        <div className="border-b border-gray-900 bg-[var(--sentinel-panel)]">
          {renderSummary()}
        </div>
      )}

      <section className="flex-1 flex flex-col gap-4 p-5 overflow-hidden">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <p className="text-[11px] text-gray-500 tracking-[0.4em] uppercase">Live sockets</p>
            <h3 className="text-xl font-semibold">{stats.total} tracked connections</h3>
          </div>
          <div className="text-[11px] text-gray-400 flex items-center gap-2">
            <InfoHint
              label="Virtualization"
              title="Performance guardrails"
              description="Lists over 140 rows switch to virtualization — only visible cards render to keep the UI responsive."
            />
            <span>
              Showing {visibleConnections.length} of {filtered.length} (top {MAX_DISPLAY})
            </span>
          </div>
        </div>

        <div className="relative flex-1 sentinel-panel border border-gray-900/70 bg-[#05060d]/70 rounded-2xl overflow-hidden">
          {filtered.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center text-center space-y-2 text-gray-500">
              <p>No live connections match your filters.</p>
              <button
                className="px-4 py-2 border border-gray-700 rounded-lg hover:border-cyan-500 hover:text-cyan-300"
                onClick={fetchConnections}
              >
                Refresh now
              </button>
            </div>
          ) : (
            <div ref={listRef} onScroll={handleVirtualScroll} className="h-full overflow-auto custom-scroll pr-2">
              {virtualizationEnabled && <div style={{ height: topSpacerHeight }} />}
              <div className="flex flex-col gap-4">
                {visibleConnections.map((conn, idx) => renderConnectionCard(conn, virtualWindow.start + idx))}
              </div>
              {virtualizationEnabled && <div style={{ height: bottomSpacerHeight }} />}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

export default NetworkMonitor;
