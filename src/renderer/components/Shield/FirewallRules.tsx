import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type {
  ShieldBlockPortRequest,
  ShieldBlockSubnetRequest,
  ShieldBlockPidRequest,
  ShieldManualBlockLogRequest,
  ShieldBlockedIpRecord,
  ShieldFirewallInventoryMeta,
  SentinelFirewallRule,
} from '../../../shared/ipcSchemas';
import type { ShieldAPI } from '../../../preload/preload';
import { useAdmin } from '../../contexts/AdminContext';
import ActionBar from '../Common/ActionBar';
import { getPortIntel, HTTPS_TRAFFIC_NOTE, getKnowledgeTopic, KnowledgeKey } from '../../../shared/portIntel';
import { usePendingRules } from '../../hooks/usePendingRules';
import InfoHint from '../Common/InfoHint';
import { notify } from '../Common/SentinelNotification';
import { useConfirmDialog } from '../../hooks/useConfirmDialog';
import ConfirmDialog from '../Common/ConfirmDialog';

const getShieldApi = (): ShieldAPI | undefined => window.electronAPI?.shield;

const WATCHLIST_EVENT = 'shield-watchlist-updated';

interface FirewallRulesProps {
  targetIP?: string;
  targetPort?: number;
  targetPid?: number;
  targetProcess?: string;
  onClearTarget?: () => void;
}

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

interface UndoRedoState {
  canUndo: boolean;
  canRedo: boolean;
}

type RuleSortOption = 'newest' | 'oldest' | 'name';

const sortOptions: { label: string; value: RuleSortOption }[] = [
  { label: 'Newest', value: 'newest' },
  { label: 'Oldest', value: 'oldest' },
  { label: 'Name A→Z', value: 'name' },
];

const TLS_READY_STATUSES = new Set(['READY', 'READY_CACHE']);
const TLS_POLLABLE_STATUSES = new Set([
  'DNS',
  'IN_PROGRESS',
  'INITIALIZING',
  'STARTING',
  'RUNNING',
  'PENDING',
  'PROCESSING',
]);
const TLS_MAX_ATTEMPTS = 6;
const TLS_RETRY_BASE_DELAY_MS = 2500;
const TLS_COOLDOWN_MS = 8000;

const formatRuleTimestamp = (input?: string | null) => {
  if (!input) return 'Unknown';
  const parsed = new Date(input);
  if (Number.isNaN(parsed.getTime())) return 'Unknown';
  return parsed.toLocaleString();
};

const coerceErrorMessage = (error: unknown): string => {
  if (!error) return 'Unknown error';
  if (typeof error === 'string') return error;
  if (error instanceof Error) return error.message;
  if (typeof error === 'object') {
    const maybe = error as { message?: unknown };
    if (typeof maybe.message === 'string') {
      return maybe.message;
    }
    try {
      return JSON.stringify(error);
    } catch {
      return String(error);
    }
  }
  return String(error);
};

const subnetOptions: Array<{ label: string; value: 8 | 16 | 20 | 22 | 24 | 26 | 30 | 32 }> = [
  { label: '/32 (1 IP)', value: 32 },
  { label: '/30 (4 IPs)', value: 30 },
  { label: '/26 (64 IPs)', value: 26 },
  { label: '/24 (256 IPs)', value: 24 },
  { label: '/22 (1K IPs)', value: 22 },
  { label: '/20 (4K IPs)', value: 20 },
  { label: '/16 (65K IPs)', value: 16 },
  { label: '/8 (16M IPs)', value: 8 },
];

const KnowledgePanel: React.FC<{ topic: KnowledgeKey }> = ({ topic }) => {
  const info = getKnowledgeTopic(topic);
  return (
    <div className="mt-3 rounded-lg border border-cyan-900/40 bg-cyan-500/5 p-3 text-xs text-gray-300">
      <div className="flex items-center justify-between">
        <span className="text-white font-semibold">{info.title}</span>
      </div>
      <p className="text-[11px] text-gray-300 mt-1">{info.summary}</p>
      {info.bullets && (
        <ul className="mt-2 list-disc list-inside text-[11px] text-cyan-200 space-y-1">
          {info.bullets.map((bullet) => (
            <li key={bullet}>{bullet}</li>
          ))}
        </ul>
      )}
    </div>
  );
};

const FirewallRules: React.FC<FirewallRulesProps> = ({ targetIP, targetPort, targetPid, targetProcess, onClearTarget }) => {
  const { isAdmin } = useAdmin();
  const { dialogState, confirm: confirmAction, handleConfirm: onDialogConfirm, handleCancel: onDialogCancel } = useConfirmDialog();
  const { pendingRules, loading: pendingLoading, error: pendingError, commitPendingRule } = usePendingRules();

  const [blockPort, setBlockPort] = useState('');
  const [blockIP, setBlockIP] = useState('');
  const [blockPid, setBlockPid] = useState('');
  const [blockLoopbackOnly, setBlockLoopbackOnly] = useState(false);
  const [useCIDR, setUseCIDR] = useState(false);
  const [subnetMask, setSubnetMask] = useState<8 | 16 | 20 | 22 | 24 | 26 | 30 | 32>(24);
  const [pidDirection, setPidDirection] = useState<'in' | 'out' | 'both'>('both');
  const [firewallRules, setFirewallRules] = useState<SentinelFirewallRule[]>([]);
  const [blockedIps, setBlockedIps] = useState<ShieldBlockedIpRecord[]>([]);
  const [inventoryMeta, setInventoryMeta] = useState<ShieldFirewallInventoryMeta | null>(null);
  const [undoRedoState, setUndoRedoState] = useState<UndoRedoState>({ canUndo: false, canRedo: false });
  const [loadingRules, setLoadingRules] = useState(false);
  const [sortBy, setSortBy] = useState<RuleSortOption>('newest');
  const [watchlist, setWatchlist] = useState<AddressWatchRecord[]>([]);
  const [watchLoading, setWatchLoading] = useState(false);
  const [tlsHost, setTlsHost] = useState('');
  const [tlsState, setTlsState] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [tlsResult, setTlsResult] = useState<TLSInspectionSummary | null>(null);
  const [tlsError, setTlsError] = useState('');
  const [tlsAttempts, setTlsAttempts] = useState(0);
  const [tlsStatusMessage, setTlsStatusMessage] = useState('');
  const [tlsCooldownUntil, setTlsCooldownUntil] = useState(0);
  const [tlsLastHost, setTlsLastHost] = useState('');
  const tlsRetryRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [selectedRuleIdx, setSelectedRuleIdx] = useState<number | null>(null);
  const [exportFormat, setExportFormat] = useState<'txt' | 'csv' | 'json'>('txt');
  const [exporting, setExporting] = useState(false);

  const selectedPortIntel = useMemo(() => {
    const numeric = Number(blockPort);
    if (!Number.isFinite(numeric)) return undefined;
    return getPortIntel(numeric);
  }, [blockPort]);

  const sortedRules = useMemo(() => {
    const copy = [...firewallRules];
    const getTime = (rule: SentinelFirewallRule) => (rule.timeCreated ? new Date(rule.timeCreated).getTime() : 0);
    return copy.sort((a, b) => {
      switch (sortBy) {
        case 'oldest':
          return getTime(a) - getTime(b);
        case 'name':
          return (a.name || '').localeCompare(b.name || '');
        case 'newest':
        default:
          return getTime(b) - getTime(a);
      }
    });
  }, [firewallRules, sortBy]);

  const ruleStats = useMemo(() => {
    const inbound = firewallRules.filter((r) => r.direction?.toLowerCase().includes('in')).length;
    const outbound = firewallRules.filter((r) => r.direction?.toLowerCase().includes('out')).length;
    const disabled = firewallRules.filter((r) => r.enabled === false || String(r.enabled).toLowerCase() === 'no').length;
    return { inbound, outbound, disabled };
  }, [firewallRules]);

  const formatEndpoint = useCallback((ip?: string, port?: string | number) => {
    const safeIP = ip && ip !== 'Any' ? ip : 'Any';
    if (!port || port === 'Any' || Number(port) === 0) {
      return safeIP;
    }
    return `${safeIP}:${port}`;
  }, []);

  const refreshWatchlist = useCallback(async () => {
    try {
      setWatchLoading(true);
      const shield = getShieldApi();
      const res = await shield?.getAddressWatch();
      if (res?.success) {
        const payload = res.data as unknown;
        const payloadObj = payload as Record<string, unknown> | undefined;
        const records = Array.isArray(payload)
          ? payload
          : Array.isArray(payloadObj?.tracked)
          ? (payloadObj.tracked as unknown[])
          : [];
        setWatchlist(records);
      }
    } catch (err) {
      console.error('Failed to load watchlist:', err);
    } finally {
      setWatchLoading(false);
    }
  }, []);

  useEffect(() => {
    if (typeof targetPort === 'number') {
      setBlockPort(String(targetPort));
    }
  }, [targetPort]);

  useEffect(() => {
    if (targetIP) {
      setBlockIP(targetIP);
      setUseCIDR(false);
    }
  }, [targetIP]);

  useEffect(() => {
    if (typeof targetPid === 'number' && targetPid > 0) {
      setBlockPid(String(targetPid));
    }
  }, [targetPid]);

  const loadFirewallInventory = useCallback(async () => {
    try {
      setLoadingRules(true);
      const shield = getShieldApi();
      const res = await shield?.getFirewallInventory();
      if (res?.success) {
        setFirewallRules((res.rules || []) as SentinelFirewallRule[]);
        setBlockedIps((res.blockedIps || []) as ShieldBlockedIpRecord[]);
        setInventoryMeta(res.meta || null);
      } else if (res?.rules) {
        setFirewallRules(res.rules as SentinelFirewallRule[]);
      }
    } catch (err) {
      console.error('Failed to load firewall inventory:', err);
    } finally {
      setLoadingRules(false);
    }
  }, []);

  const refreshUndoRedo = useCallback(async () => {
    try {
      const shield = getShieldApi();
      const state = await shield?.getUndoRedoState();
      if (state) setUndoRedoState(state);
    } catch (err) {
      console.error('Failed to refresh undo/redo state:', err);
    }
  }, []);

  useEffect(() => {
    loadFirewallInventory();
    refreshUndoRedo();
    refreshWatchlist();

    // Independent background polling for firewall rules (every 10s)
    const pollInterval = setInterval(() => {
      loadFirewallInventory();
      refreshUndoRedo();
    }, 10000);

    return () => clearInterval(pollInterval);
  }, [loadFirewallInventory, refreshUndoRedo]);

  useEffect(() => {
    const handleWatchlistEvent = () => {
      refreshWatchlist();
      loadFirewallInventory();
    };
    window.addEventListener(WATCHLIST_EVENT, handleWatchlistEvent as EventListener);
    return () => {
      window.removeEventListener(WATCHLIST_EVENT, handleWatchlistEvent as EventListener);
    };
  }, [loadFirewallInventory, refreshWatchlist]);

  const handleBlockPort = useCallback(async () => {
    const port = Number(blockPort);
    if (!Number.isFinite(port) || port < 0 || port > 65535) {
      notify.error('Enter valid port (0-65535)');
      return;
    }
    if (!isAdmin) {
      notify.error('Requires admin privileges');
      return;
    }
    if (!(await confirmAction({ title: 'Block Port', message: `Block TCP port ${port} (both directions)?`, variant: 'warning' }))) {
      return;
    }
    try {
      const payload: ShieldBlockPortRequest = {
        port,
        protocol: 'TCP',
        direction: 'both',
        options: { loopbackOnly: blockLoopbackOnly },
      };
      const shield = getShieldApi();
      const res = await shield?.blockPort(payload);
      if (res.success) {
        // Log manual block to security events store for ThreatTimeline
        try {
          const logPayload: ShieldManualBlockLogRequest = {
            ip: blockLoopbackOnly ? '127.0.0.1' : '0.0.0.0',
            port,
            pid: targetPid,
            processName: targetProcess,
            reason: `Manual port block (${port}/TCP) from FirewallRules UI`,
          };
          await shield?.logManualBlock(logPayload);
        } catch (logErr) {
          console.warn('[FirewallRules] Failed to log manual block:', logErr);
        }
        setBlockPort('');
        setBlockLoopbackOnly(false);
        await loadFirewallInventory();
        await refreshUndoRedo();
        onClearTarget?.();
      } else {
        notify.error(res.message || 'Failed to block port');
      }
    } catch (err) {
      notify.error(`Error: ${err}`);
    }
  }, [blockPort, isAdmin, loadFirewallInventory, refreshUndoRedo, onClearTarget, blockLoopbackOnly, targetPid, targetProcess, confirmAction]);

  const handleBlockSubnet = useCallback(async () => {
    const input = blockIP.trim();
    if (!input) {
      notify.error('Enter IP address or CIDR');
      return;
    }
    if (!isAdmin) {
      notify.error('Requires admin privileges');
      return;
    }
    const confirmationLabel = useCIDR || input.includes('/') ? input : `${input}/${subnetMask}`;
    if (!(await confirmAction({ title: 'Block Subnet', message: `Block remote network ${confirmationLabel} (both directions)?`, variant: 'warning' }))) {
      return;
    }
    try {
      const payload: ShieldBlockSubnetRequest = {
        input,
        subnetMask,
        direction: 'both',
      };
      const shield = getShieldApi();
      const res = await shield?.blockIPSubnet(input, subnetMask);
      if (res.success) {
        notify.success(res.message || 'Subnet blocked successfully');
        // Log manual block to security events store for ThreatTimeline
        try {
          const logPayload: ShieldManualBlockLogRequest = {
            ip: input,
            subnet: useCIDR || input.includes('/') ? input : `${input}/${subnetMask}`,
            pid: targetPid,
            processName: targetProcess,
            reason: 'Manual block from FirewallRules UI',
          };
          await shield?.logManualBlock(logPayload);
        } catch (logErr) {
          console.warn('[FirewallRules] Failed to log manual block:', logErr);
        }
        setBlockIP('');
        await loadFirewallInventory();
        await refreshUndoRedo();
        onClearTarget?.();
      } else {
        notify.error(res.message || 'Failed to block subnet');
      }
    } catch (err) {
      notify.error(`Error: ${err}`);
    }
  }, [blockIP, isAdmin, subnetMask, loadFirewallInventory, refreshUndoRedo, onClearTarget, targetPid, targetProcess, useCIDR, confirmAction]);

  const handleMonitorIP = useCallback(
    async (ip?: string) => {
      const target = (ip || blockIP || targetIP || '').trim();
      if (!target) {
        notify.error('Enter an IP first');
        return;
      }
      try {
        const shield = getShieldApi();
        const res = await shield?.registerAddressWatch(target);
        if (res?.success) {
          notify.success(`Monitoring ${target}. Sentinel will warn on repeated attempts.`);
          refreshWatchlist();
        } else {
          notify.error(res?.error || 'Failed to register watch');
        }
      } catch (err) {
        notify.error(`Error: ${err}`);
      }
    },
    [blockIP, targetIP, refreshWatchlist]
  );

  const handleBlockPid = useCallback(async () => {
    const pid = Number(blockPid);
    if (!Number.isFinite(pid) || pid < 0) {
      notify.error('Enter a valid PID (0 or positive integer)');
      return;
    }
    if (!isAdmin) {
      notify.error('Requires admin privileges');
      return;
    }
    if (!(await confirmAction({ title: 'Block Process', message: `Block PID ${pid} (${pidDirection.toUpperCase()})?`, variant: 'warning' }))) {
      return;
    }
    try {
      const payload: ShieldBlockPidRequest = {
        pid,
        direction: pidDirection,
      };
      const shield = getShieldApi();
      const res = await shield?.blockPid(payload);
      if (res.success) {
        await loadFirewallInventory();
        await refreshUndoRedo();
        setBlockPid('');
        onClearTarget?.();
      } else {
        notify.error(res.message || res.error || 'Failed to block PID');
      }
    } catch (err) {
      notify.error(`Error: ${err}`);
    }
  }, [blockPid, pidDirection, isAdmin, loadFirewallInventory, refreshUndoRedo, onClearTarget, confirmAction]);

  const handleUndo = useCallback(async () => {
    if (!(await confirmAction({ title: 'Undo', message: 'Undo last firewall action?', variant: 'info' }))) return;
    try {
      const shield = getShieldApi();
      const res = await shield?.undoFirewall();
      if (res.success) {
        await loadFirewallInventory();
        await refreshUndoRedo();
      } else {
        notify.error(res.message || 'Nothing to undo');
      }
    } catch (err) {
      console.error('Undo failed:', err);
    }
  }, [loadFirewallInventory, refreshUndoRedo, confirmAction]);

  const handleRedo = useCallback(async () => {
    if (!(await confirmAction({ title: 'Redo', message: 'Redo previously undone firewall action?', variant: 'info' }))) return;
    try {
      const shield = getShieldApi();
      const res = await shield?.redoFirewall();
      if (res.success) {
        await loadFirewallInventory();
        await refreshUndoRedo();
      } else {
        notify.error(res.message || 'Nothing to redo');
      }
    } catch (err) {
      console.error('Redo failed:', err);
    }
  }, [loadFirewallInventory, refreshUndoRedo]);

  const handleDeleteRule = useCallback(async (ruleName: string) => {
    if (!ruleName) return;
    if (!isAdmin) return;
    if (!(await confirmAction({ title: 'Delete Rule', message: `Delete firewall rule: ${ruleName}?`, variant: 'danger' }))) return;
    try {
      const shield = getShieldApi();
      const res = await shield?.deleteFirewallRule(ruleName);
      if (res.success) {
        await loadFirewallInventory();
        await refreshUndoRedo();
      }
    } catch (err) {
      console.error('Failed to delete rule:', err);
    }
  }, [isAdmin, loadFirewallInventory, refreshUndoRedo]);

  const pendingSelection = useMemo(() => {
    if (!targetIP && typeof targetPid !== 'number') return null;
    return {
      address: targetIP ? `${targetIP}${targetPort ? `:${targetPort}` : ''}` : null,
      pid: targetPid,
      process: targetProcess,
    };
  }, [targetIP, targetPort, targetPid, targetProcess]);

  const estimatedRange = useMemo(() => {
    if (!blockIP || useCIDR || subnetMask === 32) return null;
    const size = Math.pow(2, 32 - subnetMask);
    if (!Number.isFinite(size)) return null;
    return size;
  }, [blockIP, useCIDR, subnetMask]);

  const pendingQueue = useMemo(() => pendingRules.sort((a, b) => a.expiresAt - b.expiresAt), [pendingRules]);
  const pendingErrorMessage = useMemo(() => {
    if (!pendingError) return null;
    if (typeof pendingError === 'string') {
      return pendingError;
    }
    if (pendingError instanceof Error) {
      return pendingError.message || pendingError.toString();
    }
    try {
      return JSON.stringify(pendingError);
    } catch {
      return String(pendingError);
    }
  }, [pendingError]);

  const clearScheduledTlsRetry = useCallback(() => {
    if (tlsRetryRef.current) {
      clearTimeout(tlsRetryRef.current);
      tlsRetryRef.current = null;
    }
  }, []);

  useEffect(() => {
    return () => clearScheduledTlsRetry();
  }, [clearScheduledTlsRetry]);

  const runTlsInspection = useCallback(
    async (host: string, attempt = 1) => {
      const shield = getShieldApi();
      if (!shield?.inspectTls) {
        setTlsState('error');
        setTlsError('TLS inspection API unavailable');
        setTlsStatusMessage('');
        return;
      }
      try {
        const res = await shield.inspectTls(host);
        if (res?.success) {
          const data = res.data as TLSInspectionSummary;
          setTlsResult(data);
          setTlsError('');
          setTlsAttempts(attempt);
          const status = (data.status || 'UNKNOWN').toUpperCase();
          if (TLS_READY_STATUSES.has(status)) {
            clearScheduledTlsRetry();
            setTlsState('ready');
            setTlsStatusMessage('Received latest SSL Labs assessment.');
            setTlsCooldownUntil(Date.now() + TLS_COOLDOWN_MS);
            return;
          }

          if (TLS_POLLABLE_STATUSES.has(status) && attempt < TLS_MAX_ATTEMPTS) {
            const delay = Math.min(15000, TLS_RETRY_BASE_DELAY_MS * attempt);
            setTlsState('loading');
            setTlsStatusMessage(`SSL Labs status: ${status}. Retrying in ${Math.round(delay / 1000)}s (attempt ${attempt}/${TLS_MAX_ATTEMPTS}).`);
            clearScheduledTlsRetry();
            tlsRetryRef.current = setTimeout(() => runTlsInspection(host, attempt + 1), delay);
            return;
          }

          if (TLS_POLLABLE_STATUSES.has(status)) {
            clearScheduledTlsRetry();
            setTlsState('error');
            setTlsError(`SSL Labs is still processing (${status}). Please retry later.`);
            setTlsStatusMessage('');
            return;
          }

          clearScheduledTlsRetry();
          setTlsState('error');
          setTlsError(`TLS inspection returned status ${status}.`);
          setTlsStatusMessage('');
          return;
        }

        clearScheduledTlsRetry();
        setTlsState('error');
        setTlsError(coerceErrorMessage(res?.error));
        setTlsStatusMessage('');
      } catch (err) {
        clearScheduledTlsRetry();
        setTlsState('error');
        setTlsError(coerceErrorMessage(err));
        setTlsStatusMessage('');
      }
    },
    [clearScheduledTlsRetry]
  );

  const cancelTlsInspection = useCallback(() => {
    clearScheduledTlsRetry();
    setTlsState('idle');
    setTlsStatusMessage('');
    setTlsAttempts(0);
    setTlsError('');
  }, [clearScheduledTlsRetry]);

  const cooldownMsRemaining = Math.max(0, tlsCooldownUntil - Date.now());
  const tlsCoolingDown = cooldownMsRemaining > 0;
  const tlsCooldownSeconds = tlsCoolingDown ? Math.ceil(cooldownMsRemaining / 1000) : 0;
  const effectiveTlsHost = tlsHost || blockIP || targetIP || '';
  const canCancelTls = tlsState === 'loading' && !tlsCoolingDown;
  const canRetryTls = tlsState === 'error' && Boolean(tlsLastHost);

  const handleInspectTLS = useCallback(async () => {
    const host = (tlsHost || blockIP || targetIP || '').trim();
    if (!host) {
      notify.error('Enter a hostname/IP to inspect');
      return;
    }
    if (tlsCoolingDown) {
      notify.error(`TLS inspection cooling down. Please wait ${tlsCooldownSeconds}s before retrying.`);
      return;
    }
    clearScheduledTlsRetry();
    setTlsHost(host);
    setTlsState('loading');
    setTlsError('');
    setTlsResult(null);
    setTlsAttempts(0);
    setTlsStatusMessage('Contacting SSL Labs…');
    setTlsLastHost(host);
    runTlsInspection(host, 1);
  }, [blockIP, targetIP, tlsHost, tlsCoolingDown, tlsCooldownSeconds, clearScheduledTlsRetry, runTlsInspection]);

  const renderPendingDrawer = () => {
    if (!pendingQueue.length && !pendingLoading) return null;
    return (
      <div className="mt-4 border border-purple-500/40 bg-purple-500/5 rounded-xl p-4 text-xs text-purple-100">
        <div className="flex items-center justify-between mb-2">
          <div>
            <p className="text-sm font-semibold text-white">Quarantine Queue</p>
            <p className="text-[11px] text-gray-400">Pending auto-blocks awaiting confirmation</p>
          </div>
          {pendingLoading && <span className="text-gray-400">Refreshing…</span>}
        </div>
        {pendingErrorMessage && <p className="text-red-400 text-[11px] mb-2">{pendingErrorMessage}</p>}
        <div className="space-y-2 max-h-64 overflow-y-auto pr-2">
          {pendingQueue.map((rule) => {
            const secondsLeft = Math.max(0, Math.floor((rule.expiresAt - Date.now()) / 1000));
            return (
              <div
                key={rule.id}
                className="rounded-lg border border-purple-500/30 bg-purple-500/5 p-3 flex flex-col gap-2"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-white font-semibold text-sm">{rule.processName} (PID {rule.pid})</p>
                    <p className="font-mono text-[11px] text-gray-300">{rule.remoteIP ?? 'Unknown IP'}</p>
                  </div>
                  <span className="text-[11px] text-cyan-300">{secondsLeft}s</span>
                </div>
                {rule.reasons?.length > 0 && (
                  <p className="text-[11px] text-gray-400">
                    Reasons: <span className="text-gray-200">{rule.reasons.join(', ')}</span>
                  </p>
                )}
                <div className="flex gap-2">
                  <button
                    className="flex-1 px-3 py-1.5 rounded bg-purple-600/70 text-white text-[11px] font-semibold hover:bg-purple-600"
                    onClick={() => commitPendingRule(rule.id)}
                  >
                    Apply Block
                  </button>
                  <button
                    className="px-3 py-1.5 rounded border border-gray-700 text-gray-300 text-[11px] hover:bg-gray-800"
                    onClick={() => commitPendingRule(rule.id)}
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            );
          })}
          {pendingLoading && <p className="text-gray-400 text-center">Loading pending rules…</p>}
        </div>
      </div>
    );
  };

  return (
    <div className="flex flex-col h-full bg-[var(--sentinel-bg)] border border-gray-900/40 rounded-2xl shadow-[0_30px_80px_rgba(3,8,41,0.65)] text-white">
      <div className="p-5 border-b border-gray-900/60 bg-[var(--sentinel-panel)]">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <p className="text-[11px] uppercase tracking-[0.4em] text-gray-500">Sentinel Firewall</p>
            <h2 className="text-2xl font-black text-white">Firewall Orchestrator</h2>
            <p className="text-xs text-gray-400 max-w-3xl">
              Curate every block rule with neon-level clarity. Use the "?" badges to see what Sentinel logs, where your data lives,
              and what each automation switch actually does before you deploy a change.
            </p>
          </div>
          <ActionBar
            onUndo={handleUndo}
            onRedo={handleRedo}
            canUndo={undoRedoState.canUndo}
            canRedo={undoRedoState.canRedo}
          >
            <button
              className="px-3 py-2 rounded border border-cyan-500/40 text-cyan-200 text-xs font-semibold hover:bg-cyan-500/10"
              onClick={loadFirewallInventory}
            >
              🔄 Refresh
            </button>
          </ActionBar>
        </div>

        <div className="mt-3 flex flex-wrap gap-3 text-[11px] text-gray-400">
          <InfoHint
            label="Undo / Redo"
            title="Immutable audit trail"
            description="Sentinel stores every firewall operation locally so you can reverse mistakes instantly without touching Windows defaults."
            details={[{ label: 'Undo available', value: undoRedoState.canUndo ? 'Yes' : 'No' }, { label: 'Redo available', value: undoRedoState.canRedo ? 'Yes' : 'No' }]}
          />
          <InfoHint
            label="Quarantine"
            title="Pending rules"
            description="Auto-generated policies land here first. Review the evidence, then promote or dismiss with full transparency."
          />
          <InfoHint
            label="Data store"
            title="Local-only logging"
            description="Firewall history, watchlists, and TLS results stay inside Sentinel's telemetry folder on this PC—nothing syncs to the cloud."
          />
        </div>

        {pendingSelection && (
          <div className="mt-3 flex flex-col gap-2 rounded-lg bg-cyan-500/10 border border-cyan-500/40 px-3 py-2 text-xs text-cyan-200">
            <div className="flex items-center justify-between">
              <span>Selected from Network Monitor</span>
              <button
                className="px-2 py-1 rounded border border-gray-600 text-gray-400 hover:bg-gray-800"
                onClick={onClearTarget}
              >
                Clear
              </button>
            </div>
            {pendingSelection.address && (
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-gray-300">Remote</span>
                <strong className="font-mono text-cyan-100">{pendingSelection.address}</strong>
              </div>
            )}
            {typeof pendingSelection.pid === 'number' && (
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-gray-300">Process</span>
                <span className="font-mono text-cyan-100">
                  {pendingSelection.process || 'Unknown'} • PID {pendingSelection.pid}
                </span>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              {targetPort && (
                <button
                  className="px-2 py-1 rounded border border-cyan-400 text-cyan-200 hover:bg-cyan-500/10"
                  onClick={() => handleBlockPort()}
                >
                  Block Port
                </button>
              )}
              {pendingSelection.address && (
                <button
                  className="px-2 py-1 rounded border border-cyan-400 text-cyan-200 hover:bg-cyan-500/10"
                  onClick={() => handleBlockSubnet()}
                >
                  Block IP
                </button>
              )}
              {typeof pendingSelection.pid === 'number' && (
                <button
                  className="px-2 py-1 rounded border border-cyan-400 text-cyan-200 hover:bg-cyan-500/10"
                  onClick={() => handleBlockPid()}
                >
                  Block PID
                </button>
              )}
            </div>
          </div>
        )}

        {!isAdmin && (
          <div className="mt-3 p-3 bg-threat-warning/10 border border-threat-warning/30 rounded text-xs text-threat-warning">
            ⚠️ Admin privileges required for firewall operations
          </div>
        )}
      </div>

      <div className="p-5 space-y-4 overflow-y-auto flex-1">
        {renderPendingDrawer()}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
          {[
            { label: 'Inbound', value: ruleStats.inbound, accent: 'text-cyan-300' },
            { label: 'Outbound', value: ruleStats.outbound, accent: 'text-purple-300' },
            { label: 'Disabled', value: ruleStats.disabled, accent: 'text-orange-300' },
            { label: 'Blocked IPs', value: blockedIps.length, accent: 'text-red-300' },
          ].map((stat) => (
            <div key={stat.label} className="sentinel-panel p-3">
              <p className="text-gray-500 uppercase tracking-wide text-[10px]">{stat.label}</p>
              <p className={`text-lg font-semibold ${stat.accent}`}>{stat.value}</p>
            </div>
          ))}
        </div>

        <div className="sentinel-panel p-3 text-xs text-cyan-200 flex items-center gap-2">
          <strong className="font-semibold">Why so much port 443?</strong>
          <span>{HTTPS_TRAFFIC_NOTE}</span>
          <InfoHint
            title="TLS-heavy traffic"
            description="Most modern malware hides inside HTTPS. Sentinel keeps surfacing 443 because the telemetry store prioritizes encrypted flows."
          />
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <section className="sentinel-panel p-4">
            <div className="flex items-center justify-between mb-3">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold text-white">🔌 Block Port</h3>
                  <InfoHint
                    title="Port rule"
                    description="Creates inbound+outbound Windows Firewall rules scoped to the TCP port you enter. Sentinel tags the rule for you so it can be undone later."
                    details={[{ label: 'Scope', value: 'System-wide' }]}
                  />
                </div>
                <p className="text-[11px] text-gray-500">Creates Sentinel TCP rules (both directions)</p>
              </div>
              <span className="text-[11px] text-gray-500 font-mono">{blockPort || '—'}</span>
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                value={blockPort}
                onChange={(e) => setBlockPort(e.target.value)}
                placeholder="Port (0-65535)"
                className="flex-1 px-3 py-2 bg-black/40 border border-gray-800 rounded text-sm text-white"
                disabled={!isAdmin}
              />
              <label className="flex items-center gap-2 text-[11px] text-gray-500">
                <input
                  type="checkbox"
                  className="rounded text-cyan-400"
                  checked={blockLoopbackOnly}
                  onChange={(e) => setBlockLoopbackOnly(e.target.checked)}
                  disabled={!isAdmin}
                />
                Restrict to localhost
              </label>
              <button
                onClick={handleBlockPort}
                disabled={!isAdmin}
                className="px-4 py-2 bg-accent-cyan-DEFAULT text-black rounded font-semibold text-sm hover:bg-accent-cyan-DEFAULT/90 disabled:opacity-40"
              >
                Apply
              </button>
            </div>
            {selectedPortIntel ? (
              <div className="mt-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 text-xs text-gray-300 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-white font-semibold">{selectedPortIntel.label}</span>
                  <span className="font-mono text-cyan-300">Port {selectedPortIntel.port}</span>
                </div>
                <p><strong className="text-cyan-200">Historical:</strong> {selectedPortIntel.historicalUse}</p>
                <p><strong className="text-cyan-200">Modern:</strong> {selectedPortIntel.modernUse}</p>
                <div>
                  <strong className="text-cyan-200">Threats:</strong>
                  <ul className="list-disc list-inside text-[11px] text-red-200">
                    {selectedPortIntel.threats.map((threat) => (
                      <li key={threat}>{threat}</li>
                    ))}
                  </ul>
                </div>
                <p><strong className="text-cyan-200">Hardening:</strong> {selectedPortIntel.hardening}</p>
              </div>
            ) : (
              blockPort && (
                <p className="mt-3 text-[11px] text-gray-500">
                  No curated intel for port {blockPort}. The firewall rule will still be created.
                </p>
              )
            )}
          </section>
          <KnowledgePanel topic="portBlocking" />

          <section className="bg-[#10101a] border border-gray-900 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white">🔎 TLS Inspector</h3>
                <p className="text-[11px] text-gray-500">Deep SSL Labs checks</p>
              </div>
              <button
                className="text-[11px] text-cyan-300 underline"
                onClick={() => {
                  setTlsHost('');
                  setTlsResult(null);
                  setTlsError('');
                  setTlsStatusMessage('');
                }}
              >
                Clear
              </button>
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={effectiveTlsHost}
                onChange={(e) => setTlsHost(e.target.value)}
                placeholder="Hostname or IP"
                className="flex-1 px-3 py-2 bg-black/40 border border-gray-800 rounded text-sm text-white"
              />
              <div className="flex gap-2">
                <button
                  onClick={handleInspectTLS}
                  disabled={!effectiveTlsHost.trim() || tlsState === 'loading'}
                  className="px-4 py-2 bg-indigo-500 text-black rounded font-semibold text-sm hover:bg-indigo-400 disabled:opacity-40"
                >
                  {tlsState === 'loading' ? 'Inspecting…' : 'Inspect'}
                </button>
                {canCancelTls && (
                  <button
                    onClick={cancelTlsInspection}
                    className="px-3 py-2 bg-gray-800 text-gray-200 rounded text-xs font-semibold hover:bg-gray-700"
                  >
                    Cancel
                  </button>
                )}
                {canRetryTls && (
                  <button
                    onClick={() => runTlsInspection(tlsLastHost, 1)}
                    className="px-3 py-2 bg-gray-800 text-gray-200 rounded text-xs font-semibold hover:bg-gray-700"
                  >
                    Retry Last
                  </button>
                )}
              </div>
            </div>
            {tlsStatusMessage && <p className="text-[11px] text-cyan-300">{tlsStatusMessage}</p>}
            {tlsCoolingDown && (
              <p className="text-[11px] text-yellow-300">
                Cooling down to respect SSL Labs limits. Retry in {tlsCooldownSeconds}s.
              </p>
            )}
            {tlsError && <p className="text-[11px] text-orange-300">{tlsError}</p>}
            {tlsResult && (
              <div className="rounded-lg border border-indigo-500/40 bg-indigo-500/5 p-3 text-[11px] text-gray-200 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-white font-semibold">{tlsResult.host}</span>
                  <span className="font-mono text-green-300">Grade: {tlsResult.grade || '—'}</span>
                </div>
                <p>Status: {tlsResult.status}</p>
                <p>Attempts: {tlsAttempts || 1}</p>
                {tlsResult.protocols?.length ? (
                  <p>Protocols: {tlsResult.protocols.join(', ')}</p>
                ) : (
                  <p>No protocol data returned</p>
                )}
                <div>
                  <strong className="text-red-300">Issues:</strong>
                  <ul className="list-disc list-inside text-red-200">
                    {tlsResult.issues.length ? tlsResult.issues.map((issue) => <li key={issue}>{issue}</li>) : <li>No critical issues reported</li>}
                  </ul>
                </div>
                <p className="text-[10px] text-gray-400">Fetched {new Date(tlsResult.fetchedAt).toLocaleString()}</p>
              </div>
            )}
            <KnowledgePanel topic="tlsInspection" />
          </section>

          <section className="sentinel-panel p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-white">🧱 Block Process (PID)</h3>
                  <p className="text-[11px] text-gray-500">Blocks executable tied to a PID using program rules</p>
                </div>
                <InfoHint
                  title="PID blocking"
                  description="Creates a Windows Firewall rule bound to the executable backing the PID. Use this when a single process keeps beaconing out."
                />
              </div>
              <select
                value={pidDirection}
                onChange={(e) => setPidDirection(e.target.value as 'in' | 'out' | 'both')}
                className="px-3 py-1 text-xs bg-black/40 border border-gray-800 rounded text-white"
                disabled={!isAdmin}
              >
                <option value="both">Both Directions</option>
                <option value="in">Inbound Only</option>
                <option value="out">Outbound Only</option>
              </select>
            </div>
            <div className="flex gap-2">
              <input
                type="number"
                value={blockPid}
                onChange={(e) => setBlockPid(e.target.value)}
                placeholder="PID (e.g., 1234)"
                className="flex-1 px-3 py-2 bg-black/40 border border-gray-800 rounded text-sm text-white"
                disabled={!isAdmin}
              />
              <button
                onClick={handleBlockPid}
                disabled={!isAdmin}
                className="px-4 py-2 bg-orange-500 text-black rounded font-semibold text-sm hover:bg-orange-400 disabled:opacity-40"
              >
                Apply
              </button>
            </div>
            <p className="text-[11px] text-gray-500">
              Sentinel resolves the executable path for this PID before creating firewall rules.
            </p>
            <KnowledgePanel topic="pidBlocking" />
          </section>
        </div>

        {/* Subnet Blocking */}
        <section className="sentinel-panel p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-white">🌍 Block IP / Subnet</h3>
              <InfoHint
                title="Network blocking"
                description="Sentinel builds both inbound and outbound rules. Toggle CIDR to enter a range manually or pick a preset mask for quick conversions."
              />
            </div>
            <label className="flex items-center gap-2 text-[11px] text-gray-500">
              <input
                type="checkbox"
                checked={useCIDR}
                onChange={(e) => setUseCIDR(e.target.checked)}
                className="rounded text-cyan-400"
                disabled={!isAdmin}
              />
              CIDR Input
            </label>
          </div>
          <div className="flex gap-2">
            <input
              type="text"
              value={blockIP}
              onChange={(e) => setBlockIP(e.target.value)}
              placeholder={useCIDR ? 'CIDR (e.g., 10.0.0.0/8)' : 'IP Address (e.g., 192.168.1.1)'}
              className="flex-1 px-3 py-2 bg-black/40 border border-gray-800 rounded text-sm text-white font-mono"
              disabled={!isAdmin}
            />
            {!useCIDR && (
              <select
                value={subnetMask}
                onChange={(e) => setSubnetMask(Number(e.target.value) as 8 | 16 | 20 | 22 | 24 | 26 | 30 | 32)}
                className="px-3 py-2 bg-black/40 border border-gray-800 rounded text-sm text-white"
                disabled={!isAdmin}
              >
                {subnetOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            )}
            <button
              onClick={handleBlockSubnet}
              disabled={!isAdmin}
              className="px-4 py-2 bg-threat-warning text-black rounded font-semibold text-sm hover:bg-threat-warning/90 disabled:opacity-40"
            >
              Apply
            </button>
          </div>
          <div className="text-[11px] text-gray-500">
            {useCIDR ? 'CIDR will be applied exactly as provided.' : 'Select a mask to convert IP into subnet blocking.'}
            {estimatedRange && (
              <p className="text-cyan-300 mt-1">Will block approximately {estimatedRange.toLocaleString()} IPs.</p>
            )}
          </div>
          <KnowledgePanel topic="subnetBlocking" />
          <div className="flex gap-2">
            <button
              onClick={() => handleMonitorIP(blockIP)}
              className="px-4 py-2 bg-cyan-700 text-white rounded text-sm hover:bg-cyan-600"
            >
              Monitor IP
            </button>
            <span className="text-[11px] text-gray-500">Alerts trigger once an address attempts twice.</span>
          </div>
        </section>

        {/* Rule List */}
        <section className="sentinel-panel p-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between mb-3">
            <div>
              <div className="flex items-center gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-white">📋 Active Rules</h3>
                  <p className="text-[11px] text-gray-500">Review Sentinel-authored policies with live metadata</p>
                </div>
                <InfoHint
                  title="Rule inventory"
                  description="Aggregates Windows Firewall (PowerShell) results, Sentinel-tagged rules, and tracked names. Useful for answering “what exactly is blocked?”"
                  details={[{ label: 'Source', value: 'Get-NetFirewallRule' }, { label: 'Fallback', value: 'netsh advfirewall' }]}
                />
              </div>
              {inventoryMeta && (
                <p className="text-[11px] text-gray-600 mt-1">
                  {inventoryMeta.totalCollected ?? firewallRules.length} rules • {inventoryMeta.sentinelTagged ?? 0} Sentinel •
                  {inventoryMeta.tracked ?? 0} tracked • updated {inventoryMeta.generatedAt ? new Date(inventoryMeta.generatedAt).toLocaleTimeString() : 'now'}
                </p>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-2 text-[11px]">
              <span className="text-gray-500">Sort by:</span>
              {sortOptions.map((option) => (
                <button
                  key={option.value}
                  className={`px-3 py-1 rounded border text-xs transition ${
                    sortBy === option.value
                      ? 'border-cyan-500 text-cyan-300 bg-cyan-500/10'
                      : 'border-gray-800 text-gray-500 hover:border-gray-600'
                  }`}
                  onClick={() => setSortBy(option.value)}
                >
                  {option.label}
                </button>
              ))}
              {loadingRules && <span className="text-gray-500">Loading…</span>}
              <div className="flex items-center gap-2 ml-auto">
                <select
                  className="bg-black/50 border border-gray-800 text-gray-400 text-[10px] rounded px-2 py-1"
                  value={exportFormat}
                  onChange={(e) => setExportFormat(e.target.value as 'txt' | 'csv' | 'json')}
                >
                  <option value="txt">TXT</option>
                  <option value="csv">CSV</option>
                  <option value="json">JSON</option>
                </select>
                <button
                  className="px-3 py-1 rounded border border-gray-700 text-gray-400 text-[10px] hover:text-cyan-300 hover:border-cyan-500/40 disabled:opacity-40"
                  disabled={exporting || firewallRules.length === 0}
                  onClick={async () => {
                    setExporting(true);
                    try {
                      const shield = getShieldApi();
                      const res = await (shield as any)?.exportFirewallRules?.({ format: exportFormat });
                      if (res?.success) notify.success(`Exported ${res.ruleCount} rules`);
                      else if (res?.error !== 'Export cancelled') notify.error(res?.error || 'Export failed');
                    } catch (e: any) { notify.error(e?.message || 'Export failed'); }
                    setExporting(false);
                  }}
                >
                  {exporting ? '…' : '📥 Export'}
                </button>
              </div>
            </div>
          </div>

          {firewallRules.length > 0 && (
            <div className="grid grid-cols-3 gap-3 text-[11px] text-gray-400 mb-3">
              <div className="bg-black/30 rounded-lg border border-gray-900 p-3">
                <p className="text-gray-500 uppercase tracking-wide text-[10px]">Inbound</p>
                <p className="text-lg text-cyan-300 font-semibold">{ruleStats.inbound}</p>
              </div>
              <div className="bg-black/30 rounded-lg border border-gray-900 p-3">
                <p className="text-gray-500 uppercase tracking-wide text-[10px]">Outbound</p>
                <p className="text-lg text-purple-300 font-semibold">{ruleStats.outbound}</p>
              </div>
              <div className="bg-black/30 rounded-lg border border-gray-900 p-3">
                <p className="text-gray-500 uppercase tracking-wide text-[10px]">Disabled</p>
                <p className="text-lg text-orange-300 font-semibold">{ruleStats.disabled}</p>
              </div>
            </div>
          )}

          <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
            {sortedRules.length === 0 && !loadingRules ? (
              <div className="p-4 text-center text-gray-600 text-sm border border-dashed border-gray-800 rounded">
                No Sentinel firewall rules detected.
              </div>
            ) : (
              sortedRules.map((rule, idx) => {
                const isSelected = selectedRuleIdx === idx;
                return (
                  <div
                    key={`${rule.name}-${idx}`}
                    className={`rounded-xl border text-xs flex flex-col transition-all cursor-pointer ${
                      isSelected
                        ? 'border-cyan-500/40 bg-black/40 shadow-[0_0_12px_rgba(34,211,238,0.08)]'
                        : 'border-gray-900 bg-black/30 hover:border-gray-700'
                    }`}
                    onClick={() => setSelectedRuleIdx(isSelected ? null : idx)}
                  >
                    {/* Collapsed header */}
                    <div className="p-4 flex flex-col gap-3">
                      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2">
                        <div>
                          <p className="text-white font-semibold flex items-center gap-2">
                            {rule.name || 'Unnamed Rule'}
                            <span
                              className={`px-2 py-0.5 rounded-full text-[10px] border ${
                                rule.enabled ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10' : 'border-red-500/40 text-red-300 bg-red-500/10'
                              }`}
                            >
                              {rule.enabled ? 'Enabled' : 'Disabled'}
                            </span>
                            <span className={`px-2 py-0.5 rounded-full text-[10px] border ${
                              rule.action === 'Block' ? 'border-red-500/40 text-red-300 bg-red-500/10' : 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10'
                            }`}>
                              {rule.action || 'N/A'}
                            </span>
                          </p>
                          <p className="text-gray-500 text-[11px]">
                            {rule.direction || 'N/A'} • {rule.protocol || 'Any'} • {rule.profile || 'Any profile'}
                          </p>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] transition-transform ${isSelected ? 'rotate-180' : 'rotate-0'}`}>▾</span>
                          {rule.name?.includes('Sentinel') && (
                            <button
                              onClick={(e) => { e.stopPropagation(); handleDeleteRule(rule.name); }}
                              disabled={!isAdmin}
                              className="px-3 py-1 bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 disabled:opacity-40"
                            >
                              Delete
                            </button>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Expanded detail panel */}
                    {isSelected && (
                      <div className="px-4 pb-4 pt-0 border-t border-gray-800/60 space-y-3">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[11px] text-gray-300 pt-3">
                          <div className="space-y-1">
                            <p className="text-gray-500 uppercase tracking-wide text-[10px]">Program</p>
                            <p className="font-mono text-[11px] break-all">{rule.program || 'Any process'}</p>
                            {rule.description && <p className="text-gray-500 italic">{rule.description}</p>}
                          </div>
                          <div>
                            <p className="text-gray-500 uppercase tracking-wide text-[10px]">Local Endpoint</p>
                            <p className="font-mono text-[11px]">{formatEndpoint(rule.localAddress, rule.localPort)}</p>
                          </div>
                          <div>
                            <p className="text-gray-500 uppercase tracking-wide text-[10px]">Remote Endpoint</p>
                            <p className="font-mono text-[11px]">{formatEndpoint(rule.remoteAddress, rule.remotePort)}</p>
                          </div>
                        </div>
                        <div className="flex flex-wrap items-center gap-4 text-[11px] text-gray-500 pt-1">
                          <span>Created: {formatRuleTimestamp(rule.timeCreated)}</span>
                          <span>Direction: <span className="text-gray-300">{rule.direction || 'N/A'}</span></span>
                          <span>Protocol: <span className="text-gray-300">{rule.protocol || 'Any'}</span></span>
                          <span>Profile: <span className="text-gray-300">{rule.profile || 'Any'}</span></span>
                        </div>
                        <div className="flex items-center gap-2 pt-2">
                          {rule.remoteAddress && rule.remoteAddress !== 'Any' && (
                            <button
                              className="px-2 py-1 rounded border border-cyan-500/30 text-cyan-300 text-[10px] hover:bg-cyan-500/10"
                              onClick={(e) => {
                                e.stopPropagation();
                                navigator.clipboard?.writeText(rule.remoteAddress || '');
                                notify.success('Copied remote address');
                              }}
                            >
                              📋 Copy Remote
                            </button>
                          )}
                          {rule.name?.includes('Sentinel') && (
                            <button
                              className="px-2 py-1 rounded border border-gray-700 text-gray-400 text-[10px] hover:text-gray-200"
                              onClick={(e) => {
                                e.stopPropagation();
                                const shield = getShieldApi();
                                shield?.enableFirewallRule?.(rule.name, !rule.enabled);
                                notify.success(rule.enabled ? 'Rule disabled' : 'Rule enabled');
                              }}
                            >
                              {rule.enabled ? '⏸ Disable' : '▶ Enable'}
                            </button>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </section>
        <KnowledgePanel topic="firewallRules" />

        <section className="sentinel-panel p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white">⛔ Blocked IP Inventory</h3>
              <p className="text-[11px] text-gray-500">Hosts file & firewall-sourced IP bans</p>
            </div>
            <InfoHint
              title="Blocked IP sources"
              description="Sentinel merges Windows Firewall address filters with hosts-file entries created by Shield. Use this list to audit manual bans."
            />
            <span className="text-[11px] text-gray-500">{blockedIps.length} entries</span>
          </div>
          {inventoryMeta?.blockedIpsError && (
            <p className="text-[11px] text-orange-300">{inventoryMeta.blockedIpsError}</p>
          )}
          {blockedIps.length === 0 ? (
            <p className="text-[11px] text-gray-500">No blocked IP entries were discovered.</p>
          ) : (
            <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
              {blockedIps.map((entry) => (
                <div key={`${entry.ip}-${entry.timestamp || entry.reason}`} className="p-3 rounded-lg border border-gray-800 bg-black/30 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-white">{entry.ip}</span>
                    <span className="text-[10px] text-gray-500">{entry.timestamp ? new Date(entry.timestamp).toLocaleString() : 'Unknown'}</span>
                  </div>
                  <p className="text-[11px] text-gray-400">{entry.reason || 'Unspecified reason'}</p>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="bg-[#10101a] border border-gray-900 rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">👁 Watchlisted Addresses</h3>
            <button
              className="text-[11px] text-cyan-300 underline"
              onClick={refreshWatchlist}
            >
              Refresh
            </button>
          </div>
          {watchLoading ? (
            <p className="text-[11px] text-gray-500">Loading watchlist…</p>
          ) : watchlist.length === 0 ? (
            <p className="text-[11px] text-gray-500">No addresses are being monitored yet.</p>
          ) : (
            <div className="space-y-2">
              {watchlist.map((record) => (
                <div
                  key={record.ip}
                  className={`p-3 rounded-lg border ${record.hits >= 2 ? 'border-red-500/40 bg-red-500/5 text-red-200' : 'border-gray-800 bg-black/20 text-gray-300'}`}
                >
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-mono">{record.ip}</span>
                    <span className="text-[11px]">Hits: {record.hits}</span>
                  </div>
                  <p className="text-[11px]">Last seen: {record.lastSeen ? new Date(record.lastSeen).toLocaleString() : '—'}</p>
                  {record.hits >= 2 && <p className="text-[11px] font-semibold">⚠ Sentinel detected repeated attempts!</p>}
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
      <ConfirmDialog {...dialogState} onConfirm={onDialogConfirm} onCancel={onDialogCancel} />
    </div>
  );
};

export default FirewallRules;
