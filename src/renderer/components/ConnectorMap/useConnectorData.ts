/**
 * Sentinel Unified — useConnectorData
 * Hook that manages connector node/edge state, status polling,
 * and filter/selection logic for the ConnectorMap.
 */

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import type {
  ConnectorNode,
  ConnectorEdge,
  ConnectorMapFilters,
  ConnectorMapState,
  ClusterType,
  NodeStatus,
  NodeLogEntry,
} from '../../types/connectorMap';
import { ALL_NODES, ALL_EDGES } from './connectorMapData';
import { POLL_INTERVAL_MS } from './connectorMapTheme';

// ---------------------------------------------------------------------------
// Electron API accessor (typed, safe)
// ---------------------------------------------------------------------------

function getElectronApi(): typeof window.electronAPI | null {
  try {
    if (typeof window !== 'undefined' && window.electronAPI) {
      return window.electronAPI;
    }
  } catch {
    // Not available
  }
  return null;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export interface UseConnectorDataResult {
  state: ConnectorMapState;
  filteredNodes: ConnectorNode[];
  filteredEdges: ConnectorEdge[];
  selectNode: (id: string | null) => void;
  hoverNode: (id: string | null) => void;
  toggleCluster: (cluster: ClusterType) => void;
  setZoom: (zoom: number) => void;
  resetFilters: () => void;
  getNodeLogs: (nodeId: string) => NodeLogEntry[];
  getNodeResponse: (nodeId: string) => any;
  getNodeEdges: (nodeId: string) => ConnectorEdge[];
  executeNode: (nodeId: string, payload?: Record<string, unknown>) => void;
  disableNode: (nodeId: string) => void;
}

const DEFAULT_FILTERS: ConnectorMapFilters = {
  clusters: ['firewall', 'intel', 'automation', 'network', 'dns', 'system', 'vault'],
  status: ['online', 'degraded', 'error', 'offline'],
  source: ['sentinel', 'argus'],
};

export function useConnectorData(): UseConnectorDataResult {
  const [nodes, setNodes] = useState<ConnectorNode[]>(() => [...ALL_NODES]);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [filters, setFilters] = useState<ConnectorMapFilters>({ ...DEFAULT_FILTERS });
  const [zoom, setZoomState] = useState(1);
  const [nodeLogs, setNodeLogs] = useState<Record<string, NodeLogEntry[]>>({});
  const [nodeResponses, setNodeResponses] = useState<Record<string, any>>({});
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // -----------------------------------------------------------------------
  // Status polling
  // -----------------------------------------------------------------------

  const pollStatuses = useCallback(async () => {
    const api = getElectronApi();
    if (!api) return;

    const updatedNodes = [...nodes];
    let changed = false;

    // Check ARGUS health once (covers all ARGUS nodes)
    let argusOnline = false;
    try {
      const healthResult = await api.argus.getHealth();
      if (healthResult.success && healthResult.data?.status === 'running') {
        argusOnline = true;
      }
    } catch {
      argusOnline = false;
    }

    for (let i = 0; i < updatedNodes.length; i++) {
      const node = updatedNodes[i];

      if (node.ring === 0) continue; // Core is always online

      if (node.source === 'argus') {
        const newStatus: NodeStatus = argusOnline ? 'online' : 'offline';
        if (node.status !== newStatus) {
          updatedNodes[i] = { ...node, status: newStatus };
          changed = true;
        }
        continue;
      }

      // For Sentinel nodes, we do a lightweight check on a subset each cycle
      // to avoid hammering all 58 IPC channels every 5 seconds.
      // Only check nodes that are currently visible (filtered in).
      if (!filters.clusters.includes(node.cluster)) continue;

      // Spot-check: only poll ~10 nodes per cycle (round-robin)
      const cycleSlot = Math.floor(Date.now() / POLL_INTERVAL_MS) % 10;
      const nodeSlot = i % 10;
      if (cycleSlot !== nodeSlot) continue;

      try {
        const start = performance.now();
        // Use a lightweight IPC call to test responsiveness
        if (node.ipcChannel === 'sentinel-get-health-report') {
          await api.shield.getSecurityOverview();
        } else if (node.ipcChannel === 'check-admin-rights') {
          // Skip — this is a sync check, not worth polling
          continue;
        } else {
          // Generic: we just mark Sentinel nodes as online since the IPC bridge is alive
          // A more granular check would call each specific handler
          continue;
        }
        const latency = performance.now() - start;
        const newStatus: NodeStatus = latency < 3000 ? 'online' : 'degraded';
        if (node.status !== newStatus || Math.abs(node.lastResponseMs - latency) > 50) {
          updatedNodes[i] = { ...node, status: newStatus, lastResponseMs: latency };
          changed = true;
        }
      } catch {
        if (node.status !== 'error') {
          updatedNodes[i] = { ...node, status: 'error', errorCount24h: node.errorCount24h + 1 };
          changed = true;
        }
      }
    }

    if (changed) {
      setNodes(updatedNodes);
    }
  }, [nodes, filters.clusters]);

  useEffect(() => {
    pollStatuses();
    pollTimerRef.current = setInterval(pollStatuses, POLL_INTERVAL_MS);
    return () => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
      }
    };
  }, [pollStatuses]);

  // -----------------------------------------------------------------------
  // Filtering
  // -----------------------------------------------------------------------

  const filteredNodes = useMemo(() => {
    return nodes.filter((n) => {
      if (n.ring === 0) return true; // Core always visible
      if (!filters.clusters.includes(n.cluster)) return false;
      if (!filters.status.includes(n.status)) return false;
      if (!filters.source.includes(n.source)) return false;
      return true;
    });
  }, [nodes, filters]);

  const filteredNodeIds = useMemo(() => {
    return new Set(filteredNodes.map((n) => n.id));
  }, [filteredNodes]);

  const filteredEdges = useMemo(() => {
    return ALL_EDGES.filter(
      (e) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target)
    );
  }, [filteredNodeIds]);

  // -----------------------------------------------------------------------
  // Actions
  // -----------------------------------------------------------------------

  const selectNode = useCallback((id: string | null) => {
    setSelectedNode(id);
  }, []);

  const hoverNode = useCallback((id: string | null) => {
    setHoveredNode(id);
  }, []);

  const toggleCluster = useCallback((cluster: ClusterType) => {
    setFilters((prev) => {
      const current = prev.clusters;
      const next = current.includes(cluster)
        ? current.filter((c) => c !== cluster)
        : [...current, cluster];
      return { ...prev, clusters: next.length > 0 ? next : [cluster] };
    });
  }, []);

  const setZoom = useCallback((z: number) => {
    setZoomState(Math.max(0.3, Math.min(3, z)));
  }, []);

  const resetFilters = useCallback(() => {
    setFilters({ ...DEFAULT_FILTERS });
    setZoomState(1);
    setSelectedNode(null);
  }, []);

  const getNodeLogs = useCallback(
    (nodeId: string): NodeLogEntry[] => {
      return nodeLogs[nodeId] ?? [];
    },
    [nodeLogs]
  );

  const addLog = useCallback((nodeId: string, message: string, level: NodeLogEntry['level'] = 'info') => {
    setNodeLogs((prev) => {
      const existing = prev[nodeId] ?? [];
      const entry: NodeLogEntry = { timestamp: Date.now(), message, level };
      const updated = [entry, ...existing].slice(0, 50);
      return { ...prev, [nodeId]: updated };
    });
  }, []);

  const executeNode = useCallback(
    async (nodeId: string, payload?: Record<string, unknown>) => {
      const node = nodes.find((n) => n.id === nodeId);
      if (!node) { addLog(nodeId, 'Node not found', 'error'); return; }

      addLog(nodeId, `Executing${payload ? ' with payload' : ''}...`, 'info');
      const api = getElectronApi();
      if (!api) { addLog(nodeId, 'Electron API not available', 'error'); return; }

      const start = performance.now();
      try {
        let result: any;
        const s = api.shield;
        const ch = node.ipcChannel;

        // ─── Route to the real IPC handler based on channel ───
        if (ch === 'shield-block-ip' && payload?.ip) {
          result = await s.blockIP(String(payload.ip), String(payload.reason || 'Blocked via Connector Map'));
        } else if (ch === 'shield-unblock-ip' && payload?.ip) {
          result = await s.unblockIP(String(payload.ip));
        } else if (ch === 'shield-block-subnet' && payload?.ip) {
          result = await s.blockIPSubnet(String(payload.ip), Number(payload.mask ?? 24));
        } else if (ch === 'shield-block-port' && payload?.port) {
          result = await s.blockPort({ port: Number(payload.port), protocol: (payload.protocol as 'TCP' | 'UDP' | 'Both') ?? 'TCP', direction: (payload.direction as 'in' | 'out' | 'both') ?? 'both' });
        } else if (ch === 'shield-block-pid' && payload?.pid) {
          result = await s.blockPid({ pid: Number(payload.pid), direction: (payload.direction as 'in' | 'out' | 'both') ?? 'both' });
        } else if (ch === 'shield-get-blocked-ips') {
          result = await s.getBlockedIPs();
        } else if (ch === 'shield-get-firewall-rules') {
          result = await s.getFirewallRules();
        } else if (ch === 'shield-get-firewall-inventory') {
          result = await s.getFirewallInventory();
        } else if (ch === 'shield-delete-firewall-rule' && payload?.ruleName) {
          result = await s.deleteFirewallRule(String(payload.ruleName));
        } else if (ch === 'shield-get-sentinel-rules') {
          result = await s.getSentinelRules();
        } else if (ch === 'shield-clear-sentinel-rules') {
          result = await s.clearSentinelRules();
        } else if (ch === 'shield-self-test') {
          result = await s.selfTest();
        } else if (ch === 'shield-undo-firewall') {
          result = await s.undoFirewall();
        } else if (ch === 'shield-redo-firewall') {
          result = await s.redoFirewall();
        } else if (ch === 'shield-get-undo-redo-state') {
          result = await s.getUndoRedoState();
        } else if (ch === 'shield-stage-firewall-rule' && payload) {
          result = await s.stageFirewallRule(payload as any);
        } else if (ch === 'shield-get-pending-rules') {
          result = await s.getPendingRules();
        } else if (ch === 'shield-commit-pending-rule' && payload?.ruleId) {
          result = await s.commitPendingRule(String(payload.ruleId));
        } else if (ch === 'shield-dismiss-pending-rule' && payload?.ruleId) {
          result = await s.dismissPendingRule(String(payload.ruleId));
        } else if (ch === 'shield-register-address-watch' && payload?.ip) {
          result = await s.registerAddressWatch(String(payload.ip));
        } else if (ch === 'shield-get-address-watch') {
          result = await s.getAddressWatch();
        } else if (ch === 'shield-whitelist-threat' && payload?.ip) {
          result = await s.whitelistThreat({ ip: String(payload.ip) });
        } else if (ch === 'shield-get-network-traffic') {
          result = await s.getNetworkTraffic();
        } else if (ch === 'shield-get-processes') {
          result = await s.getProcesses();
        } else if (ch === 'shield-kill-process' && payload?.pid) {
          result = await s.killProcess(Number(payload.pid), String(payload.name ?? ''));
        } else if (ch === 'shield-inspect-tls' && payload?.host) {
          result = await s.inspectTls(String(payload.host));
        } else if (ch === 'shield-get-ip-metadata' && payload?.ip) {
          result = await s.getIpMetadata(String(payload.ip));
        } else if (ch === 'shield-get-security-overview') {
          result = await s.getSecurityOverview();
        } else if (ch === 'forge-get-windows-services') {
          result = await (api as any).system?.getServices?.();
        } else if (ch === 'forge-control-service' && payload?.serviceName) {
          result = await (api as any).system?.controlService?.(String(payload.serviceName), String(payload.action ?? 'status'));
        } else if (ch === 'sentinel-full-scan') {
          result = await s.fullScan();
        } else if (ch === 'sentinel-kernel-scan') {
          result = await s.kernelScan();
        } else if (ch === 'sentinel-edr-scan') {
          result = await s.edrScan();
        } else if (ch === 'sentinel-network-scan') {
          result = await s.networkScan();
        } else if (ch === 'sentinel-performance-scan') {
          result = await s.performanceScan();
        } else if (ch === 'sentinel-privacy-scan') {
          result = await s.privacyScan();
        // --- Guardian / Intel ---
        } else if (ch === 'guardian-get-threat-intel') {
          result = await s.getGuardianThreatIntel();
        } else if (ch === 'guardian-refresh-threat-intel') {
          result = await s.refreshGuardianThreatIntel({ force: true } as any);
        } else if (ch === 'shield-get-guardian-stories') {
          result = await s.getGuardianStories();
        } else if (ch === 'shield-log-guardian-event') {
          result = await s.logGuardianEvent(payload as any || {});
        } else if (ch === 'shield-get-threat-events') {
          result = await s.getThreatEvents();
        } else if (ch === 'shield-get-policy-suggestions') {
          result = await s.getPolicySuggestions();
        } else if (ch === 'shield-accept-policy-suggestion' && payload?.policyId) {
          result = await s.acceptPolicySuggestion(String(payload.policyId));
        } else if (ch === 'shield-dismiss-policy-suggestion' && payload?.policyId) {
          result = await s.dismissPolicySuggestion(String(payload.policyId));
        // --- Guardian Playbooks ---
        } else if (ch === 'guardian-list-playbooks') {
          result = await s.listGuardianPlaybooks();
        } else if (ch === 'guardian-save-playbook') {
          result = await s.saveGuardianPlaybook(payload as any || {});
        } else if (ch === 'guardian-delete-playbook' && payload?.id) {
          result = await s.deleteGuardianPlaybook(String(payload.id));
        } else if (ch === 'guardian-run-playbook' && payload?.id) {
          result = await s.runGuardianPlaybook({ id: String(payload.id), dryRun: !!payload.dryRun });
        } else if (ch === 'guardian-get-playbook-runs') {
          result = await s.getGuardianPlaybookRuns();
        } else if (ch === 'guardian-get-anomaly-config') {
          result = await s.getGuardianAnomalyConfig();
        } else if (ch === 'guardian-update-anomaly-config') {
          result = await s.updateGuardianAnomalyConfig(payload as any || {});
        // --- Network / Diagnostics ---
        } else if (ch === 'shield-get-network-diagnostics') {
          result = await s.getNetworkDiagnostics();
        } else if (ch === 'shield-get-full-network-audit') {
          result = await s.getNetworkTraffic(500);
        } else if (ch === 'shield-test-internet') {
          result = await (api as any).advanced?.getNetworkDiagnostics?.() ?? { success: true, message: 'N/A' };
        // --- ARGUS Intel ---
        } else if (ch === 'intel-url-scan' && payload?.url) {
          result = await api.argus.scanUrl(String(payload.url));
        } else if (ch === 'intel-batch-scan' && payload?.urls) {
          result = await api.argus.batchScan(payload.urls as string[]);
        } else if (ch === 'intel-scan-history') {
          result = await api.argus.getScanHistory();
        } else if (ch === 'intel-export-history') {
          result = await api.argus.exportHistory();
        } else if (ch === 'intel-clear-history') {
          result = await api.argus.clearHistory();
        } else if (ch === 'net-sandbox-status') {
          result = await api.argus.getSandboxStatus();
        } else if (ch === 'net-sandbox-toggle') {
          result = await api.argus.toggleSandbox(!!payload?.enabled);
        // --- Ghost DNS / Privacy ---
        } else if (ch === 'ghost-get-current-dns') {
          result = await (api as any).ghost?.getCurrentDNS?.();
        } else if (ch === 'ghost-set-dns' && payload?.primary) {
          result = await (api as any).ghost?.setDNS?.(String(payload.primary), String(payload.secondary || ''));
        } else if (ch === 'ghost-get-hosts-file') {
          result = await (api as any).ghost?.getHostsFile?.();
        } else if (ch === 'ghost-save-hosts-file' && payload?.content) {
          result = await (api as any).ghost?.saveHostsFile?.(String(payload.content));
        // --- Forge Performance ---
        } else if (ch === 'forge-get-ram-stats') {
          result = await (api as any).forge?.getRAMStats?.();
        } else if (ch === 'forge-clear-standby-cache') {
          result = await (api as any).forge?.clearStandbyCache?.();
        } else if (ch === 'forge-get-startup-items') {
          result = await (api as any).forge?.getStartupItems?.();
        // --- Vault ---
        } else if (ch === 'vault-get-secure-notes') {
          result = await (api as any).vault?.getSecureNotes?.();
        } else if (ch === 'vault-save-secure-note') {
          result = await (api as any).vault?.saveSecureNote?.(payload || {});
        } else if (ch === 'vault-get-encrypted-files') {
          result = await (api as any).vault?.getEncryptedFiles?.();
        } else if (ch === 'vault-encrypt') {
          result = await api.argus.encryptData(String(payload?.data || ''));
        } else if (ch === 'vault-decrypt') {
          result = await api.argus.decryptData(String(payload?.data || ''));
        // --- Sentinel Config ---
        } else if (ch === 'sentinel-get-config') {
          result = await (api as any).sentinelConfig?.getConfig?.();
        } else if (ch === 'sentinel-set-autonomous-mode') {
          result = await (api as any).sentinelConfig?.setAutonomousMode?.(!!payload?.enabled);
        } else if (ch === 'sentinel-add-whitelist' && payload?.ip) {
          result = await (api as any).sentinelConfig?.addWhitelist?.(String(payload.ip));
        } else if (ch === 'sentinel-remove-whitelist' && payload?.ip) {
          result = await (api as any).sentinelConfig?.removeWhitelist?.(String(payload.ip));
        } else if (ch === 'sentinel-set-whitelist' && payload?.ips) {
          result = await (api as any).sentinelConfig?.setWhitelist?.(payload.ips as string[]);
        } else if (ch === 'sentinel-log-manual-block') {
          result = await s.logManualBlock(payload as any || {});
        } else if (ch === 'sentinel-quick-block-subnet' && payload?.subnet) {
          result = await s.quickBlockSubnet(String(payload.subnet), String(payload.reason || ''));
        } else if (ch === 'sentinel-get-health-report') {
          result = await (api as any).getSystemHealth?.() ?? { success: true };
        // --- System / Settings ---
        } else if (ch === 'check-admin-rights') {
          result = await (api as any).admin?.checkAdminRights?.();
        } else if (ch === 'get-real-system-data') {
          result = await (api as any).getSystemData?.() ?? { success: true, message: 'Invoke via main' };
        } else if (ch === 'get-system-health') {
          result = await (api as any).getSystemHealth?.();
        } else if (ch === 'get-system-stats') {
          result = await (api as any).getSystemStats?.();
        } else if (ch === 'get-settings') {
          result = await (api as any).getSettings?.();
        } else if (ch === 'save-settings' && payload) {
          result = await (api as any).saveSettings?.(payload);
        } else if (ch === 'get-activity-log') {
          result = await (api as any).getActivityLog?.();
        } else if (ch === 'clear-activity-log') {
          result = await (api as any).clearActivityLog?.();
        } else if (ch === 'execute-quick-action' && payload?.action) {
          result = await (api as any).executeQuickAction?.(String(payload.action));
        } else {
          addLog(nodeId, `Unrouted channel: ${ch} — no handler mapped`, 'warn');
          return;
        }

        const latency = performance.now() - start;
        const success = result?.success !== false;

        // Store full response for output display
        setNodeResponses(prev => ({ ...prev, [nodeId]: result }));

        // Build detailed log message
        let logMsg = `${success ? 'OK' : 'FAIL'} (${Math.round(latency)}ms)`;
        if (result?.message) logMsg += `: ${result.message}`;
        if (result?.error && typeof result.error === 'string') logMsg += ` | Error: ${result.error}`;
        if (result?.data && typeof result.data === 'object') {
          const keys = Object.keys(result.data);
          if (keys.length > 0) logMsg += ` | Keys: ${keys.slice(0, 6).join(', ')}${keys.length > 6 ? '...' : ''}`;
        }
        if (Array.isArray(result?.rules)) logMsg += ` | ${result.rules.length} rules`;
        if (Array.isArray(result?.events)) logMsg += ` | ${result.events.length} events`;
        if (Array.isArray(result?.checks)) logMsg += ` | ${result.checks.length} checks, score: ${result.score ?? '?'}`;
        if (result?.score !== undefined && result?.modules) logMsg += ` | Score: ${result.score}/100`;

        addLog(nodeId, logMsg, success ? 'info' : 'error');

        // Update node status based on result
        setNodes(prev => prev.map(n =>
          n.id === nodeId ? { ...n, status: success ? 'online' : 'error', lastResponseMs: latency } : n
        ));
      } catch (err: any) {
        const errMsg = err?.message || String(err);
        setNodeResponses(prev => ({ ...prev, [nodeId]: { success: false, error: errMsg } }));
        addLog(nodeId, `Error: ${errMsg}`, 'error');
        setNodes(prev => prev.map(n =>
          n.id === nodeId ? { ...n, status: 'error', errorCount24h: n.errorCount24h + 1 } : n
        ));
      }
    },
    [nodes, addLog]
  );

  const disableNode = useCallback(
    (nodeId: string) => {
      addLog(nodeId, `Node disabled by user`, 'warn');
      setNodes((prev) =>
        prev.map((n) => (n.id === nodeId ? { ...n, status: 'offline' as NodeStatus } : n))
      );
    },
    [addLog]
  );

  // -----------------------------------------------------------------------
  // State
  // -----------------------------------------------------------------------

  const state: ConnectorMapState = useMemo(
    () => ({
      nodes,
      edges: ALL_EDGES,
      selectedNode,
      hoveredNode,
      filters,
      zoom,
      rotation: 0,
    }),
    [nodes, selectedNode, hoveredNode, filters, zoom]
  );

  const getNodeResponse = useCallback((nodeId: string) => nodeResponses[nodeId] ?? null, [nodeResponses]);

  const getNodeEdges = useCallback(
    (nodeId: string): ConnectorEdge[] => ALL_EDGES.filter(e => e.source === nodeId || e.target === nodeId),
    []
  );

  return {
    state,
    filteredNodes,
    filteredEdges,
    selectNode,
    hoverNode,
    toggleCluster,
    setZoom,
    resetFilters,
    getNodeLogs,
    getNodeResponse,
    getNodeEdges,
    executeNode,
    disableNode,
  };
}
