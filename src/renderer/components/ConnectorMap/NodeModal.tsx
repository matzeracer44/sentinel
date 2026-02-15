/**
 * Sentinel Unified — NodeModal
 * Detail overlay for a selected connector node.
 * Dynamic handler-specific inputs per IPC channel.
 */

import React, { useEffect, useCallback, useState, useRef } from 'react';
import type { ConnectorNode, ConnectorEdge, NodeLogEntry, NodeStatus } from '../../types/connectorMap';
import { CLUSTER_COLORS, STATUS_COLORS } from './connectorMapTheme';

// ---------------------------------------------------------------------------
// Handler Schema — maps IPC channels to their required input fields
// ---------------------------------------------------------------------------

interface FieldDef {
  key: string;
  label: string;
  type: 'text' | 'number' | 'select';
  placeholder?: string;
  options?: { label: string; value: string }[];
  defaultValue?: string;
  required?: boolean;
}

type HandlerSchema = { label: string; fields: FieldDef[]; noPayload?: boolean };

const HANDLER_SCHEMAS: Record<string, HandlerSchema> = {
  // Firewall — IP blocking
  'shield-block-ip': {
    label: 'Block IP Address',
    fields: [
      { key: 'ip', label: 'Target IP', type: 'text', placeholder: '93.184.216.34', required: true },
      { key: 'reason', label: 'Reason', type: 'text', placeholder: 'Suspicious activity' },
    ],
  },
  'shield-unblock-ip': {
    label: 'Unblock IP Address',
    fields: [
      { key: 'ip', label: 'IP to Unblock', type: 'text', placeholder: '93.184.216.34', required: true },
    ],
  },
  'shield-block-subnet': {
    label: 'Block Subnet',
    fields: [
      { key: 'ip', label: 'Network / CIDR', type: 'text', placeholder: '10.0.0.0/8', required: true },
      { key: 'mask', label: 'Mask', type: 'number', placeholder: '24', defaultValue: '24' },
    ],
  },
  'shield-block-port': {
    label: 'Block Port',
    fields: [
      { key: 'port', label: 'Port', type: 'number', placeholder: '4444', required: true },
      { key: 'protocol', label: 'Protocol', type: 'select', options: [{ label: 'TCP', value: 'TCP' }, { label: 'UDP', value: 'UDP' }, { label: 'Both', value: 'Both' }], defaultValue: 'TCP' },
      { key: 'direction', label: 'Direction', type: 'select', options: [{ label: 'Both', value: 'both' }, { label: 'Inbound', value: 'in' }, { label: 'Outbound', value: 'out' }], defaultValue: 'both' },
    ],
  },
  'shield-block-pid': {
    label: 'Block Process (PID)',
    fields: [
      { key: 'pid', label: 'PID', type: 'number', placeholder: '1234', required: true },
      { key: 'direction', label: 'Direction', type: 'select', options: [{ label: 'Both', value: 'both' }, { label: 'Inbound', value: 'in' }, { label: 'Outbound', value: 'out' }], defaultValue: 'both' },
    ],
  },
  'shield-delete-firewall-rule': {
    label: 'Delete Firewall Rule',
    fields: [
      { key: 'ruleName', label: 'Rule Name', type: 'text', placeholder: 'Sentinel_Block_...', required: true },
    ],
  },
  'shield-register-address-watch': {
    label: 'Watch IP Address',
    fields: [
      { key: 'ip', label: 'IP to Monitor', type: 'text', placeholder: '93.184.216.34', required: true },
    ],
  },
  'shield-whitelist-threat': {
    label: 'Whitelist Threat',
    fields: [
      { key: 'ip', label: 'IP to Whitelist', type: 'text', placeholder: '93.184.216.34', required: true },
    ],
  },
  'shield-commit-pending-rule': {
    label: 'Commit Pending Rule',
    fields: [
      { key: 'ruleId', label: 'Rule ID', type: 'text', placeholder: 'rule-id', required: true },
    ],
  },
  'shield-dismiss-pending-rule': {
    label: 'Dismiss Pending Rule',
    fields: [
      { key: 'ruleId', label: 'Rule ID', type: 'text', placeholder: 'rule-id', required: true },
    ],
  },
  // Network
  'shield-kill-process': {
    label: 'Kill Process',
    fields: [
      { key: 'pid', label: 'PID', type: 'number', placeholder: '1234', required: true },
      { key: 'name', label: 'Process Name', type: 'text', placeholder: 'malware.exe' },
    ],
  },
  'shield-inspect-tls': {
    label: 'TLS Inspection',
    fields: [
      { key: 'host', label: 'Hostname', type: 'text', placeholder: 'google.com', required: true },
    ],
  },
  'shield-get-ip-metadata': {
    label: 'IP Lookup',
    fields: [
      { key: 'ip', label: 'IP Address', type: 'text', placeholder: '8.8.8.8', required: true },
    ],
  },
  // System services
  'forge-get-windows-services': {
    label: 'List Services',
    fields: [],
    noPayload: true,
  },
  'forge-control-service': {
    label: 'Control Service',
    fields: [
      { key: 'serviceName', label: 'Service Name', type: 'text', placeholder: 'wuauserv', required: true },
      { key: 'action', label: 'Action', type: 'select', options: [{ label: 'Start', value: 'start' }, { label: 'Stop', value: 'stop' }, { label: 'Restart', value: 'restart' }, { label: 'Status', value: 'status' }], defaultValue: 'status' },
    ],
  },
  // Read-only / no-payload channels
  'shield-get-blocked-ips': { label: 'Fetch Blocked IPs', fields: [], noPayload: true },
  'shield-get-firewall-rules': { label: 'Fetch Firewall Rules', fields: [], noPayload: true },
  'shield-get-firewall-inventory': { label: 'Fetch Full Inventory', fields: [], noPayload: true },
  'shield-get-sentinel-rules': { label: 'Fetch Sentinel Rules', fields: [], noPayload: true },
  'shield-clear-sentinel-rules': { label: 'Clear All Sentinel Rules', fields: [], noPayload: true },
  'shield-self-test': { label: 'Run Self Test', fields: [], noPayload: true },
  'shield-undo-firewall': { label: 'Undo Last Action', fields: [], noPayload: true },
  'shield-redo-firewall': { label: 'Redo Action', fields: [], noPayload: true },
  'shield-get-undo-redo-state': { label: 'Get Undo/Redo State', fields: [], noPayload: true },
  'shield-get-pending-rules': { label: 'List Pending Rules', fields: [], noPayload: true },
  'shield-get-address-watch': { label: 'Get Watch Summary', fields: [], noPayload: true },
  'shield-get-network-traffic': { label: 'Fetch Connections', fields: [], noPayload: true },
  'shield-get-processes': { label: 'List Processes', fields: [], noPayload: true },
  'shield-get-security-overview': { label: 'Security Overview', fields: [], noPayload: true },
  'sentinel-full-scan': { label: 'Full Security Scan', fields: [], noPayload: true },
  'sentinel-kernel-scan': { label: 'Kernel Scan', fields: [], noPayload: true },
  'sentinel-edr-scan': { label: 'EDR Scan', fields: [], noPayload: true },
  'sentinel-network-scan': { label: 'Network Scan', fields: [], noPayload: true },
  'sentinel-performance-scan': { label: 'Performance Scan', fields: [], noPayload: true },
  'sentinel-privacy-scan': { label: 'Privacy Scan', fields: [], noPayload: true },
  // --- Guardian / Intel ---
  'guardian-get-threat-intel': { label: 'Query Threat Intel', fields: [], noPayload: true },
  'guardian-refresh-threat-intel': { label: 'Refresh Threat Intel', fields: [], noPayload: true },
  'shield-get-guardian-stories': { label: 'Fetch Threat Stories', fields: [], noPayload: true },
  'shield-log-guardian-event': { label: 'Log Guardian Event', fields: [], noPayload: true },
  'shield-get-threat-events': { label: 'Fetch Threat Events', fields: [], noPayload: true },
  'shield-get-policy-suggestions': { label: 'Policy Suggestions', fields: [], noPayload: true },
  'shield-accept-policy-suggestion': {
    label: 'Accept Policy',
    fields: [{ key: 'policyId', label: 'Policy ID', type: 'text', placeholder: 'pol-...', required: true }],
  },
  'shield-dismiss-policy-suggestion': {
    label: 'Dismiss Policy',
    fields: [{ key: 'policyId', label: 'Policy ID', type: 'text', placeholder: 'pol-...', required: true }],
  },
  // --- Playbooks ---
  'guardian-list-playbooks': { label: 'List Playbooks', fields: [], noPayload: true },
  'guardian-save-playbook': { label: 'Save Playbook', fields: [], noPayload: true },
  'guardian-delete-playbook': {
    label: 'Delete Playbook',
    fields: [{ key: 'id', label: 'Playbook ID', type: 'text', placeholder: 'pb-...', required: true }],
  },
  'guardian-run-playbook': {
    label: 'Run Playbook',
    fields: [
      { key: 'id', label: 'Playbook ID', type: 'text', placeholder: 'pb-...', required: true },
      { key: 'dryRun', label: 'Dry Run', type: 'select', options: [{ label: 'No', value: '' }, { label: 'Yes', value: 'true' }], defaultValue: '' },
    ],
  },
  'guardian-get-playbook-runs': { label: 'Playbook History', fields: [], noPayload: true },
  'guardian-get-anomaly-config': { label: 'Anomaly Config', fields: [], noPayload: true },
  'guardian-update-anomaly-config': { label: 'Update Anomaly Config', fields: [], noPayload: true },
  // --- Network ---
  'shield-get-network-diagnostics': { label: 'Network Diagnostics', fields: [], noPayload: true },
  'shield-get-full-network-audit': { label: 'Full Network Audit', fields: [], noPayload: true },
  'shield-test-internet': { label: 'Internet Connectivity Test', fields: [], noPayload: true },
  // --- ARGUS Intel ---
  'intel-url-scan': {
    label: 'Deep URL Scan',
    fields: [{ key: 'url', label: 'Target URL', type: 'text', placeholder: 'https://example.com', required: true }],
  },
  'intel-batch-scan': {
    label: 'Batch URL Scan',
    fields: [{ key: 'urls', label: 'URLs (comma-separated)', type: 'text', placeholder: 'https://a.com, https://b.com', required: true }],
  },
  'intel-scan-history': { label: 'Scan History', fields: [], noPayload: true },
  'intel-export-history': { label: 'Export History', fields: [], noPayload: true },
  'intel-clear-history': { label: 'Clear History', fields: [], noPayload: true },
  'net-sandbox-status': { label: 'Sandbox Status', fields: [], noPayload: true },
  'net-sandbox-toggle': {
    label: 'Toggle Sandbox',
    fields: [{ key: 'enabled', label: 'Enable', type: 'select', options: [{ label: 'On', value: 'true' }, { label: 'Off', value: '' }], defaultValue: 'true' }],
  },
  // --- Ghost DNS ---
  'ghost-get-current-dns': { label: 'Get Current DNS', fields: [], noPayload: true },
  'ghost-set-dns': {
    label: 'Set DNS Servers',
    fields: [
      { key: 'primary', label: 'Primary DNS', type: 'text', placeholder: '1.1.1.1', required: true },
      { key: 'secondary', label: 'Secondary DNS', type: 'text', placeholder: '1.0.0.1' },
    ],
  },
  'ghost-get-hosts-file': { label: 'Read Hosts File', fields: [], noPayload: true },
  'ghost-save-hosts-file': {
    label: 'Write Hosts File',
    fields: [{ key: 'content', label: 'Hosts Content', type: 'text', placeholder: '127.0.0.1 blocked.com', required: true }],
  },
  // --- Forge ---
  'forge-get-ram-stats': { label: 'RAM Statistics', fields: [], noPayload: true },
  'forge-clear-standby-cache': { label: 'Clear Standby Cache', fields: [], noPayload: true },
  'forge-get-startup-items': { label: 'Startup Items', fields: [], noPayload: true },
  // --- Vault ---
  'vault-get-secure-notes': { label: 'Get Secure Notes', fields: [], noPayload: true },
  'vault-save-secure-note': { label: 'Save Secure Note', fields: [], noPayload: true },
  'vault-get-encrypted-files': { label: 'Encrypted Files', fields: [], noPayload: true },
  'vault-encrypt': {
    label: 'Encrypt Data',
    fields: [{ key: 'data', label: 'Plaintext', type: 'text', placeholder: 'Data to encrypt', required: true }],
  },
  'vault-decrypt': {
    label: 'Decrypt Data',
    fields: [{ key: 'data', label: 'Ciphertext', type: 'text', placeholder: 'Encrypted data', required: true }],
  },
  // --- Sentinel Config ---
  'sentinel-get-config': { label: 'Get Sentinel Config', fields: [], noPayload: true },
  'sentinel-set-autonomous-mode': {
    label: 'Set Autonomous Mode',
    fields: [{ key: 'enabled', label: 'Enable', type: 'select', options: [{ label: 'On', value: 'true' }, { label: 'Off', value: '' }], defaultValue: '' }],
  },
  'sentinel-add-whitelist': {
    label: 'Add to Whitelist',
    fields: [{ key: 'ip', label: 'IP Address', type: 'text', placeholder: '8.8.8.8', required: true }],
  },
  'sentinel-remove-whitelist': {
    label: 'Remove from Whitelist',
    fields: [{ key: 'ip', label: 'IP Address', type: 'text', placeholder: '8.8.8.8', required: true }],
  },
  'sentinel-set-whitelist': { label: 'Set Whitelist', fields: [], noPayload: true },
  'sentinel-log-manual-block': { label: 'Log Manual Block', fields: [], noPayload: true },
  'sentinel-quick-block-subnet': {
    label: 'Quick Block Subnet',
    fields: [
      { key: 'subnet', label: 'Subnet CIDR', type: 'text', placeholder: '10.0.0.0/8', required: true },
      { key: 'reason', label: 'Reason', type: 'text', placeholder: 'Suspicious network' },
    ],
  },
  'sentinel-get-health-report': { label: 'Health Report', fields: [], noPayload: true },
  // --- System ---
  'check-admin-rights': { label: 'Check Admin Rights', fields: [], noPayload: true },
  'get-real-system-data': { label: 'System Data', fields: [], noPayload: true },
  'get-system-health': { label: 'System Health Score', fields: [], noPayload: true },
  'get-system-stats': { label: 'System Stats', fields: [], noPayload: true },
  'get-settings': { label: 'Get Settings', fields: [], noPayload: true },
  'save-settings': { label: 'Save Settings', fields: [], noPayload: true },
  'get-activity-log': { label: 'Activity Log', fields: [], noPayload: true },
  'clear-activity-log': { label: 'Clear Activity Log', fields: [], noPayload: true },
  'execute-quick-action': {
    label: 'Quick Action',
    fields: [{ key: 'action', label: 'Action Name', type: 'text', placeholder: 'flush-dns', required: true }],
  },
};

// ---------------------------------------------------------------------------
// Shared styles
// ---------------------------------------------------------------------------

const INPUT_STYLE: React.CSSProperties = {
  width: '100%',
  padding: '6px 10px',
  fontSize: 12,
  fontFamily: "'Cascadia Code', 'Fira Code', monospace",
  background: 'rgba(10, 14, 30, 0.6)',
  border: '1px solid rgba(109, 120, 255, 0.2)',
  borderRadius: 6,
  color: '#e2e8f0',
  outline: 'none',
};

const SELECT_STYLE: React.CSSProperties = { ...INPUT_STYLE, cursor: 'pointer' };
const LABEL_STYLE: React.CSSProperties = { fontSize: 10, color: '#94a3b8', marginBottom: 3, display: 'block' };

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Source file mapping — which .ts file handles each IPC channel prefix
// ---------------------------------------------------------------------------

const SOURCE_MAP: { prefix: string; file: string; module: string }[] = [
  { prefix: 'shield-block-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-unblock-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-get-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-delete-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-enable-', file: 'main.ts', module: 'Shield' },
  { prefix: 'shield-add-', file: 'main.ts', module: 'Shield' },
  { prefix: 'shield-stage-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-commit-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-dismiss-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-register-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-whitelist-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-clear-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-self-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-undo-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-redo-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-kill-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-inspect-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'shield-log-', file: 'shieldHandlers.ts', module: 'Shield' },
  { prefix: 'guardian-', file: 'shieldHandlers.ts', module: 'Guardian' },
  { prefix: 'sentinel-kernel-', file: 'main.ts', module: 'Kernel Integrity' },
  { prefix: 'sentinel-edr-', file: 'main.ts', module: 'EDR Engine' },
  { prefix: 'sentinel-network-', file: 'main.ts', module: 'Network WFP' },
  { prefix: 'sentinel-performance-', file: 'main.ts', module: 'Performance' },
  { prefix: 'sentinel-privacy-', file: 'main.ts', module: 'Privacy' },
  { prefix: 'sentinel-full-', file: 'main.ts', module: 'Full Scan' },
  { prefix: 'sentinel-', file: 'main.ts', module: 'Sentinel Core' },
  { prefix: 'forge-', file: 'main.ts', module: 'Forge' },
  { prefix: 'ghost-', file: 'main.ts', module: 'Ghost' },
  { prefix: 'vault-', file: 'main.ts', module: 'Vault' },
  { prefix: 'intel-', file: 'main.ts', module: 'Intel (ARGUS)' },
  { prefix: 'get-', file: 'main.ts', module: 'System' },
  { prefix: 'check-', file: 'main.ts', module: 'System' },
  { prefix: 'execute-', file: 'main.ts', module: 'System' },
];

function getSourceInfo(channel?: string): { file: string; module: string } {
  if (!channel) return { file: 'N/A', module: 'N/A' };
  for (const m of SOURCE_MAP) {
    if (channel.startsWith(m.prefix)) return { file: `src/main/${m.file.includes('/') ? m.file : (m.file === 'main.ts' ? 'main.ts' : 'ipc/' + m.file)}`, module: m.module };
  }
  return { file: 'src/main/main.ts', module: 'Main' };
}

// ---------------------------------------------------------------------------
// Edge type styling
// ---------------------------------------------------------------------------

const EDGE_TYPE_STYLE: Record<string, { color: string; label: string }> = {
  'data-flow': { color: '#00f0ff', label: 'DATA FLOW' },
  heartbeat: { color: '#4b5563', label: 'HEARTBEAT' },
  dependency: { color: '#a855f7', label: 'DEPENDENCY' },
  trigger: { color: '#ff3366', label: 'TRIGGER' },
};

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface NodeModalProps {
  node: ConnectorNode;
  logs: NodeLogEntry[];
  edges: ConnectorEdge[];
  lastResponse: any;
  allNodes: ConnectorNode[];
  loading: boolean;
  onClose: () => void;
  onExecute: (nodeId: string, payload?: Record<string, unknown>) => void;
  onDisable: (nodeId: string) => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatLatency(ms: number): string {
  if (ms < 0) return '\u2014';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function statusLabel(status: NodeStatus): string {
  switch (status) {
    case 'online': return 'ONLINE';
    case 'degraded': return 'DEGRADED';
    case 'error': return 'ERROR';
    case 'offline': return 'OFFLINE';
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const NodeModal: React.FC<NodeModalProps> = ({ node, logs, edges, lastResponse, allNodes, loading, onClose, onExecute, onDisable }) => {
  const [phase, setPhase] = useState<'entering' | 'visible' | 'exiting'>('entering');
  const [fields, setFields] = useState<Record<string, string>>({});
  const [executing, setExecuting] = useState(false);
  const [responseExpanded, setResponseExpanded] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const sourceInfo = getSourceInfo(node.ipcChannel);

  const schema = node.ipcChannel ? HANDLER_SCHEMAS[node.ipcChannel] : undefined;

  // Initialize default values when node changes
  useEffect(() => {
    const defaults: Record<string, string> = {};
    if (schema?.fields) {
      schema.fields.forEach(f => { if (f.defaultValue) defaults[f.key] = f.defaultValue; });
    }
    setFields(defaults);
  }, [node.id]);

  useEffect(() => {
    const timer = setTimeout(() => setPhase('visible'), 210);
    return () => clearTimeout(timer);
  }, []);

  const handleClose = useCallback(() => {
    setPhase('exiting');
    setTimeout(() => onClose(), 160);
  }, [onClose]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') handleClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [handleClose]);

  const handleBackdropClick = useCallback((e: React.MouseEvent) => {
    if (e.target === e.currentTarget) handleClose();
  }, [handleClose]);

  const handleFieldChange = useCallback((key: string, value: string) => {
    setFields(prev => ({ ...prev, [key]: value }));
  }, []);

  const handleExecute = useCallback(async () => {
    if (!schema) return;
    // Validate required fields
    for (const f of schema.fields) {
      if (f.required && !fields[f.key]?.trim()) {
        return; // don't execute without required fields
      }
    }
    setExecuting(true);
    try {
      const payload: Record<string, unknown> = {};
      schema.fields.forEach(f => {
        const v = fields[f.key]?.trim();
        if (v) payload[f.key] = f.type === 'number' ? Number(v) : v;
      });
      await onExecute(node.id, Object.keys(payload).length > 0 ? payload : undefined);
    } finally {
      setExecuting(false);
    }
  }, [schema, fields, node.id, onExecute]);

  const clusterColor = CLUSTER_COLORS[node.cluster];
  const statusColor = STATUS_COLORS[node.status] ?? STATUS_COLORS.offline;

  // Check if all required fields are filled
  const canExecute = !executing && (!schema?.fields.length || schema.fields.every(f => !f.required || fields[f.key]?.trim()));

  return (
    <div
      className={`modal-backdrop modal-backdrop--${phase === 'exiting' ? 'exiting' : 'entering'}`}
      onClick={handleBackdropClick}
    >
      <div
        ref={panelRef}
        className={`modal-panel modal-panel--${phase === 'exiting' ? 'exiting' : 'entering'}`}
        style={{ borderColor: clusterColor, boxShadow: `0 0 30px ${clusterColor}22` }}
      >
        {/* Header */}
        <div className="modal-header">
          <div className="modal-title">
            <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: statusColor, boxShadow: `0 0 6px ${statusColor}` }} />
            <span>{node.name}</span>
            <span style={{ fontSize: 10, color: clusterColor, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.8px' }}>
              {node.cluster}
            </span>
          </div>
          <button className="modal-close" onClick={handleClose} aria-label="Close">
            {'\u00D7'}
          </button>
        </div>

        {/* Status Section */}
        <div className="modal-section">
          <div className="modal-section-title">Status</div>
          <div className="modal-status-row">
            <div className="modal-stat">
              <span className="modal-stat-label">Status</span>
              <span className="modal-stat-value" style={{ color: statusColor }}>{statusLabel(node.status)}</span>
            </div>
            <div className="modal-stat">
              <span className="modal-stat-label">Latency</span>
              <span className="modal-stat-value">{formatLatency(node.lastResponseMs)}</span>
            </div>
            <div className="modal-stat">
              <span className="modal-stat-label">Errors (24h)</span>
              <span className="modal-stat-value" style={{ color: node.errorCount24h > 0 ? '#ff3366' : '#e2e8f0' }}>{node.errorCount24h}</span>
            </div>
            <div className="modal-stat">
              <span className="modal-stat-label">Source</span>
              <span className="modal-stat-value">{node.source === 'argus' ? 'ARGUS' : 'Sentinel'}</span>
            </div>
          </div>
        </div>

        {/* Connection Info */}
        <div className="modal-section">
          <div className="modal-section-title">Connection</div>
          <div className="modal-status-row" style={{ flexWrap: 'wrap' }}>
            {node.ipcChannel && (
              <div className="modal-stat">
                <span className="modal-stat-label">IPC Channel</span>
                <span className="modal-stat-value" style={{ fontFamily: "'Cascadia Code', 'Fira Code', monospace", fontSize: 11 }}>{node.ipcChannel}</span>
              </div>
            )}
            {node.restEndpoint && (
              <div className="modal-stat">
                <span className="modal-stat-label">REST Endpoint</span>
                <span className="modal-stat-value" style={{ fontFamily: "'Cascadia Code', 'Fira Code', monospace", fontSize: 11 }}>{node.restEndpoint}</span>
              </div>
            )}
            <div className="modal-stat">
              <span className="modal-stat-label">Node ID</span>
              <span className="modal-stat-value" style={{ fontFamily: "'Cascadia Code', 'Fira Code', monospace", fontSize: 11, color: '#94a3b8' }}>{node.id}</span>
            </div>
            <div className="modal-stat">
              <span className="modal-stat-label">Handler</span>
              <span className="modal-stat-value" style={{ fontFamily: "'Cascadia Code', 'Fira Code', monospace", fontSize: 10, color: '#a855f7' }}>{sourceInfo.file}</span>
            </div>
            <div className="modal-stat">
              <span className="modal-stat-label">Module</span>
              <span className="modal-stat-value" style={{ fontSize: 11, color: clusterColor }}>{sourceInfo.module}</span>
            </div>
            <div className="modal-stat">
              <span className="modal-stat-label">Ring</span>
              <span className="modal-stat-value" style={{ fontSize: 11 }}>{node.ring === 0 ? 'Core' : `Ring ${node.ring}`}</span>
            </div>
          </div>
        </div>

        {/* Cross-References (edges) */}
        {edges.length > 0 && (
          <div className="modal-section">
            <div className="modal-section-title">Cross-References ({edges.length})</div>
            <div style={{ display: 'grid', gap: 4 }}>
              {edges.map((edge, i) => {
                const isSource = edge.source === node.id;
                const peerId = isSource ? edge.target : edge.source;
                const peerNode = allNodes.find(n => n.id === peerId);
                const edgeStyle = EDGE_TYPE_STYLE[edge.type] || { color: '#64748b', label: edge.type.toUpperCase() };
                return (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px',
                    background: 'rgba(10,14,30,0.4)', borderRadius: 5, fontSize: 10,
                    border: `1px solid ${edgeStyle.color}15`,
                  }}>
                    <span style={{
                      fontSize: 8, fontWeight: 700, color: edgeStyle.color,
                      padding: '1px 5px', borderRadius: 3,
                      background: `${edgeStyle.color}15`, letterSpacing: '0.05em',
                      flexShrink: 0, minWidth: 62, textAlign: 'center',
                    }}>
                      {edgeStyle.label}
                    </span>
                    <span style={{ color: '#64748b', flexShrink: 0 }}>
                      {isSource ? '\u2192' : '\u2190'}
                    </span>
                    <span style={{ color: '#e2e8f0', fontWeight: 600, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                      {peerNode?.name || peerId}
                    </span>
                    {edge.label && (
                      <span style={{ color: '#64748b', fontStyle: 'italic', marginLeft: 'auto' }}>
                        {edge.label}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Dynamic Handler Inputs */}
        {schema && schema.fields.length > 0 && (
          <div className="modal-section">
            <div className="modal-section-title">{schema.label}</div>
            <div style={{ display: 'grid', gap: 10 }}>
              {schema.fields.map(f => (
                <div key={f.key}>
                  <label style={LABEL_STYLE}>
                    {f.label}{f.required && <span style={{ color: '#ff3366' }}> *</span>}
                  </label>
                  {f.type === 'select' ? (
                    <select
                      style={SELECT_STYLE}
                      value={fields[f.key] || f.defaultValue || ''}
                      onChange={e => handleFieldChange(f.key, e.target.value)}
                    >
                      {f.options?.map(o => (
                        <option key={o.value} value={o.value}>{o.label}</option>
                      ))}
                    </select>
                  ) : (
                    <input
                      style={INPUT_STYLE}
                      type={f.type === 'number' ? 'number' : 'text'}
                      placeholder={f.placeholder}
                      value={fields[f.key] || ''}
                      onChange={e => handleFieldChange(f.key, e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter' && canExecute) handleExecute(); }}
                    />
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Response Output */}
        {lastResponse && (
          <div className="modal-section">
            <div className="modal-section-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>Response Output</span>
              <button
                onClick={() => setResponseExpanded(!responseExpanded)}
                style={{
                  background: 'rgba(109,120,255,0.1)', border: '1px solid rgba(109,120,255,0.2)',
                  borderRadius: 4, padding: '1px 8px', fontSize: 9, color: '#94a3b8',
                  cursor: 'pointer', fontFamily: "'Segoe UI', system-ui, sans-serif",
                }}
              >
                {responseExpanded ? 'Collapse' : 'Expand JSON'}
              </button>
            </div>
            {/* Summary row */}
            <div style={{ display: 'flex', gap: 10, marginBottom: 6, flexWrap: 'wrap' }}>
              <span style={{
                fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                background: lastResponse.success !== false ? 'rgba(0,255,136,0.1)' : 'rgba(255,51,102,0.1)',
                color: lastResponse.success !== false ? '#00ff88' : '#ff3366',
                border: `1px solid ${lastResponse.success !== false ? 'rgba(0,255,136,0.2)' : 'rgba(255,51,102,0.2)'}`,
              }}>
                {lastResponse.success !== false ? 'SUCCESS' : 'FAILED'}
              </span>
              {lastResponse.score !== undefined && (
                <span style={{ fontSize: 10, color: '#ffaa00', fontWeight: 600 }}>Score: {lastResponse.score}/100</span>
              )}
              {lastResponse.message && (
                <span style={{ fontSize: 10, color: '#94a3b8' }}>{String(lastResponse.message).slice(0, 120)}</span>
              )}
              {lastResponse.error && typeof lastResponse.error === 'string' && (
                <span style={{ fontSize: 10, color: '#ff3366' }}>{lastResponse.error.slice(0, 120)}</span>
              )}
            </div>
            {/* Collapsed: key-value summary */}
            {!responseExpanded && (
              <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '2px 10px', fontSize: 10 }}>
                {Object.entries(lastResponse).filter(([k]) => k !== 'success').slice(0, 8).map(([key, val]) => {
                  let display = '';
                  if (val === null || val === undefined) display = 'null';
                  else if (Array.isArray(val)) display = `Array(${val.length})`;
                  else if (typeof val === 'object') display = `{${Object.keys(val as object).slice(0, 4).join(', ')}${Object.keys(val as object).length > 4 ? '...' : ''}}`;
                  else display = String(val).slice(0, 80);
                  return (
                    <React.Fragment key={key}>
                      <span style={{ color: '#a855f7', fontFamily: "'Cascadia Code', monospace", fontWeight: 600 }}>{key}</span>
                      <span style={{ color: '#94a3b8', fontFamily: "'Cascadia Code', monospace", overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{display}</span>
                    </React.Fragment>
                  );
                })}
              </div>
            )}
            {/* Expanded: full JSON */}
            {responseExpanded && (
              <pre style={{
                background: 'rgba(5,8,20,0.7)', border: '1px solid rgba(109,120,255,0.1)',
                borderRadius: 6, padding: '8px 10px', fontSize: 9.5,
                fontFamily: "'Cascadia Code', 'Fira Code', monospace",
                color: '#94a3b8', maxHeight: 280, overflow: 'auto',
                whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0,
              }}>
                {JSON.stringify(lastResponse, null, 2)}
              </pre>
            )}
          </div>
        )}

        {/* Activity Log */}
        <div className="modal-section">
          <div className="modal-section-title">
            Activity Log ({logs.length}) {loading && <span style={{ color: '#64748b' }}> (loading...)</span>}
          </div>
          {logs.length === 0 ? (
            <div style={{ color: '#4b5563', fontSize: 12, fontStyle: 'italic' }}>No activity yet — execute an action to see results</div>
          ) : (
            <ul className="modal-log-list" style={{ maxHeight: 160, overflow: 'auto' }}>
              {logs.map((entry, i) => (
                <li key={i} className="modal-log-entry">
                  <span className="modal-log-time">{formatTime(entry.timestamp)}</span>
                  <span className={`modal-log-msg--${entry.level}`} style={{ wordBreak: 'break-all' }}>{entry.message}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Actions */}
        <div className="modal-section">
          <div className="modal-section-title">Actions</div>
          <div className="modal-actions">
            <button
              className="modal-btn modal-btn--primary"
              disabled={!canExecute}
              onClick={handleExecute}
              style={{ opacity: canExecute ? 1 : 0.4 }}
            >
              {executing ? 'Executing...' : schema?.label || 'Execute Now'}
            </button>
            <button className="modal-btn modal-btn--danger" onClick={() => onDisable(node.id)}>Disable</button>
            <button className="modal-btn modal-btn--ghost" onClick={handleClose}>Close</button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NodeModal;
