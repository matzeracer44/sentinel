/**
 * Sentinel Unified — Connector Map Static Data
 * All 98 connector nodes and inter-cluster edges.
 */

import type { ConnectorNode, ConnectorEdge } from '../../types/connectorMap';

// ---------------------------------------------------------------------------
// CLUSTER 1: FIREWALL ENGINE (Ring 1) — 23 nodes
// ---------------------------------------------------------------------------

const firewallNodes: ConnectorNode[] = [
  { id: 'fw.block-port', name: 'Block Port', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-block-port', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.block-subnet', name: 'Block Subnet', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-block-subnet', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.block-pid', name: 'Block Process', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-block-pid', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.block-ip', name: 'Block IP', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-block-ip', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.unblock-ip', name: 'Unblock IP', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-unblock-ip', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.blocked-ips', name: 'Blocked IPs', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-blocked-ips', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.rules', name: 'Firewall Rules', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-firewall-rules', status: 'online', size: 'lg', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.inventory', name: 'Full Inventory', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-firewall-inventory', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.delete-rule', name: 'Delete Rule', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-delete-firewall-rule', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.sentinel-rules', name: 'Sentinel Rules', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-sentinel-rules', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.clear-rules', name: 'Clear Rules', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-clear-sentinel-rules', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.self-test', name: 'Self Test', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-self-test', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.undo', name: 'Undo Action', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-undo-firewall', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.redo', name: 'Redo Action', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-redo-firewall', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.undo-state', name: 'Undo/Redo State', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-undo-redo-state', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.stage-rule', name: 'Stage Rule', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-stage-firewall-rule', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.pending', name: 'Pending Rules', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-pending-rules', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.commit', name: 'Commit Rule', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-commit-pending-rule', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.dismiss', name: 'Dismiss Rule', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-dismiss-pending-rule', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.watch-addr', name: 'Address Watch', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-register-address-watch', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.watch-summary', name: 'Watch Summary', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-address-watch', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.whitelist', name: 'Whitelist Threat', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'shield-whitelist-threat', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'fw.quick-block', name: 'Quick Block', cluster: 'firewall', ring: 1, source: 'sentinel', ipcChannel: 'sentinel-quick-block-subnet', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
];

// ---------------------------------------------------------------------------
// CLUSTER 2: THREAT INTELLIGENCE (Ring 2) — 24 nodes
// ---------------------------------------------------------------------------

const intelNodes: ConnectorNode[] = [
  { id: 'intel.query', name: 'Query Intel', cluster: 'intel', ring: 2, source: 'sentinel', ipcChannel: 'guardian-get-threat-intel', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.refresh', name: 'Refresh Intel', cluster: 'intel', ring: 2, source: 'sentinel', ipcChannel: 'guardian-refresh-threat-intel', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.stories', name: 'Threat Stories', cluster: 'intel', ring: 2, source: 'sentinel', ipcChannel: 'shield-get-guardian-stories', status: 'online', size: 'lg', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.log-event', name: 'Log Event', cluster: 'intel', ring: 2, source: 'sentinel', ipcChannel: 'shield-log-guardian-event', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.events', name: 'Threat Events', cluster: 'intel', ring: 2, source: 'sentinel', ipcChannel: 'shield-get-threat-events', status: 'online', size: 'lg', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.url-scan', name: 'URL Deep Scan', cluster: 'intel', ring: 2, source: 'argus', restEndpoint: 'POST /api/scan', ipcChannel: 'intel-url-scan', status: 'offline', size: 'lg', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.batch-scan', name: 'Batch URL Scan', cluster: 'intel', ring: 2, source: 'argus', restEndpoint: 'POST /api/batch_scan', ipcChannel: 'intel-batch-scan', status: 'offline', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.scan-history', name: 'Scan History', cluster: 'intel', ring: 2, source: 'argus', restEndpoint: 'GET /api/history', ipcChannel: 'intel-scan-history', status: 'offline', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.export-history', name: 'Export History', cluster: 'intel', ring: 2, source: 'argus', restEndpoint: 'GET /api/history/export', ipcChannel: 'intel-export-history', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.clear-history', name: 'Clear History', cluster: 'intel', ring: 2, source: 'argus', restEndpoint: 'POST /api/history/clear', ipcChannel: 'intel-clear-history', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.virustotal', name: 'VirusTotal', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'lg', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.abuseipdb', name: 'AbuseIPDB', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.alienvault', name: 'AlienVault OTX', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.ipinfo', name: 'IPinfo Geo', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.dns', name: 'DNS Intel', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.whois', name: 'WHOIS Lookup', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.http', name: 'HTTP Analysis', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.ssl', name: 'SSL/TLS Cert', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.geoip', name: 'GeoIP Resolve', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.ip-whois', name: 'IP WHOIS', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.reverse-dns', name: 'Reverse DNS', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.redirects', name: 'Redirect Chain', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.content', name: 'Content Analysis', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'intel.domain', name: 'Domain Analysis', cluster: 'intel', ring: 2, source: 'argus', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
];

// ---------------------------------------------------------------------------
// CLUSTER 3: AUTOMATION ENGINE (Ring 2) — 11 nodes
// ---------------------------------------------------------------------------

const automationNodes: ConnectorNode[] = [
  { id: 'auto.playbook-list', name: 'List Playbooks', cluster: 'automation', ring: 2, source: 'sentinel', ipcChannel: 'guardian-list-playbooks', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'auto.playbook-save', name: 'Save Playbook', cluster: 'automation', ring: 2, source: 'sentinel', ipcChannel: 'guardian-save-playbook', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'auto.playbook-delete', name: 'Delete Playbook', cluster: 'automation', ring: 2, source: 'sentinel', ipcChannel: 'guardian-delete-playbook', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'auto.playbook-run', name: 'Run Playbook', cluster: 'automation', ring: 2, source: 'sentinel', ipcChannel: 'guardian-run-playbook', status: 'online', size: 'lg', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'auto.playbook-history', name: 'Playbook Runs', cluster: 'automation', ring: 2, source: 'sentinel', ipcChannel: 'guardian-get-playbook-runs', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'auto.anomaly-config', name: 'Anomaly Config', cluster: 'automation', ring: 2, source: 'sentinel', ipcChannel: 'guardian-get-anomaly-config', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'auto.anomaly-update', name: 'Update Anomaly', cluster: 'automation', ring: 2, source: 'sentinel', ipcChannel: 'guardian-update-anomaly-config', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'auto.policy-list', name: 'Policy Suggestions', cluster: 'automation', ring: 2, source: 'sentinel', ipcChannel: 'shield-get-policy-suggestions', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'auto.policy-accept', name: 'Accept Policy', cluster: 'automation', ring: 2, source: 'sentinel', ipcChannel: 'shield-accept-policy-suggestion', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'auto.policy-dismiss', name: 'Dismiss Policy', cluster: 'automation', ring: 2, source: 'sentinel', ipcChannel: 'shield-dismiss-policy-suggestion', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'auto.autonomous-mode', name: 'Autonomous Mode', cluster: 'automation', ring: 2, source: 'sentinel', ipcChannel: 'sentinel-set-autonomous-mode', status: 'online', size: 'lg', lastResponseMs: -1, errorCount24h: 0 },
];

// ---------------------------------------------------------------------------
// CLUSTER 4: NETWORK MONITOR (Ring 1) — 11 nodes
// ---------------------------------------------------------------------------

const networkNodes: ConnectorNode[] = [
  { id: 'net.traffic', name: 'Live Traffic', cluster: 'network', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-network-traffic', status: 'online', size: 'lg', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'net.audit', name: 'Full Audit', cluster: 'network', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-full-network-audit', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'net.diagnostics', name: 'Diagnostics', cluster: 'network', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-network-diagnostics', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'net.ip-meta', name: 'IP Metadata', cluster: 'network', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-ip-metadata', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'net.tls-inspect', name: 'TLS Inspect', cluster: 'network', ring: 1, source: 'sentinel', ipcChannel: 'shield-inspect-tls', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'net.internet-test', name: 'Internet Check', cluster: 'network', ring: 1, source: 'sentinel', ipcChannel: 'shield-test-internet', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'net.processes', name: 'Process List', cluster: 'network', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-processes', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'net.kill-process', name: 'Kill Process', cluster: 'network', ring: 1, source: 'sentinel', ipcChannel: 'shield-kill-process', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'net.sandbox-status', name: 'Sandbox Status', cluster: 'network', ring: 1, source: 'argus', restEndpoint: 'GET /api/sandbox', ipcChannel: 'net-sandbox-status', status: 'offline', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'net.sandbox-toggle', name: 'Sandbox Toggle', cluster: 'network', ring: 1, source: 'argus', restEndpoint: 'POST /api/sandbox', ipcChannel: 'net-sandbox-toggle', status: 'offline', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'net.safety-guard', name: 'URL Safety Guard', cluster: 'network', ring: 1, source: 'argus', status: 'offline', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
];

// ---------------------------------------------------------------------------
// CLUSTER 5: DNS & HOSTS (Ring 3) — 4 nodes
// ---------------------------------------------------------------------------

const dnsNodes: ConnectorNode[] = [
  { id: 'dns.current', name: 'Current DNS', cluster: 'dns', ring: 3, source: 'sentinel', ipcChannel: 'ghost-get-current-dns', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'dns.set', name: 'Set DNS', cluster: 'dns', ring: 3, source: 'sentinel', ipcChannel: 'ghost-set-dns', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'dns.hosts-read', name: 'Read Hosts', cluster: 'dns', ring: 3, source: 'sentinel', ipcChannel: 'ghost-get-hosts-file', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'dns.hosts-write', name: 'Write Hosts', cluster: 'dns', ring: 3, source: 'sentinel', ipcChannel: 'ghost-save-hosts-file', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
];

// ---------------------------------------------------------------------------
// CLUSTER 6: SYSTEM & PERFORMANCE (Ring 1) — 11 nodes
// ---------------------------------------------------------------------------

const systemNodes: ConnectorNode[] = [
  { id: 'sys.realdata', name: 'System Data', cluster: 'system', ring: 1, source: 'sentinel', ipcChannel: 'get-real-system-data', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'sys.health', name: 'Health Score', cluster: 'system', ring: 1, source: 'sentinel', ipcChannel: 'get-system-health', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'sys.stats', name: 'System Stats', cluster: 'system', ring: 1, source: 'sentinel', ipcChannel: 'get-system-stats', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'sys.health-report', name: 'Health Report', cluster: 'system', ring: 1, source: 'sentinel', ipcChannel: 'sentinel-get-health-report', status: 'online', size: 'lg', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'sys.admin-check', name: 'Admin Rights', cluster: 'system', ring: 1, source: 'sentinel', ipcChannel: 'check-admin-rights', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'sys.ram', name: 'RAM Stats', cluster: 'system', ring: 1, source: 'sentinel', ipcChannel: 'forge-get-ram-stats', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'sys.cache-clear', name: 'Clear Cache', cluster: 'system', ring: 1, source: 'sentinel', ipcChannel: 'forge-clear-standby-cache', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'sys.startup', name: 'Startup Items', cluster: 'system', ring: 1, source: 'sentinel', ipcChannel: 'forge-get-startup-items', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'sys.services', name: 'Win Services', cluster: 'system', ring: 1, source: 'sentinel', ipcChannel: 'forge-get-windows-services', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'sys.security-overview', name: 'Security Overview', cluster: 'system', ring: 1, source: 'sentinel', ipcChannel: 'shield-get-security-overview', status: 'online', size: 'lg', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'sys.quick-action', name: 'Quick Action', cluster: 'system', ring: 1, source: 'sentinel', ipcChannel: 'execute-quick-action', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
];

// ---------------------------------------------------------------------------
// CLUSTER 7: VAULT & CONFIG (Ring 3) — 14 nodes
// ---------------------------------------------------------------------------

const vaultNodes: ConnectorNode[] = [
  { id: 'vault.notes-get', name: 'Get Secure Notes', cluster: 'vault', ring: 3, source: 'sentinel', ipcChannel: 'vault-get-secure-notes', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.notes-save', name: 'Save Secure Note', cluster: 'vault', ring: 3, source: 'sentinel', ipcChannel: 'vault-save-secure-note', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.files', name: 'Encrypted Files', cluster: 'vault', ring: 3, source: 'sentinel', ipcChannel: 'vault-get-encrypted-files', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.encrypt', name: 'Encrypt Data', cluster: 'vault', ring: 3, source: 'argus', restEndpoint: 'POST /api/encrypt', ipcChannel: 'vault-encrypt', status: 'offline', size: 'lg', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.decrypt', name: 'Decrypt Data', cluster: 'vault', ring: 3, source: 'argus', restEndpoint: 'POST /api/decrypt', ipcChannel: 'vault-decrypt', status: 'offline', size: 'lg', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.config-get', name: 'Get Config', cluster: 'vault', ring: 3, source: 'sentinel', ipcChannel: 'sentinel-get-config', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.whitelist-add', name: 'Add Whitelist', cluster: 'vault', ring: 3, source: 'sentinel', ipcChannel: 'sentinel-add-whitelist', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.whitelist-remove', name: 'Remove Whitelist', cluster: 'vault', ring: 3, source: 'sentinel', ipcChannel: 'sentinel-remove-whitelist', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.whitelist-set', name: 'Set Whitelist', cluster: 'vault', ring: 3, source: 'sentinel', ipcChannel: 'sentinel-set-whitelist', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.settings-get', name: 'Get Settings', cluster: 'vault', ring: 3, source: 'sentinel', ipcChannel: 'get-settings', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.settings-save', name: 'Save Settings', cluster: 'vault', ring: 3, source: 'sentinel', ipcChannel: 'save-settings', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.activity-log', name: 'Activity Log', cluster: 'vault', ring: 3, source: 'sentinel', ipcChannel: 'get-activity-log', status: 'online', size: 'md', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.activity-clear', name: 'Clear Log', cluster: 'vault', ring: 3, source: 'sentinel', ipcChannel: 'clear-activity-log', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
  { id: 'vault.manual-block-log', name: 'Log Manual Block', cluster: 'vault', ring: 3, source: 'sentinel', ipcChannel: 'sentinel-log-manual-block', status: 'online', size: 'sm', lastResponseMs: -1, errorCount24h: 0 },
];

// ---------------------------------------------------------------------------
// SENTINEL CORE (Ring 0) — 1 node
// ---------------------------------------------------------------------------

const coreNode: ConnectorNode = {
  id: 'core.sentinel',
  name: 'SENTINEL',
  cluster: 'core',
  ring: 0,
  source: 'sentinel',
  status: 'online',
  size: 'lg',
  lastResponseMs: -1,
  errorCount24h: 0,
};

// ---------------------------------------------------------------------------
// ALL NODES (exported)
// ---------------------------------------------------------------------------

export const ALL_NODES: ConnectorNode[] = [
  coreNode,
  ...firewallNodes,
  ...intelNodes,
  ...automationNodes,
  ...networkNodes,
  ...dnsNodes,
  ...systemNodes,
  ...vaultNodes,
];

// ---------------------------------------------------------------------------
// EDGES — Inter-cluster data flows and dependencies
// ---------------------------------------------------------------------------

export const ALL_EDGES: ConnectorEdge[] = [
  // --- Heartbeat: Every cluster → Core ---
  { source: 'fw.rules', target: 'core.sentinel', type: 'heartbeat', animated: false },
  { source: 'intel.events', target: 'core.sentinel', type: 'heartbeat', animated: false },
  { source: 'auto.playbook-run', target: 'core.sentinel', type: 'heartbeat', animated: false },
  { source: 'net.traffic', target: 'core.sentinel', type: 'heartbeat', animated: false },
  { source: 'dns.current', target: 'core.sentinel', type: 'heartbeat', animated: false },
  { source: 'sys.health-report', target: 'core.sentinel', type: 'heartbeat', animated: false },
  { source: 'vault.config-get', target: 'core.sentinel', type: 'heartbeat', animated: false },

  // --- ARGUS Intel aggregation flow ---
  { source: 'intel.virustotal', target: 'intel.url-scan', type: 'data-flow', animated: true, color: '#00f0ff', label: 'VT scan data' },
  { source: 'intel.abuseipdb', target: 'intel.url-scan', type: 'data-flow', animated: true, color: '#00f0ff', label: 'AbuseIPDB data' },
  { source: 'intel.alienvault', target: 'intel.url-scan', type: 'data-flow', animated: true, color: '#00f0ff', label: 'OTX pulse data' },
  { source: 'intel.ipinfo', target: 'intel.url-scan', type: 'data-flow', animated: true, color: '#00f0ff', label: 'Geo enrichment' },

  // --- ARGUS sub-modules feed into URL scan ---
  { source: 'intel.dns', target: 'intel.url-scan', type: 'dependency', animated: false, label: 'DNS records' },
  { source: 'intel.whois', target: 'intel.url-scan', type: 'dependency', animated: false, label: 'WHOIS data' },
  { source: 'intel.http', target: 'intel.url-scan', type: 'dependency', animated: false, label: 'HTTP headers' },
  { source: 'intel.ssl', target: 'intel.url-scan', type: 'dependency', animated: false, label: 'TLS cert info' },
  { source: 'intel.geoip', target: 'intel.url-scan', type: 'dependency', animated: false, label: 'GeoIP location' },
  { source: 'intel.ip-whois', target: 'intel.url-scan', type: 'dependency', animated: false, label: 'IP ownership' },
  { source: 'intel.reverse-dns', target: 'intel.url-scan', type: 'dependency', animated: false, label: 'PTR records' },
  { source: 'intel.redirects', target: 'intel.url-scan', type: 'dependency', animated: false, label: 'Redirect chain' },
  { source: 'intel.content', target: 'intel.url-scan', type: 'dependency', animated: false, label: 'Content scan' },
  { source: 'intel.domain', target: 'intel.url-scan', type: 'dependency', animated: false, label: 'Domain risk' },

  // --- URL scan → Safety Guard validation ---
  { source: 'intel.url-scan', target: 'net.safety-guard', type: 'data-flow', animated: true, color: '#00f0ff', label: 'Pre-fetch validation' },

  // --- Playbook triggers firewall actions ---
  { source: 'auto.playbook-run', target: 'fw.stage-rule', type: 'trigger', animated: true, color: '#a855f7', label: 'Auto-stage rule' },
  { source: 'auto.playbook-run', target: 'fw.block-subnet', type: 'trigger', animated: true, color: '#a855f7', label: 'Auto-block subnet' },

  // --- Events feed anomaly detection ---
  { source: 'intel.events', target: 'auto.anomaly-config', type: 'data-flow', animated: true, color: '#a855f7', label: 'Event stream' },

  // --- Encryption backend for vault ---
  { source: 'vault.encrypt', target: 'vault.notes-save', type: 'dependency', animated: false, color: '#f472b6', label: 'Encrypt payload' },
  { source: 'vault.decrypt', target: 'vault.notes-get', type: 'dependency', animated: false, color: '#f472b6', label: 'Decrypt payload' },
  { source: 'vault.encrypt', target: 'vault.files', type: 'dependency', animated: false, color: '#f472b6', label: 'File encryption' },

  // --- Live traffic → domain/geo analysis ---
  { source: 'net.traffic', target: 'intel.domain', type: 'data-flow', animated: true, color: '#00ff88', label: 'Live domain check' },
  { source: 'net.traffic', target: 'intel.geoip', type: 'data-flow', animated: true, color: '#00ff88', label: 'Live geo resolve' },

  // --- Network → Firewall feedback loop ---
  { source: 'net.traffic', target: 'fw.watch-summary', type: 'data-flow', animated: true, color: '#00ff88', label: 'Watch hits' },

  // --- Security events → Threat timeline ---
  { source: 'fw.block-ip', target: 'intel.events', type: 'data-flow', animated: true, color: '#ff3366', label: 'Block event' },
  { source: 'fw.block-subnet', target: 'intel.events', type: 'data-flow', animated: true, color: '#ff3366', label: 'Block event' },
  { source: 'fw.block-port', target: 'intel.events', type: 'data-flow', animated: true, color: '#ff3366', label: 'Block event' },

  // --- System health feeds core ---
  { source: 'sys.health-report', target: 'sys.health', type: 'dependency', animated: false, label: 'Health data' },
  { source: 'sys.ram', target: 'sys.stats', type: 'dependency', animated: false, label: 'RAM metrics' },

  // --- Sandbox status visible in network cluster ---
  { source: 'net.sandbox-status', target: 'net.safety-guard', type: 'dependency', animated: false, label: 'Sandbox mode' },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function getNodeById(id: string): ConnectorNode | undefined {
  return ALL_NODES.find((n) => n.id === id);
}

export function getNodesByCluster(cluster: ClusterType): ConnectorNode[] {
  return ALL_NODES.filter((n) => n.cluster === cluster);
}

export function getNodesByRing(ring: RingIndex): ConnectorNode[] {
  return ALL_NODES.filter((n) => n.ring === ring);
}

export function getEdgesForNode(nodeId: string): ConnectorEdge[] {
  return ALL_EDGES.filter((e) => e.source === nodeId || e.target === nodeId);
}

// Re-export types used by helpers
import type { ClusterType, RingIndex } from '../../types/connectorMap';
