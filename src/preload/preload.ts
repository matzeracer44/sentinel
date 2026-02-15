import { contextBridge, ipcRenderer } from 'electron';
import type {
  ShieldBlockPortRequest,
  ShieldBlockSubnetRequest,
  ShieldBlockPidRequest,
  ShieldManualBlockLogRequest,
  ShieldStageFirewallRuleRequest,
  GuardianGetThreatIntelRequest,
  GuardianGetThreatIntelResponse,
  GuardianRefreshThreatIntelRequest,
  GuardianRefreshThreatIntelResponse,
  GuardianGetAnomalyConfigResponse,
  GuardianUpdateAnomalyConfigRequest,
  GuardianAnomalyConfig,
  GuardianPlaybook,
  GuardianPlaybookRun,
  GuardianStory,
  GuardianRunPlaybookResponse,
  GuardianEvent,
  PolicySuggestion,
} from '../shared/ipcSchemas';

type ThreatWhitelistPayload = {
  ip?: string;
  subnet?: string;
  processName?: string;
  pid?: number;
  reason?: string;
};

console.log(' [Preload] Preload script starting...');

// Listen for DevTools state notifications from main and expose it to renderer
ipcRenderer.on('devtools-state', (_event: any, isOpen: boolean) => {
  (window as any).__SENTINEL_DEVTOOLS_OPEN__ = isOpen;
  window.dispatchEvent(new CustomEvent('sentinel-devtools', { detail: isOpen }));
});

// Handle errors in the preload script
process.on('uncaughtException', (error) => {
  console.error(' [PRELOAD] Uncaught exception in preload:', error);
});

process.on('unhandledRejection', (reason) => {
  console.error(' [PRELOAD] Unhandled rejection in preload:', reason);
});

// Dialog helpers
const showError = (title: string, message: string) =>
  ipcRenderer.invoke('show-error-box', title, message);

const showSuccess = (title: string, message: string) =>
  ipcRenderer.invoke('show-message-box', title, message);

const confirm = (title: string, message: string): Promise<boolean> =>
  ipcRenderer.invoke('show-confirm-box', title, message);

// Expose protected methods that allow the renderer process to use ipcRenderer
export type ShieldGuardianThreatIntelResponse =
  | ({ success: true } & GuardianGetThreatIntelResponse)
  | { success: false; error: string };

export type ShieldGuardianThreatIntelRefreshResponse =
  | ({ success: true } & GuardianRefreshThreatIntelResponse)
  | { success: false; error: string };

export type ShieldGuardianAnomalyConfigResponse =
  | { success: true; config: GuardianAnomalyConfig }
  | { success: false; error?: string };

const electronAPI = {
  // System Health
  getSystemHealth: () => ipcRenderer.invoke('get-system-health'),

  // System Stats
  getSystemStats: () => ipcRenderer.invoke('get-system-stats'),

  // DevTools toggle
  toggleDevTools: () => ipcRenderer.invoke('toggle-devtools'),

  // Activity Log
  getActivityLog: () => ipcRenderer.invoke('get-activity-log'),
  clearActivityLog: () => ipcRenderer.invoke('clear-activity-log'),

  // Quick Actions
  executeQuickAction: (action: string) => ipcRenderer.invoke('execute-quick-action', action),

  // Real System Data
  getRealSystemData: () => ipcRenderer.invoke('get-real-system-data'),

  // Settings
  saveSettings: (key: string, value: any) => ipcRenderer.invoke('save-settings', key, value),
  getSettings: () => ipcRenderer.invoke('get-settings'),

    // Shield Module APIs
  shield: {
    // Process Management
    getProcesses: () => ipcRenderer.invoke('shield-get-processes'),
    killProcess: (pid: number, processName: string) => 
      ipcRenderer.invoke('shield-kill-process', pid, processName),

    // IP Blocking
    getBlockedIPs: () => ipcRenderer.invoke('shield-get-blocked-ips'),
    blockIP: (ip: string, reason: string) => 
      ipcRenderer.invoke('shield-block-ip', ip, reason),
    unblockIP: (ip: string) => 
      ipcRenderer.invoke('shield-unblock-ip', ip),

    // Firewall Rules
    getFirewallRules: () => ipcRenderer.invoke('shield-get-firewall-rules'),
    getFirewallInventory: () => ipcRenderer.invoke('shield-get-firewall-inventory'),
    exportFirewallRules: (options: { format: 'txt' | 'csv' | 'json'; filter?: string; includeDisabled?: boolean }) =>
      ipcRenderer.invoke('firewall-export', options),
    deleteFirewallRule: (ruleName: string) => ipcRenderer.invoke('shield-delete-firewall-rule', ruleName),
    enableFirewallRule: (ruleName: string, enable: boolean) => ipcRenderer.invoke('shield-enable-firewall-rule', ruleName, enable),
    updateFirewallRule: (ruleName: string, options: any) => ipcRenderer.invoke('shield-update-firewall-rule', ruleName, options),
    addFirewallRule: (ruleName: string, protocol: string, port: number, action: 'Allow'|'Block') => ipcRenderer.invoke('shield-add-firewall-rule', ruleName, protocol, port, action),
    undoFirewall: () => ipcRenderer.invoke('shield-undo-firewall'),
    redoFirewall: () => ipcRenderer.invoke('shield-redo-firewall'),
    getUndoRedoState: () => ipcRenderer.invoke('shield-get-undo-redo-state'),

    // NEW: Bulk blocking methods
    blockIPSubnet: (ip: string, subnetMask: number) =>
      ipcRenderer.invoke('shield-block-ip-subnet', ip, subnetMask),
    unblockSubnet: (subnet: string) =>
      ipcRenderer.invoke('shield-unblock-subnet', subnet),
    blockSubnet: (payload: ShieldBlockSubnetRequest) =>
      ipcRenderer.invoke('shield-block-subnet', payload),
    blockIPRange: (startIP: string, endIP: string, ruleName: string, direction?: 'in' | 'out' | 'both') => 
      ipcRenderer.invoke('shield-block-ip-range', startIP, endIP, ruleName, direction),
    blockDangerousSubnets: () => 
      ipcRenderer.invoke('shield-block-dangerous-subnets'),

    // Port Scanning
    scanPorts: () => ipcRenderer.invoke('shield-scan-ports'),

    // Security Overview
    getSecurityOverview: () => ipcRenderer.invoke('shield-get-security-overview'),

    // IP Metadata Lookup
    getIpMetadata: (ip: string) => ipcRenderer.invoke('shield-get-ip-metadata', ip),
    getIPMetadataStats: () => ipcRenderer.invoke('shield-get-ip-metadata-stats'),

    // Network Traffic
    getNetworkTraffic: (limit?: number) => ipcRenderer.invoke('shield-get-network-traffic', limit),
    getNetworkDiagnostics: () => ipcRenderer.invoke('shield-get-network-diagnostics'),
    inspectTls: (host: string) => ipcRenderer.invoke('shield-inspect-tls', host),
    registerAddressWatch: (ip: string) => ipcRenderer.invoke('shield-register-address-watch', ip),
    getAddressWatch: () => ipcRenderer.invoke('shield-get-address-watch'),
    getThreatEvents: (options?: { limit?: number; pid?: number }) =>
      ipcRenderer.invoke('shield-get-threat-events', options),
    getGuardianStories: (options?: {
      cursor?: string;
      limit?: number;
      pid?: number;
      processName?: string;
      remoteIP?: string;
      module?: string;
    }) => ipcRenderer.invoke('shield-get-guardian-stories', options),
    logGuardianEvent: (payload: any) => ipcRenderer.invoke('shield-log-guardian-event', payload),
    listGuardianPlaybooks: () => ipcRenderer.invoke('guardian-list-playbooks'),
    saveGuardianPlaybook: (payload: any) => ipcRenderer.invoke('guardian-save-playbook', payload),
    deleteGuardianPlaybook: (id: string) => ipcRenderer.invoke('guardian-delete-playbook', { id }),
    runGuardianPlaybook: (payload: any) => ipcRenderer.invoke('guardian-run-playbook', payload),
    getGuardianPlaybookRuns: (limit?: number) =>
      ipcRenderer.invoke('guardian-get-playbook-runs', { limit }),
    getGuardianThreatIntel: (payload?: GuardianGetThreatIntelRequest) =>
      ipcRenderer.invoke('guardian-get-threat-intel', payload),
    refreshGuardianThreatIntel: (payload: GuardianRefreshThreatIntelRequest) =>
      ipcRenderer.invoke('guardian-refresh-threat-intel', payload),
    getGuardianAnomalyConfig: () => ipcRenderer.invoke('guardian-get-anomaly-config'),
    updateGuardianAnomalyConfig: (payload: GuardianUpdateAnomalyConfigRequest) =>
      ipcRenderer.invoke('guardian-update-anomaly-config', payload),
    stageFirewallRule: (payload: any) => ipcRenderer.invoke('shield-stage-firewall-rule', payload),
    getPendingRules: () => ipcRenderer.invoke('shield-get-pending-rules'),
    commitPendingRule: (pendingRuleId: string) =>
      ipcRenderer.invoke('shield-commit-pending-rule', { pendingRuleId }),
    dismissPendingRule: (pendingRuleId: string) =>
      ipcRenderer.invoke('shield-dismiss-pending-rule', { pendingRuleId }),
    getPolicySuggestions: (options?: any) => ipcRenderer.invoke('shield-get-policy-suggestions', options),
    acceptPolicySuggestion: (policyId: string) =>
      ipcRenderer.invoke('shield-accept-policy-suggestion', { policyId }),
    dismissPolicySuggestion: (policyId: string) =>
      ipcRenderer.invoke('shield-dismiss-policy-suggestion', { policyId }),
    onPendingRuleUpdate: (callback: (payload: any) => void) => {
      const wrapped = (_event: Electron.IpcRendererEvent, payload: any) => callback(payload);
      ipcRenderer.on('shield-pending-rule-update', wrapped);
      return () => ipcRenderer.removeListener('shield-pending-rule-update', wrapped);
    },
    quickBlockSubnet: (subnet: string, reason?: string) =>
      ipcRenderer.invoke('sentinel-quick-block-subnet', subnet, reason),
    whitelistThreat: (payload: ThreatWhitelistPayload) =>
      ipcRenderer.invoke('shield-whitelist-threat', payload),
    logManualBlock: (payload: ShieldManualBlockLogRequest) => ipcRenderer.invoke('sentinel-log-manual-block', payload),

    // Port Blocking
    blockPort: (payload: ShieldBlockPortRequest) =>
      ipcRenderer.invoke('shield-block-port', payload),
    unblockPort: (port: number, protocol?: 'TCP' | 'UDP' | 'Any') =>
      ipcRenderer.invoke('shield-unblock-port', port, protocol),
    blockPid: (payload: ShieldBlockPidRequest) =>
      ipcRenderer.invoke('shield-block-pid', payload),

    // Sentinel Rules
    getSentinelRules: () => ipcRenderer.invoke('shield-get-sentinel-rules'),
    clearSentinelRules: () => ipcRenderer.invoke('shield-clear-sentinel-rules'),
    selfTest: () => ipcRenderer.invoke('shield-self-test'),

    // Deep System Scans (101 checks across 5 modules)
    setScanLanguage: (lang: string) => ipcRenderer.invoke('sentinel-set-scan-language', lang),
    fullScan: () => ipcRenderer.invoke('sentinel-full-scan'),
    kernelScan: () => ipcRenderer.invoke('sentinel-kernel-scan'),
    edrScan: () => ipcRenderer.invoke('sentinel-edr-scan'),
    networkScan: () => ipcRenderer.invoke('sentinel-network-scan'),
    performanceScan: () => ipcRenderer.invoke('sentinel-performance-scan'),
    privacyScan: () => ipcRenderer.invoke('sentinel-privacy-scan'),
    applyScanFix: (checkId: string) => ipcRenderer.invoke('scan-apply-fix', checkId),
    getFixImpact: (checkId: string) => ipcRenderer.invoke('scan-get-fix-impact', checkId),
    undoFix: (checkId: string) => ipcRenderer.invoke('scan-undo-fix', checkId),
    getUndos: () => ipcRenderer.invoke('scan-get-undos'),

    // Scan Result Persistence
    saveScanResult: (scanType: string, data: unknown) => ipcRenderer.invoke('scan-save-result', scanType, data),
    loadScanResult: (scanType: string) => ipcRenderer.invoke('scan-load-result', scanType),
    loadAllScanResults: () => ipcRenderer.invoke('scan-load-all-results'),
    clearScanResult: (scanType: string) => ipcRenderer.invoke('scan-clear-result', scanType),

    // Phase 4 — New Feature Scans
    vpnGetStatus: () => ipcRenderer.invoke('sentinel-vpn-get-status'),
    hardeningAudit: () => ipcRenderer.invoke('sentinel-hardening-run-audit'),
    portScanLocal: () => ipcRenderer.invoke('sentinel-ports-scan-local'),
    wifiAudit: () => ipcRenderer.invoke('sentinel-wifi-audit'),
    usbGetDevices: () => ipcRenderer.invoke('sentinel-usb-get-devices'),
    hardwareReport: () => ipcRenderer.invoke('sentinel-hardware-report'),
    eventLogAnalyze: () => ipcRenderer.invoke('sentinel-event-log-analyze'),
    generateReport: (scanModules?: any) => ipcRenderer.invoke('sentinel-generate-report', scanModules),
    generateReportHTML: (scanModules?: any) => ipcRenderer.invoke('sentinel-generate-report-html', scanModules),
    exportReportFile: (scanModules?: any) => ipcRenderer.invoke('sentinel-export-report-file', scanModules),

    // Auto-start with Windows
    getAutostart: () => ipcRenderer.invoke('sentinel-get-autostart'),
    setAutostart: (enabled: boolean) => ipcRenderer.invoke('sentinel-set-autostart', enabled),

    // File Integrity Monitor
    fimGetChanges: () => ipcRenderer.invoke('sentinel-fim-get-changes'),
    fimGetBaseline: () => ipcRenderer.invoke('sentinel-fim-get-baseline'),
    fimRunCheck: () => ipcRenderer.invoke('sentinel-fim-run-check'),
    fimResetBaseline: () => ipcRenderer.invoke('sentinel-fim-reset-baseline'),
    fimGetConfig: () => ipcRenderer.invoke('sentinel-fim-get-config'),
    fimSetConfig: (update: any) => ipcRenderer.invoke('sentinel-fim-set-config', update),
  },

  // Sentinel Config APIs
  sentinelConfig: {
    getConfig: () => ipcRenderer.invoke('sentinel-get-config'),
    setAutonomousMode: (enabled: boolean) =>
      ipcRenderer.invoke('sentinel-set-autonomous-mode', enabled),
    addWhitelist: (ip: string) => ipcRenderer.invoke('sentinel-add-whitelist', ip),
    removeWhitelist: (ip: string) => ipcRenderer.invoke('sentinel-remove-whitelist', ip),
    setWhitelist: (ips: string[]) => ipcRenderer.invoke('sentinel-set-whitelist', ips),
    exportConfig: () => ipcRenderer.invoke('sentinel-config-export'),
    importConfig: () => ipcRenderer.invoke('sentinel-config-import'),
  },

  // Performance Profile APIs (auto-detect hardware, adaptive settings)
  performance: {
    getProfile: () => ipcRenderer.invoke('perf-get-profile'),
    setMode: (mode: string, customOverrides?: Record<string, number>) =>
      ipcRenderer.invoke('perf-set-mode', mode, customOverrides),
    refreshHardware: () => ipcRenderer.invoke('perf-refresh-hardware'),
  },

  // Ghost Privacy Module APIs
  ghost: {
    getTelemetryServices: () => ipcRenderer.invoke('ghost-get-telemetry-services'),
    getBlockedRequestsCount: () => ipcRenderer.invoke('ghost-get-blocked-requests-count'),
    toggleTelemetryService: (serviceName: string, enable: boolean) => ipcRenderer.invoke('ghost-toggle-telemetry-service', serviceName, enable),
    toggleAllTelemetry: (enableAll: boolean) => ipcRenderer.invoke('ghost-toggle-all-telemetry', enableAll),
    getAppPermissions: () => ipcRenderer.invoke('ghost-get-app-permissions'),
    toggleAppPermission: (packageName: string, permission: string, enable: boolean) => ipcRenderer.invoke('ghost-toggle-app-permission', packageName, permission, enable),
    getHostsFile: () => ipcRenderer.invoke('ghost-get-hosts-file'),
    saveHostsFile: (content: string) => ipcRenderer.invoke('ghost-save-hosts-file', content),
    importHostsBlocklist: (url: string) => ipcRenderer.invoke('ghost-import-hosts-blocklist', url),
    getCurrentDNS: () => ipcRenderer.invoke('ghost-get-current-dns'),
    setDNS: (primary: string, secondary: string, forceVpn?: boolean) => ipcRenderer.invoke('ghost-set-dns', primary, secondary, forceVpn),
    rollbackDNS: () => ipcRenderer.invoke('ghost-rollback-dns'),
    testDNSSpeed: (dnsServer: string) => ipcRenderer.invoke('ghost-test-dns-speed', dnsServer),
  },

  // Forge Performance Module APIs
  forge: {
    // RAM Optimizer
    getRAMStats: () => ipcRenderer.invoke('forge-get-ram-stats'),
    clearStandbyCache: () => ipcRenderer.invoke('forge-clear-standby-cache'),
    emptyWorkingSets: () => ipcRenderer.invoke('forge-empty-working-sets'),
    optimizeRAM: () => ipcRenderer.invoke('forge-optimize-ram'),

    // Simplified APIs (German Windows compatible)
    getRamUsage: () => ipcRenderer.invoke('get-ram-usage'),
    getPowerPlan: () => ipcRenderer.invoke('get-power-plan'),
    setPowerPlanSimple: (plan: string) => ipcRenderer.invoke('set-power-plan', plan),
    getStartupApps: () => ipcRenderer.invoke('get-startup-apps'),
    toggleStartupApp: (program: any, enable: boolean) => ipcRenderer.invoke('toggle-startup-app', program, enable),
    getServices: () => ipcRenderer.invoke('get-services'),
    toggleService: (serviceName: string, enable: boolean) => ipcRenderer.invoke('toggle-service', serviceName, enable),
    getDiskInfo: () => ipcRenderer.invoke('get-disk-info'),
    analyzeDisk: (drive: string) => ipcRenderer.invoke('analyze-disk', drive),
    cleanDiskSimple: (items: string[]) => ipcRenderer.invoke('clean-disk', items),

    // CPU Governor
    getTopCPUProcesses: () => ipcRenderer.invoke('forge-get-top-cpu-processes'),
    getCPUCoreCount: () => ipcRenderer.invoke('forge-get-cpu-core-count'),
    setProcessPriority: (pid: number, priority: string) => ipcRenderer.invoke('forge-set-process-priority', pid, priority),
    setProcessAffinity: (pid: number, affinity: number) => ipcRenderer.invoke('forge-set-process-affinity', pid, affinity),
    getCurrentPowerPlan: () => ipcRenderer.invoke('forge-get-current-power-plan'),
    setPowerPlan: (plan: string) => ipcRenderer.invoke('forge-set-power-plan', plan),

    // Startup Manager
    getStartupItems: () => ipcRenderer.invoke('forge-get-startup-items'),
    toggleStartupItem: (name: string, enable: boolean) => ipcRenderer.invoke('forge-toggle-startup-item', name, enable),

    // Service Optimizer
    getWindowsServices: () => ipcRenderer.invoke('forge-get-windows-services'),
    controlService: (serviceName: string, action: 'start' | 'stop' | 'disable' | 'enable') => ipcRenderer.invoke('forge-control-service', serviceName, action),
    toggleWindowsService: (name: string, enable: boolean) => ipcRenderer.invoke('forge-toggle-windows-service', name, enable),
    disableAllBloatware: () => ipcRenderer.invoke('forge-disable-all-bloatware'),
    backupServicesState: () => ipcRenderer.invoke('forge-backup-services-state'),
    restoreServicesState: () => ipcRenderer.invoke('forge-restore-services-state'),

    // Disk Cleaner
    getDriveInfo: () => ipcRenderer.invoke('forge-get-drive-info'),
    analyzeDiskCleanup: () => ipcRenderer.invoke('forge-analyze-disk-cleanup'),
    cleanDisk: (selectedPaths: string[]) => ipcRenderer.invoke('forge-clean-disk', selectedPaths),
  },

  // Admin check APIs
  admin: {
    checkAdminRights: () => ipcRenderer.invoke('check-admin-rights'),
    restartAsAdmin: () => ipcRenderer.invoke('restart-as-admin'),
  },

  // Vault Encryption Module APIs
  vault: {
    // File Encryptor
    getEncryptedFiles: () => ipcRenderer.invoke('vault-get-encrypted-files'),
    encryptFiles: (filePaths: string[], password: string) => ipcRenderer.invoke('vault-encrypt-files', filePaths, password),
    decryptFile: (filePath: string, password: string) => ipcRenderer.invoke('vault-decrypt-file', filePath, password),

    // Secure Notes
    getSecureNotes: () => ipcRenderer.invoke('vault-get-secure-notes'),
    saveSecureNote: (noteData: any) => ipcRenderer.invoke('vault-save-secure-note', noteData),
    openSecureNote: (noteId: string, password: string) => ipcRenderer.invoke('vault-open-secure-note', noteId, password),
    deleteSecureNote: (noteId: string) => ipcRenderer.invoke('vault-delete-secure-note', noteId),

    // File Shredder
    getShredStats: () => ipcRenderer.invoke('vault-get-shred-stats'),
    shredFiles: (filePaths: string[]) => ipcRenderer.invoke('vault-shred-files', filePaths),

    // Password Generator
    getSavedPasswords: () => ipcRenderer.invoke('vault-get-saved-passwords'),
    savePassword: (password: string, note: string) => ipcRenderer.invoke('vault-save-password', password, note),
  },

  // Advanced Features APIs
  advanced: {
    // Network Diagnostics
    getNetworkDiagnostics: () => ipcRenderer.invoke('get-network-diagnostics'),

    // Hardware Temperatures
    getTemperatures: () => ipcRenderer.invoke('get-temperatures'),

    // Security Status
    getSecurityStatus: () => ipcRenderer.invoke('get-security-status'),
    enableFirewall: () => ipcRenderer.invoke('enable-firewall'),
    disableSMBv1: () => ipcRenderer.invoke('disable-smbv1'),
    enableDefender: () => ipcRenderer.invoke('enable-defender'),
    enableUAC: () => ipcRenderer.invoke('enable-uac'),

    // Profiler controls
    startProfiler: () => ipcRenderer.invoke('profiler-start'),
    stopProfiler: () => ipcRenderer.invoke('profiler-stop'),
    listProfiles: () => ipcRenderer.invoke('profiler-list'),
    createSnapshot: (name: string) => ipcRenderer.invoke('create-snapshot', name),
    listSnapshots: () => ipcRenderer.invoke('list-snapshots'),
    deleteSnapshot: (id: string) => ipcRenderer.invoke('delete-snapshot', id),
    getSnapshot: (id: string) => ipcRenderer.invoke('get-snapshot', id),

    // Enhanced Process Management
    getProcessesEnhanced: () => ipcRenderer.invoke('get-processes-enhanced'),
    killProcess: (pid: number) => ipcRenderer.invoke('kill-process', pid),
    getStartupPrograms: () => ipcRenderer.invoke('get-startup-programs'),
    disableStartupProgram: (name: string) => ipcRenderer.invoke('disable-startup-program', name),
  },

  // DSGVO — Datenschutz Controls (Art. 6, 17 DSGVO)
  dsgvo: {
    getIpLookupEnabled: () => ipcRenderer.invoke('dsgvo-get-ip-lookup-enabled'),
    setIpLookupEnabled: (enabled: boolean) => ipcRenderer.invoke('dsgvo-set-ip-lookup-enabled', enabled),
    clearThreatEvents: () => ipcRenderer.invoke('dsgvo-clear-threat-events'),
  },

  // Renderer management (fallback UI)
  renderer: {
    build: () => ipcRenderer.invoke('renderer-build'),
    reload: () => ipcRenderer.invoke('renderer-reload'),
    onBuildLog: (cb: (msg: string) => void) => ipcRenderer.on('renderer-build-log', (_e, msg) => cb(String(msg))),
    onBuildDone: (cb: (res: any) => void) => ipcRenderer.on('renderer-build-done', (_e, res) => cb(res)),
  },

  // ARGUS Python Backend Bridge
  argus: {
    // Threat Intelligence
    scanUrl: (url: string, deepFetch?: boolean) => ipcRenderer.invoke('intel-url-scan', deepFetch ? { url, deepFetch } : url),
    batchScan: (urls: string[], deepFetch?: boolean) => ipcRenderer.invoke('intel-batch-scan', deepFetch ? { urls, deepFetch } : urls),
    getScanHistory: (limit?: number, offset?: number) =>
      ipcRenderer.invoke('intel-scan-history', limit, offset),
    exportHistory: () => ipcRenderer.invoke('intel-export-history'),
    clearHistory: () => ipcRenderer.invoke('intel-clear-history'),

    // Sandbox
    getSandboxStatus: () => ipcRenderer.invoke('net-sandbox-status'),
    toggleSandbox: (enabled: boolean) => ipcRenderer.invoke('net-sandbox-toggle', enabled),

    // Encryption
    encryptData: (data: string) => ipcRenderer.invoke('vault-encrypt-data', data),
    decryptData: (encryptedData: string) => ipcRenderer.invoke('vault-decrypt-data', encryptedData),

    // Health & Lifecycle
    getHealth: () => ipcRenderer.invoke('argus-get-health'),
    start: () => ipcRenderer.invoke('argus-start'),
    stop: () => ipcRenderer.invoke('argus-stop'),
    restart: () => ipcRenderer.invoke('argus-restart'),
    getStatus: () => ipcRenderer.invoke('argus-status'),
    onStatusChanged: (cb: (payload: { online: boolean; status: string; pid: number | null; uptimeMs: number; lastError: string | null; timestamp: number }) => void) => {
      const wrapped = (_event: Electron.IpcRendererEvent, payload: any) => cb(payload);
      ipcRenderer.on('argus-status-changed', wrapped);
      return () => ipcRenderer.removeListener('argus-status-changed', wrapped);
    },
  },

  // VPN Awareness Layer
  vpn: {
    getStatus: () => ipcRenderer.invoke('sentinel-vpn-get-status'),
    getAdapterInfo: () => ipcRenderer.invoke('sentinel-vpn-get-adapter-info'),
  },

  // File Integrity Monitoring (FIM)
  fim: {
    getConfig: () => ipcRenderer.invoke('sentinel-fim-get-config'),
    setConfig: (update: any) => ipcRenderer.invoke('sentinel-fim-set-config', update),
    getChanges: () => ipcRenderer.invoke('sentinel-fim-get-changes'),
    getBaseline: () => ipcRenderer.invoke('sentinel-fim-get-baseline'),
    runCheck: () => ipcRenderer.invoke('sentinel-fim-run-check'),
    resetBaseline: () => ipcRenderer.invoke('sentinel-fim-reset-baseline'),
  },

  // Event Log Analyzer
  eventLog: {
    getSecurity: () => ipcRenderer.invoke('sentinel-eventlog-get-security'),
    getAlerts: () => ipcRenderer.invoke('sentinel-eventlog-get-alerts'),
  },

  // System Hardening Score
  hardening: {
    getScore: () => ipcRenderer.invoke('sentinel-hardening-get-score'),
  },

  // Port Scanner (own open ports)
  portScanner: {
    run: () => ipcRenderer.invoke('sentinel-portscan-run'),
  },

  // Incident Timeline (aggregated)
  timeline: {
    getEvents: (maxEvents?: number) => ipcRenderer.invoke('sentinel-timeline-get-events', maxEvents),
  },

  // Real-time Push Notifications (Main → Renderer)
  notifications: {
    onThreatAlert: (cb: (data: { title: string; message: string; severity: string; timestamp: number }) => void) => {
      const wrapped = (_event: Electron.IpcRendererEvent, data: any) => cb(data);
      ipcRenderer.on('sentinel-threat-alert', wrapped);
      return () => ipcRenderer.removeListener('sentinel-threat-alert', wrapped);
    },
    onScanComplete: (cb: (data: { score: number; passed: number; failed?: number; total: number; scheduled?: boolean }) => void) => {
      const wrapped = (_event: Electron.IpcRendererEvent, data: any) => cb(data);
      ipcRenderer.on('sentinel-scan-complete', wrapped);
      return () => ipcRenderer.removeListener('sentinel-scan-complete', wrapped);
    },
    onScanProgress: (cb: (data: { phase: string; elapsed: number }) => void) => {
      const wrapped = (_event: Electron.IpcRendererEvent, data: any) => cb(data);
      ipcRenderer.on('sentinel-scan-progress', wrapped);
      return () => ipcRenderer.removeListener('sentinel-scan-progress', wrapped);
    },
    onActivityLogAppended: (cb: (entry: any) => void) => {
      const wrapped = (_event: Electron.IpcRendererEvent, entry: any) => cb(entry);
      ipcRenderer.on('activity-log-appended', wrapped);
      return () => ipcRenderer.removeListener('activity-log-appended', wrapped);
    },
    onAuditEvent: (cb: (evt: { ts: number; module: string; action: string; message: string; severity: string; meta?: Record<string, unknown> }) => void) => {
      const wrapped = (_event: Electron.IpcRendererEvent, evt: any) => cb(evt);
      ipcRenderer.on('sentinel-audit-event', wrapped);
      return () => ipcRenderer.removeListener('sentinel-audit-event', wrapped);
    },
    getAuditBuffer: () => ipcRenderer.invoke('get-audit-log-buffer'),
  },

  // Platform info
  platform: process.platform,
};

// Type declarations for TypeScript
export interface ShieldAPI {
  // Guardian Threat Intel
  getGuardianThreatIntel: (payload?: GuardianGetThreatIntelRequest) => Promise<ShieldGuardianThreatIntelResponse>;
  refreshGuardianThreatIntel: (payload: GuardianRefreshThreatIntelRequest) => Promise<ShieldGuardianThreatIntelRefreshResponse>;

  // Guardian Anomaly Config
  getGuardianAnomalyConfig: () => Promise<ShieldGuardianAnomalyConfigResponse>;
  updateGuardianAnomalyConfig: (payload: GuardianUpdateAnomalyConfigRequest) => Promise<ShieldGuardianAnomalyConfigResponse>;

  // Guardian Stories
  getGuardianStories: (options?: {
    cursor?: string;
    limit?: number;
    pid?: number;
    processName?: string;
    remoteIP?: string;
    module?: string;
  }) => Promise<{ success: boolean; stories?: GuardianStory[]; nextCursor?: string | null; error?: string }>;
  logGuardianEvent: (payload: Partial<GuardianEvent>) => Promise<{ success: boolean; error?: string }>;

  // Guardian Playbooks
  listGuardianPlaybooks: () => Promise<{ success: boolean; playbooks?: GuardianPlaybook[]; error?: string }>;
  saveGuardianPlaybook: (payload: Record<string, unknown>) => Promise<{ success: boolean; playbook?: GuardianPlaybook; error?: string }>;
  deleteGuardianPlaybook: (id: string) => Promise<{ success: boolean; error?: string }>;
  runGuardianPlaybook: (payload: { id: string; context?: Partial<GuardianEvent>; dryRun?: boolean }) => Promise<{ success: boolean; actionsExecuted?: number; log?: string[]; error?: string }>;
  getGuardianPlaybookRuns: (limit?: number) => Promise<{ success: boolean; runs?: GuardianPlaybookRun[]; error?: string }>;

  // Policy Suggestions
  getPolicySuggestions: (options?: { cursor?: string; limit?: number; status?: string }) => Promise<{ success: boolean; suggestions?: PolicySuggestion[]; nextCursor?: string | null; error?: string }>;
  acceptPolicySuggestion: (policyId: string) => Promise<{ success: boolean; suggestion?: PolicySuggestion; error?: string }>;
  dismissPolicySuggestion: (policyId: string) => Promise<{ success: boolean; suggestion?: PolicySuggestion; error?: string }>;

  // Firewall Staging
  stageFirewallRule: (payload: ShieldStageFirewallRuleRequest) => Promise<{ success: boolean; pendingRuleId?: string; pendingRule?: unknown; expiresAt?: number; error?: string | { message?: string } }>;
  getPendingRules: () => Promise<{ success: boolean; pendingRules?: unknown[]; error?: string | { message?: string } }>;
  commitPendingRule: (pendingRuleId: string) => Promise<{ success: boolean; error?: string | { message?: string } }>;
  dismissPendingRule: (pendingRuleId: string) => Promise<{ success: boolean; error?: string | { message?: string } }>;

  // Threat Events
  getThreatEvents: (options?: Record<string, unknown>) => Promise<{ success: boolean; events?: unknown[]; nextCursor?: string | null; error?: string }>;

  // Network / TLS
  getNetworkTraffic: (limit?: number) => Promise<unknown>;
  getNetworkDiagnostics: () => Promise<{ success: boolean; data?: unknown; error?: string }>;
  inspectTls: (host: string) => Promise<{ success: boolean; data?: unknown; error?: string }>;
  registerAddressWatch: (ip: string) => Promise<{ success: boolean; data?: unknown; error?: string }>;
  getAddressWatch: () => Promise<{ success: boolean; data?: unknown[]; error?: string }>;
  onSessionUpdate: (callback: (sessions: unknown[]) => void) => () => void;
  flushSessionCache: () => Promise<{ success: boolean; error?: string }>;

  // Process Management
  getProcesses: () => Promise<unknown[]>;
  killProcess: (pid: number, processName: string) => Promise<{ success: boolean; message: string }>;

  // IP Blocking
  getBlockedIPs: () => Promise<unknown[]>;
  blockIP: (ip: string, reason: string) => Promise<{ success: boolean; message: string }>;
  unblockIP: (ip: string) => Promise<{ success: boolean; message: string }>;

  // Firewall Rules
  getFirewallRules: () => Promise<{ success: boolean; rules?: unknown[]; error?: string }>;
  getFirewallInventory: () => Promise<{ success: boolean; rules?: unknown[]; blockedIps?: unknown[]; meta?: Record<string, unknown>; error?: string }>;
  deleteFirewallRule: (ruleName: string) => Promise<{ success: boolean; message?: string; error?: string }>;
  enableFirewallRule: (ruleName: string, enable: boolean) => Promise<{ success: boolean; message?: string }>;
  updateFirewallRule: (ruleName: string, options: Record<string, unknown>) => Promise<{ success: boolean; message?: string }>;
  addFirewallRule: (ruleName: string, protocol: string, port: number, action: 'Allow' | 'Block') => Promise<{ success: boolean; message?: string }>;
  undoFirewall: () => Promise<{ success: boolean; message?: string }>;
  redoFirewall: () => Promise<{ success: boolean; message?: string }>;
  getUndoRedoState: () => Promise<{ canUndo: boolean; canRedo: boolean; undoCount?: number; redoCount?: number }>;

  // Bulk Blocking
  blockIPSubnet: (ip: string, subnetMask: number) => Promise<{ success: boolean; message?: string; error?: string }>;
  unblockSubnet: (subnet: string) => Promise<{ success: boolean; message?: string; error?: string }>;
  quickBlockSubnet: (subnet: string, reason?: string) => Promise<{ success: boolean; message?: string; error?: string }>;
  whitelistThreat: (payload: ThreatWhitelistPayload) => Promise<{ success: boolean; data?: unknown; error?: string }>;
  logManualBlock: (payload: ShieldManualBlockLogRequest) => Promise<{ success: boolean; message?: string; error?: string }>;
  blockIPRange: (startIP: string, endIP: string, ruleName: string, direction?: 'in' | 'out' | 'both') => Promise<{ success: boolean; message?: string; error?: string }>;
  blockDangerousSubnets: () => Promise<{ success: boolean; message: string; blocked?: number; error?: string }>;

  // Port / PID Blocking
  blockPort: (payload: ShieldBlockPortRequest) => Promise<{ success: boolean; message?: string }>;
  unblockPort: (port: number, protocol?: 'TCP' | 'UDP' | 'Any') => Promise<{ success: boolean; message?: string; results?: unknown[] }>;
  blockPid: (payload: ShieldBlockPidRequest) => Promise<{ success: boolean; message?: string; error?: string }>;

  // IP Metadata
  getIpMetadata: (ip: string) => Promise<{ success: boolean; data?: unknown; error?: string }>;
  getIPMetadataStats: () => Promise<unknown>;

  // Sentinel Rules
  getSentinelRules: () => Promise<{ success: boolean; rules: string[] }>;
  clearSentinelRules: () => Promise<{ success: boolean; message?: string }>;
  selfTest: () => Promise<{ success: boolean; message?: string; details?: unknown }>;

  // Pending Rule Updates
  onPendingRuleUpdate: (callback: (payload: unknown) => void) => () => void;

  // Security Overview
  getSecurityOverview: () => Promise<unknown>;
  scanPorts: () => Promise<unknown>;

  // Sentinel Deep System Scans (101 checks across 5 modules)
  fullScan: () => Promise<{ success: boolean; score: number; total: number; passed: number; failed: number; warnings: number; modules: Record<string, { checks: any[]; passed: number; total: number; score: number }>; error?: string }>;
  kernelScan: () => Promise<{ success: boolean; module: string; checks: any[]; passed: number; total: number; score: number; error?: string }>;
  edrScan: () => Promise<{ success: boolean; module: string; checks: any[]; passed: number; total: number; score: number; error?: string }>;
  networkScan: () => Promise<{ success: boolean; module: string; checks: any[]; passed: number; total: number; score: number; error?: string }>;
  performanceScan: () => Promise<{ success: boolean; module: string; checks: any[]; passed: number; total: number; score: number; error?: string }>;
  privacyScan: () => Promise<{ success: boolean; module: string; checks: any[]; passed: number; total: number; score: number; error?: string }>;
}

export interface ElectronAPI {
  getSystemHealth: () => Promise<{
    score: number;
    factors: {
      security: number;
      performance: number;
      privacy: number;
    };
  }>; 
  getHealthReport: (
    options?: { force?: boolean }
  ) => Promise<{ success: true; data: any } | { success: false; error: string }>;
  toggleDevTools: () => Promise<{ success: boolean; error?: string }>;  // Profiler controls
  startProfiler: () => Promise<{ success: boolean; error?: string }>;
  stopProfiler: () => Promise<{ success: boolean; error?: string }>;
  listProfiles: () => Promise<{ success: boolean; profiles?: string[]; error?: string }>;  getSystemStats: () => Promise<{
    cpu: number;
    ram: number;
    disk: number;
    network: number;
  }>;
  getActivityLog: () => Promise<Array<{
    id: number;
    timestamp: string;
    module: string;
    action: string;
    details: string;
    severity: string;
  }>>;
  clearActivityLog: () => Promise<{ success: boolean; message: string }>;
  executeQuickAction: (action: string) => Promise<{
    success: boolean;
    message: string;
  }>;
  getRealSystemData: () => Promise<{
    success: boolean;
    data?: {
      ram: { totalGB: number; usedGB: number; freeGB: number; usagePercent: number };
      cpu: { name: string; cores: number; threads: number; currentLoad: number };
      disks: Array<{ drive: string; totalGB: number; freeGB: number; usedGB: number; usagePercent: number }>;
      system: { manufacturer: string; model: string; computerName: string; userName: string };
      os: { caption: string; version: string; buildNumber: string; installDate: string; lastBootUpTime: string };
      network: Array<{ adapterName: string; ipAddress: string; macAddress: string }>;
    };
    error?: string;
  }>;
  saveSettings: (key: string, value: any) => Promise<{ success: boolean; message?: string }>;
  getSettings: () => Promise<{ success: boolean; settings?: any; error?: string }>;
  shield: ShieldAPI;
  ghost: {
    getTelemetryServices: () => Promise<{ success: boolean; services: any[]; error?: string }>;
    getBlockedRequestsCount: () => Promise<{ success: boolean; count: number }>;
    toggleTelemetryService: (serviceName: string, enable: boolean) => Promise<{ success: boolean; message: string; error?: string }>;
    toggleAllTelemetry: (enableAll: boolean) => Promise<{ success: boolean; message: string; results: any[]; error?: string }>;
    getAppPermissions: () => Promise<{ success: boolean; apps: any[]; error?: string }>;
    toggleAppPermission: (packageName: string, permission: string, enable: boolean) => Promise<{ success: boolean; message: string; error?: string }>;
    getHostsFile: () => Promise<{ success: boolean; content: string; entries: any[]; lastModified?: string; error?: string }>;
    saveHostsFile: (content: string) => Promise<{ success: boolean; message: string; backupPath?: string; error?: string }>;
    importHostsBlocklist: (url: string) => Promise<{ success: boolean; message: string; backupPath?: string; error?: string }>;
    getCurrentDNS: () => Promise<{ success: boolean; primary: string; secondary: string; name?: string; error?: string }>;
    setDNS: (primary: string, secondary: string, forceVpn?: boolean) => Promise<{ success: boolean; message: string; vpnDetected?: boolean; vpnAdapters?: string; autoRolledBack?: boolean; error?: string }>;
    testDNSSpeed: (dnsServer: string) => Promise<{ success: boolean; latency: number }>;
  };
  forge: {
    // RAM Optimizer
    getRAMStats: () => Promise<{ totalGB: number; usedGB: number; availableGB: number; systemGB: number; appsGB: number; cacheGB: number; usagePercent: number }>;
    clearStandbyCache: () => Promise<{ success: boolean; freedMB?: number; message?: string; error?: string }>;
    emptyWorkingSets: () => Promise<{ success: boolean; freedMB?: number; message?: string; error?: string }>;
    optimizeRAM: () => Promise<{ success: boolean; freedMB?: number; actions?: string[]; message?: string; error?: string }>;

    // CPU Governor
    getTopCPUProcesses: () => Promise<{ success: boolean; processes: any[] }>;
    getCPUCoreCount: () => Promise<{ success: boolean; cores: number }>;
    setProcessPriority: (pid: number, priority: string) => Promise<{ success: boolean; priority?: string; message?: string; error?: string }>;
    setProcessAffinity: (pid: number, affinity: number) => Promise<{ success: boolean; message?: string; error?: string }>;
    getCurrentPowerPlan: () => Promise<{ success: boolean; plan: string }>;
    setPowerPlan: (plan: string) => Promise<{ success: boolean; planName?: string; message?: string; error?: string }>;

    // Startup Manager
    getStartupItems: () => Promise<{ success: boolean; items: any[]; currentBootTime: number; optimizedBootTime: number }>;
    toggleStartupItem: (name: string, enable: boolean) => Promise<{ success: boolean; message?: string; error?: string }>;

    // Service Optimizer
    getWindowsServices: () => Promise<{ success: boolean; services: any[] }>;
    controlService: (serviceName: string, action: 'start' | 'stop' | 'disable' | 'enable') => Promise<{ success: boolean; message?: string; error?: string }>;
    toggleWindowsService: (name: string, enable: boolean) => Promise<{ success: boolean; message?: string; error?: string }>;
    disableAllBloatware: () => Promise<{ success: boolean; disabledCount?: number; message?: string; error?: string }>;
    backupServicesState: () => Promise<{ success: boolean; backupFile?: string; message?: string; error?: string }>;
    restoreServicesState: () => Promise<{ success: boolean; restoredCount?: number; message?: string; error?: string }>;

    // Disk Cleaner
    getDriveInfo: () => Promise<{ success: boolean; drives: any[] }>;
    analyzeDiskCleanup: () => Promise<{ success: boolean; locations: any[]; totalMB: number; totalFiles: number; error?: string }>;
    cleanDisk: (selectedPaths: string[]) => Promise<{ success: boolean; freedMB?: number; deletedFiles?: number; message?: string; error?: string }>;
  };
  admin: {
    checkAdminRights: () => Promise<{ isAdmin: boolean; message: string }>;
    restartAsAdmin: () => Promise<{ success: boolean; error?: string }>;
  };
  vault: {
    // File Encryptor
    getEncryptedFiles: () => Promise<{ success: boolean; files: any[] }>;
    encryptFiles: (filePaths: string[], password: string) => Promise<{ success: boolean; encryptedCount?: number; message?: string }>;
    decryptFile: (filePath: string, password: string) => Promise<{ success: boolean; outputPath?: string; message?: string }>;

    // Secure Notes
    getSecureNotes: () => Promise<{ success: boolean; notes: any[] }>;
    saveSecureNote: (noteData: any) => Promise<{ success: boolean; noteId?: string; message?: string }>;
    openSecureNote: (noteId: string, password: string) => Promise<{ success: boolean; note?: any; message?: string }>;
    deleteSecureNote: (noteId: string) => Promise<{ success: boolean; message?: string; error?: string }>;

    // File Shredder
    getShredStats: () => Promise<{ shreddedCount: number; totalSize: number }>;
    shredFiles: (filePaths: string[]) => Promise<{ success: boolean; shreddedCount?: number; totalSize?: number; message?: string }>;

    // Password Generator
    getSavedPasswords: () => Promise<{ success: boolean; passwords: any[] }>;
    savePassword: (password: string, note: string) => Promise<{ success: boolean; message?: string }>;
  };
  advanced: {
    // Network Diagnostics
    getNetworkDiagnostics: () => Promise<{ success: boolean; data?: any; error?: string }>;

    // Hardware Temperatures
    getTemperatures: () => Promise<{ success: boolean; data?: { cpuTemp: number; gpuTemp: number }; error?: string }>;

    // Security Status
    getSecurityStatus: () => Promise<{ success: boolean; data?: any; error?: string }>;
    enableFirewall: () => Promise<{ success: boolean; error?: string }>;
    disableSMBv1: () => Promise<{ success: boolean; error?: string }>;
    enableDefender: () => Promise<{ success: boolean; error?: string }>;
    enableUAC: () => Promise<{ success: boolean; error?: string }>;

    // Cleanup Operations
    getCleanupData: () => Promise<{ success: boolean; data?: any; error?: string }>;
    cleanTemp: () => Promise<{ success: boolean; error?: string }>;
    cleanWindowsOld: () => Promise<{ success: boolean; error?: string }>;
    emptyRecycleBin: () => Promise<{ success: boolean; error?: string }>;
    cleanBrowserCache: () => Promise<{ success: boolean; error?: string }>;
    cleanAll: () => Promise<{ success: boolean; results?: any; error?: string }>;

    // Registry Tweaks
    getTweaks: () => Promise<{ success: boolean; tweaks?: any[]; error?: string }>;
    applyTweak: (tweakId: string, enable: boolean) => Promise<{ success: boolean; error?: string }>;

    // System Snapshots
    createSnapshot: (name: string) => Promise<{ success: boolean; snapshot?: any; error?: string }>;
    listSnapshots: () => Promise<{ success: boolean; snapshots?: any[]; error?: string }>;
    deleteSnapshot: (id: string) => Promise<{ success: boolean; error?: string }>;
    getSnapshot: (id: string) => Promise<{ success: boolean; snapshot?: any; error?: string }>;

    // Enhanced Process Management
    getProcessesEnhanced: () => Promise<{ success: boolean; processes?: any[]; error?: string }>;
    killProcess: (pid: number) => Promise<{ success: boolean; error?: string }>;
    getStartupPrograms: () => Promise<{ success: boolean; programs?: any[]; error?: string }>;
    disableStartupProgram: (name: string) => Promise<{ success: boolean; error?: string }>;
  };
  dsgvo: {
    getIpLookupEnabled: () => Promise<{ success: boolean; enabled: boolean }>;
    setIpLookupEnabled: (enabled: boolean) => Promise<{ success: boolean; enabled: boolean; error?: string }>;
    clearThreatEvents: () => Promise<{ success: boolean; deleted?: number; message?: string; error?: string }>;
  };
  renderer: {
    build: () => Promise<{ success: boolean; message?: string }>;
    reload: () => Promise<{ success: boolean; message?: string; path?: string }>;
    onBuildLog: (cb: (msg: string) => void) => void;
    onBuildDone: (cb: (res: any) => void) => void;
  };
  argus: ArgusAPI;
  vpn: {
    getStatus: () => Promise<{ success: boolean; data?: { active: boolean; adapters: any[]; provider: string; serverIp: string }; error?: string }>;
    getAdapterInfo: () => Promise<{ success: boolean; adapters: any[]; active: boolean; provider?: string; error?: string }>;
  };
  fim: {
    getConfig: () => Promise<{ success: boolean; config?: any; error?: string }>;
    setConfig: (update: any) => Promise<{ success: boolean; config?: any; error?: string }>;
    getChanges: () => Promise<{ success: boolean; changes: any[]; error?: string }>;
    getBaseline: () => Promise<{ success: boolean; baseline: any[]; error?: string }>;
    runCheck: () => Promise<{ success: boolean; newChanges?: any[]; totalChanges?: number; error?: string }>;
    resetBaseline: () => Promise<{ success: boolean; message?: string; error?: string }>;
  };
  eventLog: {
    getSecurity: () => Promise<{ success: boolean; events: any[]; error?: string }>;
    getAlerts: () => Promise<{ success: boolean; alerts: any[]; error?: string }>;
  };
  hardening: {
    getScore: () => Promise<{ success: boolean; score: number; passed: number; total: number; checks: any[]; error?: string }>;
  };
  portScanner: {
    run: () => Promise<{ success: boolean; ports: any[]; error?: string }>;
  };
  timeline: {
    getEvents: (maxEvents?: number) => Promise<{ success: boolean; events: any[]; error?: string }>;
  };
  platform: string;
}

export interface ArgusAPI {
  scanUrl: (url: string, deepFetch?: boolean) => Promise<{ success: boolean; data?: unknown; error?: string }>;
  batchScan: (urls: string[], deepFetch?: boolean) => Promise<{ success: boolean; data?: unknown; error?: string }>;
  getScanHistory: (limit?: number, offset?: number) => Promise<{ success: boolean; data?: unknown; error?: string }>;
  exportHistory: () => Promise<{ success: boolean; data?: unknown; error?: string }>;
  clearHistory: () => Promise<{ success: boolean; data?: unknown; error?: string }>;
  getSandboxStatus: () => Promise<{ success: boolean; data?: unknown; error?: string }>;
  toggleSandbox: (enabled: boolean) => Promise<{ success: boolean; data?: unknown; error?: string }>;
  encryptData: (data: string) => Promise<{ success: boolean; data?: unknown; error?: string }>;
  decryptData: (encryptedData: string) => Promise<{ success: boolean; data?: unknown; error?: string }>;
  getHealth: () => Promise<{ success: boolean; data?: { status: string; pid: number | null; port: number; uptimeMs: number; lastError: string | null }; error?: string }>;
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}
// Expose electronAPI to renderer
try {
  contextBridge.exposeInMainWorld('electronAPI', electronAPI);
  console.log('✅ [Preload] electronAPI exposed to renderer successfully');
} catch (error) {
  console.error('❌ [Preload] Failed to expose electronAPI:', error);
}

console.log('✅ [Preload] Preload script finished');