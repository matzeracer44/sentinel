/**
 * SENTINEL UNIFIED — IPC Channel Constants
 * Every IPC channel name in one place. Never use raw strings in ipcMain.handle() or ipcRenderer.invoke().
 */

export const IPC = {
  // ═══════════════════════════════════════════
  // FIREWALL ENGINE
  // ═══════════════════════════════════════════
  FIREWALL: {
    GET_RULES:            'firewall:get-rules',
    GET_INVENTORY:        'firewall:get-inventory',
    BLOCK_PORT:           'firewall:block-port',
    BLOCK_SUBNET:         'firewall:block-subnet',
    BLOCK_PID:            'firewall:block-pid',
    BLOCK_IP:             'firewall:block-ip',
    UNBLOCK_IP:           'firewall:unblock-ip',
    GET_BLOCKED_IPS:      'firewall:get-blocked-ips',
    BLOCK_IP_SUBNET:      'firewall:block-ip-subnet',
    UNBLOCK_SUBNET:       'firewall:unblock-subnet',
    DELETE_RULE:           'firewall:delete-rule',
    UNDO:                 'firewall:undo',
    REDO:                 'firewall:redo',
    GET_UNDO_REDO_STATE:  'firewall:get-undo-redo-state',
    GET_SENTINEL_RULES:   'firewall:get-sentinel-rules',
    CLEAR_SENTINEL_RULES: 'firewall:clear-sentinel-rules',
    SELF_TEST:            'firewall:self-test',
    STAGE_RULE:           'firewall:stage-rule',
    GET_PENDING_RULES:    'firewall:get-pending-rules',
    COMMIT_PENDING_RULE:  'firewall:commit-pending-rule',
    DISMISS_PENDING_RULE: 'firewall:dismiss-pending-rule',
    WHITELIST_THREAT:     'firewall:whitelist-threat',
    QUICK_BLOCK_SUBNET:   'firewall:quick-block-subnet',
    LOG_MANUAL_BLOCK:     'firewall:log-manual-block',
    /** Push channel: main → renderer */
    PENDING_RULE_UPDATE:  'firewall:pending-rule-update',
  },

  // ═══════════════════════════════════════════
  // THREAT INTELLIGENCE
  // ═══════════════════════════════════════════
  INTEL: {
    GET_THREAT_EVENTS:        'intel:get-threat-events',
    GET_GUARDIAN_STORIES:      'intel:get-guardian-stories',
    LOG_GUARDIAN_EVENT:        'intel:log-guardian-event',
    LIST_PLAYBOOKS:           'intel:list-playbooks',
    SAVE_PLAYBOOK:            'intel:save-playbook',
    DELETE_PLAYBOOK:           'intel:delete-playbook',
    RUN_PLAYBOOK:             'intel:run-playbook',
    GET_PLAYBOOK_RUNS:        'intel:get-playbook-runs',
    GET_THREAT_INTEL:         'intel:get-threat-intel',
    REFRESH_THREAT_INTEL:     'intel:refresh-threat-intel',
    GET_ANOMALY_CONFIG:       'intel:get-anomaly-config',
    UPDATE_ANOMALY_CONFIG:    'intel:update-anomaly-config',
    GET_POLICY_SUGGESTIONS:   'intel:get-policy-suggestions',
    ACCEPT_POLICY:            'intel:accept-policy',
    DISMISS_POLICY:           'intel:dismiss-policy',
    // ARGUS URL scanning
    URL_SCAN:                 'intel:url-scan',
    BATCH_SCAN:               'intel:batch-scan',
    SCAN_HISTORY:             'intel:scan-history',
    EXPORT_HISTORY:           'intel:export-history',
    CLEAR_HISTORY:            'intel:clear-history',
  },

  // ═══════════════════════════════════════════
  // AUTOMATION ENGINE
  // ═══════════════════════════════════════════
  AUTOMATION: {
    SET_AUTONOMOUS_MODE:  'automation:set-autonomous-mode',
    EXECUTE_QUICK_ACTION: 'automation:execute-quick-action',
  },

  // ═══════════════════════════════════════════
  // NETWORK MONITOR
  // ═══════════════════════════════════════════
  NETWORK: {
    GET_TRAFFIC:          'network:get-traffic',
    GET_FULL_AUDIT:       'network:get-full-audit',
    GET_DIAGNOSTICS:      'network:get-diagnostics',
    GET_IP_METADATA:      'network:get-ip-metadata',
    INSPECT_TLS:          'network:inspect-tls',
    REGISTER_WATCH:       'network:register-watch',
    GET_WATCH:            'network:get-watch',
    TEST_INTERNET:        'network:test-internet',
    GET_PROCESSES:        'network:get-processes',
    KILL_PROCESS:         'network:kill-process',
    GET_SYSTEM_STATS:     'network:get-system-stats',
    // ARGUS sandbox
    SANDBOX_STATUS:       'network:sandbox-status',
    SANDBOX_TOGGLE:       'network:sandbox-toggle',
    // Session streaming (from Sentinel2.44)
    SESSION_UPDATE:       'network:session-update',
    FLUSH_SESSION_CACHE:  'network:flush-session-cache',
  },

  // ═══════════════════════════════════════════
  // DNS & HOSTS
  // ═══════════════════════════════════════════
  DNS: {
    GET_CURRENT:          'dns:get-current',
    SET_DNS:              'dns:set-dns',
    GET_HOSTS_FILE:       'dns:get-hosts-file',
    SAVE_HOSTS_FILE:      'dns:save-hosts-file',
  },

  // ═══════════════════════════════════════════
  // SYSTEM & PERFORMANCE
  // ═══════════════════════════════════════════
  SYSTEM: {
    GET_DATA:             'system:get-data',
    GET_HEALTH:           'system:get-health',
    GET_STATS:            'system:get-stats',
    GET_HEALTH_REPORT:    'system:get-health-report',
    GET_RAM_STATS:        'system:get-ram-stats',
    CLEAR_STANDBY_CACHE:  'system:clear-standby-cache',
    GET_STARTUP_ITEMS:    'system:get-startup-items',
    GET_WINDOWS_SERVICES: 'system:get-windows-services',
    CHECK_ADMIN:          'system:check-admin',
    GET_SECURITY_OVERVIEW:'system:get-security-overview',
  },

  // ═══════════════════════════════════════════
  // VAULT & CONFIG
  // ═══════════════════════════════════════════
  VAULT: {
    GET_SECURE_NOTES:     'vault:get-secure-notes',
    SAVE_SECURE_NOTE:     'vault:save-secure-note',
    GET_ENCRYPTED_FILES:  'vault:get-encrypted-files',
    ENCRYPT_DATA:         'vault:encrypt-data',
    DECRYPT_DATA:         'vault:decrypt-data',
    GET_CONFIG:           'vault:get-config',
    ADD_WHITELIST:        'vault:add-whitelist',
    REMOVE_WHITELIST:     'vault:remove-whitelist',
    SET_WHITELIST:        'vault:set-whitelist',
    GET_SETTINGS:         'vault:get-settings',
    SAVE_SETTINGS:        'vault:save-settings',
    GET_ACTIVITY_LOG:     'vault:get-activity-log',
    CLEAR_ACTIVITY_LOG:   'vault:clear-activity-log',
    ARGUS_HEALTH:         'vault:argus-health',
  },

  // ═══════════════════════════════════════════
  // UTILITY / DIALOG
  // ═══════════════════════════════════════════
  DIALOG: {
    SHOW_ERROR:           'dialog:show-error',
    SHOW_MESSAGE:         'dialog:show-message',
    SHOW_CONFIRM:         'dialog:show-confirm',
    TOGGLE_DEV_TOOLS:     'dialog:toggle-dev-tools',
  },

  RENDERER: {
    BUILD:                'renderer:build',
    RELOAD:               'renderer:reload',
    BUILD_LOG:            'renderer:build-log',
    BUILD_DONE:           'renderer:build-done',
  },
} as const;

/** Flattened type of all IPC channel string values */
type DeepValues<T> = T extends string ? T : T extends object ? DeepValues<T[keyof T]> : never;
export type IPCChannel = DeepValues<typeof IPC>;

// ═══════════════════════════════════════════
// PROTECTED PROCESSES — BUG-026 BSOD PREVENTION
// Killing any of these causes Blue Screen, forced reboot, or system hang.
// ═══════════════════════════════════════════

export const PROTECTED_PROCESSES: Set<string> = new Set([
  'system',
  'secure system',
  'registry',
  'smss.exe',
  'csrss.exe',
  'wininit.exe',
  'winlogon.exe',
  'services.exe',
  'lsass.exe',
  'lsaiso.exe',
  'svchost.exe',
  'dwm.exe',
  'fontdrvhost.exe',
  'memory compression',
  'system idle process',
  'ntoskrnl.exe',
  'hal.dll',
  'conhost.exe',
  'searchhost.exe',
  'runtimebroker.exe',
  'sihost.exe',
  'taskhostw.exe',
  'explorer.exe',
  'shellexperiencehost.exe',
  'startmenuexperiencehost.exe',
  'textinputhost.exe',
  'dllhost.exe',
  'wmiprvse.exe',
  'spoolsv.exe',
]);

export const SENTINEL_PROCESSES: Set<string> = new Set([
  'electron.exe',
  'sentinel.exe',
  'python.exe',
  'python3.exe',
]);

export type ProcessKillRisk = 'safe' | 'caution' | 'dangerous' | 'forbidden';

export function getProcessKillRisk(name: string, pid: number): ProcessKillRisk {
  const lower = (name || '').toLowerCase().trim();
  if (pid <= 4) return 'forbidden';
  if (PROTECTED_PROCESSES.has(lower)) return 'forbidden';
  if (SENTINEL_PROCESSES.has(lower)) return 'dangerous';
  if (lower.includes('service') || lower.includes('host')) return 'caution';
  return 'safe';
}
