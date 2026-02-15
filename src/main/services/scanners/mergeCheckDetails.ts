/**
 * SENTINEL — Check Detail Merger
 * Maps runtime scan check IDs to rich detail templates,
 * producing full ScanCheckResult objects for the UI.
 */

import type { CheckDetailTemplate } from './networkScanChecks';
import { NETWORK_CHECK_DETAILS } from './networkScanChecks';
import { PRIVACY_CHECK_DETAILS } from './privacyScanChecks';
import { EDR_CHECK_DETAILS, KERNEL_CHECK_DETAILS, PERFORMANCE_CHECK_DETAILS } from './edrKernelPerfChecks';

interface RuntimeCheck {
  id: string;
  name: string;
  status: 'pass' | 'fail' | 'warn' | 'unknown';
  detail: string;
  risk: string;
  offenders?: { label: string; detail: string; severity?: string }[];
}

export interface EnrichedCheck {
  id: string;
  name: string;
  status: string;
  detail: string;
  risk: string;
  richDetail?: {
    whatChecked: string;
    whatFound: string;
    offenders?: { label: string; detail: string; severity?: string }[];
    riskExplanation: string;
    fixActions: string[];
    preserves: string[];
    canUndo: boolean;
    undoPath?: string;
  };
}

/**
 * Runtime check ID → template key mapping.
 * Keys from runtime checks (sentinelNetworkAdvanced, sentinelEdr, etc.)
 * mapped to keys in the detail template records.
 */
const ID_TO_TEMPLATE: Record<string, string> = {
  // ── Network (15) ──
  'net-wfp': 'wfp-kernel-filter',
  'net-tcphard': 'tcp-stack-hardening',
  'net-stealth': 'port-stealthing',
  'net-beacon': 'beaconing-detection',
  'net-alg': 'app-layer-gateway',
  'net-geoip': 'geo-ip-blocking',
  'net-outbound': 'process-outbound-control',
  'net-arp': 'arp-table-status',
  'net-doh': 'dns-over-https',
  'net-torblock': 'tor-proxy-blocking',
  'net-domrep': 'domain-reputation-filter',
  'net-zerotrust': 'zero-trust-isolation',
  'net-dpi': 'dpi-tls-check',
  'net-smbkill': 'smb-kill-switch',
  'net-netflow': 'netflow-active-connections',

  // ── EDR & Behavioral ──
  'edr-amsi': 'amsi-status',
  'edr-etw': 'etw-integrity',
  'edr-hollowing': 'process-hollowing',
  'edr-reflectivedll': 'reflective-dll',
  'edr-lsass': 'lsass-protection',
  'edr-entropy': 'ransomware-entropy',
  'edr-wmi': 'wmi-persistence',
  'edr-mitigations': 'exploit-protection',
  'edr-lsa': 'credential-dump-protection',
  'edr-autorun': 'autorun-entries',
  'edr-apc': 'apc-injection-monitor',
  'edr-scriptlog': 'powershell-logging',
  'edr-memscan': 'defender-status',
  'edr-apimap': 'sysmon-status',
  'edr-cig': 'code-integrity',
  'edr-honeypot': 'honeypot-mesh',
  'edr-syscall': 'syscall-integrity',
  'edr-etwti': 'etw-threat-intelligence',
  'edr-ppid': 'parent-pid-spoofing',
  'edr-token': 'token-elevation-guard',
  'edr-namedpipe': 'named-pipe-audit',
  'edr-dlls': 'dll-search-order',
  'edr-schtask': 'scheduled-task-audit',
  'edr-svcaudit': 'service-audit',
  'edr-nla': 'network-level-auth',
  'edr-asr': 'attack-surface-reduction',

  // ── Kernel & Firmware ──
  'kernel-elam': 'elam-status',
  'kernel-vbs': 'vbs-status',
  'kernel-tpm': 'tpm-status',
  'kernel-secureboot': 'secure-boot',
  'kernel-dse': 'driver-signing',
  'kernel-msr': 'spectre-meltdown',
  'kernel-shadowstack': 'shadow-stack',

  // ── Performance ──
  'perf-dpc': 'dpc-latency',
  'perf-timer': 'timer-resolution',
  'perf-ultimate': 'power-plan',
  'perf-superfetch': 'superfetch-prefetch',
  'perf-coreparking': 'core-parking',
  'perf-pagefile': 'pagefile-config',
  'perf-memcomp': 'memory-compression',

  // ── Privacy (22) ──
  'priv-hwid': 'hardware-id-exposure',
  'priv-adid': 'advertising-id',
  'priv-telemetry': 'telemetry-registry',
  'priv-cammic': 'webcam-mic-lock',
  'priv-clipboard': 'clipboard-history',
  'priv-metadata': 'metadata-stripper',
  'priv-cortana': 'cortana-web-search',
  'priv-wer': 'error-reporting',
  'priv-wifisense': 'wifi-sense',
  'priv-bluetooth': 'bluetooth-status',
  'priv-gpo': 'gpo-hardening',
  'priv-uac': 'uac-stealth-mode',
  'priv-shredder': 'military-shredder',
  'priv-antikeylog': 'anti-keylogging',
  'priv-fingerprint': 'tracking-protection',
  'priv-dnsleak': 'dns-leak-protection',
  'priv-location': 'location-services',
  'priv-winget': 'winget-available',
  'priv-usb': 'usb-storage',
  'priv-lockscreen': 'lockscreen-hardening',
  'priv-shellext': 'shell-extension-audit',
  'priv-dashboard': 'data-science-dashboard',
};

/** All detail templates merged into one lookup */
const ALL_TEMPLATES: Record<string, CheckDetailTemplate> = {
  ...NETWORK_CHECK_DETAILS,
  ...PRIVACY_CHECK_DETAILS,
  ...EDR_CHECK_DETAILS,
  ...KERNEL_CHECK_DETAILS,
  ...PERFORMANCE_CHECK_DETAILS,
};

/**
 * Enrich a runtime check with its detail template.
 */
function enrichCheck(check: RuntimeCheck): EnrichedCheck {
  const templateKey = ID_TO_TEMPLATE[check.id];
  const template = templateKey ? ALL_TEMPLATES[templateKey] : undefined;

  if (!template) {
    return { ...check };
  }

  return {
    ...check,
    richDetail: {
      whatChecked: template.whatChecked,
      whatFound: check.status === 'pass' ? template.passDetail : check.detail,
      offenders: check.offenders,
      riskExplanation: template.riskExplanation,
      fixActions: check.status !== 'pass' ? template.fixActionsTemplate : [],
      preserves: template.preserves,
      canUndo: template.canUndo,
      undoPath: template.undoPath,
    },
  };
}

/**
 * Enrich an array of runtime checks with detail templates.
 */
export function enrichChecks(checks: RuntimeCheck[]): EnrichedCheck[] {
  return checks.map(enrichCheck);
}
