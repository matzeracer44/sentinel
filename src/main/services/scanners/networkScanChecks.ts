/**
 * SENTINEL — Network Scan Check Detail Definitions (15 checks)
 * Each check defines its detail template. Runtime data fills in the blanks.
 */

export interface CheckDetailTemplate {
  whatChecked: string;
  riskExplanation: string;
  passDetail: string;
  fixActionsTemplate: string[];
  preserves: string[];
  canUndo: boolean;
  undoPath?: string;
}

export const NETWORK_CHECK_DETAILS: Record<string, CheckDetailTemplate> = {
  'wfp-kernel-filter': {
    whatChecked: 'Windows Filtering Platform kernel driver, Base Filtering Engine (BFE), and Windows Firewall service (MpsSvc).',
    riskExplanation: 'WFP is the kernel-level packet filter. If BFE or MpsSvc stops, ALL firewall rules become silently inactive — your machine is fully exposed.',
    passDetail: 'BFE service running. MpsSvc service running. WFP kernel driver loaded.',
    fixActionsTemplate: ['Start BFE service (sc start BFE)', 'Start MpsSvc service', 'Reload WFP driver'],
    preserves: ['Existing firewall rules', 'Network connections'],
    canUndo: false,
  },
  'tcp-stack-hardening': {
    whatChecked: 'SynAttackProtect, DeadGWRetryCount, KeepAliveTime, and IP source routing registry settings.',
    riskExplanation: 'Weak TCP stack settings allow SYN flood attacks, dead gateway exploits, and source routing hijacks to succeed.',
    passDetail: 'SynAttackProtect enabled. DeadGW retry reduced. Source routing disabled.',
    fixActionsTemplate: ['Set SynAttackProtect=1', 'Reduce DeadGWRetryCount to 1', 'Disable IP source routing', 'Restart TCP/IP stack'],
    preserves: ['Active connections not interrupted', 'Firewall rules unchanged'],
    canUndo: true,
    undoPath: 'Registry → TCP/IP Parameters → Restore defaults',
  },
  'port-stealthing': {
    whatChecked: 'ICMP echo response, common probe ports (135, 139, 445, 3389) visibility to external scanners.',
    riskExplanation: 'Responsive ICMP and open probe ports make your machine visible to automated scanners and worm propagation.',
    passDetail: 'ICMP echo blocked. Common probe ports stealthed or filtered.',
    fixActionsTemplate: ['Block ICMP echo reply outbound', 'Create stealth rules for ports 135, 139, 445, 3389'],
    preserves: ['LAN file sharing if configured', 'RDP if explicitly allowed'],
    canUndo: true,
    undoPath: 'Firewall → Undo',
  },
  'beaconing-detection': {
    whatChecked: 'Outbound connections with regular timing intervals (potential C2 beacon patterns).',
    riskExplanation: 'Command & control beacons can exfiltrate data, download malware payloads, or maintain persistent access. Even legitimate beacons waste bandwidth and leak telemetry.',
    passDetail: 'No processes exhibit suspicious periodic connection patterns.',
    fixActionsTemplate: ['Block top beaconing IPs in firewall', 'Add flagged IPs to watchlist', 'Log blocked connections to Threat Timeline'],
    preserves: ['Browser connections to safe domains', 'Existing firewall rules'],
    canUndo: true,
    undoPath: 'Firewall → Undo',
  },
  'app-layer-gateway': {
    whatChecked: 'Application Layer Gateway (ALG) service status for FTP, SIP, PPTP protocol handling.',
    riskExplanation: 'ALG intercepts and modifies network traffic at the application layer. If exploited, attackers can bypass firewall rules entirely.',
    passDetail: 'ALG service stopped or restricted to necessary protocols only.',
    fixActionsTemplate: ['Disable ALG service (sc stop ALG)', 'Restrict to required protocols only'],
    preserves: ['FTP connections may need manual port forwarding', 'SIP/VoIP if in use'],
    canUndo: true,
    undoPath: 'Services → ALG → Set to Automatic',
  },
  'geo-ip-blocking': {
    whatChecked: 'Presence of outbound/inbound firewall rules for known high-risk country IP ranges.',
    riskExplanation: 'Without geo-blocking, traffic from hostile regions reaches your machine unrestricted. Many automated attacks originate from specific countries.',
    passDetail: 'Geo-block rules active for high-risk regions.',
    fixActionsTemplate: ['Create outbound block rules for high-risk IP ranges', 'Add exception rules for legitimate services', 'Update IP range database'],
    preserves: ['Connections to major cloud services (AWS, Azure, GCP)', 'VPN traffic unaffected'],
    canUndo: true,
    undoPath: 'Firewall → Undo → Remove geo-block rules',
  },
  'process-outbound-control': {
    whatChecked: 'Whether outbound connections are filtered per-process or allowed globally (default-allow).',
    riskExplanation: 'Default-allow outbound lets ANY process connect to ANY server. Malware, spyware, and data exfiltration tools work unrestricted.',
    passDetail: 'Outbound firewall profile configured with per-process rules. Default outbound: Block.',
    fixActionsTemplate: ['Set outbound default to Block', 'Create allow rules for known-good processes', 'Monitor blocked attempts in event log'],
    preserves: ['Existing allow rules stay active', 'Browser and system updates continue working'],
    canUndo: true,
    undoPath: 'Firewall → Outbound Policy → Set Default Allow',
  },
  'arp-table-status': {
    whatChecked: 'ARP table for duplicate MACs, static vs dynamic entries, and potential ARP spoofing indicators.',
    riskExplanation: 'ARP spoofing allows attackers on your LAN to intercept all your traffic (man-in-the-middle). Dynamic-only ARP tables are vulnerable.',
    passDetail: 'ARP table clean. No duplicate MACs. Gateway has static entry.',
    fixActionsTemplate: ['Set gateway MAC as static ARP entry', 'Enable Dynamic ARP Inspection if switch supports it'],
    preserves: ['Network connectivity unchanged', 'DHCP continues working'],
    canUndo: true,
    undoPath: 'ARP → Delete static entry',
  },
  'dns-over-https': {
    whatChecked: 'Whether DNS queries use encrypted transport (DoH/DoT) or plaintext UDP/53.',
    riskExplanation: 'Plaintext DNS exposes every domain you visit to anyone on your network, your ISP, and potential eavesdroppers.',
    passDetail: 'DNS queries routed through encrypted DNS (DoH or VPN tunnel).',
    fixActionsTemplate: ['Enable DoH in Windows DNS settings', 'Configure DoH server (e.g., Cloudflare 1.1.1.1)', 'Block plaintext DNS (port 53) in firewall'],
    preserves: ['VPN DNS routing if active', 'Local network DNS resolution'],
    canUndo: true,
    undoPath: 'DNS & Privacy → DNS Configuration → Restore',
  },
  'tor-proxy-blocking': {
    whatChecked: 'Whether known Tor exit node IPs and SOCKS proxy ports are blocked.',
    riskExplanation: 'Open Tor/proxy access allows malware to anonymize its traffic and bypass geo-restrictions on C2 servers.',
    passDetail: 'Known Tor exit nodes blocked. SOCKS proxy ports restricted.',
    fixActionsTemplate: ['Block known Tor exit node IP ranges', 'Restrict SOCKS ports 1080, 9050, 9150'],
    preserves: ['Legitimate VPN connections', 'Browser proxy settings if configured'],
    canUndo: true,
    undoPath: 'Firewall → Undo',
  },
  'domain-reputation-filter': {
    whatChecked: 'Whether DNS queries to known-malicious domains are blocked via hosts file or DNS filter.',
    riskExplanation: 'Without domain filtering, phishing, malware distribution, and ad-tracking domains resolve normally. This is the #1 vector for browser-based attacks.',
    passDetail: 'Domain reputation filter active. Blocklist loaded with known-malicious domains.',
    fixActionsTemplate: ['Update hosts file with malicious domain blocklist', 'Enable DNS-level filtering', 'Add monitoring for blocked queries'],
    preserves: ['Legitimate website access', 'Existing hosts file entries'],
    canUndo: true,
    undoPath: 'DNS & Privacy → Hosts File → Restore backup',
  },
  'zero-trust-isolation': {
    whatChecked: 'Network profile (Public/Private/Domain), firewall rules for inbound defaults, and network discovery settings.',
    riskExplanation: 'Non-public network profiles enable file sharing, printer sharing, and network discovery — exposing services to nearby attackers.',
    passDetail: 'Network profile: Public. Inbound default: Block. Network discovery: Disabled.',
    fixActionsTemplate: ['Set network profile to Public for untrusted networks', 'Disable network discovery', 'Block inbound by default'],
    preserves: ['Outbound connections unchanged', 'VPN traffic unaffected'],
    canUndo: true,
    undoPath: 'Network Settings → Change profile back to Private',
  },
  'dpi-tls-check': {
    whatChecked: 'TLS versions in use by active connections. Checks for deprecated TLS 1.0/1.1.',
    riskExplanation: 'TLS 1.0 and 1.1 have known vulnerabilities. Connections using these protocols can be intercepted or downgraded.',
    passDetail: 'All active TLS connections using TLS 1.2 or 1.3.',
    fixActionsTemplate: ['Disable TLS 1.0 and 1.1 in Windows registry', 'Update SChannel settings'],
    preserves: ['TLS 1.2 and 1.3 connections', 'HTTPS browsing'],
    canUndo: true,
    undoPath: 'Registry → SChannel → Re-enable TLS 1.0/1.1',
  },
  'smb-kill-switch': {
    whatChecked: 'SMBv1 protocol status, SMB signing, and SMB encryption settings.',
    riskExplanation: 'SMBv1 is the protocol exploited by WannaCry and EternalBlue. It must be disabled on every modern system.',
    passDetail: 'SMBv1 disabled. SMBv2/v3 with signing enabled.',
    fixActionsTemplate: ['Disable SMBv1 client and server', 'Enable SMB signing', 'Enable SMB encryption'],
    preserves: ['SMBv2/v3 file sharing continues', 'Printer sharing if using SMBv2+'],
    canUndo: true,
    undoPath: 'Windows Features → Re-enable SMBv1',
  },
  'netflow-active-connections': {
    whatChecked: 'Number of established connections, listening ports, and connection churn rate.',
    riskExplanation: 'Abnormal connection counts or high churn rates may indicate malware activity, port scanning, or data exfiltration.',
    passDetail: 'Connection counts within normal range. No abnormal listeners detected.',
    fixActionsTemplate: ['Close suspicious listening ports', 'Block high-churn processes', 'Add to monitoring watchlist'],
    preserves: ['Active browser sessions', 'System service connections'],
    canUndo: true,
    undoPath: 'Firewall → Undo',
  },
};
