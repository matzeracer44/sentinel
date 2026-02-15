export interface PortIntel {
  port: number;
  label: string;
  historicalUse: string;
  modernUse: string;
  threats: string[];
  hardening: string;
}

export interface KnowledgeTopic {
  title: string;
  summary: string;
  bullets?: string[];
  highlight?: string;
}

const PORT_INTEL: Record<number, PortIntel> = {
  20: {
    port: 20,
    label: 'FTP Data',
    historicalUse: 'Bulk file transfers between trusted hosts in early client/server deployments.',
    modernUse: 'Legacy automated jobs and embedded devices still rely on FTP data channels.',
    threats: [
      'Credential harvesting via cleartext sniffing.',
      'Bounce attacks that abuse third-party FTP servers to scan networks.',
    ],
    hardening: 'Disable plain FTP where possible or force FTPS/SFTP. Restrict outbound 20/21 to specific automation endpoints.',
  },
  21: {
    port: 21,
    label: 'FTP Control',
    historicalUse: 'Primary channel for file transfer commands.',
    modernUse: 'Remote management of printers, SCADA gear, and network appliances.',
    threats: [
      'Brute-force attacks targeting weak credentials.',
      'Malware staging (e.g., TrickBot) using open FTP servers.',
    ],
    hardening: 'Require strong authentication, monitor for anonymous logins, migrate to SFTP when possible.',
  },
  22: {
    port: 22,
    label: 'SSH / SFTP',
    historicalUse: 'Secure remote administration for UNIX hosts.',
    modernUse: 'Git deployments, CI/CD pipelines, encrypted tunnels, IoT maintenance.',
    threats: [
      'Automated password sprays and key theft.',
      'Reverse shells dropped by worms (e.g., Mirai variants).',
    ],
    hardening: 'Use key-based auth with MFA, disable root logins, rate-limit connection attempts.',
  },
  23: {
    port: 23,
    label: 'Telnet',
    historicalUse: 'Interactive shell before SSH existed.',
    modernUse: 'Legacy routers and OT gear still expose Telnet for compatibility.',
    threats: [
      'Mirai-family botnets brute force default credentials.',
      'Credential theft because Telnet is plaintext.',
    ],
    hardening: 'Disable Telnet entirely or isolate legacy devices on a management VLAN.',
  },
  25: {
    port: 25,
    label: 'SMTP',
    historicalUse: 'Internet email relay.',
    modernUse: 'Outbound email relays, alerting systems, spam campaigns.',
    threats: [
      'Opportunistic relay abuse for spam/malware.',
      'Phishing kits exfiltrating mailboxes over SMTP.',
    ],
    hardening: 'Require authentication, enforce TLS, block outbound 25 for non-mail servers.',
  },
  53: {
    port: 53,
    label: 'DNS',
    historicalUse: 'Recursive name resolution.',
    modernUse: 'Split-horizon DNS, DoH/DoT, telemetry beacons.',
    threats: [
      'DNS tunneling for data exfiltration.',
      'Domain generation algorithms (DGA) for C2 lookups.',
    ],
    hardening: 'Inspect DNS payloads, enable RPZ/response policy zones, restrict to internal resolvers.',
  },
  80: {
    port: 80,
    label: 'HTTP',
    historicalUse: 'Web browsing over plaintext.',
    modernUse: 'API gateways, device activation, some upgrade services.',
    threats: [
      'Exploit kits and drive-by downloads.',
      'Command-and-control over HTTP for ransomware droppers.',
    ],
    hardening: 'Redirect to HTTPS, apply WAF rules, monitor unusual user agents.',
  },
  110: {
    port: 110,
    label: 'POP3',
    historicalUse: 'Mailbox retrieval for desktop clients.',
    modernUse: 'Legacy mail appliances and backward compatibility.',
    threats: [
      'Credential theft via downgrade to plaintext POP3.',
      'Account takeover through exposed POP3 services.',
    ],
    hardening: 'Enforce POP3S (995), disable plain POP3 if unused.',
  },
  143: {
    port: 143,
    label: 'IMAP',
    historicalUse: 'Online mail access with folders/sync.',
    modernUse: 'Mobile mail clients and shared mailboxes.',
    threats: [
      'Brute-force attacks for BEC campaigns.',
      'IMAP IDLE abused for persistence by malware.',
    ],
    hardening: 'Force IMAPS (993), enable MFA, detect anomalous geo access.',
  },
  443: {
    port: 443,
    label: 'HTTPS / QUIC',
    historicalUse: 'Secure web browsing once SSL became common.',
    modernUse: 'Default transport for SaaS, APIs, mobile apps, QUIC/HTTP3.',
    threats: [
      'Encrypted C2 channels (e.g., Cobalt Strike over HTTPS).',
      'Domain fronting and CDN abuse for malware delivery.',
    ],
    hardening: 'Use TLS inspection where lawful, enforce certificate pinning for internal apps, monitor JA3/JA4 fingerprints.',
  },
  445: {
    port: 445,
    label: 'SMB',
    historicalUse: 'Windows file and printer sharing.',
    modernUse: 'AD authentication, file servers, M365 hybrid connectors.',
    threats: [
      'WannaCry/NotPetya leveraged EternalBlue on 445.',
      'Lateral movement via pass-the-hash.',
    ],
    hardening: 'Block 445 at perimeter, enable SMB signing, patch early and monitor for anonymous access.',
  },
  465: {
    port: 465,
    label: 'SMTPS',
    historicalUse: 'Deprecated SMTPS “wrapper” port.',
    modernUse: 'Modern secure SMTP submission for appliances.',
    threats: [
      'Attackers exfiltrating data through misconfigured relays.',
    ],
    hardening: 'Ensure STARTTLS enforcement and authenticated submission.',
  },
  587: {
    port: 587,
    label: 'Authenticated SMTP Submission',
    historicalUse: 'Replacement for port 465 after RFC 6409.',
    modernUse: 'Client-to-server email submission, automated alerting.',
    threats: [
      'Phishing toolkits abusing weak credentials.',
    ],
    hardening: 'Require SMTP AUTH with MFA and device restrictions.',
  },
  3389: {
    port: 3389,
    label: 'RDP',
    historicalUse: 'Remote desktop for Windows admin tasks.',
    modernUse: 'Managed service access, helpdesk workflows, cloud bastions.',
    threats: [
      'BlueKeep/DejaBlue vulnerabilities enable worming.',
      'Initial access brokers brute force exposed RDP endpoints.',
    ],
    hardening: 'Place RDP behind VPN or RD Gateway, enable Network Level Authentication, monitor failed logons.',
  },
  1900: {
    port: 1900,
    label: 'SSDP / UPnP',
    historicalUse: 'Discovery for small/home networks.',
    modernUse: 'IoT discovery, smart displays, media streaming.',
    threats: [
      'Reflection DDoS attacks using SSDP amplification.',
    ],
    hardening: 'Disable UPnP on edge routers, filter SSDP at WAN boundary.',
  },
};

export const getPortIntel = (port?: number | null): PortIntel | undefined => {
  if (typeof port !== 'number') return undefined;
  return PORT_INTEL[port];
};

export const listPortIntel = (): PortIntel[] => Object.values(PORT_INTEL).sort((a, b) => a.port - b.port);

export const HTTPS_TRAFFIC_NOTE =
  'Port 443 is the default for TLS-encrypted web/API traffic. Modern apps multiplex multiple services through HTTPS, so threat ' +
  'hunters usually see 443 dominating remote ports unless they capture specialized protocols (VoIP, RDP, etc.).';

const KNOWLEDGE_TOPICS: Record<string, KnowledgeTopic> = {
  portBlocking: {
    title: 'Port Hardening Playbook',
    summary:
      'Blocking TCP/UDP ports limits lateral movement and narrows the attack surface. Sentinel rules enforce both inbound and outbound paths to prevent covert callbacks.',
    bullets: [
      'Always validate business justification before blocking production ports.',
      'Loopback-only rules let you quarantine localhost malware without touching LAN traffic.',
      'Use undo/redo to test impact in seconds.',
    ],
  },
  pidBlocking: {
    title: 'Process Containment',
    summary:
      'Sentinel resolves the executable behind a PID and crafts program-scoped firewall rules. PID 0 maps to the System service for kernel networking.',
    bullets: [
      'Blocking both directions isolates suspected processes instantly.',
      'Combine with Network Monitor selection to avoid typos.',
      'Undo/redo lets you roll back accidental quarantines on critical services.',
    ],
  },
  subnetBlocking: {
    title: 'Subnet Control & CIDR Hygiene',
    summary:
      'Subnet blocking prevents entire IP ranges from talking to your host. Useful for takedowns, malware ASNs, or shadow IT segments.',
    bullets: [
      'Use CIDR input for exact ranges, or masks to quickly expand a single IP.',
      'Pair with monitoring so reappearances trigger alerts.',
      'Prefer inbound+outbound blocks to stop replies that leak context.',
    ],
  },
  firewallRules: {
    title: 'Active Rule Intelligence',
    summary:
      'Show-NetFirewallRule exposes every Sentinel-authored policy with direction, program, and ports for investigation.',
    bullets: [
      'Sort by Newest to confirm your latest enforcement landed.',
      'Rules referencing "Sentinel" are safe to remove from here.',
      'Profiles indicate which network context (Domain/Private/Public) is protected.',
    ],
  },
  networkMonitor: {
    title: 'Network Monitor Insights',
    summary:
      'Live TCP telemetry surfaces suspicious remote IPs, bandwidth spikes, and process associations.',
    bullets: [
      'Prefetch geodata for the busiest IPs automatically.',
      'Monitor repeated IPs to catch stubborn C2 traffic.',
      'Send any row to Firewall Orchestrator with one click.',
    ],
  },
  tlsInspection: {
    title: 'TLS Inspection (SSL Labs)',
    summary:
      'Run remote SSL/TLS scans via Qualys SSL Labs to understand cipher posture, protocol support, and vulnerabilities.',
    bullets: [
      'Grades summarize exposure (A=strong, F=critical issues).',
      'Issues list calls out Heartbleed, RC4, missing forward secrecy.',
      'Use cached lookups first; deep scans may take ~1-2 minutes upstream.',
    ],
  },
};

export type KnowledgeKey = keyof typeof KNOWLEDGE_TOPICS;

export const getKnowledgeTopic = (key: KnowledgeKey): KnowledgeTopic => KNOWLEDGE_TOPICS[key];
