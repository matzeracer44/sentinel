/**
 * SENTINEL — Fix Safety Classification System
 * Born from a real incident: "Apply Fix" set outbound firewall to BLOCK → no internet, no undo.
 * NEVER AGAIN.
 *
 * Every scan fix MUST be classified before execution.
 * Forbidden fixes are NEVER offered. Dangerous fixes require explicit checkbox consent.
 * Every fix that touches connectivity gets auto-reverted if internet breaks.
 */

export type FixDangerLevel = 'safe' | 'caution' | 'dangerous' | 'forbidden';

export interface FixImpactAssessment {
  dangerLevel: FixDangerLevel;
  whatChanges: string;
  whyNeeded: string;
  whatCouldBreak: string[];
  affectsConnectivity: boolean;
  affectsFirewall: boolean;
  affectsDNS: boolean;
  affectsRegistry: boolean;
  affectsServices: boolean;
  requiresReboot: boolean;
  undoable: boolean;
  undoCommand: string;
  undoDescription: string;
  estimatedTime: string;
}

export interface FixClassification {
  dangerLevel: FixDangerLevel;
  affectsFirewall: boolean;
  affectsDNS: boolean;
  affectsRegistry: boolean;
  affectsServices: boolean;
  affectsConnectivity: boolean;
  requiresReboot: boolean;
  whatChanges: string;
  whatCouldBreak: string[];
  undoCommand: string;
  undoDescription: string;
}

/**
 * FORBIDDEN FIX IDS — these are NEVER offered to the user.
 * They can make the system completely unusable.
 */
export const FORBIDDEN_FIX_IDS: ReadonlySet<string> = new Set([
  'net-outbound',  // Sets outbound policy to BLOCK → KILLS INTERNET
]);

/**
 * Master classification table for every SCAN_FIX_COMMAND.
 * If a fix is not listed here, it defaults to 'caution' with generic warnings.
 */
export const FIX_CLASSIFICATIONS: Record<string, FixClassification> = {
  // ═══════════════════════════════════════════════════════════════
  // ⛔ FORBIDDEN — Will make system unusable
  // ═══════════════════════════════════════════════════════════════
  'net-outbound': {
    dangerLevel: 'forbidden',
    affectsFirewall: true, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: true, requiresReboot: false,
    whatChanges: 'Setzt ausgehende Firewall-Policy auf BLOCK für Public-Profil',
    whatCouldBreak: ['KEIN INTERNET MEHR', 'Kein Browser, kein Update, kein Cloud-Service', 'VPN bricht ab', 'Kein Weg zurück ohne Adminrechte + Netsh'],
    undoCommand: '', undoDescription: '',
  },

  // ═══════════════════════════════════════════════════════════════
  // 🔴 DANGEROUS — Affects connectivity / firewall / DNS directly
  // ═══════════════════════════════════════════════════════════════
  'net-wfp': {
    dangerLevel: 'dangerous',
    affectsFirewall: true, affectsDNS: false, affectsRegistry: false, affectsServices: true,
    affectsConnectivity: true, requiresReboot: false,
    whatChanges: 'Startet BFE + MpsSvc Dienste, aktiviert Firewall auf allen Profilen',
    whatCouldBreak: ['Programme ohne Firewall-Regel könnten blockiert werden', 'Spieleserver könnten Verbindung verlieren'],
    undoCommand: 'Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False',
    undoDescription: 'Firewall-Profile werden wieder deaktiviert (vorheriger Zustand)',
  },
  'net-doh': {
    dangerLevel: 'dangerous',
    affectsFirewall: false, affectsDNS: true, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: true, requiresReboot: false,
    whatChanges: 'Setzt DNS auf Cloudflare (1.1.1.1, 1.0.0.1) und aktiviert DoH',
    whatCouldBreak: ['DNS-Auflösung könnte kurzzeitig fehlschlagen', 'Interne Firmen-DNS funktionieren nicht mehr', 'VPN-Split-DNS könnte gestört werden'],
    undoCommand: '$iface=(Get-NetAdapter|Where-Object Status -eq "Up"|Select-Object -First 1).InterfaceIndex; Set-DnsClientServerAddress -InterfaceIndex $iface -ResetServerAddresses',
    undoDescription: 'DNS wird auf DHCP-Standard zurückgesetzt',
  },
  'net-stealth': {
    dangerLevel: 'dangerous',
    affectsFirewall: true, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: true, requiresReboot: false,
    whatChanges: 'Erstellt 2 Firewall-Regeln: Blockiert ICMP ein- und ausgehend (Ping)',
    whatCouldBreak: ['Ping funktioniert nicht mehr', 'Netzwerk-Diagnose erschwert', 'Manche VPNs brauchen ICMP'],
    undoCommand: 'Remove-NetFirewallRule -DisplayName "Sentinel-Block-ICMPv4-In" -EA SilentlyContinue; Remove-NetFirewallRule -DisplayName "Sentinel-Block-ICMPv4-Out" -EA SilentlyContinue',
    undoDescription: 'Sentinel ICMP-Block-Regeln werden entfernt',
  },
  'net-zerotrust': {
    dangerLevel: 'dangerous',
    affectsFirewall: true, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: true, requiresReboot: false,
    whatChanges: 'Setzt Public-Profil auf "Eingehend blockieren" (DefaultInboundAction Block)',
    whatCouldBreak: ['Eingehende Verbindungen auf Public-Profil werden blockiert', 'P2P-Programme könnten nicht mehr funktionieren', 'Remote Desktop auf Public-Netzwerk unmöglich'],
    undoCommand: 'Set-NetFirewallProfile -Name Public -DefaultInboundAction Allow',
    undoDescription: 'Public-Profil wird auf "Eingehend erlauben" zurückgesetzt',
  },
  'net-domrep': {
    dangerLevel: 'dangerous',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: true, requiresReboot: false,
    whatChanges: 'Aktiviert Windows Defender Network Protection + PUA-Schutz',
    whatCouldBreak: ['Defender könnte legitime Downloads als PUA blockieren', 'Manche Websites könnten gesperrt werden'],
    undoCommand: 'Set-MpPreference -EnableNetworkProtection 0; Set-MpPreference -PUAProtection 0',
    undoDescription: 'Network Protection und PUA-Schutz werden deaktiviert',
  },
  'net-geoip': {
    dangerLevel: 'dangerous',
    affectsFirewall: true, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: true, requiresReboot: false,
    whatChanges: 'Erstellt Geo-IP Firewall-Regel (initial deaktiviert)',
    whatCouldBreak: ['Falls aktiviert: Verbindungen aus bestimmten Ländern werden blockiert'],
    undoCommand: 'Remove-NetFirewallRule -DisplayName "Sentinel-GeoBlock-Inbound" -EA SilentlyContinue',
    undoDescription: 'Geo-Block Firewall-Regel wird entfernt',
  },
  'net-torblock': {
    dangerLevel: 'dangerous',
    affectsFirewall: true, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: true, requiresReboot: false,
    whatChanges: 'Blockiert ausgehende Tor-Ports (9001, 9030, 9050, 9051, 9150)',
    whatCouldBreak: ['Tor Browser funktioniert nicht mehr', 'Dienste auf diesen Ports werden blockiert'],
    undoCommand: 'Remove-NetFirewallRule -DisplayName "Sentinel-Block-Tor-Ports" -EA SilentlyContinue',
    undoDescription: 'Tor-Block Firewall-Regel wird entfernt',
  },
  'net-arp': {
    dangerLevel: 'dangerous',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: true, requiresReboot: false,
    whatChanges: 'Setzt statischen ARP-Eintrag für das Standard-Gateway',
    whatCouldBreak: ['Falls Gateway-MAC sich ändert (Router-Wechsel) → kein Netzwerk'],
    undoCommand: 'arp -d *',
    undoDescription: 'ARP-Tabelle wird geleert (dynamisch neu aufgebaut)',
  },
  'priv-dnsleak': {
    dangerLevel: 'dangerous',
    affectsFirewall: false, affectsDNS: true, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: true, requiresReboot: false,
    whatChanges: 'Setzt DNS auf Cloudflare (1.1.1.1, 1.0.0.1) auf dem physischen Adapter',
    whatCouldBreak: ['DNS-Auflösung könnte kurzzeitig fehlschlagen', 'Firmen-DNS funktioniert nicht mehr'],
    undoCommand: '$iface=(Get-NetAdapter|Where-Object{$_.Status-eq"Up"-and$_.InterfaceDescription-notmatch"NordLynx|WireGuard|TAP-|TUN|OpenVPN"}|Select-Object -First 1).InterfaceIndex; Set-DnsClientServerAddress -InterfaceIndex $iface -ResetServerAddresses; ipconfig /flushdns',
    undoDescription: 'DNS wird auf DHCP-Standard zurückgesetzt, DNS-Cache geleert',
  },
  'net-dpi': {
    dangerLevel: 'dangerous',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: true, requiresReboot: true,
    whatChanges: 'Deaktiviert TLS 1.0 und SSL 3.0 in der Windows SCHANNEL-Registry',
    whatCouldBreak: ['Alte Websites die nur TLS 1.0 nutzen laden nicht mehr', 'Legacy-Anwendungen könnten Verbindungsfehler haben'],
    undoCommand: '$base="HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols"; @("SSL 3.0","TLS 1.0")|ForEach-Object{$p="$base\\$_\\Client";Set-ItemProperty -Path $p -Name Enabled -Value 1 -Type DWord -Force;Set-ItemProperty -Path $p -Name DisabledByDefault -Value 0 -Type DWord -Force;$s="$base\\$_\\Server";Set-ItemProperty -Path $s -Name Enabled -Value 1 -Type DWord -Force;Set-ItemProperty -Path $s -Name DisabledByDefault -Value 0 -Type DWord -Force}',
    undoDescription: 'TLS 1.0 und SSL 3.0 werden wieder aktiviert',
  },
  'edr-wmi': {
    dangerLevel: 'dangerous',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Entfernt verdächtige WMI Event-Consumer (Persistenz-Mechanismus)',
    whatCouldBreak: ['Legitime WMI-Abonnements könnten entfernt werden', 'Monitoring-Tools könnten aufhören zu funktionieren'],
    undoCommand: '',
    undoDescription: 'WMI-Consumer müssen manuell neu erstellt werden — kein automatisches Undo',
  },
  'edr-critfiles': {
    dangerLevel: 'dangerous',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Setzt Deny-Write ACLs auf cmd.exe, powershell.exe, wscript.exe',
    whatCouldBreak: ['Sentinel selbst nutzt PowerShell → Scans könnten fehlschlagen', 'Andere Programme die PS aufrufen werden blockiert', 'Admin-Tools funktionieren nicht mehr'],
    undoCommand: '$paths=@("C:\\Windows\\System32\\cmd.exe","C:\\Windows\\System32\\powershell.exe","C:\\Windows\\System32\\wscript.exe");foreach($p in $paths){$a=Get-Acl $p -EA SilentlyContinue;if($a){$a.Access|Where-Object{$_.IdentityReference-eq"BUILTIN\\Users"-and$_.FileSystemRights-eq"Write"-and$_.AccessControlType-eq"Deny"}|ForEach-Object{$a.RemoveAccessRule($_)};Set-Acl $p $a -EA SilentlyContinue}}',
    undoDescription: 'Deny-Write ACLs werden von cmd.exe, powershell.exe, wscript.exe entfernt',
  },

  // ═══════════════════════════════════════════════════════════════
  // 🟡 CAUTION — Registry/service changes, no direct connectivity impact
  // ═══════════════════════════════════════════════════════════════
  'net-tcphard': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'TCP SYN-Attack-Schutz + Dead-GW-Detect aus + PMTU-Discovery an',
    whatCouldBreak: ['Netzwerk-Verhalten ändert sich nach Neustart'],
    undoCommand: 'Remove-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" -Name SynAttackProtect -EA SilentlyContinue; Remove-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" -Name EnableDeadGWDetect -EA SilentlyContinue; Remove-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" -Name EnablePMTUDiscovery -EA SilentlyContinue',
    undoDescription: 'TCP-Parameter werden auf Windows-Standard zurückgesetzt',
  },
  'net-alg': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: true,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Stoppt und deaktiviert den ALG-Dienst (Application Layer Gateway)',
    whatCouldBreak: ['FTP über Firewall könnte nicht mehr funktionieren'],
    undoCommand: 'Set-Service ALG -StartupType Manual; Start-Service ALG -EA SilentlyContinue',
    undoDescription: 'ALG-Dienst wird wieder auf Manual gesetzt und gestartet',
  },
  'net-smbkill': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert SMBv1-Protokoll',
    whatCouldBreak: ['Sehr alte Netzwerkgeräte (vor 2012) nicht mehr erreichbar'],
    undoCommand: 'Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force',
    undoDescription: 'SMBv1 wird wieder aktiviert',
  },
  'kernel-vbs': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Aktiviert VBS (Virtualization-Based Security) und HVCI',
    whatCouldBreak: ['Performance-Einbußen möglich (~5%)', 'Inkompatible Treiber könnten nicht mehr laden', 'Neustart erforderlich'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" -Name EnableVirtualizationBasedSecurity -Value 0 -Type DWord -Force; Remove-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity" -Name Enabled -EA SilentlyContinue',
    undoDescription: 'VBS/HVCI wird deaktiviert (Neustart nötig)',
  },
  'kernel-dse': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Erzwingt Treiber-Signatur (nointegritychecks=off, testsigning=off)',
    whatCouldBreak: ['Unsigned-Treiber werden nicht mehr geladen'],
    undoCommand: '',
    undoDescription: 'Treiber-Signatur ist ein Sicherheitsstandard — Undo nicht empfohlen',
  },
  'kernel-elam': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: true,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Setzt WdFilter-Dienst auf Boot-Start (Early Launch Anti-Malware)',
    whatCouldBreak: ['Sollte keine Probleme verursachen — Standard-Sicherheitsfunktion'],
    undoCommand: 'Set-Service WdFilter -StartupType Manual -EA SilentlyContinue',
    undoDescription: 'WdFilter auf Manual zurücksetzen',
  },
  'kernel-tpm': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Initialisiert das TPM (Trusted Platform Module)',
    whatCouldBreak: ['BitLocker-Schlüssel könnten ungültig werden', 'Firmware-TPM Reset möglich'],
    undoCommand: '',
    undoDescription: 'TPM-Initialisierung ist nicht automatisch rückgängig machbar',
  },
  'kernel-secureboot': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Prüft nur den Secure Boot Status (keine Änderung)',
    whatCouldBreak: [],
    undoCommand: '', undoDescription: 'Nur Statusprüfung — kein Undo nötig',
  },
  'kernel-shadowstack': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Aktiviert CET Shadow Stack (Hardware-basierter ROP-Schutz)',
    whatCouldBreak: ['Inkompatible Programme könnten abstürzen'],
    undoCommand: 'Set-ProcessMitigation -System -Disable UserShadowStack -EA SilentlyContinue',
    undoDescription: 'CET Shadow Stack wird deaktiviert',
  },
  'kernel-patchguard': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Erzwingt Kernel-Integrität (nointegritychecks=off, testsigning=off)',
    whatCouldBreak: ['Unsigned-Treiber werden nicht mehr geladen'],
    undoCommand: '', undoDescription: 'Kernel-Integrität ist Standard — Undo nicht empfohlen',
  },
  'kernel-iommu': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Zeigt Info-Meldung über BIOS/UEFI VT-d Einstellung (keine Änderung)',
    whatCouldBreak: [],
    undoCommand: '', undoDescription: 'Nur Info — kein Undo nötig',
  },
  'kernel-vulndrivers': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert die Microsoft Vulnerable Driver Blocklist',
    whatCouldBreak: ['Alte/unsichere Treiber könnten nicht mehr geladen werden'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config" -Name VulnerableDriverBlocklistEnable -Value 0 -Type DWord -Force',
    undoDescription: 'Vulnerable Driver Blocklist wird deaktiviert',
  },
  'kernel-unsigneddrivers': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Erzwingt Treiber-Signatur via bcdedit',
    whatCouldBreak: ['Unsigned-Treiber werden nicht mehr geladen'],
    undoCommand: '', undoDescription: 'Treiber-Signatur ist Standard — Undo nicht empfohlen',
  },
  'kernel-msr': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Setzt CPU Spectre/Meltdown Mitigation-Flags',
    whatCouldBreak: ['Minimale Performance-Einbußen möglich'],
    undoCommand: 'Remove-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" -Name FeatureSettingsOverride -EA SilentlyContinue; Remove-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" -Name FeatureSettingsOverrideMask -EA SilentlyContinue',
    undoDescription: 'CPU-Mitigation-Flags werden auf Windows-Standard zurückgesetzt',
  },

  // ─── EDR ───
  'edr-amsi': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert AMSI Script-Scanning in Windows Defender',
    whatCouldBreak: [],
    undoCommand: 'Set-MpPreference -DisableScriptScanning $true -EA SilentlyContinue',
    undoDescription: 'AMSI Script-Scanning wird deaktiviert',
  },
  'edr-lsass': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Aktiviert LSASS Protected Process Light (RunAsPPL=1)',
    whatCouldBreak: ['Credential-Tools funktionieren nicht mehr', 'Neustart erforderlich'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name RunAsPPL -Value 0 -Type DWord -Force',
    undoDescription: 'LSASS PPL wird deaktiviert (Neustart nötig)',
  },
  'edr-lsa': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Aktiviert LSA Protection (RunAsPPL=1)',
    whatCouldBreak: ['Credential-Tools funktionieren nicht mehr', 'Neustart erforderlich'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name RunAsPPL -Value 0 -Type DWord -Force',
    undoDescription: 'LSA Protection wird deaktiviert (Neustart nötig)',
  },
  'edr-token': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert UAC (EnableLUA=1)',
    whatCouldBreak: ['UAC-Prompts erscheinen bei Admin-Aktionen'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name EnableLUA -Value 0 -Type DWord -Force',
    undoDescription: 'UAC wird deaktiviert (nicht empfohlen)',
  },
  'edr-memscan': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert Real-Time Protection, Behavior Monitoring, IOAV Protection',
    whatCouldBreak: [],
    undoCommand: 'Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableBehaviorMonitoring $true; Set-MpPreference -DisableIOAVProtection $true',
    undoDescription: 'Echtzeit-Schutz wird deaktiviert (nicht empfohlen)',
  },
  'edr-mitigations': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert DEP, CFG und SEHOP systemweit',
    whatCouldBreak: ['Sehr alte Software könnte abstürzen'],
    undoCommand: 'Set-ProcessMitigation -System -Disable DEP,CFG,SEHOP -EA SilentlyContinue',
    undoDescription: 'DEP/CFG/SEHOP werden deaktiviert',
  },
  'edr-scriptlog': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert PowerShell Script-Block-Logging',
    whatCouldBreak: ['Log-Dateien werden größer'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 0 -Type DWord -Force',
    undoDescription: 'Script-Block-Logging wird deaktiviert',
  },
  'edr-cig': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert den Microsoft Vulnerable Driver Blocklist',
    whatCouldBreak: ['Bekannte unsichere Treiber werden blockiert'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config" -Name VulnerableDriverBlocklistEnable -Value 0 -Type DWord -Force',
    undoDescription: 'Driver Blocklist wird deaktiviert',
  },
  'edr-etw': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Startet ETW Threat Intelligence Trace-Session',
    whatCouldBreak: [],
    undoCommand: 'logman stop "Sentinel-ETW-TI" -ets -EA SilentlyContinue',
    undoDescription: 'ETW Trace-Session wird gestoppt',
  },
  'edr-autorun': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Listet Autorun-Einträge auf (nur Audit, keine Änderung)',
    whatCouldBreak: [],
    undoCommand: '', undoDescription: 'Nur Audit — kein Undo nötig',
  },
  'edr-sandbox': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: true, requiresReboot: false,
    whatChanges: 'Aktiviert Windows Defender Network Protection',
    whatCouldBreak: ['Manche Websites könnten blockiert werden'],
    undoCommand: 'Set-MpPreference -EnableNetworkProtection 0 -EA SilentlyContinue',
    undoDescription: 'Network Protection wird deaktiviert',
  },

  // ─── Performance ───
  'perf-ultimate': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Setzt Energiesparplan auf "Höchstleistung"',
    whatCouldBreak: ['Höherer Stromverbrauch bei Laptops'],
    undoCommand: 'powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e',
    undoDescription: 'Energiesparplan wird auf "Ausbalanciert" zurückgesetzt',
  },
  'perf-superfetch': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: true,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Stoppt und deaktiviert SysMain (Superfetch)',
    whatCouldBreak: ['App-Startzeiten auf HDDs könnten langsamer werden'],
    undoCommand: 'Set-Service SysMain -StartupType Automatic; Start-Service SysMain -EA SilentlyContinue',
    undoDescription: 'SysMain wird wieder aktiviert und gestartet',
  },
  'perf-coreparking': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert CPU Core Parking (alle Kerne immer aktiv)',
    whatCouldBreak: ['Höherer Stromverbrauch'],
    undoCommand: 'powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 5; powercfg /setactive SCHEME_CURRENT',
    undoDescription: 'Core Parking wird wieder aktiviert (5% Minimum)',
  },
  'perf-storage': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert Windows Storage Sense',
    whatCouldBreak: [],
    undoCommand: 'Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy" -Name "01" -Value 0 -Type DWord -Force',
    undoDescription: 'Storage Sense wird deaktiviert',
  },
  'perf-timer': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Setzt High-Precision Timer via bcdedit',
    whatCouldBreak: ['Neustart erforderlich', 'Minimale Performance-Änderung'],
    undoCommand: 'bcdedit /deletevalue useplatformtick; bcdedit /deletevalue disabledynamictick',
    undoDescription: 'Timer-Einstellungen werden auf Windows-Standard zurückgesetzt',
  },
  'perf-largepages': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Gewährt "Lock Pages in Memory" Recht für den aktuellen User',
    whatCouldBreak: ['Erfordert Neustart für Wirkung'],
    undoCommand: '',
    undoDescription: 'Muss manuell in secpol.msc entfernt werden',
  },
  'perf-irq': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert RSS (Receive Side Scaling) auf dem primären Netzwerk-Adapter',
    whatCouldBreak: [],
    undoCommand: '$a=Get-NetAdapter|Where-Object Status -eq "Up"|Select-Object -First 1; Disable-NetAdapterRss -Name $a.Name -EA SilentlyContinue',
    undoDescription: 'RSS wird auf dem primären Adapter deaktiviert',
  },
  'perf-bcdedit': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Optimiert Boot-Timer-Präzision via bcdedit',
    whatCouldBreak: ['Neustart erforderlich'],
    undoCommand: 'bcdedit /deletevalue disabledynamictick; bcdedit /deletevalue useplatformtick',
    undoDescription: 'Timer-Einstellungen werden auf Standard zurückgesetzt',
  },
  'perf-bgapps': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert Hintergrund-UWP-Apps',
    whatCouldBreak: ['Store-Apps erhalten keine Hintergrund-Updates'],
    undoCommand: 'Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications" -Name GlobalUserDisabled -Value 0 -Type DWord -Force',
    undoDescription: 'Hintergrund-Apps werden wieder aktiviert',
  },
  'perf-hags': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Aktiviert Hardware-beschleunigte GPU-Planung (HAGS)',
    whatCouldBreak: ['Manche Spiele/Apps könnten Grafikfehler zeigen', 'Neustart erforderlich'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers" -Name HwSchMode -Value 1 -Type DWord -Force',
    undoDescription: 'HAGS wird deaktiviert (Neustart nötig)',
  },
  'perf-telemetry': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: true,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Stoppt und deaktiviert DiagTrack + dmwappushservice',
    whatCouldBreak: ['Windows-Feedback und Telemetrie werden deaktiviert'],
    undoCommand: 'Set-Service DiagTrack -StartupType Automatic; Start-Service DiagTrack -EA SilentlyContinue; Set-Service dmwappushservice -StartupType Automatic -EA SilentlyContinue; Start-Service dmwappushservice -EA SilentlyContinue',
    undoDescription: 'Telemetrie-Dienste werden wieder aktiviert',
  },
  'perf-winsxs': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Bereinigt den WinSxS Component Store mit DISM',
    whatCouldBreak: ['Alte Update-Pakete werden gelöscht — kein Rollback mehr möglich'],
    undoCommand: '',
    undoDescription: 'Bereinigung kann nicht rückgängig gemacht werden',
  },
  'perf-writecache': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert Disk Write Cache auf Datenträger 0',
    whatCouldBreak: ['Bei Stromausfall: höheres Risiko für Datenverlust'],
    undoCommand: 'Set-Disk -Number 0 -IsCacheEnabled $false -EA SilentlyContinue',
    undoDescription: 'Write Cache wird deaktiviert',
  },
  'perf-pagefile': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Setzt Auslagerungsdatei auf automatisch verwaltet',
    whatCouldBreak: [],
    undoCommand: '', undoDescription: 'Windows verwaltet die Auslagerungsdatei bereits optimal',
  },
  'perf-standby': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Leert die Standby-Liste (cached RAM freigeben)',
    whatCouldBreak: [],
    undoCommand: '', undoDescription: 'RAM wird automatisch wieder gecached — kein Undo nötig',
  },
  'perf-ioprio': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: true,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Stoppt BITS und Windows Update Dienste temporär',
    whatCouldBreak: ['Laufende Downloads werden abgebrochen', 'Windows-Updates pausiert'],
    undoCommand: 'Start-Service BITS -EA SilentlyContinue; Start-Service wuauserv -EA SilentlyContinue',
    undoDescription: 'BITS und Windows Update werden wieder gestartet',
  },
  'perf-mft': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Führt chkdsk /scan auf C: aus',
    whatCouldBreak: ['Kann bei großen Festplatten mehrere Minuten dauern'],
    undoCommand: '', undoDescription: 'Nur Scan — kein Undo nötig',
  },
  'perf-etw': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Startet ETW Performance Trace-Session',
    whatCouldBreak: [],
    undoCommand: 'logman stop "Sentinel-Perf" -ets -EA SilentlyContinue',
    undoDescription: 'ETW Trace-Session wird gestoppt',
  },

  // ─── Privacy ───
  'priv-usb': {
    dangerLevel: 'dangerous',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert USB Mass Storage Treiber (USBSTOR Start=4)',
    whatCouldBreak: [
      'USB-Sticks und externe Festplatten werden SOFORT nicht mehr erkannt',
      'WARNUNG: Falls Sentinel oder Windows von einer externen USB-Festplatte läuft, wird das System unbrauchbar!',
      'WARNING: If Sentinel or Windows runs from an external USB drive, the system will become unusable!',
      'Bereits angeschlossene USB-Geräte könnten den Zugriff verlieren',
    ],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name Start -Value 3 -Type DWord -Force',
    undoDescription: 'USB Mass Storage wird wieder aktiviert (Neustart ggf. erforderlich)',
  },
  'priv-lockscreen': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert Lockscreen-Kamera und Cortana auf Lockscreen',
    whatCouldBreak: [],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization" -Name NoLockScreenCamera -Value 0 -Type DWord -Force; Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search" -Name AllowCortanaAboveLock -Value 1 -Type DWord -Force',
    undoDescription: 'Lockscreen-Kamera und Cortana werden wieder aktiviert',
  },
  'priv-bluetooth': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: true,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Stoppt und deaktiviert den Bluetooth-Dienst',
    whatCouldBreak: ['Bluetooth-Geräte (Maus, Tastatur, Kopfhörer) funktionieren nicht mehr'],
    undoCommand: 'Set-Service bthserv -StartupType Manual; Start-Service bthserv -EA SilentlyContinue',
    undoDescription: 'Bluetooth-Dienst wird wieder aktiviert',
  },
  'priv-gpo': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Erzwingt UAC, Secure Desktop, blockiert AlwaysInstallElevated',
    whatCouldBreak: ['UAC-Prompts erscheinen häufiger'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord -Force; Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name PromptOnSecureDesktop -Value 0 -Type DWord -Force',
    undoDescription: 'UAC wird auf Standard zurückgesetzt',
  },
  'priv-telemetry': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: true,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Setzt Telemetrie auf "Security" (0) und deaktiviert DiagTrack',
    whatCouldBreak: ['Keine Feedback-Daten an Microsoft', 'Manche Diagnose-Features fehlen'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" -Name AllowTelemetry -Value 3 -Type DWord -Force; Set-Service DiagTrack -StartupType Automatic; Start-Service DiagTrack -EA SilentlyContinue',
    undoDescription: 'Telemetrie wird auf "Full" zurückgesetzt, DiagTrack gestartet',
  },
  'priv-cortana': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert Cortana und Bing-Suche im Startmenü',
    whatCouldBreak: [],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search" -Name AllowCortana -Value 1 -Type DWord -Force; Remove-ItemProperty -Path "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer" -Name DisableSearchBoxSuggestions -EA SilentlyContinue',
    undoDescription: 'Cortana und Bing-Suche werden wieder aktiviert',
  },
  'priv-adid': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert die Windows Advertising ID',
    whatCouldBreak: [],
    undoCommand: 'Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo" -Name Enabled -Value 1 -Type DWord -Force',
    undoDescription: 'Advertising ID wird wieder aktiviert',
  },
  'priv-location': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert Standort-Tracking',
    whatCouldBreak: ['Wetter-Apps und Kartenanwendungen haben keinen Standort mehr'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors" -Name DisableLocation -Value 0 -Type DWord -Force',
    undoDescription: 'Standort-Tracking wird wieder aktiviert',
  },
  'priv-clipboard': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert den Zwischenablage-Verlauf',
    whatCouldBreak: ['Win+V funktioniert nicht mehr'],
    undoCommand: 'Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Clipboard" -Name EnableClipboardHistory -Value 1 -Type DWord -Force',
    undoDescription: 'Zwischenablage-Verlauf wird wieder aktiviert',
  },
  'priv-cammic': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Blockiert globalen Zugriff auf Webcam und Mikrofon',
    whatCouldBreak: ['Video-Calls (Teams, Zoom, Discord) funktionieren nicht mehr', 'Spracherkennung nicht verfügbar'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam" -Name Value -Value "Allow" -Force; Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone" -Name Value -Value "Allow" -Force',
    undoDescription: 'Webcam und Mikrofon werden wieder freigegeben',
  },
  'priv-wer': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: true,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert Windows Error Reporting',
    whatCouldBreak: ['Crash-Reports werden nicht mehr gesendet'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting" -Name Disabled -Value 0 -Type DWord -Force; Set-Service WerSvc -StartupType Manual; Start-Service WerSvc -EA SilentlyContinue',
    undoDescription: 'Windows Error Reporting wird wieder aktiviert',
  },
  'priv-wifisense': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert WiFi Sense (automatisches Verbinden)',
    whatCouldBreak: [],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config" -Name AutoConnectAllowedOEM -Value 1 -Type DWord -Force',
    undoDescription: 'WiFi Sense wird wieder aktiviert',
  },
  'priv-uac': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Erzwingt strenge UAC-Einstellungen (Secure Desktop, Consent-Prompt)',
    whatCouldBreak: ['Häufigere UAC-Prompts'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord -Force; Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name PromptOnSecureDesktop -Value 0 -Type DWord -Force',
    undoDescription: 'UAC wird auf Windows-Standard zurückgesetzt',
  },
  'priv-hwid': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Setzt Deny-ReadKey ACL auf SystemInformation Registry-Key',
    whatCouldBreak: ['Manche Lizenz-Software könnte die Hardware-ID nicht mehr lesen'],
    undoCommand: 'Import-Module Microsoft.PowerShell.Security -EA Stop; $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions); $acl=$key.GetAccessControl(); $acl.Access|Where-Object{$_.IdentityReference.Value-eq"BUILTIN\\Users"-and$_.AccessControlType-eq"Deny"}|ForEach-Object{$acl.RemoveAccessRule($_)}; $key.SetAccessControl($acl); $key.Close()',
    undoDescription: 'Deny-ACL wird von SystemInformation entfernt',
  },
  'priv-antikeylog': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert Tipp-Datenerfassung (TIPC)',
    whatCouldBreak: [],
    undoCommand: 'Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Input\\TIPC" -Name Enabled -Value 1 -Type DWord -Force',
    undoDescription: 'Tipp-Datenerfassung wird wieder aktiviert',
  },
  'priv-fingerprint': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert Aktivitäts-Tracking (Start_TrackProgs, Start_TrackDocs)',
    whatCouldBreak: ['Zuletzt verwendet Liste im Startmenü wird leer'],
    undoCommand: 'Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" -Name Start_TrackProgs -Value 1 -Type DWord -Force; Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" -Name Start_TrackDocs -Value 1 -Type DWord -Force',
    undoDescription: 'Aktivitäts-Tracking wird wieder aktiviert',
  },

  // ═══════════════════════════════════════════════════════════════
  // EDR — Neu hinzugefügte Fixes
  // ═══════════════════════════════════════════════════════════════
  'edr-syscall': {
    dangerLevel: 'dangerous',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Prüft VBS-Kompatibilität, aktiviert HVCI + VBS, startet ETW Syscall-Tracing',
    whatCouldBreak: ['Hardware ohne VBS/Hyper-V: Fix wird abgebrochen mit Fehlermeldung', 'Ältere Treiber ohne HVCI-Kompatibilität könnten nicht laden', 'Neustart erforderlich'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity" -Name Enabled -Value 0 -Type DWord -Force; Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" -Name EnableVirtualizationBasedSecurity -Value 0 -Type DWord -Force; logman stop "Sentinel-Syscall-ETW" -ets -EA SilentlyContinue',
    undoDescription: 'HVCI + VBS deaktiviert, ETW Syscall-Tracing gestoppt (Neustart erforderlich)',
  },
  'edr-honeypot': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Platziert versteckte Canary-Dateien in Documents, Desktop und Public Documents',
    whatCouldBreak: [],
    undoCommand: 'Remove-Item "$env:USERPROFILE\\Documents\\.sentinel_canary.docx" -Force -EA SilentlyContinue; Remove-Item "$env:USERPROFILE\\Desktop\\.sentinel_canary.docx" -Force -EA SilentlyContinue; Remove-Item "$env:PUBLIC\\Documents\\.sentinel_canary.docx" -Force -EA SilentlyContinue',
    undoDescription: 'Canary-Dateien aus allen Verzeichnissen entfernen',
  },
  'edr-hollowing': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Scannt laufende Prozesse auf Process-Hollowing-Indikatoren (nur Analyse)',
    whatCouldBreak: [],
    undoCommand: '',
    undoDescription: 'Nur Analyse — keine Systemänderungen',
  },
  'edr-reflectivedll': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert DEP, CFG, SEHOP und ForceRelocateImages systemweit',
    whatCouldBreak: ['Sehr alte 32-Bit-Software könnte abstürzen', 'Die meisten modernen Programme sind kompatibel'],
    undoCommand: 'Set-ProcessMitigation -System -Disable DEP,CFG,SEHOP,ForceRelocateImages -EA SilentlyContinue',
    undoDescription: 'Exploit-Mitigationen werden systemweit deaktiviert',
  },
  'edr-apc': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert Process-Creation-Auditing mit Kommandozeilen-Logging (Event 4688)',
    whatCouldBreak: ['Erhöhtes Audit-Log-Volumen', 'Geringe Leistungsauswirkung'],
    undoCommand: 'auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable',
    undoDescription: 'Process-Creation-Auditing wird deaktiviert',
  },
  'edr-entropy': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert Controlled Folder Access (überwachter Ordnerzugriff) gegen Ransomware',
    whatCouldBreak: ['Nicht-whitegelistete Programme können nicht in geschützte Ordner schreiben', 'Manuelle Ausnahmen für Spiele/Tools nötig'],
    undoCommand: 'Set-MpPreference -EnableControlledFolderAccess Disabled -EA SilentlyContinue',
    undoDescription: 'Überwachter Ordnerzugriff wird deaktiviert',
  },
  'edr-ppid': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert Process-Creation-Auditing (Event ID 4688) mit Kommandozeilen-Logging',
    whatCouldBreak: ['Erhöhtes Audit-Log-Volumen'],
    undoCommand: 'auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable',
    undoDescription: 'Process-Creation-Auditing wird deaktiviert',
  },
  'edr-com': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Zählt und listet benutzerbasierte COM-CLSIDs auf (nur Analyse)',
    whatCouldBreak: [],
    undoCommand: '',
    undoDescription: 'Nur Analyse — keine Systemänderungen',
  },
  'edr-behavior': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert Network Protection und PUA Protection in Defender',
    whatCouldBreak: ['Potentiell unerwünschte Programme werden blockiert'],
    undoCommand: 'Set-MpPreference -EnableNetworkProtection 0 -EA SilentlyContinue; Set-MpPreference -PUAProtection 0 -EA SilentlyContinue',
    undoDescription: 'Network Protection und PUA Protection werden deaktiviert',
  },
  'edr-apimap': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Prüft ob Sysmon installiert ist und gibt Installationsanleitung aus',
    whatCouldBreak: [],
    undoCommand: '',
    undoDescription: 'Nur Statusprüfung — keine Systemänderungen',
  },
  'edr-handles': {
    dangerLevel: 'dangerous',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: true,
    whatChanges: 'Aktiviert LSASS PPL (Protected Process Light) + ASR-Regel gegen Credential-Stealing',
    whatCouldBreak: ['Einige ältere Authentifizierungs-Plugins könnten nicht mehr funktionieren', 'Neustart erforderlich für PPL'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name RunAsPPL -Value 0 -Type DWord -Force',
    undoDescription: 'LSASS PPL wird deaktiviert (Neustart erforderlich)',
  },
  'edr-namedpipe': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Scannt Named Pipes auf verdächtige C2-Kommunikationskanäle (nur Analyse)',
    whatCouldBreak: [],
    undoCommand: '',
    undoDescription: 'Nur Analyse — keine Systemänderungen',
  },
  'edr-dlls': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert SafeDllSearchMode und entfernt CWD aus DLL-Suchpfad',
    whatCouldBreak: ['Portable Apps, die DLLs aus dem gleichen Verzeichnis laden, könnten betroffen sein'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" -Name SafeDllSearchMode -Value 0 -Type DWord -Force; Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" -Name CWDIllegalInDllSearch -Value 0 -Type DWord -Force',
    undoDescription: 'SafeDllSearchMode wird deaktiviert, CWD wieder im Suchpfad',
  },
  'edr-schtask': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Listet nicht-Microsoft geplante Aufgaben auf (nur Analyse)',
    whatCouldBreak: [],
    undoCommand: '',
    undoDescription: 'Nur Analyse — keine Systemänderungen',
  },
  'edr-svcaudit': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Listet nicht-Microsoft laufende Dienste auf (nur Analyse)',
    whatCouldBreak: [],
    undoCommand: '',
    undoDescription: 'Nur Analyse — keine Systemänderungen',
  },
  'edr-nla': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Erzwingt Network Level Authentication (NLA) für alle RDP-Verbindungen',
    whatCouldBreak: ['Ältere RDP-Clients ohne NLA-Unterstützung können nicht mehr verbinden'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name UserAuthentication -Value 0 -Type DWord -Force',
    undoDescription: 'NLA-Anforderung für RDP wird deaktiviert',
  },
  'edr-asr': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Aktiviert 16 ASR-Regeln im Audit-Modus (Office-Makros, Credential-Stealing, Skript-Blockierung)',
    whatCouldBreak: ['Im Audit-Modus wird nichts blockiert, nur protokolliert', 'Bei Wechsel zu Block-Modus könnten Office-Makros blockiert werden'],
    undoCommand: '$rules=@("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550","D4F940AB-401B-4EFC-AADC-AD5F3C50688A","3B576869-A4EC-4529-8536-B80A7769E899","75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84","D3E037E1-3EB8-44C8-A917-57927947596D","5BEB7EFE-FD9A-4556-801D-275E5FFC04CC","92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B","01443614-CD74-433A-B99E-2ECDC07BFC25","C1DB55AB-C21A-4637-BB3F-A12568109D35","9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2","D1E49AAC-8F56-4280-B9BA-993A6D77406C","B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4","26190899-1602-49E8-8B27-EB1D0A1CE869","7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C","E6DB77E5-3DF2-4CF1-B95A-636979351E5B","56A863A9-875E-4185-98A7-B882C64B5CE5"); foreach($r in $rules){ Add-MpPreference -AttackSurfaceReductionRules_Ids $r -AttackSurfaceReductionRules_Actions Disabled -EA SilentlyContinue }',
    undoDescription: 'Alle 16 ASR-Regeln werden deaktiviert',
  },
  'edr-etwti': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Startet ETW Threat-Intelligence-Provider für Kernel-Level-Telemetrie',
    whatCouldBreak: ['Minimale Leistungsauswirkung durch zusätzliche Telemetrie'],
    undoCommand: 'logman stop "Sentinel-ETW-TI" -ets -EA SilentlyContinue',
    undoDescription: 'ETW-TI-Provider wird gestoppt',
  },

  // ═══════════════════════════════════════════════════════════════
  // Kernel — Neu hinzugefügte Fixes
  // ═══════════════════════════════════════════════════════════════
  'kernel-privesc': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Härtet UAC (EnableLUA=1, ConsentPrompt=2, FilterAdminToken=1), deaktiviert AlwaysInstallElevated',
    whatCouldBreak: ['UAC-Eingabeaufforderungen erscheinen häufiger', 'Manche Installationspakete benötigen manuelle Erhöhung'],
    undoCommand: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name FilterAdministratorToken -Value 0 -Type DWord -Force; Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord -Force',
    undoDescription: 'UAC wird auf Standard-Stufe zurückgesetzt, FilterAdminToken deaktiviert',
  },
  'kernel-integrity': {
    dangerLevel: 'dangerous',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Führt System File Checker (sfc /scannow) aus — prüft und repariert beschädigte Systemdateien',
    whatCouldBreak: ['Kann bis zu 30 Minuten dauern', 'Beschädigte Dateien werden durch Windows-Originale ersetzt'],
    undoCommand: '',
    undoDescription: 'SFC-Reparaturen können nicht automatisch rückgängig gemacht werden — CBS.log enthält Details',
  },
  'kernel-driverpaths': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Listet Kernel-Treiber auf, die von Nicht-System-Pfaden geladen sind (nur Analyse)',
    whatCouldBreak: [],
    undoCommand: '',
    undoDescription: 'Nur Analyse — keine Systemänderungen',
  },
  'kernel-dkom': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Vergleicht WMI- und PS-Prozesszählung auf versteckte Prozesse (nur Analyse)',
    whatCouldBreak: [],
    undoCommand: '',
    undoDescription: 'Nur Analyse — keine Systemänderungen',
  },
  'kernel-microcode': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Prüft CPU-Microcode-Revision und zeigt Update-Anleitung (nur Analyse)',
    whatCouldBreak: [],
    undoCommand: '',
    undoDescription: 'Nur Analyse — keine Systemänderungen',
  },

  // ═══════════════════════════════════════════════════════════════
  // Netzwerk — Neu hinzugefügte Fixes
  // ═══════════════════════════════════════════════════════════════
  'net-beacon': {
    dangerLevel: 'safe',
    affectsFirewall: true, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Erstellt deaktivierte Platzhalter-Firewall-Regel für Beaconing-IPs',
    whatCouldBreak: ['Regel ist standardmäßig deaktiviert — keine sofortige Auswirkung'],
    undoCommand: 'Remove-NetFirewallRule -DisplayName "Sentinel-Block-Beacon-Placeholder" -EA SilentlyContinue',
    undoDescription: 'Platzhalter-Firewall-Regel wird entfernt',
  },
  'net-netflow': {
    dangerLevel: 'safe',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Listet nicht-standardmäßige lauschende Ports mit zugehörigen Prozessen auf (nur Analyse)',
    whatCouldBreak: [],
    undoCommand: '',
    undoDescription: 'Nur Analyse — keine Systemänderungen',
  },

  // ═══════════════════════════════════════════════════════════════
  // Performance — Neu hinzugefügte Fixes
  // ═══════════════════════════════════════════════════════════════
  'perf-dpc': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: true, affectsServices: false,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Deaktiviert USB-Energiesparmodus und USB-Selective-Suspend auf allen USB-Geräten',
    whatCouldBreak: ['Leicht erhöhter Stromverbrauch', 'Akkuleistung bei Laptops kann sinken'],
    undoCommand: 'Get-PnpDevice -Class USB -Status OK -EA SilentlyContinue | ForEach-Object { $path="HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\$($_.InstanceId)\\Device Parameters"; if(Test-Path $path){ Set-ItemProperty -Path $path -Name EnhancedPowerManagementEnabled -Value 1 -Type DWord -Force -EA SilentlyContinue } }',
    undoDescription: 'USB-Energiesparmodus wird wieder aktiviert',
  },
  'perf-memcomp': {
    dangerLevel: 'caution',
    affectsFirewall: false, affectsDNS: false, affectsRegistry: false, affectsServices: true,
    affectsConnectivity: false, requiresReboot: false,
    whatChanges: 'Optimiert Speicherkomprimierung basierend auf verfügbarem RAM (deaktiviert bei ≥16GB)',
    whatCouldBreak: ['Bei Systemen mit wenig RAM kann Deaktivierung zu mehr Paging führen'],
    undoCommand: 'Enable-MMAgent -MemoryCompression -EA SilentlyContinue',
    undoDescription: 'Speicherkomprimierung wird wieder aktiviert',
  },
};

/**
 * Get the full impact assessment for a fix.
 * If the fix has no classification entry, returns a conservative 'caution' default.
 */
export function getFixImpact(checkId: string, fixLabel: string): FixImpactAssessment {
  if (FORBIDDEN_FIX_IDS.has(checkId)) {
    return {
      dangerLevel: 'forbidden',
      whatChanges: FIX_CLASSIFICATIONS[checkId]?.whatChanges || fixLabel,
      whyNeeded: 'Sicherheitshärtung',
      whatCouldBreak: FIX_CLASSIFICATIONS[checkId]?.whatCouldBreak || ['Systemkritische Änderung'],
      affectsConnectivity: true,
      affectsFirewall: true,
      affectsDNS: false,
      affectsRegistry: false,
      affectsServices: false,
      requiresReboot: false,
      undoable: false,
      undoCommand: '',
      undoDescription: '',
      estimatedTime: '',
    };
  }

  const cls = FIX_CLASSIFICATIONS[checkId];
  if (!cls) {
    return {
      dangerLevel: 'caution',
      whatChanges: fixLabel,
      whyNeeded: 'Sicherheitshärtung',
      whatCouldBreak: ['Unbekannter Fix — Auswirkung nicht klassifiziert'],
      affectsConnectivity: false,
      affectsFirewall: false,
      affectsDNS: false,
      affectsRegistry: true,
      affectsServices: false,
      requiresReboot: false,
      undoable: false,
      undoCommand: '',
      undoDescription: 'Kein automatisches Undo verfügbar für unklassifizierte Fixes',
      estimatedTime: '< 10 Sekunden',
    };
  }

  return {
    dangerLevel: cls.dangerLevel,
    whatChanges: cls.whatChanges,
    whyNeeded: 'Sicherheitshärtung',
    whatCouldBreak: cls.whatCouldBreak,
    affectsConnectivity: cls.affectsConnectivity,
    affectsFirewall: cls.affectsFirewall,
    affectsDNS: cls.affectsDNS,
    affectsRegistry: cls.affectsRegistry,
    affectsServices: cls.affectsServices,
    requiresReboot: cls.requiresReboot,
    undoable: Boolean(cls.undoCommand),
    undoCommand: cls.undoCommand,
    undoDescription: cls.undoDescription || 'Kein automatisches Undo verfügbar',
    estimatedTime: cls.requiresReboot ? '< 10 Sekunden + Neustart' : '< 5 Sekunden',
  };
}
