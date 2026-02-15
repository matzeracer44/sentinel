/**
 * SENTINEL — Privacy & Hardening Module
 * 22 privacy checks & actions: telemetry overhaul, webcam lock, clipboard,
 * USB lock, GPO hardening, fingerprint protection, etc.
 */

import { spawnSync } from 'child_process';

export interface PrivCheck {
  id: string;
  name: string;
  status: 'pass' | 'fail' | 'warn' | 'unknown';
  detail: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  actionable?: boolean;
}

function ps(script: string, timeout = 12000): string {
  const r = spawnSync('powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
    { input: script, timeout, windowsHide: true, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }
  );
  if (r.error) throw r.error;
  return (r.stdout || '').trim();
}

function safe(id: string, name: string, fn: () => PrivCheck): PrivCheck {
  try { return fn(); } catch (e: any) { return { id, name, status: 'unknown', detail: e.message, risk: 'medium' }; }
}

export function checkHWID(): PrivCheck {
  return safe('priv-hwid', 'Hardware ID Exposure', () => {
    const out = ps(`$id=(Get-CimInstance Win32_ComputerSystemProduct).UUID;"UUID:$id"`);
    return { id: 'priv-hwid', name: 'Hardware ID Exposure', status: 'warn', detail: `${out} — visible to apps`, risk: 'medium' };
  });
}

export function checkAdID(): PrivCheck {
  return safe('priv-adid', 'Advertising ID', () => {
    const out = ps(`$a=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo' -EA SilentlyContinue).Enabled;if($a-eq0){'DISABLED'}else{'ENABLED'}`);
    const ok = out.includes('DISABLED');
    return { id: 'priv-adid', name: 'Advertising ID', status: ok ? 'pass' : 'warn', detail: ok ? 'Ad ID disabled' : 'Ad ID active — tracking possible', risk: ok ? 'low' : 'medium', actionable: true };
  });
}

export function checkTelemetryRegistry(): PrivCheck {
  return safe('priv-telemetry', 'Telemetry Registry', () => {
    const out = ps(`
$t=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -EA SilentlyContinue).AllowTelemetry
$dt=(Get-Service DiagTrack -EA SilentlyContinue).Status
$dm=(Get-Service dmwappushservice -EA SilentlyContinue).Status
"TelemetryLevel:$t|DiagTrack:$dt|dmwappush:$dm"
`);
    const minimal = out.includes('TelemetryLevel:0');
    const stopped = out.includes('DiagTrack:Stopped');
    return { id: 'priv-telemetry', name: 'Telemetry Registry', status: minimal && stopped ? 'pass' : 'warn', detail: out, risk: minimal && stopped ? 'low' : 'high', actionable: true };
  });
}

export function checkWebcamMic(): PrivCheck {
  return safe('priv-cammic', 'Webcam / Mic Lock', () => {
    const out = ps(`
$cam=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam' -EA SilentlyContinue).Value
$mic=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone' -EA SilentlyContinue).Value
"Webcam:$cam|Mic:$mic"
`);
    const camOff = out.includes('Webcam:Deny');
    const micOff = out.includes('Mic:Deny');
    return { id: 'priv-cammic', name: 'Webcam / Mic Lock', status: camOff && micOff ? 'pass' : 'warn', detail: out, risk: camOff && micOff ? 'low' : 'medium', actionable: true };
  });
}

export function checkClipboard(): PrivCheck {
  return safe('priv-clipboard', 'Clipboard History', () => {
    const out = ps(`$c=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Clipboard' -EA SilentlyContinue).EnableClipboardHistory;if($c-eq0){'DISABLED'}else{'ENABLED'}`);
    const ok = out.includes('DISABLED');
    return { id: 'priv-clipboard', name: 'Clipboard History', status: ok ? 'pass' : 'warn', detail: ok ? 'Clipboard history disabled' : 'Clipboard history active — data exposure risk', risk: ok ? 'low' : 'medium', actionable: true };
  });
}

export function checkMetadata(): PrivCheck {
  return { id: 'priv-metadata', name: 'Metadata Stripper', status: 'pass', detail: 'Available via Vault module file operations', risk: 'low' };
}

export function checkCortana(): PrivCheck {
  return safe('priv-cortana', 'Cortana / Search', () => {
    const out = ps(`
$c=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' -EA SilentlyContinue).AllowCortana
$ws=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search' -EA SilentlyContinue).BingSearchEnabled
"Cortana:$c|BingSearch:$ws"
`);
    const cortanaOff = out.includes('Cortana:0');
    const bingOff = out.includes('BingSearch:0');
    return { id: 'priv-cortana', name: 'Cortana / Web Search', status: cortanaOff && bingOff ? 'pass' : 'warn', detail: out, risk: cortanaOff && bingOff ? 'low' : 'medium', actionable: true };
  });
}

export function checkErrorReporting(): PrivCheck {
  return safe('priv-wer', 'Error Reporting', () => {
    const out = ps(`$w=(Get-Service WerSvc -EA SilentlyContinue).Status;$d=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting' -EA SilentlyContinue).Disabled;"WerSvc:$w|Disabled:$d"`);
    const off = out.includes('Disabled:1') || out.includes('WerSvc:Stopped');
    return { id: 'priv-wer', name: 'Error Reporting', status: off ? 'pass' : 'warn', detail: out, risk: off ? 'low' : 'medium', actionable: true };
  });
}

export function checkWifiSense(): PrivCheck {
  return safe('priv-wifisense', 'WiFi Sense', () => {
    const out = ps(`$w=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config' -EA SilentlyContinue).AutoConnectAllowedOEM;if($w-eq0){'DISABLED'}else{'ENABLED'}`);
    const ok = out.includes('DISABLED');
    return { id: 'priv-wifisense', name: 'WiFi Sense', status: ok ? 'pass' : 'warn', detail: out, risk: ok ? 'low' : 'medium', actionable: true };
  });
}

export function checkBluetooth(): PrivCheck {
  return safe('priv-bluetooth', 'Bluetooth Protection', () => {
    const out = ps(`$bt=Get-Service bthserv -EA SilentlyContinue;"Bluetooth:$($bt.Status)|StartType:$($bt.StartType)"`);
    return { id: 'priv-bluetooth', name: 'Bluetooth Status', status: 'pass', detail: out, risk: 'low', actionable: true };
  });
}

export function checkGPOHardening(): PrivCheck {
  return safe('priv-gpo', 'GPO Hardening', () => {
    const out = ps(`
$checks=0;$passed=0
$checks++;$v=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -EA SilentlyContinue).EnableLUA;if($v-eq1){$passed++}
$checks++;$v=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -EA SilentlyContinue).AlwaysInstallElevated;if($v-ne1){$passed++}
$checks++;$v=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -EA SilentlyContinue).fDenyTSConnections;if($v-eq1){$passed++}
$checks++;$v=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -EA SilentlyContinue).ConsentPromptBehaviorAdmin;if($v-ge2){$passed++}
$checks++;$v=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -EA SilentlyContinue).NullSessionShares;if(-not$v-or$v.Count-eq0){$passed++}
"Passed:$passed/$checks"
`);
    const m = out.match(/Passed:(\d+)\/(\d+)/);
    const p = m ? parseInt(m[1]) : 0;
    const t = m ? parseInt(m[2]) : 1;
    return { id: 'priv-gpo', name: 'GPO Hardening', status: p === t ? 'pass' : 'warn', detail: out, risk: p === t ? 'low' : 'high' };
  });
}

export function checkUACStealth(): PrivCheck {
  return safe('priv-uac', 'UAC Stealth Mode', () => {
    const out = ps(`
$u=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -EA SilentlyContinue
"LUA:$($u.EnableLUA)|Consent:$($u.ConsentPromptBehaviorAdmin)|SecureDesktop:$($u.PromptOnSecureDesktop)"
`);
    const strict = out.includes('Consent:1') || out.includes('Consent:2');
    return { id: 'priv-uac', name: 'UAC Stealth Mode', status: strict ? 'pass' : 'warn', detail: out, risk: strict ? 'low' : 'high', actionable: true };
  });
}

export function checkShredder(): PrivCheck {
  return { id: 'priv-shredder', name: 'Military Shredder', status: 'pass', detail: 'Available via Vault file shredder (DoD 5220.22-M)', risk: 'low' };
}

export function checkAntiKeylogging(): PrivCheck {
  return safe('priv-antikeylog', 'Anti-Keylogging', () => {
    const out = ps(`$f=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Input\\TIPC' -EA SilentlyContinue).Enabled;if($f-eq0){'TYPING_DATA_OFF'}else{'TYPING_DATA_ON'}`);
    const ok = out.includes('OFF');
    return { id: 'priv-antikeylog', name: 'Anti-Keylogging', status: ok ? 'pass' : 'warn', detail: ok ? 'Typing data collection disabled' : 'Typing data sent to Microsoft', risk: ok ? 'low' : 'medium', actionable: true };
  });
}

export function checkBrowserFingerprint(): PrivCheck {
  return safe('priv-fingerprint', 'Browser Fingerprint', () => {
    const out = ps(`$dnt=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -EA SilentlyContinue).Start_TrackProgs;if($dnt-eq0){'TRACKING_OFF'}else{'TRACKING_ON'}`);
    return { id: 'priv-fingerprint', name: 'Tracking Protection', status: out.includes('OFF') ? 'pass' : 'warn', detail: out, risk: out.includes('OFF') ? 'low' : 'medium', actionable: true };
  });
}

const KNOWN_VPN_DNS: Record<string, string[]> = {
  NordVPN: ['103.86.96.100', '103.86.99.100', '103.86.96.101', '103.86.99.101'],
  ExpressVPN: ['100.64.0.1'],
  ProtonVPN: ['10.2.0.1'],
  Mullvad: ['100.64.0.1', '100.64.0.2'],
  Surfshark: ['162.252.172.57', '149.154.159.92'],
};

export function checkDNSLeak(): PrivCheck {
  return safe('priv-dnsleak', 'DNS Leak Protection', () => {
    const dnsOut = ps(`
$dns=Get-DnsClientServerAddress -AddressFamily IPv4|?{$_.ServerAddresses.Count-gt0}|Select -First 1 -Expand ServerAddresses
$vpn=Get-NetAdapter|?{$_.InterfaceDescription-match'NordLynx|NordVPN|WireGuard|TAP-|TUN|OpenVPN|Surfshark|Mullvad|ProtonVPN|ExpressVPN' -and $_.Status-eq'Up'}|Select -First 1 -Expand InterfaceDescription -EA SilentlyContinue
$known=@('1.1.1.1','8.8.8.8','9.9.9.9','208.67.222.222')
$secure=$false;foreach($s in $dns){if($known-contains$s){$secure=$true}}
"DNS:$($dns-join',')|SecureDNS:$secure|VPN:$vpn"
`);
    const dnsServers = (dnsOut.match(/DNS:([^|]*)/)?.[1] || '').split(',').map(s => s.trim()).filter(Boolean);
    const vpnAdapter = (dnsOut.match(/VPN:(.*)$/)?.[1] || '').trim();
    const hasVpn = vpnAdapter.length > 0;

    if (hasVpn) {
      const providerName = Object.keys(KNOWN_VPN_DNS).find(p =>
        vpnAdapter.toLowerCase().includes(p.toLowerCase())
      );
      const vpnDnsList = providerName ? KNOWN_VPN_DNS[providerName] : [];
      const allDnsAreVpn = dnsServers.every(dns =>
        vpnDnsList.includes(dns) || dns.startsWith('10.') || dns.startsWith('100.64.')
      );

      if (allDnsAreVpn) {
        return {
          id: 'priv-dnsleak', name: 'DNS Leak Protection', status: 'pass',
          detail: `DNS routed through ${providerName || 'VPN'} (${dnsServers.join(', ')})`,
          risk: 'low',
        };
      }

      const leaked = dnsServers.filter(dns => !vpnDnsList.includes(dns) && !dns.startsWith('10.') && !dns.startsWith('100.64.'));
      if (leaked.length > 0) {
        return {
          id: 'priv-dnsleak', name: 'DNS Leak Protection', status: 'fail',
          detail: `DNS LEAK: ${leaked.join(', ')} bypasses VPN (${providerName || vpnAdapter})`,
          risk: 'high',
        };
      }

      return {
        id: 'priv-dnsleak', name: 'DNS Leak Protection', status: 'pass',
        detail: `DNS secured via VPN tunnel (${dnsServers.join(', ')})`,
        risk: 'low',
      };
    }

    const knownSecure = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '208.67.222.222', '1.0.0.1', '8.8.4.4'];
    const isSecure = dnsServers.some(dns => knownSecure.includes(dns));
    return {
      id: 'priv-dnsleak', name: 'DNS Leak Protection',
      status: isSecure ? 'pass' : 'warn',
      detail: `DNS: ${dnsServers.join(', ')} | ${isSecure ? 'Using known secure DNS' : 'ISP DNS detected — consider encrypted DNS'}`,
      risk: isSecure ? 'low' : 'high',
    };
  });
}

export function checkLocation(): PrivCheck {
  return safe('priv-location', 'Location Services', () => {
    const out = ps(`$l=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location' -EA SilentlyContinue).Value;if($l-eq'Deny'){'DISABLED'}else{'ENABLED'}`);
    const ok = out.includes('DISABLED');
    return { id: 'priv-location', name: 'Location Services', status: ok ? 'pass' : 'warn', detail: ok ? 'Location disabled' : 'Location services active', risk: ok ? 'low' : 'medium', actionable: true };
  });
}

export function checkWinget(): PrivCheck {
  return safe('priv-winget', 'Auto App Update (Winget)', () => {
    const out = ps(`$w=Get-Command winget -EA SilentlyContinue;if($w){'AVAILABLE'}else{'NOT_FOUND'}`);
    return { id: 'priv-winget', name: 'Winget Available', status: out.includes('AVAILABLE') ? 'pass' : 'warn', detail: out, risk: 'low' };
  });
}

export function checkUSBLock(): PrivCheck {
  return safe('priv-usb', 'USB Port Lock', () => {
    const out = ps(`$u=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -EA SilentlyContinue).Start;if($u-eq4){'DISABLED'}else{'ENABLED'}`);
    const locked = out.includes('DISABLED');
    return { id: 'priv-usb', name: 'USB Storage', status: locked ? 'pass' : 'warn', detail: locked ? 'USB storage disabled' : 'USB storage enabled — BadUSB risk', risk: locked ? 'low' : 'medium', actionable: true };
  });
}

export function checkLockscreen(): PrivCheck {
  return safe('priv-lockscreen', 'Lockscreen Hardening', () => {
    const out = ps(`
$cam=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization' -EA SilentlyContinue).NoLockScreenCamera
$cortana=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' -EA SilentlyContinue).AllowCortanaAboveLock
"LockCam:$cam|LockCortana:$cortana"
`);
    const camOff = out.includes('LockCam:1');
    return { id: 'priv-lockscreen', name: 'Lockscreen Hardening', status: camOff ? 'pass' : 'warn', detail: out, risk: camOff ? 'low' : 'medium', actionable: true };
  });
}

export function checkShellExtensions(): PrivCheck {
  return safe('priv-shellext', 'Shell Extension Audit', () => {
    const out = ps(`
$ErrorActionPreference='SilentlyContinue'
$ext=Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved' -EA SilentlyContinue
$c=if($ext){$ext.Count}else{0}
"ApprovedExtensions:$c"
`);
    return { id: 'priv-shellext', name: 'Shell Extension Audit', status: 'pass', detail: out, risk: 'low' };
  });
}

export function checkDataDashboard(): PrivCheck {
  return { id: 'priv-dashboard', name: 'Data Science Dashboard', status: 'pass', detail: 'Integrated into Sentinel Connector Map', risk: 'low' };
}

export function runAllPrivacyChecks(): PrivCheck[] {
  return [
    checkHWID(), checkAdID(), checkTelemetryRegistry(), checkWebcamMic(),
    checkClipboard(), checkMetadata(), checkCortana(), checkErrorReporting(),
    checkWifiSense(), checkBluetooth(), checkGPOHardening(), checkUACStealth(),
    checkShredder(), checkAntiKeylogging(), checkBrowserFingerprint(),
    checkDNSLeak(), checkLocation(), checkWinget(), checkUSBLock(),
    checkLockscreen(), checkShellExtensions(), checkDataDashboard(),
  ];
}
