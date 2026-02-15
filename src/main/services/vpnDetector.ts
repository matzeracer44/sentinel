/**
 * SENTINEL — VPN Awareness Layer
 * Detects active VPN adapters, provides status for all modules.
 * Used by: Network Monitor, DNS, Firewall, Dashboard
 */

import { spawnSync } from 'child_process';

export interface VpnStatus {
  active: boolean;
  adapters: VpnAdapter[];
  provider: string;
  serverIp: string;
}

export interface VpnAdapter {
  name: string;
  description: string;
  status: string;
  type: string;
}

const VPN_PATTERNS = /NordLynx|WireGuard|TAP-|TUN|VPN|Wintun|OpenVPN|Surfshark|ExpressVPN|ProtonVPN|Mullvad/i;

let _cachedStatus: VpnStatus | null = null;
let _lastCheck = 0;
const CACHE_TTL_MS = 5000;

/**
 * Detect active VPN adapters via PowerShell Get-NetAdapter
 */
export function getVpnStatus(forceRefresh = false): VpnStatus {
  const now = Date.now();
  if (!forceRefresh && _cachedStatus && (now - _lastCheck) < CACHE_TTL_MS) {
    return _cachedStatus;
  }

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$adapters = @(Get-NetAdapter | Where-Object {
  $_.InterfaceDescription -match 'NordLynx|WireGuard|TAP-|TUN|VPN|Wintun|OpenVPN|Surfshark|ExpressVPN|ProtonVPN|Mullvad'
} | Select-Object Name, InterfaceDescription, Status, @{n='type';e={
  if($_.InterfaceDescription -match 'NordLynx|WireGuard|Wintun'){'WireGuard'}
  elseif($_.InterfaceDescription -match 'TAP-|OpenVPN'){'OpenVPN'}
  elseif($_.InterfaceDescription -match 'TUN'){'TUN'}
  else{'VPN'}
}})

$active = @($adapters | Where-Object { $_.Status -eq 'Up' })
$provider = ''
if ($active.Count -gt 0) {
  $desc = $active[0].InterfaceDescription
  if ($desc -match 'NordLynx') { $provider = 'NordVPN' }
  elseif ($desc -match 'Surfshark') { $provider = 'Surfshark' }
  elseif ($desc -match 'ExpressVPN') { $provider = 'ExpressVPN' }
  elseif ($desc -match 'ProtonVPN') { $provider = 'ProtonVPN' }
  elseif ($desc -match 'Mullvad') { $provider = 'Mullvad' }
  elseif ($desc -match 'WireGuard') { $provider = 'WireGuard' }
  elseif ($desc -match 'OpenVPN') { $provider = 'OpenVPN' }
  else { $provider = 'Unknown VPN' }
}

# Try to get VPN server IP from routing table
$serverIp = ''
if ($active.Count -gt 0) {
  $idx = $active[0].ifIndex
  $route = Get-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($route) { $serverIp = $route.NextHop }
}

[PSCustomObject]@{
  active = ($active.Count -gt 0)
  adapters = $active | ForEach-Object {
    [PSCustomObject]@{ name=$_.Name; description=$_.InterfaceDescription; status=$_.Status; type=$_.type }
  }
  provider = $provider
  serverIp = $serverIp
} | ConvertTo-Json -Depth 3 -Compress
`;
    const result = spawnSync('powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
      { input: psScript, timeout: 8000, windowsHide: true, encoding: 'utf8', maxBuffer: 1024 * 1024 }
    );

    if (result.error) throw result.error;
    const output = (result.stdout || '').trim();
    if (!output) {
      _cachedStatus = { active: false, adapters: [], provider: '', serverIp: '' };
    } else {
      const parsed = JSON.parse(output);
      _cachedStatus = {
        active: !!parsed.active,
        adapters: Array.isArray(parsed.adapters) ? parsed.adapters : parsed.adapters ? [parsed.adapters] : [],
        provider: parsed.provider || '',
        serverIp: parsed.serverIp || '',
      };
    }
  } catch (err) {
    console.warn('[VpnDetector] Detection failed:', err);
    _cachedStatus = { active: false, adapters: [], provider: '', serverIp: '' };
  }

  _lastCheck = now;
  return _cachedStatus;
}

/**
 * Quick check if VPN is active (uses cache)
 */
export function isVpnActive(): boolean {
  return getVpnStatus().active;
}

/**
 * Check if a given adapter name matches VPN patterns
 */
export function isVpnAdapter(adapterDescription: string): boolean {
  return VPN_PATTERNS.test(adapterDescription);
}
