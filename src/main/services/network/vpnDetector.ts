/**
 * SENTINEL — VPN Awareness Layer
 * Detects active VPN adapters (NordLynx, TAP-NordVPN, WireGuard, OpenVPN),
 * resolves tunnel IP vs real IP, provides VPN status to all network modules.
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const PS_TIMEOUT = 5000;
const PS_MAX_BUFFER = 4 * 1024 * 1024;

export interface VpnStatus {
  active: boolean;
  adapter: string | null;
  tunnelIP: string | null;
  publicIP: string | null;
  protocol: string | null;
  provider: string | null;
}

const VPN_ADAPTER_KEYWORDS = [
  'nordlynx', 'nordvpn', 'tap-nordvpn', 'wireguard',
  'openvpn', 'expressvpn', 'protonvpn', 'surfshark',
  'wintun', 'mullvad', 'cyberghost', 'pia',
  'privateinternetaccess', 'windscribe',
];

function detectProvider(adapterName: string): string | null {
  const lower = adapterName.toLowerCase();
  if (lower.includes('nordlynx') || lower.includes('nordvpn') || lower.includes('tap-nordvpn')) return 'NordVPN';
  if (lower.includes('expressvpn')) return 'ExpressVPN';
  if (lower.includes('protonvpn') || lower.includes('proton')) return 'ProtonVPN';
  if (lower.includes('surfshark')) return 'Surfshark';
  if (lower.includes('mullvad')) return 'Mullvad';
  if (lower.includes('cyberghost')) return 'CyberGhost';
  if (lower.includes('windscribe')) return 'Windscribe';
  if (lower.includes('wireguard') || lower.includes('wintun')) return 'WireGuard';
  if (lower.includes('openvpn') || lower.includes('tap-')) return 'OpenVPN';
  if (lower.includes('pia') || lower.includes('privateinternet')) return 'PIA';
  return null;
}

function detectProtocol(adapterName: string): string | null {
  const lower = adapterName.toLowerCase();
  if (lower.includes('nordlynx') || lower.includes('wireguard') || lower.includes('wintun')) return 'WireGuard';
  if (lower.includes('openvpn') || lower.includes('tap-')) return 'OpenVPN';
  return 'Unknown';
}

export async function getVpnStatus(): Promise<VpnStatus> {
  const result: VpnStatus = {
    active: false,
    adapter: null,
    tunnelIP: null,
    publicIP: null,
    protocol: null,
    provider: null,
  };

  try {
    const psScript = `
      Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } |
      Select-Object Name, InterfaceDescription, ifIndex |
      ConvertTo-Json -Compress
    `;
    const { stdout } = await execAsync(
      `powershell -NoProfile -NonInteractive -Command "${psScript.replace(/\n/g, ' ')}"`,
      { timeout: PS_TIMEOUT, maxBuffer: PS_MAX_BUFFER }
    );

    const adapters = JSON.parse(stdout.trim() || '[]');
    const adapterList = Array.isArray(adapters) ? adapters : [adapters];

    for (const adapter of adapterList) {
      const name = (adapter.Name || '').toLowerCase();
      const desc = (adapter.InterfaceDescription || '').toLowerCase();
      const combined = `${name} ${desc}`;

      const isVpn = VPN_ADAPTER_KEYWORDS.some(kw => combined.includes(kw));
      if (isVpn) {
        result.active = true;
        result.adapter = adapter.Name || adapter.InterfaceDescription;
        result.provider = detectProvider(combined);
        result.protocol = detectProtocol(combined);

        try {
          const ipScript = `
            Get-NetIPAddress -InterfaceIndex ${adapter.ifIndex} -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty IPAddress
          `;
          const { stdout: ipOut } = await execAsync(
            `powershell -NoProfile -NonInteractive -Command "${ipScript.replace(/\n/g, ' ')}"`,
            { timeout: PS_TIMEOUT, maxBuffer: PS_MAX_BUFFER }
          );
          result.tunnelIP = ipOut.trim() || null;
        } catch {
          // Could not resolve tunnel IP
        }
        break;
      }
    }
  } catch (err) {
    console.error('[VpnDetector] Failed to detect VPN status:', err instanceof Error ? err.message : err);
  }

  return result;
}
