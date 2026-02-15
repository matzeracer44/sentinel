/**
 * SENTINEL — WiFi Security Audit Service
 * Audits current WiFi connection and visible networks for security posture.
 * Uses netsh wlan commands on Windows.
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const PS_TIMEOUT = 8000;
const PS_MAX_BUFFER = 4 * 1024 * 1024;

export interface WifiNetwork {
  ssid: string;
  bssid: string;
  signal: number;
  channel: number;
  band: string;
  auth: string;
  encryption: string;
  risk: 'high' | 'medium' | 'low' | 'safe';
  riskReason: string;
}

export interface WifiAuditResult {
  connected: boolean;
  currentSSID: string | null;
  currentAuth: string | null;
  currentSignal: number | null;
  currentBand: string | null;
  networks: WifiNetwork[];
  timestamp: string;
}

function assessWifiRisk(auth: string, encryption: string): { risk: WifiNetwork['risk']; reason: string } {
  const a = auth.toLowerCase();
  const e = encryption.toLowerCase();
  if (a.includes('open') || a === 'open') return { risk: 'high', reason: 'Open network — no encryption' };
  if (a.includes('wep')) return { risk: 'high', reason: 'WEP — trivially crackable' };
  if (e.includes('tkip') && !e.includes('ccmp')) return { risk: 'medium', reason: 'TKIP only — deprecated encryption' };
  if (a.includes('wpa3')) return { risk: 'safe', reason: 'WPA3 — strongest protection' };
  if (a.includes('wpa2')) return { risk: 'low', reason: 'WPA2 — adequate protection' };
  if (a.includes('wpa')) return { risk: 'medium', reason: 'WPA1 — outdated' };
  return { risk: 'low', reason: `Auth: ${auth}` };
}

function parseBand(channel: number): string {
  if (channel >= 1 && channel <= 14) return '2.4 GHz';
  if (channel >= 32 && channel <= 177) return '5 GHz';
  if (channel >= 1 && channel <= 233) return '6 GHz';
  return 'Unknown';
}

export async function auditWifi(): Promise<WifiAuditResult> {
  const result: WifiAuditResult = {
    connected: false,
    currentSSID: null,
    currentAuth: null,
    currentSignal: null,
    currentBand: null,
    networks: [],
    timestamp: new Date().toISOString(),
  };

  try {
    // Current connection
    const { stdout: ifaceOut } = await execAsync(
      'netsh wlan show interfaces',
      { timeout: PS_TIMEOUT, maxBuffer: PS_MAX_BUFFER }
    );

    const ssidMatch = ifaceOut.match(/^\s*SSID\s*:\s*(.+)$/m);
    const authMatch = ifaceOut.match(/^\s*Authentifizierung\s*:\s*(.+)$/m) || ifaceOut.match(/^\s*Authentication\s*:\s*(.+)$/m);
    const signalMatch = ifaceOut.match(/^\s*Signal\s*:\s*(\d+)%/m);
    const channelMatch = ifaceOut.match(/^\s*(?:Kanal|Channel)\s*:\s*(\d+)/m);
    const stateMatch = ifaceOut.match(/^\s*(?:Zustand|State)\s*:\s*(.+)$/m);

    if (stateMatch && /connect|verbunden/i.test(stateMatch[1].trim())) {
      result.connected = true;
    }
    if (ssidMatch) result.currentSSID = ssidMatch[1].trim();
    if (authMatch) result.currentAuth = authMatch[1].trim();
    if (signalMatch) result.currentSignal = parseInt(signalMatch[1], 10);
    if (channelMatch) {
      const ch = parseInt(channelMatch[1], 10);
      result.currentBand = parseBand(ch);
    }
  } catch {
    // WiFi interface query failed — might not have WiFi
  }

  try {
    // Visible networks
    const { stdout: netOut } = await execAsync(
      'netsh wlan show networks mode=bssid',
      { timeout: PS_TIMEOUT, maxBuffer: PS_MAX_BUFFER }
    );

    const blocks = netOut.split(/(?=SSID \d+ :)/);
    for (const block of blocks) {
      const ssidM = block.match(/SSID \d+ :\s*(.+)/);
      if (!ssidM) continue;
      const ssid = ssidM[1].trim();
      if (!ssid) continue;

      const bssidM = block.match(/BSSID \d+\s*:\s*([0-9a-f:]+)/i);
      const signalM = block.match(/Signal\s*:\s*(\d+)%/);
      const channelM = block.match(/(?:Kanal|Channel)\s*:\s*(\d+)/);
      const authM = block.match(/(?:Authentifizierung|Authentication)\s*:\s*(.+)/);
      const encM = block.match(/(?:Verschl|Encryption|Cipher)\s*:\s*(.+)/);

      const auth = authM ? authM[1].trim() : 'Unknown';
      const encryption = encM ? encM[1].trim() : 'Unknown';
      const channel = channelM ? parseInt(channelM[1], 10) : 0;
      const { risk, reason } = assessWifiRisk(auth, encryption);

      result.networks.push({
        ssid,
        bssid: bssidM ? bssidM[1].trim() : '',
        signal: signalM ? parseInt(signalM[1], 10) : 0,
        channel,
        band: parseBand(channel),
        auth,
        encryption,
        risk,
        riskReason: reason,
      });
    }

    result.networks.sort((a, b) => {
      const riskOrder = { high: 0, medium: 1, low: 2, safe: 3 };
      return (riskOrder[a.risk] - riskOrder[b.risk]) || (b.signal - a.signal);
    });
  } catch {
    // Network scan failed
  }

  return result;
}
