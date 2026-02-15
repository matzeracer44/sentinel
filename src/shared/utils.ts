/**
 * SENTINEL UNIFIED — Shared Utilities
 * Pure functions shared between main and renderer processes.
 */

// ═══════════════════════════════════════════════════════════
// ERROR SERIALIZATION
// ═══════════════════════════════════════════════════════════

export interface SerializedError {
  message: string;
  stack?: string;
  code?: string | number;
}

export function serializeError(error: unknown): SerializedError {
  if (error instanceof Error) {
    return {
      message: error.message,
      stack: error.stack,
      code: (error as unknown as Record<string, unknown>).code as string | number | undefined,
    };
  }
  if (typeof error === 'object' && error !== null) {
    const obj = error as Record<string, unknown>;
    return {
      message: String(obj.message ?? 'Unknown error'),
      stack: typeof obj.stack === 'string' ? obj.stack : undefined,
      code: obj.code as string | number | undefined,
    };
  }
  return { message: String(error) };
}

/**
 * Extract a human-readable error message from unknown catch values.
 * Use this instead of `catch (err: any) { err.message }`.
 */
export function extractErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  if (err && typeof err === 'object') {
    const maybe = err as { message?: unknown; error?: unknown };
    if (typeof maybe.message === 'string') return maybe.message;
    if (typeof maybe.error === 'string') return maybe.error;
    try { return JSON.stringify(err); } catch { return String(err); }
  }
  return String(err);
}

// ═══════════════════════════════════════════════════════════
// FIREWALL LOCALE NORMALIZATION (German/English)
// ═══════════════════════════════════════════════════════════

export function normalizeDirection(raw: string): 'Inbound' | 'Outbound' | 'Both' | 'Unknown' {
  const lower = (raw ?? '').trim().toLowerCase();
  if (lower === 'inbound' || lower === 'eingehend' || lower === 'in') return 'Inbound';
  if (lower === 'outbound' || lower === 'ausgehend' || lower === 'out') return 'Outbound';
  if (lower === 'both' || lower === 'beide') return 'Both';
  return 'Unknown';
}

export function normalizeAction(raw: string): 'Allow' | 'Block' | 'Unknown' {
  const lower = (raw ?? '').trim().toLowerCase();
  if (lower === 'allow' || lower === 'zulassen') return 'Allow';
  if (lower === 'block' || lower === 'blockieren') return 'Block';
  return 'Unknown';
}

export function normalizeEnabled(raw: string | boolean): boolean {
  if (typeof raw === 'boolean') return raw;
  const lower = (raw ?? '').trim().toLowerCase();
  return lower === 'true' || lower === 'ja' || lower === 'yes' || lower === '1';
}

// ═══════════════════════════════════════════════════════════
// IP / NETWORK HELPERS
// ═══════════════════════════════════════════════════════════

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

export function isValidIPv4(ip: string): boolean {
  return IPV4_REGEX.test(ip.trim());
}

export function isPrivateIP(ip: string): boolean {
  const trimmed = ip.trim();
  return (
    trimmed.startsWith('10.') ||
    trimmed.startsWith('192.168.') ||
    trimmed.startsWith('127.') ||
    trimmed.startsWith('169.254.') ||
    trimmed === 'localhost' ||
    trimmed === '::1' ||
    trimmed === '0.0.0.0' ||
    isPrivate172(trimmed)
  );
}

function isPrivate172(ip: string): boolean {
  if (!ip.startsWith('172.')) return false;
  const second = parseInt(ip.split('.')[1], 10);
  return second >= 16 && second <= 31;
}

export function isMetadataIP(ip: string): boolean {
  return ip.trim() === '169.254.169.254';
}

export function isLoopback(ip: string): boolean {
  const t = ip.trim();
  return t.startsWith('127.') || t === '::1' || t === '0.0.0.0';
}

export function calculateSubnet(ip: string, mask: 8 | 16 | 20 | 22 | 24 | 26 | 30 | 32): string | null {
  if (!isValidIPv4(ip)) return null;
  const octets = ip.split('.').map(Number);
  const bits = 32 - mask;
  const ipNum = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const netMask = (0xFFFFFFFF << bits) >>> 0;
  const network = (ipNum & netMask) >>> 0;
  const o1 = (network >>> 24) & 0xFF;
  const o2 = (network >>> 16) & 0xFF;
  const o3 = (network >>> 8) & 0xFF;
  const o4 = network & 0xFF;
  return `${o1}.${o2}.${o3}.${o4}/${mask}`;
}

export function getIPCountForMask(mask: number): string {
  const count = Math.pow(2, 32 - mask);
  if (count === 1) return '1 IP';
  return `${count.toLocaleString()} IPs`;
}

// ═══════════════════════════════════════════════════════════
// URL SAFETY
// ═══════════════════════════════════════════════════════════

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

export function isAllowedScheme(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ALLOWED_SCHEMES.has(parsed.protocol);
  } catch {
    return false;
  }
}

export function isArgusLocalhost(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.hostname === '127.0.0.1' && parsed.port === '8080';
  } catch {
    return false;
  }
}

// ═══════════════════════════════════════════════════════════
// STRING / FORMATTING
// ═══════════════════════════════════════════════════════════

export function escapeHtml(str: string): string {
  const map: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return str.replace(/[&<>"']/g, (c) => map[c] || c);
}

export function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60000);
  const seconds = Math.floor((ms % 60000) / 1000);
  return `${minutes}m ${seconds}s`;
}

// ═══════════════════════════════════════════════════════════
// TIMING
// ═══════════════════════════════════════════════════════════

export function nowMs(): number {
  return Date.now();
}

export function isoNow(): string {
  return new Date().toISOString();
}

// ═══════════════════════════════════════════════════════════
// RESULT WRAPPER
// ═══════════════════════════════════════════════════════════

export type IpcResult<T = unknown> =
  | { success: true; data: T }
  | { success: false; error: SerializedError };

export function ok<T>(data: T): { success: true; data: T } {
  return { success: true, data };
}

export function fail(error: unknown): { success: false; error: SerializedError } {
  return { success: false, error: serializeError(error) };
}
