import { lookup } from 'dns/promises';
import https from 'https';

export interface ConnectivityResult {
  success: boolean;
  connected: boolean;
  dnsTimeMs?: number;
  httpTimeMs?: number;
  totalTimeMs?: number;
  checkedAt: number;
  cached: boolean;
  error?: string;
}

const DNS_TARGET = process.env.SENTINEL_CONNECTIVITY_DNS?.trim() || 'www.google.com';
const HTTP_TARGET = process.env.SENTINEL_CONNECTIVITY_URL?.trim() || 'https://www.gstatic.com/generate_204';
const CACHE_TTL_MS = 30_000;
const HTTP_TIMEOUT_MS = 5_000;

let lastResult: ConnectivityResult | null = null;

export async function performConnectivityCheck(options: { force?: boolean } = {}): Promise<ConnectivityResult> {
  const now = Date.now();
  if (!options.force && lastResult && now - lastResult.checkedAt < CACHE_TTL_MS) {
    return { ...lastResult, cached: true };
  }

  const totalStart = now;
  let dnsTimeMs: number | undefined;
  let httpTimeMs: number | undefined;

  try {
    const dnsStart = Date.now();
    await lookup(DNS_TARGET, { family: 4 });
    dnsTimeMs = Date.now() - dnsStart;
  } catch (err: any) {
    const failure: ConnectivityResult = {
      success: false,
      connected: false,
      dnsTimeMs,
      httpTimeMs,
      totalTimeMs: Date.now() - totalStart,
      checkedAt: Date.now(),
      cached: false,
      error: `DNS lookup failed: ${err?.message || err}`,
    };
    lastResult = failure;
    return failure;
  }

  try {
    const httpStart = Date.now();
    await runHttpProbe();
    httpTimeMs = Date.now() - httpStart;
  } catch (err: any) {
    const failure: ConnectivityResult = {
      success: false,
      connected: false,
      dnsTimeMs,
      httpTimeMs,
      totalTimeMs: Date.now() - totalStart,
      checkedAt: Date.now(),
      cached: false,
      error: `HTTP probe failed: ${err?.message || err}`,
    };
    lastResult = failure;
    return failure;
  }

  const successResult: ConnectivityResult = {
    success: true,
    connected: true,
    dnsTimeMs,
    httpTimeMs,
    totalTimeMs: Date.now() - totalStart,
    checkedAt: Date.now(),
    cached: false,
  };
  lastResult = successResult;
  return successResult;
}

async function runHttpProbe(): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const req = https.request(HTTP_TARGET, { method: 'GET' }, (res) => {
      res.on('data', () => {});
      res.on('end', () => resolve());
    });

    req.on('error', (err) => reject(err));
    req.setTimeout(HTTP_TIMEOUT_MS, () => {
      req.destroy(new Error('HTTP probe timed out'));
    });

    req.end();
  });
}
