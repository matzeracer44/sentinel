import https from 'https';

export interface TLSInspectionSummary {
  host: string;
  status: string;
  grade?: string;
  protocols?: string[];
  issues: string[];
  fetchedAt: number;
}

interface SSLLabsResponse {
  host: string;
  status: string;
  statusMessage?: string;
  endpoints?: Array<{
    statusMessage?: string;
    grade?: string;
    details?: {
      protocols?: Array<{ name: string; version: string }>;
      forwardSecrecy?: number;
      supportsRC4?: number;
      heartbleed?: number;
      openSslCcs?: number;
      openSSLLuckyMinus20?: number;
    };
  }>;
}

const SSL_LABS_ENDPOINT = 'https://api.ssllabs.com/api/v3/analyze';

function fetchJson(url: string): Promise<any> {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode && res.statusCode >= 400) {
          reject(new Error(`TLS inspector HTTP ${res.statusCode}`));
          return;
        }

        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(data || '{}'));
          } catch (err) {
            reject(err);
          }
        });
      })
      .on('error', (err) => reject(err));
  });
}

function deriveIssues(endpoint: SSLLabsResponse['endpoints'][number] | undefined): string[] {
  if (!endpoint) return [];
  const issues: string[] = [];
  const details = endpoint.details;
  if (!details) return issues;

  if (details.forwardSecrecy === 1) {
    issues.push('Forward secrecy supported.');
  } else if (details.forwardSecrecy === 2) {
    issues.push('Forward secrecy limited to modern clients.');
  } else {
    issues.push('No forward secrecy detected.');
  }

  if (details.supportsRC4 === 1) {
    issues.push('RC4 cipher detected — vulnerable.');
  }
  if (details.heartbleed === 1) {
    issues.push('Heartbleed vulnerability present.');
  }
  if (details.openSslCcs === 1 || details.openSSLLuckyMinus20 === 1) {
    issues.push('OpenSSL CCS/LuckyMinus20 vulnerability detected.');
  }

  return issues;
}

export async function inspectTLS(host: string): Promise<TLSInspectionSummary> {
  if (!host || !host.trim()) {
    throw new Error('Host is required for TLS inspection');
  }

  const url = `${SSL_LABS_ENDPOINT}?host=${encodeURIComponent(host)}&publish=off&fromCache=on&all=done`;
  const payload = (await fetchJson(url)) as SSLLabsResponse;
  const primaryEndpoint = payload?.endpoints?.[0];
  const protocols = primaryEndpoint?.details?.protocols?.map((p) => `${p.name} ${p.version}`) ?? [];

  return {
    host: payload?.host || host,
    status: payload?.status || 'UNKNOWN',
    grade: primaryEndpoint?.grade,
    protocols,
    issues: deriveIssues(primaryEndpoint),
    fetchedAt: Date.now(),
  };
}
