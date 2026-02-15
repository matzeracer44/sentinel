import { isAutonomousModeEnabled, getSentinelConfig } from './sentinelConfig';
import { execSync } from 'child_process';

export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';

let cachedGateway: string | null = null;

function detectLocalGateway(): string | null {
  if (cachedGateway !== null) return cachedGateway;
  try {
    const output = execSync('powershell -NoProfile -Command "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1).NextHop"', {
      encoding: 'utf-8',
      windowsHide: true,
      timeout: 5000,
    });
    const gateway = output.trim();
    if (gateway && gateway !== '0.0.0.0') {
      cachedGateway = gateway;
      return gateway;
    }
  } catch (err) {
    console.warn('[RiskEngine] Failed to detect local gateway:', err);
  }
  cachedGateway = '';
  return null;
}

export interface RemoteClusterSnapshot {
  subnet: string;
  primaryIP: string;
  connectionCount: number;
  lastSeen: number;
  velocity: number;
}

export interface SessionRiskContext {
  pid: number;
  processName: string;
  processCompany?: string;
  processPath?: string;
  signature?: string;
  localPort: number;
  connectionVelocity: number;
  remoteClusters: RemoteClusterSnapshot[];
  tlsPenalty?: number;
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  reasons: string[];
  flaggedSubnets: string[];
  recommendsBlock: boolean;
}

const SYSTEM_PATH_PREFIXES = ['c:/windows', 'c:/program files', 'c:/program files (x86)'];
const BASE_WHITELIST = new Set<string>(['127.0.0.1', '::1', '8.8.8.8', '1.1.1.1', '192.168.0.1', '192.168.1.1', '10.0.0.1']);

function normalizePath(input?: string): string {
  return (input || '').trim().toLowerCase().replace(/\\/g, '/');
}

function isSystemPath(path?: string): boolean {
  if (!path) return false;
  const normalized = normalizePath(path);
  return SYSTEM_PATH_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

function isSigned(signature?: string): boolean {
  if (!signature) return false;
  const normalized = signature.toLowerCase();
  return normalized.includes('valid') || normalized.includes('trusted');
}

function isPrivateSubnet(subnet: string): boolean {
  return subnet.startsWith('10.') || subnet.startsWith('192.168.') || subnet.startsWith('172.16.');
}

function getWhitelist(): Set<string> {
  const config = getSentinelConfig();
  const merged = new Set<string>(BASE_WHITELIST);
  config.whitelist.forEach((ip) => merged.add(ip));
  const gateway = detectLocalGateway();
  if (gateway) {
    merged.add(gateway);
  }
  return merged;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

export function calculateRisk(context: SessionRiskContext): RiskAssessment {
  let score = 0;
  const reasons: string[] = [];
  const flaggedSubnets: string[] = [];

  if (context.tlsPenalty && context.tlsPenalty > 0) {
    score += context.tlsPenalty;
    reasons.push('TLS certificate issue (expired/self-signed)');
  }

  if (context.connectionVelocity > 80) {
    score += 40;
    reasons.push('Extreme connection velocity');
  } else if (context.connectionVelocity > 40) {
    score += 25;
    reasons.push('High connection churn');
  } else if (context.connectionVelocity > 15) {
    score += 10;
  }

  if (!isSystemPath(context.processPath)) {
    score += 15;
    reasons.push('Process running outside trusted paths');
  }

  if (!isSigned(context.signature)) {
    score += 20;
    reasons.push('Unsigned or unknown binary signature');
  }

  const suspiciousClusters = context.remoteClusters.filter((cluster) => {
    if (!cluster.primaryIP || cluster.primaryIP === '0.0.0.0') return false;
    if (isPrivateSubnet(cluster.subnet)) return false;
    return cluster.connectionCount > 2 || cluster.velocity > 5;
  });

  if (suspiciousClusters.length) {
    score += 15;
    suspiciousClusters.forEach((cluster) => {
      flaggedSubnets.push(cluster.subnet);
    });
    reasons.push('Suspicious remote subnets detected');
  }

  if (context.processName.toLowerCase().includes('sentinel')) {
    score = 0;
    reasons.length = 0;
  }

  score = clamp(score, 0, 100);

  let level: RiskLevel = 'Low';
  if (score >= 80) level = 'Critical';
  else if (score >= 60) level = 'High';
  else if (score >= 40) level = 'Medium';

  const whitelist = getWhitelist();
  const isWhitelisted = context.remoteClusters.some((cluster) =>
    whitelist.has(cluster.primaryIP) || whitelist.has(cluster.subnet)
  );

  const recommendsBlock = level === 'Critical' && isAutonomousModeEnabled() && !isWhitelisted;

  return {
    score,
    level,
    reasons,
    flaggedSubnets,
    recommendsBlock,
  };
}
