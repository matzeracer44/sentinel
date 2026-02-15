/**
 * SENTINEL UNIFIED — Network Types (Renderer)
 */

export interface NetworkConnection {
  localIP: string;
  localPort: number;
  remoteIP: string;
  remotePort: number;
  protocol: string;
  state: string;
  pid: number;
  processName: string;
  processPath?: string;
  processCompany?: string;
  signature?: string;
  userName?: string;
}

export interface IPMetadata {
  ip: string;
  type: 'local' | 'external';
  country: string;
  countryCode: string;
  region: string;
  city: string;
  zip: string;
  isp: string;
  org: string;
  as: string;
  timezone: string;
  lat: number;
  lon: number;
  mobile: boolean;
  proxy: boolean;
  hosting: boolean;
  reputation: string;
  riskLevel: 'safe' | 'low' | 'medium' | 'high';
  hostname?: string;
  macAddress?: string;
  vendor?: string;
  deviceType?: string;
  raw?: Record<string, unknown>;
}

export interface TLSSummary {
  host: string;
  grade?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  protocol?: string;
  cipher?: string;
  issues?: string[];
  error?: string;
}

export interface AddressWatch {
  ip: string;
  hits: number;
  firstSeen: number;
  lastSeen: number;
}

export interface AddressWatchSummary {
  totalTracked: number;
  topHit: AddressWatch | null;
}

export interface ConnectivityResult {
  success: boolean;
  connected: boolean;
  latency: number;
}

export interface NetworkDiagnostics {
  Services?: Array<{
    Name: string;
    DisplayName: string;
    Status: string;
    Error?: string;
  }>;
  NetworkStatistics?: Array<{
    Protocol: string;
    LocalAddress: string;
    LocalPort: number;
    RemoteAddress: string;
    RemotePort: number;
    State: string;
    PID: number;
    ProcessName: string;
    Error?: string;
  }>;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  cpu: number;
  ram: number;
  trustScore: number;
  connections: unknown[];
}

export interface SessionSummary {
  key: string;
  pid: number;
  processName: string;
  processPath?: string;
  processCompany?: string;
  userName?: string;
  localPort: number;
  protocol?: string;
  connectionState?: string;
  primaryRemoteIP?: string;
  primaryRemotePort?: number;
  connectionCount: number;
  connectionVelocity: number;
  remoteClusters: RemoteClusterSummary[];
  risk: RiskAssessment;
  lastUpdated: number;
}

export interface RemoteClusterSummary {
  subnet: string;
  primaryIP: string;
  connectionCount: number;
  lastSeen: number;
  velocity: number;
}

export interface RiskAssessment {
  score: number;
  level: 'Low' | 'Medium' | 'High' | 'Critical';
  factors: string[];
}
