/**
 * SENTINEL UNIFIED — System & Performance Types (Renderer)
 */

export interface SystemData {
  cpu: CPUInfo;
  ram: RAMUsage;
  disks: DiskInfo[];
  system: SystemInfo;
  os: OSInfo;
  gpu: GPUInfo[];
  network: NetworkAdapterInfo[];
  battery: BatteryInfo;
}

export interface CPUInfo {
  name: string;
  cores: number;
  threads: number;
  currentLoad: number;
}

export interface RAMUsage {
  totalGB: number;
  usedGB: number;
  freeGB: number;
  usagePercent: number;
}

export interface RAMStats {
  totalGB: number;
  usedGB: number;
  availableGB: number;
  systemGB: number;
  appsGB: number;
  cacheGB: number;
  usagePercent: number;
}

export interface DiskInfo {
  drive: string;
  totalGB: number;
  usedGB: number;
  freeGB: number;
  usagePercent: number;
}

export interface SystemInfo {
  manufacturer: string;
  model: string;
  computerName: string;
  username: string;
}

export interface OSInfo {
  name: string;
  version: string;
  build: string;
}

export interface GPUInfo {
  name: string;
  memory: number;
}

export interface NetworkAdapterInfo {
  adapter: string;
  status: string;
  ipAddress: string;
  macAddress: string;
}

export interface BatteryInfo {
  status: string;
  percentage: number;
}

export interface SystemHealth {
  score: number;
  factors: {
    security: number;
    performance: number;
    privacy: number;
  };
}

export interface SystemStats {
  cpu: number;
  ram: number;
  disk: number;
  network: number;
}

export interface HealthReport {
  overall: string;
  score: number;
  components: HealthComponent[];
  generatedAt: number;
  durationMs: number;
}

export interface HealthComponent {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  message?: string;
  durationMs?: number;
}

export interface SecurityOverview {
  firewallEnabled: boolean;
  antivirusEnabled: boolean;
  uacEnabled: boolean;
  bitlockerEnabled: boolean;
  windowsUpdateEnabled: boolean;
  score: number;
}

export interface StartupItem {
  name: string;
  path: string;
  enabled: boolean;
  impact: 'low' | 'medium' | 'high';
}

export interface WindowsService {
  name: string;
  displayName: string;
  status: string;
  startType: string;
  isBloatware: boolean;
}

export interface QuickAction {
  id: string;
  name: string;
  description: string;
  icon: string;
  category: 'gaming' | 'privacy' | 'performance' | 'security';
}

export interface SystemSnapshot {
  id: string;
  name: string;
  createdAt: number;
  data: Record<string, unknown>;
}
