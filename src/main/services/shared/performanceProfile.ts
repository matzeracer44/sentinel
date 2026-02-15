/**
 * SENTINEL — Hardware-Tuned Performance Profile
 * Optimized for AMD Ryzen 7 7730U (8C/16T), 15.4 GB RAM, NVMe SSD.
 * All timeouts and buffer sizes calibrated for this hardware class.
 */

export interface PerformanceProfile {
  psTimeout: number;
  psMaxBuffer: number;
  pollingInterval: {
    networkMonitor: number;
    threatTimeline: number;
    firewallRules: number;
    systemStats: number;
    healthCheck: number;
    activityLog: number;
    argusHealth: number;
  };
  cache: {
    metadataTTL: number;
    maxEntries: number;
    firewallRulesTTL: number;
  };
}

export const PERFORMANCE_PROFILE: PerformanceProfile = {
  psTimeout: 5000,
  psMaxBuffer: 8 * 1024 * 1024,
  pollingInterval: {
    networkMonitor: 2000,
    threatTimeline: 5000,
    firewallRules: 10000,
    systemStats: 3000,
    healthCheck: 30000,
    activityLog: 6000,
    argusHealth: 15000,
  },
  cache: {
    metadataTTL: 300000,
    maxEntries: 500,
    firewallRulesTTL: 10000,
  },
};
