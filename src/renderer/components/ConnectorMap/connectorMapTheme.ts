/**
 * Sentinel Unified — Connector Map Theme
 * Dark Cyber color system, ring configuration, and cluster sector definitions.
 */

import type { ClusterType, RingConfig, ClusterSector, RingIndex } from '../../types/connectorMap';

// ---------------------------------------------------------------------------
// Base Colors
// ---------------------------------------------------------------------------

export const COLORS = {
  bgPrimary: '#0a0e1a',
  bgSecondary: '#111827',
  bgSurface: '#1a2035',
  borderDefault: '#1e293b',
  textPrimary: '#e2e8f0',
  textSecondary: '#94a3b8',
  textMuted: '#64748b',
} as const;

// ---------------------------------------------------------------------------
// Cluster Accent Colors (Neon)
// ---------------------------------------------------------------------------

export const CLUSTER_COLORS: Record<ClusterType, string> = {
  core: '#ffffff',
  firewall: '#ff3366',
  intel: '#00f0ff',
  automation: '#a855f7',
  network: '#00ff88',
  dns: '#ffaa00',
  system: '#3b82f6',
  vault: '#f472b6',
} as const;

// ---------------------------------------------------------------------------
// Status LED Colors
// ---------------------------------------------------------------------------

export const STATUS_COLORS: Record<string, string> = {
  online: '#00ff88',
  degraded: '#ffaa00',
  error: '#ff3366',
  offline: '#4b5563',
} as const;

// ---------------------------------------------------------------------------
// Edge / Line Colors
// ---------------------------------------------------------------------------

export const EDGE_COLORS = {
  active: 'rgba(0, 240, 255, 0.3)',
  dataFlow: 'rgba(0, 255, 136, 0.2)',
  trigger: 'rgba(168, 85, 247, 0.35)',
  heartbeat: 'rgba(255, 255, 255, 0.12)',
} as const;

// ---------------------------------------------------------------------------
// Glow Presets (box-shadow values)
// ---------------------------------------------------------------------------

export const GLOW = {
  cyan: '0 0 20px rgba(0, 240, 255, 0.4)',
  green: '0 0 20px rgba(0, 255, 136, 0.4)',
  red: '0 0 20px rgba(255, 51, 102, 0.4)',
  violet: '0 0 20px rgba(168, 85, 247, 0.4)',
  amber: '0 0 20px rgba(255, 170, 0, 0.4)',
  blue: '0 0 20px rgba(59, 130, 246, 0.4)',
  pink: '0 0 20px rgba(244, 114, 182, 0.4)',
  white: '0 0 20px rgba(255, 255, 255, 0.25)',
} as const;

export function clusterGlow(cluster: ClusterType): string {
  const map: Record<ClusterType, string> = {
    core: GLOW.white,
    firewall: GLOW.red,
    intel: GLOW.cyan,
    automation: GLOW.violet,
    network: GLOW.green,
    dns: GLOW.amber,
    system: GLOW.blue,
    vault: GLOW.pink,
  };
  return map[cluster];
}

// ---------------------------------------------------------------------------
// Ring Configuration
// ---------------------------------------------------------------------------

export const RING_CONFIGS: RingConfig[] = [
  { ring: 0, label: 'SENTINEL CORE', radiusMin: 0, radiusMax: 0.08 },
  { ring: 1, label: 'Operations', radiusMin: 0.22, radiusMax: 0.36 },
  { ring: 2, label: 'Analysis', radiusMin: 0.40, radiusMax: 0.54 },
  { ring: 3, label: 'Infrastructure', radiusMin: 0.60, radiusMax: 0.74 },
];

export function ringRadius(ring: RingIndex, viewportSize: number): number {
  const config = RING_CONFIGS[ring];
  const midFraction = (config.radiusMin + config.radiusMax) / 2;
  return midFraction * (viewportSize / 2);
}

// ---------------------------------------------------------------------------
// Cluster Sector Definitions (angle ranges in degrees, 0° = top)
// ---------------------------------------------------------------------------

export const CLUSTER_SECTORS: ClusterSector[] = [
  // Ring 1 — Operations
  { cluster: 'firewall', ring: 1, angleStart: 0, angleEnd: 120, label: 'Firewall Engine', icon: 'flame' },
  { cluster: 'network', ring: 1, angleStart: 120, angleEnd: 240, label: 'Network Monitor', icon: 'activity' },
  { cluster: 'system', ring: 1, angleStart: 240, angleEnd: 360, label: 'System & Perf', icon: 'cpu' },

  // Ring 2 — Analysis
  { cluster: 'intel', ring: 2, angleStart: 0, angleEnd: 180, label: 'Threat Intelligence', icon: 'search' },
  { cluster: 'automation', ring: 2, angleStart: 180, angleEnd: 360, label: 'Automation Engine', icon: 'bot' },

  // Ring 3 — Infrastructure
  { cluster: 'dns', ring: 3, angleStart: 0, angleEnd: 120, label: 'DNS & Hosts', icon: 'globe' },
  { cluster: 'vault', ring: 3, angleStart: 120, angleEnd: 360, label: 'Vault & Config', icon: 'lock' },
];

export function clusterSector(cluster: ClusterType): ClusterSector | undefined {
  return CLUSTER_SECTORS.find((s) => s.cluster === cluster);
}

// ---------------------------------------------------------------------------
// Node Size Dimensions (radius in px)
// ---------------------------------------------------------------------------

export const NODE_RADIUS = {
  lg: 28,
  md: 20,
  sm: 14,
} as const;

export const NODE_FONT_SIZE = {
  lg: 11,
  md: 9,
  sm: 7,
} as const;

// ---------------------------------------------------------------------------
// Animation Timing
// ---------------------------------------------------------------------------

export const ANIMATION = {
  pulseDuration: 2000,
  blinkDuration: 500,
  particleSpeed: 40,
  hoverScale: 1.08,
  modalFadeIn: 200,
  modalFadeOut: 150,
  ambientRotationSpeed: 0.1,
  shockwaveDuration: 800,
} as const;

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

export const POLL_INTERVAL_MS = 5000;
export const ARGUS_HEALTH_ENDPOINT = 'net-sandbox-status';
