/**
 * Sentinel Unified — Connector Map Type Definitions
 * Defines all interfaces for the radial connector map visualization.
 */

// ---------------------------------------------------------------------------
// Cluster & Ring Types
// ---------------------------------------------------------------------------

export type ClusterType =
  | 'core'
  | 'firewall'
  | 'intel'
  | 'automation'
  | 'network'
  | 'dns'
  | 'system'
  | 'vault';

export type RingIndex = 0 | 1 | 2 | 3;

// ---------------------------------------------------------------------------
// Node Source & Status
// ---------------------------------------------------------------------------

export type ConnectorSource = 'sentinel' | 'argus';

export type NodeStatus = 'online' | 'degraded' | 'error' | 'offline';

export type NodeSize = 'lg' | 'md' | 'sm';

// ---------------------------------------------------------------------------
// Edge Types
// ---------------------------------------------------------------------------

export type EdgeType = 'data-flow' | 'trigger' | 'dependency' | 'heartbeat';

// ---------------------------------------------------------------------------
// Connector Node
// ---------------------------------------------------------------------------

export interface ConnectorNode {
  /** Unique identifier, e.g. "fw.block-port" */
  id: string;
  /** Human-readable display name, e.g. "Block Port" */
  name: string;
  /** Which logical cluster this node belongs to */
  cluster: ClusterType;
  /** Which concentric ring (0=core, 1=inner, 2=mid, 3=outer) */
  ring: RingIndex;
  /** Whether this connector originates from Sentinel or ARGUS */
  source: ConnectorSource;
  /** Electron IPC channel name (Sentinel nodes) */
  ipcChannel?: string;
  /** REST endpoint path (ARGUS nodes), e.g. "POST /api/scan" */
  restEndpoint?: string;
  /** Current operational status */
  status: NodeStatus;
  /** Visual size weight */
  size: NodeSize;
  /** Last response latency in ms (-1 = unknown) */
  lastResponseMs: number;
  /** Number of errors in the last 24 hours */
  errorCount24h: number;
  /** Node-specific configuration (varies per node type) */
  config?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Connector Edge
// ---------------------------------------------------------------------------

export interface ConnectorEdge {
  /** Source node ID */
  source: string;
  /** Target node ID */
  target: string;
  /** Semantic type of the connection */
  type: EdgeType;
  /** Whether to render animated particles along this edge */
  animated: boolean;
  /** Optional color override (defaults to source cluster color) */
  color?: string;
  /** Optional label shown on hover */
  label?: string;
}

// ---------------------------------------------------------------------------
// D3 Simulation Node (extends ConnectorNode with mutable x/y)
// ---------------------------------------------------------------------------

export interface SimulationNode extends ConnectorNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  fx?: number | null;
  fy?: number | null;
}

// ---------------------------------------------------------------------------
// D3 Simulation Link (resolved references)
// ---------------------------------------------------------------------------

export interface SimulationLink {
  source: SimulationNode;
  target: SimulationNode;
  type: EdgeType;
  animated: boolean;
  color?: string;
  label?: string;
}

// ---------------------------------------------------------------------------
// Filter State
// ---------------------------------------------------------------------------

export interface ConnectorMapFilters {
  clusters: ClusterType[];
  status: NodeStatus[];
  source: ConnectorSource[];
}

// ---------------------------------------------------------------------------
// Full Map State
// ---------------------------------------------------------------------------

export interface ConnectorMapState {
  nodes: ConnectorNode[];
  edges: ConnectorEdge[];
  selectedNode: string | null;
  hoveredNode: string | null;
  filters: ConnectorMapFilters;
  zoom: number;
  rotation: number;
}

// ---------------------------------------------------------------------------
// Ring Layout Configuration
// ---------------------------------------------------------------------------

export interface RingConfig {
  ring: RingIndex;
  label: string;
  /** Radius as fraction of the smaller viewport dimension (0–1) */
  radiusMin: number;
  /** Radius as fraction of the smaller viewport dimension (0–1) */
  radiusMax: number;
}

// ---------------------------------------------------------------------------
// Cluster Sector Configuration
// ---------------------------------------------------------------------------

export interface ClusterSector {
  cluster: ClusterType;
  ring: RingIndex;
  /** Start angle in degrees (0 = top / 12 o'clock) */
  angleStart: number;
  /** End angle in degrees */
  angleEnd: number;
  /** Display label */
  label: string;
  /** Icon identifier (Lucide icon name or emoji) */
  icon: string;
}

// ---------------------------------------------------------------------------
// Node Modal Data
// ---------------------------------------------------------------------------

export interface NodeModalData {
  node: ConnectorNode;
  /** Recent log entries for this node */
  logs: NodeLogEntry[];
  /** Whether the modal is currently loading data */
  loading: boolean;
}

export interface NodeLogEntry {
  timestamp: number;
  message: string;
  level: 'info' | 'warn' | 'error';
}

// ---------------------------------------------------------------------------
// Status Check Result (from polling)
// ---------------------------------------------------------------------------

export interface NodeStatusCheck {
  nodeId: string;
  status: NodeStatus;
  latencyMs: number;
  checkedAt: number;
  error?: string;
}
