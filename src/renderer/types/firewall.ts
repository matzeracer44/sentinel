/**
 * SENTINEL UNIFIED — Firewall Types (Renderer)
 */

export interface FirewallRule {
  name: string;
  direction: string;
  action: string;
  enabled: string | boolean;
  profile: string;
  protocol: string;
  program: string;
  localPort: string | number;
  remotePort: string | number;
  localAddress: string;
  remoteAddress: string;
  description: string;
  timeCreated: string | null;
}

export interface BlockedIp {
  ip: string;
  reason?: string;
  blocked?: boolean;
  timestamp?: string;
}

export interface FirewallInventoryMeta {
  totalCollected?: number;
  sentinelTagged?: number;
  tracked?: number;
  fallbackUsed?: boolean;
  powershellRuleCount?: number;
  blockedIpCount?: number;
  blockedIpsError?: string | null;
  errors?: string[];
  generatedAt?: number;
}

export interface FirewallInventory {
  success: boolean;
  rules?: FirewallRule[];
  blockedIps?: BlockedIp[];
  meta?: FirewallInventoryMeta;
  error?: string;
}

export interface UndoRedoState {
  canUndo: boolean;
  canRedo: boolean;
  undoCount?: number;
  redoCount?: number;
}

export interface PendingRule {
  id: string;
  sessionKey: string;
  pid: number;
  processName: string;
  remoteIP: string;
  remotePort?: number;
  reasons: string[];
  recommendsBlock: boolean;
  ttlSeconds?: number;
  createdAt: number;
  expiresAt: number;
  status: 'pending' | 'committed' | 'dismissed' | 'expired';
}

export interface PendingRuleUpdate {
  event: 'staged' | 'committed' | 'expired' | 'dismissed';
  pendingRule: PendingRule;
}

export interface BlockResult {
  success: boolean;
  message?: string;
  error?: string;
  subnet?: string;
  ipCount?: string;
}
