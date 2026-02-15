/**
 * SENTINEL UNIFIED — Threat Intelligence Types (Renderer)
 */

export interface ThreatEvent {
  id: string;
  timestamp: number;
  pid: number;
  processName: string;
  remoteIP?: string;
  remoteSubnet?: string;
  riskScore: number;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  actionTaken: 'Blocked' | 'Alerted' | 'Throttled';
  reason?: string;
}

export interface GuardianStory {
  id: string;
  firstSeen: number;
  lastSeen: number;
  modules: string[];
  maxRiskScore?: number;
  maxRiskLevel?: 'Low' | 'Medium' | 'High' | 'Critical';
  pid?: number;
  processName?: string;
  remoteIP?: string;
  remoteSubnet?: string;
  policyFingerprint?: string;
  linkedThreatIds?: string[];
  linkedPolicyIds?: string[];
  summary?: string;
}

export interface GuardianEvent {
  id: string;
  timestamp: number;
  pid?: number;
  processName?: string;
  remoteIP?: string;
  remoteSubnet?: string;
  fingerprint?: string;
  module: string;
  action?: string;
  riskScore?: number;
  riskLevel?: 'Low' | 'Medium' | 'High' | 'Critical';
  metadata?: Record<string, unknown>;
}

export interface Playbook {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  priority?: number;
  tags?: string[];
  conditions: PlaybookCondition[];
  actions: PlaybookAction[];
  createdAt: number;
  updatedAt: number;
}

export interface PlaybookCondition {
  modules?: string[];
  minRiskLevel?: 'Low' | 'Medium' | 'High' | 'Critical';
  processName?: string;
  remoteIP?: string;
  fingerprint?: string;
  tags?: string[];
}

export interface PlaybookAction {
  type: 'log' | 'stage-firewall-rule' | 'dispatch-script' | 'notify';
  message?: string;
  ttlSeconds?: number;
  block?: boolean;
  scriptId?: string;
  args?: string[];
  channel?: 'toast' | 'system' | 'webhook';
  title?: string;
  body?: string;
}

export interface PlaybookRun {
  id: string;
  playbookId: string;
  triggeredAt: number;
  status: 'pending' | 'completed' | 'failed';
  actionsExecuted: number;
  error?: string;
}

export interface ThreatIntelRecord {
  indicator: string;
  type: 'ip' | 'domain' | 'hash';
  reputation?: number;
  confidence?: number;
  sources: string[];
  tags?: string[];
  lastSeen?: number;
  metadata?: Record<string, unknown>;
}

export interface AnomalyConfig {
  enabled: boolean;
  sensitivity: 'low' | 'medium' | 'high';
  windowMinutes: number;
  minSamples: number;
}

export interface PolicySuggestion {
  id: string;
  createdAt: number;
  updatedAt: number;
  recommendation: string;
  confidence: number;
  evidenceCount: number;
  remoteIP?: string;
  processName?: string;
  status: 'pending' | 'accepted' | 'dismissed';
  fingerprint?: string;
  intel?: PolicyIntel;
}

export interface PolicyIntel {
  ip?: string;
  org?: string;
  country?: string;
  region?: string;
  city?: string;
  watchHits?: number;
  lastSeen?: number;
  tlsGrade?: string;
  tlsIssues?: string[];
  leakSignals?: string[];
  riskSummary?: string;
}

export interface ArgusScanResult {
  url: string;
  threat_level: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'CRITICAL' | 'UNKNOWN';
  threat_score?: number;
  reasons?: string[];
  intel?: Record<string, unknown>;
  encrypted_intel?: string;
  from_cache?: boolean;
  error?: string;
}
