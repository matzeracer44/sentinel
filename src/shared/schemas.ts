/**
 * SENTINEL UNIFIED — Zod Schemas
 * Every IPC input/output schema in one place.
 * All IPC handlers MUST validate input with these schemas.
 */

import { z } from 'zod';

// ═══════════════════════════════════════════════════════════
// SHARED PRIMITIVES
// ═══════════════════════════════════════════════════════════

export const FirewallDirectionSchema = z.enum(['in', 'out', 'both']);
export type FirewallDirection = z.infer<typeof FirewallDirectionSchema>;

export const FirewallProtocolSchema = z.enum(['TCP', 'UDP', 'Both']);
export type FirewallProtocol = z.infer<typeof FirewallProtocolSchema>;

export const SubnetMaskSchema = z.union([
  z.literal(8),
  z.literal(16),
  z.literal(20),
  z.literal(22),
  z.literal(24),
  z.literal(26),
  z.literal(30),
  z.literal(32),
]);
export type SubnetMaskBits = z.infer<typeof SubnetMaskSchema>;

export const RiskLevelSchema = z.enum(['Low', 'Medium', 'High', 'Critical']);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

export const ThreatActionSchema = z.enum(['Blocked', 'Alerted', 'Throttled']);
export type ThreatAction = z.infer<typeof ThreatActionSchema>;

export const GuardianModuleSchema = z.enum([
  'network-monitor',
  'policy-composer',
  'firewall-rules',
  'threat-timeline',
  'watchlist',
  'tls-inspector',
  'security-events',
  'manual',
]);
export type GuardianModule = z.infer<typeof GuardianModuleSchema>;

export const PolicyStatusSchema = z.enum(['pending', 'accepted', 'dismissed']);
export type PolicyStatus = z.infer<typeof PolicyStatusSchema>;

const IPSchema = z.string().ip({ version: 'v4' }).or(z.string().ip({ version: 'v6' }));

// ═══════════════════════════════════════════════════════════
// FIREWALL ENGINE SCHEMAS
// ═══════════════════════════════════════════════════════════

export const BlockPortSchema = z.object({
  port: z.number().int().min(0).max(65535),
  protocol: FirewallProtocolSchema.default('TCP'),
  direction: FirewallDirectionSchema.default('both'),
  options: z.object({
    loopbackOnly: z.boolean().optional(),
  }).partial().optional(),
});
export type BlockPortRequest = z.infer<typeof BlockPortSchema>;

export const BlockSubnetSchema = z.object({
  input: z.string().min(1),
  subnetMask: SubnetMaskSchema.optional(),
  direction: FirewallDirectionSchema.default('both'),
});
export type BlockSubnetRequest = z.infer<typeof BlockSubnetSchema>;

export const BlockPidSchema = z.object({
  pid: z.number().int().nonnegative(),
  direction: FirewallDirectionSchema.default('both'),
});
export type BlockPidRequest = z.infer<typeof BlockPidSchema>;

export const BlockIPSchema = z.object({
  ip: IPSchema,
  reason: z.string().min(1).max(500),
});
export type BlockIPRequest = z.infer<typeof BlockIPSchema>;

export const UnblockIPSchema = z.object({
  ip: IPSchema,
});
export type UnblockIPRequest = z.infer<typeof UnblockIPSchema>;

export const BlockIpSubnetSchema = z.object({
  ip: z.string().min(1),
  subnetMask: SubnetMaskSchema,
});
export type BlockIpSubnetRequest = z.infer<typeof BlockIpSubnetSchema>;

export const StageFirewallRuleSchema = z.object({
  sessionKey: z.string().min(1, 'sessionKey required'),
  pid: z.number().int().min(0),
  processName: z.string().min(1),
  remoteIP: IPSchema,
  remotePort: z.number().int().min(0).max(65535).optional(),
  reasons: z.array(z.string().min(1)).max(10),
  recommendsBlock: z.boolean(),
  ttlSeconds: z.number().int().min(30).max(24 * 60 * 60).optional(),
});
export type StageFirewallRuleRequest = z.infer<typeof StageFirewallRuleSchema>;

export const StageFirewallRuleResponseSchema = z.object({
  pendingRuleId: z.string().uuid(),
  expiresAt: z.number().int(),
});
export type StageFirewallRuleResponse = z.infer<typeof StageFirewallRuleResponseSchema>;

export const CommitPendingRuleSchema = z.object({
  pendingRuleId: z.string().uuid(),
});
export type CommitPendingRuleRequest = z.infer<typeof CommitPendingRuleSchema>;

export const DismissPendingRuleSchema = CommitPendingRuleSchema;
export type DismissPendingRuleRequest = z.infer<typeof DismissPendingRuleSchema>;

export const WhitelistThreatSchema = z.object({
  ip: z.string().optional(),
  subnet: z.string().optional(),
  processName: z.string().optional(),
  pid: z.number().int().optional(),
  reason: z.string().optional(),
});
export type WhitelistThreatRequest = z.infer<typeof WhitelistThreatSchema>;

export const ManualBlockLogSchema = z.object({
  ip: z.string().min(1),
  subnet: z.string().min(1).optional(),
  port: z.number().int().min(0).max(65535).optional(),
  pid: z.number().int().nonnegative().optional(),
  processName: z.string().min(1).optional(),
  reason: z.string().min(1).optional(),
});
export type ManualBlockLogRequest = z.infer<typeof ManualBlockLogSchema>;

export const QuickBlockSubnetSchema = z.object({
  subnet: z.string().min(1),
  reason: z.string().optional(),
});
export type QuickBlockSubnetRequest = z.infer<typeof QuickBlockSubnetSchema>;

// ═══════════════════════════════════════════════════════════
// FIREWALL RULE TYPES
// ═══════════════════════════════════════════════════════════

export const FirewallRuleSchema = z.object({
  name: z.string().optional(),
  direction: z.string().optional(),
  action: z.string().optional(),
  enabled: z.union([z.boolean(), z.string()]).optional(),
  profile: z.string().optional(),
  protocol: z.string().optional(),
  program: z.string().optional(),
  localPort: z.union([z.string(), z.number()]).optional(),
  remotePort: z.union([z.string(), z.number()]).optional(),
  localAddress: z.string().optional(),
  remoteAddress: z.string().optional(),
  description: z.string().optional(),
  timeCreated: z.string().nullable().optional(),
});
export type FirewallRule = z.infer<typeof FirewallRuleSchema>;

export const BlockedIpSchema = z.object({
  ip: z.string(),
  reason: z.string().optional(),
  blocked: z.boolean().optional(),
  timestamp: z.string().optional(),
});
export type BlockedIpRecord = z.infer<typeof BlockedIpSchema>;

export const FirewallInventoryMetaSchema = z.object({
  totalCollected: z.number().int().nonnegative().optional(),
  sentinelTagged: z.number().int().nonnegative().optional(),
  tracked: z.number().int().nonnegative().optional(),
  fallbackUsed: z.boolean().optional(),
  powershellRuleCount: z.number().int().nonnegative().optional(),
  blockedIpCount: z.number().int().nonnegative().optional(),
  blockedIpsError: z.string().nullable().optional(),
  errors: z.array(z.string()).optional(),
  generatedAt: z.number().int().optional(),
});
export type FirewallInventoryMeta = z.infer<typeof FirewallInventoryMetaSchema>;

export const FirewallInventoryResponseSchema = z.object({
  success: z.boolean(),
  rules: z.array(FirewallRuleSchema).optional(),
  blockedIps: z.array(BlockedIpSchema).optional(),
  meta: FirewallInventoryMetaSchema.optional(),
  error: z.string().optional(),
});
export type FirewallInventoryResponse = z.infer<typeof FirewallInventoryResponseSchema>;

// ═══════════════════════════════════════════════════════════
// THREAT INTELLIGENCE SCHEMAS
// ═══════════════════════════════════════════════════════════

export const ThreatTimelineFiltersSchema = z.object({
  pid: z.number().int().optional(),
  processName: z.string().min(1).optional(),
  range: z.object({
    from: z.number().int(),
    to: z.number().int(),
  }).refine((v) => v.from <= v.to, { message: 'from must be <= to' }).optional(),
});
export type ThreatTimelineFilters = z.infer<typeof ThreatTimelineFiltersSchema>;

export const GetThreatEventsSchema = z.object({
  cursor: z.string().optional(),
  limit: z.number().int().min(10).max(200).optional(),
  filters: ThreatTimelineFiltersSchema.optional(),
});
export type GetThreatEventsRequest = z.infer<typeof GetThreatEventsSchema>;

export const ThreatEventSchema = z.object({
  id: z.string().min(1),
  timestamp: z.number().int(),
  pid: z.number().int(),
  processName: z.string(),
  remoteIP: z.string().optional(),
  remoteSubnet: z.string().optional(),
  riskScore: z.number(),
  riskLevel: RiskLevelSchema,
  actionTaken: ThreatActionSchema,
  reason: z.string().optional(),
});
export type ThreatEvent = z.infer<typeof ThreatEventSchema>;

export const GetThreatEventsResponseSchema = z.object({
  events: z.array(ThreatEventSchema),
  nextCursor: z.string().nullable(),
});
export type GetThreatEventsResponse = z.infer<typeof GetThreatEventsResponseSchema>;

// Guardian Events & Stories
export const GuardianEventSchema = z.object({
  id: z.string(),
  timestamp: z.number().int(),
  pid: z.number().int().optional(),
  processName: z.string().optional(),
  remoteIP: z.string().optional(),
  remoteSubnet: z.string().optional(),
  fingerprint: z.string().optional(),
  module: GuardianModuleSchema,
  action: z.string().optional(),
  riskScore: z.number().optional(),
  riskLevel: RiskLevelSchema.optional(),
  metadata: z.record(z.any()).optional(),
});
export type GuardianEvent = z.infer<typeof GuardianEventSchema>;

export const LogGuardianEventSchema = GuardianEventSchema.omit({ id: true }).extend({
  id: z.string().optional(),
});
export type LogGuardianEventRequest = z.infer<typeof LogGuardianEventSchema>;

export const GuardianStorySchema = z.object({
  id: z.string(),
  firstSeen: z.number().int(),
  lastSeen: z.number().int(),
  modules: z.array(GuardianModuleSchema),
  maxRiskScore: z.number().optional(),
  maxRiskLevel: RiskLevelSchema.optional(),
  pid: z.number().int().optional(),
  processName: z.string().optional(),
  remoteIP: z.string().optional(),
  remoteSubnet: z.string().optional(),
  policyFingerprint: z.string().optional(),
  linkedThreatIds: z.array(z.string()).optional(),
  linkedPolicyIds: z.array(z.string()).optional(),
  summary: z.string().optional(),
});
export type GuardianStory = z.infer<typeof GuardianStorySchema>;

export const GetGuardianStoriesSchema = z.object({
  cursor: z.string().optional(),
  limit: z.number().int().min(10).max(100).optional(),
  pid: z.number().int().optional(),
  processName: z.string().optional(),
  remoteIP: z.string().optional(),
  module: GuardianModuleSchema.optional(),
});
export type GetGuardianStoriesRequest = z.infer<typeof GetGuardianStoriesSchema>;

export const GetGuardianStoriesResponseSchema = z.object({
  stories: z.array(GuardianStorySchema),
  nextCursor: z.string().nullable(),
});
export type GetGuardianStoriesResponse = z.infer<typeof GetGuardianStoriesResponseSchema>;

// Guardian Playbooks
const PlaybookConditionSchema = z.object({
  modules: z.array(GuardianModuleSchema).nonempty().optional(),
  minRiskLevel: RiskLevelSchema.optional(),
  processName: z.string().optional(),
  remoteIP: z.string().optional(),
  fingerprint: z.string().optional(),
  tags: z.array(z.string().min(1)).optional(),
});
export type PlaybookCondition = z.infer<typeof PlaybookConditionSchema>;

const PlaybookActionSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('log'), message: z.string().min(1) }),
  z.object({ type: z.literal('stage-firewall-rule'), ttlSeconds: z.number().int().min(30).max(86400).optional(), block: z.boolean().default(true) }),
  z.object({ type: z.literal('dispatch-script'), scriptId: z.string().min(1), args: z.array(z.string()).max(10).optional() }),
  z.object({ type: z.literal('notify'), channel: z.enum(['toast', 'system', 'webhook']).default('toast'), title: z.string().min(1), body: z.string().optional() }),
]);
export type PlaybookAction = z.infer<typeof PlaybookActionSchema>;

export const PlaybookSchema = z.object({
  id: z.string(),
  name: z.string().min(1),
  description: z.string().optional(),
  enabled: z.boolean(),
  priority: z.number().int().min(0).optional(),
  tags: z.array(z.string().min(1)).optional(),
  conditions: z.array(PlaybookConditionSchema).nonempty(),
  actions: z.array(PlaybookActionSchema).nonempty(),
  createdAt: z.number().int(),
  updatedAt: z.number().int(),
});
export type Playbook = z.infer<typeof PlaybookSchema>;

export const SavePlaybookSchema = PlaybookSchema.omit({ createdAt: true, updatedAt: true }).extend({
  id: z.string().optional(),
});
export type SavePlaybookRequest = z.infer<typeof SavePlaybookSchema>;

export const SavePlaybookResponseSchema = z.object({ playbook: PlaybookSchema });
export type SavePlaybookResponse = z.infer<typeof SavePlaybookResponseSchema>;

export const DeletePlaybookSchema = z.object({ id: z.string().min(1) });
export type DeletePlaybookRequest = z.infer<typeof DeletePlaybookSchema>;

export const RunPlaybookSchema = z.object({
  id: z.string().min(1),
  context: GuardianEventSchema.partial().optional(),
  dryRun: z.boolean().optional(),
});
export type RunPlaybookRequest = z.infer<typeof RunPlaybookSchema>;

export const RunPlaybookResponseSchema = z.object({
  success: z.boolean(),
  actionsExecuted: z.number().int().nonnegative(),
  log: z.array(z.string()).optional(),
});
export type RunPlaybookResponse = z.infer<typeof RunPlaybookResponseSchema>;

export const PlaybookRunSchema = z.object({
  id: z.string(),
  playbookId: z.string(),
  triggeredAt: z.number().int(),
  status: z.enum(['pending', 'completed', 'failed']),
  actionsExecuted: z.number().int().nonnegative(),
  error: z.string().optional(),
});
export type PlaybookRun = z.infer<typeof PlaybookRunSchema>;

export const ListPlaybooksResponseSchema = z.object({ playbooks: z.array(PlaybookSchema) });
export type ListPlaybooksResponse = z.infer<typeof ListPlaybooksResponseSchema>;

export const GetPlaybookRunsResponseSchema = z.object({ runs: z.array(PlaybookRunSchema) });
export type GetPlaybookRunsResponse = z.infer<typeof GetPlaybookRunsResponseSchema>;

// Threat Intel
const ThreatIntelIndicatorTypeSchema = z.enum(['ip', 'domain', 'hash']);

export const ThreatIntelRecordSchema = z.object({
  indicator: z.string().min(1),
  type: ThreatIntelIndicatorTypeSchema,
  reputation: z.number().min(0).max(100).optional(),
  confidence: z.number().min(0).max(100).optional(),
  sources: z.array(z.string().min(1)).nonempty(),
  tags: z.array(z.string().min(1)).optional(),
  lastSeen: z.number().int().optional(),
  metadata: z.record(z.any()).optional(),
});
export type ThreatIntelRecord = z.infer<typeof ThreatIntelRecordSchema>;

export const GetThreatIntelSchema = z.object({
  indicator: z.string().optional(),
  type: ThreatIntelIndicatorTypeSchema.optional(),
  cursor: z.string().optional(),
  limit: z.number().int().min(5).max(100).optional(),
});
export type GetThreatIntelRequest = z.infer<typeof GetThreatIntelSchema>;

export const GetThreatIntelResponseSchema = z.object({
  records: z.array(ThreatIntelRecordSchema),
  nextCursor: z.string().nullable(),
});
export type GetThreatIntelResponse = z.infer<typeof GetThreatIntelResponseSchema>;

export const RefreshThreatIntelSchema = z.object({
  indicator: z.string().min(1),
  source: z.string().optional(),
  force: z.boolean().optional(),
});
export type RefreshThreatIntelRequest = z.infer<typeof RefreshThreatIntelSchema>;

export const RefreshThreatIntelResponseSchema = z.object({
  refreshed: z.boolean(),
  records: z.array(ThreatIntelRecordSchema).optional(),
});
export type RefreshThreatIntelResponse = z.infer<typeof RefreshThreatIntelResponseSchema>;

// Anomaly Config
export const AnomalyConfigSchema = z.object({
  enabled: z.boolean(),
  sensitivity: z.enum(['low', 'medium', 'high']).default('medium'),
  windowMinutes: z.number().int().min(5).max(1440),
  minSamples: z.number().int().min(10).max(10000),
});
export type AnomalyConfig = z.infer<typeof AnomalyConfigSchema>;

export const GetAnomalyConfigResponseSchema = z.object({ config: AnomalyConfigSchema });
export type GetAnomalyConfigResponse = z.infer<typeof GetAnomalyConfigResponseSchema>;

// Policy Suggestions
export const PolicyIntelSchema = z.object({
  ip: z.string().optional(),
  org: z.string().optional(),
  country: z.string().optional(),
  region: z.string().optional(),
  city: z.string().optional(),
  watchHits: z.number().int().optional(),
  lastSeen: z.number().int().optional(),
  tlsGrade: z.string().optional(),
  tlsIssues: z.array(z.string()).optional(),
  leakSignals: z.array(z.string()).optional(),
  riskSummary: z.string().optional(),
});
export type PolicyIntel = z.infer<typeof PolicyIntelSchema>;

export const PolicySuggestionSchema = z.object({
  id: z.string().uuid(),
  createdAt: z.number().int(),
  updatedAt: z.number().int(),
  recommendation: z.string().min(1),
  confidence: z.number().min(0).max(1),
  evidenceCount: z.number().int().min(0),
  remoteIP: z.string().ip().optional(),
  processName: z.string().optional(),
  status: PolicyStatusSchema,
  fingerprint: z.string().optional(),
  intel: PolicyIntelSchema.optional(),
});
export type PolicySuggestion = z.infer<typeof PolicySuggestionSchema>;

export const GetPolicySuggestionsSchema = z.object({
  cursor: z.string().optional(),
  limit: z.number().int().min(5).max(50).optional(),
  status: PolicyStatusSchema.optional(),
});
export type GetPolicySuggestionsRequest = z.infer<typeof GetPolicySuggestionsSchema>;

export const GetPolicySuggestionsResponseSchema = z.object({
  suggestions: z.array(PolicySuggestionSchema),
  nextCursor: z.string().nullable(),
});
export type GetPolicySuggestionsResponse = z.infer<typeof GetPolicySuggestionsResponseSchema>;

export const AcceptPolicySchema = z.object({ policyId: z.string().uuid() });
export type AcceptPolicyRequest = z.infer<typeof AcceptPolicySchema>;

export const DismissPolicySchema = AcceptPolicySchema;
export type DismissPolicyRequest = z.infer<typeof DismissPolicySchema>;

export const PolicyMutationResponseSchema = z.object({ suggestion: PolicySuggestionSchema });
export type PolicyMutationResponse = z.infer<typeof PolicyMutationResponseSchema>;

// ═══════════════════════════════════════════════════════════
// NETWORK SCHEMAS
// ═══════════════════════════════════════════════════════════

export const InspectTlsSchema = z.object({
  host: z.string().min(1),
});
export type InspectTlsRequest = z.infer<typeof InspectTlsSchema>;

export const RegisterWatchSchema = z.object({
  ip: z.string().min(1),
});
export type RegisterWatchRequest = z.infer<typeof RegisterWatchSchema>;

// ═══════════════════════════════════════════════════════════
// SECURITY EVENT SCHEMAS
// ═══════════════════════════════════════════════════════════

export const SecurityEventSchema = z.object({
  pid: z.number().int(),
  processName: z.string(),
  processCompany: z.string().optional(),
  processPath: z.string().optional(),
  localPort: z.number().int(),
  remoteSubnet: z.string(),
  remoteIP: z.string(),
  riskScore: z.number(),
  riskLevel: RiskLevelSchema,
  tlsStatus: z.string(),
  reason: z.string(),
  actionTaken: ThreatActionSchema,
});
export type SecurityEventInput = z.infer<typeof SecurityEventSchema>;

// ═══════════════════════════════════════════════════════════
// SENSITIVE PROCESS ALERTS
// ═══════════════════════════════════════════════════════════

export const SensitiveAlertSchema = z.object({
  pid: z.number().int(),
  processName: z.string().min(1),
  remoteIP: z.string().ip(),
  remotePort: z.number().int().min(0).max(65535).optional(),
  reason: z.literal('sensitive-watch'),
  detectedAt: z.number().int(),
});
export type SensitiveAlert = z.infer<typeof SensitiveAlertSchema>;

// ═══════════════════════════════════════════════════════════
// CSP VIOLATION REPORTING
// ═══════════════════════════════════════════════════════════

export const CspReportSchema = z.object({
  documentURI: z.string().url(),
  referrer: z.string().optional(),
  blockedURI: z.string().optional(),
  violatedDirective: z.string().min(1),
  effectiveDirective: z.string().optional(),
  originalPolicy: z.string().optional(),
  sourceFile: z.string().optional(),
  lineNumber: z.number().int().optional(),
  columnNumber: z.number().int().optional(),
  disposition: z.enum(['enforce', 'report']).optional(),
  statusCode: z.number().int().optional(),
  timestamp: z.number().int().optional(),
});
export type CspReportRequest = z.infer<typeof CspReportSchema>;

// ═══════════════════════════════════════════════════════════
// ARGUS SCHEMAS
// ═══════════════════════════════════════════════════════════

export const ArgusUrlScanSchema = z.object({
  url: z.string().url().min(1),
});
export type ArgusUrlScanRequest = z.infer<typeof ArgusUrlScanSchema>;

export const ArgusBatchScanSchema = z.object({
  urls: z.array(z.string().url()).min(1).max(100),
});
export type ArgusBatchScanRequest = z.infer<typeof ArgusBatchScanSchema>;

export const ArgusScanHistorySchema = z.object({
  limit: z.number().int().min(1).max(500).default(50),
  offset: z.number().int().min(0).default(0),
});
export type ArgusScanHistoryRequest = z.infer<typeof ArgusScanHistorySchema>;

export const ArgusEncryptSchema = z.object({
  data: z.string().min(1),
});
export type ArgusEncryptRequest = z.infer<typeof ArgusEncryptSchema>;

export const ArgusDecryptSchema = z.object({
  encryptedData: z.string().min(1),
});
export type ArgusDecryptRequest = z.infer<typeof ArgusDecryptSchema>;

export const ArgusSandboxToggleSchema = z.object({
  enabled: z.boolean(),
});
export type ArgusSandboxToggleRequest = z.infer<typeof ArgusSandboxToggleSchema>;
