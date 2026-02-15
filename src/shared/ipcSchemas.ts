import { z } from 'zod';

const FirewallDirectionSchema = z.enum(['in', 'out', 'both']);
const FirewallProtocolSchema = z.enum(['TCP', 'UDP', 'Both']);
const SubnetMaskSchema = z.union([
  z.literal(8),
  z.literal(16),
  z.literal(20),
  z.literal(22),
  z.literal(24),
  z.literal(26),
  z.literal(30),
  z.literal(32),
]);

export type FirewallDirection = z.infer<typeof FirewallDirectionSchema>;
export type FirewallProtocol = z.infer<typeof FirewallProtocolSchema>;
export type SubnetMaskBits = z.infer<typeof SubnetMaskSchema>;

// ==== Session Monitor ↔ Firewall Pending Rule Workflow ====
export const ShieldStageFirewallRuleRequestSchema = z.object({
  sessionKey: z.string().min(1, 'sessionKey required'),
  pid: z.number().int().min(0),
  processName: z.string().min(1),
  remoteIP: z.string().ip({ version: 'v4' }).or(z.string().ip({ version: 'v6' })),
  remotePort: z.number().int().min(0).max(65535).optional(),
  reasons: z.array(z.string().min(1)).max(10),
  recommendsBlock: z.boolean(),
  ttlSeconds: z.number().int().min(30).max(24 * 60 * 60).optional(),
});
export type ShieldStageFirewallRuleRequest = z.infer<typeof ShieldStageFirewallRuleRequestSchema>;

export const ShieldStageFirewallRuleResponseSchema = z.object({
  pendingRuleId: z.string().uuid(),
  expiresAt: z.number().int(),
});
export type ShieldStageFirewallRuleResponse = z.infer<typeof ShieldStageFirewallRuleResponseSchema>;

export const ShieldCommitPendingRuleSchema = z.object({
  pendingRuleId: z.string().uuid(),
});
export type ShieldCommitPendingRule = z.infer<typeof ShieldCommitPendingRuleSchema>;

export const ShieldDismissPendingRuleSchema = ShieldCommitPendingRuleSchema;
export type ShieldDismissPendingRule = z.infer<typeof ShieldDismissPendingRuleSchema>;

// ==== Threat Timeline Paging ====
export const ThreatTimelineFiltersSchema = z.object({
  pid: z.number().int().optional(),
  processName: z.string().min(1).optional(),
  range: z
    .object({
      from: z.number().int(),
      to: z.number().int(),
    })
    .refine((value) => value.from <= value.to, {
      message: 'from must be <= to',
    })
    .optional(),
});
export type ThreatTimelineFilters = z.infer<typeof ThreatTimelineFiltersSchema>;

export const ShieldGetThreatEventsRequestSchema = z.object({
  cursor: z.string().optional(),
  limit: z.number().int().min(10).max(200).optional(),
  filters: ThreatTimelineFiltersSchema.optional(),
});
export type ShieldGetThreatEventsRequest = z.infer<typeof ShieldGetThreatEventsRequestSchema>;

const RiskLevelSchema = z.enum(['Low', 'Medium', 'High', 'Critical']);
const ThreatActionSchema = z.enum(['Blocked', 'Alerted', 'Throttled']);
const GuardianModuleSchema = z.enum([
  'network-monitor',
  'policy-composer',
  'firewall-rules',
  'threat-timeline',
  'watchlist',
  'tls-inspector',
  'security-events',
  'manual',
]);

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

export const ShieldGetThreatEventsResponseSchema = z.object({
  events: z.array(ThreatEventSchema),
  nextCursor: z.string().nullable(),
});
export type ShieldGetThreatEventsResponse = z.infer<typeof ShieldGetThreatEventsResponseSchema>;

// ==== Guardian Event Bus / Stories ====
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

const GuardianPlaybookConditionSchema = z.object({
  modules: z.array(GuardianModuleSchema).nonempty().optional(),
  minRiskLevel: RiskLevelSchema.optional(),
  processName: z.string().optional(),
  remoteIP: z.string().optional(),
  fingerprint: z.string().optional(),
  tags: z.array(z.string().min(1)).optional(),
});
export type GuardianPlaybookCondition = z.infer<typeof GuardianPlaybookConditionSchema>;

const GuardianPlaybookActionSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('log'),
    message: z.string().min(1),
  }),
  z.object({
    type: z.literal('stage-firewall-rule'),
    ttlSeconds: z.number().int().min(30).max(24 * 60 * 60).optional(),
    block: z.boolean().default(true),
  }),
  z.object({
    type: z.literal('dispatch-script'),
    scriptId: z.string().min(1),
    args: z.array(z.string()).max(10).optional(),
  }),
  z.object({
    type: z.literal('notify'),
    channel: z.enum(['toast', 'system', 'webhook']).default('toast'),
    title: z.string().min(1),
    body: z.string().optional(),
  }),
]);
export type GuardianPlaybookAction = z.infer<typeof GuardianPlaybookActionSchema>;

export const GuardianPlaybookSchema = z.object({
  id: z.string(),
  name: z.string().min(1),
  description: z.string().optional(),
  enabled: z.boolean(),
  priority: z.number().int().min(0).optional(),
  tags: z.array(z.string().min(1)).optional(),
  conditions: z.array(GuardianPlaybookConditionSchema).nonempty(),
  actions: z.array(GuardianPlaybookActionSchema).nonempty(),
  createdAt: z.number().int(),
  updatedAt: z.number().int(),
});
export type GuardianPlaybook = z.infer<typeof GuardianPlaybookSchema>;

export const GuardianPlaybookRunSchema = z.object({
  id: z.string(),
  playbookId: z.string(),
  triggeredAt: z.number().int(),
  status: z.enum(['pending', 'completed', 'failed']),
  actionsExecuted: z.number().int().nonnegative(),
  error: z.string().optional(),
});
export type GuardianPlaybookRun = z.infer<typeof GuardianPlaybookRunSchema>;

const GuardianThreatIntelIndicatorTypeSchema = z.enum(['ip', 'domain', 'hash']);

export const GuardianThreatIntelRecordSchema = z.object({
  indicator: z.string().min(1),
  type: GuardianThreatIntelIndicatorTypeSchema,
  reputation: z.number().min(0).max(100).optional(),
  confidence: z.number().min(0).max(100).optional(),
  sources: z.array(z.string().min(1)).nonempty(),
  tags: z.array(z.string().min(1)).optional(),
  lastSeen: z.number().int().optional(),
  metadata: z.record(z.any()).optional(),
});
export type GuardianThreatIntelRecord = z.infer<typeof GuardianThreatIntelRecordSchema>;

export const GuardianAnomalyConfigSchema = z.object({
  enabled: z.boolean(),
  sensitivity: z.enum(['low', 'medium', 'high']).default('medium'),
  windowMinutes: z.number().int().min(5).max(24 * 60),
  minSamples: z.number().int().min(10).max(10000),
});
export type GuardianAnomalyConfig = z.infer<typeof GuardianAnomalyConfigSchema>;

export const ShieldLogGuardianEventRequestSchema = GuardianEventSchema.omit({ id: true }).extend({
  id: z.string().optional(),
});
export type ShieldLogGuardianEventRequest = z.infer<typeof ShieldLogGuardianEventRequestSchema>;

export const ShieldGetGuardianStoriesRequestSchema = z.object({
  cursor: z.string().optional(),
  limit: z.number().int().min(10).max(100).optional(),
  pid: z.number().int().optional(),
  processName: z.string().optional(),
  remoteIP: z.string().optional(),
  module: GuardianModuleSchema.optional(),
});
export type ShieldGetGuardianStoriesRequest = z.infer<typeof ShieldGetGuardianStoriesRequestSchema>;

export const ShieldGetGuardianStoriesResponseSchema = z.object({
  stories: z.array(GuardianStorySchema),
  nextCursor: z.string().nullable(),
});
export type ShieldGetGuardianStoriesResponse = z.infer<typeof ShieldGetGuardianStoriesResponseSchema>;

export const GuardianListPlaybooksResponseSchema = z.object({
  playbooks: z.array(GuardianPlaybookSchema),
});
export type GuardianListPlaybooksResponse = z.infer<typeof GuardianListPlaybooksResponseSchema>;

export const GuardianSavePlaybookRequestSchema = GuardianPlaybookSchema.omit({
  createdAt: true,
  updatedAt: true,
}).extend({
  id: z.string().optional(),
});
export type GuardianSavePlaybookRequest = z.infer<typeof GuardianSavePlaybookRequestSchema>;

export const GuardianSavePlaybookResponseSchema = z.object({
  playbook: GuardianPlaybookSchema,
});
export type GuardianSavePlaybookResponse = z.infer<typeof GuardianSavePlaybookResponseSchema>;

export const GuardianDeletePlaybookRequestSchema = z.object({
  id: z.string().min(1),
});
export type GuardianDeletePlaybookRequest = z.infer<typeof GuardianDeletePlaybookRequestSchema>;

export const GuardianRunPlaybookRequestSchema = z.object({
  id: z.string().min(1),
  context: GuardianEventSchema.partial().optional(),
  dryRun: z.boolean().optional(),
});
export type GuardianRunPlaybookRequest = z.infer<typeof GuardianRunPlaybookRequestSchema>;

export const GuardianRunPlaybookResponseSchema = z.object({
  success: z.boolean(),
  actionsExecuted: z.number().int().nonnegative(),
  log: z.array(z.string()).optional(),
});
export type GuardianRunPlaybookResponse = z.infer<typeof GuardianRunPlaybookResponseSchema>;

export const GuardianGetPlaybookRunsResponseSchema = z.object({
  runs: z.array(GuardianPlaybookRunSchema),
});
export type GuardianGetPlaybookRunsResponse = z.infer<typeof GuardianGetPlaybookRunsResponseSchema>;

export const GuardianGetThreatIntelRequestSchema = z.object({
  indicator: z.string().optional(),
  type: GuardianThreatIntelIndicatorTypeSchema.optional(),
  cursor: z.string().optional(),
  limit: z.number().int().min(5).max(100).optional(),
});
export type GuardianGetThreatIntelRequest = z.infer<typeof GuardianGetThreatIntelRequestSchema>;

export const GuardianGetThreatIntelResponseSchema = z.object({
  records: z.array(GuardianThreatIntelRecordSchema),
  nextCursor: z.string().nullable(),
});
export type GuardianGetThreatIntelResponse = z.infer<typeof GuardianGetThreatIntelResponseSchema>;

export const GuardianRefreshThreatIntelRequestSchema = z.object({
  indicator: z.string().min(1),
  source: z.string().optional(),
  force: z.boolean().optional(),
});
export type GuardianRefreshThreatIntelRequest = z.infer<typeof GuardianRefreshThreatIntelRequestSchema>;

export const GuardianRefreshThreatIntelResponseSchema = z.object({
  refreshed: z.boolean(),
  records: z.array(GuardianThreatIntelRecordSchema).optional(),
});
export type GuardianRefreshThreatIntelResponse = z.infer<typeof GuardianRefreshThreatIntelResponseSchema>;

export const GuardianGetAnomalyConfigResponseSchema = z.object({
  config: GuardianAnomalyConfigSchema,
});
export type GuardianGetAnomalyConfigResponse = z.infer<typeof GuardianGetAnomalyConfigResponseSchema>;

export const GuardianUpdateAnomalyConfigRequestSchema = GuardianAnomalyConfigSchema;
export type GuardianUpdateAnomalyConfigRequest = z.infer<typeof GuardianUpdateAnomalyConfigRequestSchema>;

// ==== Policy Composer Suggestions ====
export const PolicyStatusSchema = z.enum(['pending', 'accepted', 'dismissed']);

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

export const ShieldGetPolicySuggestionsRequestSchema = z.object({
  cursor: z.string().optional(),
  limit: z.number().int().min(5).max(50).optional(),
  status: PolicyStatusSchema.optional(),
});
export type ShieldGetPolicySuggestionsRequest = z.infer<typeof ShieldGetPolicySuggestionsRequestSchema>;

export const ShieldGetPolicySuggestionsResponseSchema = z.object({
  suggestions: z.array(PolicySuggestionSchema),
  nextCursor: z.string().nullable(),
});
export type ShieldGetPolicySuggestionsResponse = z.infer<typeof ShieldGetPolicySuggestionsResponseSchema>;

export const ShieldAcceptPolicySchema = z.object({
  policyId: z.string().uuid(),
});
export type ShieldAcceptPolicyRequest = z.infer<typeof ShieldAcceptPolicySchema>;

export const ShieldDismissPolicySchema = ShieldAcceptPolicySchema;
export type ShieldDismissPolicyRequest = z.infer<typeof ShieldDismissPolicySchema>;

export const ShieldPolicyMutationResponseSchema = z.object({
  suggestion: PolicySuggestionSchema,
});
export type ShieldPolicyMutationResponse = z.infer<typeof ShieldPolicyMutationResponseSchema>;

// ==== Firewall Actions (Shield) ====
export const ShieldBlockPortRequestSchema = z.object({
  port: z.number().int().min(0).max(65535),
  protocol: FirewallProtocolSchema.default('TCP'),
  direction: FirewallDirectionSchema.default('both'),
  options: z
    .object({
      loopbackOnly: z.boolean().optional(),
    })
    .partial()
    .optional(),
});
export type ShieldBlockPortRequest = z.infer<typeof ShieldBlockPortRequestSchema>;

export const ShieldBlockSubnetRequestSchema = z.object({
  input: z.string().min(1),
  subnetMask: SubnetMaskSchema.optional(),
  direction: FirewallDirectionSchema.default('both'),
});
export type ShieldBlockSubnetRequest = z.infer<typeof ShieldBlockSubnetRequestSchema>;

export const ShieldBlockPidRequestSchema = z.object({
  pid: z.number().int().nonnegative(),
  direction: FirewallDirectionSchema.default('both'),
});
export type ShieldBlockPidRequest = z.infer<typeof ShieldBlockPidRequestSchema>;

export const ShieldManualBlockLogSchema = z.object({
  ip: z.string().min(1),
  subnet: z.string().min(1).optional(),
  port: z.number().int().min(0).max(65535).optional(),
  pid: z.number().int().nonnegative().optional(),
  processName: z.string().min(1).optional(),
  reason: z.string().min(1).optional(),
});
export type ShieldManualBlockLogRequest = z.infer<typeof ShieldManualBlockLogSchema>;

const SentinelFirewallRuleSchema = z.object({
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
export type SentinelFirewallRule = z.infer<typeof SentinelFirewallRuleSchema>;

const ShieldBlockedIpSchema = z.object({
  ip: z.string(),
  reason: z.string().optional(),
  blocked: z.boolean().optional(),
  timestamp: z.string().optional(),
});
export type ShieldBlockedIpRecord = z.infer<typeof ShieldBlockedIpSchema>;

const ShieldFirewallInventoryMetaSchema = z.object({
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
export type ShieldFirewallInventoryMeta = z.infer<typeof ShieldFirewallInventoryMetaSchema>;

export const ShieldFirewallInventoryResponseSchema = z.object({
  success: z.boolean(),
  rules: z.array(SentinelFirewallRuleSchema).optional(),
  blockedIps: z.array(ShieldBlockedIpSchema).optional(),
  meta: ShieldFirewallInventoryMetaSchema.optional(),
  error: z.string().optional(),
});
export type ShieldFirewallInventoryResponse = z.infer<typeof ShieldFirewallInventoryResponseSchema>;

// ==== Sensitive Process Alerts ====
export const ShieldSensitiveAlertSchema = z.object({
  pid: z.number().int(),
  processName: z.string().min(1),
  remoteIP: z.string().ip(),
  remotePort: z.number().int().min(0).max(65535).optional(),
  reason: z.literal('sensitive-watch'),
  detectedAt: z.number().int(),
});
export type ShieldSensitiveAlert = z.infer<typeof ShieldSensitiveAlertSchema>;

// ==== CSP Violation Reporting ====
export const ShieldLogCspReportSchema = z.object({
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
export type ShieldLogCspReportRequest = z.infer<typeof ShieldLogCspReportSchema>;

// ==== Scan Check Result Schema (v3.1 — BUG-014/019) ====
export const ScanCheckResultSchema = z.object({
  id: z.string(),
  name: z.string(),
  category: z.enum(['network', 'privacy', 'performance', 'kernel', 'edr']),
  status: z.enum(['pass', 'warn', 'fail']),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  summary: z.string(),
  score: z.number().min(0).max(100),
  detail: z.object({
    whatChecked: z.string(),
    whatFound: z.string(),
    offenders: z.array(z.object({
      label: z.string(),
      detail: z.string(),
      severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
    })).optional(),
    riskExplanation: z.string(),
    fixActions: z.array(z.string()),
    preserves: z.array(z.string()),
    canUndo: z.boolean(),
    undoPath: z.string().optional(),
    references: z.array(z.object({
      label: z.string(), url: z.string().optional(),
    })).optional(),
  }),
  fixAvailable: z.boolean(),
  fixHandler: z.string().optional(),
  fixPayload: z.record(z.unknown()).optional(),
  lastChecked: z.number(),
  vpnAware: z.boolean().default(false),
});
export type ScanCheckResult = z.infer<typeof ScanCheckResultSchema>;

export const ScanResultSchema = z.object({
  scanType: z.string(),
  score: z.number(),
  maxScore: z.number(),
  checks: z.array(ScanCheckResultSchema),
  passed: z.number(),
  failed: z.number(),
  warnings: z.number(),
  timestamp: z.number(),
  duration: z.number(),
  vpnActive: z.boolean(),
});
export type ScanResult = z.infer<typeof ScanResultSchema>;
