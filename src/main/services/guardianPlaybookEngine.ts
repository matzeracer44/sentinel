import { app, BrowserWindow } from 'electron';
import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { randomUUID } from 'crypto';
import {
  GuardianEvent,
  GuardianPlaybook,
  GuardianPlaybookAction,
  GuardianPlaybookCondition,
  ShieldStageFirewallRuleRequest,
} from '@/shared/ipcSchemas';
import {
  appendGuardianEvent,
  listGuardianPlaybooks,
  getGuardianPlaybookById,
  logGuardianPlaybookRun,
  getGuardianPlaybookRuns,
  saveGuardianPlaybook,
  deleteGuardianPlaybook,
  type GuardianEventRecord,
  type GuardianPlaybookRecord,
  type GuardianPlaybookRunRecord,
  stagePendingRule,
} from '@main/services/telemetryStore';

const RISK_WEIGHT: Record<string, number> = {
  Low: 0,
  Medium: 1,
  High: 2,
  Critical: 3,
};

export interface GuardianPlaybookExecutionResult {
  playbookId: string;
  playbookName: string;
  matched: boolean;
  runId?: string;
  status?: 'completed' | 'failed';
  actionsExecuted?: number;
  log?: string[];
  error?: string;
}

export interface GuardianEventProcessingResult {
  event: GuardianEventRecord;
  executions: GuardianPlaybookExecutionResult[];
}

export interface ManualRunOptions {
  dryRun?: boolean;
}

interface ActionContext {
  event: GuardianEventRecord;
  playbook: GuardianPlaybook;
  dryRun: boolean;
  log: string[];
}

const scriptLookupCache = new Map<string, string>();

function getTagList(event: GuardianEventRecord): string[] {
  const tags = event.metadata?.tags;
  if (Array.isArray(tags)) {
    return tags.filter((tag): tag is string => typeof tag === 'string');
  }
  return [];
}

function compareRiskLevels(eventLevel: GuardianEventRecord['riskLevel'], required?: GuardianPlaybookCondition['minRiskLevel']): boolean {
  if (!required) return true;
  if (!eventLevel) return false;
  return (RISK_WEIGHT[eventLevel] ?? 0) >= (RISK_WEIGHT[required] ?? 0);
}

function matchCondition(event: GuardianEventRecord, condition: GuardianPlaybookCondition): boolean {
  if (condition.modules && !condition.modules.includes(event.module)) {
    return false;
  }
  if (!compareRiskLevels(event.riskLevel, condition.minRiskLevel)) {
    return false;
  }
  if (condition.processName) {
    if (!event.processName || event.processName.toLowerCase() !== condition.processName.toLowerCase()) {
      return false;
    }
  }
  if (condition.remoteIP && condition.remoteIP !== event.remoteIP) {
    return false;
  }
  if (condition.fingerprint && condition.fingerprint !== event.fingerprint) {
    return false;
  }
  if (condition.tags && condition.tags.length > 0) {
    const eventTags = getTagList(event);
    const hasAllTags = condition.tags.every((tag) => eventTags.includes(tag));
    if (!hasAllTags) {
      return false;
    }
  }
  return true;
}

function playbookMatchesEvent(playbook: GuardianPlaybook, event: GuardianEventRecord): boolean {
  if (!playbook.enabled) {
    return false;
  }
  if (!playbook.conditions?.length) {
    return true;
  }
  return playbook.conditions.some((condition) => matchCondition(event, condition));
}

function broadcastNotification(payload: { title: string; body?: string; playbookId: string; eventId: string }): void {
  BrowserWindow.getAllWindows().forEach((win) => {
    try {
      win.webContents.send('guardian-playbook-notification', payload);
    } catch (err) {
      console.warn('[GuardianPlaybookEngine] Failed to broadcast notification', err);
    }
  });
}

function ensureGuardianScriptDir(): string {
  const base = app?.getPath?.('userData') ?? path.join(process.cwd(), '.sentinel');
  const scriptsDir = path.join(base, 'guardian-scripts');
  if (!fs.existsSync(scriptsDir)) {
    fs.mkdirSync(scriptsDir, { recursive: true });
  }
  return scriptsDir;
}

function resolveScriptPath(scriptId: string): string {
  if (!scriptLookupCache.has(scriptId)) {
    const normalized = scriptId.endsWith('.ps1') ? scriptId : `${scriptId}.ps1`;
    const userDir = ensureGuardianScriptDir();
    const candidateUserPath = path.join(userDir, normalized);
    if (fs.existsSync(candidateUserPath)) {
      scriptLookupCache.set(scriptId, candidateUserPath);
    } else {
      const repoPath = path.join(process.cwd(), 'scripts', 'guardian', normalized);
      if (fs.existsSync(repoPath)) {
        scriptLookupCache.set(scriptId, repoPath);
      } else {
        scriptLookupCache.set(scriptId, candidateUserPath);
      }
    }
  }
  return scriptLookupCache.get(scriptId)!;
}

async function executePowerShellScript(scriptPath: string, args: string[] = []): Promise<string> {
  if (!fs.existsSync(scriptPath)) {
    throw new Error(`Script not found at ${scriptPath}`);
  }
  return new Promise<string>((resolve, reject) => {
    const child = spawn('powershell.exe', ['-ExecutionPolicy', 'Bypass', '-File', scriptPath, ...args], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', (err) => reject(err));
    child.on('close', (code) => {
      if (code === 0) {
        resolve(stdout.trim());
      } else {
        reject(new Error(stderr.trim() || `Script exited with code ${code}`));
      }
    });
  });
}

async function executeAction(action: GuardianPlaybookAction, ctx: ActionContext): Promise<void> {
  switch (action.type) {
    case 'log': {
      ctx.log.push(`[log] ${action.message}`);
      return;
    }
    case 'stage-firewall-rule': {
      const remoteIP = ctx.event.remoteIP ?? undefined;
      if (!remoteIP) {
        ctx.log.push('[stage-firewall-rule] Skipped (no remoteIP on event)');
        return;
      }
      const payload: ShieldStageFirewallRuleRequest = {
        sessionKey: `guardian-${ctx.playbook.id}`,
        pid: ctx.event.pid ?? 0,
        processName: ctx.event.processName ?? 'unknown-process',
        remoteIP,
        remotePort: typeof ctx.event.metadata?.remotePort === 'number' ? ctx.event.metadata.remotePort : undefined,
        reasons: [`Guardian playbook ${ctx.playbook.name} (${ctx.playbook.id})`],
        recommendsBlock: true,
        ttlSeconds: action.ttlSeconds,
      };
      if (ctx.dryRun) {
        ctx.log.push('[stage-firewall-rule] Dry run - would stage pending firewall rule');
        return;
      }
      await stagePendingRule(payload);
      ctx.log.push('[stage-firewall-rule] Pending firewall rule staged');
      return;
    }
    case 'dispatch-script': {
      const scriptPath = resolveScriptPath(action.scriptId);
      if (ctx.dryRun) {
        ctx.log.push(`[dispatch-script] Dry run - would execute ${scriptPath}`);
        return;
      }
      const output = await executePowerShellScript(scriptPath, action.args ?? []);
      ctx.log.push(`[dispatch-script] Executed ${scriptPath}${output ? ` -> ${output}` : ''}`);
      return;
    }
    case 'notify': {
      ctx.log.push(`[notify] ${action.channel.toUpperCase()}: ${action.title}`);
      if (!ctx.dryRun) {
        broadcastNotification({
          title: action.title,
          body: action.body,
          playbookId: ctx.playbook.id,
          eventId: ctx.event.id,
        });
      }
      return;
    }
    default:
      ctx.log.push(`[unknown-action] ${JSON.stringify(action)}`);
  }
}

async function executePlaybook(playbook: GuardianPlaybookRecord, event: GuardianEventRecord, dryRun: boolean): Promise<GuardianPlaybookExecutionResult> {
  const log: string[] = [`Playbook ${playbook.name} triggered for Guardian event ${event.id}`];
  const runId = randomUUID();
  let actionsExecuted = 0;
  try {
    for (const action of playbook.actions) {
      await executeAction(action, { event, playbook, dryRun, log });
      actionsExecuted += 1;
    }
    if (!dryRun) {
      await logGuardianPlaybookRun({
        id: runId,
        playbookId: playbook.id,
        triggeredAt: Date.now(),
        status: 'completed',
        actionsExecuted,
      });
    }
    return {
      playbookId: playbook.id,
      playbookName: playbook.name,
      matched: true,
      runId,
      status: 'completed',
      actionsExecuted,
      log,
    };
  } catch (err: any) {
    const message = err?.message ?? String(err);
    log.push(`[error] ${message}`);
    if (!dryRun) {
      await logGuardianPlaybookRun({
        id: runId,
        playbookId: playbook.id,
        triggeredAt: Date.now(),
        status: 'failed',
        actionsExecuted,
        error: message,
      });
    }
    return {
      playbookId: playbook.id,
      playbookName: playbook.name,
      matched: true,
      runId,
      status: 'failed',
      actionsExecuted,
      log,
      error: message,
    };
  }
}

export async function recordGuardianEvent(payload: Omit<GuardianEvent, 'id' | 'timestamp'> & { id?: string; timestamp?: number }, options: { dryRun?: boolean } = {}): Promise<GuardianEventProcessingResult> {
  const event = await appendGuardianEvent(payload);
  const playbooks = await listGuardianPlaybooks();
  const executions: GuardianPlaybookExecutionResult[] = [];
  const matched = playbooks.filter((playbook) => playbookMatchesEvent(playbook, event));
  for (const playbook of matched) {
    const result = await executePlaybook(playbook, event, Boolean(options.dryRun));
    executions.push(result);
  }
  return { event, executions };
}

export async function runGuardianPlaybook(id: string, context?: Partial<GuardianEvent>, options: ManualRunOptions = {}): Promise<GuardianPlaybookExecutionResult> {
  const playbook = await getGuardianPlaybookById(id);
  if (!playbook) {
    throw new Error(`Guardian playbook ${id} not found`);
  }
  const eventContext: GuardianEventRecord = {
    id: context?.id ?? randomUUID(),
    module: context?.module ?? 'manual',
    timestamp: context?.timestamp ?? Date.now(),
    pid: context?.pid ?? 0,
    processName: context?.processName ?? 'manual-trigger',
    remoteIP: context?.remoteIP,
    remoteSubnet: context?.remoteSubnet,
    fingerprint: context?.fingerprint,
    action: context?.action,
    riskScore: context?.riskScore,
    riskLevel: context?.riskLevel,
    metadata: context?.metadata,
  };
  return executePlaybook(playbook, eventContext, Boolean(options.dryRun));
}

export async function getRecentGuardianPlaybookRuns(limit = 50): Promise<GuardianPlaybookRunRecord[]> {
  return getGuardianPlaybookRuns(limit);
}

export async function listGuardianPlaybookCatalog(): Promise<GuardianPlaybookRecord[]> {
  return listGuardianPlaybooks();
}

export async function saveGuardianPlaybookDefinition(
  payload: Parameters<typeof saveGuardianPlaybook>[0],
): Promise<GuardianPlaybookRecord> {
  return saveGuardianPlaybook(payload);
}

export async function deleteGuardianPlaybookDefinition(id: string): Promise<void> {
  await deleteGuardianPlaybook(id);
}
