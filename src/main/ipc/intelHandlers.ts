/**
 * SENTINEL UNIFIED — Intel Cluster IPC Handlers
 * Threat intelligence, Guardian, playbooks, ARGUS scanning.
 */

import { ipcMain } from 'electron';
import { IPC } from '../../shared/constants';
import {
  GetThreatEventsSchema,
  GetGuardianStoriesSchema,
  LogGuardianEventSchema,
  SavePlaybookSchema,
  DeletePlaybookSchema,
  RunPlaybookSchema,
  GetThreatIntelSchema,
  RefreshThreatIntelSchema,
  AnomalyConfigSchema,
  GetPolicySuggestionsSchema,
  AcceptPolicySchema,
  DismissPolicySchema,
} from '../../shared/schemas';
import { serializeError } from '../../shared/utils';
import { getThreatEventsPage, getPolicySuggestionsPage, updatePolicySuggestionStatus } from '../services/telemetryStore';
import { recordGuardianEvent, listGuardianPlaybookCatalog, saveGuardianPlaybookDefinition, deleteGuardianPlaybookDefinition, runGuardianPlaybook, getRecentGuardianPlaybookRuns } from '../services/guardianPlaybookEngine';
import { queryGuardianThreatIntel, refreshGuardianThreatIntel } from '../services/guardianIntelService';
import { loadGuardianAnomalyConfig, saveGuardianAnomalyConfig } from '../services/guardianAnomalyService';
import { getArgusManager } from '../services/argusManager';

export function registerIntelHandlers(): void {
  // ─── Threat Events ───
  ipcMain.handle(IPC.INTEL.GET_THREAT_EVENTS, async (_event, payload) => {
    try {
      const request = GetThreatEventsSchema.parse(payload ?? {});
      const page = await getThreatEventsPage(request);
      return { success: true, events: page.entries, nextCursor: page.nextCursor };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Guardian Stories ───
  ipcMain.handle(IPC.INTEL.GET_GUARDIAN_STORIES, async (_event, payload) => {
    try {
      const request = GetGuardianStoriesSchema.parse(payload ?? {});
      const page = await (await import('../services/telemetryStore')).getGuardianStoriesPage({
        cursor: request.cursor,
        limit: request.limit,
        filters: { pid: request.pid, processName: request.processName, remoteIP: request.remoteIP, module: request.module },
      });
      return { success: true, stories: page.entries, nextCursor: page.nextCursor };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Log Guardian Event ───
  ipcMain.handle(IPC.INTEL.LOG_GUARDIAN_EVENT, async (_event, payload) => {
    try {
      const request = LogGuardianEventSchema.parse(payload ?? {});
      const recorded = await recordGuardianEvent(request);
      return { success: true, event: recorded.event, executions: recorded.executions };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Playbooks ───
  ipcMain.handle(IPC.INTEL.LIST_PLAYBOOKS, async () => {
    try {
      return { success: true, playbooks: await listGuardianPlaybookCatalog() };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.INTEL.SAVE_PLAYBOOK, async (_event, payload) => {
    try {
      const request = SavePlaybookSchema.parse(payload ?? {});
      const playbook = await saveGuardianPlaybookDefinition(request);
      return { success: true, playbook };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.INTEL.DELETE_PLAYBOOK, async (_event, payload) => {
    try {
      const request = DeletePlaybookSchema.parse(payload ?? {});
      await deleteGuardianPlaybookDefinition(request.id);
      return { success: true };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.INTEL.RUN_PLAYBOOK, async (_event, payload) => {
    try {
      const request = RunPlaybookSchema.parse(payload ?? {});
      const result = await runGuardianPlaybook(request.id, request.context, { dryRun: request.dryRun });
      return {
        success: result.status !== 'failed',
        actionsExecuted: result.actionsExecuted ?? 0,
        log: result.log,
      };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.INTEL.GET_PLAYBOOK_RUNS, async (_event, payload) => {
    try {
      const limit = typeof payload?.limit === 'number' ? payload.limit : 50;
      return { success: true, runs: await getRecentGuardianPlaybookRuns(limit) };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Threat Intel ───
  ipcMain.handle(IPC.INTEL.GET_THREAT_INTEL, async (_event, payload) => {
    try {
      const request = GetThreatIntelSchema.parse(payload ?? {});
      const result = await queryGuardianThreatIntel({
        indicator: request.indicator,
        type: request.type,
        cursor: request.cursor,
        limit: request.limit,
      });
      return { success: true, records: result.records, nextCursor: result.nextCursor ?? null };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.INTEL.REFRESH_THREAT_INTEL, async (_event, payload) => {
    try {
      const request = RefreshThreatIntelSchema.parse(payload ?? {});
      const result = await refreshGuardianThreatIntel(request);
      return { success: true, refreshed: result.refreshed, records: result.records };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Anomaly Config ───
  ipcMain.handle(IPC.INTEL.GET_ANOMALY_CONFIG, async () => {
    try {
      const config = await loadGuardianAnomalyConfig();
      return { success: true, config };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.INTEL.UPDATE_ANOMALY_CONFIG, async (_event, payload) => {
    try {
      const request = AnomalyConfigSchema.parse(payload ?? {});
      const config = await saveGuardianAnomalyConfig(request);
      return { success: true, config };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Policy Suggestions ───
  ipcMain.handle(IPC.INTEL.GET_POLICY_SUGGESTIONS, async (_event, payload) => {
    try {
      const request = GetPolicySuggestionsSchema.parse(payload ?? {});
      const page = await getPolicySuggestionsPage(request);
      return { success: true, suggestions: page.entries, nextCursor: page.nextCursor };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.INTEL.ACCEPT_POLICY, async (_event, payload) => {
    try {
      const { policyId } = AcceptPolicySchema.parse(payload ?? {});
      const suggestion = await updatePolicySuggestionStatus(policyId, 'accepted');
      if (!suggestion) throw new Error('Policy suggestion not found');
      return { success: true, suggestion };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.INTEL.DISMISS_POLICY, async (_event, payload) => {
    try {
      const { policyId } = DismissPolicySchema.parse(payload ?? {});
      const suggestion = await updatePolicySuggestionStatus(policyId, 'dismissed');
      if (!suggestion) throw new Error('Policy suggestion not found');
      return { success: true, suggestion };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── ARGUS URL Scanning ───
  ipcMain.handle(IPC.INTEL.URL_SCAN, async (_event, urlOrOpts: string | { url: string; deepFetch?: boolean }) => {
    try {
      const url = typeof urlOrOpts === 'string' ? urlOrOpts : urlOrOpts?.url;
      const deepFetch = typeof urlOrOpts === 'object' ? !!urlOrOpts.deepFetch : false;
      if (!url || typeof url !== 'string') return { success: false, error: 'URL is required' };
      const result = await getArgusManager().scanUrl(url, false, deepFetch);
      return { success: true, data: result };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.INTEL.BATCH_SCAN, async (_event, payload: string[] | { urls: string[]; deepFetch?: boolean }) => {
    try {
      const urls = Array.isArray(payload) ? payload : payload?.urls;
      const deepFetch = !Array.isArray(payload) && payload ? !!payload.deepFetch : false;
      if (!Array.isArray(urls) || urls.length === 0) return { success: false, error: 'URLs array is required' };
      const result = await getArgusManager().batchScan(urls, deepFetch);
      return { success: true, data: result };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.INTEL.SCAN_HISTORY, async (_event, limit?: number, offset?: number) => {
    try {
      const result = await getArgusManager().getScanHistory(limit ?? 50, offset ?? 0);
      return { success: true, data: result };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.INTEL.EXPORT_HISTORY, async () => {
    try {
      const result = await getArgusManager().exportHistory();
      return { success: true, data: result };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.INTEL.CLEAR_HISTORY, async () => {
    try {
      const result = await getArgusManager().clearHistory();
      return { success: true, data: result };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });
}
