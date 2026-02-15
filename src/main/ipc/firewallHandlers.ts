/**
 * SENTINEL UNIFIED — Firewall Cluster IPC Handlers
 * All firewall-related IPC channels registered here.
 */

import { ipcMain, BrowserWindow } from 'electron';
import { exec } from 'child_process';
import { promisify } from 'util';
const execAsyncFw = promisify(exec);
async function runNetsh(cmd: string): Promise<string> {
  const { stdout } = await execAsyncFw(cmd, { encoding: 'utf8', windowsHide: true, timeout: 10000 });
  return (stdout || '').trim();
}
import { IPC } from '../../shared/constants';
import {
  BlockPortSchema,
  BlockSubnetSchema,
  BlockPidSchema,
  BlockIPSchema,
  UnblockIPSchema,
  StageFirewallRuleSchema,
  CommitPendingRuleSchema,
  DismissPendingRuleSchema,
  WhitelistThreatSchema,
  ManualBlockLogSchema,
} from '../../shared/schemas';
import { serializeError } from '../../shared/utils';
import {
  safeBlockPort,
  blockSubnet as firewallBlockSubnet,
  blockProcessByPid,
  undoFirewallAction,
  redoFirewallAction,
  getUndoRedoStatus,
} from '../services/firewallSafety';
import {
  getBlockedIPs,
  blockIP,
  unblockIP,
  deleteFirewallRule,
  getSentinelRules,
  clearSentinelRules,
  addSentinelRule,
  createFirewallRule,
  blockSubnet as shieldBlockSubnet,
} from '../services/shieldData';
import {
  stagePendingRule,
  listPendingRules,
  getPendingRuleById,
  setPendingRuleStatus,
  deletePendingRule,
} from '../services/telemetryStore';
import { logSecurityEvent, type SecurityEventRecord } from '../services/securityEventsStore';
import { addActivityLog } from '../services/activityLog';
import {
  addWhitelistEntry,
} from '../services/sentinelConfig';
import { isValidIPv4, calculateSubnet, getIPCountForMask } from '../../shared/utils';

let mainWindow: BrowserWindow | null = null;
let isAdmin = false;

export function setFirewallContext(opts: { mainWindow: BrowserWindow | null; isAdmin: boolean }): void {
  mainWindow = opts.mainWindow;
  isAdmin = opts.isAdmin;
}

function broadcastPendingRuleUpdate(event: string, rule: Record<string, unknown>): void {
  try {
    const wins = BrowserWindow.getAllWindows();
    for (const win of wins) {
      if (!win.isDestroyed()) {
        win.webContents.send(IPC.FIREWALL.PENDING_RULE_UPDATE, { event, pendingRule: rule });
      }
    }
  } catch {
    // ignore broadcast errors
  }
}

function sanitizePendingRule(record: Record<string, unknown>): Record<string, unknown> {
  const { ...rest } = record;
  return rest;
}

export function registerFirewallHandlers(): void {
  // ─── Get Firewall Rules ───
  ipcMain.handle(IPC.FIREWALL.GET_RULES, async () => {
    try {
      const { aggregateFirewallRules } = await import('./shieldHandlers');
      const aggregation = await aggregateFirewallRules();
      return { success: true, rules: aggregation.rules, meta: aggregation.meta };
    } catch (err) {
      return { success: false, error: serializeError(err), rules: [] };
    }
  });

  // ─── Get Firewall Inventory ───
  ipcMain.handle(IPC.FIREWALL.GET_INVENTORY, async () => {
    try {
      const { aggregateFirewallRules } = await import('./shieldHandlers');
      const aggregation = await aggregateFirewallRules();
      let blockedIps: unknown[] = [];
      let blockedIpsError: string | null = null;
      try {
        blockedIps = await getBlockedIPs();
      } catch (blockedErr) {
        blockedIpsError = blockedErr instanceof Error ? blockedErr.message : String(blockedErr);
      }
      return {
        success: true,
        rules: aggregation.rules,
        blockedIps,
        meta: { ...aggregation.meta, blockedIpCount: blockedIps.length, blockedIpsError },
      };
    } catch (err) {
      return { success: false, error: serializeError(err), rules: [], blockedIps: [] };
    }
  });

  // ─── Block Port ───
  ipcMain.handle(IPC.FIREWALL.BLOCK_PORT, async (_event, payload: unknown) => {
    try {
      const parsed = BlockPortSchema.parse(payload);
      const result = await safeBlockPort(parsed.port, parsed.direction, parsed.protocol, parsed.options);
      if (result.success) {
        addActivityLog('firewall', 'block-port', `Blocked port ${parsed.port}/${parsed.protocol}`, 'success');
      }
      return result;
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Block Subnet ───
  ipcMain.handle(IPC.FIREWALL.BLOCK_SUBNET, async (_event, payload: unknown) => {
    try {
      const parsed = BlockSubnetSchema.parse(payload);
      const targetMask = parsed.subnetMask ?? 32;
      const result = await firewallBlockSubnet(parsed.input, targetMask, parsed.direction);
      if (result.success) {
        addActivityLog('firewall', 'block-subnet', `Blocked subnet ${parsed.input}/${targetMask}`, 'success');
      }
      return result;
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Block PID ───
  ipcMain.handle(IPC.FIREWALL.BLOCK_PID, async (_event, payload: unknown) => {
    try {
      const parsed = BlockPidSchema.parse(payload);
      const result = await blockProcessByPid(parsed.pid, parsed.direction);
      if (result.success) {
        addActivityLog('firewall', 'block-pid', `Blocked PID ${parsed.pid} (${parsed.direction})`, 'success');
      }
      return result;
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Block IP ───
  ipcMain.handle(IPC.FIREWALL.BLOCK_IP, async (_event, ip: string, reason: string) => {
    try {
      const parsed = BlockIPSchema.parse({ ip, reason });
      return blockIP(parsed.ip, parsed.reason);
    } catch (err) {
      return { success: false, message: 'Invalid IP or reason', error: serializeError(err) };
    }
  });

  // ─── Unblock IP ───
  ipcMain.handle(IPC.FIREWALL.UNBLOCK_IP, async (_event, ip: string) => {
    try {
      const parsed = UnblockIPSchema.parse({ ip });
      return unblockIP(parsed.ip);
    } catch (err) {
      return { success: false, message: 'Invalid IP address', error: serializeError(err) };
    }
  });

  // ─── Get Blocked IPs ───
  ipcMain.handle(IPC.FIREWALL.GET_BLOCKED_IPS, async () => {
    try {
      const ips = await getBlockedIPs();
      return { success: true, data: ips };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Block IP Subnet (with mask) ───
  ipcMain.handle(IPC.FIREWALL.BLOCK_IP_SUBNET, async (_event, ip: string, subnetMask: number) => {
    if (!isAdmin) {
      return { success: false, message: 'Admin privileges required' };
    }
    try {
      if (!isValidIPv4(ip)) {
        return { success: false, message: 'Invalid IP address format' };
      }
      const mask = subnetMask as 8 | 16 | 20 | 22 | 24 | 26 | 30 | 32;
      const subnet = calculateSubnet(ip, mask);
      if (!subnet) {
        return { success: false, message: 'Failed to calculate subnet' };
      }
      const ipCount = getIPCountForMask(mask);
      const ruleName = `Sentinel Block Subnet ${subnet}`;

      // Inbound
      const cmdIn = `netsh advfirewall firewall add rule name="${ruleName} IN" dir=in action=block remoteip=${subnet} enable=yes`;
      await runNetsh(cmdIn);
      addSentinelRule(`${ruleName} IN`);

      // Outbound
      const cmdOut = `netsh advfirewall firewall add rule name="${ruleName} OUT" dir=out action=block remoteip=${subnet} enable=yes`;
      await runNetsh(cmdOut);
      addSentinelRule(`${ruleName} OUT`);

      addActivityLog('firewall', 'block-ip-subnet', `Blocked subnet: ${subnet} (${ipCount})`, 'success');
      return { success: true, message: `Successfully blocked subnet ${subnet} (${ipCount})`, subnet, ipCount };
    } catch (error) {
      const msg = `Failed to block subnet: ${error instanceof Error ? error.message : String(error)}`;
      addActivityLog('firewall', 'block-ip-subnet', msg, 'error');
      return { success: false, message: msg };
    }
  });

  // ─── Unblock Subnet ───
  ipcMain.handle(IPC.FIREWALL.UNBLOCK_SUBNET, async (_event, subnet: string) => {
    if (!isAdmin) {
      return { success: false, message: 'Admin privileges required' };
    }
    try {
      const ruleName = `Sentinel Block Subnet ${subnet}`;
      try { await deleteFirewallRule(`${ruleName} IN`); } catch { /* rule may not exist */ }
      try { await deleteFirewallRule(`${ruleName} OUT`); } catch { /* rule may not exist */ }
      addActivityLog('firewall', 'unblock-subnet', `Unblocked subnet: ${subnet}`, 'success');
      return { success: true, message: `Successfully unblocked subnet ${subnet}` };
    } catch (error) {
      const msg = `Failed to unblock subnet: ${error instanceof Error ? error.message : String(error)}`;
      addActivityLog('firewall', 'unblock-subnet', msg, 'error');
      return { success: false, message: msg };
    }
  });

  // ─── Delete Firewall Rule ───
  ipcMain.handle(IPC.FIREWALL.DELETE_RULE, async (_event, ruleName: string) => {
    try {
      await runNetsh(`netsh advfirewall firewall delete rule name="${ruleName}"`);
      addActivityLog('firewall', 'delete-rule', `Deleted firewall rule: ${ruleName}`, 'info');
      return { success: true, message: `Deleted rule: ${ruleName}` };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Undo / Redo ───
  ipcMain.handle(IPC.FIREWALL.UNDO, async () => {
    try {
      const result = await undoFirewallAction();
      if (result.success) addActivityLog('firewall', 'undo', 'Undid firewall action', 'success');
      return result;
    } catch (err) {
      return { success: false, error: serializeError(err), message: 'Nothing to undo' };
    }
  });

  ipcMain.handle(IPC.FIREWALL.REDO, async () => {
    try {
      const result = await redoFirewallAction();
      if (result.success) addActivityLog('firewall', 'redo', 'Redid firewall action', 'success');
      return result;
    } catch (err) {
      return { success: false, error: serializeError(err), message: 'Nothing to redo' };
    }
  });

  ipcMain.handle(IPC.FIREWALL.GET_UNDO_REDO_STATE, async () => {
    try {
      return getUndoRedoStatus();
    } catch {
      return { canUndo: false, canRedo: false, undoCount: 0, redoCount: 0 };
    }
  });

  // ─── Sentinel Rules ───
  ipcMain.handle(IPC.FIREWALL.GET_SENTINEL_RULES, async () => {
    try {
      return { success: true, rules: getSentinelRules() };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.FIREWALL.CLEAR_SENTINEL_RULES, async () => {
    try {
      clearSentinelRules();
      return { success: true, message: 'Cleared sentinel tracking' };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Self Test ───
  ipcMain.handle(IPC.FIREWALL.SELF_TEST, async () => {
    if (!isAdmin) return { success: false, message: 'Admin privileges required' };
    try {
      const testName = `SentinelTest-${Date.now()}`;
      const create = await createFirewallRule(testName, 'TCP', 54321, 'Block');
      await new Promise((r) => setTimeout(r, 400));
      const tracked = getSentinelRules().includes(testName);
      const del = await deleteFirewallRule(testName);
      return {
        success: create.success && tracked && del.success,
        details: { created: create, tracked, deleted: del },
      };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Pending Rules (Stage / Commit / Dismiss) ───
  ipcMain.handle(IPC.FIREWALL.STAGE_RULE, async (_event, payload: unknown) => {
    try {
      const request = StageFirewallRuleSchema.parse(payload);
      const record = await stagePendingRule(request);
      broadcastPendingRuleUpdate('staged', record as unknown as Record<string, unknown>);
      return { success: true, pendingRule: sanitizePendingRule(record as unknown as Record<string, unknown>) };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.FIREWALL.GET_PENDING_RULES, async () => {
    try {
      const rules = await listPendingRules();
      return { success: true, pendingRules: rules.map((r) => sanitizePendingRule(r as unknown as Record<string, unknown>)) };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.FIREWALL.COMMIT_PENDING_RULE, async (_event, payload: unknown) => {
    try {
      const { pendingRuleId } = CommitPendingRuleSchema.parse(payload);
      const record = await getPendingRuleById(pendingRuleId);
      if (!record) throw new Error('Pending rule not found');
      if (record.status !== 'pending') throw new Error('Pending rule already processed');
      // Apply the rule via netsh
      const ip = (record as unknown as Record<string, unknown>).remoteIP as string;
      if (ip) {
        await shieldBlockSubnet(ip, undefined, 'both');
      }
      await setPendingRuleStatus(pendingRuleId, 'committed');
      await deletePendingRule(pendingRuleId);
      broadcastPendingRuleUpdate('committed', { ...(record as unknown as Record<string, unknown>), status: 'committed' });
      return { success: true };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.FIREWALL.DISMISS_PENDING_RULE, async (_event, payload: unknown) => {
    try {
      const { pendingRuleId } = DismissPendingRuleSchema.parse(payload);
      const record = await getPendingRuleById(pendingRuleId);
      if (!record) throw new Error('Pending rule not found');
      await setPendingRuleStatus(pendingRuleId, 'dismissed');
      await deletePendingRule(pendingRuleId);
      broadcastPendingRuleUpdate('dismissed', { ...(record as unknown as Record<string, unknown>), status: 'dismissed' });
      return { success: true };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Whitelist Threat ───
  ipcMain.handle(IPC.FIREWALL.WHITELIST_THREAT, async (_event, payload: unknown) => {
    if (!isAdmin) return { success: false, error: 'Admin privileges required' };
    try {
      const parsed = WhitelistThreatSchema.parse(payload);
      const target = parsed.subnet?.trim() || parsed.ip?.trim();
      if (!target) return { success: false, error: 'No IP or subnet provided for whitelisting' };

      const config = addWhitelistEntry(target);
      const message = `Whitelisted ${target} (${parsed.processName || 'Unknown process'})`;
      addActivityLog('firewall', 'whitelist-threat', message, 'success');

      try {
        const auditEvent: SecurityEventRecord = {
          pid: parsed.pid ?? 0,
          processName: parsed.processName ?? 'Unknown',
          processCompany: undefined,
          processPath: undefined,
          localPort: 0,
          remoteSubnet: parsed.subnet ?? target,
          remoteIP: parsed.ip ?? target,
          riskScore: 0,
          riskLevel: 'Low',
          tlsStatus: 'pending',
          reason: parsed.reason ?? 'Manual whitelist from ThreatTimeline',
          actionTaken: 'Alerted',
        };
        logSecurityEvent(auditEvent);
      } catch {
        // non-fatal
      }

      return { success: true, data: { target, config } };
    } catch (error) {
      addActivityLog('firewall', 'whitelist-threat', `Failed: ${error instanceof Error ? error.message : String(error)}`, 'error');
      return { success: false, error: serializeError(error) };
    }
  });

  // ─── Quick Block Subnet ───
  ipcMain.handle(IPC.FIREWALL.QUICK_BLOCK_SUBNET, async (_event, subnet: string, reason?: string) => {
    try {
      await shieldBlockSubnet(subnet, reason || 'Quick block from Threat Timeline', 'both');
      const event: SecurityEventRecord = {
        pid: 0,
        processName: 'ThreatTimeline',
        localPort: 0,
        remoteSubnet: subnet,
        remoteIP: subnet.split('/')[0] || subnet,
        riskScore: 0,
        riskLevel: 'High',
        tlsStatus: 'unknown',
        reason: reason || 'Quick block from Threat Timeline',
        actionTaken: 'Blocked',
      };
      logSecurityEvent(event);
      return { success: true, message: `Blocked subnet ${subnet}` };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Log Manual Block ───
  ipcMain.handle(IPC.FIREWALL.LOG_MANUAL_BLOCK, async (_event, payload: unknown) => {
    try {
      const parsed = ManualBlockLogSchema.parse(payload);
      const event: SecurityEventRecord = {
        pid: parsed.pid ?? 0,
        processName: parsed.processName ?? 'Manual',
        localPort: parsed.port ?? 0,
        remoteSubnet: parsed.subnet ?? parsed.ip,
        remoteIP: parsed.ip,
        riskScore: 0,
        riskLevel: 'Low',
        tlsStatus: 'unknown',
        reason: parsed.reason ?? 'Manual block from FirewallRules UI',
        actionTaken: 'Blocked',
      };
      logSecurityEvent(event);
      return { success: true };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });
}
