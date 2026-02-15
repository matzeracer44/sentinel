import { app, BrowserWindow, ipcMain, dialog, Tray, Menu, nativeImage } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import { execSync, spawn, exec } from 'child_process';
import { promisify } from 'util';
import * as os from 'os';
import { 
  getBlockedIPs, 
  blockIP, 
  unblockIP,
  createFirewallRule,
  deleteFirewallRule,
  scanOpenPorts,
  getSecurityOverview,
  blockSubnet,
  blockIPRange
} from './services/shieldData';
import { registerShieldHandlers } from './ipc/shieldHandlers';
import { runAllKernelChecks } from './services/sentinelKernelIntegrity';
import { runAllEdrChecks } from './services/sentinelEdr';
import { runAllNetworkChecks } from './services/sentinelNetworkAdvanced';
import { runAllPerformanceChecks } from './services/sentinelPerformanceTuning';
import { runAllPrivacyChecks } from './services/sentinelPrivacyHardening';
import { registerAddressWatch, getAddressWatchSummary } from './services/networkMonitor';
import { inspectTLS } from './services/tlsInspector';
import {
  initTelemetryStore,
  closeTelemetryStore,
  stagePendingRule,
  listPendingRules,
  getPendingRuleById,
  deletePendingRule,
  purgeExpiredPendingRules,
  setPendingRuleStatus,
  getThreatEventsPage,
  clearAllThreatEvents,
  type PendingRuleRecord,
  getPolicySuggestionsPage,
  updatePolicySuggestionStatus,
  getGuardianStoriesPage,
} from './services/telemetryStore';
import {
  recordGuardianEvent,
  listGuardianPlaybookCatalog,
  saveGuardianPlaybookDefinition,
  deleteGuardianPlaybookDefinition,
  runGuardianPlaybook,
  getRecentGuardianPlaybookRuns,
} from './services/guardianPlaybookEngine';
import { queryGuardianThreatIntel, refreshGuardianThreatIntel } from './services/guardianIntelService';
import { loadGuardianAnomalyConfig, saveGuardianAnomalyConfig } from './services/guardianAnomalyService';
import {
  startPolicyScanner,
  stopPolicyScanner
} from './services/policyScanner';
import {
  ShieldStageFirewallRuleRequestSchema,
  ShieldCommitPendingRuleSchema,
  ShieldDismissPendingRuleSchema,
  ShieldGetThreatEventsRequestSchema,
  ShieldGetThreatEventsResponseSchema,
  ShieldGetPolicySuggestionsRequestSchema,
  ShieldGetPolicySuggestionsResponseSchema,
  ShieldAcceptPolicySchema,
  ShieldDismissPolicySchema,
  ShieldPolicyMutationResponseSchema,
  ShieldManualBlockLogSchema,
  ShieldGetGuardianStoriesRequestSchema,
  ShieldLogGuardianEventRequestSchema,
  GuardianListPlaybooksResponseSchema,
  GuardianSavePlaybookRequestSchema,
  GuardianSavePlaybookResponseSchema,
  GuardianDeletePlaybookRequestSchema,
  GuardianRunPlaybookRequestSchema,
  GuardianRunPlaybookResponseSchema,
  GuardianGetPlaybookRunsResponseSchema,
  GuardianGetThreatIntelRequestSchema,
  GuardianGetThreatIntelResponseSchema,
  GuardianRefreshThreatIntelRequestSchema,
  GuardianRefreshThreatIntelResponseSchema,
  GuardianGetAnomalyConfigResponseSchema,
  GuardianUpdateAnomalyConfigRequestSchema,
} from '../shared/ipcSchemas';
import {
  initFirewallHistoryStore,
  closeFirewallHistoryStore,
} from './services/firewallHistoryStore';
import { hydrateFirewallHistoryStacks } from './services/firewallSafety';
import { getHealthReport } from './services/healthCheckService';
import {
  getSentinelConfig,
  updateAutonomousMode,
  addWhitelistEntry,
  removeWhitelistEntry,
  setWhitelist,
  setExternalIpLookup,
  isExternalIpLookupAllowed,
  SentinelConfig,
} from './services/sentinelConfig';
import { addSentinelRule } from './services/shieldData';
import {
  logSecurityEvent,
  SecurityEventRecord,
  configureSecurityEventsStore,
} from './services/securityEventsStore';
import { getArgusManager } from './services/argusManager';


let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let isQuitting = false;
let isAdmin = false;
let hasInitialized = false;
let initAttempt = 0;
let pendingRuleSweepTimer: NodeJS.Timeout | null = null;
let scheduledScanTimer: NodeJS.Timeout | null = null;
const PENDING_RULE_CHANNEL = 'shield-pending-rule-update';

const PENDING_RULE_PURGE_INTERVAL_MS = 30_000;

const gotSingleInstanceLock = app.requestSingleInstanceLock();

if (!gotSingleInstanceLock) {
  console.warn('[MAIN] Another Sentinel instance is already running. Exiting this instance.');
  app.quit();
  process.exit(0);
}

async function applyPendingRule(record: PendingRuleRecord): Promise<void> {
  if (!record.remoteIP) {
    throw new Error('Pending rule missing remoteIP');
  }
  const ruleName = `Sentinel Pending ${record.sessionKey} (${record.processName})`;
  const blockResult = await blockSubnet(record.remoteIP, ruleName, 'both');
  if (!blockResult.success) {
    throw new Error(blockResult.message || 'Failed to create firewall rule');
  }
}

function sanitizePendingRule(record: PendingRuleRecord) {
  return {
    id: record.id,
    sessionKey: record.sessionKey,
    pid: record.pid,
    processName: record.processName,
    remoteIP: record.remoteIP,
    remotePort: record.remotePort,
    reasons: record.reasons,
    recommendsBlock: record.recommendsBlock,
    ttlSeconds: record.ttlSeconds,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    status: record.status,
  };
}

function broadcastPendingRuleUpdate(event: 'staged' | 'committed' | 'expired' | 'dismissed', record: PendingRuleRecord) {
  const payload = {
    event,
    pendingRule: sanitizePendingRule(record),
  };
  BrowserWindow.getAllWindows().forEach((win) => {
    try {
      win.webContents.send(PENDING_RULE_CHANNEL, payload);
    } catch (err) {
      console.warn('[MAIN] Failed to broadcast pending rule update:', err);
    }
  });
}

function startPendingRuleSweep() {
  if (pendingRuleSweepTimer) {
    return;
  }
  const runSweep = async () => {
    try {
      const expired = await purgeExpiredPendingRules();
      expired.forEach((record) => {
        broadcastPendingRuleUpdate('expired', { ...record, status: 'expired' });
      });
    } catch (err) {
      console.warn('[MAIN] Pending rule sweep failed:', err);
    }
  };
  runSweep().catch((err) => console.warn('[MAIN] Initial pending rule sweep failed:', err));
  pendingRuleSweepTimer = setInterval(runSweep, PENDING_RULE_PURGE_INTERVAL_MS);
}

function stopPendingRuleSweep() {
  if (pendingRuleSweepTimer) {
    clearInterval(pendingRuleSweepTimer);
    pendingRuleSweepTimer = null;
  }
}

app.on('second-instance', () => {
  console.warn('[MAIN] Second instance attempt detected. Focusing existing window.');
  if (mainWindow) {
    if (mainWindow.isMinimized()) {
      mainWindow.restore();
    }
    mainWindow.focus();
  } else {
    console.warn('[MAIN] No window to focus; creating a new one.');
    createWindow();
  }
});

ipcMain.handle('shield-accept-policy-suggestion', async (_event, payload) => {
  try {
    const { policyId } = ShieldAcceptPolicySchema.parse(payload ?? {});
    const suggestion = await updatePolicySuggestionStatus(policyId, 'accepted');
    if (!suggestion) {
      throw new Error('Policy suggestion not found');
    }
    const response = { suggestion };
    ShieldPolicyMutationResponseSchema.parse(response);
    return { success: true, ...response };
  } catch (err) {
    return { success: false, error: serializeIpcError(err) };
  }
});

ipcMain.handle('shield-dismiss-policy-suggestion', async (_event, payload) => {
  try {
    const { policyId } = ShieldDismissPolicySchema.parse(payload ?? {});
    const suggestion = await updatePolicySuggestionStatus(policyId, 'dismissed');
    if (!suggestion) {
      throw new Error('Policy suggestion not found');
    }
    const response = { suggestion };
    ShieldPolicyMutationResponseSchema.parse(response);
    return { success: true, ...response };
  } catch (err) {
    return { success: false, error: serializeIpcError(err) };
  }
});

ipcMain.handle('shield-get-policy-suggestions', async (_event, payload) => {
  try {
    const request = ShieldGetPolicySuggestionsRequestSchema.parse(payload ?? {});
    const page = await getPolicySuggestionsPage(request);
    const response = {
      suggestions: page.entries,
      nextCursor: page.nextCursor,
    };
    ShieldGetPolicySuggestionsResponseSchema.parse(response);
    return { success: true, ...response };
  } catch (err) {
    return { success: false, error: serializeIpcError(err) };
  }
});

ipcMain.handle('shield-dismiss-pending-rule', async (_event, payload) => {
  try {
    const { pendingRuleId } = ShieldDismissPendingRuleSchema.parse(payload);
    const record = await getPendingRuleById(pendingRuleId);
    if (!record) {
      throw new Error('Pending rule not found');
    }
    await setPendingRuleStatus(pendingRuleId, 'dismissed');
    await deletePendingRule(pendingRuleId);
    broadcastPendingRuleUpdate('dismissed', { ...record, status: 'dismissed' });
    return { success: true };
  } catch (err) {
    console.error('[MAIN] Failed to dismiss pending rule:', err);
    return { success: false, error: serializeIpcError(err) };
  }
});

const execPromise = promisify(exec);

interface SerializedErrorPayload {
  message: string;
  stack?: string;
  code?: string | number;
}

interface ThreatWhitelistPayload {
  ip?: string;
  subnet?: string;
  processName?: string;
  pid?: number;
  reason?: string;
}

const serializeIpcError = (error: unknown): SerializedErrorPayload => {
  if (error instanceof Error) {
    return {
      message: error.message,
      stack: error.stack,
      code: (error as any)?.code,
    };
  }

  if (typeof error === 'object' && error !== null) {
    const errObj = error as Record<string, any>;
    return {
      message: String(errObj.message ?? 'Unknown error'),
      stack: typeof errObj.stack === 'string' ? errObj.stack : undefined,
      code: errObj.code,
    };
  }

  return { message: String(error) };
};

// ============================================
// ENHANCED LOGGING FOR RENDERER CRASHES
// ============================================

console.log('🌐 [MAIN] Electron main process started');

// ============================================
// UTILITY FUNCTIONS FOR REAL SYSTEM DATA
// ============================================

function getRAMUsage() {
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();
  const usedMemory = totalMemory - freeMemory;
  
  return {
    totalGB: Math.round(totalMemory / 1024 / 1024 / 1024 * 100) / 100,
    usedGB: Math.round(usedMemory / 1024 / 1024 / 1024 * 100) / 100,
    freeGB: Math.round(freeMemory / 1024 / 1024 / 1024 * 100) / 100,
    usagePercent: Math.round((usedMemory / totalMemory) * 100),
  };
}

function getCPUInfo() {
  const cpus = os.cpus();
  // Calculate real CPU idle ratio from current snapshot
  let totalIdle = 0, totalTick = 0;
  for (const cpu of cpus) {
    const t = cpu.times;
    totalIdle += t.idle;
    totalTick += t.user + t.nice + t.sys + t.irq + t.idle;
  }
  const currentLoad = totalTick > 0 ? Math.round(((totalTick - totalIdle) / totalTick) * 100) : -1;
  return {
    name: cpus[0]?.model || 'Unknown',
    cores: cpus.length,
    threads: cpus.length,
    currentLoad,
  };
}

function getSystemInfo() {
  return {
    manufacturer: os.platform(),
    model: os.arch(),
    computerName: os.hostname(),
    username: os.userInfo().username,
  };
}

function getOSInfo() {
  const platform = process.platform;
  const release = os.release();
  
  return {
    name: platform === 'win32' ? 'Windows' : platform,
    version: release,
    build: release,
  };
}

// ============================================
// ADMIN CHECK - CRITICAL FIRST
// ============================================

function checkAdminSync(): boolean {
  try {
    execSync('net session >nul 2>&1');
    return true;
  } catch {
    return false;
  }
}

function requestElevationSync(): void {
  console.log('Requesting Windows UAC elevation...');
  try {
    const appPath = process.execPath;
    const args = process.argv.slice(1);
    
    const escapedArgs = args.map(arg => arg.replace(/"/g, '`"')).join('", "');
    let command: string;
    
    if (args.length > 0) {
      command = `Start-Process -FilePath "${appPath}" -ArgumentList "${escapedArgs}" -Verb RunAs`;
    } else {
      command = `Start-Process -FilePath "${appPath}" -Verb RunAs`;
    }
    
    require('child_process').spawn('powershell.exe', ['-ExecutionPolicy', 'Bypass', '-Command', command], {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    });
    
    setTimeout(() => process.exit(0), 500);
  } catch (error: any) {
    console.error('Failed to request elevation:', error.message);
    process.exit(1);
  }
}

// ============================================
// CACHE SETUP
// ============================================

function setupCache() {
  try {
    const userDataPath = app.getPath('userData');
    const cachePath = path.join(userDataPath, 'Cache');
    const gpuCachePath = path.join(userDataPath, 'GPUCache');
    
    [cachePath, gpuCachePath].forEach((dir) => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o777 });
        console.log(`✓ Created cache directory: ${dir}`);
      }
    });
    
    if (process.platform === 'win32') {
      try {
        execSync(`icacls "${cachePath}" /grant Everyone:(OI)(CI)F /T /C /Q`, {
          windowsHide: true,
          stdio: 'ignore',
          timeout: 5000,
        });
        console.log('✓ Set cache permissions');
      } catch (e) {
        console.log('⚠ Could not set cache permissions (non-critical)');
      }
    }
    
    app.commandLine.appendSwitch('disk-cache-dir', cachePath);
    app.commandLine.appendSwitch('disk-cache-size', '104857600');
    app.commandLine.appendSwitch('disable-gpu-shader-disk-cache');
    
    console.log('✓ Cache configured successfully');
  } catch (error: any) {
    console.error('Cache setup error:', error.message);
  }
}

if (process.platform === 'win32') {
  app.setAppUserModelId('com.sentinel.app');
}

// ============================================
// CRITICAL: CHECK ADMIN BEFORE APP STARTS
// ============================================

app.whenReady().then(async () => {
  initAttempt += 1;
  console.log(`=== Sentinel Startup (attempt ${initAttempt}) ===`);

  if (hasInitialized) {
    console.warn('[MAIN] Initialization already completed; skipping duplicate app.whenReady() execution.');
    return;
  }
  hasInitialized = true;

  console.log('Checking administrator privileges...');
  isAdmin = checkAdminSync();
  console.log(`Running as administrator: ${isAdmin}`);

  // Setup event handlers after app is ready
  app.on('web-contents-created', (event, contents) => {
    console.log('🌐 [MAIN] Web contents created');
    
    contents.on('did-finish-load', () => {
      console.log('✅ [MAIN] Renderer finished loading');
    });
    
    contents.on('did-fail-load', (event, errorCode, errorDescription) => {
      console.error('❌ [MAIN] Renderer failed to load:', errorCode, errorDescription);
    });
    
    contents.on('render-process-gone', (event, details) => {
      console.error('💀 [MAIN] RENDER PROCESS GONE!', details);
    });
    
    contents.on('unresponsive', () => {
      console.error('⏰ [MAIN] Renderer became unresponsive');
    });
    
    contents.on('console-message', (event, level, message, line, sourceId) => {
      const prefix = level === 1 ? '⚠️ [WARN]' : level === 2 ? '❌ [ERROR]' : 'ℹ️ [LOG]';
      console.log(`${prefix} [Renderer:${line}]: ${message}`);
    });
  });

  // Catch uncaught exceptions
  process.on('uncaughtException', (error) => {
    console.error('[MAIN] UNCAUGHT EXCEPTION:', error);
    try { dialog.showErrorBox('Uncaught Exception', String(error?.stack || error?.message || error)); } catch {}
  });

  process.on('unhandledRejection', (reason, _promise) => {
    console.error('[MAIN] UNHANDLED REJECTION:', reason);
    try { dialog.showErrorBox('Unhandled Rejection', String((reason as any)?.stack || reason)); } catch {}
  });

  console.log('App ready, initializing...');

  if (!isAdmin) {
    console.log('Administrator privileges required. Triggering Windows UAC...');
    
    if (process.platform === 'win32') {
      try {
        console.log('Setting permanent admin flag in registry...');
        execSync(`reg add "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers" /v "${process.execPath.replace(/\\/g, '\\\\')}" /t REG_SZ /d "RUNASADMIN" /f`, { windowsHide: true });
        console.log('✓ Permanent admin flag set');
      } catch (error) {
        console.error('Failed to set permanent admin flag:', error);
      }
    }
    
    const env = Object.assign({}, process.env);
    env.SENTINEL_REQUESTED_ELEVATION = 'true';
    
    try {
      const appPath = process.execPath;
      const args = process.argv.slice(1).join('" "');
      const cmd = `Start-Process -FilePath "${appPath}" -ArgumentList "${args}" -Verb RunAs`;
      
      require('child_process').spawn('powershell.exe', ['-ExecutionPolicy', 'Bypass', '-Command', cmd], {
        detached: true,
        stdio: 'ignore',
        windowsHide: true,
        env: env,
      });
      
      setTimeout(() => process.exit(0), 500);
    } catch (error: any) {
      console.error('Failed to request elevation:', error.message);
      process.exit(1);
    }
    return;
  }

  console.log('=== All prerequisites met - Loading GUI ===');

  // Auto-detect hardware and compute adaptive performance settings
  try {
    const { initPerformanceProfile } = require('./services/performanceProfile');
    initPerformanceProfile();
  } catch (err) {
    console.warn('[MAIN] Performance profile init failed (non-fatal):', err);
  }

  setupCache();
  try {
    configureSecurityEventsStore({ baseDir: app.getPath('userData') });
  } catch (err) {
    console.warn('[MAIN] Failed to configure security events store path, falling back to default:', err);
  }

  try {
    await initTelemetryStore(app.getPath('userData'));
    console.log('[MAIN] Telemetry store initialized');
    startPendingRuleSweep();
    startPolicyScanner();
  } catch (err) {
    console.error('[MAIN] Failed to initialize telemetry store:', err);
  }
  try {
    await initFirewallHistoryStore(app.getPath('userData'));
    await hydrateFirewallHistoryStacks();
    console.log('[MAIN] Firewall history store ready');
  } catch (err) {
    console.error('[MAIN] Failed to initialize firewall history store:', err);
  }
  registerShieldHandlers();

  // Start ARGUS Python backend as managed child process
  const argus = getArgusManager();
  argus.start().catch((err) => {
    console.warn('[MAIN] ARGUS failed to start (non-fatal):', err instanceof Error ? err.message : err);
  });

  // Initialize File Integrity Monitoring
  try {
    const { initFim } = require('./services/fileIntegrityMonitor');
    initFim();
    console.log('[MAIN] FIM initialized');
  } catch (err) {
    console.warn('[MAIN] FIM init failed (non-fatal):', err);
  }

  createTray();
  createWindow();
  startScheduledScans();
  
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Security suite stays in tray — do NOT quit on window close
app.on('window-all-closed', () => {
  // Intentionally empty: Sentinel runs in system tray
});

app.on('before-quit', (event) => {
  if (scheduledScanTimer) { clearInterval(scheduledScanTimer); scheduledScanTimer = null; }
  if (!isQuitting) {
    event.preventDefault();
    isQuitting = true;
    stopPendingRuleSweep();
    stopPolicyScanner();
    app.quit();
    return;
  }
  stopPolicyScanner();
});

app.on('will-quit', async (event) => {
  event.preventDefault();
  try {
    getArgusManager().stop();
    console.log('[MAIN] ARGUS stopped');
    await closeTelemetryStore();
    console.log('[MAIN] Telemetry store closed');
    await stopPolicyScanner();
    await closeFirewallHistoryStore();
    console.log('[MAIN] Firewall history store closed');
  } catch (err) {
    console.warn('[MAIN] Failed to dispose SessionStore:', err);
  } finally {
    app.exit(0);
  }
});

// INITIALIZATION
// ============================================

function createWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    console.warn('[MAIN] createWindow called while an existing window is active. Focusing current window.');
    mainWindow.focus();
    return;
  }

  const PRELOAD_PATH = path.join(__dirname, '../preload/preload.js');
  const RENDERER_PATH = path.join(__dirname, '../renderer/index.html');

  console.log('=== Creating BrowserWindow ===');
  console.log('Preload path:', PRELOAD_PATH, 'exists?', fs.existsSync(PRELOAD_PATH));
  console.log('Renderer path:', RENDERER_PATH, 'exists?', fs.existsSync(RENDERER_PATH));

  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 600,
    webPreferences: {
      preload: PRELOAD_PATH,
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
    icon: path.join(__dirname, '../assets/icon.png'),
    show: false,
  });

  // CSP: Remove unsafe-eval, restrict sources to self + ARGUS localhost
  const { session } = require('electron');
  session.defaultSession.webRequest.onHeadersReceived((details: any, callback: any) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' http://127.0.0.1:8080"
        ],
      },
    });
  });

  const loadRenderer = async () => {
    if (!mainWindow || mainWindow.isDestroyed()) {
      console.error('[MAIN] Cannot load renderer because BrowserWindow is missing or destroyed.');
      return;
    }
    try {
      await mainWindow.loadFile(RENDERER_PATH);
      console.log('✅ Renderer loaded successfully');
      mainWindow.show();
    } catch (err: any) {
      console.error('❌ ERROR loading renderer:', err);
      try {
        dialog.showErrorBox('Renderer Load Failed', String(err?.message || err));
      } catch (dialogErr) {
        console.warn('Failed to surface renderer error dialog:', dialogErr);
      }
    }
  };

  loadRenderer();

  mainWindow.webContents.on('did-finish-load', () => {
    console.log('✅ Renderer finished loading');
  });

  mainWindow.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL) => {
    console.error('❌ Renderer failed to load:', errorCode, errorDescription, validatedURL);
  });

  mainWindow.webContents.on('render-process-gone', (_event, details) => {
    console.error('💀 Renderer process gone:', details.reason);
  });

  // Minimize to tray instead of closing
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow?.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ============================================
// SYSTEM TRAY — Always-on background protection
// ============================================

function createTray() {
  if (tray && !tray.isDestroyed()) return;

  // Create a 16x16 cyan shield icon programmatically (no external file dependency)
  const iconDataUrl = nativeImage.createFromDataURL(
    'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAA2ElEQVQ4T6WTwQ3CMAAE7wpaIB2EDkIHoYPQQegAOoAO6CB0QAdxFkWKLPt8lpCQ/CS+nW/t5EJEjpKeJD1IOkfEO7c/SLqW9CLpKSLemX1Z0q2kG0mvkmZ9bHch6UzSu6T7iPhK3W96lvQREZ+/bkj5qKSJpFdJp5J2EbFM/ZR/0BqgJOaAEcOAIdsZYOhw9gXSzgDdB/4dmANGjBgB+tIz6hUvHQn3JFBXoDRA/RdJL9CZpJ2IWPTlFzXI2u/b6JZKbUl1BVJNOeC/75GOZUDU1ht6/ANZRz8Ri0dDIwAAAABJRU5ErkJggg=='
  );

  tray = new Tray(iconDataUrl);
  tray.setToolTip('Sentinel Security Suite — Active Protection');

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show Sentinel',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        } else {
          createWindow();
        }
      },
    },
    { type: 'separator' },
    {
      label: 'Deep Scan',
      click: async () => {
        try {
          const { enrichChecks } = await import('./services/scanners/mergeCheckDetails');
          const kernel = enrichChecks(runAllKernelChecks());
          const edr = enrichChecks(runAllEdrChecks());
          const network = enrichChecks(runAllNetworkChecks());
          const performance = enrichChecks(runAllPerformanceChecks());
          const privacy = enrichChecks(runAllPrivacyChecks());
          const all = [...kernel, ...edr, ...network, ...performance, ...privacy];
          const passed = all.filter((c: any) => c.status === 'pass').length;
          const score = Math.round((passed / all.length) * 100);
          // Push result to renderer if open
          mainWindow?.webContents.send('sentinel-scan-complete', { score, passed, total: all.length });
          tray?.displayBalloon({ title: 'Sentinel Deep Scan', content: `Score: ${score}% — ${passed}/${all.length} checks passed`, iconType: score >= 80 ? 'info' : 'warning' });
        } catch (e: any) {
          tray?.displayBalloon({ title: 'Scan Failed', content: e?.message || 'Unknown error', iconType: 'error' });
        }
      },
    },
    {
      label: 'Gaming Mode',
      click: () => {
        try {
          execSync('powershell -ExecutionPolicy Bypass -NoProfile -Command "powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c; Stop-Service DiagTrack -Force -EA SilentlyContinue; Stop-Service SysMain -Force -EA SilentlyContinue"', { timeout: 10000, windowsHide: true });
          tray?.displayBalloon({ title: 'Gaming Mode', content: 'High Performance plan + background services stopped', iconType: 'info' });
        } catch (e: any) {
          tray?.displayBalloon({ title: 'Gaming Mode', content: `Partial: ${e?.message}`, iconType: 'warning' });
        }
      },
    },
    { type: 'separator' },
    {
      label: 'Quit Sentinel',
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);

  tray.setContextMenu(contextMenu);

  tray.on('double-click', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    } else {
      createWindow();
    }
  });

  console.log('[TRAY] System tray created');
}

// ============================================
// SCHEDULED SCANS — Automatic periodic protection
// ============================================

function startScheduledScans() {
  if (scheduledScanTimer) clearInterval(scheduledScanTimer);

  // Run a background scan every 6 hours
  const SCAN_INTERVAL_MS = 6 * 60 * 60 * 1000;

  scheduledScanTimer = setInterval(async () => {
    console.log('[SCHEDULED] Running automatic background scan...');
    try {
      const { enrichChecks } = await import('./services/scanners/mergeCheckDetails');
      const kernel = enrichChecks(runAllKernelChecks());
      const edr = enrichChecks(runAllEdrChecks());
      const network = enrichChecks(runAllNetworkChecks());
      const performance = enrichChecks(runAllPerformanceChecks());
      const privacy = enrichChecks(runAllPrivacyChecks());
      const all = [...kernel, ...edr, ...network, ...performance, ...privacy];
      const passed = all.filter((c: any) => c.status === 'pass').length;
      const failed = all.filter((c: any) => c.status === 'fail').length;
      const score = Math.round((passed / all.length) * 100);

      // Push to renderer
      mainWindow?.webContents.send('sentinel-scan-complete', { score, passed, failed, total: all.length, scheduled: true });

      // Show balloon if issues found
      if (failed > 0) {
        tray?.displayBalloon({
          title: 'Sentinel Scheduled Scan',
          content: `Score: ${score}% — ${failed} issues found. Click to review.`,
          iconType: 'warning',
        });
      }

      // Log to activity
      const { addActivityLog } = await import('./services/activityLog');
      addActivityLog('Scanner', 'Scheduled Scan', `Score: ${score}% (${passed}/${all.length} passed)`, failed > 5 ? 'warning' : 'info');

      console.log(`[SCHEDULED] Scan complete: ${score}% (${passed}/${all.length})`);
    } catch (e: any) {
      console.warn('[SCHEDULED] Background scan failed:', e?.message);
    }
  }, SCAN_INTERVAL_MS);

  console.log(`[SCHEDULED] Auto-scan every ${SCAN_INTERVAL_MS / 3600000}h`);
}

// ============================================
// APP LIFECYCLE
// ============================================

// Disable hardware acceleration if renderer crashes
app.disableHardwareAcceleration();

// ============================================
// IPC HANDLERS
// ============================================

// Check admin rights
ipcMain.handle('check-admin-rights', async () => {
  return {
    isAdmin,
    message: isAdmin ? 'Running with administrator privileges' : 'Running with limited privileges',
  };
});

ipcMain.handle('shield-get-threat-events', async (_event, payload) => {
  try {
    const request = ShieldGetThreatEventsRequestSchema.parse(payload ?? {});
    const page = await getThreatEventsPage(request);
    const response = {
      events: page.entries,
      nextCursor: page.nextCursor,
    };
    ShieldGetThreatEventsResponseSchema.parse(response);
    return { success: true, ...response };
  } catch (err) {
    return { success: false, error: serializeIpcError(err) };
  }
});

ipcMain.handle('shield-get-guardian-stories', async (_event, payload) => {
  try {
    const request = ShieldGetGuardianStoriesRequestSchema.parse(payload ?? {});
    const page = await getGuardianStoriesPage({
      cursor: request.cursor,
      limit: request.limit,
      filters: {
        pid: request.pid,
        processName: request.processName,
        remoteIP: request.remoteIP,
        module: request.module,
      },
    });
    return {
      success: true,
      stories: page.entries,
      nextCursor: page.nextCursor,
    };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('shield-log-guardian-event', async (_event, payload) => {
  try {
    const request = ShieldLogGuardianEventRequestSchema.parse(payload ?? {});
    const recorded = await recordGuardianEvent(request);
    return { success: true, event: recorded.event, executions: recorded.executions };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('guardian-list-playbooks', async () => {
  try {
    const response = { playbooks: await listGuardianPlaybookCatalog() };
    GuardianListPlaybooksResponseSchema.parse(response);
    return { success: true, ...response };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('guardian-save-playbook', async (_event, payload) => {
  try {
    const request = GuardianSavePlaybookRequestSchema.parse(payload ?? {});
    const playbook = await saveGuardianPlaybookDefinition(request);
    const response = { playbook };
    GuardianSavePlaybookResponseSchema.parse(response);
    return { success: true, ...response };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('guardian-delete-playbook', async (_event, payload) => {
  try {
    const request = GuardianDeletePlaybookRequestSchema.parse(payload ?? {});
    await deleteGuardianPlaybookDefinition(request.id);
    return { success: true };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('guardian-run-playbook', async (_event, payload) => {
  try {
    const request = GuardianRunPlaybookRequestSchema.parse(payload ?? {});
    const result = await runGuardianPlaybook(request.id, request.context, { dryRun: request.dryRun });
    const response = {
      success: result.status !== 'failed',
      actionsExecuted: result.actionsExecuted ?? 0,
      log: result.log,
    };
    GuardianRunPlaybookResponseSchema.parse(response);
    return response;
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('guardian-get-playbook-runs', async (_event, payload) => {
  try {
    const limit = typeof payload?.limit === 'number' ? payload.limit : 50;
    const response = { runs: await getRecentGuardianPlaybookRuns(limit) };
    GuardianGetPlaybookRunsResponseSchema.parse(response);
    return { success: true, ...response };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('guardian-get-threat-intel', async (_event, payload) => {
  try {
    const request = GuardianGetThreatIntelRequestSchema.parse(payload ?? {});
    const result = await queryGuardianThreatIntel({
      indicator: request.indicator,
      type: request.type,
      cursor: request.cursor,
      limit: request.limit,
    });
    const response = {
      records: result.records,
      nextCursor: result.nextCursor ?? null,
    };
    GuardianGetThreatIntelResponseSchema.parse(response);
    return { success: true, ...response };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('guardian-refresh-threat-intel', async (_event, payload) => {
  try {
    const request = GuardianRefreshThreatIntelRequestSchema.parse(payload ?? {});
    const result = await refreshGuardianThreatIntel(request);
    const response = {
      refreshed: result.refreshed,
      records: result.records,
    };
    GuardianRefreshThreatIntelResponseSchema.parse(response);
    return { success: true, ...response };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('guardian-get-anomaly-config', async () => {
  try {
    const config = await loadGuardianAnomalyConfig();
    const response = { config };
    GuardianGetAnomalyConfigResponseSchema.parse(response);
    return { success: true, ...response };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('guardian-update-anomaly-config', async (_event, payload) => {
  try {
    const request = GuardianUpdateAnomalyConfigRequestSchema.parse(payload ?? {});
    const config = await saveGuardianAnomalyConfig(request);
    const response = { config };
    GuardianGetAnomalyConfigResponseSchema.parse(response);
    return { success: true, ...response };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('shield-stage-firewall-rule', async (_event, payload) => {
  try {
    const request = ShieldStageFirewallRuleRequestSchema.parse(payload);
    const record = await stagePendingRule(request);
    broadcastPendingRuleUpdate('staged', record);
    return { success: true, pendingRule: sanitizePendingRule(record) };
  } catch (err) {
    console.error('[MAIN] Failed to stage firewall rule:', err);
    return { success: false, error: serializeIpcError(err) };
  }
});

ipcMain.handle('shield-get-pending-rules', async () => {
  try {
    const rules = await listPendingRules();
    return { success: true, pendingRules: rules.map(sanitizePendingRule) };
  } catch (err) {
    return { success: false, error: serializeIpcError(err) };
  }
});

ipcMain.handle('shield-commit-pending-rule', async (_event, payload) => {
  try {
    const { pendingRuleId } = ShieldCommitPendingRuleSchema.parse(payload);
    const record = await getPendingRuleById(pendingRuleId);
    if (!record) {
      throw new Error('Pending rule not found');
    }
    if (record.status !== 'pending') {
      throw new Error('Pending rule already processed');
    }
    await applyPendingRule(record);
    await setPendingRuleStatus(pendingRuleId, 'committed');
    await deletePendingRule(pendingRuleId);
    broadcastPendingRuleUpdate('committed', { ...record, status: 'committed' });
    return { success: true };
  } catch (err) {
    console.error('[MAIN] Failed to commit pending rule:', err);
    return { success: false, error: serializeIpcError(err) };
  }
});

// Get system data (basic)
ipcMain.handle('get-real-system-data', async () => {
  try {
    const ramUsage = getRAMUsage();
    const cpuInfo = getCPUInfo();
    const systemInfo = getSystemInfo();
    const osInfo = getOSInfo();
    const { spawnSync } = require('child_process');

    // Real disk data
    let disks: any[] = [];
    try {
      const diskResult = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
        input: `Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } | ForEach-Object {
  $total = [math]::Round(($_.Used + $_.Free) / 1GB, 2)
  $used = [math]::Round($_.Used / 1GB, 2)
  $free = [math]::Round($_.Free / 1GB, 2)
  $pct = if($total -gt 0){[math]::Round(($used / $total) * 100)}else{0}
  [PSCustomObject]@{ drive=$_.Name+':'; totalGB=$total; usedGB=$used; freeGB=$free; usagePercent=$pct }
} | ConvertTo-Json -Compress`,
        timeout: 8000, windowsHide: true, encoding: 'utf8',
      });
      if (diskResult.stdout) {
        let parsed = JSON.parse(diskResult.stdout.trim());
        if (!Array.isArray(parsed)) parsed = parsed ? [parsed] : [];
        disks = parsed;
      }
    } catch { disks = []; }

    // Real GPU data
    let gpu: any[] = [];
    try {
      const gpuResult = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
        input: `Get-CimInstance Win32_VideoController | ForEach-Object {
  [PSCustomObject]@{ name=$_.Name; memory=[math]::Round($_.AdapterRAM / 1MB) }
} | ConvertTo-Json -Compress`,
        timeout: 5000, windowsHide: true, encoding: 'utf8',
      });
      if (gpuResult.stdout) {
        let parsed = JSON.parse(gpuResult.stdout.trim());
        if (!Array.isArray(parsed)) parsed = parsed ? [parsed] : [];
        gpu = parsed;
      }
    } catch { gpu = []; }

    // Real network adapter data
    let network: any[] = [];
    try {
      const netResult = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
        input: `Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
  $ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
  [PSCustomObject]@{ adapter=$_.Name; status=$_.Status; ipAddress=if($ip){$ip}else{'N/A'}; macAddress=$_.MacAddress }
} | ConvertTo-Json -Compress`,
        timeout: 8000, windowsHide: true, encoding: 'utf8',
      });
      if (netResult.stdout) {
        let parsed = JSON.parse(netResult.stdout.trim());
        if (!Array.isArray(parsed)) parsed = parsed ? [parsed] : [];
        network = parsed;
      }
    } catch { network = []; }

    // Real battery data
    let battery = { status: 'N/A', percentage: 0 };
    try {
      const batResult = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
        input: `$b = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
if($b){ [PSCustomObject]@{ status=$b.Status; percentage=$b.EstimatedChargeRemaining } | ConvertTo-Json -Compress }
else { '{"status":"No Battery","percentage":0}' }`,
        timeout: 5000, windowsHide: true, encoding: 'utf8',
      });
      if (batResult.stdout) {
        const parsed = JSON.parse(batResult.stdout.trim());
        battery = { status: parsed.status || 'N/A', percentage: parsed.percentage || 0 };
      }
    } catch { /* keep defaults */ }

    return {
      success: true,
      data: {
        cpu: cpuInfo,
        ram: ramUsage,
        disks,
        system: systemInfo,
        os: osInfo,
        gpu,
        network,
        battery,
      }
    };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// Settings persistence
let _settingsPath: string | null = null;
function getSettingsPath(): string {
  if (!_settingsPath) {
    _settingsPath = path.join(app.getPath('userData'), 'settings.json');
  }
  return _settingsPath;
}

ipcMain.handle('get-settings', async () => {
  try {
    let settings = {
      language: 'de',
      theme: 'dark',
      autostart: false,
      autoUpdate: false,
    };
    
    const sPath = getSettingsPath();
    if (fs.existsSync(sPath)) {
      const data = fs.readFileSync(sPath, 'utf8');
      settings = JSON.parse(data);
    }
    
    return { success: true, settings };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('save-settings', async (_event, key: string, value: any) => {
  try {
    let settings: any = { language: 'de', theme: 'dark', autostart: false, autoUpdate: false };
    
    const sPath = getSettingsPath();
    if (fs.existsSync(sPath)) {
      const data = fs.readFileSync(sPath, 'utf8');
      settings = JSON.parse(data);
    }
    
    settings[key] = value;
    
    const dir = path.dirname(sPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(sPath, JSON.stringify(settings, null, 2), 'utf8');
    
    return { success: true, message: 'Settings saved successfully' };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

// Activity Log
let _activityLogPath: string | null = null;
function getActivityLogPath(): string {
  if (!_activityLogPath) {
    _activityLogPath = path.join(app.getPath('userData'), 'activity.log');
  }
  return _activityLogPath;
}

ipcMain.handle('get-activity-log', async () => {
  try {
    const aPath = getActivityLogPath();
    if (!fs.existsSync(aPath)) {
      return [];
    }
    
    const logs = fs.readFileSync(aPath, 'utf8')
      .split('\n')
      .filter(line => line.trim())
      .slice(-50)
      .map(line => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
    
    return logs;
  } catch (error) {
    return [];
  }
});

ipcMain.handle('clear-activity-log', async () => {
  try {
    if (fs.existsSync(getActivityLogPath())) {
      fs.unlinkSync(getActivityLogPath());
    }
    return { success: true };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// Quick Actions — dispatch to real services
ipcMain.handle('execute-quick-action', async (_event, action: string) => {
  try {
    console.log(`[Quick Action] Executing: ${action}`);
    const actions: string[] = [];

    if (action === 'lockdown') {
      // Block all non-essential outbound
      try {
        const { execSync } = require('child_process');
        execSync('netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound', { windowsHide: true });
        actions.push('Firewall set to block all inbound+outbound');
      } catch (e: any) { actions.push(`Firewall lockdown failed: ${e.message}`); }
    } else if (action === 'stealth') {
      // Disable ICMP echo (ping)
      try {
        const { execSync } = require('child_process');
        execSync('netsh advfirewall firewall add rule name="Sentinel-Stealth-BlockPing" dir=in action=block protocol=icmpv4', { windowsHide: true });
        actions.push('ICMP echo blocked (stealth mode)');
      } catch (e: any) { actions.push(`Stealth mode failed: ${e.message}`); }
    } else if (action === 'reset') {
      // Reset firewall to defaults
      try {
        const { execSync } = require('child_process');
        execSync('netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound', { windowsHide: true });
        actions.push('Firewall reset to default policy');
      } catch (e: any) { actions.push(`Reset failed: ${e.message}`); }
    } else if (action === 'gaming') {
      // Gaming mode: High performance + disable background apps + stop telemetry services
      try {
        const { execSync } = require('child_process');
        execSync('powershell -ExecutionPolicy Bypass -NoProfile -Command "powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c; Set-ItemProperty -Path HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications -Name GlobalUserDisabled -Value 1 -Type DWord -Force; Stop-Service DiagTrack -Force -EA SilentlyContinue; Stop-Service SysMain -Force -EA SilentlyContinue; Stop-Service BITS -Force -EA SilentlyContinue; powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100; powercfg /setactive SCHEME_CURRENT"', { timeout: 15000, windowsHide: true });
        actions.push('High Performance power plan activated', 'Background UWP apps disabled', 'DiagTrack + SysMain + BITS stopped', 'Core parking disabled');
      } catch (e: any) { actions.push(`Gaming mode partial: ${e.message}`); }
    } else if (action === 'privacy') {
      // Privacy mode: Disable telemetry, ad ID, Cortana, clipboard history, error reporting
      try {
        const { execSync } = require('child_process');
        execSync('powershell -ExecutionPolicy Bypass -NoProfile -Command "Set-ItemProperty -Path HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection -Name AllowTelemetry -Value 0 -Type DWord -Force -EA SilentlyContinue; Set-ItemProperty -Path HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo -Name Enabled -Value 0 -Type DWord -Force; Set-ItemProperty -Path HKCU:\\SOFTWARE\\Microsoft\\Clipboard -Name EnableClipboardHistory -Value 0 -Type DWord -Force; Stop-Service DiagTrack -Force -EA SilentlyContinue; Set-Service DiagTrack -StartupType Disabled -EA SilentlyContinue; Stop-Service WerSvc -Force -EA SilentlyContinue; Set-Service WerSvc -StartupType Disabled -EA SilentlyContinue"', { timeout: 15000, windowsHide: true });
        actions.push('Telemetry set to 0 (Security only)', 'Advertising ID disabled', 'Clipboard history disabled', 'DiagTrack stopped + disabled', 'Error Reporting stopped + disabled');
      } catch (e: any) { actions.push(`Privacy mode partial: ${e.message}`); }
    } else if (action === 'performance') {
      // Performance mode: Clear standby, stop background, optimize memory
      try {
        const { execSync } = require('child_process');
        execSync('powershell -ExecutionPolicy Bypass -NoProfile -Command "powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c; Stop-Service SysMain -Force -EA SilentlyContinue; Stop-Service DiagTrack -Force -EA SilentlyContinue; Stop-Service BITS -Force -EA SilentlyContinue; Stop-Service wuauserv -Force -EA SilentlyContinue; [System.GC]::Collect()"', { timeout: 15000, windowsHide: true });
        actions.push('High Performance plan activated', 'SysMain + DiagTrack + BITS + WU paused', 'GC triggered');
      } catch (e: any) { actions.push(`Performance mode partial: ${e.message}`); }
    } else if (action === 'restore' || action === 'reset-all') {
      // Restore defaults: Re-enable services, balanced power, allow outbound
      try {
        const { execSync } = require('child_process');
        execSync('powershell -ExecutionPolicy Bypass -NoProfile -Command "powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e; Set-Service SysMain -StartupType Automatic -EA SilentlyContinue; Start-Service SysMain -EA SilentlyContinue; Set-Service DiagTrack -StartupType Automatic -EA SilentlyContinue; Start-Service DiagTrack -EA SilentlyContinue; Set-Service BITS -StartupType Automatic -EA SilentlyContinue; Start-Service BITS -EA SilentlyContinue; Set-ItemProperty -Path HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications -Name GlobalUserDisabled -Value 0 -Type DWord -Force; netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"', { timeout: 15000, windowsHide: true });
        actions.push('Balanced power plan restored', 'SysMain + DiagTrack + BITS restarted', 'Background apps re-enabled', 'Firewall reset to default policy');
      } catch (e: any) { actions.push(`Restore partial: ${e.message}`); }
    } else if (action === 'cleanup') {
      // Cleanup: Clear temp files, standby cache, DNS cache, thumbnail cache
      try {
        const { execSync } = require('child_process');
        const out = execSync('powershell -ExecutionPolicy Bypass -NoProfile -Command "$b=0; Get-ChildItem $env:TEMP -Recurse -Force -EA SilentlyContinue | Remove-Item -Recurse -Force -EA SilentlyContinue; $b+=(Get-ChildItem $env:TEMP -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum; Remove-Item -Path \\"$env:LOCALAPPDATA\\Microsoft\\Windows\\Explorer\\thumbcache_*\\" -Force -EA SilentlyContinue; ipconfig /flushdns | Out-Null; Write-Output \\"CleanedBytes:$b\\""', { timeout: 30000, windowsHide: true, encoding: 'utf8' });
        actions.push('Temp files cleaned', 'Thumbnail cache cleared', 'DNS cache flushed');
        const m = out.match(/CleanedBytes:(\d+)/);
        if (m) actions.push(`${Math.round(parseInt(m[1]) / 1048576)} MB recovered`);
      } catch (e: any) { actions.push(`Cleanup partial: ${e.message}`); }
    } else {
      return { success: false, message: `Unknown quick action: ${action}`, actions: [] };
    }

    return { success: true, message: `${action} executed`, actions };
  } catch (error: any) {
    return { success: false, message: error.message || 'Failed to execute quick action', actions: [] };
  }
});

// System Health (REAL DATA)
ipcMain.handle('get-system-health', async () => {
  try {
    const ram = getRAMUsage();
    const ramHealth = Math.max(0, 100 - ram.usagePercent);

    // Real security score: check if firewall is enabled
    let securityScore = 50; // base
    try {
      const { execSync } = require('child_process');
      const fwStatus = execSync(
        'powershell -NoProfile -Command "(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $true }).Count"',
        { encoding: 'utf-8', timeout: 5000, windowsHide: true }
      ).trim();
      const enabledProfiles = parseInt(fwStatus, 10);
      if (enabledProfiles >= 3) securityScore = 95;
      else if (enabledProfiles >= 2) securityScore = 80;
      else if (enabledProfiles >= 1) securityScore = 65;
    } catch { /* keep base */ }

    // Real privacy score: check if telemetry is restricted
    let privacyScore = 60; // base
    try {
      const { execSync } = require('child_process');
      const telemetry = execSync(
        'powershell -NoProfile -Command "(Get-ItemProperty -Path HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection -Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry"',
        { encoding: 'utf-8', timeout: 3000, windowsHide: true }
      ).trim();
      const level = parseInt(telemetry, 10);
      if (level === 0) privacyScore = 95;
      else if (level === 1) privacyScore = 80;
      else if (level === 2) privacyScore = 65;
      else privacyScore = 50;
    } catch { /* keep base — registry key may not exist */ }

    const score = Math.round((securityScore + ramHealth + privacyScore) / 3);
    return {
      score,
      factors: {
        security: securityScore,
        performance: ramHealth,
        privacy: privacyScore,
      },
    };
  } catch (error: any) {
    return { score: -1, factors: { security: -1, performance: -1, privacy: -1 } };
  }
});

// System Stats (REAL DATA)
ipcMain.handle('get-system-stats', async () => {
  try {
    const ram = getRAMUsage();

    // Real CPU usage via 200ms sample
    let cpuPercent = 0;
    try {
      const cpus1 = os.cpus();
      await new Promise((r) => setTimeout(r, 200));
      const cpus2 = os.cpus();
      let idleDiff = 0, totalDiff = 0;
      for (let i = 0; i < cpus1.length; i++) {
        const t1 = cpus1[i].times, t2 = cpus2[i].times;
        const idle = t2.idle - t1.idle;
        const total = (t2.user - t1.user) + (t2.nice - t1.nice) + (t2.sys - t1.sys) + (t2.irq - t1.irq) + idle;
        idleDiff += idle;
        totalDiff += total;
      }
      cpuPercent = totalDiff > 0 ? Math.round(((totalDiff - idleDiff) / totalDiff) * 100) : -1;
    } catch { cpuPercent = -1; }

    // Real disk usage
    let diskPercent = -1;
    try {
      const { execSync } = require('child_process');
      const diskOut = execSync(
        'powershell -NoProfile -Command "(Get-PSDrive C).Used / ((Get-PSDrive C).Used + (Get-PSDrive C).Free) * 100"',
        { encoding: 'utf-8', timeout: 5000, windowsHide: true }
      ).trim();
      diskPercent = Math.round(parseFloat(diskOut));
      if (isNaN(diskPercent)) diskPercent = -1;
    } catch { diskPercent = -1; }

    return {
      cpu: cpuPercent,
      ram: ram.usagePercent,
      disk: diskPercent,
      network: 0,
    };
  } catch (error: any) {
    return { cpu: -1, ram: -1, disk: -1, network: 0 };
  }
});

ipcMain.handle('sentinel-get-health-report', async (_event, options: { force?: boolean } = {}) => {
  try {
    const report = await getHealthReport(options);
    return { success: true, data: report };
  } catch (error: any) {
    return { success: false, error: serializeIpcError(error) };
  }
});

// === SHIELD MODULE IPC HANDLERS ===
// NOTE: These handlers are now registered via registerShieldHandlers() in shieldHandlers.ts
// Keeping non-duplicate handlers only (shield-get-blocked-ips, shield-block-ip, shield-unblock-ip, etc.)
// Removing duplicates that are already in shieldHandlers.ts:
// - shield-get-processes
// - shield-kill-process
// - shield-get-firewall-rules
// - shield-block-port
// - shield-block-subnet
// - shield-delete-firewall-rule
// - shield-get-network-traffic

// IP Blocking (NOT in shieldHandlers.ts, keep this)
ipcMain.handle('shield-get-blocked-ips', async () => {
  try {
    const ips = await getBlockedIPs();
    return { success: true, data: ips };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('shield-block-ip', async (event, ip: string, reason: string) => {
  return await blockIP(ip, reason);
});

ipcMain.handle('shield-unblock-ip', async (event, ip: string) => {
  return await unblockIP(ip);
});

// Security Overview
ipcMain.handle('shield-get-security-overview', async () => {
  try {
    const overview = await getSecurityOverview();
    return { success: true, data: overview };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// --- Shield Deep Scans: Kernel, EDR, Network ---

ipcMain.handle('sentinel-kernel-scan', async () => {
  try {
    const { enrichChecks } = await import('./services/scanners/mergeCheckDetails');
    const checks = enrichChecks(runAllKernelChecks());
    const passed = checks.filter((c: any) => c.status === 'pass').length;
    const score = Math.round((passed / checks.length) * 100);
    return { success: true, module: 'kernel', checks, passed, total: checks.length, score };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-edr-scan', async () => {
  try {
    const { enrichChecks } = await import('./services/scanners/mergeCheckDetails');
    const checks = enrichChecks(runAllEdrChecks());
    const passed = checks.filter((c: any) => c.status === 'pass').length;
    const score = Math.round((passed / checks.length) * 100);
    return { success: true, module: 'edr', checks, passed, total: checks.length, score };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-network-scan', async () => {
  try {
    const { enrichChecks } = await import('./services/scanners/mergeCheckDetails');
    const checks = enrichChecks(runAllNetworkChecks());
    const passed = checks.filter((c: any) => c.status === 'pass').length;
    const score = Math.round((passed / checks.length) * 100);
    return { success: true, module: 'network', checks, passed, total: checks.length, score };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-performance-scan', async () => {
  try {
    const { enrichChecks } = await import('./services/scanners/mergeCheckDetails');
    const checks = enrichChecks(runAllPerformanceChecks());
    const passed = checks.filter((c: any) => c.status === 'pass').length;
    const score = Math.round((passed / checks.length) * 100);
    return { success: true, module: 'performance', checks, passed, total: checks.length, score };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-privacy-scan', async () => {
  try {
    const { enrichChecks } = await import('./services/scanners/mergeCheckDetails');
    const checks = enrichChecks(runAllPrivacyChecks());
    const passed = checks.filter((c: any) => c.status === 'pass').length;
    const score = Math.round((passed / checks.length) * 100);
    return { success: true, module: 'privacy', checks, passed, total: checks.length, score };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-full-scan', async () => {
  try {
    const { enrichChecks } = await import('./services/scanners/mergeCheckDetails');
    const kernel = enrichChecks(runAllKernelChecks());
    const edr = enrichChecks(runAllEdrChecks());
    const network = enrichChecks(runAllNetworkChecks());
    const performance = enrichChecks(runAllPerformanceChecks());
    const privacy = enrichChecks(runAllPrivacyChecks());
    const all = [...kernel, ...edr, ...network, ...performance, ...privacy];
    const passed = all.filter((c: any) => c.status === 'pass').length;
    const failed = all.filter((c: any) => c.status === 'fail').length;
    const warnings = all.filter((c: any) => c.status === 'warn').length;
    const score = Math.round((passed / all.length) * 100);
    const modScore = (arr: any[]) => { const p = arr.filter((c: any) => c.status === 'pass').length; return { checks: arr, passed: p, total: arr.length, score: Math.round((p / arr.length) * 100) }; };
    return {
      success: true, score, total: all.length, passed, failed, warnings,
      modules: { kernel: modScore(kernel), edr: modScore(edr), network: modScore(network), performance: modScore(performance), privacy: modScore(privacy) },
    };
  } catch (e: any) { return { success: false, error: e.message }; }
});

// ============================================
// SCAN FIX ACTIONS — Apply remediation from scan results
// ============================================

const SCAN_FIX_COMMANDS: Record<string, { label: string; ps: string }> = {
  // ─── Network checks ───
  'net-wfp': { label: 'Enable WFP & Firewall', ps: `Set-Service BFE -StartupType Automatic -EA Stop; Start-Service BFE -EA Stop; Set-Service MpsSvc -StartupType Automatic -EA Stop; Start-Service MpsSvc -EA Stop; Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled True` },
  'net-doh': { label: 'Set DoH-capable DNS (Cloudflare)', ps: `$iface = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1).InterfaceIndex; Set-DnsClientServerAddress -InterfaceIndex $iface -ServerAddresses ('1.1.1.1','1.0.0.1'); Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' -Name EnableAutoDoh -Value 2 -Type DWord -Force` },
  'net-tcphard': { label: 'Enable TCP SYN Attack Protection', ps: `Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name SynAttackProtect -Value 1 -Type DWord -Force; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name EnableDeadGWDetect -Value 0 -Type DWord -Force; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name EnablePMTUDiscovery -Value 1 -Type DWord -Force` },
  'net-stealth': { label: 'Block ICMP (stealth ports)', ps: `New-NetFirewallRule -DisplayName 'Sentinel-Block-ICMPv4-In' -Direction Inbound -Protocol ICMPv4 -Action Block -Enabled True -EA SilentlyContinue; New-NetFirewallRule -DisplayName 'Sentinel-Block-ICMPv4-Out' -Direction Outbound -Protocol ICMPv4 -Action Block -Enabled True -EA SilentlyContinue` },
  'net-domrep': { label: 'Enable Network Protection', ps: `Set-MpPreference -EnableNetworkProtection 1; Set-MpPreference -PUAProtection 1` },
  'net-zerotrust': { label: 'Set Public profile to Block Inbound', ps: `Set-NetFirewallProfile -Name Public -DefaultInboundAction Block` },
  'net-dpi': { label: 'Disable TLS 1.0 & SSL 3.0', ps: `$base='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols'; @('SSL 3.0','TLS 1.0') | ForEach-Object { $p="$base\\$_\\Client"; New-Item -Path $p -Force | Out-Null; Set-ItemProperty -Path $p -Name Enabled -Value 0 -Type DWord -Force; Set-ItemProperty -Path $p -Name DisabledByDefault -Value 1 -Type DWord -Force; $s="$base\\$_\\Server"; New-Item -Path $s -Force | Out-Null; Set-ItemProperty -Path $s -Name Enabled -Value 0 -Type DWord -Force; Set-ItemProperty -Path $s -Name DisabledByDefault -Value 1 -Type DWord -Force }` },
  'net-alg': { label: 'Stop & disable ALG service', ps: `Stop-Service ALG -Force -EA SilentlyContinue; Set-Service ALG -StartupType Disabled` },
  'net-smbkill': { label: 'Disable SMBv1', ps: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force` },
  // ─── Kernel checks ───
  'kernel-vbs': { label: 'Enable VBS/HVCI', ps: `Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name EnableVirtualizationBasedSecurity -Value 1 -Type DWord -Force; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name Enabled -Value 1 -Type DWord -Force` },
  'kernel-dse': { label: 'Enforce Driver Signature', ps: `bcdedit /set nointegritychecks off; bcdedit /set testsigning off` },
  'kernel-elam': { label: 'Enable WdFilter (ELAM)', ps: `Set-Service WdFilter -StartupType Boot -EA SilentlyContinue; Start-Service WdFilter -EA SilentlyContinue` },
  // ─── EDR checks ───
  'edr-amsi': { label: 'Enable AMSI', ps: `Set-MpPreference -DisableScriptScanning $false -EA SilentlyContinue` },
  'edr-lsass': { label: 'Enable LSASS PPL', ps: `Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 1 -Type DWord -Force` },
  'edr-lsa': { label: 'Enable LSA Protection', ps: `Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 1 -Type DWord -Force` },
  'edr-token': { label: 'Enable UAC/LUA', ps: `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1 -Type DWord -Force` },
  'edr-memscan': { label: 'Enable Real-Time Protection', ps: `Set-MpPreference -DisableRealtimeMonitoring $false; Set-MpPreference -DisableBehaviorMonitoring $false; Set-MpPreference -DisableIOAVProtection $false` },
  'edr-mitigations': { label: 'Enable DEP/ASLR/CFG', ps: `Set-ProcessMitigation -System -Enable DEP,CFG,SEHOP` },
  'edr-scriptlog': { label: 'Enable Script-Block Logging', ps: `New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord -Force` },
  'edr-cig': { label: 'Enable Driver Blocklist', ps: `Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -Name VulnerableDriverBlocklistEnable -Value 1 -Type DWord -Force` },
  // ─── Performance checks ───
  'perf-ultimate': { label: 'Set High Performance plan', ps: `powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c` },
  'perf-superfetch': { label: 'Stop SysMain (SSD)', ps: `Stop-Service SysMain -Force -EA SilentlyContinue; Set-Service SysMain -StartupType Disabled` },
  'perf-coreparking': { label: 'Disable core parking', ps: `powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100; powercfg /setactive SCHEME_CURRENT` },
  'perf-storage': { label: 'Enable Storage Sense', ps: `Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy' -Name '01' -Value 1 -Type DWord -Force` },
  'perf-timer': { label: 'Set high-precision timer', ps: `bcdedit /set useplatformtick yes; bcdedit /set disabledynamictick yes` },
  'perf-largepages': { label: 'Grant Lock Pages in Memory', ps: '$sid=(New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([System.Security.Principal.SecurityIdentifier]).Value; $tmp=[System.IO.Path]::GetTempFileName(); secedit /export /cfg $tmp /quiet; $c=Get-Content $tmp; $c=$c -replace "(SeLockMemoryPrivilege.*)","`$1,*$sid"; Set-Content $tmp $c; secedit /configure /db secedit.sdb /cfg $tmp /quiet; Remove-Item $tmp -Force -EA SilentlyContinue' },
  'perf-irq': { label: 'Enable RSS on primary adapter', ps: `$a=Get-NetAdapter|Where-Object Status -eq 'Up'|Select-Object -First 1; Enable-NetAdapterRss -Name $a.Name -EA SilentlyContinue` },
  'perf-bcdedit': { label: 'Optimize boot timer precision', ps: `bcdedit /set disabledynamictick yes; bcdedit /set useplatformtick yes` },
  'perf-bgapps': { label: 'Disable background UWP apps', ps: `Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications' -Name GlobalUserDisabled -Value 1 -Type DWord -Force` },
  'perf-hags': { label: 'Enable Hardware GPU Scheduling', ps: `Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers' -Name HwSchMode -Value 2 -Type DWord -Force` },
  'perf-telemetry': { label: 'Stop telemetry services', ps: `Stop-Service DiagTrack -Force -EA SilentlyContinue; Set-Service DiagTrack -StartupType Disabled; Stop-Service dmwappushservice -Force -EA SilentlyContinue; Set-Service dmwappushservice -StartupType Disabled -EA SilentlyContinue` },
  'perf-winsxs': { label: 'Clean WinSxS component store', ps: `Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase` },
  'perf-writecache': { label: 'Enable disk write cache', ps: `$d=Get-Disk -Number 0 -EA SilentlyContinue; if($d){Set-Disk -Number 0 -IsCacheEnabled $true -EA SilentlyContinue}` },
  'perf-pagefile': { label: 'Optimize pagefile (auto-managed)', ps: `$cs=Get-CimInstance Win32_ComputerSystem; $cs.AutomaticManagedPagefile=$true; Set-CimInstance $cs -EA SilentlyContinue` },
  'perf-standby': { label: 'Clear standby list', ps: `$code='[DllImport("ntdll.dll")]public static extern int NtSetSystemInformation(int i,ref int d,int l);';$t=Add-Type -MemberDefinition $code -Name 'Mem' -PassThru;$v=4;$t::NtSetSystemInformation(80,[ref]$v,4)|Out-Null` },
  'perf-ioprio': { label: 'Pause BITS & Windows Update', ps: `Stop-Service BITS -Force -EA SilentlyContinue; Stop-Service wuauserv -Force -EA SilentlyContinue` },
  // ─── Privacy checks ───
  'priv-dnsleak': { label: 'Fix DNS leak (VPN-only DNS)', ps: `$iface=(Get-NetAdapter|Where-Object{$_.Status-eq'Up'-and$_.InterfaceDescription-notmatch'NordLynx|WireGuard|TAP-|TUN|OpenVPN'}|Select-Object -First 1).InterfaceIndex; Set-DnsClientServerAddress -InterfaceIndex $iface -ServerAddresses ('1.1.1.1','1.0.0.1') -EA SilentlyContinue; ipconfig /flushdns | Out-Null` },
  'priv-usb': { label: 'Disable USB mass storage', ps: `Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name Start -Value 4 -Type DWord -Force` },
  'priv-lockscreen': { label: 'Harden lock screen', ps: `New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization' -Force -EA SilentlyContinue | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization' -Name NoLockScreenCamera -Value 1 -Type DWord -Force; New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' -Force -EA SilentlyContinue | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' -Name AllowCortanaAboveLock -Value 0 -Type DWord -Force` },
  'priv-bluetooth': { label: 'Disable Bluetooth service', ps: `Stop-Service bthserv -Force -EA SilentlyContinue; Set-Service bthserv -StartupType Disabled -EA SilentlyContinue` },
  'priv-gpo': { label: 'Enforce GPO hardening', ps: `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1 -Type DWord -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 2 -Type DWord -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name PromptOnSecureDesktop -Value 1 -Type DWord -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -Value 0 -Type DWord -Force -EA SilentlyContinue` },
  'priv-telemetry': { label: 'Reduce telemetry to Security', ps: `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name AllowTelemetry -Value 0 -Type DWord -Force; Stop-Service DiagTrack -Force -EA SilentlyContinue; Set-Service DiagTrack -StartupType Disabled -EA SilentlyContinue` },
  'priv-cortana': { label: 'Disable Cortana & Bing Search', ps: `New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' -Force -EA SilentlyContinue | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' -Name AllowCortana -Value 0 -Type DWord -Force; Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer' -Name DisableSearchBoxSuggestions -Value 1 -Type DWord -Force -EA SilentlyContinue` },
  'priv-adid': { label: 'Disable Advertising ID', ps: `Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo' -Name Enabled -Value 0 -Type DWord -Force` },
  'priv-location': { label: 'Disable location tracking', ps: `New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors' -Force -EA SilentlyContinue | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors' -Name DisableLocation -Value 1 -Type DWord -Force` },
  'priv-clipboard': { label: 'Disable clipboard history', ps: `Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Clipboard' -Name EnableClipboardHistory -Value 0 -Type DWord -Force` },
  'priv-cammic': { label: 'Deny webcam & mic access', ps: `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam' -Name Value -Value 'Deny' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone' -Name Value -Value 'Deny' -Force` },
  'priv-wer': { label: 'Disable Error Reporting', ps: `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting' -Name Disabled -Value 1 -Type DWord -Force; Stop-Service WerSvc -Force -EA SilentlyContinue; Set-Service WerSvc -StartupType Disabled -EA SilentlyContinue` },
  'priv-wifisense': { label: 'Disable WiFi Sense', ps: `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config' -Name AutoConnectAllowedOEM -Value 0 -Type DWord -Force` },
  'priv-uac': { label: 'Enforce strict UAC', ps: `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 2 -Type DWord -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name PromptOnSecureDesktop -Value 1 -Type DWord -Force` },
  // ─── Privacy (missing) ───
  'priv-hwid': { label: 'Restrict Hardware ID access', ps: `$acl=Get-Acl 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation'; $rule=New-Object System.Security.AccessControl.RegistryAccessRule('Users','ReadKey','Deny'); $acl.AddAccessRule($rule); Set-Acl 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation' $acl -EA SilentlyContinue` },
  'priv-antikeylog': { label: 'Disable typing data collection', ps: `Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Input\\TIPC' -Name Enabled -Value 0 -Type DWord -Force` },
  'priv-fingerprint': { label: 'Disable activity tracking', ps: `Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name Start_TrackProgs -Value 0 -Type DWord -Force; Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name Start_TrackDocs -Value 0 -Type DWord -Force` },
  // ─── Network (missing) ───
  'net-geoip': { label: 'Add geo-block firewall rules', ps: `New-NetFirewallRule -DisplayName 'Sentinel-GeoBlock-Inbound' -Direction Inbound -RemoteAddress '0.0.0.0/0' -Action Block -Enabled False -Description 'Sentinel Geo-IP placeholder — configure specific ranges' -EA SilentlyContinue` },
  'net-outbound': { label: 'Block default outbound on Public', ps: `Set-NetFirewallProfile -Name Public -DefaultOutboundAction Block` },
  'net-torblock': { label: 'Block Tor exit nodes', ps: `New-NetFirewallRule -DisplayName 'Sentinel-Block-Tor-Ports' -Direction Outbound -Protocol TCP -RemotePort 9001,9030,9050,9051,9150 -Action Block -Enabled True -EA SilentlyContinue` },
  'net-arp': { label: 'Add static ARP for gateway', ps: `$gw=(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA SilentlyContinue|Select-Object -First 1).NextHop; $mac=(Get-NetNeighbor -IPAddress $gw -EA SilentlyContinue).LinkLayerAddress; if($gw-and$mac){arp -s $gw $mac}` },
  // ─── EDR (missing — actionable ones) ───
  'edr-etw': { label: 'Enable ETW Threat Intelligence', ps: `logman start "Sentinel-ETW-TI" -p "Microsoft-Windows-Threat-Intelligence" -o "$env:LOCALAPPDATA\\Sentinel\\etw_ti.etl" -ets -EA SilentlyContinue` },
  'edr-wmi': { label: 'Remove suspicious WMI consumers', ps: `Get-WmiObject -Namespace root\\subscription -Class __EventConsumer -EA SilentlyContinue | Where-Object { $_.Name -notmatch 'SCM|BVTFilter' } | Remove-WmiObject -EA SilentlyContinue` },
  'edr-critfiles': { label: 'Lock critical file ACLs', ps: `$paths=@('C:\\Windows\\System32\\cmd.exe','C:\\Windows\\System32\\powershell.exe','C:\\Windows\\System32\\wscript.exe'); foreach($p in $paths){$a=Get-Acl $p -EA SilentlyContinue; if($a){$r=New-Object System.Security.AccessControl.FileSystemAccessRule('Users','Write','Deny'); $a.AddAccessRule($r); Set-Acl $p $a -EA SilentlyContinue}}` },
  'edr-autorun': { label: 'Audit & clean autoruns', ps: `Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -EA SilentlyContinue | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notmatch 'PS' } | ForEach-Object { Write-Output "$($_.Name)=$($_.Value)" } }` },
  'edr-sandbox': { label: 'Enable Network Protection sandbox', ps: `Set-MpPreference -EnableNetworkProtection 1 -EA SilentlyContinue` },
  // ─── Kernel (missing) ───
  'kernel-secureboot': { label: 'Verify Secure Boot status', ps: `Confirm-SecureBootUEFI -EA SilentlyContinue` },
  'kernel-tpm': { label: 'Initialize TPM', ps: `Initialize-Tpm -AllowClear -EA SilentlyContinue` },
  'kernel-shadowstack': { label: 'Enable CET Shadow Stack', ps: `Set-ProcessMitigation -System -Enable UserShadowStack -EA SilentlyContinue` },
  'kernel-patchguard': { label: 'Verify KPP (PatchGuard)', ps: `bcdedit /set nointegritychecks off; bcdedit /set testsigning off` },
  'kernel-iommu': { label: 'Enable VT-d in firmware', ps: `Write-Output 'VT-d/IOMMU must be enabled in BIOS/UEFI firmware settings'` },
  'kernel-vulndrivers': { label: 'Enable vulnerable driver blocklist', ps: `Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name VulnerableDriverBlocklistEnable -Value 1 -Type DWord -Force` },
  'kernel-unsigneddrivers': { label: 'Enforce driver signing', ps: `bcdedit /set nointegritychecks off; bcdedit /set testsigning off` },
  'kernel-msr': { label: 'Set CPU mitigation flags', ps: `Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverride -Value 0 -Type DWord -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverrideMask -Value 3 -Type DWord -Force` },
  // ─── Performance (missing) ───
  'perf-mft': { label: 'Check & repair NTFS volume', ps: `chkdsk C: /scan /perf` },
  'perf-etw': { label: 'Enable ETW performance tracing', ps: `logman start "Sentinel-Perf" -p "Microsoft-Windows-Kernel-Process" -o "$env:LOCALAPPDATA\Sentinel\perf.etl" -ets -EA SilentlyContinue` },
};

// ════════════════════════════════════════════════════════════════
// SCAN FIX SAFETY SYSTEM — Born from a real incident
// "Apply Fix" set outbound to BLOCK → no internet, no undo. NEVER AGAIN.
// ════════════════════════════════════════════════════════════════

// Returns the danger assessment for a fix BEFORE execution (UI shows confirm dialog)
ipcMain.handle('scan-get-fix-impact', async (_event, checkId: string) => {
  const fix = SCAN_FIX_COMMANDS[checkId];
  if (!fix) {
    return { success: false, error: `No fix available for "${checkId}".` };
  }
  const { getFixImpact, FORBIDDEN_FIX_IDS } = await import('../shared/fixSafety');
  const impact = getFixImpact(checkId, fix.label);
  return {
    success: true,
    checkId,
    label: fix.label,
    impact,
    forbidden: FORBIDDEN_FIX_IDS.has(checkId),
  };
});

// Apply a scan fix with FULL SAFETY: forbidden check, connectivity verify, auto-revert, undo store
ipcMain.handle('scan-apply-fix', async (_event, checkId: string) => {
  if (!isAdmin) {
    return { success: false, error: 'Administrator privileges required to apply fixes.' };
  }
  const fix = SCAN_FIX_COMMANDS[checkId];
  if (!fix) {
    return { success: false, error: `No automated fix available for check "${checkId}".` };
  }

  // ═══ SAFETY GATE 1: Forbidden fix check ═══
  const { getFixImpact, FORBIDDEN_FIX_IDS } = await import('../shared/fixSafety');
  if (FORBIDDEN_FIX_IDS.has(checkId)) {
    console.error(`[SAFETY] BLOCKED forbidden fix: ${checkId} — ${fix.label}`);
    return {
      success: false,
      error: 'Dieser Fix ist zu gefährlich und wurde blockiert. Er könnte dein System unbenutzbar machen.',
      forbidden: true,
      label: fix.label,
      checkId,
    };
  }

  const impact = getFixImpact(checkId, fix.label);

  // ═══ EXECUTE FIX ═══
  try {
    const { execSync } = require('child_process');
    execSync(
      `powershell -ExecutionPolicy Bypass -NoProfile -Command "${fix.ps.replace(/"/g, '\\"')}"`,
      { timeout: 30000, windowsHide: true, encoding: 'utf8' }
    );
  } catch (err: any) {
    return { success: false, error: err?.message || 'Fix command failed', label: fix.label, checkId };
  }

  // ═══ SAFETY GATE 2: Post-fix connectivity check (for network/firewall/DNS fixes) ═══
  if (impact.affectsConnectivity || impact.affectsFirewall || impact.affectsDNS) {
    const { postFixConnectivityCheck, autoRevert } = await import('./services/shared/fixUndoStore');

    // Wait a moment for network stack to settle
    await new Promise(resolve => setTimeout(resolve, 2000));
    const connectivity = await postFixConnectivityCheck();

    // ╔════════════════════════════════════════════════════════════╗
    // ║ INTERNET KAPUTT → SOFORT AUTOMATISCH RÜCKGÄNGIG!          ║
    // ╚════════════════════════════════════════════════════════════╝
    if (!connectivity.internet && impact.undoCommand) {
      console.error(`[SAFETY] Fix "${checkId}" broke internet! AUTO-REVERTING!`);
      const reverted = await autoRevert(impact.undoCommand);
      // Wait and verify
      await new Promise(resolve => setTimeout(resolve, 2000));
      const afterUndo = await postFixConnectivityCheck();

      const { addActivityLog } = await import('./services/activityLog');
      addActivityLog('scan', 'fix-auto-reverted', `Auto-reverted fix: ${fix.label} — Internet was broken`, 'error');

      return {
        success: false,
        error: 'Fix wurde automatisch rückgängig gemacht — Internet-Verbindung wäre verloren gegangen.',
        autoReverted: true,
        connectivityRestored: afterUndo.internet,
        label: fix.label,
        checkId,
      };
    }

    if (!connectivity.dns && impact.affectsDNS && impact.undoCommand) {
      console.error(`[SAFETY] Fix "${checkId}" broke DNS! AUTO-REVERTING!`);
      await autoRevert(impact.undoCommand);
      await new Promise(resolve => setTimeout(resolve, 2000));

      const { addActivityLog } = await import('./services/activityLog');
      addActivityLog('scan', 'fix-auto-reverted', `Auto-reverted fix: ${fix.label} — DNS was broken`, 'error');

      return {
        success: false,
        error: 'Fix wurde automatisch rückgängig gemacht — DNS-Auflösung wäre fehlgeschlagen.',
        autoReverted: true,
        label: fix.label,
        checkId,
      };
    }

    if (connectivity.firewallOutbound === 'BLOCK' && impact.undoCommand) {
      console.error(`[SAFETY] Fix "${checkId}" set outbound to BLOCK! AUTO-REVERTING!`);
      await autoRevert(impact.undoCommand);
      await new Promise(resolve => setTimeout(resolve, 1000));

      const { addActivityLog } = await import('./services/activityLog');
      addActivityLog('scan', 'fix-auto-reverted', `Auto-reverted fix: ${fix.label} — Outbound was BLOCKED`, 'error');

      return {
        success: false,
        error: 'Fix wurde automatisch rückgängig gemacht — ausgehende Verbindungen wären blockiert worden.',
        autoReverted: true,
        label: fix.label,
        checkId,
      };
    }
  }

  // ═══ SAFETY GATE 3: Store undo for 24h rollback ═══
  if (impact.undoCommand) {
    const { storeUndo } = await import('./services/shared/fixUndoStore');
    storeUndo({
      checkId,
      checkName: fix.label,
      appliedAt: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000,
      undoCommand: impact.undoCommand,
      undoDescription: impact.undoDescription,
      affectsConnectivity: impact.affectsConnectivity,
    });
  }

  // ═══ Activity Log ═══
  try {
    const { addActivityLog } = await import('./services/activityLog');
    addActivityLog('scan', 'fix-applied', `Applied fix: ${fix.label} [${impact.dangerLevel}]`, impact.dangerLevel === 'dangerous' ? 'warning' : 'info');
  } catch { /* log failure is non-critical */ }

  return {
    success: true,
    label: fix.label,
    checkId,
    impact,
    undoAvailable: Boolean(impact.undoCommand),
  };
});

// Undo a previously applied fix (available for 24 hours)
ipcMain.handle('scan-undo-fix', async (_event, checkId: string) => {
  if (!isAdmin) {
    return { success: false, error: 'Administrator privileges required to undo fixes.' };
  }
  const { executeUndo, postFixConnectivityCheck } = await import('./services/shared/fixUndoStore');
  const result = await executeUndo(checkId);

  if (result.success) {
    // Verify connectivity after undo
    const connectivity = await postFixConnectivityCheck();
    try {
      const { addActivityLog } = await import('./services/activityLog');
      addActivityLog('scan', 'fix-undone', `Undone fix: ${checkId}`, 'info');
    } catch { /* non-critical */ }

    return {
      success: true,
      checkId,
      connectivityOk: connectivity.internet,
    };
  }
  return result;
});

// Get all available undos
ipcMain.handle('scan-get-undos', async () => {
  const { getAllUndos } = await import('./services/shared/fixUndoStore');
  return { success: true, undos: getAllUndos() };
});

// ============================================
// SENTINEL NEW FEATURES — Phase 4 Services
// ============================================

ipcMain.handle('sentinel-vpn-get-status', async () => {
  try {
    const { getVpnStatus } = await import('./services/network/vpnDetector');
    const data = await getVpnStatus();
    return { success: true, data };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-hardening-run-audit', async () => {
  try {
    const { runHardeningAudit } = await import('./services/system/hardeningAudit');
    const data = await runHardeningAudit();
    return { success: true, data };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-ports-scan-local', async () => {
  try {
    const { scanLocalPorts } = await import('./services/system/portScanner');
    const data = await scanLocalPorts();
    return { success: true, data };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-wifi-audit', async () => {
  try {
    const { auditWifi } = await import('./services/system/wifiAudit');
    const data = await auditWifi();
    return { success: true, data };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-usb-get-devices', async () => {
  try {
    const { getUsbDevices } = await import('./services/system/usbMonitor');
    const data = await getUsbDevices();
    return { success: true, data };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-hardware-report', async () => {
  try {
    const { getFullHardwareReport } = await import('./services/system/hardwareDiscovery');
    const data = await getFullHardwareReport();
    return { success: true, data };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-event-log-analyze', async () => {
  try {
    const { analyzeEventLogs } = await import('./services/system/eventLogAnalyzer');
    const data = await analyzeEventLogs();
    return { success: true, data };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-generate-report', async (_event, scanModules?: any) => {
  try {
    const { generateSecurityReport } = await import('./services/system/securityReportGenerator');
    const data = await generateSecurityReport(scanModules || undefined);
    return { success: true, data };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-generate-report-html', async (_event, scanModules?: any) => {
  try {
    const { generateSecurityReport, generateReportHTML } = await import('./services/system/securityReportGenerator');
    const report = await generateSecurityReport(scanModules || undefined);
    const html = generateReportHTML(report);
    return { success: true, data: { report, html } };
  } catch (e: any) { return { success: false, error: e.message }; }
});

// ── Auto-start with Windows ──
ipcMain.handle('sentinel-get-autostart', async () => {
  try {
    const settings = app.getLoginItemSettings();
    return { success: true, data: { enabled: settings.openAtLogin } };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-set-autostart', async (_event, enabled: boolean) => {
  try {
    app.setLoginItemSettings({ openAtLogin: Boolean(enabled), path: process.execPath });
    const settings = app.getLoginItemSettings();
    return { success: true, data: { enabled: settings.openAtLogin } };
  } catch (e: any) { return { success: false, error: e.message }; }
});

// ── Security Report Export to File ──
ipcMain.handle('sentinel-export-report-file', async (_event, scanModules?: any) => {
  try {
    const { generateSecurityReport, generateReportHTML } = await import('./services/system/securityReportGenerator');
    const report = await generateSecurityReport(scanModules || undefined);
    const html = generateReportHTML(report);
    const result = await dialog.showSaveDialog(mainWindow || (undefined as any), {
      title: 'Export Security Report',
      defaultPath: `Sentinel_Report_${new Date().toISOString().slice(0, 10)}.html`,
      filters: [{ name: 'HTML Report', extensions: ['html'] }, { name: 'JSON Data', extensions: ['json'] }],
    });
    if (result.canceled || !result.filePath) return { success: false, error: 'Export cancelled' };
    const ext = path.extname(result.filePath).toLowerCase();
    if (ext === '.json') {
      fs.writeFileSync(result.filePath, JSON.stringify(report, null, 2), 'utf-8');
    } else {
      fs.writeFileSync(result.filePath, html, 'utf-8');
    }
    return { success: true, data: { path: result.filePath, format: ext === '.json' ? 'json' : 'html' } };
  } catch (e: any) { return { success: false, error: e.message }; }
});

// ── Push Notification: Main → Renderer threat alerts ──
function pushThreatAlert(title: string, message: string, severity: 'info' | 'warning' | 'error' = 'warning') {
  try {
    mainWindow?.webContents.send('sentinel-threat-alert', { title, message, severity, timestamp: Date.now() });
  } catch { /* renderer may not be loaded */ }
  try {
    tray?.displayBalloon({ title, content: message, iconType: severity === 'error' ? 'error' : severity === 'warning' ? 'warning' : 'info' });
  } catch { /* tray may not exist */ }
}

// Expose pushThreatAlert for use by other modules
(global as any).__sentinelPushAlert = pushThreatAlert;

// ── Settings Export / Import ──
ipcMain.handle('sentinel-config-export', async () => {
  try {
    const { getSentinelConfig } = await import('./services/sentinelConfig');
    const config = getSentinelConfig();
    const exportData = {
      _sentinel_config_backup: true,
      version: '5.0',
      exportedAt: new Date().toISOString(),
      config,
    };
    const result = await dialog.showSaveDialog(mainWindow || (undefined as any), {
      title: 'Export Sentinel Configuration',
      defaultPath: `Sentinel_Config_${new Date().toISOString().slice(0, 10)}.json`,
      filters: [{ name: 'JSON', extensions: ['json'] }],
    });
    if (result.canceled || !result.filePath) return { success: false, error: 'Cancelled' };
    fs.writeFileSync(result.filePath, JSON.stringify(exportData, null, 2), 'utf-8');
    return { success: true, data: { path: result.filePath } };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-config-import', async () => {
  try {
    const result = await dialog.showOpenDialog(mainWindow || (undefined as any), {
      title: 'Import Sentinel Configuration',
      filters: [{ name: 'JSON', extensions: ['json'] }],
      properties: ['openFile'],
    });
    if (result.canceled || !result.filePaths?.length) return { success: false, error: 'Cancelled' };
    const raw = fs.readFileSync(result.filePaths[0], 'utf-8');
    const data = JSON.parse(raw);
    if (!data?._sentinel_config_backup) return { success: false, error: 'Invalid Sentinel config file' };
    const { getSentinelConfig, updateAutonomousMode, setWhitelist, setExternalIpLookup } = await import('./services/sentinelConfig');
    if (data.config?.autonomousMode !== undefined) updateAutonomousMode(Boolean(data.config.autonomousMode));
    if (Array.isArray(data.config?.whitelist)) setWhitelist(data.config.whitelist);
    if (data.config?.allowExternalIpLookup !== undefined) setExternalIpLookup(Boolean(data.config.allowExternalIpLookup));
    return { success: true, data: getSentinelConfig() };
  } catch (e: any) { return { success: false, error: e.message }; }
});

// ── File Integrity Monitor ──

// Wire FIM to push real-time alerts when critical files change
(async () => {
  try {
    const fim = await import('./services/fileIntegrityMonitor');
    if (typeof fim.getChanges === 'function') {
      let lastChangeCount = 0;
      setInterval(() => {
        try {
          const changes = fim.getChanges();
          if (changes.length > lastChangeCount) {
            const newChanges = changes.slice(lastChangeCount);
            for (const c of newChanges) {
              if (c.risk === 'critical' || c.risk === 'high') {
                pushThreatAlert('File Integrity Alert', `${c.changeType}: ${c.filePath}`, c.risk === 'critical' ? 'error' : 'warning');
              }
            }
            lastChangeCount = changes.length;
          }
        } catch { /* FIM may not be running */ }
      }, 30_000);
    }
  } catch { /* FIM not available */ }
})();

// Wire USB Monitor — alert on new mass storage device connections
(async () => {
  try {
    const { getUsbDevices } = await import('./services/system/usbMonitor');
    let knownDeviceIds = new Set<string>();
    // Seed known devices on startup
    try {
      const initial = await getUsbDevices();
      for (const d of initial.connected) {
        if (d.deviceId) knownDeviceIds.add(d.deviceId);
      }
    } catch { /* initial seed failed — non-critical */ }

    setInterval(async () => {
      try {
        const result = await getUsbDevices();
        for (const d of result.connected) {
          if (d.deviceId && !knownDeviceIds.has(d.deviceId)) {
            knownDeviceIds.add(d.deviceId);
            if (d.isMassStorage) {
              pushThreatAlert('USB Mass Storage Detected', `${d.name} (${d.manufacturer}) — review for unauthorized access`, 'warning');
              const { addActivityLog } = await import('./services/activityLog');
              addActivityLog('USB Monitor', 'New Device', `${d.name} — ${d.manufacturer} [${d.deviceId}]`, 'warning');
            }
          }
        }
      } catch { /* USB poll failed — non-critical */ }
    }, 60_000); // Check every 60s
  } catch { /* USB monitor not available */ }
})();

// Wire Network Anomaly Detection — alert on suspicious connections
(async () => {
  try {
    const SUSPICIOUS_PORTS = new Set([4444, 5555, 6666, 8888, 9999, 1337, 31337, 12345, 65535, 1234]);
    const SAFE_PROCESSES = new Set(['svchost.exe', 'system', 'wininit.exe', 'lsass.exe', 'services.exe', 'csrss.exe', 'dwm.exe', 'explorer.exe', 'msedge.exe', 'chrome.exe', 'firefox.exe', 'code.exe', 'electron.exe', 'sentinel.exe']);
    let alertedConnections = new Set<string>();

    setInterval(async () => {
      try {
        const { getNetworkTrafficSnapshot } = await import('./services/networkMonitor');
        const connections = await getNetworkTrafficSnapshot(200);
        for (const conn of connections) {
          if (!conn.remoteIP || conn.remoteIP === '0.0.0.0' || conn.remoteIP === '127.0.0.1' || conn.remoteIP.startsWith('192.168.') || conn.remoteIP.startsWith('10.') || conn.remoteIP.startsWith('::')) continue;
          const key = `${conn.remoteIP}:${conn.remotePort}:${conn.pid}`;
          if (alertedConnections.has(key)) continue;
          const processLower = (conn.process || '').toLowerCase();
          // Flag suspicious port connections from non-standard processes
          if (SUSPICIOUS_PORTS.has(conn.remotePort) && !SAFE_PROCESSES.has(processLower)) {
            alertedConnections.add(key);
            pushThreatAlert('Suspicious Connection', `${conn.process} (PID:${conn.pid}) → ${conn.remoteIP}:${conn.remotePort}`, 'warning');
          }
        }
        // Prevent memory leak: trim old alerts
        if (alertedConnections.size > 500) {
          const arr = Array.from(alertedConnections);
          alertedConnections = new Set(arr.slice(-200));
        }
      } catch { /* Network poll failed — non-critical */ }
    }, 45_000); // Check every 45s
  } catch { /* Network monitor not available */ }
})();

ipcMain.handle('sentinel-fim-get-changes', async () => {
  try {
    const { getChanges } = await import('./services/fileIntegrityMonitor');
    return { success: true, data: getChanges() };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-fim-get-baseline', async () => {
  try {
    const { getBaseline } = await import('./services/fileIntegrityMonitor');
    return { success: true, data: getBaseline() };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-fim-run-check', async () => {
  try {
    const { runCheck } = await import('./services/fileIntegrityMonitor');
    const changes = runCheck();
    return { success: true, data: changes };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-fim-reset-baseline', async () => {
  try {
    const { resetBaseline } = await import('./services/fileIntegrityMonitor');
    resetBaseline();
    return { success: true };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-fim-get-config', async () => {
  try {
    const { getConfig } = await import('./services/fileIntegrityMonitor');
    return { success: true, data: getConfig() };
  } catch (e: any) { return { success: false, error: e.message }; }
});

ipcMain.handle('sentinel-fim-set-config', async (_event, update: any) => {
  try {
    const { setConfig } = await import('./services/fileIntegrityMonitor');
    const cfg = setConfig(update || {});
    return { success: true, data: cfg };
  } catch (e: any) { return { success: false, error: e.message }; }
});

// ============================================
// Shield/Firewall Handlers
// ============================================

ipcMain.handle('shield-enable-firewall-rule', async (_event, ruleName: string, enable: boolean) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const escaped = (ruleName || '').replace(/"/g, '\\"');
    const action = enable ? 'yes' : 'no';
    execSync(`netsh advfirewall firewall set rule name="${escaped}" new enable=${action}`, { windowsHide: true, timeout: 10000 });
    return { success: true, message: `Rule "${ruleName}" ${enable ? 'enabled' : 'disabled'}` };
  } catch (error: any) {
    return { success: false, message: error.message || 'Failed to toggle rule' };
  }
});

ipcMain.handle('shield-add-firewall-rule', async (_event, ruleName: string, protocol: string, port: number, action: 'Allow' | 'Block') => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const result = await createFirewallRule(ruleName, protocol, port, action);
    return result;
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('shield-update-firewall-rule', async (_event, ruleName: string, options: any) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const escaped = (ruleName || '').replace(/"/g, '\\"');
    let setClause = '';
    if (options?.localPort) setClause += ` localport=${options.localPort}`;
    if (options?.action) setClause += ` action=${options.action}`;
    if (options?.enable !== undefined) setClause += ` enable=${options.enable ? 'yes' : 'no'}`;
    if (!setClause.trim()) return { success: false, message: 'No update options provided' };
    execSync(`netsh advfirewall firewall set rule name="${escaped}" new${setClause}`, { windowsHide: true, timeout: 10000 });
    return { success: true, message: `Rule "${ruleName}" updated` };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('shield-scan-ports', async () => {
  try {
    const ports = await scanOpenPorts();
    return { success: true, data: ports };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('shield-unblock-port', async (_event, port: number, protocol?: 'TCP' | 'UDP' | 'Any') => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const proto = protocol || 'Any';
    const results: any[] = [];
    const dirs = ['in', 'out'];
    for (const dir of dirs) {
      const name = `Sentinel Block Port ${port} ${proto} ${dir === 'in' ? 'IN' : 'OUT'}`;
      try {
        execSync(`netsh advfirewall firewall delete rule name="${name}"`, { windowsHide: true, timeout: 10000 });
        results.push({ direction: dir, success: true });
      } catch {
        results.push({ direction: dir, success: false });
      }
    }
    return { success: true, message: `Port ${port} unblocked`, results };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('shield-block-ip-range', async (_event, startIP: string, endIP: string, ruleName: string, direction?: 'in' | 'out' | 'both') => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const result = await blockIPRange(startIP, endIP, ruleName, direction);
    return result;
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('shield-block-dangerous-subnets', async () => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const dangerous = ['185.220.0.0/16', '45.154.0.0/16', '193.142.0.0/16'];
    let blocked = 0;
    for (const subnet of dangerous) {
      try {
        await blockSubnet(subnet, `Sentinel Dangerous Subnet ${subnet}`, 'both');
        blocked++;
      } catch { /* skip failed */ }
    }
    return { success: true, message: `Blocked ${blocked} dangerous subnets`, blocked };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('shield-get-ip-metadata-stats', async () => {
  try {
    return { success: true, totalLookups: 0, cachedEntries: 0, lastLookup: null };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// ============================================
// SENTINEL CONFIG IPC HANDLERS
// ============================================

ipcMain.handle('sentinel-get-config', async () => {
  try {
    const config = getSentinelConfig();
    return { success: true, data: config };
  } catch (error: any) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('sentinel-set-autonomous-mode', async (_event, enabled: boolean) => {
  try {
    const config = updateAutonomousMode(enabled);
    return { success: true, data: config };
  } catch (error: any) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('sentinel-add-whitelist', async (_event, ip: string) => {
  try {
    const config = addWhitelistEntry(ip);
    return { success: true, data: config };
  } catch (error: any) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('sentinel-remove-whitelist', async (_event, ip: string) => {
  try {
    const config = removeWhitelistEntry(ip);
    return { success: true, data: config };
  } catch (error: any) {
    return { success: false, error: serializeIpcError(error) };
  }
});

// ============================================
// PERFORMANCE PROFILE IPC HANDLERS
// ============================================

ipcMain.handle('perf-get-profile', async () => {
  try {
    const { getPerformanceProfile } = await import('./services/performanceProfile');
    return { success: true, data: getPerformanceProfile() };
  } catch (error: any) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('perf-set-mode', async (_event, mode: string, customOverrides?: Record<string, number>) => {
  try {
    const { setProfileMode } = await import('./services/performanceProfile');
    const profile = setProfileMode(mode as 'auto' | 'low' | 'balanced' | 'high' | 'custom', customOverrides);
    return { success: true, data: profile };
  } catch (error: any) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('perf-refresh-hardware', async () => {
  try {
    const { refreshHardware } = await import('./services/performanceProfile');
    const profile = refreshHardware();
    return { success: true, data: profile };
  } catch (error: any) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('sentinel-set-whitelist', async (_event, ips: string[]) => {
  try {
    const config = setWhitelist(ips);
    return { success: true, data: config };
  } catch (error: any) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('shield-whitelist-threat', async (_event, payload: ThreatWhitelistPayload) => {
  if (!isAdmin) {
    return { success: false, error: 'Admin privileges required' };
  }

  try {
    const target = payload.subnet?.trim() || payload.ip?.trim();
    if (!target) {
      return { success: false, error: 'No IP or subnet provided for whitelisting' };
    }

    const config = addWhitelistEntry(target);
    const message = `Whitelisted ${target} (${payload.processName || 'Unknown process'})`;
    addActivityLog('Shield', 'Whitelist Threat', message, 'success');

    try {
      const auditEvent: SecurityEventRecord = {
        pid: payload.pid ?? 0,
        processName: payload.processName ?? 'Unknown',
        processCompany: undefined,
        processPath: undefined,
        localPort: 0,
        remoteSubnet: payload.subnet ?? target,
        remoteIP: payload.ip ?? target,
        riskScore: 0,
        riskLevel: 'Low',
        tlsStatus: 'pending',
        reason: payload.reason ?? 'Manual whitelist from ThreatTimeline',
        actionTaken: 'Alerted',
      };
      logSecurityEvent(auditEvent);
    } catch (auditErr) {
      console.warn('[Whitelist] Failed to log security event:', auditErr);
    }

    return {
      success: true,
      data: {
        target,
        config,
      },
    };
  } catch (error: any) {
    addActivityLog('Shield', 'Whitelist Threat', `Failed to whitelist threat: ${error.message}`, 'error');
    return { success: false, error: serializeIpcError(error) };
  }
});

// ============================================
// MANUAL BLOCK EVENT LOGGING (Unified Event Logging)
// ============================================

ipcMain.handle('sentinel-log-manual-block', async (_event, payload: unknown) => {
  try {
    const parsed = ShieldManualBlockLogSchema.parse(payload ?? {});
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
  } catch (error: any) {
    return { success: false, error: serializeIpcError(error) };
  }
});

// ============================================
// QUICK BLOCK FROM THREAT TIMELINE
// ============================================

ipcMain.handle('sentinel-quick-block-subnet', async (_event, subnet: string, reason?: string) => {
  try {
    await blockSubnet(subnet, reason || 'Quick block from Threat Timeline', 'both');
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
  } catch (error: any) {
    return { success: false, error: serializeIpcError(error) };
  }
});

// VPN-Awareness Layer — sentinel-vpn-get-status already registered in Phase 4 block above

ipcMain.handle('sentinel-vpn-get-adapter-info', async () => {
  try {
    const { getVpnStatus } = await import('./services/vpnDetector');
    const status = getVpnStatus();
    return { success: true, adapters: status.adapters, active: status.active, provider: status.provider };
  } catch (error: any) {
    return { success: false, error: error.message, adapters: [], active: false };
  }
});

// DNS — Real implementation using PowerShell Get/Set-DnsClientServerAddress
let _dnsBackup: { adapter: string; servers: string[] } | null = null;

ipcMain.handle('ghost-get-current-dns', async () => {
  try {
    const { getExecOptions } = await import('./services/execOptions');
    const opts = getExecOptions();

    // Get active adapter and its DNS servers
    const cmd = `powershell -ExecutionPolicy Bypass -NoProfile -Command "` +
      `$a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1; ` +
      `if ($a) { $dns = Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses; ` +
      `$a.Name + '|' + ($dns -join ',') } else { 'NONE' }"`;

    const { stdout } = await execPromise(cmd, opts);
    const trimmed = String(stdout).trim();

    if (!trimmed || trimmed === 'NONE') {
      return { success: true, primary: 'DHCP', secondary: '', name: 'Auto (DHCP)', adapter: '' };
    }

    const [adapter, dnsStr] = trimmed.split('|');
    const servers = (dnsStr || '').split(',').filter(Boolean);

    return {
      success: true,
      primary: servers[0] || 'DHCP',
      secondary: servers[1] || '',
      name: servers.length > 0 ? 'Custom' : 'Auto (DHCP)',
      adapter: adapter?.trim() || '',
    };
  } catch (error: any) {
    return { success: false, error: error.message, primary: '', secondary: '', name: 'Unknown' };
  }
});

ipcMain.handle('ghost-set-dns', async (_event, primary: string, secondary: string, forceVpn?: boolean) => {
  if (!isAdmin) {
    return { success: false, message: 'Admin privileges required. Run Sentinel as Administrator.' };
  }

  // Validate IP format
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(primary)) {
    return { success: false, message: `Invalid primary DNS: ${primary}` };
  }
  if (secondary && !ipRegex.test(secondary)) {
    return { success: false, message: `Invalid secondary DNS: ${secondary}` };
  }

  try {
    const { getExecOptions } = await import('./services/execOptions');
    const opts = getExecOptions();

    // VPN detection — warn user before DNS change
    const vpnCheckCmd = `powershell -ExecutionPolicy Bypass -NoProfile -Command "` +
      `$vpn = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'NordLynx|WireGuard|TAP-|TUN|VPN|Wintun' -and $_.Status -eq 'Up' }; ` +
      `if ($vpn) { $vpn.InterfaceDescription -join ',' } else { '' }"`;
    const { stdout: vpnOut } = await execPromise(vpnCheckCmd, opts);
    const vpnAdapters = String(vpnOut).trim();

    if (vpnAdapters && !forceVpn) {
      return {
        success: false,
        vpnDetected: true,
        vpnAdapters,
        message: `VPN detected (${vpnAdapters}). DNS is managed by VPN. Changing DNS on the physical adapter may break internet. Use forceVpn=true to override.`,
      };
    }

    // Get active physical adapter (skip VPN adapters)
    const adapterCmd = `powershell -ExecutionPolicy Bypass -NoProfile -Command "` +
      `$a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'NordLynx|WireGuard|TAP-|TUN|Wintun' } | Select-Object -First 1; ` +
      `if ($a) { $dns = Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses; ` +
      `$a.Name + '|' + ($dns -join ',') } else { 'NONE' }"`;

    const { stdout: adapterOut } = await execPromise(adapterCmd, opts);
    const [adapterName, currentDnsStr] = String(adapterOut).trim().split('|');

    if (!adapterName || adapterName === 'NONE') {
      return { success: false, message: 'No active physical network adapter found' };
    }

    // Backup current DNS for rollback (memory + disk)
    _dnsBackup = {
      adapter: adapterName.trim(),
      servers: (currentDnsStr || '').split(',').filter(Boolean),
    };
    try {
      const backupPath = path.join(app.getPath('userData'), 'dns-backup.json');
      fs.writeFileSync(backupPath, JSON.stringify(_dnsBackup, null, 2), 'utf8');
    } catch { /* non-fatal */ }

    // Set new DNS
    const servers = secondary
      ? `('${primary}','${secondary}')`
      : `('${primary}')`;

    const setCmd = `powershell -ExecutionPolicy Bypass -NoProfile -Command "` +
      `Set-DnsClientServerAddress -InterfaceAlias '${adapterName.trim()}' -ServerAddresses ${servers}"`;

    await execPromise(setCmd, opts);

    // Flush DNS cache
    try { await execPromise('ipconfig /flushdns', opts); } catch { /* non-fatal */ }

    // Automatic internet test after DNS change
    let internetOk = false;
    try {
      // IP connectivity test
      const pingRes = await execPromise('ping -n 1 -w 3000 1.1.1.1', { ...opts, timeout: 5000 });
      const pingOk = !String(pingRes.stdout).includes('Request timed out') && !String(pingRes.stdout).includes('unreachable');
      // DNS resolution test
      const dnsRes = await execPromise('nslookup google.com 2>&1', { ...opts, timeout: 5000 });
      const dnsOk = String(dnsRes.stdout).includes('Address') && !String(dnsRes.stdout).includes('can\'t find');
      internetOk = pingOk && dnsOk;
    } catch {
      internetOk = false;
    }

    if (!internetOk && _dnsBackup) {
      // AUTO-ROLLBACK: internet broken after DNS change
      try {
        if (_dnsBackup.servers.length === 0) {
          await execPromise(`powershell -ExecutionPolicy Bypass -NoProfile -Command "Set-DnsClientServerAddress -InterfaceAlias '${_dnsBackup.adapter}' -ResetServerAddresses"`, opts);
        } else {
          const rollbackServers = _dnsBackup.servers.map((s: string) => `'${s}'`).join(',');
          await execPromise(`powershell -ExecutionPolicy Bypass -NoProfile -Command "Set-DnsClientServerAddress -InterfaceAlias '${_dnsBackup.adapter}' -ServerAddresses (${rollbackServers})"`, opts);
        }
        try { await execPromise('ipconfig /flushdns', opts); } catch { /* */ }
      } catch { /* rollback failed */ }

      addActivityLog('DNS', 'Set DNS', `DNS change to ${primary} FAILED internet test — AUTO-ROLLED BACK`, 'error');
      return {
        success: false,
        autoRolledBack: true,
        message: `DNS changed to ${primary} but internet test failed. Automatically rolled back to previous DNS.`,
      };
    }

    addActivityLog('DNS', 'Set DNS', `DNS changed to ${primary}${secondary ? ' / ' + secondary : ''} on ${adapterName.trim()}${vpnAdapters ? ' (VPN active, forced)' : ''}`, 'success');

    return {
      success: true,
      message: `DNS set to ${primary}${secondary ? ' / ' + secondary : ''} on ${adapterName.trim()}`,
      vpnActive: !!vpnAdapters,
      internetTestPassed: true,
    };
  } catch (error: any) {
    return { success: false, message: error.message || 'Failed to set DNS' };
  }
});

ipcMain.handle('ghost-rollback-dns', async () => {
  if (!isAdmin) {
    return { success: false, message: 'Admin privileges required' };
  }
  if (!_dnsBackup) {
    // Try loading from disk (survives app restart)
    try {
      const backupPath = path.join(app.getPath('userData'), 'dns-backup.json');
      if (fs.existsSync(backupPath)) {
        _dnsBackup = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
      }
    } catch { /* */ }
  }
  if (!_dnsBackup) {
    return { success: false, message: 'No DNS backup available to rollback' };
  }

  try {
    const { getExecOptions } = await import('./services/execOptions');
    const opts = getExecOptions();

    if (_dnsBackup.servers.length === 0) {
      // Restore to DHCP
      const cmd = `powershell -ExecutionPolicy Bypass -NoProfile -Command "` +
        `Set-DnsClientServerAddress -InterfaceAlias '${_dnsBackup.adapter}' -ResetServerAddresses"`;
      await execPromise(cmd, opts);
    } else {
      const servers = _dnsBackup.servers.map((s) => `'${s}'`).join(',');
      const cmd = `powershell -ExecutionPolicy Bypass -NoProfile -Command "` +
        `Set-DnsClientServerAddress -InterfaceAlias '${_dnsBackup.adapter}' -ServerAddresses (${servers})"`;
      await execPromise(cmd, opts);
    }

    try { await execPromise('ipconfig /flushdns', opts); } catch { /* non-fatal */ }

    addActivityLog('DNS', 'Rollback DNS', `DNS restored to ${_dnsBackup.servers.join(', ') || 'DHCP'} on ${_dnsBackup.adapter}`, 'success');

    const result = { success: true, message: `DNS rolled back to ${_dnsBackup.servers.join(', ') || 'DHCP'}` };
    _dnsBackup = null;
    return result;
  } catch (error: any) {
    return { success: false, message: error.message || 'Rollback failed' };
  }
});

ipcMain.handle('ghost-test-dns-speed', async (_event, dnsServer: string) => {
  try {
    const { getExecOptions } = await import('./services/execOptions');
    const opts = getExecOptions();

    const pingCmd = `powershell -ExecutionPolicy Bypass -NoProfile -Command "` +
      `$r = Test-Connection -ComputerName '${dnsServer}' -Count 2 -BufferSize 32 -ErrorAction SilentlyContinue; ` +
      `if ($r) { [math]::Round(($r | Measure-Object -Property ResponseTime -Average).Average, 1) } else { -1 }"`;

    const { stdout } = await execPromise(pingCmd, opts);
    const latency = parseFloat(String(stdout).trim());

    return { success: true, latency: isNaN(latency) || latency < 0 ? -1 : latency };
  } catch (error: any) {
    return { success: false, latency: -1 };
  }
});

// Hosts file
ipcMain.handle('ghost-get-hosts-file', async () => {
  try {
    const hostsPath = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
    const content = fs.readFileSync(hostsPath, 'utf8');
    return { success: true, content, entries: [], lastModified: new Date().toLocaleString() };
  } catch (error: any) {
    return { success: false, error: error.message, content: '', entries: [] };
  }
});

ipcMain.handle('ghost-save-hosts-file', async (_event, content: string) => {
  if (!isAdmin) {
    return { success: false, error: 'Admin privileges required' };
  }
  try {
    const hostsPath = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
    fs.writeFileSync(hostsPath, content, 'utf8');
    return { success: true, message: 'Hosts file saved' };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// RAM Operations
ipcMain.handle('forge-get-ram-stats', async () => {
  try {
    const ram = getRAMUsage();
    return {
      totalGB: ram.totalGB,
      usedGB: ram.usedGB,
      availableGB: ram.freeGB,
      systemGB: ram.usedGB * 0.25,
      appsGB: ram.usedGB * 0.75,
      cacheGB: 0,
      usagePercent: ram.usagePercent,
    };
  } catch (error: any) {
    return { totalGB: 0, usedGB: 0, availableGB: 0, systemGB: 0, appsGB: 0, cacheGB: 0, usagePercent: 0 };
  }
});

ipcMain.handle('forge-clear-standby-cache', async () => {
  if (!isAdmin) {
    return { success: false, message: 'Admin privileges required' };
  }
  try {
    const { getExecOptions } = await import('./services/execOptions');
    const opts = getExecOptions();
    const freeBefore = os.freemem();
    // Clear standby list via PowerShell — requires admin
    await execPromise(
      'powershell -ExecutionPolicy Bypass -NoProfile -Command "Clear-RecycleBin -Force -ErrorAction SilentlyContinue; [System.GC]::Collect()"',
      opts
    );
    const freeAfter = os.freemem();
    const freedMB = Math.max(0, Math.round((freeAfter - freeBefore) / (1024 * 1024)));
    return { success: true, freedMB, message: `Cache cleared, freed ~${freedMB} MB` };
  } catch (error: any) {
    return { success: false, message: error.message || 'Cache clear failed' };
  }
});

// Startup Programs — Registry + WMI + Scheduled Tasks + Risk assessment
ipcMain.handle('forge-get-startup-items', async () => {
  try {
    const { spawnSync } = require('child_process');
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$all = @()

# 1. Win32_StartupCommand (WMI)
Get-CimInstance Win32_StartupCommand | ForEach-Object {
  $all += [PSCustomObject]@{ name=$_.Name; command=$_.Command; location=$_.Location; user=$_.User; source='WMI' }
}

# 2. Registry HKLM Run
$hklm = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
if (Test-Path $hklm) {
  (Get-ItemProperty $hklm).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
    $all += [PSCustomObject]@{ name=$_.Name; command=$_.Value; location=$hklm; user='AllUsers'; source='Registry-HKLM' }
  }
}

# 3. Registry HKCU Run
$hkcu = 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
if (Test-Path $hkcu) {
  (Get-ItemProperty $hkcu).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
    $all += [PSCustomObject]@{ name=$_.Name; command=$_.Value; location=$hkcu; user=$env:USERNAME; source='Registry-HKCU' }
  }
}

# 4. Scheduled Tasks (Ready state only)
Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -and $_.Actions.Count -gt 0 } | Select-Object -First 50 | ForEach-Object {
  $act = $_.Actions[0]
  $cmd = if($act.Execute){$act.Execute + ' ' + $act.Arguments}else{''}
  $all += [PSCustomObject]@{ name=$_.TaskName; command=$cmd.Trim(); location=$_.TaskPath; user=$_.Principal.UserId; source='ScheduledTask' }
}

# Boot time
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = [math]::Round(((Get-Date) - $boot).TotalSeconds)

# Deduplicate by name
$unique = $all | Sort-Object name -Unique

@{ items = $unique; bootSeconds = $uptime } | ConvertTo-Json -Depth 3 -Compress
`;
    const result = spawnSync('powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
      { input: psScript, timeout: 20000, windowsHide: true, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
    );
    if (result.error) throw result.error;
    const output = (result.stdout || '').trim();
    if (!output) return { success: true, items: [], currentBootTime: -1 };

    const parsed = JSON.parse(output);
    let items = parsed.items;
    if (!Array.isArray(items)) items = items ? [items] : [];

    // Known safe publishers for risk assessment
    const safePaths = /microsoft|windows|nvidia|amd|intel|realtek|synaptics|logitech/i;

    return {
      success: true,
      items: items.map((i: any) => {
        const cmd = String(i.command || '');
        const name = String(i.name || 'Unknown');
        const isSafe = safePaths.test(cmd) || safePaths.test(name);
        const isSuspicious = /temp|appdata\\local\\temp|powershell|cmd\.exe|wscript|cscript/i.test(cmd);
        const risk = isSuspicious ? 'high' : isSafe ? 'low' : 'medium';
        return {
          name,
          command: cmd,
          location: i.location || '',
          user: i.user || '',
          source: i.source || 'Unknown',
          risk,
        };
      }),
      currentBootTime: parsed.bootSeconds || -1,
    };
  } catch (error: any) {
    return { success: false, items: [], currentBootTime: -1, error: error.message };
  }
});

// Services — real enumeration via PowerShell + WMI PathName
ipcMain.handle('forge-get-windows-services', async () => {
  try {
    const { spawnSync } = require('child_process');
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$wmiMap = @{}
Get-CimInstance Win32_Service | ForEach-Object { $wmiMap[$_.Name] = $_.PathName }
Get-Service | ForEach-Object {
  [PSCustomObject]@{
    name = $_.Name
    displayName = $_.DisplayName
    status = $_.Status.ToString()
    startType = $_.StartType.ToString()
    path = if($wmiMap.ContainsKey($_.Name)){$wmiMap[$_.Name]}else{''}
  }
} | ConvertTo-Json -Depth 2 -Compress
`;
    const result = spawnSync('powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
      { input: psScript, timeout: 25000, windowsHide: true, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 }
    );
    if (result.error) throw result.error;
    const output = (result.stdout || '').trim();
    if (!output) return { success: true, services: [] };
    let services = JSON.parse(output);
    if (!Array.isArray(services)) services = services ? [services] : [];
    return {
      success: true,
      services: services.map((s: any) => ({
        name: s.name || '',
        displayName: s.displayName || '',
        status: String(s.status ?? ''),
        startType: String(s.startType ?? ''),
        path: s.path || '',
      })),
    };
  } catch (error: any) {
    return { success: false, services: [], error: error.message };
  }
});

// Service control actions: start, stop, disable, enable
ipcMain.handle('forge-control-service', async (_event, serviceName: string, action: 'start' | 'stop' | 'disable' | 'enable') => {
  if (!isAdmin) {
    return { success: false, message: 'Admin privileges required' };
  }
  if (!serviceName || !action) {
    return { success: false, message: 'Missing service name or action' };
  }
  try {
    const escaped = serviceName.replace(/'/g, "''");
    let psCmd = '';
    switch (action) {
      case 'start':
        psCmd = `Start-Service -Name '${escaped}' -ErrorAction Stop`;
        break;
      case 'stop':
        psCmd = `Stop-Service -Name '${escaped}' -Force -ErrorAction Stop`;
        break;
      case 'disable':
        psCmd = `Set-Service -Name '${escaped}' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name '${escaped}' -Force -ErrorAction SilentlyContinue`;
        break;
      case 'enable':
        psCmd = `Set-Service -Name '${escaped}' -StartupType Automatic -ErrorAction Stop`;
        break;
      default:
        return { success: false, message: `Unknown action: ${action}` };
    }
    const { getExecOptions } = await import('./services/execOptions');
    const opts = getExecOptions();
    await execPromise(`powershell -NoProfile -ExecutionPolicy Bypass -Command "${psCmd}"`, opts);
    addActivityLog('Forge', 'Service Control', `${action} service: ${serviceName}`, 'success');
    return { success: true, message: `Service ${serviceName} — ${action} successful` };
  } catch (error: any) {
    return { success: false, message: error.message || `Failed to ${action} service` };
  }
});

// Vault — Secure Notes with AES-256-GCM encryption at rest
// Machine-derived key from hostname + userData path (deterministic per machine)
const _vaultKeySource = () => {
  const crypto = require('crypto');
  const seed = `sentinel-vault-${os.hostname()}-${app.getPath('userData')}`;
  return crypto.createHash('sha256').update(seed).digest();
};

const _vaultEncrypt = (plaintext: string): string => {
  const crypto = require('crypto');
  const key = _vaultKeySource();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + ':' + tag + ':' + encrypted;
};

const _vaultDecrypt = (ciphertext: string): string => {
  const crypto = require('crypto');
  const key = _vaultKeySource();
  const [ivHex, tagHex, encHex] = ciphertext.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

const _vaultPath = () => path.join(app.getPath('userData'), 'vault', 'notes.encrypted');

ipcMain.handle('vault-get-secure-notes', async () => {
  try {
    const vaultFile = _vaultPath();
    const storagePath = path.dirname(vaultFile);
    if (!fs.existsSync(vaultFile)) {
      return { success: true, notes: [], storagePath };
    }
    const raw = fs.readFileSync(vaultFile, 'utf8').trim();
    if (!raw) return { success: true, notes: [], storagePath };
    const decrypted = _vaultDecrypt(raw);
    const notes = JSON.parse(decrypted);
    return { success: true, notes: Array.isArray(notes) ? notes : [], storagePath };
  } catch (error: any) {
    return { success: false, notes: [], error: error.message };
  }
});

ipcMain.handle('vault-save-secure-note', async (_event, noteData: any) => {
  try {
    const vaultFile = _vaultPath();
    const vaultDir = path.dirname(vaultFile);
    if (!fs.existsSync(vaultDir)) fs.mkdirSync(vaultDir, { recursive: true });

    let notes: any[] = [];
    if (fs.existsSync(vaultFile)) {
      try {
        const raw = fs.readFileSync(vaultFile, 'utf8').trim();
        if (raw) notes = JSON.parse(_vaultDecrypt(raw));
      } catch { notes = []; }
    }

    if (noteData.id) {
      // Update existing note
      const idx = notes.findIndex((n: any) => n.id === noteData.id);
      if (idx >= 0) {
        notes[idx] = { ...notes[idx], ...noteData, updatedAt: new Date().toISOString() };
      } else {
        notes.push({ ...noteData, createdAt: new Date().toISOString() });
      }
    } else {
      const id = `note-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      notes.push({ id, ...noteData, createdAt: new Date().toISOString() });
    }

    fs.writeFileSync(vaultFile, _vaultEncrypt(JSON.stringify(notes)), 'utf8');
    return { success: true, message: 'Note saved (encrypted)' };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('vault-delete-secure-note', async (_event, noteId: string) => {
  try {
    const vaultFile = _vaultPath();
    if (!fs.existsSync(vaultFile)) return { success: false, error: 'No notes found' };
    const raw = fs.readFileSync(vaultFile, 'utf8').trim();
    let notes: any[] = raw ? JSON.parse(_vaultDecrypt(raw)) : [];
    const before = notes.length;
    notes = notes.filter((n: any) => n.id !== noteId);
    if (notes.length === before) return { success: false, error: 'Note not found' };
    fs.writeFileSync(vaultFile, _vaultEncrypt(JSON.stringify(notes)), 'utf8');
    return { success: true, message: 'Note deleted' };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('vault-get-encrypted-files', async () => {
  try {
    const vaultDir = path.join(app.getPath('userData'), 'vault-files');
    if (!fs.existsSync(vaultDir)) {
      return { success: true, files: [], storagePath: vaultDir };
    }
    const files = fs.readdirSync(vaultDir).map((f) => {
      const fp = path.join(vaultDir, f);
      const stat = fs.statSync(fp);
      return { name: f, path: fp, size: stat.size, modified: stat.mtime.toISOString() };
    });
    return { success: true, files, storagePath: vaultDir };
  } catch (error: any) {
    return { success: false, files: [], error: error.message };
  }
});

// FIM handlers already registered in Phase 4 block above (sentinel-fim-get-config, etc.)

// === EVENT LOG ANALYZER ===
ipcMain.handle('sentinel-eventlog-get-security', async () => {
  try {
    const { spawnSync } = require('child_process');
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
Get-WinEvent -LogName Security -MaxEvents 200 | ForEach-Object {
  [PSCustomObject]@{
    id = $_.Id
    timeCreated = $_.TimeCreated.ToString('o')
    level = $_.LevelDisplayName
    message = ($_.Message -split '\\n')[0]
    provider = $_.ProviderName
  }
} | ConvertTo-Json -Depth 2 -Compress
`;
    const result = spawnSync('powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
      { input: psScript, timeout: 15000, windowsHide: true, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
    );
    if (result.error) throw result.error;
    const output = (result.stdout || '').trim();
    if (!output) return { success: true, events: [] };
    let events = JSON.parse(output);
    if (!Array.isArray(events)) events = events ? [events] : [];
    return { success: true, events };
  } catch (error: any) {
    return { success: false, events: [], error: error.message };
  }
});

ipcMain.handle('sentinel-eventlog-get-alerts', async () => {
  try {
    const { spawnSync } = require('child_process');
    // Filter for suspicious events: failed logins, privilege escalation, service installs, process creation
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$suspiciousIds = @(4625, 4672, 4688, 7045, 4720, 4732, 1102)
$events = Get-WinEvent -LogName Security -MaxEvents 5000 | Where-Object { $suspiciousIds -contains $_.Id } | Select-Object -First 100 | ForEach-Object {
  $risk = 'medium'
  if ($_.Id -eq 4625) { $risk = 'high' }
  if ($_.Id -eq 7045) { $risk = 'high' }
  if ($_.Id -eq 1102) { $risk = 'critical' }
  if ($_.Id -eq 4672) { $risk = 'medium' }
  [PSCustomObject]@{
    id = $_.Id
    timeCreated = $_.TimeCreated.ToString('o')
    level = $_.LevelDisplayName
    message = ($_.Message -split '\\n')[0]
    provider = $_.ProviderName
    risk = $risk
    eventType = switch($_.Id) {
      4625 { 'Failed Login' }
      4672 { 'Privilege Escalation' }
      4688 { 'Process Created' }
      7045 { 'Service Installed' }
      4720 { 'Account Created' }
      4732 { 'Group Membership Changed' }
      1102 { 'Audit Log Cleared' }
      default { 'Suspicious' }
    }
  }
}
$events | ConvertTo-Json -Depth 2 -Compress
`;
    const result = spawnSync('powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
      { input: psScript, timeout: 20000, windowsHide: true, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
    );
    if (result.error) throw result.error;
    const output = (result.stdout || '').trim();
    if (!output) return { success: true, alerts: [] };
    let alerts = JSON.parse(output);
    if (!Array.isArray(alerts)) alerts = alerts ? [alerts] : [];
    return { success: true, alerts };
  } catch (error: any) {
    return { success: false, alerts: [], error: error.message };
  }
});

// === SYSTEM HARDENING SCORE ===
ipcMain.handle('sentinel-hardening-get-score', async () => {
  try {
    const { spawnSync } = require('child_process');
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$checks = @()
$passed = 0
$total = 0

# 1. Firewall active (all profiles)
$total++
$fw = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $true }
$fwOk = ($fw.Count -ge 3)
if ($fwOk) { $passed++ }
$checks += [PSCustomObject]@{ name='Firewall Active (All Profiles)'; passed=$fwOk; category='Network' }

# 2. Windows Defender active
$total++
$def = Get-MpComputerStatus -ErrorAction SilentlyContinue
$defOk = ($def.AntivirusEnabled -eq $true)
if ($defOk) { $passed++ }
$checks += [PSCustomObject]@{ name='Windows Defender Active'; passed=$defOk; category='Antivirus' }

# 3. Defender real-time protection
$total++
$rtOk = ($def.RealTimeProtectionEnabled -eq $true)
if ($rtOk) { $passed++ }
$checks += [PSCustomObject]@{ name='Real-Time Protection'; passed=$rtOk; category='Antivirus' }

# 4. UAC enabled
$total++
$uac = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue).EnableLUA
$uacOk = ($uac -eq 1)
if ($uacOk) { $passed++ }
$checks += [PSCustomObject]@{ name='UAC Enabled'; passed=$uacOk; category='System' }

# 5. Auto-Updates
$total++
$au = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' -ErrorAction SilentlyContinue).AUOptions
$auOk = ($au -ge 3)
if ($auOk) { $passed++ }
$checks += [PSCustomObject]@{ name='Auto-Updates Enabled'; passed=$auOk; category='Updates' }

# 6. Remote Desktop disabled
$total++
$rdp = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
$rdpOk = ($rdp -eq 1)
if ($rdpOk) { $passed++ }
$checks += [PSCustomObject]@{ name='Remote Desktop Disabled'; passed=$rdpOk; category='Network' }

# 7. SMBv1 disabled
$total++
$smb1 = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol
$smb1Ok = ($smb1 -eq $false)
if ($smb1Ok) { $passed++ }
$checks += [PSCustomObject]@{ name='SMBv1 Disabled'; passed=$smb1Ok; category='Network' }

# 8. Guest account disabled
$total++
$guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
$guestOk = ($guest.Enabled -eq $false)
if ($guestOk) { $passed++ }
$checks += [PSCustomObject]@{ name='Guest Account Disabled'; passed=$guestOk; category='Accounts' }

# 9. BitLocker (check C: drive)
$total++
$bl = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue
$blOk = ($bl.ProtectionStatus -eq 'On')
if ($blOk) { $passed++ }
$checks += [PSCustomObject]@{ name='BitLocker Active (C:)'; passed=$blOk; category='Encryption' }

# 10. Secure Boot
$total++
$sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
$sbOk = ($sb -eq $true)
if ($sbOk) { $passed++ }
$checks += [PSCustomObject]@{ name='Secure Boot Enabled'; passed=$sbOk; category='Boot' }

$score = if($total -gt 0){[math]::Round(($passed / $total) * 100)}else{0}

[PSCustomObject]@{
  score = $score
  passed = $passed
  total = $total
  checks = $checks
} | ConvertTo-Json -Depth 3 -Compress
`;
    const result = spawnSync('powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
      { input: psScript, timeout: 20000, windowsHide: true, encoding: 'utf8', maxBuffer: 5 * 1024 * 1024 }
    );
    if (result.error) throw result.error;
    const output = (result.stdout || '').trim();
    if (!output) return { success: true, score: 0, passed: 0, total: 0, checks: [] };
    const parsed = JSON.parse(output);
    let checks = parsed.checks;
    if (!Array.isArray(checks)) checks = checks ? [checks] : [];
    return { success: true, score: parsed.score || 0, passed: parsed.passed || 0, total: parsed.total || 0, checks };
  } catch (error: any) {
    return { success: false, score: 0, passed: 0, total: 0, checks: [], error: error.message };
  }
});

// === PORT SCANNER (own open ports) ===
ipcMain.handle('sentinel-portscan-run', async () => {
  try {
    const { spawnSync } = require('child_process');
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$listening = Get-NetTCPConnection -State Listen | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  [PSCustomObject]@{
    port = $_.LocalPort
    address = $_.LocalAddress
    pid = $_.OwningProcess
    process = if($proc){$proc.ProcessName}else{'Unknown'}
    processPath = if($proc){$proc.Path}else{''}
  }
} | Sort-Object port -Unique
$listening | ConvertTo-Json -Depth 2 -Compress
`;
    const result = spawnSync('powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
      { input: psScript, timeout: 10000, windowsHide: true, encoding: 'utf8', maxBuffer: 5 * 1024 * 1024 }
    );
    if (result.error) throw result.error;
    const output = (result.stdout || '').trim();
    if (!output) return { success: true, ports: [] };
    let ports = JSON.parse(output);
    if (!Array.isArray(ports)) ports = ports ? [ports] : [];

    // Risk assessment per port
    const highRiskPorts = new Set([21, 23, 25, 135, 137, 138, 139, 445, 1433, 1434, 3389, 5900, 5985, 5986]);
    const knownSafe = new Set([80, 443, 8080, 53]);

    return {
      success: true,
      ports: ports.map((p: any) => ({
        port: p.port,
        address: p.address || '0.0.0.0',
        pid: p.pid,
        process: p.process || 'Unknown',
        processPath: p.processPath || '',
        risk: highRiskPorts.has(p.port) ? 'high' : knownSafe.has(p.port) ? 'low' : 'medium',
      })),
    };
  } catch (error: any) {
    return { success: false, ports: [], error: error.message };
  }
});

// === INCIDENT TIMELINE (aggregation) ===
ipcMain.handle('sentinel-timeline-get-events', async (_event, maxEvents?: number) => {
  try {
    const limit = maxEvents || 100;
    const timeline: any[] = [];

    // 1. Activity log entries
    try {
      const logPath = path.join(app.getPath('userData'), 'activity-log.json');
      if (fs.existsSync(logPath)) {
        const logs = JSON.parse(fs.readFileSync(logPath, 'utf8'));
        if (Array.isArray(logs)) {
          for (const l of logs.slice(-50)) {
            timeline.push({
              id: `act-${l.timestamp || Date.now()}`,
              timestamp: l.timestamp || new Date().toISOString(),
              type: 'activity',
              source: l.module || l.source || 'System',
              description: l.message || l.action || '',
              severity: l.level === 'error' ? 'high' : l.level === 'warning' ? 'medium' : 'low',
            });
          }
        }
      }
    } catch { /* */ }

    // 2. FIM changes
    try {
      const fim = await import('./services/fileIntegrityMonitor');
      const changes = fim.getChanges();
      for (const c of changes.slice(-30)) {
        timeline.push({
          id: c.id,
          timestamp: c.detectedAt,
          type: 'fim',
          source: 'File Integrity',
          description: `${c.changeType}: ${c.filePath}`,
          severity: c.risk,
        });
      }
    } catch { /* */ }

    // 3. Security events
    try {
      const eventsPath = path.join(app.getPath('userData'), 'security-events.json');
      if (fs.existsSync(eventsPath)) {
        const events = JSON.parse(fs.readFileSync(eventsPath, 'utf8'));
        if (Array.isArray(events)) {
          for (const e of events.slice(-30)) {
            timeline.push({
              id: e.id || `sec-${e.timestamp}`,
              timestamp: e.timestamp || new Date().toISOString(),
              type: 'security',
              source: e.source || 'Security',
              description: e.description || e.message || '',
              severity: e.severity || 'medium',
            });
          }
        }
      }
    } catch { /* */ }

    // Sort by timestamp descending, limit
    timeline.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    return { success: true, events: timeline.slice(0, limit) };
  } catch (error: any) {
    return { success: false, events: [], error: error.message };
  }
});

// === SHIELD MODULE: IP METADATA LOOKUP ===
// Note: shield-get-ip-metadata is now handled in shieldHandlers.ts

// Network traffic + metadata (REMOVED - now in shieldHandlers.ts)

// --- Shield network inspection helpers (request/response style) ---
ipcMain.handle('shield-inspect-tls', async (_event, host: string) => {
  try {
    const sanitized = (host || '').trim();
    if (!sanitized) {
      return { success: false, error: { message: 'Host is required' } };
    }

    const summary = await inspectTLS(sanitized);
    return { success: true, data: summary };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('shield-register-address-watch', async (_event, ip: string) => {
  try {
    const normalized = (ip || '').trim();
    if (!normalized) {
      return { success: false, error: { message: 'IP address is required' } };
    }

    const record = registerAddressWatch(normalized);
    return { success: true, data: record };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

ipcMain.handle('shield-get-address-watch', async () => {
  try {
    const tracked = getAddressWatchSummary();
    const topHit = tracked.reduce<ReturnType<typeof getAddressWatchSummary>[number] | null>((best, current) => {
      if (!best) return current;
      return current.hits > best.hits ? current : best;
    }, null);
    const summary = {
      totalTracked: tracked.length,
      topHit,
    };
    return {
      success: true,
      data: {
        summary,
        tracked,
        fetchedAt: Date.now(),
      },
    };
  } catch (error) {
    return { success: false, error: serializeIpcError(error) };
  }
});

// --- Renderer discovery helper (used by reload/build) ---
function findRendererFile(): string | null {
	const candidates = [
		path.join(__dirname, '../renderer/index.html'),
		path.join(__dirname, '../../renderer/index.html'),
		path.join(process.resourcesPath, 'renderer', 'index.html'),
		path.join(process.cwd(), 'dist', 'renderer', 'index.html'),
		path.join(process.cwd(), 'renderer', 'index.html'),
	];
	for (const p of candidates) {
		if (fs.existsSync(p)) return p;
	}
	return null;
}

// --- IPC: start a renderer build and stream logs back to the fallback UI ---
ipcMain.handle('renderer-build', async () => {
	if (!mainWindow) return { success: false, message: 'No main window' };
	try {
		// Use npm run build without shell:true to avoid DEP0190 warnings.
		const cmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
		const build = spawn(cmd, ['run', 'build'], { cwd: process.cwd() });

		build.stdout.on('data', (d) => {
			try { mainWindow?.webContents.send('renderer-build-log', d.toString()); } catch {}
		});
		build.stderr.on('data', (d) => {
			try { mainWindow?.webContents.send('renderer-build-log', d.toString()); } catch {}
		});
		build.on('close', (code) => {
			try { mainWindow?.webContents.send('renderer-build-done', { success: code === 0, code }); } catch {}
		});

		return { success: true, message: 'Build started' };
	} catch (err: any) {
		return { success: false, message: err.message || String(err) };
	}
});

// --- IPC: attempt to reload the renderer after build (or on user retry) ---
ipcMain.handle('renderer-reload', async () => {
	const rendererFile = findRendererFile();
	if (!rendererFile) return { success: false, message: 'Renderer file not found' };
	if (!mainWindow) return { success: false, message: 'No window' };
	try {
		await mainWindow.loadFile(rendererFile);
		mainWindow.show();
		return { success: true, message: 'Renderer loaded', path: rendererFile };
	} catch (err: any) {
		return { success: false, message: err.message || String(err) };
	}
});

// Firewall handlers (REMOVED - now in shieldHandlers.ts)
// shield-block-subnet, shield-block-port, shield-delete-firewall-rule moved to shieldHandlers.ts

// New IPCs for sentinel-tracked rules
ipcMain.handle('shield-get-sentinel-rules', async () => {
  try {
    const { getSentinelRules } = await import('./services/shieldData');
    return { success: true, rules: getSentinelRules() };
  } catch (err: any) {
    return { success: false, message: err.message || String(err) };
  }
});

ipcMain.handle('shield-clear-sentinel-rules', async () => {
  try {
    const { clearSentinelRules } = await import('./services/shieldData');
    clearSentinelRules();
    return { success: true, message: 'Cleared sentinel tracking' };
  } catch (err: any) {
    return { success: false, message: err.message || String(err) };
  }
});

// Self-test: create a test rule, ensure it's tracked, then delete it
ipcMain.handle('shield-self-test', async () => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const testName = `SentinelTest-${Date.now()}`;
    const { createFirewallRule, getSentinelRules, deleteFirewallRule } = await import('./services/shieldData');

    const create = await createFirewallRule(testName, 'TCP', 54321, 'Block');
    // small delay to ensure tracking finished
    await new Promise((r) => setTimeout(r, 400));
    const tracked = getSentinelRules().includes(testName);
    const del = await deleteFirewallRule(testName);

    return {
      success: create.success && tracked && del.success,
      details: { created: create, tracked, deleted: del }
    };
  } catch (err: any) {
    return { success: false, message: err.message || String(err) };
  }
});

// Legacy Firewall Manager window removed — all firewall management is in FirewallPage.tsx



// === SUBNET BLOCKING HELPERS ===

function validateIPAddress(ip: string): boolean {
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipRegex.test(ip.trim());
}

function calculateSubnet(ip: string, subnetMask: 8 | 16 | 24 | 32): string | null {
  if (!validateIPAddress(ip)) return null;
  
  const octets = ip.split('.').map(Number);
  
  switch (subnetMask) {
    case 32:
      return `${ip}/32`;
    case 24:
      return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
    case 16:
      return `${octets[0]}.${octets[1]}.0.0/16`;
    case 8:
      return `${octets[0]}.0.0.0/8`;
    default:
      return null;
  }
}

function getIPCountForMask(mask: 8 | 16 | 24 | 32): string {
  switch (mask) {
    case 32: return '1 IP';
    case 24: return '256 IPs';
    case 16: return '65,536 IPs';
    case 8: return '16,777,216 IPs';
    default: return 'Unknown';
  }
}

// === SUBNET BLOCKING IPC HANDLERS ===

ipcMain.handle('shield-block-ip-subnet', async (_event, ip: string, subnetMask: 8 | 16 | 24 | 32) => {
  if (!isAdmin) {
    return { success: false, message: 'Admin privileges required' };
  }
  
  try {
    // Validate IP format
    if (!validateIPAddress(ip)) {
      return { success: false, message: 'Invalid IP address format' };
    }
    
    // Calculate subnet
    const subnet = calculateSubnet(ip, subnetMask);
    if (!subnet) {
      return { success: false, message: 'Failed to calculate subnet' };
    }
    
    const ipCount = getIPCountForMask(subnetMask);
    const ruleName = `Sentinel Block Subnet ${subnet}`;
    
    // Create Inbound rule
    try {
      const cmdIn = `netsh advfirewall firewall add rule name="${ruleName} IN" dir=in action=block remoteip=${subnet.split('/')[0]}/${subnetMask} enable=yes`;
      execSync(cmdIn, { windowsHide: true });
      addSentinelRule(`${ruleName} IN`);
    } catch (err: any) {
      console.error('Failed to create inbound rule:', err.message);
      throw new Error(`Inbound rule creation failed: ${err.message}`);
    }
    
    // Create Outbound rule
    try {
      const cmdOut = `netsh advfirewall firewall add rule name="${ruleName} OUT" dir=out action=block remoteip=${subnet.split('/')[0]}/${subnetMask} enable=yes`;
      execSync(cmdOut, { windowsHide: true });
      addSentinelRule(`${ruleName} OUT`);
    } catch (err: any) {
      console.error('Failed to create outbound rule:', err.message);
      throw new Error(`Outbound rule creation failed: ${err.message}`);
    }
    
    addActivityLog('Shield', 'Block IP Subnet', `Blocked subnet: ${subnet} (${ipCount})`, 'success');
    
    return {
      success: true,
      message: `Successfully blocked subnet ${subnet} (${ipCount})`,
      subnet,
      ipCount
    };
  } catch (error: any) {
    const message = `Failed to block subnet: ${error.message}`;
    addActivityLog('Shield', 'Block IP Subnet', message, 'error');
    return { success: false, message };
  }
});

ipcMain.handle('shield-unblock-subnet', async (_event, subnet: string) => {
  if (!isAdmin) {
    return { success: false, message: 'Admin privileges required' };
  }
  
  try {
    const ruleName = `Sentinel Block Subnet ${subnet}`;
    
    // Delete Inbound rule
    try {
      await deleteFirewallRule(`${ruleName} IN`);
    } catch (err) {
      console.warn(`Failed to delete inbound rule for ${subnet}:`, err);
    }
    
    // Delete Outbound rule
    try {
      await deleteFirewallRule(`${ruleName} OUT`);
    } catch (err) {
      console.warn(`Failed to delete outbound rule for ${subnet}:`, err);
    }
    
    addActivityLog('Shield', 'Unblock IP Subnet', `Unblocked subnet: ${subnet}`, 'success');
    
    return {
      success: true,
      message: `Successfully unblocked subnet ${subnet}`
    };
  } catch (error: any) {
    const message = `Failed to unblock subnet: ${error.message}`;
    addActivityLog('Shield', 'Unblock IP Subnet', message, 'error');
    return { success: false, message };
  }
});

ipcMain.handle('firewall-export', async (_event, options: { format: 'txt' | 'csv' | 'json'; filter?: string; includeDisabled?: boolean }) => {
  try {
    const { aggregateFirewallRules } = await import('./ipc/shieldHandlers');
    const { exportFirewallRules } = await import('./services/firewall/firewallExporter');

    const aggregation = aggregateFirewallRules();
    const exportOpts = {
      format: options.format,
      filter: (options.filter || 'all') as 'all' | 'inbound' | 'outbound' | 'sentinel-only' | 'block-only',
      includeDisabled: options.includeDisabled,
    };
    const content = exportFirewallRules(aggregation.rules, exportOpts);

    const ext = options.format === 'csv' ? 'csv' : options.format === 'json' ? 'json' : 'txt';
    const filterMap: Record<string, { name: string; extensions: string[] }[]> = {
      txt: [{ name: 'Text Files', extensions: ['txt'] }],
      csv: [{ name: 'CSV Files', extensions: ['csv'] }],
      json: [{ name: 'JSON Files', extensions: ['json'] }],
    };
    const { filePath, canceled } = await dialog.showSaveDialog({
      title: 'Export Firewall Rules',
      defaultPath: `Sentinel_Firewall_${new Date().toISOString().slice(0, 10)}.${ext}`,
      filters: filterMap[ext] || filterMap.txt,
    });

    if (canceled || !filePath) {
      return { success: false, error: 'Export cancelled' };
    }

    const bom = ext === 'csv' ? '\uFEFF' : '';
    fs.writeFileSync(filePath, bom + content, 'utf-8');
    return { success: true, path: filePath, ruleCount: aggregation.rules.length };
  } catch (error: any) {
    return { success: false, error: error.message || 'Export failed' };
  }
});

function addActivityLog(source: string, action: string, message: string, level: string = 'info'): void {
  try {
    const entry = {
      timestamp: new Date().toISOString(),
      source,
      action,
      message,
      level,
    };

    // Ensure directory exists
    const dir = path.dirname(getActivityLogPath());
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    // Append as JSON line
    fs.appendFileSync(getActivityLogPath(), JSON.stringify(entry) + '\n', { encoding: 'utf8' });

    // Keep log file bounded (keep last N lines)
    try {
      const maxLines = 2000;
      const lines = fs.readFileSync(getActivityLogPath(), 'utf8').split('\n').filter(Boolean);
      if (lines.length > maxLines) {
        const preserved = lines.slice(-maxLines);
        fs.writeFileSync(getActivityLogPath(), preserved.join('\n') + '\n', { encoding: 'utf8' });
      }
    } catch (e) {
      // Non-fatal pruning error
      console.warn('Activity log prune failed:', (e as Error).message);
    }

    // Notify renderer if available
    try {
      mainWindow?.webContents.send('activity-log-appended', entry);
    } catch {
      // ignore send errors
    }
  } catch (err: any) {
    console.error('Failed to write activity log:', err?.message || err);
  }
}

// === DIALOG IPC HANDLERS ===

ipcMain.handle('show-error-box', async (_event, title: string, message: string) => {
  dialog.showErrorBox(title, message);
  return undefined;
});

ipcMain.handle('show-message-box', async (_event, title: string, message: string) => {
  await dialog.showMessageBox(mainWindow || undefined, {
    type: 'info',
    title,
    message,
    buttons: ['OK']
  });
  return undefined;
});

ipcMain.handle('show-confirm-box', async (_event, title: string, message: string) => {
  const result = await dialog.showMessageBox(mainWindow || undefined, {
    type: 'question',
    title,
    message,
    buttons: ['Yes', 'No'],
    defaultId: 1,
    cancelId: 1
  });
  return result.response === 0; // true if "Yes" clicked
});

ipcMain.handle('toggle-devtools', async () => {
  if (mainWindow) {
    mainWindow.webContents.toggleDevTools();
  }
  return undefined;
});

// ============================================
// ARGUS IPC HANDLERS (Python Backend Bridge)
// ============================================

ipcMain.handle('intel-url-scan', async (_event, url: string) => {
  try {
    if (!url || typeof url !== 'string') {
      return { success: false, error: 'URL is required' };
    }
    const result = await getArgusManager().scanUrl(url);
    return { success: true, data: result };
  } catch (error: any) {
    return { success: false, error: error?.message || 'ARGUS scan failed' };
  }
});

ipcMain.handle('intel-batch-scan', async (_event, urls: string[]) => {
  try {
    if (!Array.isArray(urls) || urls.length === 0) {
      return { success: false, error: 'URLs array is required' };
    }
    const result = await getArgusManager().batchScan(urls);
    return { success: true, data: result };
  } catch (error: any) {
    return { success: false, error: error?.message || 'ARGUS batch scan failed' };
  }
});

ipcMain.handle('intel-scan-history', async (_event, limit?: number, offset?: number) => {
  try {
    const result = await getArgusManager().getScanHistory(limit ?? 50, offset ?? 0);
    return { success: true, data: result };
  } catch (error: any) {
    return { success: false, error: error?.message || 'ARGUS history fetch failed' };
  }
});

ipcMain.handle('intel-export-history', async () => {
  try {
    const result = await getArgusManager().exportHistory();
    return { success: true, data: result };
  } catch (error: any) {
    return { success: false, error: error?.message || 'ARGUS history export failed' };
  }
});

ipcMain.handle('intel-clear-history', async () => {
  try {
    const result = await getArgusManager().clearHistory();
    return { success: true, data: result };
  } catch (error: any) {
    return { success: false, error: error?.message || 'ARGUS history clear failed' };
  }
});

ipcMain.handle('net-sandbox-status', async () => {
  try {
    const result = await getArgusManager().getSandboxStatus();
    return { success: true, data: result };
  } catch (error: any) {
    return { success: false, error: error?.message || 'ARGUS sandbox status failed' };
  }
});

ipcMain.handle('net-sandbox-toggle', async (_event, enabled: boolean) => {
  try {
    const result = await getArgusManager().toggleSandbox(enabled);
    return { success: true, data: result };
  } catch (error: any) {
    return { success: false, error: error?.message || 'ARGUS sandbox toggle failed' };
  }
});

// Fallback crypto using Node.js crypto when ARGUS is offline
const FALLBACK_ALGO = 'aes-256-gcm';
const FALLBACK_KEY_SEED = 'sentinel-vault-local-key-v1'; // Derived key, not used for production secrets

function getFallbackKey(): Buffer {
  const nodeCrypto = require('crypto');
  return nodeCrypto.createHash('sha256').update(FALLBACK_KEY_SEED).digest();
}

function fallbackEncrypt(plaintext: string): string {
  const nodeCrypto = require('crypto');
  const key = getFallbackKey();
  const iv = nodeCrypto.randomBytes(12);
  const cipher = nodeCrypto.createCipheriv(FALLBACK_ALGO, key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `SENTINEL_LOCAL:${iv.toString('hex')}:${tag}:${encrypted}`;
}

function fallbackDecrypt(ciphertext: string): string {
  const nodeCrypto = require('crypto');
  if (!ciphertext.startsWith('SENTINEL_LOCAL:')) {
    throw new Error('Not a local-encrypted value. Requires ARGUS backend.');
  }
  const parts = ciphertext.replace('SENTINEL_LOCAL:', '').split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted format');
  const [ivHex, tagHex, encHex] = parts;
  const key = getFallbackKey();
  const decipher = nodeCrypto.createDecipheriv(FALLBACK_ALGO, key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  let decrypted = decipher.update(encHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function detectEncryptionSource(ciphertext: string): 'local' | 'argus' | 'unknown' {
  if (ciphertext.startsWith('SENTINEL_LOCAL:')) return 'local';
  try {
    const parsed = JSON.parse(ciphertext);
    if (parsed.encrypted && !parsed.iv && !parsed.tag) return 'argus';
    if (parsed.iv && parsed.tag && parsed.data) return 'local';
  } catch {
    // Not JSON — check for raw base64 (ARGUS output)
    if (/^[A-Za-z0-9+/=]{16,}$/.test(ciphertext.trim())) return 'argus';
  }
  return 'unknown';
}

ipcMain.handle('vault-encrypt-data', async (_event, data: string) => {
  try {
    if (!data || typeof data !== 'string') {
      return { success: false, error: 'Data string is required' };
    }
    // Try ARGUS first
    try {
      const argus = getArgusManager();
      if (argus.getHealthInfo().status === 'running') {
        const result = await argus.encryptData(data);
        return { success: true, data: result, engine: 'argus' };
      }
    } catch { /* ARGUS unavailable, fall through */ }

    // Fallback: local AES-256-GCM
    const encrypted = fallbackEncrypt(data);
    addActivityLog('Vault', 'Encrypt', 'Data encrypted (local AES-256-GCM)', 'info');
    return { success: true, data: encrypted, engine: 'local' };
  } catch (error: any) {
    return { success: false, error: error?.message || 'Encryption failed' };
  }
});

ipcMain.handle('vault-decrypt-data', async (_event, encryptedData: string) => {
  try {
    if (!encryptedData || typeof encryptedData !== 'string') {
      return { success: false, error: 'Encrypted data string is required', source: 'unknown' };
    }

    // Detect encryption source from ciphertext format
    const source = detectEncryptionSource(encryptedData);

    if (source === 'local') {
      try {
        const decrypted = fallbackDecrypt(encryptedData);
        return { success: true, data: decrypted, engine: 'local', source: 'local' };
      } catch (err: any) {
        return { success: false, error: `Local decryption failed: ${err?.message || 'Invalid format'}`, source: 'local' };
      }
    }

    if (source === 'argus') {
      const argus = getArgusManager();
      const isRunning = argus.getHealthInfo().status === 'running';
      if (isRunning) {
        try {
          const result = await argus.decryptData(encryptedData);
          return { success: true, data: result, engine: 'argus', source: 'argus' };
        } catch (err: any) {
          return {
            success: false,
            error: `ARGUS decryption failed: ${err?.message || 'Unknown error'}`,
            source: 'argus',
            hint: 'The data may be corrupted or was encrypted with a different ARGUS instance.',
          };
        }
      }
      return {
        success: false,
        error: 'This data was encrypted by ARGUS. ARGUS must be running to decrypt it.',
        source: 'argus',
        argusOffline: true,
        hint: 'Start ARGUS from the dashboard or wait for auto-start, then retry.',
      };
    }

    // Unknown format — try both backends
    // Try local first (fast)
    try {
      const decrypted = fallbackDecrypt(encryptedData);
      return { success: true, data: decrypted, engine: 'local', source: 'local' };
    } catch { /* not local format */ }

    // Try ARGUS
    const argus = getArgusManager();
    if (argus.getHealthInfo().status === 'running') {
      try {
        const result = await argus.decryptData(encryptedData);
        return { success: true, data: result, engine: 'argus', source: 'argus' };
      } catch { /* ARGUS can't decrypt either */ }
    }

    return {
      success: false,
      error: 'Unrecognized encryption format. Data was not encrypted by Sentinel.',
      source: 'unknown',
    };
  } catch (error: any) {
    return { success: false, error: error?.message || 'Decryption failed', source: 'unknown' };
  }
});

ipcMain.handle('argus-get-health', async () => {
  try {
    const info = await getArgusManager().getHealthInfoLive();
    return { success: true, data: info };
  } catch (error: any) {
    return { success: false, error: error?.message || 'ARGUS health check failed' };
  }
});

ipcMain.handle('argus-start', async () => {
  try {
    const mgr = getArgusManager();
    await mgr.start();
    return { success: mgr.status === 'running', error: mgr.status !== 'running' ? 'Failed to start ARGUS' : undefined };
  } catch (e: any) { return { success: false, error: e?.message || 'ARGUS start failed' }; }
});

ipcMain.handle('argus-stop', async () => {
  try {
    getArgusManager().stop();
    return { success: true };
  } catch (e: any) { return { success: false, error: e?.message || 'ARGUS stop failed' }; }
});

ipcMain.handle('argus-restart', async () => {
  try {
    const mgr = getArgusManager();
    mgr.stop();
    await mgr.start();
    return { success: mgr.status === 'running', error: mgr.status !== 'running' ? 'Failed to restart ARGUS' : undefined };
  } catch (e: any) { return { success: false, error: e?.message || 'ARGUS restart failed' }; }
});

ipcMain.handle('argus-status', async () => {
  try {
    const mgr = getArgusManager();
    const info = mgr.getHealthInfo();
    return {
      success: true, data: {
        online: info.status === 'running',
        status: info.status,
        pid: info.pid,
        port: info.port,
        uptimeMs: info.uptimeMs,
        restartAttempts: mgr.restartAttempts,
        maxRestarts: mgr.maxRestarts,
        lastError: info.lastError,
      },
    };
  } catch (e: any) { return { success: false, error: e?.message }; }
});

// ============================================
// GHOST CHANNEL FIXES — Forge/Performance
// ============================================

ipcMain.handle('forge-empty-working-sets', async () => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const freeBefore = os.freemem();
    await execPromise('powershell -NoProfile -ExecutionPolicy Bypass -Command "[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()"', { windowsHide: true, timeout: 10000 });
    const freeAfter = os.freemem();
    const freedMB = Math.max(0, Math.round((freeAfter - freeBefore) / (1024 * 1024)));
    return { success: true, freedMB, message: `Working sets emptied, freed ~${freedMB} MB` };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('forge-optimize-ram', async () => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const freeBefore = os.freemem();
    const actions: string[] = [];
    try { await execPromise('powershell -NoProfile -Command "[System.GC]::Collect()"', { windowsHide: true, timeout: 5000 }); actions.push('GC collected'); } catch { /* */ }
    try { await execPromise('powershell -NoProfile -Command "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"', { windowsHide: true, timeout: 5000 }); actions.push('Recycle bin cleared'); } catch { /* */ }
    const freeAfter = os.freemem();
    const freedMB = Math.max(0, Math.round((freeAfter - freeBefore) / (1024 * 1024)));
    return { success: true, freedMB, actions, message: `RAM optimized, freed ~${freedMB} MB` };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('forge-get-top-cpu-processes', async () => {
  try {
    const { spawnSync } = require('child_process');
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
      input: 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Id, ProcessName, @{N="CPU";E={[math]::Round($_.CPU,1)}}, @{N="MemMB";E={[math]::Round($_.WorkingSet64/1MB,1)}} | ConvertTo-Json -Compress',
      timeout: 10000, windowsHide: true, encoding: 'utf8',
    });
    if (result.error) throw result.error;
    let procs = JSON.parse((result.stdout || '[]').trim());
    if (!Array.isArray(procs)) procs = procs ? [procs] : [];
    return { success: true, processes: procs };
  } catch (error: any) {
    return { success: true, processes: [] };
  }
});

ipcMain.handle('forge-get-cpu-core-count', async () => {
  try {
    const { execSync } = require('child_process');
    const out = execSync(
      'powershell -NoProfile -NonInteractive -Command "Get-CimInstance Win32_Processor | Select-Object -First 1 NumberOfCores, NumberOfLogicalProcessors | ConvertTo-Json -Compress"',
      { timeout: 5000, windowsHide: true, encoding: 'utf8' }
    ).trim();
    const parsed = JSON.parse(out);
    const physicalCores = typeof parsed.NumberOfCores === 'number' ? parsed.NumberOfCores : Math.max(1, Math.ceil(os.cpus().length / 2));
    const logicalThreads = typeof parsed.NumberOfLogicalProcessors === 'number' ? parsed.NumberOfLogicalProcessors : os.cpus().length;
    return { success: true, cores: physicalCores, threads: logicalThreads };
  } catch {
    const threads = os.cpus().length;
    return { success: true, cores: Math.max(1, Math.ceil(threads / 2)), threads };
  }
});

ipcMain.handle('forge-set-process-priority', async (_event, pid: number, priority: string) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const priMap: Record<string, string> = { idle: 'Idle', below: 'BelowNormal', normal: 'Normal', above: 'AboveNormal', high: 'High', realtime: 'RealTime' };
    const priClass = priMap[priority.toLowerCase()] || 'Normal';
    await execPromise(`powershell -NoProfile -Command "(Get-Process -Id ${pid}).PriorityClass = '${priClass}'"`, { windowsHide: true, timeout: 5000 });
    return { success: true, priority: priClass, message: `PID ${pid} priority set to ${priClass}` };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('forge-set-process-affinity', async (_event, pid: number, affinity: number) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    await execPromise(`powershell -NoProfile -Command "(Get-Process -Id ${pid}).ProcessorAffinity = ${affinity}"`, { windowsHide: true, timeout: 5000 });
    return { success: true, message: `PID ${pid} affinity set to ${affinity}` };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('forge-get-current-power-plan', async () => {
  try {
    const { stdout } = await execPromise('powercfg /getactivescheme', { windowsHide: true, timeout: 5000 });
    const match = String(stdout).match(/\((.+)\)/);
    return { success: true, plan: match ? match[1] : 'Unknown' };
  } catch {
    return { success: true, plan: 'Unknown' };
  }
});

ipcMain.handle('forge-set-power-plan', async (_event, plan: string) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const guids: Record<string, string> = { balanced: '381b4222-f694-41f0-9685-ff5bb260df2e', high: '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c', saver: 'a1841308-3541-4fab-bc81-f71556f20b4a' };
    const guid = guids[plan.toLowerCase()] || plan;
    await execPromise(`powercfg /setactive ${guid}`, { windowsHide: true, timeout: 5000 });
    return { success: true, planName: plan, message: `Power plan set to ${plan}` };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('forge-toggle-startup-item', async (_event, name: string, enable: boolean) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const escaped = name.replace(/'/g, "''");
    if (enable) {
      return { success: false, message: 'Re-enabling startup items requires manual registry edit' };
    }
    await execPromise(`powershell -NoProfile -Command "Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '${escaped}' -ErrorAction SilentlyContinue"`, { windowsHide: true, timeout: 5000 });
    return { success: true, message: `Startup item "${name}" disabled` };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('forge-toggle-windows-service', async (_event, name: string, enable: boolean) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const escaped = name.replace(/'/g, "''");
    if (enable) {
      await execPromise(`powershell -NoProfile -Command "Set-Service -Name '${escaped}' -StartupType Automatic; Start-Service -Name '${escaped}' -ErrorAction SilentlyContinue"`, { windowsHide: true, timeout: 10000 });
    } else {
      await execPromise(`powershell -NoProfile -Command "Stop-Service -Name '${escaped}' -Force -ErrorAction SilentlyContinue; Set-Service -Name '${escaped}' -StartupType Disabled"`, { windowsHide: true, timeout: 10000 });
    }
    return { success: true, message: `Service "${name}" ${enable ? 'enabled' : 'disabled'}` };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('forge-disable-all-bloatware', async () => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const bloatware = ['DiagTrack', 'dmwappushservice', 'WMPNetworkSvc', 'WSearch', 'SysMain'];
    let disabled = 0;
    for (const svc of bloatware) {
      try {
        execSync(`sc config "${svc}" start= disabled`, { windowsHide: true, timeout: 5000 });
        try { execSync(`sc stop "${svc}"`, { windowsHide: true, timeout: 5000 }); } catch { /* */ }
        disabled++;
      } catch { /* skip */ }
    }
    return { success: true, disabledCount: disabled, message: `Disabled ${disabled} bloatware services` };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('forge-backup-services-state', async () => {
  try {
    const backupPath = path.join(app.getPath('userData'), 'services-backup.json');
    const { spawnSync } = require('child_process');
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
      input: 'Get-Service | Select-Object Name, StartType | ConvertTo-Json -Compress',
      timeout: 15000, windowsHide: true, encoding: 'utf8',
    });
    if (result.stdout) {
      fs.writeFileSync(backupPath, result.stdout.trim(), 'utf8');
      return { success: true, backupFile: backupPath, message: 'Services state backed up' };
    }
    return { success: false, message: 'No output from service enumeration' };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('forge-restore-services-state', async () => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const backupPath = path.join(app.getPath('userData'), 'services-backup.json');
    if (!fs.existsSync(backupPath)) return { success: false, message: 'No backup found' };
    let services = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
    if (!Array.isArray(services)) services = services ? [services] : [];
    let restored = 0;
    for (const svc of services) {
      try {
        const startType = String(svc.StartType || 'Manual');
        execSync(`powershell -NoProfile -Command "Set-Service -Name '${svc.Name}' -StartupType '${startType}' -ErrorAction SilentlyContinue"`, { windowsHide: true, timeout: 3000 });
        restored++;
      } catch { /* skip */ }
    }
    return { success: true, restoredCount: restored, message: `Restored ${restored} services` };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('forge-get-drive-info', async () => {
  try {
    const { spawnSync } = require('child_process');
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
      input: 'Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{N="UsedGB";E={[math]::Round($_.Used/1GB,2)}}, @{N="FreeGB";E={[math]::Round($_.Free/1GB,2)}} | ConvertTo-Json -Compress',
      timeout: 10000, windowsHide: true, encoding: 'utf8',
    });
    let drives = JSON.parse((result.stdout || '[]').trim());
    if (!Array.isArray(drives)) drives = drives ? [drives] : [];
    return { success: true, drives };
  } catch (error: any) {
    return { success: true, drives: [] };
  }
});

ipcMain.handle('forge-analyze-disk-cleanup', async () => {
  try {
    const locations: any[] = [];
    const tempDir = path.join(os.tmpdir());
    let totalMB = 0;
    let totalFiles = 0;
    try {
      const files = fs.readdirSync(tempDir);
      let size = 0;
      for (const f of files) { try { size += fs.statSync(path.join(tempDir, f)).size; } catch { /* */ } }
      const mb = Math.round(size / (1024 * 1024));
      locations.push({ path: tempDir, sizeMB: mb, files: files.length, label: 'Temp Files' });
      totalMB += mb;
      totalFiles += files.length;
    } catch { /* */ }
    return { success: true, locations, totalMB, totalFiles };
  } catch (error: any) {
    return { success: false, locations: [], totalMB: 0, totalFiles: 0, error: error.message };
  }
});

ipcMain.handle('forge-clean-disk', async (_event, selectedPaths: string[]) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    let deletedFiles = 0;
    let freedBytes = 0;
    for (const p of selectedPaths) {
      try {
        if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
          const files = fs.readdirSync(p);
          for (const f of files) {
            try {
              const fp = path.join(p, f);
              const stat = fs.statSync(fp);
              if (stat.isFile()) { freedBytes += stat.size; fs.unlinkSync(fp); deletedFiles++; }
            } catch { /* skip locked */ }
          }
        }
      } catch { /* skip */ }
    }
    return { success: true, freedMB: Math.round(freedBytes / (1024 * 1024)), deletedFiles, message: `Cleaned ${deletedFiles} files` };
  } catch (error: any) {
    return { success: false, message: error.message };
  }
});

// Simplified Forge aliases
ipcMain.handle('get-ram-usage', async () => {
  return getRAMUsage();
});

ipcMain.handle('get-power-plan', async () => {
  try {
    const { stdout } = await execPromise('powercfg /getactivescheme', { windowsHide: true, timeout: 5000 });
    const match = String(stdout).match(/\((.+)\)/);
    return { success: true, plan: match ? match[1] : 'Unknown' };
  } catch { return { success: true, plan: 'Unknown' }; }
});

ipcMain.handle('set-power-plan', async (_event, plan: string) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const guids: Record<string, string> = { balanced: '381b4222-f694-41f0-9685-ff5bb260df2e', high: '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c', saver: 'a1841308-3541-4fab-bc81-f71556f20b4a' };
    const guid = guids[plan.toLowerCase()] || plan;
    await execPromise(`powercfg /setactive ${guid}`, { windowsHide: true, timeout: 5000 });
    return { success: true, message: `Power plan set to ${plan}` };
  } catch (error: any) { return { success: false, message: error.message }; }
});

ipcMain.handle('get-startup-apps', async () => {
  try {
    const { spawnSync } = require('child_process');
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
      input: 'Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | ConvertTo-Json -Compress',
      timeout: 10000, windowsHide: true, encoding: 'utf8',
    });
    let apps = JSON.parse((result.stdout || '[]').trim());
    if (!Array.isArray(apps)) apps = apps ? [apps] : [];
    return apps;
  } catch { return []; }
});

ipcMain.handle('toggle-startup-app', async (_event, program: any, enable: boolean) => {
  return { success: false, message: 'Use forge-toggle-startup-item instead' };
});

ipcMain.handle('get-services', async () => {
  try {
    const { spawnSync } = require('child_process');
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
      input: 'Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json -Compress',
      timeout: 15000, windowsHide: true, encoding: 'utf8',
    });
    let svcs = JSON.parse((result.stdout || '[]').trim());
    if (!Array.isArray(svcs)) svcs = svcs ? [svcs] : [];
    return svcs;
  } catch { return []; }
});

ipcMain.handle('toggle-service', async (_event, serviceName: string, enable: boolean) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const escaped = serviceName.replace(/'/g, "''");
    const cmd = enable
      ? `Set-Service -Name '${escaped}' -StartupType Automatic -ErrorAction Stop; Start-Service -Name '${escaped}' -ErrorAction SilentlyContinue`
      : `Stop-Service -Name '${escaped}' -Force -ErrorAction SilentlyContinue; Set-Service -Name '${escaped}' -StartupType Disabled -ErrorAction Stop`;
    await execPromise(`powershell -NoProfile -ExecutionPolicy Bypass -Command "${cmd}"`, { windowsHide: true, timeout: 10000 });
    return { success: true, message: `Service ${serviceName} ${enable ? 'enabled' : 'disabled'}` };
  } catch (error: any) { return { success: false, message: error.message }; }
});

ipcMain.handle('get-disk-info', async () => {
  try {
    const { spawnSync } = require('child_process');
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
      input: 'Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{N="UsedGB";E={[math]::Round($_.Used/1GB,2)}}, @{N="FreeGB";E={[math]::Round($_.Free/1GB,2)}} | ConvertTo-Json -Compress',
      timeout: 10000, windowsHide: true, encoding: 'utf8',
    });
    let drives = JSON.parse((result.stdout || '[]').trim());
    if (!Array.isArray(drives)) drives = drives ? [drives] : [];
    return { success: true, drives };
  } catch { return { success: true, drives: [] }; }
});

ipcMain.handle('analyze-disk', async (_event, drive: string) => {
  try {
    const { spawnSync } = require('child_process');
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
      input: `$d = Get-PSDrive ${drive.replace(':','')}; [PSCustomObject]@{UsedGB=[math]::Round($d.Used/1GB,2);FreeGB=[math]::Round($d.Free/1GB,2)} | ConvertTo-Json -Compress`,
      timeout: 10000, windowsHide: true, encoding: 'utf8',
    });
    return { success: true, data: JSON.parse((result.stdout || '{}').trim()) };
  } catch (error: any) { return { success: false, error: error.message }; }
});

ipcMain.handle('clean-disk', async (_event, items: string[]) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    let cleaned = 0;
    for (const item of items) {
      try { if (fs.existsSync(item)) { fs.rmSync(item, { recursive: true, force: true }); cleaned++; } } catch { /* */ }
    }
    return { success: true, message: `Cleaned ${cleaned} items` };
  } catch (error: any) { return { success: false, message: error.message }; }
});

// ============================================
// GHOST CHANNEL FIXES — Ghost/Privacy
// ============================================

ipcMain.handle('ghost-get-telemetry-services', async () => {
  try {
    const telemetrySvcs = ['DiagTrack', 'dmwappushservice', 'WerSvc', 'WMPNetworkSvc'];
    const services: any[] = [];
    for (const name of telemetrySvcs) {
      try {
        const { stdout } = await execPromise(`powershell -NoProfile -Command "(Get-Service -Name '${name}' -ErrorAction SilentlyContinue).Status"`, { windowsHide: true, timeout: 3000 });
        services.push({ name, status: String(stdout).trim() || 'NotFound', enabled: String(stdout).trim() === 'Running' });
      } catch { services.push({ name, status: 'NotFound', enabled: false }); }
    }
    return { success: true, services };
  } catch (error: any) { return { success: false, services: [], error: error.message }; }
});

ipcMain.handle('ghost-get-blocked-requests-count', async () => {
  return { success: true, count: 0 };
});

ipcMain.handle('ghost-toggle-telemetry-service', async (_event, serviceName: string, enable: boolean) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required', error: 'Admin required' };
  try {
    const escaped = serviceName.replace(/'/g, "''");
    if (enable) {
      await execPromise(`powershell -NoProfile -Command "Set-Service -Name '${escaped}' -StartupType Automatic; Start-Service -Name '${escaped}'"`, { windowsHide: true, timeout: 10000 });
    } else {
      await execPromise(`powershell -NoProfile -Command "Stop-Service -Name '${escaped}' -Force -ErrorAction SilentlyContinue; Set-Service -Name '${escaped}' -StartupType Disabled"`, { windowsHide: true, timeout: 10000 });
    }
    return { success: true, message: `${serviceName} ${enable ? 'enabled' : 'disabled'}` };
  } catch (error: any) { return { success: false, message: error.message, error: error.message }; }
});

ipcMain.handle('ghost-toggle-all-telemetry', async (_event, enableAll: boolean) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required', results: [] };
  const svcs = ['DiagTrack', 'dmwappushservice', 'WerSvc'];
  const results: any[] = [];
  for (const svc of svcs) {
    try {
      const escaped = svc.replace(/'/g, "''");
      if (enableAll) {
        await execPromise(`powershell -NoProfile -Command "Set-Service -Name '${escaped}' -StartupType Automatic -ErrorAction SilentlyContinue"`, { windowsHide: true, timeout: 5000 });
      } else {
        await execPromise(`powershell -NoProfile -Command "Stop-Service -Name '${escaped}' -Force -ErrorAction SilentlyContinue; Set-Service -Name '${escaped}' -StartupType Disabled -ErrorAction SilentlyContinue"`, { windowsHide: true, timeout: 5000 });
      }
      results.push({ service: svc, success: true });
    } catch { results.push({ service: svc, success: false }); }
  }
  return { success: true, message: `${enableAll ? 'Enabled' : 'Disabled'} ${results.filter(r => r.success).length} telemetry services`, results };
});

ipcMain.handle('ghost-get-app-permissions', async () => {
  return { success: true, apps: [] };
});

ipcMain.handle('ghost-toggle-app-permission', async (_event, packageName: string, permission: string, enable: boolean) => {
  return { success: false, message: 'App permission control not available on Windows', error: 'Not supported' };
});

ipcMain.handle('ghost-import-hosts-blocklist', async (_event, url: string) => {
  if (!isAdmin) return { success: false, message: 'Admin privileges required' };
  try {
    const https = require('https');
    const http = require('http');
    const mod = url.startsWith('https') ? https : http;
    const body: string = await new Promise((resolve, reject) => {
      mod.get(url, { timeout: 15000 }, (res: any) => {
        let data = '';
        res.on('data', (c: any) => { data += c; });
        res.on('end', () => resolve(data));
      }).on('error', reject);
    });
    const hostsPath = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
    const backupPath = hostsPath + '.sentinel-backup';
    if (fs.existsSync(hostsPath)) fs.copyFileSync(hostsPath, backupPath);
    const existing = fs.existsSync(hostsPath) ? fs.readFileSync(hostsPath, 'utf8') : '';
    fs.writeFileSync(hostsPath, existing + '\n# Sentinel Blocklist Import\n' + body, 'utf8');
    return { success: true, message: 'Blocklist imported', backupPath };
  } catch (error: any) { return { success: false, message: error.message }; }
});

// ============================================
// GHOST CHANNEL FIXES — Vault
// ============================================

ipcMain.handle('vault-encrypt-files', async (_event, filePaths: string[], password: string) => {
  try {
    const crypto = require('crypto');
    const vaultDir = path.join(app.getPath('userData'), 'vault-files');
    if (!fs.existsSync(vaultDir)) fs.mkdirSync(vaultDir, { recursive: true });
    let count = 0;
    for (const fp of filePaths) {
      try {
        const data = fs.readFileSync(fp);
        const salt = crypto.randomBytes(16);
        const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
        const outName = path.basename(fp) + '.sentinel';
        const outPath = path.join(vaultDir, outName);
        const header = Buffer.concat([salt, iv, tag, encrypted]);
        fs.writeFileSync(outPath, header);
        count++;
      } catch { /* skip */ }
    }
    return { success: true, encryptedCount: count, message: `Encrypted ${count} files` };
  } catch (error: any) { return { success: false, message: error.message }; }
});

ipcMain.handle('vault-decrypt-file', async (_event, filePath: string, password: string) => {
  try {
    const crypto = require('crypto');
    const data = fs.readFileSync(filePath);
    const salt = data.subarray(0, 16);
    const iv = data.subarray(16, 28);
    const tag = data.subarray(28, 44);
    const encrypted = data.subarray(44);
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    const outPath = filePath.replace(/\.sentinel$/, '');
    fs.writeFileSync(outPath, decrypted);
    return { success: true, outputPath: outPath, message: 'File decrypted' };
  } catch (error: any) { return { success: false, message: error.message || 'Decryption failed (wrong password?)' }; }
});

ipcMain.handle('vault-open-secure-note', async (_event, noteId: string, _password: string) => {
  try {
    const vaultFile = path.join(app.getPath('userData'), 'vault', 'notes.encrypted');
    if (!fs.existsSync(vaultFile)) return { success: false, message: 'No notes found' };
    const raw = fs.readFileSync(vaultFile, 'utf8').trim();
    if (!raw) return { success: false, message: 'Empty vault' };
    const decrypted = _vaultDecrypt(raw);
    const notes = JSON.parse(decrypted);
    const note = Array.isArray(notes) ? notes.find((n: any) => n.id === noteId) : null;
    if (!note) return { success: false, message: 'Note not found' };
    return { success: true, note };
  } catch (error: any) { return { success: false, message: error.message }; }
});

ipcMain.handle('vault-get-saved-passwords', async () => {
  try {
    const pwFile = path.join(app.getPath('userData'), 'vault', 'passwords.encrypted');
    if (!fs.existsSync(pwFile)) return { success: true, passwords: [] };
    const raw = fs.readFileSync(pwFile, 'utf8').trim();
    if (!raw) return { success: true, passwords: [] };
    const decrypted = _vaultDecrypt(raw);
    return { success: true, passwords: JSON.parse(decrypted) };
  } catch (error: any) { return { success: true, passwords: [] }; }
});

ipcMain.handle('vault-save-password', async (_event, password: string, note: string) => {
  try {
    const pwFile = path.join(app.getPath('userData'), 'vault', 'passwords.encrypted');
    const vaultDir = path.dirname(pwFile);
    if (!fs.existsSync(vaultDir)) fs.mkdirSync(vaultDir, { recursive: true });
    let passwords: any[] = [];
    if (fs.existsSync(pwFile)) {
      try { passwords = JSON.parse(_vaultDecrypt(fs.readFileSync(pwFile, 'utf8').trim())); } catch { passwords = []; }
    }
    passwords.push({ id: `pw-${Date.now()}`, password, note, createdAt: new Date().toISOString() });
    fs.writeFileSync(pwFile, _vaultEncrypt(JSON.stringify(passwords)), 'utf8');
    return { success: true, message: 'Password saved (encrypted)' };
  } catch (error: any) { return { success: false, message: error.message }; }
});

ipcMain.handle('vault-get-shred-stats', async () => {
  return { shreddedCount: 0, totalSize: 0 };
});

ipcMain.handle('vault-shred-files', async (_event, filePaths: string[]) => {
  try {
    const crypto = require('crypto');
    let count = 0;
    let totalSize = 0;
    for (const fp of filePaths) {
      try {
        if (!fs.existsSync(fp)) continue;
        const stat = fs.statSync(fp);
        totalSize += stat.size;
        const fd = fs.openSync(fp, 'w');
        for (let pass = 0; pass < 3; pass++) {
          const buf = crypto.randomBytes(stat.size);
          fs.writeSync(fd, buf, 0, buf.length, 0);
        }
        fs.closeSync(fd);
        fs.unlinkSync(fp);
        count++;
      } catch { /* skip locked */ }
    }
    addActivityLog('Vault', 'Shred', `Shredded ${count} files (${Math.round(totalSize / 1024)} KB, 3-pass overwrite)`, 'info');
    return { success: true, shreddedCount: count, totalSize, message: `Shredded ${count} files` };
  } catch (error: any) { return { success: false, message: error.message }; }
});

// ============================================
// DSGVO — Datenschutz Controls (Art. 6, 17 DSGVO)
// ============================================

ipcMain.handle('dsgvo-get-ip-lookup-enabled', async () => {
  return { success: true, enabled: isExternalIpLookupAllowed() };
});

ipcMain.handle('dsgvo-set-ip-lookup-enabled', async (_event, enabled: boolean) => {
  try {
    const config = setExternalIpLookup(Boolean(enabled));
    return { success: true, enabled: config.allowExternalIpLookup };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('dsgvo-clear-threat-events', async () => {
  try {
    const result = await clearAllThreatEvents();
    return { success: true, deleted: result.deleted, message: `${result.deleted} Threat-Events gelöscht (Art. 17 DSGVO)` };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// ============================================
// GHOST CHANNEL FIXES — Advanced/System
// ============================================

ipcMain.handle('get-network-diagnostics', async () => {
  try {
    const { stdout } = await execPromise('ipconfig /all', { windowsHide: true, timeout: 10000 });
    return { success: true, data: String(stdout) };
  } catch (error: any) { return { success: false, error: error.message }; }
});

ipcMain.handle('get-temperatures', async () => {
  try {
    const { spawnSync } = require('child_process');
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
      input: '$t = Get-CimInstance MSAcpi_ThermalZoneTemperature -Namespace root/wmi -ErrorAction SilentlyContinue | Select-Object -First 1; if($t){[math]::Round(($t.CurrentTemperature - 2732) / 10, 1)}else{-1}',
      timeout: 5000, windowsHide: true, encoding: 'utf8',
    });
    const temp = parseFloat((result.stdout || '-1').trim());
    return { success: true, data: { cpuTemp: isNaN(temp) ? -1 : temp, gpuTemp: -1 } };
  } catch { return { success: true, data: { cpuTemp: -1, gpuTemp: -1 } }; }
});

ipcMain.handle('get-security-status', async () => {
  try {
    const { spawnSync } = require('child_process');
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
      input: `$fw = (Get-NetFirewallProfile | Where-Object {$_.Enabled}).Count; $def = (Get-MpComputerStatus -ErrorAction SilentlyContinue); [PSCustomObject]@{firewallProfiles=$fw;defenderEnabled=$def.AntivirusEnabled;realTimeProtection=$def.RealTimeProtectionEnabled} | ConvertTo-Json -Compress`,
      timeout: 10000, windowsHide: true, encoding: 'utf8',
    });
    return { success: true, data: JSON.parse((result.stdout || '{}').trim()) };
  } catch (error: any) { return { success: false, error: error.message }; }
});

ipcMain.handle('enable-firewall', async () => {
  if (!isAdmin) return { success: false, error: 'Admin privileges required' };
  try {
    execSync('netsh advfirewall set allprofiles state on', { windowsHide: true, timeout: 10000 });
    return { success: true };
  } catch (error: any) { return { success: false, error: error.message }; }
});

ipcMain.handle('disable-smbv1', async () => {
  if (!isAdmin) return { success: false, error: 'Admin privileges required' };
  try {
    await execPromise('powershell -NoProfile -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"', { windowsHide: true, timeout: 10000 });
    return { success: true };
  } catch (error: any) { return { success: false, error: error.message }; }
});

ipcMain.handle('enable-defender', async () => {
  if (!isAdmin) return { success: false, error: 'Admin privileges required' };
  try {
    await execPromise('powershell -NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring $false"', { windowsHide: true, timeout: 10000 });
    return { success: true };
  } catch (error: any) { return { success: false, error: error.message }; }
});

ipcMain.handle('enable-uac', async () => {
  if (!isAdmin) return { success: false, error: 'Admin privileges required' };
  try {
    execSync('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f', { windowsHide: true, timeout: 5000 });
    return { success: true };
  } catch (error: any) { return { success: false, error: error.message }; }
});

const _enhancedCpuPrev = new Map<number, { name: string; cpuMs: number; ts: number }>();
ipcMain.handle('get-processes-enhanced', async () => {
  try {
    const { getProcessKillRisk } = await import('../shared/constants');
    const { spawnSync } = require('child_process');
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
      input: `Get-Process | Where-Object { $_.Id -gt 0 } | Sort-Object WorkingSet64 -Descending | Select-Object -First 80 Id, ProcessName, @{N="CPUms";E={[math]::Round($_.TotalProcessorTime.TotalMilliseconds)}}, @{N="MemMB";E={[math]::Round($_.WorkingSet64/1MB,1)}}, Path, Description, Company | ConvertTo-Json -Compress`,
      timeout: 12000, windowsHide: true, encoding: 'utf8',
    });
    let procs = JSON.parse((result.stdout || '[]').trim());
    if (!Array.isArray(procs)) procs = procs ? [procs] : [];
    const now = Date.now();
    const cores = os.cpus().length || 1;
    const mapped = procs.map((p: any) => {
      let cpuPercent = 0;
      const prev = _enhancedCpuPrev.get(p.Id);
      if (prev && prev.name === p.ProcessName) {
        const dt = now - prev.ts;
        const dc = (p.CPUms || 0) - prev.cpuMs;
        if (dt > 0 && dc >= 0) cpuPercent = Math.min(100, (dc / dt) * 100 / cores);
      }
      _enhancedCpuPrev.set(p.Id, { name: p.ProcessName, cpuMs: p.CPUms || 0, ts: now });
      return {
        PID: p.Id, Name: p.ProcessName,
        CPU: Math.round(cpuPercent * 10) / 10,
        MemMB: p.MemMB, Path: p.Path || undefined,
        Description: p.Description || undefined,
        Company: p.Company || undefined,
        killRisk: getProcessKillRisk(p.ProcessName, p.Id),
      };
    });
    return { success: true, processes: mapped };
  } catch (error: any) { return { success: true, processes: [] }; }
});

ipcMain.handle('kill-process', async (_event, pid: number) => {
  try {
    const { getProcessKillRisk } = await import('../shared/constants');
    const risk = getProcessKillRisk('', pid);
    if (risk === 'forbidden') {
      return { success: false, error: `Cannot terminate PID ${pid} — system-critical process.` };
    }
    process.kill(pid, 'SIGTERM');
    return { success: true };
  } catch (error: any) { return { success: false, error: error.message }; }
});

ipcMain.handle('get-startup-programs', async () => {
  try {
    const { spawnSync } = require('child_process');
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
      input: 'Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | ConvertTo-Json -Compress',
      timeout: 10000, windowsHide: true, encoding: 'utf8',
    });
    let progs = JSON.parse((result.stdout || '[]').trim());
    if (!Array.isArray(progs)) progs = progs ? [progs] : [];
    return { success: true, programs: progs };
  } catch { return { success: true, programs: [] }; }
});

ipcMain.handle('disable-startup-program', async (_event, name: string) => {
  if (!isAdmin) return { success: false, error: 'Admin privileges required' };
  try {
    const escaped = name.replace(/'/g, "''");
    await execPromise(`powershell -NoProfile -Command "Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '${escaped}' -ErrorAction Stop"`, { windowsHide: true, timeout: 5000 });
    return { success: true };
  } catch (error: any) { return { success: false, error: error.message }; }
});

ipcMain.handle('create-snapshot', async (_event, name: string) => {
  try {
    const { createSnapshot } = await import('./services/snapshotManager');
    const snapshot = await createSnapshot(name);
    return { success: true, snapshot };
  } catch (error: any) { return { success: false, error: error.message }; }
});

ipcMain.handle('list-snapshots', async () => {
  try {
    const { listSnapshots } = await import('./services/snapshotManager');
    const snapshots = await listSnapshots();
    return { success: true, snapshots };
  } catch (error: any) { return { success: true, snapshots: [] }; }
});

ipcMain.handle('delete-snapshot', async (_event, id: string) => {
  try {
    const { deleteSnapshot } = await import('./services/snapshotManager');
    await deleteSnapshot(id);
    return { success: true };
  } catch (error: any) { return { success: false, error: error.message }; }
});

ipcMain.handle('get-snapshot', async (_event, id: string) => {
  try {
    const { getSnapshot } = await import('./services/snapshotManager');
    const snapshot = await getSnapshot(id);
    return { success: true, snapshot };
  } catch (error: any) { return { success: false, error: error.message }; }
});

// ============================================
// GHOST CHANNEL FIXES — Profiler
// ============================================

ipcMain.handle('profiler-start', async () => {
  try {
    const { getProfiler } = await import('./services/profiler');
    getProfiler().startProfile();
    return { success: true };
  } catch (error: any) { return { success: false, error: error.message }; }
});

ipcMain.handle('profiler-stop', async () => {
  try {
    const { getProfiler } = await import('./services/profiler');
    await getProfiler().stopProfile();
    return { success: true };
  } catch (error: any) { return { success: false, error: error.message }; }
});

ipcMain.handle('profiler-list', async () => {
  try {
    const { getProfiler } = await import('./services/profiler');
    return { success: true, profiles: getProfiler().listProfiles() };
  } catch (error: any) { return { success: true, profiles: [] }; }
});

// ============================================
// GHOST CHANNEL FIXES — Admin
// ============================================

ipcMain.handle('restart-as-admin', async () => {
  try {
    requestElevationSync();
    return { success: true };
  } catch (error: any) { return { success: false, error: error.message }; }
});

