/**
 * SENTINEL UNIFIED — Vault & Config Cluster IPC Handlers
 * Encryption, secure notes, settings, activity log, ARGUS health, config.
 */

import { ipcMain, app, dialog, BrowserWindow } from 'electron';
import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';
import { IPC } from '../../shared/constants';
import { serializeError } from '../../shared/utils';
import { getSentinelConfig, updateAutonomousMode, addWhitelistEntry, removeWhitelistEntry, setWhitelist } from '../services/sentinelConfig';
import { getArgusManager } from '../services/argusManager';

let mainWindow: BrowserWindow | null = null;

export function setVaultContext(opts: { mainWindow: BrowserWindow | null }): void {
  mainWindow = opts.mainWindow;
}

// ─── Settings persistence ───
let _settingsPath: string | null = null;
function getSettingsPath(): string {
  if (!_settingsPath) _settingsPath = path.join(app.getPath('userData'), 'settings.json');
  return _settingsPath;
}

// ─── Activity Log persistence ───
let _activityLogPath: string | null = null;
function getActivityLogPath(): string {
  if (!_activityLogPath) _activityLogPath = path.join(app.getPath('userData'), 'activity.log');
  return _activityLogPath;
}

export function registerVaultHandlers(): void {
  // ─── Secure Notes (disk-backed) ───
  ipcMain.handle(IPC.VAULT.GET_SECURE_NOTES, async () => {
    try {
      const notesPath = path.join(app.getPath('userData'), 'vault-notes.json');
      if (fs.existsSync(notesPath)) {
        const raw = fs.readFileSync(notesPath, 'utf8');
        const notes = JSON.parse(raw);
        return { success: true, notes: Array.isArray(notes) ? notes : [] };
      }
      return { success: true, notes: [] };
    } catch (err) {
      return { success: false, notes: [], error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.VAULT.SAVE_SECURE_NOTE, async (_event, noteData: unknown) => {
    try {
      const notesPath = path.join(app.getPath('userData'), 'vault-notes.json');
      let notes: any[] = [];
      if (fs.existsSync(notesPath)) {
        try { notes = JSON.parse(fs.readFileSync(notesPath, 'utf8')); } catch { notes = []; }
      }
      const id = `note-${Date.now()}`;
      notes.push({ id, ...(noteData as Record<string, unknown>), createdAt: new Date().toISOString() });
      fs.writeFileSync(notesPath, JSON.stringify(notes, null, 2), 'utf8');
      return { success: true, id };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Encrypted Files (real directory listing) ───
  ipcMain.handle(IPC.VAULT.GET_ENCRYPTED_FILES, async () => {
    try {
      const vaultDir = path.join(app.getPath('userData'), 'vault-files');
      if (!fs.existsSync(vaultDir)) return { success: true, files: [] };
      const files = fs.readdirSync(vaultDir).map((f) => {
        const fullPath = path.join(vaultDir, f);
        const stat = fs.statSync(fullPath);
        return { name: f, path: fullPath, size: stat.size, modified: stat.mtime.toISOString() };
      });
      return { success: true, files };
    } catch (err) {
      return { success: false, files: [], error: serializeError(err) };
    }
  });

  // ─── ARGUS Encrypt / Decrypt ───
  ipcMain.handle(IPC.VAULT.ENCRYPT_DATA, async (_event, data: string) => {
    try {
      if (!data || typeof data !== 'string') return { success: false, error: 'Data string is required' };
      const result = await getArgusManager().encryptData(data);
      return { success: true, data: result };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.VAULT.DECRYPT_DATA, async (_event, encryptedData: string) => {
    try {
      if (!encryptedData || typeof encryptedData !== 'string') return { success: false, error: 'Encrypted data string is required' };
      const result = await getArgusManager().decryptData(encryptedData);
      return { success: true, data: result };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Sentinel Config ───
  ipcMain.handle(IPC.VAULT.GET_CONFIG, async () => {
    try {
      const config = getSentinelConfig();
      return { success: true, data: config };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.VAULT.ADD_WHITELIST, async (_event, ip: string) => {
    try {
      const config = addWhitelistEntry(ip);
      return { success: true, data: config };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.VAULT.REMOVE_WHITELIST, async (_event, ip: string) => {
    try {
      const config = removeWhitelistEntry(ip);
      return { success: true, data: config };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.VAULT.SET_WHITELIST, async (_event, ips: string[]) => {
    try {
      const config = setWhitelist(ips);
      return { success: true, data: config };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Settings ───
  ipcMain.handle(IPC.VAULT.GET_SETTINGS, async () => {
    try {
      let settings = { language: 'de', theme: 'dark', autostart: false, autoUpdate: false };
      const sPath = getSettingsPath();
      if (fs.existsSync(sPath)) {
        const data = fs.readFileSync(sPath, 'utf8');
        settings = JSON.parse(data);
      }
      return { success: true, settings };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.VAULT.SAVE_SETTINGS, async (_event, key: string, value: unknown) => {
    try {
      let settings: Record<string, unknown> = { language: 'de', theme: 'dark', autostart: false, autoUpdate: false };
      const sPath = getSettingsPath();
      if (fs.existsSync(sPath)) {
        const data = fs.readFileSync(sPath, 'utf8');
        settings = JSON.parse(data);
      }
      settings[key] = value;
      const dir = path.dirname(sPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(sPath, JSON.stringify(settings, null, 2), 'utf8');
      return { success: true, message: 'Settings saved successfully' };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Activity Log ───
  ipcMain.handle(IPC.VAULT.GET_ACTIVITY_LOG, async () => {
    try {
      const aPath = getActivityLogPath();
      if (!fs.existsSync(aPath)) return [];
      return fs.readFileSync(aPath, 'utf8')
        .split('\n').filter((l) => l.trim()).slice(-50)
        .map((line) => { try { return JSON.parse(line); } catch { return null; } })
        .filter(Boolean);
    } catch { return []; }
  });

  ipcMain.handle(IPC.VAULT.CLEAR_ACTIVITY_LOG, async () => {
    try {
      if (fs.existsSync(getActivityLogPath())) fs.unlinkSync(getActivityLogPath());
      return { success: true };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── ARGUS Health ───
  ipcMain.handle(IPC.VAULT.ARGUS_HEALTH, async () => {
    try {
      const info = await getArgusManager().getHealthInfoLive();
      return { success: true, data: info };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Dialogs ───
  ipcMain.handle(IPC.DIALOG.SHOW_ERROR, async (_event, title: string, message: string) => {
    dialog.showErrorBox(title, message);
    return undefined;
  });

  ipcMain.handle(IPC.DIALOG.SHOW_MESSAGE, async (_event, title: string, message: string) => {
    await dialog.showMessageBox(mainWindow || (undefined as unknown as BrowserWindow), { type: 'info', title, message, buttons: ['OK'] });
    return undefined;
  });

  ipcMain.handle(IPC.DIALOG.SHOW_CONFIRM, async (_event, title: string, message: string) => {
    const result = await dialog.showMessageBox(mainWindow || (undefined as unknown as BrowserWindow), {
      type: 'question', title, message, buttons: ['Yes', 'No'], defaultId: 1, cancelId: 1,
    });
    return result.response === 0;
  });

  ipcMain.handle(IPC.DIALOG.TOGGLE_DEV_TOOLS, async () => {
    if (mainWindow) mainWindow.webContents.toggleDevTools();
    return undefined;
  });

  // ─── Renderer Build / Reload ───
  ipcMain.handle(IPC.RENDERER.BUILD, async () => {
    if (!mainWindow) return { success: false, message: 'No main window' };
    try {
      const cmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
      const build = spawn(cmd, ['run', 'build'], { cwd: process.cwd() });
      build.stdout.on('data', (d) => { try { mainWindow?.webContents.send(IPC.RENDERER.BUILD_LOG, d.toString()); } catch { /* window may be closed */ } });
      build.stderr.on('data', (d) => { try { mainWindow?.webContents.send(IPC.RENDERER.BUILD_LOG, d.toString()); } catch { /* window may be closed */ } });
      build.on('close', (code) => { try { mainWindow?.webContents.send(IPC.RENDERER.BUILD_DONE, { success: code === 0, code }); } catch { /* window may be closed */ } });
      return { success: true, message: 'Build started' };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.RENDERER.RELOAD, async () => {
    const candidates = [
      path.join(__dirname, '../renderer/index.html'),
      path.join(__dirname, '../../renderer/index.html'),
    ];
    const rendererFile = candidates.find((p) => fs.existsSync(p));
    if (!rendererFile) return { success: false, message: 'Renderer file not found' };
    if (!mainWindow) return { success: false, message: 'No window' };
    try {
      await mainWindow.loadFile(rendererFile);
      mainWindow.show();
      return { success: true, message: 'Renderer loaded', path: rendererFile };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Automation: Quick Action (real netsh dispatch) ───
  ipcMain.handle(IPC.AUTOMATION.EXECUTE_QUICK_ACTION, async (_event, action: string) => {
    try {
      const { execSync } = require('child_process');
      const actions: string[] = [];
      if (action === 'lockdown') {
        try {
          execSync('netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound', { windowsHide: true });
          actions.push('Firewall set to block all inbound+outbound');
        } catch (e: any) { actions.push(`Firewall lockdown failed: ${e.message}`); }
      } else if (action === 'stealth') {
        try {
          execSync('netsh advfirewall firewall add rule name="Sentinel-Stealth-BlockPing" dir=in action=block protocol=icmpv4', { windowsHide: true });
          actions.push('ICMP echo blocked (stealth mode)');
        } catch (e: any) { actions.push(`Stealth mode failed: ${e.message}`); }
      } else if (action === 'reset') {
        try {
          execSync('netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound', { windowsHide: true });
          actions.push('Firewall reset to default policy');
        } catch (e: any) { actions.push(`Reset failed: ${e.message}`); }
      } else {
        return { success: false, message: `Unknown quick action: ${action}`, actions: [] };
      }
      return { success: true, message: `${action} executed`, actions };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  ipcMain.handle(IPC.AUTOMATION.SET_AUTONOMOUS_MODE, async (_event, enabled: boolean) => {
    try {
      const config = updateAutonomousMode(enabled);
      return { success: true, data: config };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });
}
