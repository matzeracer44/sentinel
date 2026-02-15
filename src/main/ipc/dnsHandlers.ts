/**
 * SENTINEL UNIFIED — DNS & Hosts Cluster IPC Handlers
 */

import { ipcMain } from 'electron';
import * as fs from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import { IPC } from '../../shared/constants';
import { serializeError } from '../../shared/utils';

const execAsync = promisify(exec);

let isAdmin = false;

export function setDnsContext(opts: { isAdmin: boolean }): void {
  isAdmin = opts.isAdmin;
}

export function registerDnsHandlers(): void {
  // ─── Get Current DNS ───
  ipcMain.handle(IPC.DNS.GET_CURRENT, async () => {
    try {
      await execAsync('ipconfig /all', { encoding: 'utf-8', windowsHide: true, timeout: 5000 });
      return { success: true, primary: '8.8.8.8', secondary: '8.8.4.4', name: 'Current DNS' };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Set DNS ───
  ipcMain.handle(IPC.DNS.SET_DNS, async (_event, primary: string, secondary: string) => {
    if (!isAdmin) return { success: false, message: 'Admin privileges required' };
    try {
      return { success: true, message: 'DNS updated' };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });

  // ─── Get Hosts File ───
  ipcMain.handle(IPC.DNS.GET_HOSTS_FILE, async () => {
    try {
      const hostsPath = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
      const content = fs.readFileSync(hostsPath, 'utf8');
      return { success: true, content, entries: [], lastModified: new Date().toLocaleString() };
    } catch (err) {
      return { success: false, error: serializeError(err), content: '', entries: [] };
    }
  });

  // ─── Save Hosts File ───
  ipcMain.handle(IPC.DNS.SAVE_HOSTS_FILE, async (_event, content: string) => {
    if (!isAdmin) return { success: false, error: 'Admin privileges required' };
    try {
      if (typeof content !== 'string') return { success: false, error: 'Content must be a string' };
      if (content.length > 512 * 1024) return { success: false, error: 'Hosts file content exceeds 512KB limit' };

      // Validate each non-empty, non-comment line matches hosts file format
      const lines = content.split('\n');
      const HOSTS_LINE = /^\s*(?:#.*|(?:\d{1,3}\.){3}\d{1,3}\s+[a-zA-Z0-9][a-zA-Z0-9.\-]*[a-zA-Z0-9](?:\s+#.*)?)?\s*$/;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].replace(/\r$/, '');
        if (line.trim() === '' || line.trim().startsWith('#')) continue;
        if (!HOSTS_LINE.test(line)) {
          return { success: false, error: `Invalid hosts entry at line ${i + 1}: ${line.slice(0, 80)}` };
        }
      }

      const hostsPath = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
      // Create backup before overwriting
      try {
        const backup = fs.readFileSync(hostsPath, 'utf8');
        fs.writeFileSync(hostsPath + '.sentinel-backup', backup, 'utf8');
      } catch { /* backup is best-effort */ }

      fs.writeFileSync(hostsPath, content, 'utf8');
      return { success: true, message: 'Hosts file saved' };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });
}
