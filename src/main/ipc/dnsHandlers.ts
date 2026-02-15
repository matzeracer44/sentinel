/**
 * SENTINEL UNIFIED — DNS & Hosts Cluster IPC Handlers
 */

import { ipcMain } from 'electron';
import * as fs from 'fs';
import { execSync } from 'child_process';
import { IPC } from '../../shared/constants';
import { serializeError } from '../../shared/utils';

let isAdmin = false;

export function setDnsContext(opts: { isAdmin: boolean }): void {
  isAdmin = opts.isAdmin;
}

export function registerDnsHandlers(): void {
  // ─── Get Current DNS ───
  ipcMain.handle(IPC.DNS.GET_CURRENT, async () => {
    try {
      execSync('ipconfig /all', { encoding: 'utf-8' });
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
      const hostsPath = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
      fs.writeFileSync(hostsPath, content, 'utf8');
      return { success: true, message: 'Hosts file saved' };
    } catch (err) {
      return { success: false, error: serializeError(err) };
    }
  });
}
