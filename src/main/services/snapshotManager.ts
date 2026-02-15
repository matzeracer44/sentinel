import { execSync } from 'child_process';
import { app } from 'electron';
import * as fs from 'fs';
import * as path from 'path';
import { getExecOptions } from './execOptions';

function execPowerShell(command: string): string {
  try {
    const fullCommand = `powershell -ExecutionPolicy Bypass -NoProfile -Command "${command}"`;
    return execSync(fullCommand, getExecOptions()).toString().trim();
  } catch (error: any) {
    console.error('PowerShell execution error:', error.message);
    return '';
  }
}

export interface SystemSnapshot {
  id: string;
  name: string;
  timestamp: number;
  date: string;
  services: any;
  tweaks: any;
  startupPrograms: any;
}

let SNAPSHOTS_DIR: string | null = null;

function getSnapshotsDir(): string {
  if (!SNAPSHOTS_DIR) {
    SNAPSHOTS_DIR = path.join(app.getPath('userData'), 'snapshots');
  }
  return SNAPSHOTS_DIR;
}

function ensureSnapshotsDir() {
  const dir = getSnapshotsDir();
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

export async function createSnapshot(name: string): Promise<SystemSnapshot | null> {
  try {
    ensureSnapshotsDir();

    const id = Date.now().toString();
    const timestamp = Date.now();

    const servicesCmd = `Get-Service | Select-Object Name,StartType,Status | ConvertTo-Json`;
    const services = execPowerShell(servicesCmd);

    const startupCmd = `Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -ErrorAction SilentlyContinue | ConvertTo-Json`;
    const startupPrograms = execPowerShell(startupCmd);

    const snapshot: SystemSnapshot = {
      id,
      name,
      timestamp,
      date: new Date(timestamp).toLocaleString(),
      services: JSON.parse(services || '[]'),
      tweaks: {},
      startupPrograms: JSON.parse(startupPrograms || '{}'),
    };

    const filePath = path.join(getSnapshotsDir(), `${id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2));

    console.log(`✓ Snapshot created: ${name}`);
    return snapshot;
  } catch (error: any) {
    console.error('Error creating snapshot:', error);
    return null;
  }
}

export async function listSnapshots(): Promise<SystemSnapshot[]> {
  try {
    ensureSnapshotsDir();

    const files = fs.readdirSync(getSnapshotsDir()).filter((f) => f.endsWith('.json'));
    const snapshots: SystemSnapshot[] = [];

    for (const file of files) {
      const filePath = path.join(getSnapshotsDir(), file);
      const data = fs.readFileSync(filePath, 'utf8');
      snapshots.push(JSON.parse(data));
    }

    return snapshots.sort((a, b) => b.timestamp - a.timestamp);
  } catch (error: any) {
    console.error('Error listing snapshots:', error);
    return [];
  }
}

export async function deleteSnapshot(id: string): Promise<boolean> {
  try {
    const filePath = path.join(getSnapshotsDir(), `${id}.json`);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      console.log(`✓ Snapshot deleted: ${id}`);
      return true;
    }
    return false;
  } catch (error: any) {
    console.error('Error deleting snapshot:', error);
    return false;
  }
}

export async function getSnapshot(id: string): Promise<SystemSnapshot | null> {
  try {
    const filePath = path.join(getSnapshotsDir(), `${id}.json`);
    if (fs.existsSync(filePath)) {
      const data = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(data);
    }
    return null;
  } catch (error: any) {
    console.error('Error getting snapshot:', error);
    return null;
  }
}
