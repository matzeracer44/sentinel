/**
 * SENTINEL UNIFIED — Vault & Config Types (Renderer)
 */

export interface SecureNote {
  id: string;
  title: string;
  content?: string;
  createdAt: number;
  updatedAt: number;
  encrypted: boolean;
}

export interface EncryptedFile {
  id: string;
  originalName: string;
  encryptedPath: string;
  size: number;
  createdAt: number;
}

export interface SavedPassword {
  id: string;
  password: string;
  note: string;
  createdAt: number;
}

export interface ShredStats {
  shreddedCount: number;
  totalSize: number;
}

export interface SentinelConfig {
  autonomousMode: boolean;
  whitelist: string[];
}

export interface AppSettings {
  language: string;
  theme: string;
  autostart: boolean;
  autoUpdate: boolean;
}

export interface ActivityLogEntry {
  timestamp: string;
  source: string;
  action: string;
  message: string;
  level: string;
}

export interface ArgusHealth {
  status: 'running' | 'stopped' | 'starting' | 'error';
  pid: number | null;
  port: number;
  uptimeMs: number;
  lastError: string | null;
}
