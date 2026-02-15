/**
 * Sentinel — ARGUS Managed Child Process
 *
 * Spawns the ARGUS Python Flask backend as a child process,
 * provides a safeFetch wrapper that enforces localhost-only requests,
 * and exposes lifecycle management (start / stop / health).
 *
 * Security invariants:
 *  - ARGUS binds exclusively to 127.0.0.1
 *  - All HTTP requests go through safeFetch (localhost guard + timeout)
 *  - No shell: true in spawn
 *  - API keys are passed via env vars, never logged
 */

import { spawn, execSync, ChildProcess } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as http from 'http';
import { app, BrowserWindow } from 'electron';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ArgusStatus = 'stopped' | 'starting' | 'running' | 'error';

export interface ArgusSafeFetchOptions {
  method?: 'GET' | 'POST';
  body?: string;
  timeoutMs?: number;
}

export interface ArgusHealthInfo {
  status: ArgusStatus;
  pid: number | null;
  port: number;
  uptimeMs: number;
  lastError: string | null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_PORT = 8080;
const DEFAULT_TIMEOUT_MS = 12_000;
const READY_POLL_INTERVAL_MS = 500;
const READY_TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024; // 10 MB

// ---------------------------------------------------------------------------
// ArgusManager
// ---------------------------------------------------------------------------

export class ArgusManager {
  private process: ChildProcess | null = null;
  private _status: ArgusStatus = 'stopped';
  private _port: number;
  private _baseUrl: string;
  private _startedAt: number = 0;
  private _lastError: string | null = null;
  private _stdoutBuffer: string[] = [];
  private _stderrBuffer: string[] = [];
  private _restartAttempts: number = 0;
  private _maxRestarts: number = 3;
  private _healthInterval: ReturnType<typeof setInterval> | null = null;
  private _generation: number = 0;
  private _starting: boolean = false;

  constructor(port: number = DEFAULT_PORT) {
    this._port = port;
    this._baseUrl = `http://127.0.0.1:${this._port}`;
  }

  get restartAttempts(): number { return this._restartAttempts; }
  get maxRestarts(): number { return this._maxRestarts; }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  get status(): ArgusStatus {
    return this._status;
  }

  get port(): number {
    return this._port;
  }

  get baseUrl(): string {
    return this._baseUrl;
  }

  get pid(): number | null {
    return this.process?.pid ?? null;
  }

  private broadcastStatus(): void {
    try {
      const payload = {
        online: this._status === 'running',
        status: this._status,
        pid: this.pid,
        uptimeMs: this._startedAt > 0 ? Date.now() - this._startedAt : 0,
        lastError: this._lastError,
        timestamp: Date.now(),
      };
      for (const win of BrowserWindow.getAllWindows()) {
        if (!win.isDestroyed()) {
          win.webContents.send('argus-status-changed', payload);
        }
      }
    } catch { /* ignore broadcast errors during shutdown */ }
  }

  getHealthInfo(): ArgusHealthInfo {
    return {
      status: this._status,
      pid: this.pid,
      port: this._port,
      uptimeMs: this._startedAt > 0 ? Date.now() - this._startedAt : 0,
      lastError: this._lastError,
    };
  }

  /**
   * Live health check — actually pings ARGUS HTTP server.
   * Updates internal _status if ARGUS is reachable but status was stale.
   */
  async getHealthInfoLive(): Promise<ArgusHealthInfo> {
    try {
      await this.safeFetch('/api/sandbox', { timeoutMs: 3000 });
      // ARGUS responded — it's alive
      if (this._status !== 'running') {
        console.log('[ArgusManager] Live health check: ARGUS is responding, updating status to running');
        this._status = 'running';
        if (this._startedAt === 0) this._startedAt = Date.now();
      }
    } catch {
      // ARGUS didn't respond — if we thought it was running, mark as error
      if (this._status === 'running') {
        this._status = 'error';
        this._lastError = 'ARGUS not responding to health check';
      }
    }
    return this.getHealthInfo();
  }

  getRecentLogs(maxLines: number = 50): { stdout: string[]; stderr: string[] } {
    return {
      stdout: this._stdoutBuffer.slice(-maxLines),
      stderr: this._stderrBuffer.slice(-maxLines),
    };
  }

  // -----------------------------------------------------------------------
  // Lifecycle
  // -----------------------------------------------------------------------

  async start(): Promise<void> {
    if (this._status === 'running') {
      return;
    }
    if (this._starting) {
      console.warn('[ArgusManager] start() already in progress, ignoring duplicate call');
      return;
    }

    this._starting = true;
    this._generation++;
    const gen = this._generation;
    this._status = 'starting';
    this._lastError = null;
    this._stdoutBuffer = [];
    this._stderrBuffer = [];

    const argusRoot = this.resolveArgusRoot();
    if (!argusRoot) {
      this._status = 'error';
      this._lastError = 'ARGUS directory not found';
      console.error('[ArgusManager] ARGUS directory not found');
      this._starting = false;
      this.broadcastStatus();
      return;
    }

    const mainPy = path.join(argusRoot, 'main.py');
    if (!fs.existsSync(mainPy)) {
      this._status = 'error';
      this._lastError = `main.py not found at ${mainPy}`;
      console.error(`[ArgusManager] main.py not found at ${mainPy}`);
      this._starting = false;
      this.broadcastStatus();
      return;
    }

    // Kill any stale process occupying our port before spawning
    this.killStalePortProcess();

    const pythonPath = this.resolvePythonPath();
    console.log(`[ArgusManager] Starting ARGUS: ${pythonPath} ${mainPy} --web (port ${this._port} from config.yaml)`);

    try {
      this.process = spawn(
        pythonPath,
        [mainPy, '--web'],
        {
          cwd: argusRoot,
          env: { ...process.env },
          stdio: ['ignore', 'pipe', 'pipe'],
          windowsHide: true,
        }
      );

      this.process.stdout?.on('data', (chunk: Buffer) => {
        const line = chunk.toString().trim();
        if (line) {
          this._stdoutBuffer.push(line);
          if (this._stdoutBuffer.length > 200) {
            this._stdoutBuffer.shift();
          }
          console.log(`[ARGUS stdout] ${line}`);
        }
      });

      this.process.stderr?.on('data', (chunk: Buffer) => {
        const line = chunk.toString().trim();
        if (line) {
          this._stderrBuffer.push(line);
          if (this._stderrBuffer.length > 200) {
            this._stderrBuffer.shift();
          }
          // Flask logs to stderr by default — not necessarily errors
          console.log(`[ARGUS stderr] ${line}`);
        }
      });

      this.process.on('close', (code: number | null) => {
        if (this._generation !== gen) {
          console.log(`[ArgusManager] Ignoring close event from old generation ${gen} (current: ${this._generation})`);
          return;
        }
        console.warn(`[ArgusManager] ARGUS process exited with code ${code}`);
        this._status = 'stopped';
        this.process = null;
        this.broadcastStatus();
      });

      this.process.on('error', (err: Error) => {
        if (this._generation !== gen) {
          console.log(`[ArgusManager] Ignoring error event from old generation ${gen} (current: ${this._generation})`);
          return;
        }
        console.error('[ArgusManager] Failed to spawn ARGUS:', err.message);
        this._status = 'error';
        this._lastError = err.message;
        this.process = null;
        this.broadcastStatus();
      });

      await this.waitForReady(READY_TIMEOUT_MS);
      if (this._generation !== gen) {
        console.log('[ArgusManager] Generation changed during startup, aborting');
        this._starting = false;
        return;
      }
      this._startedAt = Date.now();
      this._status = 'running';
      this._restartAttempts = 0;
      this.startHealthMonitor();
      this.broadcastStatus();
      console.log(`[ArgusManager] ARGUS is running on ${this._baseUrl} (gen ${gen})`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (this._generation === gen) {
        this._status = 'error';
        this._lastError = message;
        console.error('[ArgusManager] Failed to start ARGUS:', message);
        this.stop();
      }
    } finally {
      this._starting = false;
    }
  }

  startHealthMonitor(): void {
    this.stopHealthMonitor();
    this._healthInterval = setInterval(async () => {
      if (this._status !== 'running') return;
      try {
        await this.safeFetch('/api/sandbox', { timeoutMs: 3000 });
      } catch {
        console.warn('[ArgusManager] Health check failed');
        this._status = 'error';
        this._lastError = 'ARGUS not responding to health check';
        this.broadcastStatus();
        if (this._restartAttempts < this._maxRestarts) {
          this._restartAttempts++;
          console.warn(`[ArgusManager] Auto-restart attempt ${this._restartAttempts}/${this._maxRestarts}`);
          this.stop();
          try { await this.start(); } catch { /* logged inside start() */ }
        } else {
          console.error('[ArgusManager] Max restarts reached. Manual intervention needed.');
          this.stopHealthMonitor();
        }
      }
    }, 15000);
  }

  stopHealthMonitor(): void {
    if (this._healthInterval) {
      clearInterval(this._healthInterval);
      this._healthInterval = null;
    }
  }

  stop(): void {
    this.stopHealthMonitor();
    if (this.process) {
      console.log('[ArgusManager] Stopping ARGUS...');
      try {
        this.process.kill('SIGTERM');
      } catch {
        try {
          this.process.kill('SIGKILL');
        } catch {
          // Process already dead
        }
      }
      this.process = null;
    }
    this._status = 'stopped';
    this._startedAt = 0;
    this.broadcastStatus();
  }

  // -----------------------------------------------------------------------
  // safeFetch — ALL requests to ARGUS go through this method
  // -----------------------------------------------------------------------

  async safeFetch<T = unknown>(endpoint: string, options?: ArgusSafeFetchOptions): Promise<T> {
    const url = `${this._baseUrl}${endpoint}`;

    // Security: Only localhost allowed
    if (!url.startsWith('http://127.0.0.1:')) {
      throw new Error(`[ArgusManager] safeFetch blocked non-localhost URL: ${url}`);
    }

    const method = options?.method ?? 'GET';
    const body = options?.body;
    const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;

    return new Promise<T>((resolve, reject) => {
      const urlObj = new URL(url);

      const reqOptions: http.RequestOptions = {
        hostname: urlObj.hostname,
        port: Number(urlObj.port),
        path: urlObj.pathname + urlObj.search,
        method,
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Sentinel/1.0',
          'Accept': 'application/json',
        },
        timeout: timeoutMs,
      };

      const req = http.request(reqOptions, (res) => {
        const chunks: Buffer[] = [];
        let totalBytes = 0;

        res.on('data', (chunk: Buffer) => {
          totalBytes += chunk.length;
          if (totalBytes > MAX_RESPONSE_BYTES) {
            req.destroy(new Error(`Response exceeds ${MAX_RESPONSE_BYTES} bytes`));
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8');

          if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`ARGUS ${endpoint}: HTTP ${res.statusCode} — ${raw.slice(0, 200)}`));
            return;
          }

          try {
            const parsed = JSON.parse(raw) as T;
            resolve(parsed);
          } catch {
            reject(new Error(`ARGUS ${endpoint}: Invalid JSON response`));
          }
        });

        res.on('error', (err) => {
          reject(new Error(`ARGUS ${endpoint}: Response error — ${err.message}`));
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`ARGUS ${endpoint}: Request timed out after ${timeoutMs}ms`));
      });

      req.on('error', (err) => {
        reject(new Error(`ARGUS ${endpoint}: ${err.message}`));
      });

      if (body && (method === 'POST')) {
        req.write(body);
      }

      req.end();
    });
  }

  // -----------------------------------------------------------------------
  // Convenience wrappers for ARGUS endpoints
  // -----------------------------------------------------------------------

  async scanUrl(url: string, force: boolean = false): Promise<unknown> {
    return this.safeFetch('/api/scan', {
      method: 'POST',
      body: JSON.stringify({ url, force }),
      timeoutMs: 60_000,
    });
  }

  async batchScan(urls: string[]): Promise<unknown> {
    return this.safeFetch('/api/batch_scan', {
      method: 'POST',
      body: JSON.stringify({ urls }),
      timeoutMs: 90_000,
    });
  }

  async getScanHistory(limit: number = 50, offset: number = 0): Promise<unknown> {
    return this.safeFetch(`/api/history?limit=${limit}&offset=${offset}`);
  }

  async exportHistory(): Promise<unknown> {
    return this.safeFetch('/api/history/export');
  }

  async clearHistory(): Promise<unknown> {
    return this.safeFetch('/api/history/clear', { method: 'POST' });
  }

  async getSandboxStatus(): Promise<unknown> {
    return this.safeFetch('/api/sandbox');
  }

  async toggleSandbox(enabled: boolean): Promise<unknown> {
    return this.safeFetch('/api/sandbox', {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    });
  }

  async encryptData(data: string): Promise<unknown> {
    return this.safeFetch('/api/encrypt', {
      method: 'POST',
      body: JSON.stringify({ data }),
    });
  }

  async decryptData(encryptedData: string): Promise<unknown> {
    return this.safeFetch('/api/decrypt', {
      method: 'POST',
      body: JSON.stringify({ encrypted_data: encryptedData }),
    });
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  /**
   * Kill any stale process that is already listening on the ARGUS port.
   * Prevents "Address already in use" failures on restart.
   */
  private killStalePortProcess(): void {
    try {
      const raw = execSync(
        `netstat -ano | findstr "LISTENING" | findstr ":${this._port}"`,
        { windowsHide: true, timeout: 5000, encoding: 'utf-8' }
      ).trim();
      if (!raw) return;

      const pids = new Set<number>();
      for (const line of raw.split('\n')) {
        const parts = line.trim().split(/\s+/);
        const pid = parseInt(parts[parts.length - 1], 10);
        if (pid > 0 && pid !== process.pid) pids.add(pid);
      }

      for (const pid of pids) {
        console.warn(`[ArgusManager] Killing stale process on port ${this._port}: PID ${pid}`);
        try {
          execSync(`taskkill /PID ${pid} /F`, { windowsHide: true, timeout: 5000 });
        } catch { /* process may already be dead */ }
      }

      if (pids.size > 0) {
        // Brief pause to let the OS release the port
        const wait = (ms: number) => { const end = Date.now() + ms; while (Date.now() < end) { /* spin */ } };
        wait(500);
      }
    } catch {
      // netstat may return exit code 1 if no matches — that's fine
    }
  }

  private resolveArgusRoot(): string | null {
    let appPath: string;
    try { appPath = app.getAppPath(); } catch { appPath = process.cwd(); }
    const candidates = [
      path.join(process.cwd(), 'ARGUS'),
      path.resolve(__dirname, '../../ARGUS'),
      path.resolve(__dirname, '../../../ARGUS'),
      path.join(appPath, 'ARGUS'),
      path.resolve(appPath, '../ARGUS'),
    ];
    console.log('[ArgusManager] resolveArgusRoot candidates:', candidates.map(c => `${c} -> ${fs.existsSync(path.join(c, 'main.py'))}`));

    for (const candidate of candidates) {
      if (fs.existsSync(path.join(candidate, 'main.py'))) {
        return candidate;
      }
    }

    return null;
  }

  private resolvePythonPath(): string {
    const envPath = process.env.ARGUS_PYTHON_PATH;
    if (envPath && envPath.trim().length > 0) {
      return envPath.trim();
    }
    return process.platform === 'win32' ? 'python' : 'python3';
  }

  private async waitForReady(timeoutMs: number): Promise<void> {
    const start = Date.now();

    while (Date.now() - start < timeoutMs) {
      // Check if process died during startup
      if (!this.process || this.process.exitCode !== null) {
        throw new Error('ARGUS process exited during startup');
      }

      try {
        await this.safeFetch('/api/sandbox', { timeoutMs: 3000 });
        return; // ARGUS responded — it's ready
      } catch {
        await new Promise<void>((r) => setTimeout(r, READY_POLL_INTERVAL_MS));
      }
    }

    throw new Error(`ARGUS failed to become ready within ${timeoutMs}ms`);
  }
}

// ---------------------------------------------------------------------------
// Singleton instance
// ---------------------------------------------------------------------------

let _instance: ArgusManager | null = null;

export function getArgusManager(port?: number): ArgusManager {
  if (!_instance) {
    _instance = new ArgusManager(port ?? DEFAULT_PORT);
  }
  return _instance;
}
