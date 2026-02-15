import { app } from 'electron';
import * as fs from 'fs';
import * as path from 'path';
import { monitorEventLoopDelay } from 'perf_hooks';
import inspector from 'inspector';
import { EventEmitter } from 'events';

interface ProfileMeta {
  file: string;
  startedAt: string;
  stoppedAt: string;
  reason: string;
  cpuUsage: NodeJS.CpuUsage;
  memory: NodeJS.MemoryUsage;
}

export class Profiler extends EventEmitter {
  private monitor = monitorEventLoopDelay({ resolution: 10 });
  private checkInterval = 1000; // ms
  private thresholdMs = 200; // trigger when event loop lag > 200ms
  private consecutiveThreshold = 2; // require 2 consecutive checks to avoid noise
  private exceedCount = 0;
  private session: inspector.Session | null = null;
  private running = false;
  private sampleDuration = 15000; // ms
  private dir: string | null = null;
  private checkerTimer: NodeJS.Timeout | null = null;

  private getProfileDir(): string {
    if (!this.dir) {
      this.dir = path.join(app.getPath('userData'), 'profiles');
      try { fs.mkdirSync(this.dir, { recursive: true }); } catch { /* dir may already exist */ }
    }
    return this.dir;
  }

  constructor() {
    super();

    this.monitor.enable();
    this.monitor.reset();

    this.checkerTimer = setInterval(() => this.checkLag(), this.checkInterval);
  }

  private checkLag() {
    try {
      // use mean and max to detect spikes
      const max = this.monitor.max / 1e6; // convert ns to ms
      if (max > this.thresholdMs) {
        this.exceedCount++;
      } else {
        this.exceedCount = 0;
      }

      // if exceed count reached, trigger an automatic profile
      if (this.exceedCount >= this.consecutiveThreshold && !this.running) {
        this.startAutoProfile('lag-detected');
        this.exceedCount = 0;
      }

      // reset monitor for next interval
      this.monitor.reset();
    } catch (e) {
      // swallow
    }
  }

  public async startAutoProfile(reason = 'auto') {
    if (this.running) return;
    this.emit('started', reason);
    await this.startProfile(reason);
  }

  public async startProfile(reason = 'manual') {
    if (this.running) return;
    this.running = true;

    this.session = new inspector.Session();
    this.session.connect();

    const startedAt = new Date();
    try {
      await this.post('Profiler.enable');
      await this.post('Profiler.start');

      // automatically stop after sampleDuration
      setTimeout(async () => {
        try {
          const profile = await this.stopProfileInternal();
          const stoppedAt = new Date();

          const fileBase = `profile-${startedAt.toISOString().replace(/[:.]/g, '-')}`;
          const profilePath = path.join(this.getProfileDir(), `${fileBase}.cpuprofile`);
          await fs.promises.writeFile(profilePath, JSON.stringify(profile), 'utf8');

          const meta: ProfileMeta = {
            file: profilePath,
            startedAt: startedAt.toISOString(),
            stoppedAt: stoppedAt.toISOString(),
            reason,
            cpuUsage: process.cpuUsage(),
            memory: process.memoryUsage(),
          };

          const metaPath = path.join(this.getProfileDir(), `${fileBase}.json`);
          await fs.promises.writeFile(metaPath, JSON.stringify(meta, null, 2), 'utf8');

          this.emit('saved', profilePath, metaPath);
        } catch (e) {
          this.emit('error', e);
        }
      }, this.sampleDuration);
    } catch (e) {
      this.running = false;
      this.emit('error', e);
    }
  }

  private stopProfileInternal(): Promise<inspector.Profiler.Profile> {
    return new Promise((resolve, reject) => {
      if (!this.session) return reject(new Error('No inspector session'));

      this.session.post('Profiler.stop', (err: any, r: any) => {
        try {
          if (err) return reject(err);
          const profile = r.profile as inspector.Profiler.Profile;
          this.session?.disconnect();
          this.session = null;
          this.running = false;
          resolve(profile);
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  public async stopProfile() {
    if (!this.running) return;
    try {
      const profile = await this.stopProfileInternal();
      const now = new Date();
      const fileBase = `profile-${now.toISOString().replace(/[:.]/g, '-')}`;
      const profilePath = path.join(this.getProfileDir(), `${fileBase}.cpuprofile`);
      await fs.promises.writeFile(profilePath, JSON.stringify(profile), 'utf8');

      const meta: ProfileMeta = {
        file: profilePath,
        startedAt: now.toISOString(),
        stoppedAt: now.toISOString(),
        reason: 'manual-stop',
        cpuUsage: process.cpuUsage(),
        memory: process.memoryUsage(),
      };

      const metaPath = path.join(this.getProfileDir(), `${fileBase}.json`);
      await fs.promises.writeFile(metaPath, JSON.stringify(meta, null, 2), 'utf8');

      this.emit('saved', profilePath, metaPath);
    } catch (e) {
      this.emit('error', e);
    }
  }

  private post(method: string): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.session) return reject(new Error('No inspector session'));
      this.session.post(method, (err: any, res: any) => {
        if (err) return reject(err);
        resolve(res);
      });
    });
  }

  public listProfiles() {
    try {
      const dir = this.getProfileDir();
      const files = fs.readdirSync(dir).filter((f) => f.endsWith('.cpuprofile'));
      return files.map((f) => path.join(dir, f));
    } catch (e) {
      return [];
    }
  }

  public dispose() {
    try { if (this.checkerTimer) clearInterval(this.checkerTimer); } catch { /* timer may already be cleared */ }
    try { this.monitor.disable(); } catch { /* monitor may already be disabled */ }
  }
}

let _profilerInstance: Profiler | null = null;

export function getProfiler(): Profiler {
  if (!_profilerInstance) {
    _profilerInstance = new Profiler();
  }
  return _profilerInstance;
}

export default { getProfiler };
