/**
 * SENTINEL — Global ARGUS Status Hook
 * Singleton state shared across all components that need ARGUS status.
 * Listens for real-time broadcasts from ArgusManager via IPC.
 */

import { useState, useEffect, useCallback } from 'react';

interface ArgusStatusPayload {
  online: boolean;
  status: string;
  pid: number | null;
  uptimeMs: number;
  lastError: string | null;
  timestamp: number;
}

interface ArgusState {
  online: boolean;
  status: string;
  pid: number | null;
  uptimeMs: number;
  lastError: string | null;
  lastChecked: number;
}

const DEFAULT_STATE: ArgusState = {
  online: false,
  status: 'unknown',
  pid: null,
  uptimeMs: 0,
  lastError: null,
  lastChecked: 0,
};

let globalState: ArgusState = { ...DEFAULT_STATE };
const listeners = new Set<(s: ArgusState) => void>();

function notify(next: ArgusState): void {
  globalState = next;
  listeners.forEach((fn) => fn(next));
}

function getApi(): any {
  return (window as any).electronAPI;
}

export function useArgusStatus() {
  const [state, setState] = useState<ArgusState>(globalState);

  useEffect(() => {
    listeners.add(setState);

    const api = getApi();
    const unsub = api?.argus?.onStatusChanged?.((payload: ArgusStatusPayload) => {
      notify({
        online: payload.online,
        status: payload.status,
        pid: payload.pid,
        uptimeMs: payload.uptimeMs,
        lastError: payload.lastError,
        lastChecked: payload.timestamp,
      });
    });

    return () => {
      listeners.delete(setState);
      if (typeof unsub === 'function') unsub();
    };
  }, []);

  const refreshStatus = useCallback(async () => {
    try {
      const api = getApi();
      const result = await api?.argus?.getStatus?.();
      if (result?.success) {
        notify({
          online: result.data?.status === 'running',
          status: result.data?.status ?? 'unknown',
          pid: result.data?.pid ?? null,
          uptimeMs: result.data?.uptimeMs ?? 0,
          lastError: result.data?.lastError ?? null,
          lastChecked: Date.now(),
        });
      }
    } catch (e: any) { console.warn('[useArgusStatus] fetch:', e?.message); }
  }, []);

  const startArgus = useCallback(async () => {
    try {
      const api = getApi();
      const result = await api?.argus?.start?.();
      if (result?.success) {
        notify({ ...globalState, online: true, status: 'running', lastChecked: Date.now() });
      }
      return result;
    } catch (err) {
      return { success: false, error: err instanceof Error ? err.message : String(err) };
    }
  }, []);

  const stopArgus = useCallback(async () => {
    try {
      const api = getApi();
      const result = await api?.argus?.stop?.();
      if (result?.success) {
        notify({ ...globalState, online: false, status: 'stopped', pid: null, uptimeMs: 0, lastChecked: Date.now() });
      }
      return result;
    } catch (err) {
      return { success: false, error: err instanceof Error ? err.message : String(err) };
    }
  }, []);

  const restartArgus = useCallback(async () => {
    try {
      const api = getApi();
      return await api?.argus?.restart?.();
    } catch (err) {
      return { success: false, error: err instanceof Error ? err.message : String(err) };
    }
  }, []);

  return { ...state, refreshStatus, startArgus, stopArgus, restartArgus };
}
