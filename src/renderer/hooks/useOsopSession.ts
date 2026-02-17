/**
 * SENTINEL OSOP — Renderer-Side Session Guard
 *
 * - Listens for 'osop-session-reset' from main process
 * - Clears all React Query caches on reset
 * - Blocks localStorage/sessionStorage writes (except language pref)
 * - Exposes session info for UI status display
 */

import { useEffect, useCallback, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';

const ALLOWED_STORAGE_KEYS = new Set(['sentinel-language']);

/**
 * Intercept and restrict localStorage to whitelist-only.
 * Called once at app mount. Returns a restore function.
 */
function patchStorageForOsop(): () => void {
  const origSetItem = localStorage.setItem.bind(localStorage);
  const origRemoveItem = localStorage.removeItem.bind(localStorage);

  localStorage.setItem = (key: string, value: string) => {
    if (ALLOWED_STORAGE_KEYS.has(key)) {
      origSetItem(key, value);
    }
    // Silently drop all other writes — OSOP ephemeral policy
  };

  // Clear everything except whitelisted keys on mount
  const keysToRemove: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (k && !ALLOWED_STORAGE_KEYS.has(k)) keysToRemove.push(k);
  }
  keysToRemove.forEach(k => origRemoveItem(k));

  // Block sessionStorage entirely
  try {
    sessionStorage.clear();
    const origSSSet = sessionStorage.setItem.bind(sessionStorage);
    sessionStorage.setItem = () => {}; // no-op
  } catch { /* sandbox may block */ }

  return () => {
    localStorage.setItem = origSetItem;
    localStorage.removeItem = origRemoveItem;
  };
}

export function useOsopSession() {
  const queryClient = useQueryClient();
  const patchedRef = useRef(false);

  // Patch storage on first mount
  useEffect(() => {
    if (!patchedRef.current) {
      patchStorageForOsop();
      patchedRef.current = true;
    }
  }, []);

  // Listen for session reset from main process
  const handleReset = useCallback(() => {
    // Clear all cached query data — prevents stale data leaking across sessions
    queryClient.clear();
    // Clear any remaining non-whitelisted localStorage
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && !ALLOWED_STORAGE_KEYS.has(k)) keysToRemove.push(k);
    }
    keysToRemove.forEach(k => { try { localStorage.removeItem(k); } catch { /* ok */ } });
    try { sessionStorage.clear(); } catch { /* ok */ }
  }, [queryClient]);

  useEffect(() => {
    const api = (window as any).electronAPI;
    if (api?.osop?.onSessionReset) {
      api.osop.onSessionReset(() => {
        console.log('[OSOP] Session reset received — clearing renderer caches');
        handleReset();
      });
    }
  }, [handleReset]);
}
