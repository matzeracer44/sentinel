import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ElectronAPI } from '@/preload/preload';

export interface PendingRule {
  id: string;
  sessionKey: string;
  pid: number;
  processName: string;
  remoteIP?: string;
  remotePort?: number;
  reasons: string[];
  recommendsBlock: boolean;
  ttlSeconds?: number;
  createdAt: number;
  expiresAt: number;
  status: 'pending' | 'committed' | 'expired';
}

export interface StagePendingRulePayload {
  sessionKey: string;
  pid: number;
  processName: string;
  remoteIP: string;
  remotePort?: number;
  reasons: string[];
  recommendsBlock: boolean;
  ttlSeconds?: number;
}

interface PendingRuleUpdateEvent {
  event: 'staged' | 'committed' | 'expired';
  pendingRule: PendingRule;
}

export const usePendingRules = () => {
  const [pendingRules, setPendingRules] = useState<PendingRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | string | null>(null);
  const fetchController = useRef<AbortController | null>(null);

  const api: ElectronAPI | undefined = (window as Window & { electronAPI?: ElectronAPI }).electronAPI;

  const loadPendingRules = useCallback(async () => {
    if (!api?.shield?.getPendingRules) {
      return;
    }
    const controller = new AbortController();
    fetchController.current?.abort();
    fetchController.current = controller;
    setLoading(true);
    setError(null);
    try {
      const result = await api.shield.getPendingRules();
      if (controller.signal.aborted) {
        return;
      }
      if (!result?.success || !Array.isArray(result.pendingRules)) {
        const errMsg = typeof result?.error === 'string' ? result.error : result?.error?.message;
        throw new Error(errMsg || 'Unable to load pending rules');
      }
      setPendingRules(result.pendingRules as PendingRule[]);
    } catch (err: any) {
      if (controller.signal.aborted) {
        return;
      }
      setError(err instanceof Error ? err : new Error(err?.message || 'Failed to load pending rules'));
    } finally {
      if (!controller.signal.aborted) {
        setLoading(false);
      }
    }
  }, [api]);

  const handleUpdateEvent = useCallback((update: PendingRuleUpdateEvent) => {
    setPendingRules((prev) => {
      if (update.event === 'staged') {
        const filtered = prev.filter((rule) => rule.id !== update.pendingRule.id);
        return [...filtered, update.pendingRule].sort((a, b) => a.expiresAt - b.expiresAt);
      }
      return prev.filter((rule) => rule.id !== update.pendingRule.id);
    });
  }, []);

  useEffect(() => {
    loadPendingRules();
    if (!api?.shield?.onPendingRuleUpdate) {
      return () => {
        fetchController.current?.abort();
      };
    }
    const unsubscribe = api.shield.onPendingRuleUpdate(handleUpdateEvent);
    return () => {
      fetchController.current?.abort();
      unsubscribe?.();
    };
  }, [api, handleUpdateEvent, loadPendingRules]);

  const stagePendingRule = useCallback(
    async (payload: StagePendingRulePayload) => {
      if (!api?.shield?.stageFirewallRule) {
        throw new Error('Stage API unavailable');
      }
      const response = await api.shield.stageFirewallRule(payload);
      if (!response?.success) {
        const errMsg = typeof response?.error === 'string' ? response.error : response?.error?.message;
        throw new Error(errMsg || 'Failed to stage firewall rule');
      }
      if (response.pendingRule) {
        handleUpdateEvent({ event: 'staged', pendingRule: response.pendingRule as PendingRule });
      } else {
        await loadPendingRules();
      }
    },
    [api, handleUpdateEvent, loadPendingRules]
  );

  const commitPendingRule = useCallback(
    async (pendingRuleId: string) => {
      if (!api?.shield?.commitPendingRule) {
        throw new Error('Commit API unavailable');
      }
      const response = await api.shield.commitPendingRule(pendingRuleId);
      if (!response?.success) {
        const errMsg = typeof response?.error === 'string' ? response.error : response?.error?.message;
        throw new Error(errMsg || 'Failed to commit pending rule');
      }
      setPendingRules((prev) => prev.filter((rule) => rule.id !== pendingRuleId));
    },
    [api]
  );

  const activePendingRules = useMemo(
    () => pendingRules.filter((rule) => rule.status === 'pending'),
    [pendingRules]
  );

  return {
    pendingRules: activePendingRules,
    loading,
    error,
    stagePendingRule,
    commitPendingRule,
    refreshPendingRules: loadPendingRules,
  };
};
