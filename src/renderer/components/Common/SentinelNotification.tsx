/**
 * SENTINEL — Notification System
 * Replaces react-hot-toast with a purpose-built, persistent notification center.
 * Features: severity-based styling, auto-dismiss, notification history, animated transitions.
 */

import React, { createContext, useContext, useState, useCallback, useRef, useEffect } from 'react';

// ─── Types ───

export type NotifySeverity = 'success' | 'error' | 'warning' | 'info';

export interface SentinelNotification {
  id: string;
  severity: NotifySeverity;
  message: string;
  timestamp: number;
  dismissed: boolean;
  autoDismissMs: number;
}

interface NotifyAPI {
  success: (msg: string) => void;
  error: (msg: string) => void;
  warning: (msg: string) => void;
  info: (msg: string) => void;
  dismiss: (id: string) => void;
  clearAll: () => void;
  history: SentinelNotification[];
}

// ─── Defaults ───

const AUTO_DISMISS: Record<NotifySeverity, number> = {
  success: 4000,
  error: 10000,
  warning: 6000,
  info: 4000,
};

const MAX_VISIBLE = 5;
const MAX_HISTORY = 50;

// ─── Styling ───

const SEVERITY_STYLES: Record<NotifySeverity, { bg: string; border: string; icon: string; accent: string }> = {
  success: {
    bg: 'rgba(0, 255, 136, 0.08)',
    border: 'rgba(0, 255, 136, 0.35)',
    icon: '✓',
    accent: '#00ff88',
  },
  error: {
    bg: 'rgba(255, 51, 102, 0.10)',
    border: 'rgba(255, 51, 102, 0.40)',
    icon: '✕',
    accent: '#ff3366',
  },
  warning: {
    bg: 'rgba(255, 170, 0, 0.08)',
    border: 'rgba(255, 170, 0, 0.35)',
    icon: '⚠',
    accent: '#ffaa00',
  },
  info: {
    bg: 'rgba(0, 200, 255, 0.08)',
    border: 'rgba(0, 200, 255, 0.30)',
    icon: 'ℹ',
    accent: '#00c8ff',
  },
};

// ─── Context ───

const NotifyContext = createContext<NotifyAPI | null>(null);

let _globalNotify: NotifyAPI | null = null;

/**
 * Global notify function — works outside React components.
 * Available after NotificationProvider mounts.
 */
export const notify = {
  success: (msg: string) => _globalNotify?.success(msg),
  error: (msg: string) => _globalNotify?.error(msg),
  warning: (msg: string) => _globalNotify?.warning(msg),
  info: (msg: string) => _globalNotify?.info(msg),
  dismiss: (id: string) => _globalNotify?.dismiss(id),
  clearAll: () => _globalNotify?.clearAll(),
};

export function useNotify(): NotifyAPI {
  const ctx = useContext(NotifyContext);
  if (!ctx) throw new Error('useNotify must be used within <NotificationProvider>');
  return ctx;
}

// ─── Provider ───

let _idCounter = 0;
function nextId(): string {
  return `sn-${Date.now()}-${++_idCounter}`;
}

export const NotificationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [notifications, setNotifications] = useState<SentinelNotification[]>([]);
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const dismiss = useCallback((id: string) => {
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, dismissed: true } : n)));
    const timer = timersRef.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timersRef.current.delete(id);
    }
  }, []);

  const clearAll = useCallback(() => {
    setNotifications([]);
    timersRef.current.forEach((t) => clearTimeout(t));
    timersRef.current.clear();
  }, []);

  const push = useCallback((severity: NotifySeverity, message: string) => {
    const id = nextId();
    const autoDismissMs = AUTO_DISMISS[severity];
    const notif: SentinelNotification = {
      id,
      severity,
      message,
      timestamp: Date.now(),
      dismissed: false,
      autoDismissMs,
    };

    setNotifications((prev) => {
      const next = [notif, ...prev];
      if (next.length > MAX_HISTORY) next.length = MAX_HISTORY;
      return next;
    });

    const timer = setTimeout(() => dismiss(id), autoDismissMs);
    timersRef.current.set(id, timer);
  }, [dismiss]);

  const api = useRef<NotifyAPI>({
    success: (msg) => push('success', msg),
    error: (msg) => push('error', msg),
    warning: (msg) => push('warning', msg),
    info: (msg) => push('info', msg),
    dismiss,
    clearAll,
    history: notifications,
  });

  // Keep api.history in sync
  api.current.history = notifications;
  api.current.success = (msg) => push('success', msg);
  api.current.error = (msg) => push('error', msg);
  api.current.warning = (msg) => push('warning', msg);
  api.current.info = (msg) => push('info', msg);
  api.current.dismiss = dismiss;
  api.current.clearAll = clearAll;

  // Expose globally
  useEffect(() => {
    _globalNotify = api.current;
    return () => { _globalNotify = null; };
  }, []);

  // Cleanup timers on unmount
  useEffect(() => {
    return () => {
      timersRef.current.forEach((t) => clearTimeout(t));
    };
  }, []);

  return (
    <NotifyContext.Provider value={api.current}>
      {children}
      <NotificationOverlay notifications={notifications} onDismiss={dismiss} onClearAll={clearAll} />
    </NotifyContext.Provider>
  );
};

// ─── Overlay ───

interface OverlayProps {
  notifications: SentinelNotification[];
  onDismiss: (id: string) => void;
  onClearAll: () => void;
}

const NotificationOverlay: React.FC<OverlayProps> = ({ notifications, onDismiss, onClearAll }) => {
  const [showHistory, setShowHistory] = useState(false);
  const visible = notifications.filter((n) => !n.dismissed).slice(0, MAX_VISIBLE);
  const historyItems = notifications.slice(0, MAX_HISTORY);
  const unreadCount = visible.length;

  return (
    <>
      {/* Live notification stack */}
      <div
        style={{
          position: 'fixed',
          top: 38,
          right: 14,
          zIndex: 99999,
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
          pointerEvents: 'none',
          maxWidth: 380,
          width: '100%',
        }}
      >
        {visible.map((n, i) => (
          <NotificationCard
            key={n.id}
            notification={n}
            index={i}
            onDismiss={onDismiss}
          />
        ))}
      </div>

      {/* History bell icon — fixed bottom-right */}
      <button
        onClick={() => setShowHistory((v) => !v)}
        style={{
          position: 'fixed',
          bottom: 36,
          right: 14,
          zIndex: 99998,
          width: 32,
          height: 32,
          borderRadius: '50%',
          background: showHistory ? 'rgba(0,200,255,0.25)' : 'rgba(15,15,35,0.85)',
          border: `1px solid ${showHistory ? 'rgba(0,200,255,0.5)' : 'rgba(109,120,255,0.2)'}`,
          color: '#f0f1ff',
          fontSize: '0.875rem',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transition: 'all 0.2s',
          backdropFilter: 'blur(8px)',
        }}
        title="Notification History"
      >
        🔔
        {unreadCount > 0 && (
          <span
            style={{
              position: 'absolute',
              top: -4,
              right: -4,
              width: 16,
              height: 16,
              borderRadius: '50%',
              background: '#ff3366',
              fontSize: '0.5625rem',
              fontWeight: 700,
              color: '#fff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            {unreadCount}
          </span>
        )}
      </button>

      {/* History panel */}
      {showHistory && (
        <div
          style={{
            position: 'fixed',
            bottom: 74,
            right: 14,
            zIndex: 99997,
            width: 360,
            maxHeight: 420,
            background: 'rgba(8, 8, 28, 0.97)',
            border: '1px solid rgba(109, 120, 255, 0.2)',
            borderRadius: 12,
            backdropFilter: 'blur(16px)',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '10px 14px',
              borderBottom: '1px solid rgba(109,120,255,0.12)',
            }}
          >
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--s-text-dim, #8892b0)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Notification History
            </span>
            <button
              onClick={onClearAll}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--s-text-muted, #64748b)',
                fontSize: '0.6875rem',
                cursor: 'pointer',
              }}
            >
              Clear all
            </button>
          </div>
          <div style={{ overflowY: 'auto', flex: 1, padding: '6px 8px' }}>
            {historyItems.length === 0 && (
              <div style={{ padding: 20, textAlign: 'center', color: 'var(--s-text-muted, #64748b)', fontSize: '0.75rem' }}>
                No notifications yet
              </div>
            )}
            {historyItems.map((n) => {
              const sev = SEVERITY_STYLES[n.severity];
              const age = formatAge(n.timestamp);
              return (
                <div
                  key={n.id}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 8,
                    padding: '7px 8px',
                    borderRadius: 6,
                    opacity: n.dismissed ? 0.55 : 1,
                    transition: 'opacity 0.2s',
                  }}
                >
                  <span style={{ color: sev.accent, fontSize: '0.75rem', fontWeight: 700, marginTop: 1, flexShrink: 0, width: 14, textAlign: 'center' }}>
                    {sev.icon}
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: '0.75rem', color: '#cbd5e1', lineHeight: 1.35, wordBreak: 'break-word' }}>
                      {n.message}
                    </div>
                    <div style={{ fontSize: '0.625rem', color: 'var(--s-text-muted, #64748b)', marginTop: 2 }}>
                      {age}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </>
  );
};

// ─── Card ───

interface CardProps {
  notification: SentinelNotification;
  index: number;
  onDismiss: (id: string) => void;
}

const NotificationCard: React.FC<CardProps> = ({ notification, index, onDismiss }) => {
  const sev = SEVERITY_STYLES[notification.severity];
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setVisible(true), 30 + index * 40);
    return () => clearTimeout(t);
  }, [index]);

  return (
    <div
      style={{
        pointerEvents: 'auto',
        background: sev.bg,
        border: `1px solid ${sev.border}`,
        borderLeft: `3px solid ${sev.accent}`,
        borderRadius: 8,
        padding: '10px 12px 10px 10px',
        display: 'flex',
        alignItems: 'flex-start',
        gap: 8,
        backdropFilter: 'blur(14px)',
        boxShadow: '0 4px 16px rgba(0,0,0,0.35)',
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateX(0)' : 'translateX(60px)',
        transition: 'opacity 0.25s ease, transform 0.3s cubic-bezier(0.22,1,0.36,1)',
        maxWidth: '100%',
      }}
    >
      <span
        style={{
          fontSize: '0.8125rem',
          fontWeight: 700,
          color: sev.accent,
          flexShrink: 0,
          width: 18,
          height: 18,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: '50%',
          background: `${sev.accent}15`,
        }}
      >
        {sev.icon}
      </span>
      <div style={{ flex: 1, minWidth: 0, fontSize: '0.8125rem', color: '#f0f1ff', lineHeight: 1.4, wordBreak: 'break-word' }}>
        {notification.message}
      </div>
      <button
        onClick={() => onDismiss(notification.id)}
        style={{
          background: 'transparent',
          border: 'none',
          color: 'rgba(255,255,255,0.3)',
          fontSize: '0.75rem',
          cursor: 'pointer',
          flexShrink: 0,
          padding: '0 2px',
          lineHeight: 1,
        }}
        title="Dismiss"
      >
        ✕
      </button>
    </div>
  );
};

// ─── Helpers ───

function formatAge(ts: number): string {
  const sec = Math.floor((Date.now() - ts) / 1000);
  if (sec < 5) return 'just now';
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  return `${hr}h ago`;
}

export default NotificationOverlay;
