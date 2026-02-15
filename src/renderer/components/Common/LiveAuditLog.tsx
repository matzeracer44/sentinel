/**
 * SENTINEL — Live Audit Log
 * Real-time terminal-style feed showing scan checks, fix applications,
 * IP blocks, process kills, and all system audit events as they happen.
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface AuditEvent {
  ts: number;
  module: string;
  action: string;
  message: string;
  severity: 'info' | 'success' | 'warning' | 'error';
  meta?: Record<string, unknown>;
}

const api = (): any => (window as any).electronAPI;

const MODULE_COLORS: Record<string, string> = {
  kernel: '#00d4ff',
  edr: '#00ff88',
  network: '#6d78ff',
  performance: '#ffaa00',
  privacy: '#c084fc',
  scan: '#60f0ff',
  fix: '#ff6b9d',
  shield: '#ff4466',
  system: '#94a3b8',
};

const SEVERITY_COLORS: Record<string, string> = {
  info: '#94a3b8',
  success: '#00ff88',
  warning: '#ffaa00',
  error: '#ff4466',
};

const SEVERITY_ICONS: Record<string, string> = {
  info: '\u25cf',
  success: '\u2713',
  warning: '\u26a0',
  error: '\u2715',
};

function formatTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

const LiveAuditLog: React.FC<{ maxHeight?: number; compact?: boolean }> = ({ maxHeight = 400, compact = false }) => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const autoScrollRef = useRef(true);

  // Load buffer on mount
  useEffect(() => {
    (async () => {
      try {
        const r = await api()?.notifications?.getAuditBuffer?.();
        if (r?.success && Array.isArray(r.events)) {
          setEvents(r.events.slice(-MAX_AUDIT_BUFFER));
        }
      } catch { /* no buffer */ }
    })();
  }, []);

  // Subscribe to real-time events
  useEffect(() => {
    const unsub = api()?.notifications?.onAuditEvent?.((evt: AuditEvent) => {
      if (!paused) {
        setEvents(prev => {
          const next = [...prev, evt];
          return next.length > MAX_AUDIT_BUFFER ? next.slice(-MAX_AUDIT_BUFFER) : next;
        });
      }
    });
    return () => unsub?.();
  }, [paused]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScrollRef.current && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

  const handleScroll = useCallback(() => {
    if (!scrollRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
    autoScrollRef.current = scrollHeight - scrollTop - clientHeight < 60;
  }, []);

  const filtered = filter ? events.filter(e => e.module === filter) : events;
  const modules = Array.from(new Set(events.map(e => e.module)));

  return (
    <div style={{
      borderRadius: 12,
      border: '1px solid rgba(0,240,255,0.12)',
      background: 'linear-gradient(180deg, rgba(4,4,20,0.95), rgba(8,8,28,0.98))',
      overflow: 'hidden',
      fontFamily: 'var(--s-font-mono, "JetBrains Mono", "Fira Code", monospace)',
    }}>
      {/* Header Bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: compact ? '6px 10px' : '8px 14px',
        borderBottom: '1px solid rgba(0,240,255,0.08)',
        background: 'rgba(0,240,255,0.03)',
      }}>
        <div style={{
          width: 7, height: 7, borderRadius: '50%',
          background: paused ? '#ffaa00' : '#00ff88',
          boxShadow: `0 0 8px ${paused ? '#ffaa00' : '#00ff88'}`,
          animation: paused ? 'none' : 'pulse-green 2s ease-in-out infinite',
        }} />
        <span style={{
          fontSize: '0.6875rem', fontWeight: 700, color: 'rgba(0,240,255,0.8)',
          letterSpacing: '0.1em', textTransform: 'uppercase',
        }}>
          Live Audit Log
        </span>
        <span style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)' }}>
          {filtered.length} events
        </span>
        <div style={{ flex: 1 }} />

        {/* Module filter pills */}
        {modules.length > 1 && (
          <div style={{ display: 'flex', gap: 3 }}>
            <button
              onClick={() => setFilter(null)}
              style={{
                fontSize: '0.5625rem', padding: '2px 6px', borderRadius: 4,
                background: !filter ? 'rgba(0,240,255,0.15)' : 'transparent',
                border: `1px solid ${!filter ? 'rgba(0,240,255,0.3)' : 'rgba(255,255,255,0.06)'}`,
                color: !filter ? '#60f0ff' : 'var(--s-text-dim)',
                cursor: 'pointer', fontFamily: 'inherit',
              }}
            >
              ALL
            </button>
            {modules.map(m => (
              <button
                key={m}
                onClick={() => setFilter(filter === m ? null : m)}
                style={{
                  fontSize: '0.5625rem', padding: '2px 6px', borderRadius: 4,
                  background: filter === m ? `${MODULE_COLORS[m] || '#94a3b8'}15` : 'transparent',
                  border: `1px solid ${filter === m ? `${MODULE_COLORS[m] || '#94a3b8'}40` : 'rgba(255,255,255,0.06)'}`,
                  color: filter === m ? MODULE_COLORS[m] || '#94a3b8' : 'var(--s-text-dim)',
                  cursor: 'pointer', fontFamily: 'inherit', textTransform: 'uppercase',
                }}
              >
                {m}
              </button>
            ))}
          </div>
        )}

        <button
          onClick={() => setPaused(!paused)}
          style={{
            fontSize: '0.625rem', padding: '2px 8px', borderRadius: 4,
            background: paused ? 'rgba(255,170,0,0.12)' : 'rgba(255,255,255,0.04)',
            border: `1px solid ${paused ? 'rgba(255,170,0,0.3)' : 'rgba(255,255,255,0.08)'}`,
            color: paused ? '#ffaa00' : 'var(--s-text-dim)',
            cursor: 'pointer', fontFamily: 'inherit',
          }}
        >
          {paused ? '\u25b6 Resume' : '\u23f8 Pause'}
        </button>
        <button
          onClick={() => { setEvents([]); }}
          style={{
            fontSize: '0.625rem', padding: '2px 8px', borderRadius: 4,
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.08)',
            color: 'var(--s-text-dim)',
            cursor: 'pointer', fontFamily: 'inherit',
          }}
        >
          Clear
        </button>
      </div>

      {/* Event Stream */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        style={{
          maxHeight, overflowY: 'auto', overflowX: 'hidden',
          padding: compact ? '4px 0' : '6px 0',
          scrollBehavior: 'smooth',
        }}
      >
        {filtered.length === 0 && (
          <div style={{
            textAlign: 'center', padding: 32,
            color: 'var(--s-text-dim)', fontSize: '0.75rem',
          }}>
            Waiting for audit events... Run a scan or apply a fix.
          </div>
        )}
        <AnimatePresence initial={false}>
          {filtered.map((evt, i) => {
            const isStart = evt.action.includes('start');
            const isDone = evt.action.includes('done');
            const isCheck = evt.action === 'check';
            const modColor = MODULE_COLORS[evt.module] || '#94a3b8';
            const sevColor = SEVERITY_COLORS[evt.severity] || '#94a3b8';
            const sevIcon = SEVERITY_ICONS[evt.severity] || '\u25cf';

            return (
              <motion.div
                key={`${evt.ts}-${i}`}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.15 }}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 6,
                  padding: compact ? '1px 10px' : '2px 14px',
                  fontSize: compact ? '0.6875rem' : '0.75rem',
                  lineHeight: 1.5,
                  background: isStart ? 'rgba(0,240,255,0.02)' : isDone ? 'rgba(0,255,136,0.02)' : 'transparent',
                  borderLeft: isStart || isDone ? `2px solid ${modColor}33` : '2px solid transparent',
                }}
              >
                {/* Timestamp */}
                <span style={{
                  color: 'rgba(148,163,184,0.5)', fontSize: '0.625rem',
                  fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap',
                  minWidth: compact ? 52 : 58, flexShrink: 0, marginTop: 1,
                }}>
                  {formatTime(evt.ts)}
                </span>

                {/* Severity icon */}
                <span style={{
                  color: sevColor, fontSize: '0.6875rem', fontWeight: 700,
                  minWidth: 12, textAlign: 'center', flexShrink: 0, marginTop: 1,
                  textShadow: `0 0 4px ${sevColor}44`,
                }}>
                  {sevIcon}
                </span>

                {/* Module badge */}
                <span style={{
                  fontSize: '0.5625rem', padding: '1px 5px', borderRadius: 3,
                  background: `${modColor}12`, border: `1px solid ${modColor}25`,
                  color: modColor, fontWeight: 600, letterSpacing: '0.04em',
                  textTransform: 'uppercase', whiteSpace: 'nowrap', flexShrink: 0,
                }}>
                  {evt.module}
                </span>

                {/* Message */}
                <span style={{
                  color: isCheck
                    ? (evt.severity === 'success' ? 'rgba(0,255,136,0.85)' : evt.severity === 'error' ? 'rgba(255,68,102,0.85)' : 'rgba(255,170,0,0.85)')
                    : isDone ? '#00ff88'
                    : isStart ? 'rgba(0,240,255,0.7)'
                    : '#cbd5e1',
                  fontWeight: isDone || isStart ? 600 : 400,
                  wordBreak: 'break-word',
                }}>
                  {evt.message}
                </span>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </div>
  );
};

const MAX_AUDIT_BUFFER = 500;

export default LiveAuditLog;
