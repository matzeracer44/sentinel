/**
 * SENTINEL — Live Audit Log
 * Real-time terminal-style feed showing scan checks, fix applications,
 * IP blocks, process kills, and all system audit events as they happen.
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const MAX_AUDIT_BUFFER = 500;

interface AuditEvent {
  ts: number;
  module: string;
  action: string;
  message: string;
  severity: 'info' | 'success' | 'warning' | 'error';
  meta?: Record<string, unknown>;
}

interface LiveAuditLogProps {
  maxHeight?: number;
  compact?: boolean;
  collapsible?: boolean;
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

const LiveAuditLog: React.FC<LiveAuditLogProps> = ({ maxHeight = 400, compact = false, collapsible = false }) => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState(false);
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

  // Count summary for collapsed state
  const passCount = events.filter(e => e.severity === 'success' && e.action === 'check').length;
  const failCount = events.filter(e => e.severity === 'error' && e.action === 'check').length;
  const warnCount = events.filter(e => e.severity === 'warning' && e.action === 'check').length;

  return (
    <div style={{
      background: 'linear-gradient(180deg, rgba(4,4,20,0.95), rgba(8,8,28,0.98))',
      overflow: 'hidden',
      fontFamily: 'var(--s-font-mono, "JetBrains Mono", "Fira Code", monospace)',
    }}>
      {/* Single Header Bar — doubles as collapse toggle */}
      <div
        onClick={collapsible ? () => setCollapsed(!collapsed) : undefined}
        style={{
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '5px 12px',
          borderBottom: collapsed ? 'none' : '1px solid rgba(0,240,255,0.06)',
          background: 'rgba(0,240,255,0.03)',
          cursor: collapsible ? 'pointer' : 'default',
          userSelect: 'none',
        }}
      >
        <div style={{
          width: 6, height: 6, borderRadius: '50%',
          background: paused ? '#ffaa00' : '#00ff88',
          boxShadow: `0 0 6px ${paused ? '#ffaa00' : '#00ff88'}`,
          animation: paused ? 'none' : 'pulse-green 2s ease-in-out infinite',
        }} />
        <span style={{
          fontSize: '0.625rem', fontWeight: 700, color: 'rgba(0,240,255,0.75)',
          letterSpacing: '0.08em', textTransform: 'uppercase',
        }}>
          Live Audit Log
        </span>
        <span style={{ fontSize: '0.5625rem', color: 'var(--s-text-dim)' }}>
          {events.length} events
        </span>

        {/* Collapsed summary counts */}
        {collapsed && events.length > 0 && (
          <div style={{ display: 'flex', gap: 6, marginLeft: 4 }}>
            {passCount > 0 && <span style={{ fontSize: '0.5625rem', color: '#00ff88' }}>{passCount} passed</span>}
            {failCount > 0 && <span style={{ fontSize: '0.5625rem', color: '#ff4466' }}>{failCount} failed</span>}
            {warnCount > 0 && <span style={{ fontSize: '0.5625rem', color: '#ffaa00' }}>{warnCount} warn</span>}
          </div>
        )}

        <div style={{ flex: 1 }} />

        {/* Controls — only when expanded */}
        {!collapsed && (
          <>
            {/* Module filter pills */}
            {modules.length > 1 && (
              <div style={{ display: 'flex', gap: 3 }} onClick={e => e.stopPropagation()}>
                <button
                  onClick={() => setFilter(null)}
                  style={{
                    fontSize: '0.5625rem', padding: '1px 5px', borderRadius: 3,
                    background: !filter ? 'rgba(0,240,255,0.15)' : 'transparent',
                    border: `1px solid ${!filter ? 'rgba(0,240,255,0.25)' : 'rgba(255,255,255,0.06)'}`,
                    color: !filter ? '#60f0ff' : 'var(--s-text-dim)',
                    cursor: 'pointer', fontFamily: 'inherit',
                  }}
                >ALL</button>
                {modules.map(m => (
                  <button
                    key={m}
                    onClick={() => setFilter(filter === m ? null : m)}
                    style={{
                      fontSize: '0.5625rem', padding: '1px 5px', borderRadius: 3,
                      background: filter === m ? `${MODULE_COLORS[m] || '#94a3b8'}15` : 'transparent',
                      border: `1px solid ${filter === m ? `${MODULE_COLORS[m] || '#94a3b8'}40` : 'rgba(255,255,255,0.06)'}`,
                      color: filter === m ? MODULE_COLORS[m] || '#94a3b8' : 'var(--s-text-dim)',
                      cursor: 'pointer', fontFamily: 'inherit', textTransform: 'uppercase',
                    }}
                  >{m}</button>
                ))}
              </div>
            )}

            <div style={{ display: 'flex', gap: 4 }} onClick={e => e.stopPropagation()}>
              <button
                onClick={() => setPaused(!paused)}
                style={{
                  fontSize: '0.5625rem', padding: '1px 6px', borderRadius: 3,
                  background: paused ? 'rgba(255,170,0,0.12)' : 'rgba(255,255,255,0.04)',
                  border: `1px solid ${paused ? 'rgba(255,170,0,0.25)' : 'rgba(255,255,255,0.06)'}`,
                  color: paused ? '#ffaa00' : 'var(--s-text-dim)',
                  cursor: 'pointer', fontFamily: 'inherit',
                }}
              >{paused ? '\u25b6' : '\u23f8'}</button>
              <button
                onClick={() => setEvents([])}
                style={{
                  fontSize: '0.5625rem', padding: '1px 6px', borderRadius: 3,
                  background: 'rgba(255,255,255,0.04)',
                  border: '1px solid rgba(255,255,255,0.06)',
                  color: 'var(--s-text-dim)',
                  cursor: 'pointer', fontFamily: 'inherit',
                }}
              >CLR</button>
            </div>
          </>
        )}

        {collapsible && (
          <span style={{
            fontSize: '0.625rem', color: 'var(--s-text-dim)',
            transition: 'transform 0.2s',
            transform: collapsed ? 'rotate(0deg)' : 'rotate(180deg)',
          }}>
            \u25b4
          </span>
        )}
      </div>

      {/* Event Stream — hidden when collapsed */}
      {!collapsed && (
        <div
          ref={scrollRef}
          onScroll={handleScroll}
          style={{
            height: maxHeight, overflowY: 'auto', overflowX: 'hidden',
            padding: '2px 0',
          }}
        >
          {filtered.length === 0 && (
            <div style={{
              textAlign: 'center', padding: 24,
              color: 'var(--s-text-dim)', fontSize: '0.6875rem',
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
              const detail = isCheck && evt.meta?.detail ? String(evt.meta.detail) : '';

              return (
                <motion.div
                  key={`${evt.ts}-${i}`}
                  initial={{ opacity: 0, x: -6 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.12 }}
                  style={{
                    display: 'flex', alignItems: 'flex-start', gap: 5,
                    padding: compact ? '1px 10px' : '2px 12px',
                    fontSize: '0.6875rem',
                    lineHeight: 1.45,
                    background: isStart ? 'rgba(0,240,255,0.02)' : isDone ? 'rgba(0,255,136,0.02)' : 'transparent',
                    borderLeft: isStart || isDone ? `2px solid ${modColor}33` : '2px solid transparent',
                  }}
                >
                  {/* Timestamp */}
                  <span style={{
                    color: 'rgba(148,163,184,0.45)', fontSize: '0.5625rem',
                    fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap',
                    minWidth: 50, flexShrink: 0, marginTop: 1,
                  }}>
                    {formatTime(evt.ts)}
                  </span>

                  {/* Severity icon */}
                  <span style={{
                    color: sevColor, fontSize: '0.625rem', fontWeight: 700,
                    minWidth: 10, textAlign: 'center', flexShrink: 0, marginTop: 1,
                  }}>
                    {sevIcon}
                  </span>

                  {/* Module badge */}
                  <span style={{
                    fontSize: '0.5rem', padding: '0px 4px', borderRadius: 2,
                    background: `${modColor}10`, border: `1px solid ${modColor}20`,
                    color: modColor, fontWeight: 600, letterSpacing: '0.04em',
                    textTransform: 'uppercase', whiteSpace: 'nowrap', flexShrink: 0,
                    lineHeight: '14px',
                  }}>
                    {evt.module}
                  </span>

                  {/* Message + Detail */}
                  <span style={{ display: 'flex', flexDirection: 'column', gap: 0, minWidth: 0 }}>
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
                    {detail && (
                      <span style={{
                        fontSize: '0.5625rem', color: 'rgba(148,163,184,0.5)',
                        marginTop: -1,
                      }}>
                        {detail}
                      </span>
                    )}
                  </span>
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>
      )}
    </div>
  );
};

export default LiveAuditLog;
