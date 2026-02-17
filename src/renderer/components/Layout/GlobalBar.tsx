/**
 * SENTINEL — Global Activity & Undo/Redo Bar
 * Persistent footer bar visible on ALL pages showing:
 * - Last activity entry (scrolling)
 * - Undo/Redo buttons for firewall actions
 * - ARGUS status indicator
 * - Quick system stats
 */

import React, { useState, useEffect, useCallback } from 'react';
import InfoBadge from '../Common/InfoBadge';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (): any => (window as any).electronAPI;

interface ActivityEntry {
  module: string;
  action: string;
  details: string;
  severity: string;
  timestamp: string;
}

interface UndoRedoState {
  canUndo: boolean;
  canRedo: boolean;
  undoCount: number;
  redoCount: number;
}

const sevDot = (s: string) => {
  if (s === 'error') return 'var(--s-red)';
  if (s === 'warning') return 'var(--s-amber)';
  if (s === 'success') return 'var(--s-green)';
  return 'var(--s-text-dim)';
};

const GlobalBar: React.FC = () => {
  const [lastActivity, setLastActivity] = useState<ActivityEntry | null>(null);
  const [undoRedo, setUndoRedo] = useState<UndoRedoState>({ canUndo: false, canRedo: false, undoCount: 0, redoCount: 0 });
  const [argusOnline, setArgusOnline] = useState<boolean | null>(null);
  const [osopActive, setOsopActive] = useState<boolean | null>(null);
  const [mfaEnabled, setMfaEnabled] = useState<boolean>(false);

  const fetchState = useCallback(async () => {
    try {
      const a = api();
      if (a?.getActivityLog) {
        const log = await a.getActivityLog();
        if (Array.isArray(log) && log.length > 0) setLastActivity(log[0] as ActivityEntry);
      }
      if (a?.shield?.getUndoRedoState) {
        const s = await a.shield.getUndoRedoState();
        if (s) setUndoRedo(s as UndoRedoState);
      }
      if (a?.argus?.getHealth) {
        const h = await a.argus.getHealth();
        setArgusOnline(h?.data?.status === 'running');
      }
      if (a?.osop?.getSession) {
        const s = await a.osop.getSession();
        setOsopActive(s?.success && !!s?.sessionId);
      }
      if (a?.totp?.getStatus) {
        const t = await a.totp.getStatus();
        setMfaEnabled(!!t?.enabled);
      }
    } catch (e: any) { console.warn('[GlobalBar] fetchState:', e?.message); }
  }, []);

  useEffect(() => {
    fetchState();
    const i = setInterval(fetchState, 6000);
    return () => clearInterval(i);
  }, [fetchState]);

  const handleUndo = async () => {
    try { await api()?.shield?.undoFirewall?.(); fetchState(); } catch (e: any) { console.warn('[GlobalBar] undo:', e?.message); }
  };
  const handleRedo = async () => {
    try { await api()?.shield?.redoFirewall?.(); fetchState(); } catch (e: any) { console.warn('[GlobalBar] redo:', e?.message); }
  };

  return (
    <footer className="app-globalbar" style={{ position: 'relative' }}>
      {/* Top gradient line */}
      <div style={{
        position: 'absolute', top: 0, left: '5%', right: '5%', height: 1,
        background: 'linear-gradient(90deg, transparent, rgba(60,240,255,0.1), rgba(167,139,250,0.08), transparent)',
      }} />

      {/* Undo / Redo — Premium pills */}
      <div style={{ display: 'flex', gap: 3, flexShrink: 0 }}>
        <button
          style={{
            padding: '2px 8px', fontSize: '0.6rem', fontWeight: 600,
            background: undoRedo.canUndo ? 'rgba(60,240,255,0.06)' : 'transparent',
            border: `1px solid ${undoRedo.canUndo ? 'rgba(60,240,255,0.18)' : 'rgba(109,120,255,0.1)'}`,
            borderRadius: 6, color: undoRedo.canUndo ? 'var(--s-cyan)' : 'var(--s-text-dim)',
            cursor: undoRedo.canUndo ? 'pointer' : 'default',
            transition: 'all 0.15s', opacity: undoRedo.canUndo ? 1 : 0.4,
          }}
          disabled={!undoRedo.canUndo}
          onClick={handleUndo}
          title="Undo last firewall action"
        >
          ↩ {undoRedo.undoCount > 0 ? undoRedo.undoCount : ''}
        </button>
        <button
          style={{
            padding: '2px 8px', fontSize: '0.6rem', fontWeight: 600,
            background: undoRedo.canRedo ? 'rgba(60,240,255,0.06)' : 'transparent',
            border: `1px solid ${undoRedo.canRedo ? 'rgba(60,240,255,0.18)' : 'rgba(109,120,255,0.1)'}`,
            borderRadius: 6, color: undoRedo.canRedo ? 'var(--s-cyan)' : 'var(--s-text-dim)',
            cursor: undoRedo.canRedo ? 'pointer' : 'default',
            transition: 'all 0.15s', opacity: undoRedo.canRedo ? 1 : 0.4,
          }}
          disabled={!undoRedo.canRedo}
          onClick={handleRedo}
          title="Redo last firewall action"
        >
          ↪ {undoRedo.redoCount > 0 ? undoRedo.redoCount : ''}
        </button>
      </div>

      <div style={{ width: 1, height: 14, background: 'linear-gradient(180deg, transparent, rgba(109,120,255,0.15), transparent)', flexShrink: 0 }} />

      {/* Last Activity — ticker */}
      <div style={{ flex: 1, overflow: 'hidden', display: 'flex', alignItems: 'center', gap: 6 }}>
        {lastActivity ? (
          <>
            <span style={{
              width: 5, height: 5, borderRadius: '50%', flexShrink: 0,
              background: sevDot(lastActivity.severity),
              boxShadow: `0 0 5px ${sevDot(lastActivity.severity)}`,
            }} />
            <span style={{ fontWeight: 600, color: 'var(--s-text-secondary)', flexShrink: 0 }}>
              {lastActivity.module}
            </span>
            <span style={{
              color: 'var(--s-text-dim)', flexShrink: 0,
              padding: '0 4px', fontSize: '0.6rem', borderRadius: 3,
              background: 'rgba(109,120,255,0.04)',
            }}>
              {lastActivity.action}
            </span>
            <span style={{
              color: 'var(--s-text-muted)', overflow: 'hidden',
              textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1,
            }}>
              {lastActivity.details}
            </span>
            <span style={{ color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)', fontSize: '0.575rem', flexShrink: 0 }}>
              {lastActivity.timestamp ? new Date(lastActivity.timestamp).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : ''}
            </span>
          </>
        ) : (
          <span style={{ color: 'var(--s-text-dim)', fontStyle: 'italic', fontSize: '0.625rem' }}>Awaiting activity...</span>
        )}
      </div>

      <div style={{ width: 1, height: 14, background: 'linear-gradient(180deg, transparent, rgba(109,120,255,0.15), transparent)', flexShrink: 0 }} />

      {/* OSOP Session — clickable ephemeral trust indicator */}
      {osopActive && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
          <span style={{
            width: 5, height: 5, borderRadius: '50%', background: '#00e676',
            boxShadow: '0 0 6px #00e676',
            animation: 'pulse-green 2s ease-in-out infinite',
          }} />
          <InfoBadge glossaryKey="OSOP" label="Einmal-Sitzung" size="xs" />
        </div>
      )}

      {/* MFA Status — clickable TOTP indicator */}
      {mfaEnabled && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
          <span style={{
            width: 5, height: 5, borderRadius: '50%', background: 'var(--s-cyan)',
            boxShadow: '0 0 6px var(--s-cyan)',
          }} />
          <InfoBadge glossaryKey="MFA" label="Zwei-Faktor" size="xs" />
        </div>
      )}

      <div style={{ width: 1, height: 14, background: 'linear-gradient(180deg, transparent, rgba(109,120,255,0.15), transparent)', flexShrink: 0 }} />

      {/* ARGUS Status — premium indicator */}
      {argusOnline ? (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0,
          padding: '2px 8px', borderRadius: 8,
          background: 'rgba(61,255,143,0.06)', border: '1px solid rgba(61,255,143,0.15)',
        }}>
          <span style={{
            width: 5, height: 5, borderRadius: '50%', background: 'var(--s-green)',
            boxShadow: '0 0 6px var(--s-green)',
            animation: 'pulse-green 2s ease-in-out infinite',
          }} />
          <span style={{ color: 'var(--s-green)', fontSize: '0.6rem', fontWeight: 700, letterSpacing: '0.04em' }}>ARGUS</span>
        </div>
      ) : (
        <button
          onClick={async () => {
            try {
              const r = await api()?.argus?.start?.();
              if (r?.success) setArgusOnline(true);
            } catch (e: any) { console.warn('[GlobalBar] ARGUS start:', e?.message); }
            fetchState();
          }}
          style={{
            display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0,
            padding: '2px 10px', borderRadius: 8, cursor: 'pointer',
            border: '1px solid rgba(255,95,95,0.25)', background: 'rgba(255,95,95,0.06)',
            color: 'var(--s-red)', fontSize: '0.6rem', fontWeight: 700,
            transition: 'all 0.15s', letterSpacing: '0.03em',
          }}
          onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(255,95,95,0.14)'; e.currentTarget.style.boxShadow = '0 0 12px rgba(255,95,95,0.15)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = 'rgba(255,95,95,0.06)'; e.currentTarget.style.boxShadow = 'none'; }}
          title="Click to start ARGUS backend"
        >
          <span style={{
            width: 5, height: 5, borderRadius: '50%', background: 'var(--s-red)',
            animation: 'pulse-red 1.5s ease-in-out infinite',
          }} />
          START ARGUS
        </button>
      )}
    </footer>
  );
};

export default GlobalBar;
