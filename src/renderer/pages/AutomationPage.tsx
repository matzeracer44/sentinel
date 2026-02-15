/**
 * SENTINEL UNIFIED — Automation Page
 * Quick actions, autonomous mode toggle, playbook execution.
 */

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { notify } from '../components/Common/SentinelNotification';
import { useTranslation } from 'react-i18next';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (): any => (window as any).electronAPI;

interface QuickAction {
  id: string;
  label: string;
  icon: string;
  desc: string;
  color: string;
}

const ACTIONS: QuickAction[] = [
  { id: 'gaming', label: 'automation.actions.gamingMode', icon: '🎮', desc: 'automation.actions.gamingModeDesc', color: 'var(--s-cyan)' },
  { id: 'privacy', label: 'automation.actions.privacyMode', icon: '👁', desc: 'automation.actions.privacyModeDesc', color: 'var(--s-magenta)' },
  { id: 'lockdown', label: 'automation.actions.lockdownMode', icon: '🔒', desc: 'automation.actions.lockdownModeDesc', color: 'var(--s-red)' },
  { id: 'performance', label: 'automation.actions.performanceMode', icon: '⚡', desc: 'automation.actions.performanceModeDesc', color: 'var(--s-amber)' },
  { id: 'stealth', label: 'automation.actions.stealthMode', icon: '🥷', desc: 'automation.actions.stealthModeDesc', color: 'var(--s-purple)' },
  { id: 'restore', label: 'automation.actions.restoreDefaults', icon: '↩', desc: 'automation.actions.restoreDefaultsDesc', color: 'var(--s-text-muted)' },
];

const AutomationPage: React.FC = () => {
  const { t } = useTranslation();
  const [autonomousMode, setAutonomousMode] = useState(false);
  const [executing, setExecuting] = useState<string | null>(null);
  const [results, setResults] = useState<Array<{ id: string; label: string; success: boolean; message: string; timestamp: number }>>([]);

  useEffect(() => {
    const fetchConfig = async () => {
      try {
        const r = await api()?.sentinelConfig?.getConfig?.();
        if (r?.data?.autonomousMode !== undefined) setAutonomousMode(r.data.autonomousMode);
      } catch (e: any) { console.warn('[AutomationPage] fetchConfig:', e?.message); }
    };
    fetchConfig();
  }, []);

  const handleAction = async (action: QuickAction) => {
    setExecuting(action.id);
    try {
      const r = await api()?.executeQuickAction?.(action.id);
      const success = r?.success ?? false;
      const message = r?.message || (success ? 'Action completed' : 'Action failed');
      setResults((prev) => [{ id: action.id, label: action.label, success, message, timestamp: Date.now() }, ...prev.slice(0, 9)]);
      if (success) notify.success(`${action.label}: ${message}`);
      else notify.error(`${action.label}: ${message}`);
    } catch (e: any) {
      setResults((prev) => [{ id: action.id, label: action.label, success: false, message: String(e), timestamp: Date.now() }, ...prev.slice(0, 9)]);
      notify.error(`${action.label} failed: ${e?.message || 'Unknown error'}`);
    }
    setExecuting(null);
  };

  const handleToggleAutonomous = async () => {
    try {
      const newVal = !autonomousMode;
      await api()?.sentinelConfig?.setAutonomousMode?.(newVal);
      setAutonomousMode(newVal);
    } catch (e: any) { console.warn('[AutomationPage] toggle mode:', e?.message); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* ─── Spacy Autonomous Mode Toggle ─── */}
      <motion.div
        className="s-card-spacy"
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          borderColor: autonomousMode ? 'rgba(61,255,143,0.25)' : 'var(--s-border)',
          background: autonomousMode
            ? 'linear-gradient(135deg, rgba(61,255,143,0.04), rgba(8,8,28,0.6))'
            : 'var(--s-panel)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 12,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: autonomousMode ? 'rgba(61,255,143,0.1)' : 'rgba(109,120,255,0.06)',
            border: `1px solid ${autonomousMode ? 'rgba(61,255,143,0.2)' : 'rgba(109,120,255,0.12)'}`,
            fontSize: 20,
          }}>
            {autonomousMode ? '⚡' : '🔒'}
          </div>
          <div>
            <div style={{
              fontWeight: 700, fontSize: '1rem',
              fontFamily: 'var(--s-font-display)',
              background: autonomousMode ? 'linear-gradient(90deg, var(--s-green), var(--s-cyan))' : 'var(--s-text)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: autonomousMode ? 'transparent' : 'var(--s-text)',
            }}>
              {t('automation.autonomousMode')}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
              {autonomousMode ? t('automation.autonomousActive') : t('automation.autonomousDisabled')}
            </div>
          </div>
        </div>
        <button
          className={`s-btn ${autonomousMode ? 's-btn-primary' : 's-btn-ghost'}`}
          onClick={handleToggleAutonomous}
          style={{
            minWidth: 120, borderRadius: 10,
            boxShadow: autonomousMode ? '0 0 16px rgba(61,255,143,0.15)' : 'none',
          }}
        >
          {autonomousMode ? `✓ ${t('common.enabled')}` : t('common.enable')}
        </button>
      </motion.div>

      {/* ─── Spacy Quick Actions Grid ─── */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
          <span style={{
            fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)',
            background: 'linear-gradient(90deg, var(--s-cyan), rgba(167,139,250,0.8))',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          }}>{t('dashboard.quickActions')}</span>
          <div className="s-section-divider" style={{ flex: 1 }} />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
          {ACTIONS.map((action, i) => (
            <motion.div
              key={action.id}
              className="s-card-spacy"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.05 + i * 0.03 }}
              whileHover={{ borderColor: `${action.color}40`, y: -2, boxShadow: `0 4px 24px ${action.color}12` }}
              style={{ cursor: executing ? 'wait' : 'pointer', display: 'flex', flexDirection: 'column', gap: 10 }}
              onClick={() => !executing && handleAction(action)}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{
                  width: 38, height: 38, borderRadius: 10,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: `${action.color}10`, border: `1px solid ${action.color}22`,
                  fontSize: 20, filter: `drop-shadow(0 0 8px ${action.color}40)`,
                }}>
                  {action.icon}
                </div>
                <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>{t(action.label)}</div>
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--s-text-muted)', lineHeight: 1.5, flex: 1 }}>{t(action.desc)}</div>
              <div style={{ width: '100%', height: 2, borderRadius: 1, background: `linear-gradient(90deg, ${action.color}55, transparent)` }} />
              {executing === action.id && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.65rem', color: action.color }}>
                  <span className="s-loading-spinner-sm" style={{ borderTopColor: action.color }} /> {t('common.loading')}
                </div>
              )}
            </motion.div>
          ))}
        </div>
      </div>

      {/* ─── Spacy Execution Log ─── */}
      {results.length > 0 && (
        <motion.div className="s-card-spacy" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
            <span style={{
              fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)',
              background: 'linear-gradient(90deg, var(--s-cyan), rgba(167,139,250,0.8))',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            }}>{t('automation.executionLog')}</span>
            <div className="s-section-divider" style={{ flex: 1 }} />
            <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>{results.length} entries</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {results.map((r, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px',
                borderRadius: 'var(--s-radius-sm)',
                background: i % 2 === 0 ? 'rgba(109,120,255,0.02)' : 'transparent',
              }}>
                <span style={{
                  width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
                  background: r.success ? 'var(--s-green)' : 'var(--s-red)',
                  boxShadow: `0 0 6px ${r.success ? 'var(--s-green)' : 'var(--s-red)'}`,
                }} />
                <span style={{ fontWeight: 600, fontSize: '0.8rem', minWidth: 120 }}>{r.label}</span>
                <span style={{ flex: 1, fontSize: '0.7rem', color: 'var(--s-text-muted)' }}>{r.message}</span>
                <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)' }}>
                  {new Date(r.timestamp).toLocaleTimeString('de-DE')}
                </span>
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default AutomationPage;
