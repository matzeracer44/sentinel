/**
 * SENTINEL UNIFIED — Firewall Page
 * Full rule management with row-actions, bulk selection, detail modal,
 * IP/port/subnet blocking, undo/redo, pending rules, sentinel rules.
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { notify } from '../components/Common/SentinelNotification';
import InfoBadge from '../components/Common/InfoBadge';
import { useTranslation } from 'react-i18next';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (): any => (window as any).electronAPI;

interface FirewallRule {
  name: string;
  direction: string;
  action: string;
  enabled: string | boolean;
  protocol: string;
  remoteAddress: string;
  localPort: string | number;
  remotePort?: string | number;
  profile?: string;
  description?: string;
  program?: string;
  timeCreated?: string | null;
}

interface PendingRule {
  id: string;
  processName: string;
  remoteIP: string;
  reasons: string[];
  recommendsBlock: boolean;
  expiresAt: number;
  status: string;
}

interface UndoRedoState {
  canUndo: boolean;
  canRedo: boolean;
  undoCount: number;
  redoCount: number;
}

type Tab = 'rules' | 'block' | 'pending' | 'sentinel';

const isEnabled = (v: string | boolean): boolean => v === true || v === 'True' || v === 'true';

/** Normalize direction — PowerShell returns localized strings on non-EN Windows */
const isInbound = (d: string): boolean =>
  d === 'Inbound' || d === 'Eingehend' || d?.toLowerCase() === 'inbound' || d?.toLowerCase() === 'eingehend';
const dirLabel = (d: string): string => isInbound(d) ? 'IN' : 'OUT';
const dirBadge = (d: string): string => isInbound(d) ? 's-badge-cyan' : 's-badge-purple';

type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

function assessRuleRisk(rule: FirewallRule): { level: RiskLevel; reasons: string[]; score: number } {
  const reasons: string[] = [];
  let score = 0;

  // Allow inbound = risky
  if (isInbound(rule.direction) && rule.action === 'Allow') {
    score += 3;
    reasons.push('Allows inbound traffic');
  }

  // Any protocol = wide open
  if (!rule.protocol || rule.protocol === 'Any' || rule.protocol === '256') {
    score += 2;
    reasons.push('Any protocol');
  }

  // No program restriction
  if (!rule.program) {
    score += 1;
    reasons.push('No program restriction');
  }

  // All profiles = wider exposure
  if (rule.profile && rule.profile.toLowerCase().includes('public')) {
    score += 2;
    reasons.push('Active on Public profile');
  }

  // Remote address = Any
  if (!rule.remoteAddress || rule.remoteAddress === 'Any' || rule.remoteAddress === '*') {
    if (isInbound(rule.direction) && rule.action === 'Allow') {
      score += 2;
      reasons.push('Any remote address');
    }
  }

  // Port 0 or Any = all ports
  if (!rule.localPort || rule.localPort === 'Any' || Number(rule.localPort) === 0) {
    if (rule.action === 'Allow') {
      score += 1;
      reasons.push('All ports');
    }
  }

  const level: RiskLevel = score >= 7 ? 'critical' : score >= 5 ? 'high' : score >= 3 ? 'medium' : 'low';
  return { level, reasons, score };
}

const RISK_COLORS: Record<RiskLevel, string> = {
  low: 's-badge-green',
  medium: 's-badge-amber',
  high: 's-badge-red',
  critical: 's-badge-red',
};

const FirewallPage: React.FC = () => {
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const navState = (location.state || {}) as { prefillIP?: string; source?: string; process?: string; pid?: number };

  const [tab, setTab] = useState<Tab>(navState.prefillIP ? 'block' : 'rules');
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [pendingRules, setPendingRules] = useState<PendingRule[]>([]);
  const [sentinelRules, setSentinelRules] = useState<string[]>([]);
  const [undoRedo, setUndoRedo] = useState<UndoRedoState>({ canUndo: false, canRedo: false, undoCount: 0, redoCount: 0 });
  const [loading, setLoading] = useState(false);
  const [searchFilter, setSearchFilter] = useState('');
  const [directionFilter, setDirectionFilter] = useState<'all' | 'inbound' | 'outbound'>('all');

  // Bulk selection
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // Detail modal
  const [detailRule, setDetailRule] = useState<FirewallRule | null>(null);

  // Block controls — pre-fill from cross-link navigation
  const [blockIp, setBlockIp] = useState(navState.prefillIP || '');
  const [blockReason, setBlockReason] = useState('');
  const [blockPortVal, setBlockPortVal] = useState('');
  const [blockProtocol, setBlockProtocol] = useState<'TCP' | 'UDP' | 'Any'>('TCP');
  const [blockDirection, setBlockDirection] = useState<'in' | 'out' | 'both'>('both');
  const [blockSubnet, setBlockSubnet] = useState('');
  const [blockPid, setBlockPid] = useState('');
  const [blockResult, setBlockResult] = useState<{ success: boolean; message: string } | null>(null);

  // Adaptive Access / Kill-Switch state
  const [adaptiveState, setAdaptiveState] = useState<{ enabled: boolean; restricted: boolean; lastHealthScore: number | null; lastCheckAt: string | null } | null>(null);

  // ─── Data fetching ───
  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const a = api();
      if (a?.shield?.getFirewallRules) {
        const r = await a.shield.getFirewallRules();
        if (Array.isArray(r)) setRules(r);
        else if (r?.rules && Array.isArray(r.rules)) setRules(r.rules);
      }
      if (a?.shield?.getUndoRedoState) {
        const s = await a.shield.getUndoRedoState();
        if (s) setUndoRedo(s as UndoRedoState);
      }
      if (a?.shield?.getPendingRules) {
        const p = await a.shield.getPendingRules();
        if (p?.pendingRules) setPendingRules(p.pendingRules);
      }
      if (a?.shield?.getSentinelRules) {
        const sr = await a.shield.getSentinelRules();
        if (sr?.rules) setSentinelRules(sr.rules);
      }
      // Fetch adaptive access state
      if (a?.adaptive?.getState) {
        const st = await a.adaptive.getState();
        if (st) setAdaptiveState(st as any);
      }
    } catch (e: any) { console.warn('[FirewallPage] fetchData:', e?.message); }
    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // ─── Rule stats ───
  const ruleStats = useMemo(() => {
    const inbound = rules.filter((r) => isInbound(r.direction)).length;
    const outbound = rules.filter((r) => !isInbound(r.direction)).length;
    const blocked = rules.filter((r) => r.action === 'Block').length;
    const disabled = rules.filter((r) => !isEnabled(r.enabled)).length;
    return { inbound, outbound, blocked, disabled };
  }, [rules]);

  // ─── Filtered rules ───
  const filteredRules = useMemo(() => rules.filter((r) => {
    if (directionFilter === 'inbound' && !isInbound(r.direction)) return false;
    if (directionFilter === 'outbound' && isInbound(r.direction)) return false;
    if (!searchFilter) return true;
    const q = searchFilter.toLowerCase();
    return r.name?.toLowerCase().includes(q) ||
      r.remoteAddress?.toLowerCase().includes(q) ||
      r.protocol?.toLowerCase().includes(q) ||
      r.description?.toLowerCase().includes(q);
  }), [rules, searchFilter, directionFilter]);

  // ─── Row actions ───
  const handleDeleteRule = async (ruleName: string) => {
    // Optimistic removal — remove from UI immediately
    setRules(prev => prev.filter(r => r.name !== ruleName));
    setSelected(prev => { const next = new Set(prev); next.delete(ruleName); return next; });
    try {
      await api()?.shield?.deleteFirewallRule?.(ruleName);
      notify.success(`Deleted rule: ${ruleName}`);
      await fetchData();
    } catch (e: any) {
      notify.error(e?.message || `Failed to delete ${ruleName}`);
      await fetchData();
    }
  };

  const handleToggleRule = async (ruleName: string, currentEnabled: boolean) => {
    try {
      await api()?.shield?.enableFirewallRule?.(ruleName, !currentEnabled);
      notify.success(`${currentEnabled ? 'Disabled' : 'Enabled'} rule: ${ruleName}`);
      fetchData();
    } catch (e: any) { notify.error(e?.message || `Failed to toggle ${ruleName}`); }
  };

  // ─── Bulk actions ───
  const handleBulkDelete = async () => {
    const toDelete = new Set(selected);
    // Optimistic removal
    setRules(prev => prev.filter(r => !toDelete.has(r.name)));
    setSelected(new Set());
    for (const name of toDelete) {
      try { await api()?.shield?.deleteFirewallRule?.(name); } catch (e: any) { notify.error(`Delete ${name}: ${e?.message}`); }
    }
    notify.success(`Deleted ${toDelete.size} rules`);
    await fetchData();
  };

  const handleBulkDisable = async () => {
    for (const name of selected) {
      try { await api()?.shield?.enableFirewallRule?.(name, false); } catch (e: any) { notify.error(`Disable ${name}: ${e?.message}`); }
    }
    notify.success(`Disabled ${selected.size} rules`);
    setSelected(new Set());
    fetchData();
  };

  const toggleSelect = (name: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selected.size === filteredRules.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filteredRules.map((r) => r.name)));
    }
  };

  // ─── Block handlers ───
  const handleBlockIp = async () => {
    if (!blockIp.trim()) return;
    try {
      const result = await api()?.shield?.blockIP?.(blockIp.trim(), blockReason.trim() || 'Manual block');
      setBlockResult(result as { success: boolean; message: string });
      if (result?.success) { setBlockIp(''); setBlockReason(''); fetchData(); }
    } catch (e) { setBlockResult({ success: false, message: String(e) }); }
  };

  const handleBlockPort = async () => {
    const port = parseInt(blockPortVal, 10);
    if (isNaN(port) || port < 0 || port > 65535) return;
    try {
      const result = await api()?.shield?.blockPort?.({ port, protocol: blockProtocol, direction: blockDirection });
      setBlockResult(result as { success: boolean; message: string });
      if (result?.success) { setBlockPortVal(''); fetchData(); }
    } catch (e) { setBlockResult({ success: false, message: String(e) }); }
  };

  const handleBlockSubnet = async () => {
    if (!blockSubnet.trim()) return;
    try {
      const [ip, mask] = blockSubnet.split('/');
      const result = await api()?.shield?.blockIPSubnet?.(ip.trim(), parseInt(mask || '24', 10));
      setBlockResult(result as { success: boolean; message: string });
      if (result?.success) { setBlockSubnet(''); fetchData(); }
    } catch (e) { setBlockResult({ success: false, message: String(e) }); }
  };

  const handleBlockPid = async () => {
    const pid = parseInt(blockPid, 10);
    if (isNaN(pid)) return;
    try {
      const result = await api()?.shield?.blockPid?.({ pid });
      setBlockResult(result as { success: boolean; message: string });
      if (result?.success) { setBlockPid(''); fetchData(); }
    } catch (e) { setBlockResult({ success: false, message: String(e) }); }
  };

  const handleUndo = async () => { await api()?.shield?.undoFirewall?.(); fetchData(); };
  const handleRedo = async () => { await api()?.shield?.redoFirewall?.(); fetchData(); };

  const TABS: { key: Tab; labelKey: string; count?: number }[] = [
    { key: 'rules', labelKey: 'firewall.tabs.rules', count: rules.length },
    { key: 'block', labelKey: 'firewall.tabs.blocking', count: undefined },
    { key: 'pending', labelKey: 'firewall.tabs.pending', count: pendingRules.length },
    { key: 'sentinel', labelKey: 'firewall.tabs.sentinel', count: sentinelRules.length },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ═══ Rule Statistics Strip ═══ */}
      <motion.div
        className="s-threat-strip"
        initial={{ opacity: 0, y: -6 }}
        animate={{ opacity: 1, y: 0 }}
      >
        {[
          { label: 'Regeln gesamt', value: String(rules.length), color: 'var(--s-cyan)', icon: '📋' },
          { label: 'Eingehend', value: String(ruleStats.inbound), color: 'var(--s-cyan)', icon: '⬇' },
          { label: 'Ausgehend', value: String(ruleStats.outbound), color: 'var(--s-purple)', icon: '⬆' },
          { label: 'Blockiert', value: String(ruleStats.blocked), color: 'var(--s-red)', icon: '🚫' },
          { label: 'Deaktiviert', value: String(ruleStats.disabled), color: 'var(--s-amber)', icon: '⏸' },
          { label: 'Sentinel', value: String(sentinelRules.length), color: 'var(--s-green)', icon: '🛡' },
        ].map((item) => (
          <div key={item.label} className="s-threat-strip-item">
            <span style={{ fontSize: '0.9rem' }}>{item.icon}</span>
            <div>
              <div style={{ fontSize: '0.95rem', fontWeight: 800, fontFamily: 'var(--s-font-display)', color: item.color, lineHeight: 1 }}>
                {item.value}
              </div>
              <div style={{ fontSize: '0.525rem', color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em', marginTop: 2 }}>
                {item.label}
              </div>
            </div>
          </div>
        ))}
      </motion.div>

      {/* ═══ Adaptive Access / Kill-Switch ═══ */}
      {adaptiveState && (
        <motion.div
          initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
          className={adaptiveState.restricted ? 's-callout s-callout-danger' : 's-callout s-callout-success'}
          style={{
            padding: '14px 18px', borderRadius: 12,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              width: 40, height: 40, borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: adaptiveState.restricted ? 'rgba(255,95,95,0.12)' : 'rgba(61,255,143,0.1)',
              border: `1px solid ${adaptiveState.restricted ? 'rgba(255,95,95,0.2)' : 'rgba(61,255,143,0.15)'}`,
              fontSize: '1.1rem',
            }}>
              {adaptiveState.restricted ? '🚨' : '🛡'}
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontWeight: 700, fontSize: '0.85rem', color: adaptiveState.restricted ? 'var(--s-red)' : 'var(--s-green)' }}>
                  {adaptiveState.restricted ? 'NETZWERK ISOLIERT' : 'Adaptiver Zugriffsschutz'}
                </span>
                <InfoBadge glossaryKey="DSGVO Art.5" />
              </div>
              <div style={{ fontSize: '0.65rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                {'Systemzustand: '}{adaptiveState.lastHealthScore ?? '?'}{'%'}
                {adaptiveState.lastCheckAt && ` · Letzte Pr\u00fcfung: ${new Date(adaptiveState.lastCheckAt).toLocaleTimeString('de-DE')}`}
                {adaptiveState.restricted && ' · Ausgehender Datenverkehr blockiert'}
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 6, flexShrink: 0, alignItems: 'center' }}>
            {adaptiveState.restricted ? (
              <button className="s-btn s-btn-sm s-btn-ghost" style={{ borderColor: 'rgba(61,255,143,0.2)' }} onClick={async () => {
                try {
                  const r = await api()?.adaptive?.lift?.();
                  if (r?.success) { notify.success('Netzwerkeinschränkung aufgehoben'); fetchData(); }
                  else notify.error(r?.error || 'Fehler beim Aufheben');
                } catch (e: any) { notify.error(e?.message || 'Fehler'); }
              }}>{'Einschr\u00e4nkung aufheben'}</button>
            ) : (
              <button className="s-btn s-btn-sm s-btn-ghost" style={{ borderColor: 'rgba(255,95,95,0.2)' }} onClick={async () => {
                try {
                  const r = await api()?.adaptive?.restrict?.();
                  if (r?.success) { notify.warning('Netzwerk isoliert — Kill-Switch aktiviert'); fetchData(); }
                  else notify.error(r?.error || 'Fehler bei Isolierung');
                } catch (e: any) { notify.error(e?.message || 'Fehler'); }
              }}>Manuell isolieren</button>
            )}
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', userSelect: 'none' }}>
              <div
                onClick={async () => {
                  try {
                    const enabled = !adaptiveState.enabled;
                    const r = await api()?.adaptive?.setConfig?.({ enabled, autoRestrict: enabled });
                    if (r?.success) { notify.info(enabled ? 'Adaptiver Zugriffsschutz aktiviert' : 'Adaptiver Zugriffsschutz deaktiviert'); fetchData(); }
                  } catch (e: any) { notify.error(e?.message || 'Fehler'); }
                }}
                style={{
                  width: 36, height: 20, borderRadius: 10, position: 'relative',
                  background: adaptiveState.enabled ? 'var(--s-green)' : 'rgba(255,255,255,0.1)',
                  border: `1px solid ${adaptiveState.enabled ? 'rgba(0,230,118,0.4)' : 'rgba(255,255,255,0.15)'}`,
                  transition: 'all 0.2s ease', cursor: 'pointer',
                  boxShadow: adaptiveState.enabled ? '0 0 8px rgba(0,230,118,0.3)' : 'none',
                }}
              >
                <div style={{
                  width: 14, height: 14, borderRadius: '50%', background: '#fff',
                  position: 'absolute', top: 2,
                  left: adaptiveState.enabled ? 19 : 2,
                  transition: 'left 0.2s ease',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
                }} />
              </div>
              <span style={{ fontSize: '0.65rem', color: adaptiveState.enabled ? 'var(--s-green)' : 'var(--s-text-dim)', fontWeight: 600 }}>
                {adaptiveState.enabled ? 'Auto-Schutz aktiv' : 'Auto-Schutz aus'}
              </span>
            </label>
          </div>
        </motion.div>
      )}

      {/* ─── Spacy Header ─── */}
      <div className="s-page-header">
        <div className="s-tab-bar">
          {TABS.map((tb) => (
            <button key={tb.key} className={`s-tab ${tab === tb.key ? 's-tab-active' : ''}`} onClick={() => setTab(tb.key)}>
              {t(tb.labelKey)}
              {tb.count !== undefined && <span className="s-tab-badge">{tb.count}</span>}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <div style={{
            display: 'flex', gap: 2, padding: 2,
            background: 'rgba(8,8,28,0.4)', border: '1px solid var(--s-border)', borderRadius: 8,
          }}>
            <button className="s-btn s-btn-ghost s-btn-sm" style={{ borderRadius: 6, fontSize: '0.65rem', padding: '3px 8px' }} disabled={!undoRedo.canUndo} onClick={handleUndo}>
              ↩ {undoRedo.undoCount > 0 && <span style={{ opacity: 0.6 }}>{undoRedo.undoCount}</span>}
            </button>
            <button className="s-btn s-btn-ghost s-btn-sm" style={{ borderRadius: 6, fontSize: '0.65rem', padding: '3px 8px' }} disabled={!undoRedo.canRedo} onClick={handleRedo}>
              ↪ {undoRedo.redoCount > 0 && <span style={{ opacity: 0.6 }}>{undoRedo.redoCount}</span>}
            </button>
          </div>
          <select
            className="s-select s-input"
            style={{ width: 'auto', padding: '4px 24px 4px 8px', fontSize: '0.65rem', borderRadius: 8, background: 'rgba(8,8,28,0.4)' }}
            defaultValue=""
            onChange={async (e) => {
              const fmt = e.target.value as 'txt' | 'csv' | 'json';
              if (!fmt) return;
              e.target.value = '';
              try {
                const r = await api()?.shield?.exportFirewallRules?.({ format: fmt });
                if (r?.success) notify.success(`Exported rules as ${fmt.toUpperCase()}`);
                else notify.error(r?.error || 'Export failed');
              } catch (err: any) { notify.error(err?.message || 'Export failed'); }
            }}
          >
            <option value="" disabled>Export ↓</option>
            <option value="txt">TXT</option>
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
          </select>
          <button className="s-btn s-btn-primary s-btn-sm" style={{ borderRadius: 8, fontSize: '0.65rem' }} onClick={fetchData} disabled={loading}>
            {loading ? '...' : `↻ ${t('common.refresh')}`}
          </button>
        </div>
      </div>

      {/* Bulk Actions Bar */}
      {selected.size > 0 && tab === 'rules' && (
        <div className="s-bulk-bar">
          <span className="s-bulk-bar-count">{selected.size} {t('common.actions')}</span>
          <button className="s-btn s-btn-danger s-btn-sm" onClick={handleBulkDelete}>{t('common.delete')}</button>
          <button className="s-btn s-btn-ghost s-btn-sm" onClick={handleBulkDisable}>{t('common.disabled')}</button>
          <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => setSelected(new Set())}>{t('common.cancel')}</button>
        </div>
      )}

      <AnimatePresence mode="wait">
        {/* ═══ Rules Tab ═══ */}
        {tab === 'rules' && (
          <motion.div key="rules" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{
              padding: '12px 18px', borderBottom: '1px solid var(--s-border)',
              display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 10,
              background: 'rgba(8,8,28,0.3)',
            }}>
              <div className="s-tab-bar" style={{ padding: 2 }}>
                {(['all', 'inbound', 'outbound'] as const).map((d) => (
                  <button
                    key={d}
                    className={`s-tab ${directionFilter === d ? 's-tab-active' : ''}`}
                    style={{ padding: '4px 10px', fontSize: '0.65rem' }}
                    onClick={() => setDirectionFilter(d)}
                  >
                    {d === 'all' ? `${t('common.all')} (${rules.length})` : d === 'inbound' ? `${t('firewall.rules.inbound')} (${ruleStats.inbound})` : `${t('firewall.rules.outbound')} (${ruleStats.outbound})`}
                  </button>
                ))}
              </div>
              <input className="s-input" placeholder={t('firewall.rules.searchPlaceholder')} value={searchFilter} onChange={(e) => setSearchFilter(e.target.value)} style={{ maxWidth: 320, flex: 1, padding: '5px 10px', fontSize: '0.7rem', borderRadius: 8 }} />
              <div style={{ display: 'flex', gap: 10, fontSize: '0.6rem', color: 'var(--s-text-dim)', marginLeft: 'auto' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--s-red)', boxShadow: '0 0 4px var(--s-red)' }} />
                  Block: <strong style={{ color: 'var(--s-red)' }}>{ruleStats.blocked}</strong>
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--s-text-dim)' }} />
                  Off: <strong>{ruleStats.disabled}</strong>
                </span>
              </div>
            </div>
            <div style={{ maxHeight: 520, overflowY: 'auto' }}>
              <table className="s-table s-table-spacy">
                <thead>
                  <tr>
                    <th style={{ width: 36 }}><input type="checkbox" className="s-checkbox" checked={selected.size > 0 && selected.size === filteredRules.length} onChange={toggleSelectAll} /></th>
                    <th>{t('firewall.rules.name')}</th>
                    <th>{t('firewall.rules.direction')}</th>
                    <th>{t('firewall.rules.action')}</th>
                    <th>{t('scan.riskLevel')}</th>
                    <th>{t('firewall.rules.protocol')}</th>
                    <th>{t('firewall.rules.localPort')}</th>
                    <th>{t('network.processes.name')}</th>
                    <th>{t('firewall.rules.remoteAddress')}</th>
                    <th style={{ width: 120 }}>{t('common.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRules.length === 0 ? (
                    <tr><td colSpan={10} style={{ textAlign: 'center', padding: '32px 24px', color: 'var(--s-text-dim)' }}>
                      {loading ? t('common.loading') : (
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
                          <span style={{ fontSize: '1.5rem', opacity: 0.3 }}>{'\ud83d\udee1'}</span>
                          <div style={{ fontSize: '0.8125rem' }}>{searchFilter ? 'Keine Regeln f\u00fcr diesen Filter gefunden' : t('firewall.rules.noRules')}</div>
                          <div style={{ fontSize: '0.675rem', maxWidth: 440, lineHeight: 1.5, color: 'var(--s-text-dim)' }}>
                            {searchFilter
                              ? 'Versuchen Sie einen anderen Suchbegriff oder entfernen Sie den Filter.'
                              : 'Firewall-Regeln bestimmen, welcher Netzwerkverkehr erlaubt oder blockiert wird. Nutzen Sie den Tab "Block IP/Port/Subnet", um schnell eine neue Blockier-Regel zu erstellen, oder klicken Sie auf "Refresh", um bestehende Windows-Firewall-Regeln zu laden.'}
                          </div>
                        </div>
                      )}
                    </td></tr>
                  ) : filteredRules.slice(0, 200).map((rule, i) => {
                    const en = isEnabled(rule.enabled);
                    const rKey = `${rule.name}-${i}`;
                    const risk = assessRuleRisk(rule);
                    return (
                      <tr key={rKey} style={{ opacity: en ? 1 : 0.5 }}>
                        <td><input type="checkbox" className="s-checkbox" checked={selected.has(rule.name)} onChange={() => toggleSelect(rule.name)} /></td>
                        <td className="s-truncate" style={{ maxWidth: 200, cursor: 'pointer' }} onClick={() => setDetailRule(rule)}>{rule.name || '—'}</td>
                        <td><span className={`s-badge ${dirBadge(rule.direction)}`} style={{ fontSize: '0.6rem' }}>{dirLabel(rule.direction)}</span></td>
                        <td><span className={`s-badge ${rule.action === 'Block' ? 's-badge-red' : 's-badge-green'}`} style={{ fontSize: '0.6rem' }}>{rule.action || '—'}</span></td>
                        <td><span className={`s-badge ${RISK_COLORS[risk.level]}`} style={{ fontSize: '0.6rem' }} title={risk.reasons.join(', ')}>{risk.level.toUpperCase()}</span></td>
                        <td style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem' }}>{rule.protocol || '—'}</td>
                        <td style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem' }}>{rule.localPort || 'Any'}</td>
                        <td className="s-truncate" style={{ maxWidth: 120, fontSize: '0.65rem', color: 'var(--s-text-muted)' }} title={rule.program || ''}>{rule.program ? rule.program.split('\\').pop() : '—'}</td>
                        <td className="s-truncate" style={{ maxWidth: 140, fontFamily: 'var(--s-font-mono)', fontSize: '0.7rem' }}>{rule.remoteAddress || 'Any'}</td>
                        <td>
                          <div style={{ display: 'flex', gap: 4 }}>
                            <button className="s-btn s-btn-ghost s-btn-sm" style={{ padding: '2px 6px', fontSize: '0.7rem' }} onClick={() => handleToggleRule(rule.name, en)} title={en ? 'Disable' : 'Enable'}>{en ? '⏸' : '▶'}</button>
                            <button className="s-btn s-btn-ghost s-btn-sm" style={{ padding: '2px 6px', fontSize: '0.7rem' }} onClick={() => setDetailRule(rule)} title="Details">📋</button>
                            <button className="s-btn s-btn-ghost s-btn-sm" style={{ padding: '2px 6px', fontSize: '0.7rem', color: 'var(--s-red)' }} onClick={() => handleDeleteRule(rule.name)} title="Delete">🗑</button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {filteredRules.length > 200 && (
              <div style={{ padding: '8px 18px', textAlign: 'center', fontSize: '0.75rem', color: 'var(--s-text-dim)', borderTop: '1px solid var(--s-border)' }}>
                {t('common.total')}: {filteredRules.length}
              </div>
            )}
          </motion.div>
        )}

        {/* ═══ Block Controls Tab ═══ */}
        {tab === 'block' && (
          <motion.div key="block" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
            {/* Block IP */}
            <div className="s-card-spacy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-red), var(--s-amber))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>{t('firewall.blocking.blockIP')}</span>
                <div className="s-section-divider" style={{ flex: 1 }} />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <input className="s-input" placeholder="IP address (e.g. 192.168.1.100)" value={blockIp} onChange={(e) => setBlockIp(e.target.value)} />
                <input className="s-input" placeholder="Reason (optional)" value={blockReason} onChange={(e) => setBlockReason(e.target.value)} />
                <button className="s-btn s-btn-danger" onClick={handleBlockIp} disabled={!blockIp.trim()}>{t('firewall.blocking.blockIP')}</button>
              </div>
            </div>

            {/* Block Port */}
            <div className="s-card-spacy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-red), var(--s-magenta))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>{t('firewall.blocking.blockPort')}</span>
                <div className="s-section-divider" style={{ flex: 1 }} />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <input className="s-input" placeholder="Port (0-65535)" value={blockPortVal} onChange={(e) => setBlockPortVal(e.target.value)} type="number" min={0} max={65535} />
                <div style={{ display: 'flex', gap: 8 }}>
                  <select className="s-select s-input" value={blockProtocol} onChange={(e) => setBlockProtocol(e.target.value as 'TCP' | 'UDP' | 'Any')} style={{ flex: 1 }}>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="Any">Any</option>
                  </select>
                  <select className="s-select s-input" value={blockDirection} onChange={(e) => setBlockDirection(e.target.value as 'in' | 'out' | 'both')} style={{ flex: 1 }}>
                    <option value="both">Both</option>
                    <option value="in">Inbound</option>
                    <option value="out">Outbound</option>
                  </select>
                </div>
                <button className="s-btn s-btn-danger" onClick={handleBlockPort} disabled={!blockPortVal.trim()}>{t('firewall.blocking.blockPort')}</button>
              </div>
            </div>

            {/* Block Subnet */}
            <div className="s-card-spacy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-amber), var(--s-red))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>{t('firewall.blocking.blockSubnet')}</span>
                <div className="s-section-divider" style={{ flex: 1 }} />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <input className="s-input" placeholder="CIDR (e.g. 10.0.0.0/8)" value={blockSubnet} onChange={(e) => setBlockSubnet(e.target.value)} />
                <button className="s-btn s-btn-danger" onClick={handleBlockSubnet} disabled={!blockSubnet.trim()}>{t('firewall.blocking.blockSubnet')}</button>
              </div>
            </div>

            {/* Block PID */}
            <div className="s-card-spacy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-magenta), var(--s-red))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>{t('firewall.blocking.blockPID')}</span>
                <div className="s-section-divider" style={{ flex: 1 }} />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <input className="s-input" placeholder="Process ID" value={blockPid} onChange={(e) => setBlockPid(e.target.value)} type="number" />
                <button className="s-btn s-btn-danger" onClick={handleBlockPid} disabled={!blockPid.trim()}>{t('firewall.blocking.blockPID')}</button>
              </div>
            </div>

            {/* Result */}
            {blockResult && (
              <div className="s-card-spacy" style={{ gridColumn: '1 / -1', borderColor: blockResult.success ? 'rgba(61,255,143,0.3)' : 'rgba(255,95,95,0.3)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className={`s-status-dot ${blockResult.success ? 's-status-dot-online' : 's-status-dot-error'}`} />
                  <span style={{ color: blockResult.success ? 'var(--s-green)' : 'var(--s-red)' }}>{blockResult.message}</span>
                </div>
              </div>
            )}
          </motion.div>
        )}

        {/* ═══ Pending Rules Tab ═══ */}
        {tab === 'pending' && (
          <motion.div key="pending" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {pendingRules.length === 0 ? (
              <div className="s-card-spacy" style={{ textAlign: 'center', padding: '32px 24px', color: 'var(--s-text-dim)' }}>
                <div style={{ fontSize: '1.5rem', marginBottom: 8, opacity: 0.3 }}>{'✓'}</div>
                <div style={{ fontSize: '0.8125rem', marginBottom: 4 }}>Keine ausstehenden Regeln</div>
                <div style={{ fontSize: '0.675rem', maxWidth: 400, margin: '0 auto', lineHeight: 1.5 }}>
                  Ausstehende Regeln werden automatisch von Sentinel erstellt, wenn verdächtiger Netzwerkverkehr erkannt wird. Sie können sie hier bestätigen oder verwerfen.
                </div>
              </div>
            ) : pendingRules.map((rule) => (
              <div key={rule.id} className="s-card-spacy" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span style={{ fontWeight: 600 }}>{rule.processName}</span>
                    <span className="s-badge s-badge-cyan" style={{ fontFamily: 'var(--s-font-mono)' }}>{rule.remoteIP}</span>
                    {rule.recommendsBlock && <span className="s-badge s-badge-red">BLOCK</span>}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)' }}>{rule.reasons?.join(' · ') || 'No reason specified'}</div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', marginTop: 4 }}>Expires: {new Date(rule.expiresAt).toLocaleString('de-DE')}</div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="s-btn s-btn-danger s-btn-sm" onClick={async () => { await api()?.shield?.commitPendingRule?.(rule.id); fetchData(); }}>Commit</button>
                  <button className="s-btn s-btn-ghost s-btn-sm" onClick={async () => { await api()?.shield?.dismissPendingRule?.(rule.id); fetchData(); }}>Dismiss</button>
                </div>
              </div>
            ))}
          </motion.div>
        )}

        {/* ═══ Sentinel Rules Tab ═══ */}
        {tab === 'sentinel' && (
          <motion.div key="sentinel" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy">
            <div className="s-flex-between" style={{ marginBottom: 16 }}>
              <div className="s-heading-md">{t('firewall.sentinel.title')} ({sentinelRules.length})</div>
              <button className="s-btn s-btn-danger s-btn-sm" onClick={async () => { await api()?.shield?.clearSentinelRules?.(); fetchData(); }}>{t('common.clearAll')}</button>
            </div>
            {sentinelRules.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '24px 16px', color: 'var(--s-text-dim)' }}>
                <div style={{ fontSize: '0.8125rem', marginBottom: 4 }}>Keine Sentinel-verwalteten Regeln</div>
                <div style={{ fontSize: '0.675rem', maxWidth: 400, margin: '0 auto', lineHeight: 1.5 }}>
                  Hier erscheinen Regeln, die Sentinel automatisch erstellt hat (z.B. durch IoC-Erkennung oder adaptiven Zugriffsschutz). Sie können diese zentral verwalten und bei Bedarf löschen.
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {sentinelRules.map((name, i) => (
                  <div key={`sr-${i}`} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0', borderBottom: '1px solid rgba(109,120,255,0.06)' }}>
                    <span className="s-status-dot s-status-dot-online" />
                    <span style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.8125rem' }}>{name}</span>
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ═══ Detail Modal ═══ */}
      <AnimatePresence>
        {detailRule && (
          <motion.div
            className="s-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setDetailRule(null)}
          >
            <motion.div
              className="s-modal"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 12 }}
              onClick={(e) => e.stopPropagation()}
              style={{ borderTopColor: detailRule.action === 'Block' ? 'rgba(255,95,95,0.4)' : 'rgba(61,255,143,0.4)', borderTopWidth: 2 }}
            >
              <div className="s-modal-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span className={`s-status-dot ${isEnabled(detailRule.enabled) ? 's-status-dot-online' : 's-status-dot-offline'}`} />
                  <span style={{ fontWeight: 700, fontSize: '0.9375rem' }}>{detailRule.name}</span>
                </div>
                <button className="s-modal-close" onClick={() => setDetailRule(null)}>✕</button>
              </div>
              <div className="s-modal-body">
                {(() => {
                  const KNOWN_PROGRAMS: Record<string, { desc: string; risk: string; category: string }> = {
                    'NcsiUwpApp': { desc: 'Windows Network Connectivity Status Indicator — checks internet connectivity by contacting Microsoft servers.', risk: 'Safe system process. Blocking may cause "No Internet" warnings despite active connection.', category: 'System' },
                    'svchost': { desc: 'Windows Service Host — runs multiple Windows services. Many firewall rules target svchost for specific services.', risk: 'Essential system process. Review which service this rule targets before modifying.', category: 'System' },
                    'SearchHost': { desc: 'Windows Search indexing service — indexes files and provides search functionality.', risk: 'Safe. Network access is for cloud search features. Can be blocked without system impact.', category: 'System' },
                    'msedge': { desc: 'Microsoft Edge browser — web browsing and WebView components used by many apps.', risk: 'Normal browser traffic. Review if outbound rules are too permissive.', category: 'Browser' },
                    'chrome': { desc: 'Google Chrome browser — web browsing, extensions, and update services.', risk: 'Normal browser traffic. Check for unexpected inbound rules.', category: 'Browser' },
                    'firefox': { desc: 'Mozilla Firefox browser — web browsing with privacy focus.', risk: 'Normal browser traffic. Generally safe to allow outbound.', category: 'Browser' },
                    'MicrosoftEdgeUpdate': { desc: 'Edge auto-update service — downloads and installs Edge updates.', risk: 'Safe but can be blocked if you prefer manual updates.', category: 'Update' },
                    'OneDrive': { desc: 'Microsoft OneDrive cloud sync — syncs files with Microsoft cloud storage.', risk: 'Cloud sync may upload personal data. Review if privacy is a concern.', category: 'Cloud' },
                    'Teams': { desc: 'Microsoft Teams — communication and collaboration platform.', risk: 'Requires network for calls/chat. Safe for business use.', category: 'Communication' },
                    'Spotify': { desc: 'Spotify music streaming — streams audio content and syncs playlists.', risk: 'Media streaming. Safe to allow outbound. Can be blocked to save bandwidth.', category: 'Media' },
                    'Discord': { desc: 'Discord voice/text communication — gaming and community platform.', risk: 'Requires outbound for voice/text. Check for unexpected inbound rules.', category: 'Communication' },
                    'Steam': { desc: 'Steam gaming platform — downloads games, manages library, and multiplayer.', risk: 'Requires outbound for store/multiplayer. Inbound needed for hosting games.', category: 'Gaming' },
                    'WinStore.App': { desc: 'Microsoft Store — downloads and updates UWP apps.', risk: 'Safe system process. Blocking prevents Store app updates.', category: 'System' },
                    'RuntimeBroker': { desc: 'Windows Runtime Broker — manages permissions for UWP apps.', risk: 'Essential system process. Do not block.', category: 'System' },
                    'lsass': { desc: 'Local Security Authority — handles authentication and security policies.', risk: 'Critical security process. Never modify these rules without understanding the impact.', category: 'Security' },
                    'wininit': { desc: 'Windows Initialization — core startup process.', risk: 'Critical system process. Do not modify.', category: 'System' },
                    'spoolsv': { desc: 'Print Spooler — manages print jobs and printer communication.', risk: 'Safe for local printing. Network printing requires outbound access.', category: 'System' },
                    'Dropbox': { desc: 'Dropbox cloud sync — syncs files with Dropbox cloud storage.', risk: 'Cloud sync uploads data. Review privacy implications.', category: 'Cloud' },
                  };
                  const nameKey = Object.keys(KNOWN_PROGRAMS).find(k => detailRule.name.toLowerCase().includes(k.toLowerCase()));
                  const progKey = detailRule.program ? Object.keys(KNOWN_PROGRAMS).find(k => detailRule.program!.toLowerCase().includes(k.toLowerCase())) : undefined;
                  const knownInfo = KNOWN_PROGRAMS[nameKey || ''] || (progKey ? KNOWN_PROGRAMS[progKey] : undefined);
                  const risk = assessRuleRisk(detailRule);
                  const riskColor = risk.level === 'high' ? 'var(--s-red)' : risk.level === 'medium' ? 'var(--s-amber)' : 'var(--s-green)';
                  return (
                    <>
                      {/* Program Description */}
                      {knownInfo && (
                        <div style={{ padding: '10px 12px', borderRadius: 8, background: 'rgba(109,120,255,0.04)', border: '1px solid rgba(109,120,255,0.1)', marginBottom: 10 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                            <span style={{ fontSize: '0.5625rem', padding: '2px 6px', borderRadius: 6, background: 'rgba(109,120,255,0.12)', color: 'var(--s-cyan)', fontWeight: 700, textTransform: 'uppercase' }}>{knownInfo.category}</span>
                          </div>
                          <div style={{ fontSize: '0.75rem', color: 'var(--s-text-secondary)', lineHeight: 1.4 }}>{knownInfo.desc}</div>
                          <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', marginTop: 6, fontStyle: 'italic' }}>Security note: {knownInfo.risk}</div>
                        </div>
                      )}
                      {/* Risk Assessment */}
                      <div style={{ padding: '8px 12px', borderRadius: 8, background: `${riskColor}06`, border: `1px solid ${riskColor}18`, marginBottom: 10 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                          <span style={{ fontSize: '0.625rem', fontWeight: 700, color: riskColor, textTransform: 'uppercase' }}>Risk: {risk.level}</span>
                          <span style={{ fontSize: '0.5625rem', color: 'var(--s-text-dim)' }}>Score {risk.score}/10</span>
                        </div>
                        {risk.reasons.length > 0 && (
                          <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', lineHeight: 1.4 }}>
                            {risk.reasons.map((r, i) => <div key={i}>• {r}</div>)}
                          </div>
                        )}
                        {risk.reasons.length === 0 && <div style={{ fontSize: '0.6875rem', color: 'var(--s-green)' }}>No risk factors detected</div>}
                      </div>
                      {/* Rule Properties */}
                      {[
                        { label: 'Direction', value: detailRule.direction },
                        { label: 'Action', value: detailRule.action === 'Allow' || detailRule.action === 'Zulassen' ? 'Allow' : detailRule.action === 'Block' || detailRule.action === 'Blockieren' ? 'Block' : detailRule.action },
                        { label: 'Protocol', value: detailRule.protocol || 'Any' },
                        { label: 'Local Port', value: String(detailRule.localPort || 'Any') },
                        { label: 'Remote Port', value: String(detailRule.remotePort || 'Any') },
                        { label: 'Remote Address', value: detailRule.remoteAddress || 'Any' },
                        { label: 'Program', value: detailRule.program || 'Any process' },
                        { label: 'Enabled', value: isEnabled(detailRule.enabled) ? 'Yes' : 'No' },
                        { label: 'Profile', value: detailRule.profile || '—' },
                      ].map((item) => (
                        <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid rgba(109,120,255,0.06)' }}>
                          <span style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)' }}>{item.label}</span>
                          <span style={{ fontSize: '0.8125rem', fontFamily: 'var(--s-font-mono)', fontWeight: 600 }}>{item.value}</span>
                        </div>
                      ))}
                      {detailRule.description && (
                        <div style={{ fontSize: '0.75rem', color: 'var(--s-text-secondary)', padding: '8px 0', borderTop: '1px solid rgba(109,120,255,0.06)', marginTop: 4 }}>
                          <span style={{ fontWeight: 600, fontSize: '0.6875rem', color: 'var(--s-text-dim)', textTransform: 'uppercase' }}>Description: </span>
                          {detailRule.description}
                        </div>
                      )}
                    </>
                  );
                })()}
              </div>
              <div className="s-modal-footer">
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => { handleToggleRule(detailRule.name, isEnabled(detailRule.enabled)); setDetailRule(null); }}>
                  {isEnabled(detailRule.enabled) ? '⏸ Disable' : '▶ Enable'}
                </button>
                {detailRule.remoteAddress && detailRule.remoteAddress !== 'Any' && detailRule.remoteAddress !== '*' && (
                  <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => { navigate('/intel', { state: { scanUrl: detailRule.remoteAddress, source: 'firewall' } }); setDetailRule(null); }}>
                    Scan in Intel
                  </button>
                )}
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => { navigate('/network'); setDetailRule(null); }}>
                  View Network
                </button>
                <button className="s-btn s-btn-danger s-btn-sm" onClick={() => { handleDeleteRule(detailRule.name); setDetailRule(null); }}>
                  🗑 Delete
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default FirewallPage;
