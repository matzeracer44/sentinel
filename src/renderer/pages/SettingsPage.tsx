/**
 * SENTINEL UNIFIED — Settings Page
 * Language, theme, app config, activity log viewer, ARGUS health, dev tools.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { notify } from '../components/Common/SentinelNotification';
import InfoBadge from '../components/Common/InfoBadge';
import InputModal, { useInputModal } from '../components/Common/InputModal';
import { useTranslation } from 'react-i18next';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (): any => (window as any).electronAPI;

interface Settings {
  language: string;
  theme: string;
  autostart: boolean;
  autoUpdate: boolean;
}

interface ActivityEntry {
  timestamp: string;
  module: string;
  action: string;
  details: string;
  severity: string;
}

interface ArgusHealth {
  running: boolean;
  port: number;
  version?: string;
  uptime?: number;
}

interface PerfProfile {
  mode: string;
  hardware: {
    cpuModel: string;
    cpuCores: number;
    cpuThreads: number;
    totalRAM_GB: number;
    freeRAM_GB: number;
    platform: string;
    osRelease: string;
    arch: string;
    tier: string;
  };
  settings: {
    powershellTimeout: number;
    maxBuffer: number;
    pollSystem: number;
    pollNetwork: number;
    pollFirewall: number;
    pollArgus: number;
    pollConnectors: number;
    maxConcurrentScans: number;
    tlsWorkerThreads: number;
    argusWorkers: number;
    argusFetchTimeout: number;
    tableRenderLimit: number;
  };
  detectedAt: string;
}

const PERF_MODES = [
  { value: 'auto', label: 'Auto-Detect', desc: 'Adapts to your hardware automatically' },
  { value: 'low', label: 'Low', desc: 'Conservative — for older/weaker systems' },
  { value: 'balanced', label: 'Balanced', desc: 'Moderate polling and concurrency' },
  { value: 'high', label: 'High', desc: 'Aggressive — for powerful hardware' },
];

const TIER_COLORS: Record<string, string> = {
  ultra: 'var(--s-cyan)',
  high: 'var(--s-green)',
  mid: 'var(--s-amber)',
  low: 'var(--s-red)',
};

const SettingsPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { showInput, showAlert, modalProps } = useInputModal();
  const [settings, setSettings] = useState<Settings>({ language: i18n.language || 'en', theme: 'dark', autostart: false, autoUpdate: false });
  const [activity, setActivity] = useState<ActivityEntry[]>([]);
  const [argusHealth, setArgusHealth] = useState<ArgusHealth | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [perfProfile, setPerfProfile] = useState<PerfProfile | null>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [ipLookupEnabled, setIpLookupEnabled] = useState(true);
  const [threatClearing, setThreatClearing] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const a = api();
      if (a?.getSettings) {
        const r = await a.getSettings();
        if (r?.settings) setSettings(r.settings as Settings);
      }
      if (a?.getActivityLog) {
        const log = await a.getActivityLog();
        if (Array.isArray(log)) setActivity(log.reverse());
      }
      if (a?.argus?.getHealth) {
        const h = await a.argus.getHealth();
        if (h?.data) setArgusHealth(h.data as ArgusHealth);
      }
      if (a?.admin?.checkAdminRights) {
        const r = await a.admin.checkAdminRights();
        if (r && typeof r.isAdmin === 'boolean') setIsAdmin(r.isAdmin);
      }
      if (a?.performance?.getProfile) {
        const p = await a.performance.getProfile();
        if (p?.data) setPerfProfile(p.data as PerfProfile);
      }
    } catch (e: any) { console.warn('[SettingsPage] fetchData:', e?.message); }
    try {
      const dsgvoR = await api()?.dsgvo?.getIpLookupEnabled?.();
      if (dsgvoR && typeof dsgvoR.enabled === 'boolean') setIpLookupEnabled(dsgvoR.enabled);
    } catch { /* non-critical */ }
    try {
      const autoR = await api()?.shield?.getAutostart?.();
      if (autoR?.success) setSettings((prev) => ({ ...prev, autostart: Boolean(autoR.data?.enabled) }));
    } catch { /* non-critical */ }
  }, []);

  const handlePerfModeChange = async (mode: string) => {
    try {
      const r = await api()?.performance?.setMode?.(mode);
      if (r?.data) {
        setPerfProfile(r.data as PerfProfile);
        setMessage(`Performance mode: ${mode}`);
        setTimeout(() => setMessage(null), 2000);
      }
    } catch (e: any) { const msg = e?.message || 'Failed to change mode'; setMessage(msg); notify.error(msg); setTimeout(() => setMessage(null), 2000); }
  };

  const handleRefreshHardware = async () => {
    try {
      const r = await api()?.performance?.refreshHardware?.();
      if (r?.data) {
        setPerfProfile(r.data as PerfProfile);
        setMessage('Hardware re-detected');
        setTimeout(() => setMessage(null), 2000);
      }
    } catch (e: any) { console.warn('[SettingsPage] hardware detect:', e?.message); }
  };

  useEffect(() => { fetchData(); }, [fetchData]);

  const saveSetting = async (key: string, value: unknown) => {
    setSaving(true);
    try {
      // Wire autostart to real Electron loginItemSettings
      if (key === 'autostart') {
        const r = await api()?.shield?.setAutostart?.(Boolean(value));
        if (r?.success) {
          setSettings((prev) => ({ ...prev, autostart: Boolean(r.data?.enabled ?? value) }));
          notify.success(r.data?.enabled ? 'Sentinel will start with Windows' : 'Auto-start disabled');
          setMessage('autostart updated');
          setSaving(false);
          return;
        }
      }
      if (key === 'language') {
        i18n.changeLanguage(String(value));
        try { api()?.shield?.setScanLanguage?.(String(value)); } catch { /* best-effort */ }
      }
      await api()?.saveSettings?.(key, value);
      setSettings((prev) => ({ ...prev, [key]: value }));
      setMessage(`${key} updated`);
    } catch (e: any) { const msg = e?.message || 'Failed to save'; setMessage(msg); notify.error(msg); }
    setSaving(false);
    setTimeout(() => setMessage(null), 2000);
  };

  const handleClearLog = async () => {
    await api()?.clearActivityLog?.();
    setActivity([]);
    setMessage('Activity log cleared');
    setTimeout(() => setMessage(null), 2000);
  };

  const severityColor = (s: string) => {
    switch (s) {
      case 'error': return 'var(--s-red)';
      case 'warning': return 'var(--s-amber)';
      case 'success': return 'var(--s-green)';
      default: return 'var(--s-text-muted)';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Status Bar */}
      {message && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="s-badge s-badge-green" style={{ alignSelf: 'flex-end' }}>
          {message}
        </motion.div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* ─── General Settings ─── */}
        <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <span style={{
              fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)',
              background: 'linear-gradient(90deg, var(--s-cyan), rgba(167,139,250,0.8))',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            }}>{t('settings.tabs.general')}</span>
            <div className="s-section-divider" style={{ flex: 1 }} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Language */}
            <div>
              <label className="s-caption" style={{ display: 'block', marginBottom: 6 }}>{t('settings.general.language')}</label>
              <select className="s-select s-input" value={settings.language} onChange={(e) => saveSetting('language', e.target.value)} style={{ width: '100%' }}>
                <option value="de">Deutsch</option>
                <option value="en">English</option>
                <option value="fr">Français</option>
                <option value="es">Español</option>
              </select>
            </div>

            {/* Theme */}
            <div>
              <label className="s-caption" style={{ display: 'block', marginBottom: 6 }}>{t('common.type') === 'Typ' ? 'Design' : 'Theme'}</label>
              <select className="s-select s-input" value={settings.theme} onChange={(e) => saveSetting('theme', e.target.value)} style={{ width: '100%' }}>
                <option value="dark">Dark (Cyber)</option>
                <option value="midnight">Midnight</option>
                <option value="light">Light</option>
              </select>
            </div>

            {/* Toggles */}
            {[
              { key: 'autostart', label: t('settings.general.autostart') },
              { key: 'autoUpdate', label: t('common.type') === 'Typ' ? 'Auto-Update' : 'Auto-update' },
            ].map((toggle) => (
              <div key={toggle.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '0.8125rem' }}>{toggle.label}</span>
                <button
                  className={`s-btn s-btn-sm ${(settings as unknown as Record<string, unknown>)[toggle.key] ? 's-btn-primary' : 's-btn-ghost'}`}
                  onClick={() => saveSetting(toggle.key, !(settings as unknown as Record<string, unknown>)[toggle.key])}
                  style={{ minWidth: 80 }}
                >
                  {(settings as unknown as Record<string, unknown>)[toggle.key] ? t('common.on') : t('common.off')}
                </button>
              </div>
            ))}
          </div>
        </motion.div>

        {/* ─── System Info ─── */}
        <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <span style={{
              fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)',
              background: 'linear-gradient(90deg, var(--s-green), var(--s-cyan))',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            }}>{t('common.type') === 'Typ' ? 'Systemstatus' : 'System Status'}</span>
            <div className="s-section-divider" style={{ flex: 1 }} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Admin */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px', borderRadius: 8, background: isAdmin ? 'rgba(61,255,143,0.04)' : 'rgba(255,190,61,0.04)' }}>
              <span style={{ fontSize: '0.8125rem', color: 'var(--s-text-secondary)' }}>{t('common.type') === 'Typ' ? 'Administratorrechte' : 'Admin Privileges'}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{
                  width: 6, height: 6, borderRadius: '50%',
                  background: isAdmin ? 'var(--s-green)' : 'var(--s-amber)',
                  boxShadow: `0 0 6px ${isAdmin ? 'var(--s-green)' : 'var(--s-amber)'}`,
                }} />
                <span style={{ fontSize: '0.7rem', fontWeight: 600, color: isAdmin ? 'var(--s-green)' : 'var(--s-amber)' }}>{isAdmin ? 'ADMIN' : 'LIMITED'}</span>
              </div>
            </div>

            {/* ARGUS */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px', borderRadius: 8, background: argusHealth?.running ? 'rgba(61,255,143,0.04)' : 'rgba(255,95,95,0.04)' }}>
              <span style={{ fontSize: '0.8125rem', color: 'var(--s-text-secondary)' }}>ARGUS Backend</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{
                  width: 6, height: 6, borderRadius: '50%',
                  background: argusHealth?.running ? 'var(--s-green)' : 'var(--s-red)',
                  boxShadow: `0 0 6px ${argusHealth?.running ? 'var(--s-green)' : 'var(--s-red)'}`,
                  animation: argusHealth?.running ? 'pulse-green 2s ease-in-out infinite' : 'none',
                }} />
                <span style={{ fontSize: '0.7rem', fontWeight: 600, color: argusHealth?.running ? 'var(--s-green)' : 'var(--s-red)' }}>
                  {argusHealth?.running ? `Online :${argusHealth.port}` : 'Offline'}
                </span>
              </div>
            </div>

            {/* Version */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px', borderRadius: 8, background: 'rgba(109,120,255,0.04)' }}>
              <span style={{ fontSize: '0.8125rem', color: 'var(--s-text-secondary)' }}>{t('settings.advanced.version')}</span>
              <span style={{
                fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem', fontWeight: 700,
                padding: '2px 8px', borderRadius: 6,
                background: 'rgba(109,120,255,0.08)', border: '1px solid rgba(109,120,255,0.15)',
                color: 'var(--s-cyan)',
              }}>v5.0</span>
            </div>

            <div className="s-section-divider" />

            {/* Export Report */}
            <button
              className="s-btn s-btn-ghost s-btn-sm"
              style={{ width: '100%', borderRadius: 8, fontSize: '0.75rem', borderColor: 'rgba(60,240,255,0.2)', marginBottom: 4 }}
              onClick={async () => {
                try {
                  const r = await api()?.shield?.exportReportFile?.();
                  if (r?.success) notify.success(`Report exported: ${r.data?.path}`);
                  else if (r?.error !== 'Export cancelled') notify.error(r?.error || 'Export failed');
                } catch (e: any) { notify.error(e?.message || 'Export failed'); }
              }}
            >
              {t('settings.general.exportReport')} (HTML/JSON)
            </button>

            {/* Config Export / Import */}
            <div style={{ display: 'flex', gap: 6 }}>
              <button
                className="s-btn s-btn-ghost s-btn-sm"
                style={{ flex: 1, borderRadius: 8, fontSize: '0.7rem', borderColor: 'rgba(61,255,143,0.15)' }}
                onClick={async () => {
                  try {
                    const r = await api()?.sentinelConfig?.exportConfig?.();
                    if (r?.success) notify.success(`Config exported: ${r.data?.path}`);
                    else if (r?.error !== 'Cancelled') notify.error(r?.error || 'Export failed');
                  } catch (e: any) { notify.error(e?.message || 'Export failed'); }
                }}
              >
                {t('settings.general.backupConfig')}
              </button>
              <button
                className="s-btn s-btn-ghost s-btn-sm"
                style={{ flex: 1, borderRadius: 8, fontSize: '0.7rem', borderColor: 'rgba(255,190,61,0.15)' }}
                onClick={async () => {
                  try {
                    const r = await api()?.sentinelConfig?.importConfig?.();
                    if (r?.success) {
                      notify.success('Config restored successfully — reloading settings...');
                      fetchData();
                    } else if (r?.error !== 'Cancelled') { notify.error(r?.error || 'Import failed'); }
                  } catch (e: any) { notify.error(e?.message || 'Import failed'); }
                }}
              >
                {t('settings.general.restoreConfig')}
              </button>
            </div>

            {/* Tray Info */}
            <div style={{ fontSize: '0.675rem', color: 'var(--s-text-dim)', padding: '4px 8px', borderRadius: 6, background: 'rgba(109,120,255,0.03)' }}>
              {t('common.type') === 'Typ'
                ? 'Sentinel läuft im System-Tray. Das Schließen des Fensters minimiert in den Tray — der Schutz bleibt aktiv.'
                : 'Sentinel runs in system tray. Closing the window minimizes to tray — protection stays active.'}
            </div>

            <div className="s-section-divider" style={{ margin: '4px 0' }} />

            {/* Dev Tools */}
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              <button className="s-btn s-btn-ghost s-btn-sm" style={{ borderRadius: 8, fontSize: '0.65rem' }} onClick={() => api()?.toggleDevTools?.()}>Dev Tools</button>
              <button className="s-btn s-btn-ghost s-btn-sm" style={{ borderRadius: 8, fontSize: '0.65rem' }} onClick={() => api()?.renderer?.reload?.()}>Reload UI</button>
              <button className="s-btn s-btn-ghost s-btn-sm" style={{ borderRadius: 8, fontSize: '0.65rem' }} onClick={() => api()?.renderer?.build?.()}>Rebuild</button>
            </div>
          </div>
        </motion.div>
      </div>

      {/* ─── Performance Profile ─── */}
      {perfProfile && (
        <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }}>
          <div className="s-flex-between" style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{
                fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)',
                background: 'linear-gradient(90deg, var(--s-cyan), var(--s-purple))',
                WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
              }}>{t('settings.profiles.title')}</span>
              <div className="s-section-divider" style={{ flex: 1, maxWidth: 100 }} />
            </div>
            <button className="s-btn s-btn-ghost s-btn-sm" onClick={handleRefreshHardware}>{t('settings.profiles.refreshHardware')}</button>
          </div>

          {/* Hardware Info */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
            <div className="s-card-compact-spacy">
              <div className="s-caption" style={{ marginBottom: 4 }}>CPU</div>
              <div style={{ fontSize: '0.8125rem', fontWeight: 600 }}>{perfProfile.hardware.cpuModel}</div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                {perfProfile.hardware.cpuCores}C / {perfProfile.hardware.cpuThreads}T
              </div>
            </div>
            <div className="s-card-compact-spacy">
              <div className="s-caption" style={{ marginBottom: 4 }}>RAM</div>
              <div style={{ fontSize: '0.8125rem', fontWeight: 600 }}>{perfProfile.hardware.totalRAM_GB} GB</div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                {perfProfile.hardware.freeRAM_GB} GB free
              </div>
            </div>
            <div className="s-card-compact-spacy">
              <div className="s-caption" style={{ marginBottom: 4 }}>{t('settings.profiles.current')}</div>
              <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: TIER_COLORS[perfProfile.hardware.tier] || 'var(--s-text)' }}>
                {perfProfile.hardware.tier.toUpperCase()}
              </div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                {perfProfile.hardware.arch} · {perfProfile.hardware.platform}
              </div>
            </div>
            <div className="s-card-compact-spacy">
              <div className="s-caption" style={{ marginBottom: 4 }}>{t('settings.profiles.apply')}</div>
              <div style={{ fontSize: '0.8125rem', fontWeight: 600 }}>{perfProfile.mode.toUpperCase()}</div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                Since {new Date(perfProfile.detectedAt).toLocaleTimeString('de-DE')}
              </div>
            </div>
          </div>

          {/* Mode Selector */}
          <div style={{ marginBottom: 16 }}>
            <div className="s-caption" style={{ marginBottom: 8 }}>{t('settings.profiles.title')}</div>
            <div style={{ display: 'flex', gap: 8 }}>
              {PERF_MODES.map((m) => (
                <button
                  key={m.value}
                  className={`s-btn s-btn-sm ${perfProfile.mode === m.value ? 's-btn-primary' : 's-btn-ghost'}`}
                  onClick={() => handlePerfModeChange(m.value)}
                  title={m.desc}
                  style={{ flex: 1 }}
                >
                  {m.label}
                </button>
              ))}
            </div>
          </div>

          {/* Adaptive Settings Grid */}
          <div>
            <div className="s-caption" style={{ marginBottom: 8 }}>{t('settings.advanced.title')}</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
              {[
                { label: 'PS Timeout', value: `${perfProfile.settings.powershellTimeout}ms` },
                { label: 'Max Buffer', value: `${Math.round(perfProfile.settings.maxBuffer / 1024 / 1024)}MB` },
                { label: 'Poll System', value: `${perfProfile.settings.pollSystem / 1000}s` },
                { label: 'Poll Network', value: `${perfProfile.settings.pollNetwork / 1000}s` },
                { label: 'Poll Firewall', value: `${perfProfile.settings.pollFirewall / 1000}s` },
                { label: 'Poll ARGUS', value: `${perfProfile.settings.pollArgus / 1000}s` },
                { label: 'Concurrent Scans', value: `${perfProfile.settings.maxConcurrentScans}` },
                { label: 'TLS Workers', value: `${perfProfile.settings.tlsWorkerThreads}` },
                { label: 'Table Limit', value: `${perfProfile.settings.tableRenderLimit}` },
              ].map((item) => (
                <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 8px', borderRadius: 4, background: 'rgba(109,120,255,0.04)' }}>
                  <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)' }}>{item.label}</span>
                  <span style={{ fontSize: '0.6875rem', fontFamily: 'var(--s-font-mono)', fontWeight: 600 }}>{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      )}

      {/* ─── Datenschutz / DSGVO (Art. 5, 6, 13, 17, 32 DSGVO) ─── */}
      <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <span style={{
            fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)',
            background: 'linear-gradient(90deg, var(--s-green), var(--s-cyan))',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          }}>{t('settings.privacy.title')}</span>
          <span style={{
            fontSize: '0.55rem', fontWeight: 700, padding: '2px 8px', borderRadius: 6,
            background: 'rgba(61,255,143,0.08)', border: '1px solid rgba(61,255,143,0.15)',
            color: 'var(--s-green)', textTransform: 'uppercase', letterSpacing: '0.05em',
          }}>DSGVO</span>
          <div className="s-section-divider" style={{ flex: 1 }} />
        </div>

        <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', lineHeight: 1.7, marginBottom: 16, padding: '10px 14px', borderRadius: 8, background: 'rgba(109,120,255,0.03)', border: '1px solid rgba(109,120,255,0.08)' }}>
          Sentinel speichert alle Daten <strong style={{ color: 'var(--s-text-secondary)' }}>ausschließlich lokal</strong> auf diesem Gerät.
          Keine Daten werden an externe Server übertragen, außer bei aktiviertem IP-Lookup (ipinfo.io)
          für bereits mit dem System verbundene Adressen. Vault-Daten sind mit <strong style={{ color: 'var(--s-cyan)' }}>AES-256-GCM</strong> verschlüsselt.
          Gemäß Art. 17 DSGVO können Sie alle gespeicherten personenbezogenen Daten jederzeit löschen.
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* IP Lookup Toggle */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', borderRadius: 8, background: ipLookupEnabled ? 'rgba(61,255,143,0.04)' : 'rgba(255,95,95,0.04)' }}>
            <div>
              <div style={{ fontSize: '0.8125rem', fontWeight: 600 }}>Externe IP-Metadaten (ipinfo.io)</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                Geo-Lokation & ISP-Daten für verbundene externe IPs abrufen
              </div>
            </div>
            <button
              className={`s-btn s-btn-sm ${ipLookupEnabled ? 's-btn-primary' : 's-btn-ghost'}`}
              style={{ minWidth: 80 }}
              onClick={async () => {
                try {
                  const r = await api()?.dsgvo?.setIpLookupEnabled?.(!ipLookupEnabled);
                  if (r?.success) {
                    setIpLookupEnabled(r.enabled);
                    notify.success(r.enabled ? 'IP-Lookup aktiviert' : 'IP-Lookup deaktiviert');
                  }
                } catch (e: any) { notify.error(e?.message || 'Fehler'); }
              }}
            >
              {ipLookupEnabled ? 'Aktiv' : 'Aus'}
            </button>
          </div>

          <div className="s-section-divider" />

          {/* Data Deletion — Art. 17 DSGVO */}
          <div style={{ fontSize: '0.7rem', color: 'var(--s-text-dim)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{t('dsgvo.rightToErasure')}</div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <button className="s-btn s-btn-danger s-btn-sm" style={{ borderRadius: 8 }} onClick={handleClearLog}>
              {t('settings.privacy.clearActivityLog')}
            </button>
            <button className="s-btn s-btn-danger s-btn-sm" style={{ borderRadius: 8 }} disabled={threatClearing} onClick={async () => {
              setThreatClearing(true);
              try {
                const r = await api()?.dsgvo?.clearThreatEvents?.();
                if (r?.success) notify.success(r.message || 'Threat-Events gelöscht');
                else notify.error(r?.error || 'Fehler beim Löschen');
              } catch (e: any) { notify.error(e?.message || 'Fehler'); }
              setThreatClearing(false);
            }}>
              {threatClearing ? t('common.loading') : t('settings.privacy.clearThreatEvents')}
            </button>
            <button className="s-btn s-btn-danger s-btn-sm" style={{ borderRadius: 8 }} onClick={async () => {
              try {
                const r = await api()?.argus?.clearHistory?.();
                if (r?.success) notify.success('Scan-Historie gelöscht');
                else notify.error(r?.error || 'Fehler');
              } catch (e: any) { notify.error(e?.message || 'Fehler'); }
            }}>
              {t('settings.privacy.clearScanHistory')}
            </button>
          </div>

          <div className="s-section-divider" />

          {/* Storage Info */}
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {[
              { label: 'Vault', detail: 'AES-256-GCM', color: 'var(--s-cyan)' },
              { label: 'Telemetrie', detail: 'LevelDB lokal', color: 'var(--s-purple)' },
              { label: 'Settings', detail: 'JSON lokal', color: 'var(--s-amber)' },
              { label: 'Transfer', detail: 'Nur localhost', color: 'var(--s-green)' },
            ].map((s) => (
              <div key={s.label} style={{ padding: '6px 12px', borderRadius: 8, background: 'rgba(109,120,255,0.03)', border: '1px solid rgba(109,120,255,0.08)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: s.color, boxShadow: `0 0 6px ${s.color}` }} />
                <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-secondary)' }}>{s.label}:</span>
                <span style={{ fontSize: '0.6875rem', fontWeight: 600, fontFamily: 'var(--s-font-mono)' }}>{s.detail}</span>
              </div>
            ))}
          </div>
        </div>
      </motion.div>

      {/* ─── Security Hardening (Audit 2026) ─── */}
      <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <span style={{
            fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)',
            background: 'linear-gradient(90deg, var(--s-red), var(--s-amber))',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          }}>Security Hardening</span>
          <span style={{
            fontSize: '0.55rem', fontWeight: 700, padding: '2px 8px', borderRadius: 6,
            background: 'rgba(255,95,95,0.08)', border: '1px solid rgba(255,95,95,0.15)',
            color: 'var(--s-red)', textTransform: 'uppercase', letterSpacing: '0.05em',
          }}>BSI / NIST</span>
          <div className="s-section-divider" style={{ flex: 1 }} />
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* P1: Local PIN Lock */}
          <div style={{ padding: '10px 14px', borderRadius: 8, background: 'rgba(109,120,255,0.03)', border: '1px solid rgba(109,120,255,0.08)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <div>
                <div style={{ fontSize: '0.8125rem', fontWeight: 600 }}>🔐 Local PIN Lock</div>
                <div style={{ fontSize: '0.65rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                  Phishing-resistant local auth — PBKDF2-SHA512, 100K iterations, 30min session
                </div>
              </div>
              <button
                className="s-btn s-btn-sm s-btn-ghost"
                style={{ minWidth: 90 }}
                onClick={async () => {
                  try {
                    const status = await api()?.auth?.getStatus?.();
                    if (status?.hasPin) {
                      const pin = await showInput({ title: 'PIN entfernen', message: 'Geben Sie Ihre aktuelle PIN ein, um die Sperre zu entfernen.', placeholder: 'Aktuelle PIN\u2026', inputType: 'password', variant: 'warning', confirmLabel: 'Entfernen' });
                      if (pin) {
                        const r = await api()?.auth?.removePin?.(pin);
                        if (r?.success) notify.success('PIN-Sperre entfernt');
                        else notify.error(r?.error || 'Fehlgeschlagen');
                      }
                    } else {
                      const pin = await showInput({ title: 'PIN festlegen', message: 'Legen Sie eine PIN fest (mind. 4 Zeichen). Wird bei jedem Start abgefragt.', placeholder: 'Neue PIN (min. 4 Zeichen)\u2026', inputType: 'password', variant: 'info', confirmLabel: 'PIN aktivieren' });
                      if (pin) {
                        const r = await api()?.auth?.setPin?.(pin);
                        if (r?.success) notify.success('PIN-Sperre aktiviert');
                        else notify.error(r?.error || 'Fehlgeschlagen');
                      }
                    }
                  } catch (e: any) { notify.error(e?.message || 'Error'); }
                }}
              >PIN festlegen / entfernen</button>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                className="s-btn s-btn-sm s-btn-ghost"
                style={{ fontSize: '0.65rem' }}
                onClick={async () => {
                  try {
                    const r = await api()?.auth?.setRequireOnLaunch?.(true);
                    if (r?.success) notify.success('PIN required on launch');
                  } catch (e: any) { notify.error(e?.message || 'Error'); }
                }}
              >Require on Launch</button>
              <button
                className="s-btn s-btn-sm s-btn-ghost"
                style={{ fontSize: '0.65rem' }}
                onClick={async () => {
                  try {
                    await api()?.auth?.lock?.();
                    notify.info('Session locked');
                  } catch (e: any) { notify.error(e?.message || 'Error'); }
                }}
              >Lock Now</button>
            </div>
          </div>

          <div className="s-section-divider" />

          {/* P2: Update Signature Verifier */}
          <div style={{ padding: '10px 14px', borderRadius: 8, background: 'rgba(109,120,255,0.03)', border: '1px solid rgba(109,120,255,0.08)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ fontSize: '0.8125rem', fontWeight: 600 }}>🛡️ Update-Signaturprüfung</span>
              <span style={{ fontSize: '0.5rem', padding: '1px 5px', borderRadius: 4, background: 'rgba(61,255,143,0.08)', color: 'var(--s-green)', fontWeight: 600 }}>BSI APP.6.A4</span>
            </div>
            <div style={{ fontSize: '0.65rem', color: 'var(--s-text-muted)', marginBottom: 4 }}>
              Kryptografische Ed25519-Signaturen — verhindert Supply-Chain-Angriffe auf Updates
            </div>
            <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', marginBottom: 8, lineHeight: 1.5, fontStyle: 'italic' }}>
              Jedes Update muss mit einem vertrauenswürdigen Schlüssel signiert sein, bevor es installiert wird. Dies schützt vor manipulierten Downloads.
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                className="s-btn s-btn-sm s-btn-ghost"
                style={{ fontSize: '0.65rem' }}
                onClick={async () => {
                  try {
                    const r = await api()?.updater?.listKeys?.();
                    notify.info(`${r?.keys?.length || 0} trusted signing keys`);
                  } catch (e: any) { notify.error(e?.message || 'Error'); }
                }}
              >Show Keys</button>
              <button
                className="s-btn s-btn-sm s-btn-ghost"
                style={{ fontSize: '0.65rem' }}
                onClick={async () => {
                  try {
                    const r = await api()?.updater?.getHistory?.();
                    const h = r?.history || [];
                    const valid = h.filter((v: any) => v.valid).length;
                    notify.info(`${h.length} verifications — ${valid} valid, ${h.length - valid} rejected`);
                  } catch (e: any) { notify.error(e?.message || 'Error'); }
                }}
              >Verify History</button>
            </div>
          </div>

          <div className="s-section-divider" />

          {/* P2: Ransomware 3.0 Detection */}
          <div style={{ padding: '10px 14px', borderRadius: 8, background: 'rgba(109,120,255,0.03)', border: '1px solid rgba(109,120,255,0.08)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ fontSize: '0.8125rem', fontWeight: 600 }}>🧬 Ransomware 3.0 Erkennung</span>
              <span style={{ fontSize: '0.5rem', padding: '1px 5px', borderRadius: 4, background: 'rgba(255,95,95,0.08)', color: 'var(--s-red)', fontWeight: 600 }}>ECHTZEIT</span>
            </div>
            <div style={{ fontSize: '0.65rem', color: 'var(--s-text-muted)', marginBottom: 4 }}>
              Dateiintegritäts-Monitor mit Entropie-Analyse, Massenänderungs-Erkennung und Mikro-Edit-Detektion gegen stille Datenmanipulation.
              Aktiv auf allen überwachten Pfaden (hosts, SAM, Registry Hives, Autostart).
            </div>
            <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', marginBottom: 6, lineHeight: 1.5, fontStyle: 'italic' }}>
              Moderne Ransomware verschlüsselt nicht nur — sie manipuliert Daten subtil. Sentinel erkennt Entropie-Sprünge (Verschlüsselung), Massenänderungen (5+ Dateien in 10s) und Mikro-Edits (stille Vergiftung). Läuft vollständig lokal.
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 6 }}>
              {[
                { label: 'Entropy Spike', desc: 'Detects encryption attempts' },
                { label: 'Mass Modify', desc: '5+ files in 10s = alert' },
                { label: 'Micro Edit', desc: 'Subtle data poisoning' },
              ].map((d) => (
                <span key={d.label} style={{ fontSize: '0.6rem', padding: '3px 8px', borderRadius: 6, background: 'rgba(255,95,95,0.06)', border: '1px solid rgba(255,95,95,0.1)', color: 'var(--s-text-secondary)' }} title={d.desc}>{d.label}</span>
              ))}
            </div>
          </div>


          {/* ── Relocated Modules Info ── */}
          <div style={{ padding: '10px 14px', borderRadius: 8, background: 'rgba(109,120,255,0.02)', border: '1px dashed rgba(109,120,255,0.1)' }}>
            <div style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)', lineHeight: 1.7 }}>
              <strong style={{ color: 'var(--s-text-muted)' }}>In funktionale Module integriert (NIST-Transparenz):</strong><br />
              🔬 YARA + MISP/IoC → <strong style={{ color: 'var(--s-text-secondary)' }}>Intel (ARGUS)</strong> &nbsp;|&nbsp;
              🚨 Kill-Switch + Adaptive → <strong style={{ color: 'var(--s-text-secondary)' }}>Shield (Firewall)</strong> &nbsp;|&nbsp;
              🔐 PIN Lock → <strong style={{ color: 'var(--s-text-secondary)' }}>Vault</strong> &nbsp;|&nbsp;
              📦 SBOM → <strong style={{ color: 'var(--s-text-secondary)' }}>Forge (System)</strong> &nbsp;|&nbsp;
              📊 SIEM Export → <strong style={{ color: 'var(--s-text-secondary)' }}>Aktivitätslog</strong>
            </div>
          </div>
        </div>

        {/* ── OSOP: One-Session-Only Protocol ── */}
        <div style={{ padding: '12px 18px', borderTop: '1px solid var(--s-border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--s-text)' }}>OSOP — Ephemeral Session</span>
            <InfoBadge glossaryKey="BSI" />
            <InfoBadge glossaryKey="DSGVO Art.5" />
          </div>
          <div style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)', marginBottom: 8, lineHeight: 1.5 }}>
            Alle Aktivit{'\u00e4'}tsprotokolle, Netzwerkdaten und Scan-Ergebnisse existieren <strong style={{ color: 'var(--s-text-secondary)' }}>ausschlie{'\u00df'}lich im Arbeitsspeicher</strong> (In-Memory-Database).
            Beim Beenden werden alle Sitzungsdaten sicher gel{'\u00f6'}scht. Firewall-Regeln, Vault und TOTP-Konfiguration bleiben erhalten.
          </div>
          <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', marginBottom: 8, lineHeight: 1.5, fontStyle: 'italic' }}>
            <strong style={{ color: 'var(--s-text-muted)' }}>Für Einsteiger:</strong> Stellen Sie sich OSOP wie einen Inkognito-Modus vor — aber für Ihre gesamte Sicherheitssoftware. Nach dem Schließen von Sentinel existieren keine Rückstände Ihrer Aktivitäten mehr. Dies entspricht dem DSGVO-Grundsatz der Datenminimierung (Art.5 Abs.1c) und dem Recht auf Löschung (Art.17).
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            <button
              className="s-btn s-btn-sm s-btn-ghost"
              style={{ fontSize: '0.65rem' }}
              onClick={async () => {
                try {
                  const r = await api()?.osop?.getSession?.();
                  if (r?.success) notify.info(`Session: ${r.sessionId?.slice(0, 8)}… | Started: ${r.startedAt} | Auth: ${r.authenticated ? 'Yes' : 'No'}`);
                  else notify.warning('OSOP session not available');
                } catch (e: any) { notify.error(e?.message || 'Error'); }
              }}
            >Session Info</button>
            <button
              className="s-btn s-btn-sm s-btn-ghost"
              style={{ fontSize: '0.65rem' }}
              onClick={async () => {
                try {
                  const r = await api()?.osop?.getNonce?.();
                  if (r?.success) notify.info(`IPC Nonce: ${r.nonce?.slice(0, 8)}… (session-scoped, anti-replay)`);
                  else notify.warning('Nonce not available');
                } catch (e: any) { notify.error(e?.message || 'Error'); }
              }}
            >IPC Nonce</button>
          </div>
          <div style={{ marginTop: 8, display: 'flex', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#00e676', display: 'inline-block' }} />
              <span style={{ fontSize: '0.575rem', color: 'var(--s-text-dim)' }}>Key in RAM only</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#00e676', display: 'inline-block' }} />
              <span style={{ fontSize: '0.575rem', color: 'var(--s-text-dim)' }}>Wipe on exit</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#00e676', display: 'inline-block' }} />
              <span style={{ fontSize: '0.575rem', color: 'var(--s-text-dim)' }}>Zero-Trust login</span>
            </div>
          </div>
        </div>
      </motion.div>

      {/* ─── Activity Log ─── */}
      <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} style={{ padding: 0, overflow: 'hidden' }}>
        <div className="s-flex-between" style={{ padding: '14px 18px', borderBottom: '1px solid var(--s-border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div className="s-heading-sm">{t('dashboard.activityFeed')} ({activity.length})</div>
            <InfoBadge glossaryKey="SIEM" />
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            {([
              { fmt: 'json' as const, tip: 'JSON: F\u00fcr Splunk, ELK Stack, Graylog \u2014 universelles Format f\u00fcr die meisten SIEM-Systeme' },
              { fmt: 'cef' as const, tip: 'CEF: Common Event Format f\u00fcr ArcSight, QRadar \u2014 Enterprise-Standard' },
              { fmt: 'syslog' as const, tip: 'Syslog RFC 5424: Sendet Events per UDP an einen Syslog-Server (z.B. rsyslog, Graylog)' },
            ]).map(({ fmt, tip }) => (
              <button key={fmt} className="s-btn s-btn-ghost s-btn-sm" style={{ fontSize: '0.6rem', textTransform: 'uppercase', padding: '2px 8px' }}
                title={tip}
                onClick={async () => {
                  try {
                    const r = await api()?.siem?.exportEvents?.(fmt);
                    if (r?.success) notify.success(`${r.count} Events als ${fmt.toUpperCase()} exportiert`);
                    else notify.error(r?.error || 'Export fehlgeschlagen');
                  } catch (e: any) { notify.error(e?.message || 'Error'); }
                }}
              >{fmt}</button>
            ))}
            <div style={{ width: 1, height: 16, background: 'rgba(109,120,255,0.15)', alignSelf: 'center' }} />
            <button className="s-btn s-btn-ghost s-btn-sm" onClick={fetchData}>{t('common.refresh')}</button>
            <button className="s-btn s-btn-danger s-btn-sm" onClick={handleClearLog}>{t('common.clear')}</button>
          </div>
        </div>
        <div style={{ maxHeight: 400, overflowY: 'auto' }}>
          {activity.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 40, color: 'var(--s-text-dim)' }}>{t('common.noData')}</div>
          ) : activity.map((entry, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 18px', borderBottom: '1px solid rgba(109,120,255,0.06)' }}>
              <div style={{
                width: 6, height: 6, borderRadius: '50%', marginTop: 6, flexShrink: 0,
                background: severityColor(entry.severity),
                boxShadow: `0 0 6px ${severityColor(entry.severity)}`,
              }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span className="s-badge s-badge-cyan" style={{ fontSize: '0.55rem' }}>{entry.module}</span>
                  <span style={{ fontSize: '0.75rem', fontWeight: 600 }}>{entry.action}</span>
                </div>
                <div className="s-truncate" style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', marginTop: 2 }}>{entry.details}</div>
              </div>
              <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)', flexShrink: 0 }}>
                {entry.timestamp ? new Date(entry.timestamp).toLocaleString('de-DE') : '—'}
              </span>
            </div>
          ))}
        </div>
      </motion.div>
      <InputModal {...modalProps} />
    </div>
  );
};

export default SettingsPage;
