/**
 * SENTINEL UNIFIED — Settings Page
 * Language, theme, app config, activity log viewer, ARGUS health, dev tools.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { notify } from '../components/Common/SentinelNotification';
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

      {/* ─── Activity Log ─── */}
      <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} style={{ padding: 0, overflow: 'hidden' }}>
        <div className="s-flex-between" style={{ padding: '14px 18px', borderBottom: '1px solid var(--s-border)' }}>
          <div className="s-heading-sm">{t('dashboard.activityFeed')} ({activity.length})</div>
          <div style={{ display: 'flex', gap: 8 }}>
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
    </div>
  );
};

export default SettingsPage;
