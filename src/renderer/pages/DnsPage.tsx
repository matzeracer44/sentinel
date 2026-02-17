/**
 * SENTINEL UNIFIED — DNS & Privacy Page
 * Real DNS configuration via Set-DnsClientServerAddress, admin check,
 * rollback support, DNS speed test, hosts file editor.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { notify } from '../components/Common/SentinelNotification';
import InfoBadge from '../components/Common/InfoBadge';
import InputModal, { useInputModal } from '../components/Common/InputModal';
import { useTranslation } from 'react-i18next';
import { LegacyScanCheckItem as ScanCheckItem } from '../components/Common/ScanCheckItem';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (): any => (window as any).electronAPI;

type Tab = 'dns' | 'hosts' | 'privacy';

interface DnsPreset {
  name: string;
  primary: string;
  secondary: string;
  desc: string;
  latency?: number | null;
  testing?: boolean;
}

const DNS_PRESETS_DATA: Omit<DnsPreset, 'latency' | 'testing'>[] = [
  { name: 'Cloudflare', primary: '1.1.1.1', secondary: '1.0.0.1', desc: 'Fast & privacy-focused' },
  { name: 'Google', primary: '8.8.8.8', secondary: '8.8.4.4', desc: 'Reliable & fast' },
  { name: 'Quad9', primary: '9.9.9.9', secondary: '149.112.112.112', desc: 'Security-focused, blocks malware' },
  { name: 'OpenDNS', primary: '208.67.222.222', secondary: '208.67.220.220', desc: 'Content filtering available' },
  { name: 'AdGuard', primary: '94.140.14.14', secondary: '94.140.15.15', desc: 'Ad & tracker blocking' },
];

interface CurrentDns {
  primary: string;
  secondary: string;
  name: string;
  adapter?: string;
}

const DnsPage: React.FC = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { showInput, modalProps } = useInputModal();
  const [tab, setTab] = useState<Tab>('dns');
  const [currentDns, setCurrentDns] = useState<CurrentDns | null>(null);
  const [presets, setPresets] = useState<DnsPreset[]>(DNS_PRESETS_DATA.map((p) => ({ ...p, latency: null, testing: false })));
  const [hostsContent, setHostsContent] = useState('');
  const [hostsModified, setHostsModified] = useState(false);
  const [saving, setSaving] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [hasBackup, setHasBackup] = useState(false);
  const [customPrimary, setCustomPrimary] = useState('');
  const [customSecondary, setCustomSecondary] = useState('');
  const [message, setMessage] = useState<{ text: string; type: 'success' | 'error' } | null>(null);
  const [privScanning, setPrivScanning] = useState(false);
  const [privResult, setPrivResult] = useState<{ success: boolean; module: string; checks: Array<{ name: string; status: string; detail?: string; risk?: string }>; passed: number; total: number; score: number } | null>(null);

  const showMsg = (text: string, type: 'success' | 'error') => {
    setMessage({ text, type });
    setTimeout(() => setMessage(null), 4000);
    if (type === 'success') notify.success(text);
    else notify.error(text);
  };

  const fetchData = useCallback(async () => {
    try {
      const a = api();
      if (a?.ghost?.getCurrentDNS) {
        const r = await a.ghost.getCurrentDNS();
        if (r?.success) setCurrentDns(r as CurrentDns);
      }
      if (a?.admin?.checkAdminRights) {
        const r = await a.admin.checkAdminRights();
        if (r && typeof r.isAdmin === 'boolean') setIsAdmin(r.isAdmin);
      }
    } catch (e: any) { console.warn('[DnsPage] fetchData:', e?.message); }
  }, []);

  const fetchHosts = useCallback(async () => {
    try {
      const r = await api()?.ghost?.getHostsFile?.();
      if (r?.content) setHostsContent(r.content);
    } catch (e: any) { console.warn('[DnsPage] fetchHosts:', e?.message); }
  }, []);

  useEffect(() => { fetchData(); fetchHosts(); }, [fetchData, fetchHosts]);

  // Restore persisted privacy scan result on mount
  useEffect(() => {
    (async () => {
      try {
        const r = await api()?.shield?.loadScanResult?.('privacyScan');
        if (r?.success && r.entry?.data) setPrivResult(r.entry.data as any);
      } catch { /* no persisted result */ }
    })();
  }, []);

  const handlePrivacyScan = useCallback(async () => {
    setPrivScanning(true);
    try {
      const r = await api()?.shield?.privacyScan?.();
      if (r?.success) {
        setPrivResult(r as any);
        try { await api()?.shield?.saveScanResult?.('privacyScan', r); } catch { /* best-effort */ }
        notify.success(`Privacy scan: ${r.passed}/${r.total} passed (${r.score}%)`);
      } else {
        notify.error(r?.error || 'Privacy scan failed');
      }
    } catch (e: any) { notify.error(e?.message || 'Privacy scan failed'); }
    setPrivScanning(false);
  }, []);

  const handleSetDns = async (primary: string, secondary: string) => {
    if (!isAdmin) {
      showMsg('Admin privileges required. Run Sentinel as Administrator.', 'error');
      return;
    }
    try {
      const r = await api()?.ghost?.setDNS?.(primary, secondary);
      if (r?.success) {
        setCurrentDns({ primary, secondary, name: 'Custom' });
        setHasBackup(true);
        showMsg(r.message || `DNS set to ${primary} / ${secondary}`, 'success');
      } else {
        showMsg(r?.message || 'DNS konnte nicht gesetzt werden', 'error');
      }
    } catch (e) { showMsg(String(e), 'error'); }
  };

  const handleRollback = async () => {
    try {
      const r = await api()?.ghost?.rollbackDNS?.();
      if (r?.success) {
        setHasBackup(false);
        showMsg(r.message || 'DNS rolled back', 'success');
        fetchData();
      } else {
        showMsg(r?.message || 'Rollback failed', 'error');
      }
    } catch (e) { showMsg(String(e), 'error'); }
  };

  const handleTestSpeed = async (index: number) => {
    setPresets((prev) => prev.map((p, i) => i === index ? { ...p, testing: true } : p));
    try {
      const r = await api()?.ghost?.testDNSSpeed?.(presets[index].primary);
      setPresets((prev) => prev.map((p, i) => i === index ? { ...p, latency: r?.latency ?? -1, testing: false } : p));
    } catch {
      setPresets((prev) => prev.map((p, i) => i === index ? { ...p, latency: -1, testing: false } : p));
    }
  };

  const handleTestAll = async () => {
    for (let i = 0; i < presets.length; i++) {
      await handleTestSpeed(i);
    }
  };

  const handleSaveHosts = async () => {
    if (!isAdmin) { showMsg('Admin privileges required', 'error'); return; }
    setSaving(true);
    try {
      const r = await api()?.ghost?.saveHostsFile?.(hostsContent);
      if (r?.success) {
        setHostsModified(false);
        showMsg('Hosts-Datei gespeichert', 'success');
      } else {
        showMsg(r?.error || 'Speichern fehlgeschlagen', 'error');
      }
    } catch (e) { showMsg(String(e), 'error'); }
    setSaving(false);
  };

  const handleSetCustomDns = () => {
    if (!customPrimary.trim()) return;
    handleSetDns(customPrimary.trim(), customSecondary.trim());
  };

  const latencyColor = (ms: number | null | undefined): string => {
    if (ms == null || ms < 0) return 'var(--s-text-dim)';
    if (ms < 20) return 'var(--s-green)';
    if (ms < 50) return 'var(--s-cyan)';
    if (ms < 100) return 'var(--s-amber)';
    return 'var(--s-red)';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ─── Spacy Header ─── */}
      <div className="s-page-header">
        <div className="s-tab-bar">
          <button className={`s-tab ${tab === 'dns' ? 's-tab-active' : ''}`} onClick={() => setTab('dns')}>{t('dns.tabs.dns')}</button>
          <button className={`s-tab ${tab === 'hosts' ? 's-tab-active' : ''}`} onClick={() => setTab('hosts')}>{t('dns.tabs.hosts')}</button>
          <button className={`s-tab ${tab === 'privacy' ? 's-tab-active' : ''}`} onClick={() => setTab('privacy')}>
            {t('dns.tabs.privacy')} {privResult && <span className="s-tab-badge">{privResult.score}%</span>}
          </button>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {!isAdmin && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 5, padding: '3px 10px', borderRadius: 8,
              background: 'rgba(255,190,61,0.06)', border: '1px solid rgba(255,190,61,0.18)',
            }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--s-amber)', boxShadow: '0 0 6px var(--s-amber)' }} />
              <span style={{ fontSize: '0.65rem', fontWeight: 600, color: 'var(--s-amber)' }}>{t('admin.limited')}</span>
            </div>
          )}
          {message && <span className={`s-badge ${message.type === 'success' ? 's-badge-green' : 's-badge-red'}`}>{message.text}</span>}
        </div>
      </div>

      <AnimatePresence mode="wait">
        {tab === 'dns' && (
          <motion.div key="dns" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* DSGVO + DNS Info Callout */}
            <div className="s-callout s-callout-success" style={{ gap: 12 }}>
              <div style={{ display: 'flex', gap: 6, flexShrink: 0, marginTop: 2 }}>
                <InfoBadge glossaryKey="DSGVO Art.5" />
                <InfoBadge glossaryKey="LOKAL" />
              </div>
              <div style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)', lineHeight: 1.5 }}>
                <strong style={{ color: 'var(--s-text-muted)' }}>Was ist DNS?</strong>{' Das Domain Name System (DNS) ist das \u201eTelefonbuch des Internets\u201c \u2014 es \u00fcbersetzt Webseiten-Namen (z.B. google.de) in IP-Adressen. Ihr DNS-Anbieter sieht '}<strong style={{ color: 'var(--s-text-secondary)' }}>jede Webseite</strong>{', die Sie besuchen. Ein datenschutzfreundlicher DNS-Anbieter wie Cloudflare oder Quad9 sch\u00fctzt Ihre Privatsph\u00e4re besser als der Standard-DNS Ihres Internetanbieters. Alle \u00c4nderungen werden direkt auf Ihrem Ger\u00e4t vorgenommen \u2014 keine Daten\u00fcbertragung an Dritte.'}
              </div>
            </div>
            {/* Current DNS + Rollback */}
            <div className="s-card-spacy" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--s-green)', boxShadow: '0 0 8px var(--s-green)', animation: 'pulse-green 2s ease-in-out infinite', flexShrink: 0 }} />
              <div style={{ flex: 1 }}>
                <div className="s-heading-sm">{t('dns.settings.currentDNS')}</div>
                <div style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.875rem', marginTop: 4 }}>
                  {currentDns ? `${currentDns.primary}${currentDns.secondary ? ' / ' + currentDns.secondary : ''}` : t('common.loading')}
                </div>
                {currentDns?.adapter && (
                  <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                    Adapter: {currentDns.adapter}
                  </div>
                )}
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={fetchData}>↻ {t('common.refresh')}</button>
                {hasBackup && (
                  <button className="s-btn s-btn-danger s-btn-sm" onClick={handleRollback}>↩ {t('dns.settings.rollback')}</button>
                )}
              </div>
            </div>

            {/* Custom DNS */}
            <div className="s-card-spacy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-cyan), rgba(167,139,250,0.8))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>{t('dns.settings.custom')}</span>
                <div className="s-section-divider" style={{ flex: 1 }} />
              </div>
              <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end' }}>
                <div style={{ flex: 1 }}>
                  <label className="s-caption" style={{ display: 'block', marginBottom: 4 }}>{t('dns.settings.primary')}</label>
                  <input className="s-input" placeholder="e.g. 1.1.1.1" value={customPrimary} onChange={(e) => setCustomPrimary(e.target.value)} />
                </div>
                <div style={{ flex: 1 }}>
                  <label className="s-caption" style={{ display: 'block', marginBottom: 4 }}>{t('dns.settings.secondary')}</label>
                  <input className="s-input" placeholder="e.g. 1.0.0.1 (optional)" value={customSecondary} onChange={(e) => setCustomSecondary(e.target.value)} />
                </div>
                <button className="s-btn s-btn-primary" onClick={handleSetCustomDns} disabled={!customPrimary.trim() || !isAdmin}>
                  {t('common.apply')}
                </button>
              </div>
            </div>

            {/* DNS Presets */}
            <div className="s-flex-between">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-cyan), var(--s-green))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>{t('dns.settings.provider')}</span>
                <div className="s-section-divider" style={{ flex: 1, maxWidth: 80 }} />
              </div>
              <button className="s-btn s-btn-ghost s-btn-sm" onClick={handleTestAll}>{t('dns.settings.testSpeed')}</button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 12 }}>
              {presets.map((preset, idx) => {
                const isActive = currentDns?.primary === preset.primary;
                return (
                  <motion.div
                    key={preset.name}
                    className="s-card-compact-spacy"
                    whileHover={{ borderColor: 'var(--s-border-bright)', y: -2 }}
                    style={{
                      cursor: isAdmin ? 'pointer' : 'not-allowed',
                      borderColor: isActive ? 'rgba(60,240,255,0.4)' : undefined,
                      opacity: isAdmin ? 1 : 0.7,
                    }}
                    onClick={() => isAdmin && handleSetDns(preset.primary, preset.secondary)}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                      <span style={{ fontWeight: 600, fontSize: '0.875rem' }}>{preset.name}</span>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        {isActive && <span className="s-badge s-badge-green" style={{ fontSize: '0.55rem' }}>{t('common.active').toUpperCase()}</span>}
                        <span className="s-badge s-badge-cyan" style={{ fontSize: '0.55rem' }}>{t('common.apply')}</span>
                      </div>
                    </div>
                    <div style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem', color: 'var(--s-text-secondary)', marginBottom: 4 }}>
                      {preset.primary} / {preset.secondary}
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)' }}>{preset.desc}</span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        {preset.testing ? (
                          <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>{t('dns.settings.testing')}</span>
                        ) : preset.latency != null ? (
                          <span style={{ fontSize: '0.7rem', fontFamily: 'var(--s-font-mono)', fontWeight: 700, color: latencyColor(preset.latency) }}>
                            {preset.latency < 0 ? 'Timeout' : `${preset.latency}ms`}
                          </span>
                        ) : (
                          <button
                            className="s-btn s-btn-ghost s-btn-sm"
                            style={{ padding: '1px 6px', fontSize: '0.6rem' }}
                            onClick={(e) => { e.stopPropagation(); handleTestSpeed(idx); }}
                          >
                            {t('dns.settings.testSpeed')}
                          </button>
                        )}
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </motion.div>
        )}

        {tab === 'hosts' && (
          <motion.div key="hosts" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy">
            <div className="s-flex-between" style={{ marginBottom: 12 }}>
              <div className="s-heading-md">{t('dns.hosts.title')}</div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                {hostsModified && <span className="s-badge s-badge-amber">Modified</span>}
                {!isAdmin && <span style={{ fontSize: '0.6875rem', color: 'var(--s-amber)' }}>Read-only (no admin)</span>}
                <button
                  className="s-btn s-btn-ghost s-btn-sm"
                  disabled={!isAdmin}
                  onClick={async () => {
                    const url = await showInput({ title: 'Blocklist importieren', message: 'Geben Sie die URL einer Hosts-Blockliste ein. Empfohlen: Steven Black (Werbung + Malware + Tracker).', placeholder: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', variant: 'info', confirmLabel: 'Importieren' });
                    if (!url?.trim()) return;
                    try {
                      const r = await api()?.ghost?.importHostsBlocklist?.(url.trim());
                      if (r?.success) { notify.success(r.message || 'Blocklist imported'); fetchHosts(); }
                      else notify.error(r?.error || 'Import failed');
                    } catch (e: any) { notify.error(e?.message || 'Import failed'); }
                  }}
                >
                  Import Blocklist
                </button>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={fetchHosts}>↻</button>
                <button className="s-btn s-btn-primary s-btn-sm" onClick={handleSaveHosts} disabled={saving || !hostsModified || !isAdmin}>
                  {saving ? 'Saving...' : 'Save'}
                </button>
              </div>
            </div>
            {/* Beginner explanation */}
            <div style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)', lineHeight: 1.5, padding: '8px 12px', borderRadius: 8, background: 'rgba(109,120,255,0.02)', border: '1px dashed rgba(109,120,255,0.08)', marginBottom: 4 }}>
              <strong style={{ color: 'var(--s-text-muted)' }}>{'Was ist die Hosts-Datei?'}</strong>{' Die Hosts-Datei ist ein lokales "Telefonbuch", das Domainnamen direkt auf IP-Adressen zuordnet \u2014 '}<strong style={{ color: 'var(--s-text-secondary)' }}>bevor</strong>{' DNS abgefragt wird. Durch Eintr\u00e4ge wie '}<code style={{ fontSize: '0.6rem', color: 'var(--s-cyan)' }}>0.0.0.0 tracking.example.com</code>{' k\u00f6nnen Sie Tracker, Werbung und Malware-Domains systemweit blockieren. Importieren Sie eine Blockliste (z.B. Steven Black) f\u00fcr sofortigen Schutz.'}
            </div>
            <textarea
              className="s-input"
              value={hostsContent}
              onChange={(e) => { setHostsContent(e.target.value); setHostsModified(true); }}
              readOnly={!isAdmin}
              rows={20}
              style={{
                resize: 'vertical', fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem',
                lineHeight: 1.6, minHeight: 300,
                opacity: isAdmin ? 1 : 0.7,
              }}
            />
            <div style={{ marginTop: 8, fontSize: '0.6875rem', color: 'var(--s-text-dim)' }}>
              {'C:\\Windows\\System32\\drivers\\etc\\hosts \u2014 Erfordert Administratorrechte zum Speichern'}
            </div>
          </motion.div>
        )}
        {tab === 'privacy' && (
          <motion.div key="privacy" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* DSGVO + Privacy Info */}
            <div style={{ padding: '10px 16px', borderRadius: 10, background: 'rgba(0,230,118,0.04)', border: '1px solid rgba(0,230,118,0.12)', display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
              <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                <InfoBadge glossaryKey="DSGVO Art.25" />
                <InfoBadge glossaryKey="LOKAL" />
              </div>
              <span style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)', lineHeight: 1.4 }}>
                {'Der Privacy-Scan pr\u00fcft 22 Windows-Einstellungen gegen Telemetrie, Tracker und Datenlecks. Alle Pr\u00fcfungen laufen lokal \u2014 entspricht DSGVO Art.25 (Datenschutz durch Technikgestaltung).'}
              </span>
            </div>
            {/* Scan trigger */}
            <div className="s-card-spacy" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <div style={{ flex: 1 }}>
                <div className="s-heading-sm">{'Sentinel Privatsph\u00e4re- & H\u00e4rtungs-Scan'}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', marginTop: 4 }}>
                  {'22 Tiefenpr\u00fcfungen: Telemetrie-Blockierung, Webcam/Mikrofon-Sperre, Zwischenablage-Schutz, Metadaten-Bereinigung, GPO-H\u00e4rtung, USB-Port-Sperre u.v.m.'}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                {privResult && (
                  <span style={{ fontWeight: 700, fontFamily: 'var(--s-font-display)', fontSize: '1.25rem', color: privResult.score >= 80 ? 'var(--s-green)' : privResult.score >= 50 ? 'var(--s-amber)' : 'var(--s-red)' }}>
                    {privResult.score}/100
                  </span>
                )}
                <button className="s-btn s-btn-primary" onClick={handlePrivacyScan} disabled={privScanning}>
                  {privScanning ? 'Wird gescannt...' : privResult ? '\u21bb Erneut scannen' : '\ud83d\udd12 Datenschutz-Scan'}
                </button>
              </div>
            </div>

            {/* Results */}
            {privScanning && !privResult && (
              <div className="s-card-spacy" style={{ textAlign: 'center', padding: 32, color: 'var(--s-text-dim)' }}>
                {'22 Privatsph\u00e4re- und H\u00e4rtungspr\u00fcfungen werden durchgef\u00fchrt (Telemetrie, Webcam, Zwischenablage, Metadaten, GPO, USB, Sperrbildschirm...)'}
              </div>
            )}
            {privResult && (
              <div className="s-card-spacy">
                <div className="s-flex-between" style={{ marginBottom: 12 }}>
                  <div style={{ display: 'flex', gap: 12, fontSize: '0.75rem' }}>
                    <span style={{ color: 'var(--s-green)' }}>{'\u2713'} {privResult.passed} bestanden</span>
                    <span style={{ color: 'var(--s-red)' }}>{'\u2715'} {privResult.total - privResult.passed} Probleme</span>
                    <span style={{ color: 'var(--s-text-dim)' }}>{privResult.total} gesamt</span>
                  </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 6 }}>
                  {privResult.checks.map((c, i) => (
                    <ScanCheckItem key={i} check={c} onNavigate={(p) => navigate(p)} />
                  ))}
                </div>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
      <InputModal {...modalProps} />
    </div>
  );
};

export default DnsPage;
