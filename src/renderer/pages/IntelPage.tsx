/**
 * SENTINEL UNIFIED — Threat Intelligence Page
 * ARGUS URL scanning with expandable detail sections, scan history,
 * threat timeline with collapsible entries, playbooks.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { notify } from '../components/Common/SentinelNotification';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (): any => (window as any).electronAPI;

interface ScanDetail {
  category: string;
  items: { label: string; value: string; severity?: 'safe' | 'warn' | 'danger' | 'info' }[];
}

interface ScanResult {
  url: string;
  safe: boolean;
  score?: number;
  details?: string;
  timestamp?: string;
  // Rich detail fields from ARGUS
  ssl?: Record<string, unknown>;
  domain?: Record<string, unknown>;
  threats?: string[];
  headers?: Record<string, string>;
  redirects?: string[];
  technologies?: string[];
  whois?: Record<string, unknown>;
}

interface ThreatEvent {
  id: string;
  timestamp: string;
  type: string;
  severity: string;
  source: string;
  description: string;
  remoteIP?: string;
  actionTaken?: string;
}

type Tab = 'scanner' | 'history' | 'threats' | 'playbooks';

/** Parse a ScanResult into expandable detail sections */
function buildDetailSections(r: ScanResult): ScanDetail[] {
  const sections: ScanDetail[] = [];

  // Overview
  const overview: ScanDetail = { category: 'Overview', items: [
    { label: 'URL', value: r.url, severity: 'info' },
    { label: 'Verdict', value: r.safe ? 'Safe' : 'Potentially Unsafe', severity: r.safe ? 'safe' : 'danger' },
  ]};
  if (r.score !== undefined) overview.items.push({ label: 'Safety Score', value: `${r.score}/100`, severity: r.score > 70 ? 'safe' : r.score > 40 ? 'warn' : 'danger' });
  if (r.timestamp) overview.items.push({ label: 'Scanned', value: new Date(r.timestamp).toLocaleString('de-DE'), severity: 'info' });
  sections.push(overview);

  // SSL/TLS
  if (r.ssl && typeof r.ssl === 'object') {
    const ssl = r.ssl as Record<string, unknown>;
    sections.push({ category: 'SSL / TLS', items: Object.entries(ssl).map(([k, v]) => ({
      label: k, value: String(v ?? '—'), severity: k.toLowerCase().includes('valid') && v ? 'safe' : 'info',
    }))});
  }

  // Domain Info
  if (r.domain && typeof r.domain === 'object') {
    const dom = r.domain as Record<string, unknown>;
    sections.push({ category: 'Domain Info', items: Object.entries(dom).map(([k, v]) => ({
      label: k, value: String(v ?? '—'), severity: 'info',
    }))});
  }

  // Threat Indicators
  if (r.threats && r.threats.length > 0) {
    sections.push({ category: 'Threat Indicators', items: r.threats.map((t, i) => ({
      label: `Threat #${i + 1}`, value: t, severity: 'danger' as const,
    }))});
  }

  // HTTP Headers
  if (r.headers && typeof r.headers === 'object') {
    const hdr = r.headers as Record<string, string>;
    const items = Object.entries(hdr).slice(0, 20).map(([k, v]) => ({
      label: k, value: String(v), severity: 'info' as const,
    }));
    if (items.length > 0) sections.push({ category: 'HTTP Headers', items });
  }

  // Redirects
  if (r.redirects && r.redirects.length > 0) {
    sections.push({ category: 'Redirects', items: r.redirects.map((url, i) => ({
      label: `Hop ${i + 1}`, value: url, severity: 'info' as const,
    }))});
  }

  // Technologies
  if (r.technologies && r.technologies.length > 0) {
    sections.push({ category: 'Technologies', items: r.technologies.map((t) => ({
      label: t, value: 'Detected', severity: 'info' as const,
    }))});
  }

  // Raw details fallback
  if (r.details && sections.length <= 1) {
    sections.push({ category: 'Details', items: [{ label: 'Info', value: r.details, severity: 'info' }] });
  }

  return sections;
}

const sevColor = (s?: string) => {
  if (s === 'safe') return 'var(--s-green)';
  if (s === 'warn') return 'var(--s-amber)';
  if (s === 'danger') return 'var(--s-red)';
  return 'var(--s-text-secondary)';
};

const IntelPage: React.FC = () => {
  const location = useLocation();
  const navState = (location.state || {}) as { scanUrl?: string; source?: string };

  const [tab, setTab] = useState<Tab>(navState.scanUrl ? 'scanner' : 'scanner');
  const [scanUrl, setScanUrl] = useState(navState.scanUrl || '');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['Overview']));
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [expandedThreats, setExpandedThreats] = useState<Set<string>>(new Set());
  const [argusHealth, setArgusHealth] = useState<{ running: boolean; port: number; status?: string; lastError?: string | null; uptimeMs?: number } | null>(null);
  const [argusRestarting, setArgusRestarting] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const a = api();
      if (a?.argus?.getHealth) {
        const h = await a.argus.getHealth();
        if (h?.data) {
          const d = h.data as any;
          setArgusHealth({ running: d.status === 'running' || d.running === true, port: d.port || 8080, status: d.status, lastError: d.lastError, uptimeMs: d.uptimeMs });
        }
      }
      if (a?.argus?.getScanHistory) {
        const r = await a.argus.getScanHistory();
        if (r?.data && Array.isArray(r.data)) setHistory(r.data);
      }
      if (a?.shield?.getThreatEvents) {
        const t = await a.shield.getThreatEvents({});
        if (t?.events && Array.isArray(t.events)) setThreats(t.events);
      }
    } catch (e: any) { console.warn('[IntelPage] fetchData:', e?.message); }
  }, []);

  useEffect(() => { fetchData(); const i = setInterval(fetchData, 15000); return () => clearInterval(i); }, [fetchData]);

  const handleRestartArgus = async () => {
    setArgusRestarting(true);
    try {
      await api()?.argus?.restart?.();
      await new Promise<void>((r) => setTimeout(r, 3000));
      await fetchData();
      notify.success('ARGUS restarted');
    } catch (e: any) { notify.error(e?.message || 'ARGUS restart failed'); }
    setArgusRestarting(false);
  };

  const handleScan = async () => {
    if (!scanUrl.trim()) return;
    setScanning(true);
    setScanResult(null);
    setExpandedSections(new Set(['Overview']));
    try {
      const r = await api()?.argus?.scanUrl?.(scanUrl.trim());
      if (r?.data) {
        setScanResult(r.data as ScanResult);
        notify.success(`Scan complete: ${scanUrl}`);
      } else {
        setScanResult({ url: scanUrl, safe: false, details: r?.error || 'Scan failed' });
        notify.error(r?.error || 'Scan returned no data');
      }
      fetchData();
    } catch (e: any) {
      setScanResult({ url: scanUrl, safe: false, details: String(e) });
      notify.error(e?.message || 'Scan failed');
    }
    setScanning(false);
  };

  const handleBatchScan = async () => {
    const urls = scanUrl.split('\n').map((u) => u.trim()).filter(Boolean);
    if (urls.length === 0) return;
    setScanning(true);
    try {
      await api()?.argus?.batchScan?.(urls);
      fetchData();
      notify.success(`Batch scan of ${urls.length} URLs complete`);
    } catch (e: any) { notify.error(e?.message || 'Batch scan failed'); }
    setScanning(false);
  };

  const handleClearHistory = async () => {
    await api()?.argus?.clearHistory?.();
    setHistory([]);
  };

  const toggleSection = (cat: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat); else next.add(cat);
      return next;
    });
  };

  const toggleThreat = (id: string) => {
    setExpandedThreats((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const detailSections = scanResult ? buildDetailSections(scanResult) : [];

  const TABS: { key: Tab; label: string; count?: number }[] = [
    { key: 'scanner', label: 'URL Scanner' },
    { key: 'history', label: 'Scan History', count: history.length },
    { key: 'threats', label: 'Threat Timeline', count: threats.length },
    { key: 'playbooks', label: 'Playbooks' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ─── Spacy Header ─── */}
      <div className="s-page-header">
        <div className="s-tab-bar">
          {TABS.map((t) => (
            <button key={t.key} className={`s-tab ${tab === t.key ? 's-tab-active' : ''}`} onClick={() => setTab(t.key)}>
              {t.label}
              {t.count !== undefined && <span className="s-tab-badge">{t.count}</span>}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '3px 10px', borderRadius: 8,
            background: argusHealth?.running ? 'rgba(61,255,143,0.06)' : 'rgba(255,95,95,0.06)',
            border: `1px solid ${argusHealth?.running ? 'rgba(61,255,143,0.18)' : 'rgba(255,95,95,0.18)'}`,
          }}>
            <span style={{
              width: 6, height: 6, borderRadius: '50%',
              background: argusHealth?.running ? 'var(--s-green)' : 'var(--s-red)',
              boxShadow: `0 0 6px ${argusHealth?.running ? 'var(--s-green)' : 'var(--s-red)'}`,
              animation: argusHealth?.running ? 'pulse-green 2s ease-in-out infinite' : 'pulse-red 1.5s ease-in-out infinite',
            }} />
            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: argusHealth?.running ? 'var(--s-green)' : 'var(--s-red)' }}>
              ARGUS {argusHealth?.running ? `Online :${argusHealth.port}` : 'Offline'}
            </span>
          </div>
          {!argusHealth?.running && (
            <button
              className="s-btn s-btn-primary s-btn-sm"
              style={{ fontSize: '0.65rem', padding: '3px 10px' }}
              onClick={handleRestartArgus}
              disabled={argusRestarting}
            >
              {argusRestarting ? 'Starting...' : '▶ Start'}
            </button>
          )}
        </div>
      </div>

      <AnimatePresence mode="wait">
        {/* ═══ Scanner Tab ═══ */}
        {tab === 'scanner' && (
          <motion.div key="scanner" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Rich offline state when ARGUS is not running */}
            {argusHealth && !argusHealth.running && (
              <div className="s-card-spacy" style={{ borderColor: 'rgba(255,95,95,0.25)', background: 'rgba(255,95,95,0.03)' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16 }}>
                  <div style={{
                    width: 52, height: 52, borderRadius: 14, flexShrink: 0,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: 'rgba(255,95,95,0.1)', border: '1px solid rgba(255,95,95,0.25)',
                    fontSize: 24,
                  }}>
                    🧠
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--s-red)', marginBottom: 4 }}>
                      ARGUS Backend Offline
                    </div>
                    <div style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)', lineHeight: 1.6 }}>
                      The ARGUS threat intelligence engine is not running. URL scanning, batch analysis, and threat intel lookups require ARGUS to be active.
                    </div>
                    {argusHealth.lastError && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--s-red)', marginTop: 6, fontFamily: 'var(--s-font-mono)', padding: '4px 8px', background: 'rgba(255,95,95,0.06)', borderRadius: 6, border: '1px solid rgba(255,95,95,0.15)' }}>
                        {argusHealth.lastError}
                      </div>
                    )}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12 }}>
                      <button
                        className="s-btn s-btn-primary s-btn-sm"
                        onClick={handleRestartArgus}
                        disabled={argusRestarting}
                      >
                        {argusRestarting ? 'Starting ARGUS...' : '▶ Start ARGUS Engine'}
                      </button>
                      <button className="s-btn s-btn-ghost s-btn-sm" onClick={fetchData}>↻ Retry Check</button>
                    </div>
                    <div style={{ marginTop: 14, padding: '10px 12px', background: 'rgba(109,120,255,0.04)', borderRadius: 8, border: '1px solid rgba(109,120,255,0.08)' }}>
                      <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
                        Available while offline
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: '0.75rem', color: 'var(--s-text-muted)' }}>
                        <span>• View previous scan history in the History tab</span>
                        <span>• Review recorded threat events in the Timeline tab</span>
                        <span>• Shield firewall and network monitoring remain active</span>
                        <span>• Local security scans run independently of ARGUS</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            <div className="s-card-spacy">
              <div className="s-heading-md" style={{ marginBottom: 16 }}>ARGUS URL Scanner</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <textarea
                  className="s-input"
                  placeholder="Enter URL to scan (one per line for batch scan)..."
                  value={scanUrl}
                  onChange={(e) => setScanUrl(e.target.value)}
                  rows={3}
                  style={{ resize: 'vertical', minHeight: 48 }}
                  onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleScan(); } }}
                />
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="s-btn s-btn-primary" onClick={handleScan} disabled={scanning || !scanUrl.trim() || (argusHealth !== null && !argusHealth.running)}>
                    {scanning ? 'Scanning...' : argusHealth && !argusHealth.running ? 'ARGUS Offline' : 'Scan URL'}
                  </button>
                  <button className="s-btn s-btn-ghost" onClick={handleBatchScan} disabled={scanning || !scanUrl.trim() || (argusHealth !== null && !argusHealth.running)}>
                    Batch Scan
                  </button>
                </div>
              </div>
            </div>

            {/* Scan Result with expandable sections */}
            {scanResult && (
              <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                {/* Result header */}
                <div className="s-card-spacy" style={{
                  borderColor: scanResult.safe ? 'rgba(61,255,143,0.3)' : 'rgba(255,95,95,0.3)',
                  borderBottomLeftRadius: detailSections.length > 0 ? 0 : undefined,
                  borderBottomRightRadius: detailSections.length > 0 ? 0 : undefined,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{
                      width: 48, height: 48, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background: scanResult.safe ? 'rgba(61,255,143,0.1)' : 'rgba(255,95,95,0.1)',
                      border: `2px solid ${scanResult.safe ? 'rgba(61,255,143,0.3)' : 'rgba(255,95,95,0.3)'}`,
                      fontSize: 20,
                    }}>
                      {scanResult.safe ? '✓' : '!'}
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 700, fontSize: '1rem', color: scanResult.safe ? 'var(--s-green)' : 'var(--s-red)' }}>
                        {scanResult.safe ? 'Safe' : 'Potentially Unsafe'}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', fontFamily: 'var(--s-font-mono)' }}>{scanResult.url}</div>
                    </div>
                    {scanResult.score !== undefined && (
                      <div style={{ textAlign: 'center' }}>
                        <div style={{
                          fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--s-font-display)',
                          color: scanResult.score > 70 ? 'var(--s-green)' : scanResult.score > 40 ? 'var(--s-amber)' : 'var(--s-red)',
                        }}>
                          {scanResult.score}
                        </div>
                        <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>/ 100</div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Expandable detail sections */}
                {detailSections.map((section) => {
                  const isOpen = expandedSections.has(section.category);
                  return (
                    <div key={section.category} style={{
                      border: '1px solid var(--s-border)',
                      borderTop: 'none',
                      background: 'var(--s-bg-card)',
                    }}>
                      <button
                        onClick={() => toggleSection(section.category)}
                        style={{
                          width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                          padding: '10px 18px', background: 'none', border: 'none', cursor: 'pointer',
                          color: 'var(--s-text)', fontSize: '0.8125rem', fontWeight: 600,
                        }}
                      >
                        <span>{section.category} ({section.items.length})</span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--s-text-dim)', transition: 'transform 0.2s', transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}>▼</span>
                      </button>
                      {isOpen && (
                        <div style={{ padding: '0 18px 12px' }}>
                          {section.items.map((item, idx) => (
                            <div key={`${item.label}-${idx}`} style={{
                              display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
                              padding: '4px 0', borderBottom: idx < section.items.length - 1 ? '1px solid rgba(109,120,255,0.06)' : 'none',
                            }}>
                              <span style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', flexShrink: 0, marginRight: 12 }}>{item.label}</span>
                              <span style={{
                                fontSize: '0.75rem', fontFamily: 'var(--s-font-mono)', fontWeight: 600,
                                color: sevColor(item.severity), textAlign: 'right', wordBreak: 'break-all',
                              }}>
                                {item.value}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}

                {/* Expand/Collapse all */}
                {detailSections.length > 1 && (
                  <div style={{ display: 'flex', justifyContent: 'center', padding: '8px 0' }}>
                    <button className="s-btn s-btn-ghost s-btn-sm" style={{ fontSize: '0.65rem' }} onClick={() => {
                      if (expandedSections.size === detailSections.length) {
                        setExpandedSections(new Set());
                      } else {
                        setExpandedSections(new Set(detailSections.map((s) => s.category)));
                      }
                    }}>
                      {expandedSections.size === detailSections.length ? 'Collapse All' : 'Expand All'}
                    </button>
                  </div>
                )}
              </motion.div>
            )}
          </motion.div>
        )}

        {/* ═══ History Tab ═══ */}
        {tab === 'history' && (
          <motion.div key="history" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="s-flex-between" style={{ padding: '14px 18px', borderBottom: '1px solid var(--s-border)' }}>
              <span className="s-heading-sm">Scan History ({history.length})</span>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={async () => { await api()?.argus?.exportHistory?.(); }}>Export</button>
                <button className="s-btn s-btn-danger s-btn-sm" onClick={handleClearHistory}>Clear</button>
              </div>
            </div>
            <div style={{ maxHeight: 450, overflowY: 'auto' }}>
              {history.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 40, color: 'var(--s-text-dim)' }}>No scan history</div>
              ) : history.map((entry, i) => (
                <div
                  key={`h-${i}`}
                  style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 18px', borderBottom: '1px solid rgba(109,120,255,0.06)', cursor: 'pointer' }}
                  onClick={() => { setScanResult(entry); setExpandedSections(new Set(['Overview'])); setTab('scanner'); }}
                >
                  <span className={`s-status-dot ${entry.safe ? 's-status-dot-online' : 's-status-dot-error'}`} />
                  <span style={{ flex: 1, fontFamily: 'var(--s-font-mono)', fontSize: '0.8125rem' }} className="s-truncate">{entry.url}</span>
                  {entry.score !== undefined && (
                    <span className={`s-badge ${entry.score > 70 ? 's-badge-green' : entry.score > 40 ? 's-badge-amber' : 's-badge-red'}`}>{entry.score}</span>
                  )}
                  <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)' }}>
                    {entry.timestamp ? new Date(entry.timestamp).toLocaleString('de-DE') : '—'}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>
        )}

        {/* ═══ Threats Tab ═══ */}
        {tab === 'threats' && (
          <motion.div key="threats" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {threats.length === 0 ? (
              <div className="s-card-spacy" style={{ textAlign: 'center', padding: 40, color: 'var(--s-text-dim)' }}>No threat events recorded</div>
            ) : threats.slice(0, 50).map((t) => {
              const isOpen = expandedThreats.has(t.id);
              return (
                <div key={t.id} className="s-card-compact-spacy" style={{ cursor: 'pointer' }} onClick={() => toggleThreat(t.id)}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                    <div style={{
                      width: 8, height: 8, borderRadius: '50%', marginTop: 6, flexShrink: 0,
                      background: t.severity === 'critical' ? 'var(--s-red)' : t.severity === 'high' ? 'var(--s-amber)' : 'var(--s-cyan)',
                      boxShadow: `0 0 8px ${t.severity === 'critical' ? 'rgba(255,95,95,0.5)' : t.severity === 'high' ? 'rgba(255,190,61,0.5)' : 'rgba(60,240,255,0.3)'}`,
                    }} />
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontWeight: 600, fontSize: '0.8125rem' }}>{t.type}</span>
                        <span className={`s-badge ${t.severity === 'critical' ? 's-badge-red' : t.severity === 'high' ? 's-badge-amber' : 's-badge-cyan'}`}>{t.severity}</span>
                        <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', marginLeft: 'auto', fontFamily: 'var(--s-font-mono)' }}>
                          {new Date(t.timestamp).toLocaleString('de-DE')}
                        </span>
                        <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', transition: 'transform 0.2s', transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}>▼</span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', marginTop: 4 }}>{t.description}</div>
                    </div>
                  </div>
                  {isOpen && (
                    <div style={{ marginTop: 10, padding: '10px 14px', background: 'rgba(8,8,28,0.3)', borderRadius: 'var(--s-radius-sm)' }}>
                      {[
                        { label: 'Source', value: t.source },
                        { label: 'Remote IP', value: t.remoteIP || '—' },
                        { label: 'Action Taken', value: t.actionTaken || '—' },
                        { label: 'Severity', value: t.severity },
                        { label: 'Timestamp', value: new Date(t.timestamp).toLocaleString('de-DE') },
                      ].map((item) => (
                        <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', borderBottom: '1px solid rgba(109,120,255,0.04)' }}>
                          <span style={{ fontSize: '0.7rem', color: 'var(--s-text-dim)' }}>{item.label}</span>
                          <span style={{ fontSize: '0.7rem', fontFamily: 'var(--s-font-mono)', fontWeight: 600 }}>{item.value}</span>
                        </div>
                      ))}
                      {t.remoteIP && t.remoteIP !== '—' && (
                        <div style={{ marginTop: 8, display: 'flex', gap: 6 }}>
                          <button className="s-btn s-btn-danger s-btn-sm" style={{ fontSize: '0.6rem', padding: '2px 8px' }} onClick={(e) => {
                            e.stopPropagation();
                            api()?.shield?.blockIP?.(t.remoteIP, `Blocked from threat: ${t.type}`);
                          }}>Block IP</button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </motion.div>
        )}

        {/* ═══ Playbooks Tab ═══ */}
        {tab === 'playbooks' && (
          <motion.div key="playbooks" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy">
            <div className="s-heading-md" style={{ marginBottom: 16 }}>Guardian Playbooks</div>
            <div style={{ textAlign: 'center', padding: 40, color: 'var(--s-text-dim)' }}>
              <div style={{ fontSize: 32, marginBottom: 12 }}>📋</div>
              <div>Playbook management coming soon</div>
              <div style={{ fontSize: '0.75rem', marginTop: 4 }}>Create automated response playbooks for threat events</div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default IntelPage;
