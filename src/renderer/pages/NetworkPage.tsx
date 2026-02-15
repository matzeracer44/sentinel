/**
 * SENTINEL UNIFIED — Network Monitor Page
 * Live connections with real Remote IPs, row actions (Block IP, Lookup, Kill),
 * state color coding, process list, TLS inspector, IP metadata lookup.
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { notify } from '../components/Common/SentinelNotification';
import { useTranslation } from 'react-i18next';
import { LegacyScanCheckItem as ScanCheckItem } from '../components/Common/ScanCheckItem';
import { getProcessKillRisk } from '../../shared/constants';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (): any => (window as any).electronAPI;

interface Connection {
  localIP: string;
  localPort: number;
  remoteIP: string;
  remotePort: number;
  state: string;
  pid?: number;
  process?: string;
}

interface IPMeta {
  ip: string;
  type: string;
  country: string;
  city: string;
  org: string;
  isp: string;
  riskLevel: string;
  reputation: string;
  asn?: string;
}

type Tab = 'connections' | 'processes' | 'tls' | 'metadata' | 'netscan' | 'edrscan';

const isLocal = (ip: string): boolean =>
  !ip || ip === '0.0.0.0' || ip === '::' || ip === '::1' || ip === '127.0.0.1' || ip.startsWith('0.0.0.');

const formatRemoteIp = (ip: string): string => {
  if (!ip || ip === '0.0.0.0' || ip === '::') return 'Resolving\u2026';
  return ip;
};

const STATE_CONFIG: Record<string, { color: string; dot: string; label: string }> = {
  Established: { color: 'var(--s-green)', dot: 's-status-dot-online', label: 'Connected' },
  ESTABLISHED: { color: 'var(--s-green)', dot: 's-status-dot-online', label: 'Connected' },
  Listen: { color: 'var(--s-cyan)', dot: 's-status-dot-online', label: 'Listening' },
  LISTENING: { color: 'var(--s-cyan)', dot: 's-status-dot-online', label: 'Listening' },
  CloseWait: { color: 'var(--s-amber)', dot: 's-status-dot-degraded', label: 'CloseWait' },
  CLOSE_WAIT: { color: 'var(--s-amber)', dot: 's-status-dot-degraded', label: 'CloseWait' },
  TimeWait: { color: 'var(--s-text-dim)', dot: 's-status-dot-offline', label: 'TimeWait' },
  TIME_WAIT: { color: 'var(--s-text-dim)', dot: 's-status-dot-offline', label: 'TimeWait' },
  SynSent: { color: 'var(--s-blue)', dot: 's-status-dot-online', label: 'SynSent' },
  SYN_SENT: { color: 'var(--s-blue)', dot: 's-status-dot-online', label: 'SynSent' },
  FinWait1: { color: 'var(--s-purple)', dot: 's-status-dot-degraded', label: 'FinWait1' },
  FinWait2: { color: 'var(--s-purple)', dot: 's-status-dot-degraded', label: 'FinWait2' },
};

const getStateConfig = (s: string) => STATE_CONFIG[s] || { color: 'var(--s-text-muted)', dot: 's-status-dot-offline', label: s };

const NetworkPage: React.FC = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>('connections');
  const [connections, setConnections] = useState<Connection[]>([]);
  const [processes, setProcesses] = useState<Array<{ pid: number; name: string; cpu: number; ram: number; path?: string; description?: string; company?: string; threads?: number; handles?: number; startTime?: string; killRisk?: string }>>([])
  const [expandedPid, setExpandedPid] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [tlsHost, setTlsHost] = useState('');
  const [tlsResult, setTlsResult] = useState<Record<string, unknown> | null>(null);
  const [metaIp, setMetaIp] = useState('');
  const [metaResult, setMetaResult] = useState<IPMeta | null>(null);
  const [searchFilter, setSearchFilter] = useState('');
  const [processSearch, setProcessSearch] = useState('');
  const [lookupModal, setLookupModal] = useState<IPMeta | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const [netScanning, setNetScanning] = useState(false);
  const [netScanResult, setNetScanResult] = useState<{ success: boolean; checks: Array<{ name: string; status: string; detail?: string; risk?: string }>; passed: number; total: number; score: number } | null>(null);
  const [edrScanning, setEdrScanning] = useState(false);
  const [edrScanResult, setEdrScanResult] = useState<{ success: boolean; checks: Array<{ name: string; status: string; detail?: string; risk?: string }>; passed: number; total: number; score: number } | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const a = api();
      if (a?.shield?.getNetworkTraffic) {
        const r = await a.shield.getNetworkTraffic();
        if (Array.isArray(r)) setConnections(r);
      }
      if (a?.shield?.getProcesses) {
        const p = await a.shield.getProcesses();
        if (Array.isArray(p)) setProcesses(p);
      }
    } catch (e: any) { console.warn('[NetworkPage] fetchData:', e?.message); }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();
    const i = setInterval(fetchData, 4000);
    return () => clearInterval(i);
  }, [fetchData]);

  // Restore persisted scan results on mount
  useEffect(() => {
    (async () => {
      try {
        const a = api();
        const [netR, edrR] = await Promise.all([
          a?.shield?.loadScanResult?.('networkScan'),
          a?.shield?.loadScanResult?.('edrScan'),
        ]);
        if (netR?.success && netR.entry?.data) setNetScanResult(netR.entry.data as any);
        if (edrR?.success && edrR.entry?.data) setEdrScanResult(edrR.entry.data as any);
      } catch { /* no persisted results */ }
    })();
  }, []);

  // ─── Row actions ───
  const handleBlockIp = async (ip: string) => {
    if (isLocal(ip)) return;
    try {
      const r = await api()?.shield?.blockIP?.(ip, 'Blocked from Network Monitor');
      if (r?.success) {
        notify.success(`Blocked ${ip}`);
        setActionMsg(`Blocked ${ip}`);
        setTimeout(() => setActionMsg(null), 3000);
      } else {
        notify.error(r?.message || `Failed to block ${ip}`);
      }
      fetchData();
    } catch (e: any) { notify.error(e?.message || 'Block failed'); }
  };

  const handleLookupIp = async (ip: string) => {
    if (isLocal(ip)) return;
    try {
      const r = await api()?.shield?.getIpMetadata?.(ip);
      if (r?.data) setLookupModal(r.data as IPMeta);
    } catch (e: any) { console.warn('[NetworkPage] IP lookup:', e?.message); }
  };

  const handleKillProcess = async (pid: number, name: string) => {
    try {
      const r = await api()?.shield?.killProcess?.(pid, name);
      if (r?.success) {
        notify.success(`Killed ${name} (PID ${pid})`);
        setActionMsg(`Killed ${name} (${pid})`);
        setTimeout(() => setActionMsg(null), 3000);
      } else {
        notify.error(r?.message || `Failed to kill ${name}`);
      }
      fetchData();
    } catch (e: any) { notify.error(e?.message || 'Kill failed'); }
  };

  // ─── TLS & Metadata ───
  const handleTlsInspect = async () => {
    if (!tlsHost.trim()) return;
    try {
      const r = await api()?.shield?.inspectTls?.(tlsHost.trim());
      setTlsResult(r as Record<string, unknown>);
    } catch (e) { setTlsResult({ error: String(e) }); }
  };

  const handleMetaLookup = async () => {
    if (!metaIp.trim()) return;
    try {
      const r = await api()?.shield?.getIpMetadata?.(metaIp.trim());
      if (r?.data) setMetaResult(r.data as IPMeta);
    } catch (e: any) { console.warn('[NetworkPage] IP metadata:', e?.message); }
  };

  // ─── Scan handlers ───
  const handleNetScan = useCallback(async () => {
    setNetScanning(true);
    try {
      const r = await api()?.shield?.networkScan?.();
      if (r?.success) {
        setNetScanResult(r as any);
        try { await api()?.shield?.saveScanResult?.('networkScan', r); } catch { /* best-effort */ }
        notify.success(`Network scan complete: ${r.passed}/${r.total} passed (${r.score}%)`);
      } else {
        notify.error(r?.error || 'Network scan failed');
      }
    } catch (e: any) { notify.error(e?.message || 'Network scan failed'); }
    setNetScanning(false);
  }, []);

  const handleEdrScan = useCallback(async () => {
    setEdrScanning(true);
    try {
      const r = await api()?.shield?.edrScan?.();
      if (r?.success) {
        setEdrScanResult(r as any);
        try { await api()?.shield?.saveScanResult?.('edrScan', r); } catch { /* best-effort */ }
        notify.success(`EDR scan complete: ${r.passed}/${r.total} passed (${r.score}%)`);
      } else {
        notify.error(r?.error || 'EDR scan failed');
      }
    } catch (e: any) { notify.error(e?.message || 'EDR scan failed'); }
    setEdrScanning(false);
  }, []);

  // ─── Filtering ───
  const filteredConns = useMemo(() => connections.filter((c) =>
    !searchFilter ||
    c.remoteIP?.includes(searchFilter) ||
    c.process?.toLowerCase().includes(searchFilter.toLowerCase()) ||
    String(c.remotePort).includes(searchFilter) ||
    c.state?.toLowerCase().includes(searchFilter.toLowerCase())
  ), [connections, searchFilter]);

  // ─── Stats ───
  const stats = useMemo(() => {
    const established = connections.filter((c) => c.state === 'Established' || c.state === 'ESTABLISHED').length;
    const listening = connections.filter((c) => c.state === 'Listen' || c.state === 'LISTENING').length;
    const uniqueIps = new Set(connections.map((c) => c.remoteIP).filter((ip) => !isLocal(ip))).size;
    return { established, listening, uniqueIps, total: connections.length };
  }, [connections]);

  const TABS: { key: Tab; labelKey: string; count?: number; badge?: string }[] = [
    { key: 'connections', labelKey: 'network.tabs.traffic', count: stats.total },
    { key: 'processes', labelKey: 'network.tabs.processes', count: processes.length },
    { key: 'tls', labelKey: 'network.tabs.tls' },
    { key: 'metadata', labelKey: 'network.ipMetadata.title' },
    { key: 'netscan', labelKey: 'network.tabs.networkScan', badge: netScanResult ? `${netScanResult.score}%` : undefined },
    { key: 'edrscan', labelKey: 'network.tabs.edr', badge: edrScanResult ? `${edrScanResult.score}%` : undefined },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ─── Spacy Header ─── */}
      <div className="s-page-header">
        <div className="s-tab-bar">
          {TABS.map((tb) => (
            <button key={tb.key} className={`s-tab ${tab === tb.key ? 's-tab-active' : ''}`} onClick={() => setTab(tb.key)}>
              {t(tb.labelKey)}
              {tb.count !== undefined && <span className="s-tab-badge">{tb.count}</span>}
              {tb.badge && <span className="s-tab-badge">{tb.badge}</span>}
            </button>
          ))}
        </div>
        <button className="s-btn s-btn-primary s-btn-sm" style={{ borderRadius: 8, fontSize: '0.65rem' }} onClick={fetchData} disabled={loading}>
          {loading ? '...' : `↻ ${t('common.refresh')}`}
        </button>
      </div>

      {/* Action message */}
      {actionMsg && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="s-badge s-badge-green" style={{ alignSelf: 'flex-end' }}>
          {actionMsg}
        </motion.div>
      )}

      {/* Stats bar (connections tab only) */}
      {tab === 'connections' && (
        <div style={{ display: 'flex', gap: 10 }}>
          {[
            { label: t('network.traffic.established'), value: stats.established, color: 'var(--s-green)' },
            { label: t('network.traffic.listening'), value: stats.listening, color: 'var(--s-cyan)' },
            { label: 'IPs', value: stats.uniqueIps, color: 'var(--s-amber)' },
            { label: t('common.total'), value: stats.total, color: 'var(--s-text-secondary)' },
          ].map((s) => (
            <div key={s.label} style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '6px 12px', borderRadius: 8,
              background: `${s.color}06`, border: `1px solid ${s.color}18`,
            }}>
              <span style={{
                width: 6, height: 6, borderRadius: '50%', background: s.color,
                boxShadow: `0 0 6px ${s.color}`,
              }} />
              <span style={{
                fontSize: '1.1rem', fontWeight: 800, fontFamily: 'var(--s-font-display)',
                color: s.color, textShadow: `0 0 12px ${s.color}33`,
              }}>{s.value}</span>
              <span style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{s.label}</span>
            </div>
          ))}
        </div>
      )}

      <AnimatePresence mode="wait">
        {/* ═══ Connections Tab ═══ */}
        {tab === 'connections' && (
          <motion.div key="conn" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--s-border)' }}>
              <input className="s-input" placeholder="Filter by IP, process, port, or state..." value={searchFilter} onChange={(e) => setSearchFilter(e.target.value)} style={{ maxWidth: 400 }} />
            </div>
            <div style={{ maxHeight: 520, overflowY: 'auto' }}>
              <table className="s-table">
                <thead>
                  <tr>
                    <th>{t('network.traffic.remoteAddress')}</th>
                    <th>{t('network.traffic.remotePort')}</th>
                    <th>{t('network.traffic.localPort')}</th>
                    <th>{t('network.traffic.state')}</th>
                    <th>{t('network.traffic.pid')}</th>
                    <th>{t('network.traffic.process')}</th>
                    <th style={{ width: 100 }}>{t('common.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredConns.length === 0 ? (
                    <tr><td colSpan={7} style={{ textAlign: 'center', padding: 32, color: 'var(--s-text-dim)' }}>{loading ? t('common.loading') : t('network.traffic.noConnections')}</td></tr>
                  ) : filteredConns.slice(0, 200).map((c, i) => {
                    const sc = getStateConfig(c.state);
                    const local = isLocal(c.remoteIP);
                    return (
                      <tr key={`${c.remoteIP}-${c.remotePort}-${c.localPort}-${i}`}>
                        <td style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem', color: local ? 'var(--s-text-dim)' : 'var(--s-text)' }}>
                          {formatRemoteIp(c.remoteIP)}
                        </td>
                        <td style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem' }}>{c.remotePort || '—'}</td>
                        <td style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem' }}>{c.localPort || '—'}</td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <span className={`s-status-dot ${sc.dot}`} />
                            <span style={{ color: sc.color, fontSize: '0.75rem', fontWeight: 600 }}>{sc.label}</span>
                          </div>
                        </td>
                        <td style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem' }}>{c.pid ?? '—'}</td>
                        <td className="s-truncate" style={{ maxWidth: 140, fontSize: '0.75rem' }}>{c.process || '—'}</td>
                        <td>
                          {!local && (
                            <div style={{ display: 'flex', gap: 4 }}>
                              <button className="s-btn s-btn-ghost s-btn-sm" style={{ padding: '2px 6px', fontSize: '0.65rem' }} onClick={() => handleBlockIp(c.remoteIP)} title="Block IP">🛡</button>
                              <button className="s-btn s-btn-ghost s-btn-sm" style={{ padding: '2px 6px', fontSize: '0.65rem' }} onClick={() => handleLookupIp(c.remoteIP)} title="IP Lookup">🔍</button>
                              {c.pid && c.pid > 0 && getProcessKillRisk(c.process || '', c.pid) !== 'forbidden' && getProcessKillRisk(c.process || '', c.pid) !== 'dangerous' && (
                                <button className="s-btn s-btn-ghost s-btn-sm" style={{ padding: '2px 6px', fontSize: '0.65rem', color: 'var(--s-red)' }} onClick={() => handleKillProcess(c.pid!, c.process || 'Unknown')} title="Kill Process">✕</button>
                              )}
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {filteredConns.length > 200 && (
              <div style={{ padding: '8px 18px', textAlign: 'center', fontSize: '0.75rem', color: 'var(--s-text-dim)', borderTop: '1px solid var(--s-border)' }}>
                {t('common.total')}: {filteredConns.length}
              </div>
            )}
          </motion.div>
        )}

        {/* ═══ Processes Tab ═══ */}
        {tab === 'processes' && (
          <motion.div key="proc" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--s-border)', display: 'flex', alignItems: 'center', gap: 12 }}>
              <input className="s-input" placeholder={t('network.processes.searchPlaceholder', 'Prozess suchen (Name oder PID)...')} value={processSearch} onChange={(e) => setProcessSearch(e.target.value)} style={{ maxWidth: 400, flex: 1 }} />
              <span style={{ fontSize: '0.7rem', color: 'var(--s-text-dim)', whiteSpace: 'nowrap' }}>
                {processes.filter((p) => !processSearch || p.name.toLowerCase().includes(processSearch.toLowerCase()) || String(p.pid).includes(processSearch)).length} / {processes.length}
              </span>
            </div>
            <div style={{ maxHeight: 520, overflowY: 'auto' }}>
              <table className="s-table">
                <thead><tr><th>{t('network.processes.pid')}</th><th>{t('network.processes.name')}</th><th>{t('network.processes.cpu')}</th><th>{t('network.processes.memory')}</th><th style={{ width: 100 }}>{t('common.actions')}</th></tr></thead>
                <tbody>
                  {processes.length === 0 ? (
                    <tr><td colSpan={5} style={{ textAlign: 'center', padding: 32, color: 'var(--s-text-dim)' }}>{t('network.processes.noProcesses')}</td></tr>
                  ) : processes.filter((p) => !processSearch || p.name.toLowerCase().includes(processSearch.toLowerCase()) || String(p.pid).includes(processSearch)).map((p) => {
                    const risk = getProcessKillRisk(p.name, p.pid);
                    const isExpanded = expandedPid === p.pid;
                    return (
                      <React.Fragment key={`p-${p.pid}`}>
                        <tr
                          style={{ cursor: 'pointer', background: isExpanded ? 'rgba(0,240,255,0.03)' : undefined }}
                          onClick={() => setExpandedPid(isExpanded ? null : p.pid)}
                        >
                          <td style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem' }}>{p.pid}</td>
                          <td style={{ fontSize: '0.8125rem' }}>
                            {p.name}
                            {risk === 'forbidden' && <span style={{ marginLeft: 6, fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>🔒</span>}
                          </td>
                          <td>
                            <span style={{ color: p.cpu > 80 ? 'var(--s-red)' : p.cpu > 50 ? 'var(--s-amber)' : 'var(--s-text-secondary)', fontWeight: 600, fontSize: '0.8125rem' }}>
                              {typeof p.cpu === 'number' && p.cpu >= 0 ? p.cpu.toFixed(1) : '0.0'}%
                            </span>
                          </td>
                          <td style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem' }}>{Math.round(p.ram)}</td>
                          <td>
                            <div style={{ display: 'flex', gap: 4, alignItems: 'center' }} onClick={(e) => e.stopPropagation()}>
                              {risk === 'forbidden' ? (
                                <span style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)' }} title="System-critical process">🔒 Protected</span>
                              ) : risk === 'dangerous' ? (
                                <span style={{ fontSize: '0.65rem', color: 'var(--s-amber)' }} title="Sentinel process">⚠ Sentinel</span>
                              ) : (
                                <>
                                  <button className={`s-btn s-btn-sm ${risk === 'caution' ? 's-btn-ghost' : 's-btn-danger'}`} style={{ padding: '2px 8px', fontSize: '0.7rem', color: risk === 'caution' ? 'var(--s-amber)' : undefined }} onClick={() => handleKillProcess(p.pid, p.name)}>{risk === 'caution' ? '⚠ Kill' : 'Kill'}</button>
                                  <button className="s-btn s-btn-ghost s-btn-sm" style={{ padding: '2px 6px', fontSize: '0.65rem' }} onClick={() => handleBlockIp(String(p.pid))} title="Block PID">🛡</button>
                                </>
                              )}
                            </div>
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr>
                            <td colSpan={5} style={{ padding: '10px 16px', background: 'rgba(0,240,255,0.02)', borderTop: '1px solid rgba(0,240,255,0.1)' }}>
                              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 24px', fontSize: '0.75rem' }}>
                                {p.path && <div><span style={{ color: 'var(--s-text-dim)' }}>Path:</span> <span style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.7rem', wordBreak: 'break-all' }}>{p.path}</span></div>}
                                {p.description && <div><span style={{ color: 'var(--s-text-dim)' }}>Description:</span> {p.description}</div>}
                                {p.company && <div><span style={{ color: 'var(--s-text-dim)' }}>Company:</span> {p.company}</div>}
                                {p.startTime && <div><span style={{ color: 'var(--s-text-dim)' }}>Started:</span> {new Date(p.startTime).toLocaleString('de-DE')}</div>}
                                {typeof p.threads === 'number' && <div><span style={{ color: 'var(--s-text-dim)' }}>Threads:</span> {p.threads}</div>}
                                {typeof p.handles === 'number' && <div><span style={{ color: 'var(--s-text-dim)' }}>Handles:</span> {p.handles?.toLocaleString()}</div>}
                              </div>
                              <div style={{ marginTop: 8, padding: '6px 10px', borderRadius: 6, background: risk === 'forbidden' ? 'rgba(255,34,68,0.08)' : risk === 'dangerous' ? 'rgba(255,170,0,0.08)' : 'rgba(0,255,136,0.05)', fontSize: '0.7rem' }}>
                                {risk === 'forbidden' ? '🔒 System-critical — terminating this process would cause a Blue Screen of Death or system hang.'
                                  : risk === 'dangerous' ? '⚠ Sentinel process — killing may destabilize the application.'
                                  : risk === 'caution' ? '⚠ System service — exercise caution when terminating.'
                                  : '✓ Safe to terminate if needed.'}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {/* ═══ TLS Inspector Tab ═══ */}
        {tab === 'tls' && (
          <motion.div key="tls" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy">
            <div className="s-heading-md" style={{ marginBottom: 16 }}>{t('network.tls.title')}</div>
            <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
              <input className="s-input" placeholder="Hostname (e.g. google.com)" value={tlsHost} onChange={(e) => setTlsHost(e.target.value)} style={{ maxWidth: 400 }} onKeyDown={(e) => e.key === 'Enter' && handleTlsInspect()} />
              <button className="s-btn s-btn-primary" onClick={handleTlsInspect} disabled={!tlsHost.trim()}>Inspect</button>
            </div>
            {tlsResult && (
              <div className="s-card-compact-spacy" style={{ background: 'rgba(8,8,28,0.4)' }}>
                <pre style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem', color: 'var(--s-text-secondary)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {JSON.stringify(tlsResult, null, 2)}
                </pre>
              </div>
            )}
          </motion.div>
        )}

        {/* ═══ IP Lookup Tab ═══ */}
        {tab === 'metadata' && (
          <motion.div key="meta" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy">
            <div className="s-heading-md" style={{ marginBottom: 16 }}>{t('network.ipMetadata.title')}</div>
            <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
              <input className="s-input" placeholder="IP address (e.g. 8.8.8.8)" value={metaIp} onChange={(e) => setMetaIp(e.target.value)} style={{ maxWidth: 400 }} onKeyDown={(e) => e.key === 'Enter' && handleMetaLookup()} />
              <button className="s-btn s-btn-primary" onClick={handleMetaLookup} disabled={!metaIp.trim()}>Lookup</button>
            </div>
            {metaResult && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
                {[
                  { label: 'IP', value: metaResult.ip },
                  { label: 'Type', value: metaResult.type },
                  { label: 'Country', value: metaResult.country },
                  { label: 'City', value: metaResult.city },
                  { label: 'ISP', value: metaResult.isp },
                  { label: 'Organization', value: metaResult.org },
                  { label: 'ASN', value: metaResult.asn },
                  { label: 'Risk Level', value: metaResult.riskLevel },
                  { label: 'Reputation', value: metaResult.reputation },
                ].map((item) => (
                  <div key={item.label} className="s-card-compact-spacy">
                    <div className="s-caption" style={{ marginBottom: 4 }}>{item.label}</div>
                    <div style={{ fontWeight: 600, fontSize: '0.875rem', color: item.label === 'Risk Level' && item.value === 'High' ? 'var(--s-red)' : undefined }}>{item.value || '—'}</div>
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}
        {/* ═══ Network Security Scan Tab ═══ */}
        {tab === 'netscan' && (
          <motion.div key="netscan" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="s-card-spacy" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <div style={{ flex: 1 }}>
                <div className="s-heading-sm">Sentinel Network & WFP Firewall Scan</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', marginTop: 4 }}>
                  15 checks: WFP kernel filters, Geo-IP blocking, DoH enforcement, TCP hardening, ARP spoofing protection, beaconing detection, zero-trust isolation
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                {netScanResult && <span style={{ fontWeight: 700, fontFamily: 'var(--s-font-display)', fontSize: '1.25rem', color: netScanResult.score >= 80 ? 'var(--s-green)' : netScanResult.score >= 50 ? 'var(--s-amber)' : 'var(--s-red)' }}>{netScanResult.score}/100</span>}
                <button className="s-btn s-btn-primary" onClick={handleNetScan} disabled={netScanning}>
                  {netScanning ? 'Scanning...' : netScanResult ? '\u21bb Re-scan' : '\ud83c\udf10 Run Network Scan'}
                </button>
              </div>
            </div>
            {netScanning && !netScanResult && <div className="s-card-spacy" style={{ textAlign: 'center', padding: 32, color: 'var(--s-text-dim)' }}>Scanning 15 network security checks (WFP, Geo-IP, DoH, TCP stack, ARP, DPI, SMB kill-switch...)</div>}
            {netScanResult && (
              <div className="s-card-spacy">
                <div style={{ display: 'flex', gap: 12, fontSize: '0.75rem', marginBottom: 12 }}>
                  <span style={{ color: 'var(--s-green)' }}>{'✓'} {netScanResult.passed} passed</span>
                  <span style={{ color: 'var(--s-red)' }}>{'✕'} {netScanResult.total - netScanResult.passed} issues</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 6 }}>
                  {netScanResult.checks.map((c, i) => (
                    <ScanCheckItem key={i} check={c} onNavigate={(p) => navigate(p)} />
                  ))}
                </div>
              </div>
            )}
          </motion.div>
        )}

        {/* ═══ EDR & Behavioral Scan Tab ═══ */}
        {tab === 'edrscan' && (
          <motion.div key="edrscan" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="s-card-spacy" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <div style={{ flex: 1 }}>
                <div className="s-heading-sm">Sentinel EDR & Behavioral Engine</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', marginTop: 4 }}>
                  24 checks: AMSI inspection, process hollowing, reflective DLL injection, LSASS protection, ransomware entropy, honeypot mesh, WMI persistence
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                {edrScanResult && <span style={{ fontWeight: 700, fontFamily: 'var(--s-font-display)', fontSize: '1.25rem', color: edrScanResult.score >= 80 ? 'var(--s-green)' : edrScanResult.score >= 50 ? 'var(--s-amber)' : 'var(--s-red)' }}>{edrScanResult.score}/100</span>}
                <button className="s-btn s-btn-primary" onClick={handleEdrScan} disabled={edrScanning}>
                  {edrScanning ? 'Scanning...' : edrScanResult ? '\u21bb Re-scan' : '\ud83d\udee1 Run EDR Scan'}
                </button>
              </div>
            </div>
            {edrScanning && !edrScanResult && <div className="s-card-spacy" style={{ textAlign: 'center', padding: 32, color: 'var(--s-text-dim)' }}>Scanning 24 EDR checks (AMSI, ETW, process hollowing, LSASS, ransomware detection, code integrity...)</div>}
            {edrScanResult && (
              <div className="s-card-spacy">
                <div style={{ display: 'flex', gap: 12, fontSize: '0.75rem', marginBottom: 12 }}>
                  <span style={{ color: 'var(--s-green)' }}>{'✓'} {edrScanResult.passed} passed</span>
                  <span style={{ color: 'var(--s-red)' }}>{'✕'} {edrScanResult.total - edrScanResult.passed} issues</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 6 }}>
                  {edrScanResult.checks.map((c, i) => (
                    <ScanCheckItem key={i} check={c} onNavigate={(p) => navigate(p)} />
                  ))}
                </div>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ═══ IP Lookup Modal (from row action) ═══ */}
      <AnimatePresence>
        {lookupModal && (
          <motion.div className="s-overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setLookupModal(null)}>
            <motion.div className="s-modal" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 12 }} onClick={(e) => e.stopPropagation()}>
              <div className="s-modal-header">
                <span style={{ fontWeight: 700 }}>IP Lookup: {lookupModal.ip}</span>
                <button className="s-modal-close" onClick={() => setLookupModal(null)}>✕</button>
              </div>
              <div className="s-modal-body">
                {[
                  { label: 'Type', value: lookupModal.type },
                  { label: 'Country', value: lookupModal.country },
                  { label: 'City', value: lookupModal.city },
                  { label: 'ISP', value: lookupModal.isp },
                  { label: 'Organization', value: lookupModal.org },
                  { label: 'ASN', value: lookupModal.asn },
                  { label: 'Risk Level', value: lookupModal.riskLevel },
                  { label: 'Reputation', value: lookupModal.reputation },
                ].map((item) => (
                  <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid rgba(109,120,255,0.06)' }}>
                    <span style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)' }}>{item.label}</span>
                    <span style={{ fontSize: '0.8125rem', fontFamily: 'var(--s-font-mono)', fontWeight: 600 }}>{item.value || '—'}</span>
                  </div>
                ))}
              </div>
              <div className="s-modal-footer">
                <button className="s-btn s-btn-danger s-btn-sm" onClick={() => { handleBlockIp(lookupModal.ip); setLookupModal(null); }}>Block IP</button>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => setLookupModal(null)}>Close</button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default NetworkPage;
