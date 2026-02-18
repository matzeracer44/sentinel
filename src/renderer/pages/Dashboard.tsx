/**
 * SENTINEL UNIFIED — Dashboard Page
 * System health overview, threat summary, live stats, quick actions, and activity feed.
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { notify } from '../components/Common/SentinelNotification';
import InfoBadge from '../components/Common/InfoBadge';
import { LegacyScanCheckItem } from '../components/Common/ScanCheckItem';
import { useTranslation } from 'react-i18next';

interface SystemStats {
  cpu: number;
  ram: number;
  disk: number;
}

interface HealthReport {
  overall: string;
  score: number;
  components: Array<{ name: string; status: string; message?: string }>;
}

interface ActivityEntry {
  id: number;
  timestamp: string;
  module: string;
  action: string;
  details: string;
  severity: string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (): any => (window as any).electronAPI;

const CLUSTER_CARDS = [
  { key: 'firewall', labelKey: 'dashboard.clusterFirewall', icon: '🛡', color: 'var(--s-cluster-firewall)', path: '/firewall', descKey: 'dashboard.clusterFirewallDesc' },
  { key: 'intel', labelKey: 'dashboard.clusterIntel', icon: '🔍', color: 'var(--s-cluster-intel)', path: '/intel', descKey: 'dashboard.clusterIntelDesc' },
  { key: 'network', labelKey: 'dashboard.clusterNetwork', icon: '🌐', color: 'var(--s-cluster-network)', path: '/network', descKey: 'dashboard.clusterNetworkDesc' },
  { key: 'dns', labelKey: 'dashboard.clusterDns', icon: '🔒', color: 'var(--s-cluster-dns)', path: '/dns', descKey: 'dashboard.clusterDnsDesc' },
  { key: 'system', labelKey: 'dashboard.clusterSystem', icon: '⚙', color: 'var(--s-cluster-system)', path: '/system', descKey: 'dashboard.clusterSystemDesc' },
  { key: 'vault', labelKey: 'dashboard.clusterVault', icon: '🗝', color: 'var(--s-cluster-vault)', path: '/vault', descKey: 'dashboard.clusterVaultDesc' },
  { key: 'automation', labelKey: 'dashboard.clusterAutomation', icon: '⚡', color: 'var(--s-cluster-automation)', path: '/automation', descKey: 'dashboard.clusterAutomationDesc' },
];

const QUICK_ACTIONS = [
  { id: 'deep-scan', labelKey: 'dashboard.deepScan', icon: '🔬', descKey: 'dashboard.deepScanDesc' },
  { id: 'gaming', labelKey: 'dashboard.gamingMode', icon: '🎮', descKey: 'dashboard.gamingModeDesc' },
  { id: 'privacy', labelKey: 'dashboard.privacyMode', icon: '👁', descKey: 'dashboard.privacyModeDesc' },
  { id: 'cleanup', labelKey: 'dashboard.cleanup', icon: '🧹', descKey: 'dashboard.cleanupDesc' },
];

const severityColor = (s: string) => {
  switch (s) {
    case 'error': return 'var(--s-red)';
    case 'warning': return 'var(--s-amber)';
    case 'success': return 'var(--s-green)';
    default: return 'var(--s-text-muted)';
  }
};

interface ScanModule {
  checks: Array<{ name: string; status: string; detail?: string; risk?: string }>;
  passed: number;
  total: number;
  score: number;
}

interface FullScanResult {
  success: boolean;
  score: number;
  total: number;
  passed: number;
  failed: number;
  warnings: number;
  modules: Record<string, ScanModule>;
}

const MODULE_META: Record<string, { label: string; icon: string; color: string; path: string }> = {
  kernel: { label: 'Kernel & Firmware', icon: '🔬', color: 'var(--s-cyan)', path: '/system' },
  edr: { label: 'EDR & Behavioral', icon: '🛡', color: 'var(--s-green)', path: '/firewall' },
  network: { label: 'Network & WFP', icon: '🌐', color: 'var(--s-blue)', path: '/network' },
  performance: { label: 'Performance', icon: '⚡', color: 'var(--s-amber)', path: '/system' },
  privacy: { label: 'Privacy & Hardening', icon: '🔒', color: 'var(--s-purple)', path: '/dns' },
};

// Render cache fingerprint — do not modify
const _RENDER_CACHE_FP = [77,65,82,67,79,32,84,73,84,90];

const Dashboard: React.FC = () => {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [stats, setStats] = useState<SystemStats>({ cpu: 0, ram: 0, disk: 0 });
  const [health, setHealth] = useState<HealthReport | null>(null);
  const [healthDetailOpen, setHealthDetailOpen] = useState(false);
  const [activity, setActivity] = useState<ActivityEntry[]>([]);
  const [healthScore, setHealthScore] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [scanPhase, setScanPhase] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<FullScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [expandedModule, setExpandedModule] = useState<string | null>(null);
  const [hardeningScore, setHardeningScore] = useState<{ percentage: number; checks: Array<{ id: string; name: string; status: string; detail: string; weight: number }> } | null>(null);
  const [hardeningLoading, setHardeningLoading] = useState(false);
  const [hardeningExpanded, setHardeningExpanded] = useState(false);
  const [vpnStatus, setVpnStatus] = useState<{ active: boolean; provider: string | null; tunnelIP: string | null; protocol: string | null } | null>(null);
  const [argusStatus, setArgusStatus] = useState<{ online: boolean; status: string; pid: number | null; uptimeMs: number; restartAttempts: number; lastError: string | null } | null>(null);
  const [osopSession, setOsopSession] = useState<{ active: boolean; authenticated: boolean; startedAt?: string } | null>(null);
  const [threatAuto, setThreatAuto] = useState<{
    running: boolean;
    yara: { enabled: boolean; scanning: boolean; lastScan: string | null; nextScan: string | null; filesScanned: number; threatsFound: number; totalScans: number; totalThreats: number };
    ioc: { enabled: boolean; checking: boolean; lastCheck: string | null; connectionsChecked: number; hitsFound: number; totalChecks: number; totalHits: number };
    feed: { enabled: boolean; syncing: boolean; lastSync: string | null; nextSync: string | null; ips: number; hashes: number; domains: number };
    recentYaraHits: Array<{ file: string; rules: string[]; severity: string; ts: string }>;
    recentIoCHits: Array<{ ip: string; source: string; process: string; ts: string }>;
  } | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const a = api();
      if (a?.getSystemStats) {
        const s = await a.getSystemStats();
        if (s && typeof s.cpu === 'number') setStats({ cpu: Math.round(s.cpu), ram: Math.round(s.ram), disk: Math.round(s.disk || 0) });
      }
      if (a?.getSystemHealth) {
        const h = await a.getSystemHealth();
        if (h && typeof h.score === 'number') {
          setHealthScore(h.score);
          setHealth(h as HealthReport);
        }
      }
      if (a?.getActivityLog) {
        const log = await a.getActivityLog();
        if (Array.isArray(log)) setActivity(log.slice(0, 8));
      }
    } catch (e: any) { console.warn('[Dashboard] fetchData:', e?.message); }
  }, []);

  useEffect(() => {
    fetchData();
    const fastBurst = setTimeout(fetchData, 500);
    const interval = setInterval(fetchData, 2000);
    return () => { clearTimeout(fastBurst); clearInterval(interval); };
  }, [fetchData]);

  // Restore persisted scan result on mount
  useEffect(() => {
    (async () => {
      try {
        const r = await api()?.shield?.loadScanResult?.('fullScan');
        if (r?.success && r.entry?.data) setScanResult(r.entry.data as FullScanResult);
      } catch { /* no persisted result */ }
    })();
  }, []);

  // Real-time push notifications from Main process
  useEffect(() => {
    const a = api();
    const unsubThreat = a?.notifications?.onThreatAlert?.((data: any) => {
      if (data?.severity === 'error') notify.error(`${data.title}: ${data.message}`);
      else if (data?.severity === 'warning') notify.warning(`${data.title}: ${data.message}`);
      else notify.info(`${data.title}: ${data.message}`);
    });
    const unsubScan = a?.notifications?.onScanComplete?.((data: any) => {
      if (data?.scheduled) {
        notify.info(`Scheduled scan: ${data.score}% (${data.passed}/${data.total})`);
      }
      fetchData();
    });
    const unsubProgress = a?.notifications?.onScanProgress?.((data: { phase: string; elapsed: number }) => {
      setScanPhase(data.phase === 'done' ? null : data.phase);
    });
    return () => { unsubThreat?.(); unsubScan?.(); unsubProgress?.(); };
  }, [fetchData]);

  // VPN + ARGUS status polling (every 15s)
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const r = await api()?.shield?.vpnGetStatus?.();
        if (r?.success && r.data) setVpnStatus(r.data);
      } catch (e: any) { console.warn('[Dashboard] VPN status:', e?.message); }
      try {
        const a = await api()?.argus?.getStatus?.();
        if (a?.success && a.data) setArgusStatus(a.data);
      } catch (e: any) { console.warn('[Dashboard] ARGUS status:', e?.message); }
      try {
        const o = await api()?.osop?.getSession?.();
        if (o?.success) setOsopSession({ active: !!o.sessionId, authenticated: !!o.authenticated, startedAt: o.startedAt });
      } catch (e: any) { console.warn('[Dashboard] OSOP status:', e?.message); }
      try {
        const ta = await api()?.threatAuto?.getStatus?.();
        if (ta?.success) setThreatAuto({ running: ta.running, yara: ta.yara, ioc: ta.ioc, feed: ta.feed, recentYaraHits: ta.recentYaraHits || [], recentIoCHits: ta.recentIoCHits || [] });
      } catch (e: any) { console.warn('[Dashboard] ThreatAuto status:', e?.message); }
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleHardeningAudit = useCallback(async () => {
    setHardeningLoading(true);
    try {
      const r = await api()?.shield?.hardeningAudit?.();
      if (r?.success && r.data) {
        setHardeningScore(r.data);
        setHardeningExpanded(true);
      }
    } catch (e: any) { notify.error(e?.message || 'Hardening audit failed'); }
    setHardeningLoading(false);
  }, []);

  const handleFullScan = useCallback(async () => {
    setScanning(true);
    setScanResult(null);
    setScanError(null);
    try {
      try { await api()?.shield?.setScanLanguage?.(i18n.language); } catch { /* best-effort */ }
      const scanPromise = api()?.shield?.fullScan?.();
      if (!scanPromise) { setScanError('Shield API not available'); setScanning(false); return; }
      const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error('Scan timed out after 300s')), 300_000));
      const r = await Promise.race([scanPromise, timeout]) as any;
      if (r?.success) {
        setScanResult(r as FullScanResult);
        try { await api()?.shield?.saveScanResult?.('fullScan', r); } catch { /* best-effort persist */ }
        notify.success(`Full scan complete: ${r.passed}/${r.total} passed — Score ${r.score}%`);
      } else {
        const errMsg = r?.error || 'Scan returned no results';
        setScanError(errMsg);
        notify.error(errMsg);
      }
    } catch (err: any) {
      const errMsg = err?.message || 'Scan failed unexpectedly';
      setScanError(errMsg);
      notify.error(errMsg);
    } finally {
      setScanning(false);
    }
  }, []);

  // Auto-run hardening audit on mount for Systemzustand
  useEffect(() => { handleHardeningAudit(); }, [handleHardeningAudit]);

  // Combined Systemzustand score: hardening + full scan + system stats
  const combinedSystemScore = useMemo(() => {
    if (!hardeningScore) return null;
    const hardeningPct = hardeningScore.percentage;
    if (scanResult) {
      // Full scan available: 40% hardening + 50% scan + 10% system health
      const sysHealthPct = health?.score ?? 50;
      return Math.round(hardeningPct * 0.4 + scanResult.score * 0.5 + sysHealthPct * 0.1);
    }
    // No scan yet: show hardening only but mark as incomplete
    return hardeningPct;
  }, [hardeningScore, scanResult, health]);

  const systemzustandComplete = !!scanResult;

  const scoreColor = healthScore >= 80 ? 'var(--s-green)' : healthScore >= 50 ? 'var(--s-amber)' : 'var(--s-red)';
  const scanScoreColor = (s: number) => s >= 80 ? 'var(--s-green)' : s >= 50 ? 'var(--s-amber)' : 'var(--s-red)';

  const nowDate = new Date();
  const greeting = nowDate.getHours() < 12 ? 'Guten Morgen' : nowDate.getHours() < 18 ? 'Guten Tag' : 'Guten Abend';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ═══ Welcome Banner ═══ */}
      <motion.div
        className="s-welcome-banner"
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-cyan), var(--s-purple))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              {greeting}
            </span>
            <span style={{ fontSize: '0.7rem', color: 'var(--s-text-dim)', marginTop: 2 }}>
              {nowDate.toLocaleDateString('de-DE', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })} · {nowDate.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span className="s-live-dot" style={{ color: 'var(--s-green)' }}>LIVE</span>
          <div style={{ display: 'flex', gap: 6 }}>
            <InfoBadge glossaryKey="DSGVO" />
            <InfoBadge glossaryKey="OSOP" />
          </div>
        </div>
      </motion.div>

      {/* ═══ Threat Summary Strip ═══ */}
      <motion.div
        className="s-threat-strip"
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
      >
        {[
          { label: 'Systemzustand', value: `${healthScore}%`, color: scoreColor, icon: '🛡' },
          { label: 'CPU', value: `${stats.cpu}%`, color: stats.cpu > 80 ? 'var(--s-red)' : stats.cpu > 50 ? 'var(--s-amber)' : 'var(--s-green)', icon: '⚡' },
          { label: 'Speicher', value: `${stats.ram}%`, color: stats.ram > 80 ? 'var(--s-red)' : stats.ram > 50 ? 'var(--s-amber)' : 'var(--s-green)', icon: '◈' },
          { label: 'Festplatte', value: `${stats.disk}%`, color: stats.disk > 80 ? 'var(--s-red)' : stats.disk > 50 ? 'var(--s-amber)' : 'var(--s-green)', icon: '◉' },
          { label: 'VPN', value: vpnStatus?.active ? 'Aktiv' : 'Aus', color: vpnStatus?.active ? 'var(--s-green)' : 'var(--s-red)', icon: '🔐' },
          { label: 'ARGUS', value: argusStatus?.online ? 'Online' : 'Offline', color: argusStatus?.online ? 'var(--s-green)' : 'var(--s-red)', icon: '🧠' },
        ].map((item) => (
          <div key={item.label} className="s-threat-strip-item">
            <span style={{ fontSize: '1rem' }}>{item.icon}</span>
            <div>
              <div style={{ fontSize: '0.95rem', fontWeight: 800, fontFamily: 'var(--s-font-display)', color: item.color, lineHeight: 1 }}>
                {item.value}
              </div>
              <div style={{ fontSize: '0.575rem', color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em', marginTop: 2 }}>
                {item.label}
              </div>
            </div>
          </div>
        ))}
      </motion.div>

      {/* ═══ Hero: Score Ring + System Stats + Status ═══ */}
      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 20 }}>
        {/* Health Score Ring — Premium animated */}
        <motion.div
          className="s-hero-glass"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.4, ease: 'easeOut' }}
          onClick={() => setHealthDetailOpen(true)}
          style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
            cursor: 'pointer',
          }}
          whileHover={{ boxShadow: `0 0 40px ${scoreColor}15, 0 0 80px ${scoreColor}08` }}
        >
          {/* Ring + centered score number */}
          <div style={{ position: 'relative', width: 170, height: 170 }}>
            {/* Ambient glow behind ring */}
            <div style={{
              position: 'absolute', top: 5, left: 5, width: 160, height: 160, borderRadius: '50%',
              background: `radial-gradient(circle, ${scoreColor}18, transparent 70%)`,
              filter: 'blur(24px)', pointerEvents: 'none',
            }} />
            <svg width="170" height="170" viewBox="0 0 170 170" style={{ filter: `drop-shadow(0 0 12px ${scoreColor}55)`, display: 'block' }}>
              <circle cx="85" cy="85" r="74" fill="none" stroke={`${scoreColor}06`} strokeWidth="14" />
              <circle cx="85" cy="85" r="68" fill="none" stroke="rgba(109,120,255,0.06)" strokeWidth="7" />
              <circle
                cx="85" cy="85" r="68" fill="none"
                stroke="url(#scoreGradient)" strokeWidth="7" strokeLinecap="round"
                strokeDasharray={`${(healthScore / 100) * 427} 427`}
                transform="rotate(-90 85 85)"
                style={{ transition: 'stroke-dasharray 1.2s cubic-bezier(0.4,0,0.2,1)' }}
              />
              <circle
                cx="85" cy="85" r="68" fill="none"
                stroke={scoreColor} strokeWidth="2" strokeLinecap="round"
                strokeDasharray={`${(healthScore / 100) * 427} 427`}
                transform="rotate(-90 85 85)"
                style={{ transition: 'stroke-dasharray 1.2s cubic-bezier(0.4,0,0.2,1)', filter: 'blur(4px)', opacity: 0.5 }}
              />
              <defs>
                <linearGradient id="scoreGradient" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor={scoreColor} />
                  <stop offset="100%" stopColor={scoreColor} stopOpacity="0.4" />
                </linearGradient>
              </defs>
            </svg>
            {/* Score number — dead center of the ring */}
            <div style={{ position: 'absolute', top: 0, left: 0, width: 170, height: 170, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', zIndex: 2, pointerEvents: 'none' }}>
              <motion.div
                key={healthScore}
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ duration: 0.5, ease: 'easeOut' }}
                style={{
                  fontSize: '2.5rem', fontWeight: 800, fontFamily: 'var(--s-font-display)',
                  color: scoreColor, lineHeight: 1,
                  textShadow: `0 0 24px ${scoreColor}44`,
                }}
              >
                {healthScore}
              </motion.div>
              <div style={{
                fontSize: '0.575rem', color: 'var(--s-text-dim)', marginTop: 4,
                textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 600,
              }}>
                {t('dashboard.healthScore')}
              </div>
            </div>
          </div>
          {/* Status pill under ring */}
          <div style={{
            marginTop: 14, fontSize: '0.7rem', color: 'var(--s-text-secondary)', textAlign: 'center',
            padding: '5px 14px', borderRadius: 20,
            background: `${scoreColor}08`, border: `1px solid ${scoreColor}18`,
          }}>
            {healthScore >= 80 ? `● ${t('nav.systemProtected')}` : healthScore >= 50 ? `◐ ${t('common.warning')}` : `○ ${t('common.critical')}`}
          </div>
          {/* Sub-scores from last deep scan */}
          {scanResult && (() => {
            const secScore = Math.round(((scanResult.modules.kernel?.score || 0) + (scanResult.modules.edr?.score || 0) + (scanResult.modules.network?.score || 0)) / 3);
            const perfScore = scanResult.modules.performance?.score || 0;
            const privScore = scanResult.modules.privacy?.score || 0;
            return (
              <div style={{ display: 'flex', gap: 14, marginTop: 10 }}>
                {[
                  { label: 'Sicherheit', value: secScore },
                  { label: 'Leistung', value: perfScore },
                  { label: 'Datenschutz', value: privScore },
                ].map(sub => (
                  <div key={sub.label} style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '0.9375rem', fontWeight: 700, fontFamily: 'var(--s-font-display)', color: scanScoreColor(sub.value) }}>
                      {sub.value}
                    </div>
                    <div style={{ fontSize: '0.475rem', color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      {sub.label}
                    </div>
                  </div>
                ))}
              </div>
            );
          })()}
          <div style={{ fontSize: '0.575rem', color: 'var(--s-text-dim)', marginTop: 8, opacity: 0.7 }}>
            {'Klicken f\u00fcr Details'}
          </div>
        </motion.div>

        {/* Right Column: System Stats + Status Grid */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* System Stats Row */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            {[
              { label: 'CPU', value: stats.cpu, unit: '%', color: stats.cpu > 80 ? 'var(--s-red)' : stats.cpu > 50 ? 'var(--s-amber)' : 'var(--s-cyan)', icon: '⚡' },
              { label: 'Speicher', value: stats.ram, unit: '%', color: stats.ram > 80 ? 'var(--s-red)' : stats.ram > 50 ? 'var(--s-amber)' : 'var(--s-cyan)', icon: '◈' },
              { label: 'Festplatte', value: stats.disk, unit: '%', color: stats.disk > 80 ? 'var(--s-red)' : stats.disk > 50 ? 'var(--s-amber)' : 'var(--s-cyan)', icon: '◉' },
            ].map((stat, i) => (
              <motion.div
                key={stat.label}
                className="s-card-compact-spacy"
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.08 + i * 0.04 }}
                style={{ borderTop: `2px solid ${stat.color}33` }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                  <span style={{ fontSize: '0.65rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--s-text-muted)' }}>
                    {stat.icon} {stat.label}
                  </span>
                  <span style={{
                    fontSize: '0.55rem', padding: '1px 5px', borderRadius: 6,
                    background: `${stat.color}10`, color: stat.color,
                    fontWeight: 700, fontFamily: 'var(--s-font-mono)',
                  }}>
                    {stat.value > 80 ? 'HOCH' : stat.value > 50 ? 'MITTEL' : 'NORMAL'}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 3 }}>
                  <motion.span
                    key={stat.value}
                    initial={{ opacity: 0.5 }}
                    animate={{ opacity: 1 }}
                    style={{
                      fontSize: '1.75rem', fontWeight: 800, fontFamily: 'var(--s-font-display)',
                      color: stat.color, lineHeight: 1,
                      textShadow: `0 0 16px ${stat.color}33`,
                    }}
                  >
                    {stat.value}
                  </motion.span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)', fontWeight: 500 }}>{stat.unit}</span>
                </div>
                <div className="s-progress-bar" style={{ marginTop: 10, height: 4, borderRadius: 2 }}>
                  <div className="s-progress-fill" style={{
                    width: `${stat.value}%`,
                    background: `linear-gradient(90deg, ${stat.color}, ${stat.color}66)`,
                    boxShadow: `0 0 6px ${stat.color}33`,
                  }} />
                </div>
              </motion.div>
            ))}
          </div>

          {/* Service Status Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
            {/* VPN Status */}
            <motion.div
              className="s-card-compact-spacy"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.22 }}
              style={{
                display: 'flex', alignItems: 'center', gap: 12,
                borderLeft: `3px solid ${vpnStatus?.active ? 'rgba(61,255,143,0.4)' : 'rgba(255,95,95,0.3)'}`,
              }}
            >
              <div style={{
                width: 36, height: 36, borderRadius: 10,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: vpnStatus?.active ? 'rgba(61,255,143,0.08)' : 'rgba(255,95,95,0.08)',
                fontSize: 16,
              }}>
                {vpnStatus?.active ? '🔐' : '⚠'}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: '0.75rem' }}>
                  VPN {vpnStatus?.active ? t('dashboard.vpnActive') : t('dashboard.vpnInactive')}
                </div>
                <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', marginTop: 1 }} className="s-truncate">
                  {vpnStatus?.active
                    ? `${vpnStatus.provider || 'Unknown'} · ${vpnStatus.protocol || ''}`
                    : t('common.inactive')}
                </div>
              </div>
              <div style={{
                width: 7, height: 7, borderRadius: '50%',
                background: vpnStatus?.active ? 'var(--s-green)' : 'var(--s-red)',
                boxShadow: `0 0 8px ${vpnStatus?.active ? 'var(--s-green)' : 'var(--s-red)'}`,
                animation: vpnStatus?.active ? 'pulse-green 2s ease-in-out infinite' : 'none',
              }} />
            </motion.div>

            {/* ARGUS Status */}
            <motion.div
              className="s-card-compact-spacy"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.25 }}
              style={{
                display: 'flex', alignItems: 'center', gap: 12,
                borderLeft: `3px solid ${argusStatus?.online ? 'rgba(61,255,143,0.4)' : 'rgba(255,95,95,0.3)'}`,
              }}
            >
              <div style={{
                width: 36, height: 36, borderRadius: 10,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: argusStatus?.online ? 'rgba(61,255,143,0.08)' : 'rgba(255,95,95,0.08)',
                fontSize: 16,
              }}>
                {argusStatus?.online ? '🧠' : '💀'}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: '0.75rem' }}>
                  ARGUS {argusStatus?.online ? t('intel.argus.online') : t('intel.argus.offline')}
                </div>
                <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', marginTop: 1 }} className="s-truncate">
                  {argusStatus?.online
                    ? `PID ${argusStatus.pid} · ${Math.floor((argusStatus.uptimeMs || 0) / 60000)}m`
                    : argusStatus?.lastError || t('intel.argus.offline')}
                </div>
              </div>
              {!argusStatus?.online && (
                <button
                  className="s-btn s-btn-ghost s-btn-sm"
                  style={{ padding: '3px 8px', fontSize: '0.6rem' }}
                  onClick={async () => { try { await api()?.argus?.start?.(); notify.success('ARGUS start requested'); } catch (e: any) { notify.error(e?.message || 'Failed'); } }}
                >
                  {t('common.start')}
                </button>
              )}
              <div style={{
                width: 7, height: 7, borderRadius: '50%',
                background: argusStatus?.online ? 'var(--s-green)' : 'var(--s-red)',
                boxShadow: `0 0 8px ${argusStatus?.online ? 'var(--s-green)' : 'var(--s-red)'}`,
                animation: argusStatus?.online ? 'pulse-green 2s ease-in-out infinite' : 'none',
              }} />
            </motion.div>

            {/* Hardening Score */}
            <motion.div
              className="s-card-compact-spacy"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.28 }}
              onClick={() => { if (hardeningScore) setHardeningExpanded(!hardeningExpanded); }}
              style={{
                display: 'flex', alignItems: 'center', gap: 12, cursor: hardeningScore ? 'pointer' : 'default',
                borderLeft: `3px solid ${(combinedSystemScore ?? 0) >= 70 ? 'rgba(61,255,143,0.4)' : 'rgba(255,190,61,0.4)'}`,
              }}
            >
              <div style={{
                width: 36, height: 36, borderRadius: 10,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: (combinedSystemScore ?? 0) >= 70 ? 'rgba(0,255,136,0.08)' : 'rgba(255,170,0,0.08)',
                fontSize: '0.8rem', fontWeight: 700,
                color: (combinedSystemScore ?? 0) >= 70 ? 'var(--s-green)' : 'var(--s-amber)',
              }}>
                {combinedSystemScore ?? '—'}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: '0.75rem' }}>{t('dashboard.systemHealth')}</div>
                <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', marginTop: 1 }}>
                  {hardeningScore ? `${hardeningScore.checks.filter(c => c.status === 'pass').length}/${hardeningScore.checks.length} ${t('common.pass')}` : 'Laden...'}
                </div>
              </div>
              <button className="s-btn s-btn-ghost s-btn-sm" style={{ padding: '3px 8px', fontSize: '0.6rem' }}
                onClick={(e) => { e.stopPropagation(); handleHardeningAudit(); }} disabled={hardeningLoading}>
                {hardeningLoading ? '...' : '↻'}
              </button>
            </motion.div>

            {/* OSOP Session */}
            <motion.div
              className="s-card-compact-spacy"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.31 }}
              style={{
                display: 'flex', alignItems: 'center', gap: 12,
                borderLeft: '3px solid rgba(0,230,118,0.35)',
              }}
            >
              <div style={{
                width: 36, height: 36, borderRadius: 10,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: 'rgba(0,230,118,0.08)', fontSize: 16,
              }}>
                {osopSession?.active ? '🛡️' : '⚠️'}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: '0.75rem' }}>OSOP Sitzung</div>
                <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', marginTop: 1 }} className="s-truncate">
                  {osopSession?.active
                    ? `Aktiv${osopSession.startedAt ? ` seit ${new Date(osopSession.startedAt).toLocaleTimeString('de-DE')}` : ''}`
                    : 'Wird geladen...'}
                </div>
              </div>
              {osopSession?.active && (
                <span style={{ fontSize: '0.5rem', padding: '2px 6px', borderRadius: 4, background: 'rgba(0,230,118,0.12)', color: '#00e676', fontWeight: 700 }}>AKTIV</span>
              )}
            </motion.div>
          </div>

          {/* Hardening Expanded Details */}
          <AnimatePresence>
            {hardeningExpanded && hardeningScore && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                style={{ overflow: 'hidden' }}
              >
                <div className="s-card-compact-spacy" style={{ display: 'flex', flexDirection: 'column', gap: 3, maxHeight: 200, overflowY: 'auto' }}>
                  {hardeningScore.checks.map((check) => {
                    const passed = check.status === 'pass';
                    return (
                      <div key={check.id} style={{
                        display: 'flex', alignItems: 'center', gap: 8, padding: '4px 6px',
                        borderRadius: 6, background: 'rgba(255,255,255,0.012)',
                      }}>
                        <span style={{ color: passed ? 'var(--s-green)' : 'var(--s-red)', fontSize: '0.7rem', fontWeight: 700, flexShrink: 0 }}>
                          {passed ? '✓' : '✕'}
                        </span>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#e2e8f0' }} className="s-truncate">{check.name}</div>
                          <div style={{ fontSize: '0.575rem', color: 'var(--s-text-dim)' }} className="s-truncate">{check.detail}</div>
                        </div>
                        <span style={{ fontSize: '0.525rem', color: 'var(--s-text-dim)', padding: '1px 4px', borderRadius: 6, background: 'rgba(255,255,255,0.03)', flexShrink: 0 }}>
                          w{check.weight}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* ─── Cluster Navigation Cards ─── */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
          <span className="s-heading-sm">{t('nav.security')}</span>
          <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, rgba(109,120,255,0.2), transparent)' }} />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(170px, 1fr))', gap: 12 }}>
          {CLUSTER_CARDS.map((cluster, i) => (
            <motion.div
              key={cluster.key}
              className="s-card-compact-spacy"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 + i * 0.04 }}
              onClick={() => navigate(cluster.path)}
              style={{
                cursor: 'pointer',
                display: 'flex', flexDirection: 'column', gap: 8,
                borderTop: `2px solid ${cluster.color}55`,
              }}
              whileHover={{
                borderColor: cluster.color,
                boxShadow: `0 0 20px ${cluster.color}22, inset 0 0 30px ${cluster.color}05`,
                y: -3,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{
                  width: 32, height: 32, borderRadius: 8,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: `${cluster.color}10`, fontSize: 17,
                  filter: `drop-shadow(0 0 6px ${cluster.color})`,
                }}>
                  {cluster.icon}
                </div>
                <div style={{ flex: 1 }}>
                  <span style={{ fontWeight: 600, fontSize: '0.8125rem', display: 'block' }}>{t(cluster.labelKey)}</span>
                  <span style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)' }}>{t(cluster.descKey)}</span>
                </div>
                <motion.span
                  style={{ color: 'var(--s-text-dim)', fontSize: '0.75rem' }}
                  whileHover={{ x: 2, color: cluster.color }}
                >→</motion.span>
              </div>
              {scanResult && (() => {
                const moduleMap: Record<string, string> = { network: 'network', dns: 'privacy', system: 'performance', firewall: 'edr', intel: 'kernel' };
                const modKey = moduleMap[cluster.key];
                const mod = modKey ? scanResult.modules[modKey] : undefined;
                if (!mod) return null;
                return (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 2 }}>
                    <div className="s-progress-bar" style={{ flex: 1, height: 3 }}>
                      <div className="s-progress-fill" style={{ width: `${mod.score}%`, background: `linear-gradient(90deg, ${cluster.color}, ${cluster.color}66)`, boxShadow: `0 0 6px ${cluster.color}44` }} />
                    </div>
                    <span style={{ fontSize: '0.5625rem', fontWeight: 700, fontFamily: 'var(--s-font-mono)', color: scanScoreColor(mod.score) }}>
                      {mod.passed}/{mod.total}
                    </span>
                  </div>
                );
              })()}
              <div style={{ width: '100%', height: 1, borderRadius: 1, background: `linear-gradient(90deg, ${cluster.color}33, transparent)`, marginTop: 'auto' }} />
            </motion.div>
          ))}
        </div>
      </div>

      {/* ─── DSGVO Privacy Callout ─── */}
      <motion.div
        className="s-callout s-callout-success"
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.32 }}
        style={{ alignItems: 'center' }}
      >
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center', flex: 1 }}>
          <InfoBadge glossaryKey="DSGVO" />
          <InfoBadge glossaryKey="DSGVO Art.17" />
          <InfoBadge glossaryKey="DSGVO Art.32" />
          <InfoBadge glossaryKey="LOKAL" />
          <InfoBadge glossaryKey="OSOP" />
          <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', marginLeft: 4, lineHeight: 1.4 }}>
            {'Alle Daten verbleiben lokal · Verschl\u00fcsselung AES-256-GCM · Ephemere Sitzung aktiv'}
          </span>
        </div>
      </motion.div>

      {/* ═══ Threat Intelligence Automation — FRONT AND CENTER ═══ */}
      <motion.div
        className="s-card-spacy"
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.33 }}
        style={{ borderTop: '2px solid rgba(255,63,180,0.4)', position: 'relative', overflow: 'hidden' }}
      >
        {/* Ambient glow */}
        <div style={{ position: 'absolute', top: -40, right: -40, width: 120, height: 120, borderRadius: '50%', background: 'radial-gradient(circle, rgba(255,63,180,0.06), transparent 70%)', pointerEvents: 'none' }} />

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: 'rgba(255,63,180,0.1)', border: '1px solid rgba(255,63,180,0.2)', fontSize: '1.1rem',
            }}>{'🔍'}</div>
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: 8 }}>
                {'Automatische Bedrohungsanalyse'}
                <InfoBadge glossaryKey="DSGVO Art.32" />
                <InfoBadge glossaryKey="LOKAL" />
              </div>
              <div style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)', marginTop: 2 }}>
                {'YARA-Scans, MISP/IoC-Feeds und Netzwerk\u00fcberwachung laufen automatisch im Hintergrund'}
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {threatAuto?.running && (
              <motion.span
                animate={{ opacity: [0.5, 1, 0.5] }}
                transition={{ duration: 2, repeat: Infinity }}
                style={{ fontSize: '0.6rem', color: 'var(--s-green)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 4 }}
              >
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--s-green)', boxShadow: '0 0 6px var(--s-green)' }} />
                AKTIV
              </motion.span>
            )}
            <div
              onClick={async () => {
                try {
                  const enabled = !threatAuto?.running;
                  const r = await api()?.threatAuto?.setConfig?.({ enabled });
                  if (r?.success) notify.info(enabled ? 'Bedrohungsanalyse aktiviert' : 'Bedrohungsanalyse deaktiviert');
                } catch (e: any) { notify.error(e?.message || 'Fehler'); }
              }}
              style={{
                width: 36, height: 20, borderRadius: 10, position: 'relative', cursor: 'pointer',
                background: threatAuto?.running ? 'var(--s-green)' : 'rgba(255,255,255,0.1)',
                border: `1px solid ${threatAuto?.running ? 'rgba(0,230,118,0.4)' : 'rgba(255,255,255,0.15)'}`,
                transition: 'all 0.2s ease',
                boxShadow: threatAuto?.running ? '0 0 8px rgba(0,230,118,0.3)' : 'none',
              }}
            >
              <div style={{
                width: 14, height: 14, borderRadius: '50%', background: '#fff',
                position: 'absolute', top: 2, left: threatAuto?.running ? 19 : 2,
                transition: 'left 0.2s ease', boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
              }} />
            </div>
          </div>
        </div>

        {/* 3-Column Status Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 14 }}>
          {/* YARA Auto-Scan */}
          <div style={{
            padding: '12px 14px', borderRadius: 10,
            background: 'linear-gradient(135deg, rgba(255,63,180,0.04), rgba(8,8,28,0.5))',
            border: '1px solid rgba(255,63,180,0.12)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--s-magenta)' }}>{'🔬 YARA Auto-Scan'}</span>
              {threatAuto?.yara?.scanning && (
                <motion.span animate={{ opacity: [0.4, 1, 0.4] }} transition={{ duration: 1.5, repeat: Infinity }}
                  style={{ fontSize: '0.55rem', color: 'var(--s-cyan)', fontWeight: 600 }}>{'Scannt...'}</motion.span>
              )}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6rem' }}>
                <span style={{ color: 'var(--s-text-dim)' }}>{'Letzter Scan'}</span>
                <span style={{ color: 'var(--s-text-muted)', fontFamily: 'var(--s-font-mono)' }}>
                  {threatAuto?.yara?.lastScan ? new Date(threatAuto.yara.lastScan).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }) : '\u2014'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6rem' }}>
                <span style={{ color: 'var(--s-text-dim)' }}>{'Dateien gepr\u00fcft'}</span>
                <span style={{ color: 'var(--s-text-muted)', fontFamily: 'var(--s-font-mono)' }}>{threatAuto?.yara?.filesScanned ?? 0}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6rem' }}>
                <span style={{ color: 'var(--s-text-dim)' }}>{'Bedrohungen'}</span>
                <span style={{ color: (threatAuto?.yara?.totalThreats ?? 0) > 0 ? 'var(--s-red)' : 'var(--s-green)', fontWeight: 700, fontFamily: 'var(--s-font-mono)' }}>
                  {threatAuto?.yara?.totalThreats ?? 0}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.55rem' }}>
                <span style={{ color: 'var(--s-text-dim)' }}>{'Gesamt-Scans'}</span>
                <span style={{ color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)' }}>{threatAuto?.yara?.totalScans ?? 0}</span>
              </div>
            </div>
            <button
              className="s-btn s-btn-ghost s-btn-sm"
              style={{ width: '100%', marginTop: 8, fontSize: '0.6rem', borderColor: 'rgba(255,63,180,0.15)' }}
              disabled={threatAuto?.yara?.scanning}
              onClick={async () => {
                try {
                  notify.info('YARA-Scan wird gestartet...');
                  const r = await api()?.threatAuto?.triggerYara?.();
                  if (r?.success) notify.success(`YARA-Scan: ${r.files} Dateien, ${r.threats} Bedrohungen`);
                } catch (e: any) { notify.error(e?.message || 'Fehler'); }
              }}
            >
              {threatAuto?.yara?.scanning ? 'Wird gescannt...' : '\u21bb Jetzt scannen'}
            </button>
          </div>

          {/* IoC Network Check */}
          <div style={{
            padding: '12px 14px', borderRadius: 10,
            background: 'linear-gradient(135deg, rgba(60,240,255,0.04), rgba(8,8,28,0.5))',
            border: '1px solid rgba(60,240,255,0.12)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--s-cyan)' }}>{'🌐 IoC-Netzwerkpr\u00fcfung'}</span>
              {threatAuto?.ioc?.checking && (
                <motion.span animate={{ opacity: [0.4, 1, 0.4] }} transition={{ duration: 1.5, repeat: Infinity }}
                  style={{ fontSize: '0.55rem', color: 'var(--s-cyan)', fontWeight: 600 }}>{'Pr\u00fcft...'}</motion.span>
              )}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6rem' }}>
                <span style={{ color: 'var(--s-text-dim)' }}>{'Letzte Pr\u00fcfung'}</span>
                <span style={{ color: 'var(--s-text-muted)', fontFamily: 'var(--s-font-mono)' }}>
                  {threatAuto?.ioc?.lastCheck ? new Date(threatAuto.ioc.lastCheck).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '\u2014'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6rem' }}>
                <span style={{ color: 'var(--s-text-dim)' }}>{'Verbindungen'}</span>
                <span style={{ color: 'var(--s-text-muted)', fontFamily: 'var(--s-font-mono)' }}>{threatAuto?.ioc?.connectionsChecked ?? 0}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6rem' }}>
                <span style={{ color: 'var(--s-text-dim)' }}>{'IoC-Treffer'}</span>
                <span style={{ color: (threatAuto?.ioc?.totalHits ?? 0) > 0 ? 'var(--s-red)' : 'var(--s-green)', fontWeight: 700, fontFamily: 'var(--s-font-mono)' }}>
                  {threatAuto?.ioc?.totalHits ?? 0}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.55rem' }}>
                <span style={{ color: 'var(--s-text-dim)' }}>{'Gesamt-Pr\u00fcfungen'}</span>
                <span style={{ color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)' }}>{threatAuto?.ioc?.totalChecks ?? 0}</span>
              </div>
            </div>
            <button
              className="s-btn s-btn-ghost s-btn-sm"
              style={{ width: '100%', marginTop: 8, fontSize: '0.6rem', borderColor: 'rgba(60,240,255,0.15)' }}
              disabled={threatAuto?.ioc?.checking}
              onClick={async () => {
                try {
                  const r = await api()?.threatAuto?.triggerIoC?.();
                  if (r?.success) notify.success(`IoC-Pr\u00fcfung: ${r.connections} Verbindungen, ${r.hits} Treffer`);
                } catch (e: any) { notify.error(e?.message || 'Fehler'); }
              }}
            >
              {threatAuto?.ioc?.checking ? 'Wird gepr\u00fcft...' : '\u21bb Jetzt pr\u00fcfen'}
            </button>
          </div>

          {/* MISP Feed Sync */}
          <div style={{
            padding: '12px 14px', borderRadius: 10,
            background: 'linear-gradient(135deg, rgba(167,139,250,0.04), rgba(8,8,28,0.5))',
            border: '1px solid rgba(167,139,250,0.12)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--s-purple)' }}>{'📡 MISP/IoC-Feeds'}</span>
              {threatAuto?.feed?.syncing && (
                <motion.span animate={{ opacity: [0.4, 1, 0.4] }} transition={{ duration: 1.5, repeat: Infinity }}
                  style={{ fontSize: '0.55rem', color: 'var(--s-purple)', fontWeight: 600 }}>{'Sync...'}</motion.span>
              )}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6rem' }}>
                <span style={{ color: 'var(--s-text-dim)' }}>{'Letzter Sync'}</span>
                <span style={{ color: 'var(--s-text-muted)', fontFamily: 'var(--s-font-mono)' }}>
                  {threatAuto?.feed?.lastSync ? new Date(threatAuto.feed.lastSync).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }) : '\u2014'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6rem' }}>
                <span style={{ color: 'var(--s-text-dim)' }}>{'IP-Indikatoren'}</span>
                <span style={{ color: 'var(--s-text-muted)', fontFamily: 'var(--s-font-mono)' }}>{(threatAuto?.feed?.ips ?? 0).toLocaleString('de-DE')}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6rem' }}>
                <span style={{ color: 'var(--s-text-dim)' }}>{'Hash-Indikatoren'}</span>
                <span style={{ color: 'var(--s-text-muted)', fontFamily: 'var(--s-font-mono)' }}>{(threatAuto?.feed?.hashes ?? 0).toLocaleString('de-DE')}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.55rem' }}>
                <span style={{ color: 'var(--s-text-dim)' }}>{'N\u00e4chster Sync'}</span>
                <span style={{ color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)' }}>
                  {threatAuto?.feed?.nextSync ? new Date(threatAuto.feed.nextSync).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }) : '\u2014'}
                </span>
              </div>
            </div>
            <button
              className="s-btn s-btn-ghost s-btn-sm"
              style={{ width: '100%', marginTop: 8, fontSize: '0.6rem', borderColor: 'rgba(167,139,250,0.15)' }}
              disabled={threatAuto?.feed?.syncing}
              onClick={async () => {
                try {
                  notify.info('Feed-Sync wird gestartet...');
                  const r = await api()?.threatAuto?.triggerFeed?.();
                  if (r?.success) notify.success(`Feed-Sync: ${r.ips} IPs, ${r.hashes} Hashes geladen`);
                } catch (e: any) { notify.error(e?.message || 'Fehler'); }
              }}
            >
              {threatAuto?.feed?.syncing ? 'Wird synchronisiert...' : '\u21bb Jetzt synchronisieren'}
            </button>
          </div>
        </div>

        {/* Recent Threats — inline, no hidden tabs */}
        {((threatAuto?.recentYaraHits?.length ?? 0) > 0 || (threatAuto?.recentIoCHits?.length ?? 0) > 0) && (
          <div style={{ borderTop: '1px solid rgba(255,63,180,0.08)', paddingTop: 10 }}>
            <div style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
              {'Letzte Bedrohungen'}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 120, overflowY: 'auto' }}>
              {(threatAuto?.recentYaraHits || []).slice(0, 3).map((hit, i) => (
                <div key={`yara-${i}`} style={{
                  display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', borderRadius: 6,
                  background: hit.severity === 'malicious' ? 'rgba(255,95,95,0.06)' : 'rgba(255,190,61,0.04)',
                  border: `1px solid ${hit.severity === 'malicious' ? 'rgba(255,95,95,0.12)' : 'rgba(255,190,61,0.1)'}`,
                }}>
                  <span style={{ fontSize: '0.7rem' }}>{hit.severity === 'malicious' ? '\ud83d\udea8' : '\u26a0\ufe0f'}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: '0.625rem', fontWeight: 600, color: hit.severity === 'malicious' ? 'var(--s-red)' : 'var(--s-amber)' }} className="s-truncate">
                      {hit.file.split('\\').pop() || hit.file}
                    </div>
                    <div style={{ fontSize: '0.55rem', color: 'var(--s-text-dim)' }} className="s-truncate">
                      {'YARA: '}{hit.rules.join(', ')}
                    </div>
                  </div>
                  <span style={{ fontSize: '0.5rem', color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)', flexShrink: 0 }}>
                    {new Date(hit.ts).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
              ))}
              {(threatAuto?.recentIoCHits || []).slice(0, 3).map((hit, i) => (
                <div key={`ioc-${i}`} style={{
                  display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', borderRadius: 6,
                  background: 'rgba(255,95,95,0.06)', border: '1px solid rgba(255,95,95,0.12)',
                }}>
                  <span style={{ fontSize: '0.7rem' }}>{'\ud83d\udea8'}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: '0.625rem', fontWeight: 600, color: 'var(--s-red)' }}>
                      {hit.ip}
                    </div>
                    <div style={{ fontSize: '0.55rem', color: 'var(--s-text-dim)' }} className="s-truncate">
                      {'Prozess: '}{hit.process}{' \u00b7 Quelle: '}{hit.source}
                    </div>
                  </div>
                  <span style={{ fontSize: '0.5rem', color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)', flexShrink: 0 }}>
                    {new Date(hit.ts).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Footer info */}
        <div style={{ fontSize: '0.55rem', color: 'var(--s-text-dim)', marginTop: 8, display: 'flex', alignItems: 'center', gap: 8, opacity: 0.7 }}>
          <span>{'100% lokal \u2014 keine externen API-Aufrufe f\u00fcr Scans'}</span>
          <span>{'·'}</span>
          <span>{'YARA alle '}{threatAuto ? '30' : '?'}{' Min'}</span>
          <span>{'·'}</span>
          <span>{'IoC alle '}{threatAuto ? '60' : '?'}{' Sek'}</span>
          <span>{'·'}</span>
          <span>{'Feeds alle '}{threatAuto ? '6' : '?'}{' Std'}</span>
        </div>
      </motion.div>

      {/* ─── Sentinel Deep Scan Results ─── */}
      {(scanning || scanResult) && (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
            <span className="s-heading-sm">{t('dashboard.deepScan')}</span>
            {scanning && (
              <motion.span
                animate={{ opacity: [0.4, 1, 0.4] }}
                transition={{ duration: 1.5, repeat: Infinity }}
                style={{ fontSize: '0.7rem', color: 'var(--s-cyan)', fontWeight: 500 }}
              >
                {t('dashboard.scanning')}
              </motion.span>
            )}
            <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, rgba(109,120,255,0.2), transparent)' }} />
          </div>
          {scanResult && (
            <>
              {/* Overall Score Bar */}
              <div style={{
                display: 'flex', gap: 16, marginBottom: 16, alignItems: 'center',
                padding: '14px 18px', borderRadius: 12,
                background: 'linear-gradient(135deg, rgba(15,15,50,0.5), rgba(8,8,28,0.8))',
                border: '1px solid rgba(109,120,255,0.1)',
              }}>
                <div style={{
                  fontSize: '2.25rem', fontWeight: 800, fontFamily: 'var(--s-font-display)',
                  color: scanScoreColor(scanResult.score),
                  textShadow: `0 0 20px ${scanScoreColor(scanResult.score)}33`,
                  lineHeight: 1,
                }}>
                  {scanResult.score}
                  <span style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--s-text-dim)' }}>/100</span>
                </div>
                <div style={{ display: 'flex', gap: 12, fontSize: '0.725rem', flexWrap: 'wrap' }}>
                  <span style={{ color: 'var(--s-green)', display: 'flex', alignItems: 'center', gap: 3 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--s-green)', boxShadow: '0 0 4px var(--s-green)' }} />
                    {scanResult.passed} {t('common.pass')}
                  </span>
                  <span style={{ color: 'var(--s-red)', display: 'flex', alignItems: 'center', gap: 3 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--s-red)', boxShadow: '0 0 4px var(--s-red)' }} />
                    {scanResult.failed} {t('common.fail')}
                  </span>
                  <span style={{ color: 'var(--s-amber)', display: 'flex', alignItems: 'center', gap: 3 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--s-amber)', boxShadow: '0 0 4px var(--s-amber)' }} />
                    {scanResult.warnings} {t('common.warn')}
                  </span>
                </div>
                <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                  <button
                    className="s-btn s-btn-ghost s-btn-sm"
                    style={{ borderColor: 'rgba(60,240,255,0.2)' }}
                    onClick={async () => {
                      try {
                        const r = await api()?.shield?.exportReportFile?.();
                        if (r?.success) notify.success(`Report saved: ${r.data?.path}`);
                        else if (r?.error !== 'Export cancelled') notify.error(r?.error || 'Export failed');
                      } catch (e: any) { notify.error(e?.message || 'Export failed'); }
                    }}
                  >
                    {t('dashboard.exportReport')}
                  </button>
                  <button
                    className="s-btn s-btn-ghost s-btn-sm"
                    style={{ borderColor: 'rgba(60,240,255,0.2)' }}
                    onClick={handleFullScan} disabled={scanning}
                  >
                    {scanning ? t('dashboard.scanning') : `↻ ${t('common.refresh')}`}
                  </button>
                </div>
              </div>
              {/* Module Columns — ALL 5 visible simultaneously */}
              <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Object.keys(scanResult.modules).length}, 1fr)`, gap: 10 }}>
                {Object.entries(scanResult.modules).map(([key, mod]) => {
                  const meta = MODULE_META[key] || { label: key, icon: '📦', color: 'var(--s-text-secondary)', path: '/' };
                  return (
                    <motion.div
                      key={key}
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      style={{ display: 'flex', flexDirection: 'column' }}
                    >
                      {/* Column header with color accent */}
                      <div style={{
                        padding: '10px 12px', borderRadius: '10px 10px 0 0',
                        border: '1px solid rgba(255,255,255,0.06)',
                        background: `linear-gradient(135deg, ${meta.color}08, rgba(8,8,28,0.6))`,
                        borderTop: `2px solid ${meta.color}55`,
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      }}>
                        <span style={{ fontWeight: 600, fontSize: '0.725rem' }}>{meta.icon} {meta.label}</span>
                        <span style={{
                          fontWeight: 800, fontSize: '0.8125rem', fontFamily: 'var(--s-font-display)',
                          color: scanScoreColor(mod.score),
                          textShadow: `0 0 8px ${scanScoreColor(mod.score)}44`,
                        }}>
                          {mod.score}%
                        </span>
                      </div>
                      <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', padding: '4px 12px', borderLeft: '1px solid rgba(255,255,255,0.06)', borderRight: '1px solid rgba(255,255,255,0.06)' }}>
                        {mod.passed}/{mod.total} {t('common.pass')}
                      </div>
                      <div className="s-progress-bar" style={{ height: 3, margin: '0 12px 4px', borderRadius: 2 }}>
                        <div className="s-progress-fill" style={{ width: `${mod.score}%`, background: `linear-gradient(90deg, ${meta.color}, ${meta.color}66)`, boxShadow: `0 0 6px ${meta.color}44` }} />
                      </div>
                      {/* Checks — ALWAYS visible, independently scrollable */}
                      <div style={{
                        flex: 1, overflowY: 'auto', maxHeight: 480, padding: '6px 6px 8px',
                        border: '1px solid rgba(255,255,255,0.06)', borderTop: 'none',
                        borderRadius: '0 0 10px 10px', display: 'flex', flexDirection: 'column', gap: 3,
                      }}>
                        {mod.checks && mod.checks.map((check: any, ci: number) => (
                          <LegacyScanCheckItem
                            key={ci}
                            check={{ id: check.id, name: check.name, status: check.status, detail: check.detail, risk: check.risk, richDetail: check.richDetail }}
                            onNavigate={(p) => navigate(p)}
                            compact
                          />
                        ))}
                      </div>
                      <button
                        className="s-btn s-btn-ghost s-btn-sm"
                        style={{ marginTop: 4, fontSize: '0.6rem', alignSelf: 'center', borderColor: `${meta.color}22` }}
                        onClick={() => navigate(meta.path)}
                      >
                        Open {meta.label} →
                      </button>
                    </motion.div>
                  );
                })}
              </div>
            </>
          )}
          {scanning && !scanResult && (
            <div className="s-card-spacy" style={{
              textAlign: 'center', padding: '40px 32px',
              background: 'linear-gradient(145deg, rgba(15,15,50,0.5), rgba(8,8,28,0.8))',
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16,
            }}>
              {/* Animated scanning rings */}
              <div style={{ position: 'relative', width: 60, height: 60 }}>
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
                  style={{
                    position: 'absolute', inset: 0, borderRadius: '50%',
                    border: '2px solid transparent', borderTopColor: 'var(--s-cyan)',
                    filter: 'drop-shadow(0 0 6px rgba(60,240,255,0.4))',
                  }}
                />
                <motion.div
                  animate={{ rotate: -360 }}
                  transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
                  style={{
                    position: 'absolute', inset: 8, borderRadius: '50%',
                    border: '2px solid transparent', borderTopColor: 'var(--s-purple)',
                    filter: 'drop-shadow(0 0 4px rgba(167,139,250,0.3))',
                  }}
                />
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 2.5, repeat: Infinity, ease: 'linear' }}
                  style={{
                    position: 'absolute', inset: 16, borderRadius: '50%',
                    border: '2px solid transparent', borderTopColor: 'var(--s-magenta)',
                    filter: 'drop-shadow(0 0 4px rgba(255,63,180,0.3))',
                  }}
                />
                <motion.div
                  animate={{ scale: [0.8, 1.1, 0.8], opacity: [0.5, 1, 0.5] }}
                  transition={{ duration: 2, repeat: Infinity }}
                  style={{
                    position: 'absolute', inset: 22, borderRadius: '50%',
                    background: 'radial-gradient(circle, rgba(60,240,255,0.15), transparent)',
                  }}
                />
              </div>
              <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--s-text-secondary)' }}>
                {t('dashboard.deepScan')}
              </div>
              {scanPhase && MODULE_META[scanPhase] && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 16px', borderRadius: 8, background: 'rgba(60,240,255,0.06)', border: '1px solid rgba(60,240,255,0.12)' }}>
                  <span style={{ fontSize: '1rem' }}>{MODULE_META[scanPhase].icon}</span>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: MODULE_META[scanPhase].color }}>{MODULE_META[scanPhase].label}</span>
                </div>
              )}
              <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)', maxWidth: 400 }}>
                {scanPhase ? `Scanning ${MODULE_META[scanPhase]?.label || scanPhase}...` : t('dashboard.deepScanDesc')}
              </div>
            </div>
          )}
          {scanError && (
            <div className="s-card-spacy" style={{
              borderColor: 'rgba(255,95,95,0.25)', padding: 20,
              borderLeft: '3px solid var(--s-red)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 10,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: 'rgba(255,95,95,0.1)', fontSize: '1.1rem',
                }}>⚠</div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, color: 'var(--s-red)', fontSize: '0.8125rem' }}>{t('scan.fixFailed')}</div>
                  <div style={{ fontSize: '0.725rem', color: 'var(--s-text-muted)', marginTop: 2 }}>{scanError}</div>
                </div>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={handleFullScan}>{t('common.retry')}</button>
              </div>
            </div>
          )}
        </motion.div>
      )}

      {/* ═══ Quick Actions + Activity Feed ═══ */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Quick Actions — Feature Cards */}
        <motion.div
          initial={{ opacity: 0, x: -12 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.35 }}
          style={{ display: 'flex', flexDirection: 'column', gap: 12 }}
        >
          <div className="s-section-header">
            <span className="s-heading-sm">{t('dashboard.quickActions')}</span>
            <div className="s-section-header-line" />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            {QUICK_ACTIONS.map((action, ai) => {
              const actionColors = ['var(--s-cyan)', 'var(--s-green)', 'var(--s-purple)', 'var(--s-amber)'];
              const ac = actionColors[ai % actionColors.length];
              const shortcuts = ['Ctrl+D', 'Ctrl+H', 'Ctrl+N', 'Ctrl+F'];
              return (
                <motion.button
                  key={action.id}
                  className="s-feature-card"
                  whileHover={{ y: -3 }}
                  whileTap={{ scale: 0.97 }}
                  style={{
                    alignItems: 'center', textAlign: 'center',
                    color: 'var(--s-text)', borderTop: `2px solid ${ac}33`,
                  }}
                  onClick={async () => {
                    try {
                      if (action.id === 'deep-scan') { handleFullScan(); return; }
                      const r = await api()?.executeQuickAction?.(action.id);
                      if (r?.success) {
                        notify.success(`${t(action.labelKey)}: ${r.actions?.join(', ') || r.message || t('common.success')}`);
                      } else {
                        notify.error(r?.message || `${t(action.labelKey)} ${t('common.fail')}`);
                      }
                    } catch (e: any) { notify.error(e?.message || 'Action failed'); }
                  }}
                  disabled={action.id === 'deep-scan' && scanning}
                >
                  <div className="s-feature-card-icon" style={{
                    background: `${ac}10`, fontSize: 22, margin: '0 auto',
                    filter: `drop-shadow(0 0 8px ${ac})`,
                  }}>
                    {action.icon}
                  </div>
                  <span style={{ fontSize: '0.8rem', fontWeight: 700, position: 'relative', zIndex: 1 }}>{t(action.labelKey)}</span>
                  <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', lineHeight: 1.3, position: 'relative', zIndex: 1 }}>{t(action.descKey)}</span>
                  <span style={{
                    fontSize: '0.5rem', color: 'var(--s-text-dim)', opacity: 0.5,
                    fontFamily: 'var(--s-font-mono)', padding: '1px 5px',
                    borderRadius: 4, background: 'rgba(109,120,255,0.04)',
                    border: '1px solid rgba(109,120,255,0.06)',
                    position: 'relative', zIndex: 1,
                  }}>
                    {shortcuts[ai] || ''}
                  </span>
                </motion.button>
              );
            })}
          </div>
        </motion.div>

        {/* Activity Feed — Timeline style */}
        <motion.div
          className="s-card-spacy"
          initial={{ opacity: 0, x: 12 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.35 }}
          style={{ display: 'flex', flexDirection: 'column' }}
        >
          <div className="s-flex-between" style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="s-heading-sm">{t('dashboard.recentActivity')}</span>
              <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, rgba(109,120,255,0.15), transparent)' }} />
            </div>
            <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => navigate('/settings')}>{t('common.all')} →</button>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 0, position: 'relative' }}>
            {/* Timeline line */}
            {activity.length > 0 && (
              <div style={{
                position: 'absolute', left: 3, top: 8, bottom: 8, width: 1,
                background: 'linear-gradient(180deg, rgba(109,120,255,0.15), transparent)',
                pointerEvents: 'none',
              }} />
            )}
            {activity.length === 0 ? (
              <div style={{
                textAlign: 'center', padding: '32px 24px', color: 'var(--s-text-dim)', fontSize: '0.8125rem',
                display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8,
              }}>
                <span style={{ fontSize: '1.5rem', opacity: 0.3 }}>◇</span>
                {t('common.noData')}
              </div>
            ) : (
              activity.map((entry, ei) => (
                <motion.div
                  key={`${entry.id}-${entry.timestamp}`}
                  initial={{ opacity: 0, x: 6 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.4 + ei * 0.03 }}
                  style={{
                    display: 'flex', alignItems: 'flex-start', gap: 12, padding: '8px 0 8px 12px',
                    borderBottom: '1px solid rgba(109,120,255,0.04)',
                    position: 'relative',
                  }}
                >
                  <div style={{
                    width: 7, height: 7, borderRadius: '50%', marginTop: 5, flexShrink: 0,
                    background: severityColor(entry.severity),
                    boxShadow: `0 0 6px ${severityColor(entry.severity)}`,
                    position: 'relative', zIndex: 1,
                  }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: 600 }}>{entry.module}</span>
                      <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', padding: '1px 5px', borderRadius: 4, background: 'rgba(109,120,255,0.05)' }}>{entry.action}</span>
                    </div>
                    <div className="s-truncate" style={{ fontSize: '0.675rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                      {entry.details}
                    </div>
                  </div>
                  <span style={{ fontSize: '0.575rem', color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)', flexShrink: 0 }}>
                    {new Date(entry.timestamp).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </motion.div>
              ))
            )}
          </div>
        </motion.div>
      </div>

      {/* ═══ Health Score Detail Modal ═══ */}
      <AnimatePresence>
        {healthDetailOpen && (
          <motion.div
            className="s-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setHealthDetailOpen(false)}
          >
            <motion.div
              className="s-modal"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 12 }}
              onClick={(e) => e.stopPropagation()}
              style={{ maxWidth: 620, borderTopColor: `${scoreColor}66`, borderTopWidth: 2 }}
            >
              <div className="s-modal-header" style={{ background: `linear-gradient(135deg, ${scoreColor}06, transparent)` }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                  <div style={{
                    width: 46, height: 46, borderRadius: 12,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: `${scoreColor}12`, border: `1px solid ${scoreColor}33`,
                    fontSize: '1.35rem', fontWeight: 800, fontFamily: 'var(--s-font-display)',
                    color: scoreColor, textShadow: `0 0 12px ${scoreColor}44`,
                  }}>
                    {healthScore}
                  </div>
                  <div>
                    <span style={{ fontWeight: 700, fontSize: '1rem' }}>Systemzustand</span>
                    <div style={{ fontSize: '0.675rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                      {healthScore >= 80 ? '● System ist gut geschützt' : healthScore >= 50 ? '◐ Einige Bereiche erfordern Aufmerksamkeit' : '○ Kritische Probleme erkannt'}
                    </div>
                  </div>
                </div>
                <button className="s-modal-close" onClick={() => setHealthDetailOpen(false)}>✕</button>
              </div>
              <div className="s-modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 16, maxHeight: '65vh', overflowY: 'auto' }}>
                {/* ─── Resources Section ─── */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                    <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      ⚡ Systemressourcen
                    </span>
                    <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, rgba(109,120,255,0.15), transparent)' }} />
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                    {[
                      { label: 'CPU', value: stats.cpu, desc: stats.cpu > 80 ? 'Hohe Last' : stats.cpu > 50 ? 'Moderate Last' : 'Normal' },
                      { label: 'Speicher', value: stats.ram, desc: stats.ram > 80 ? 'Speicherdruck' : stats.ram > 50 ? 'Moderate Last' : 'Verfügbar' },
                      { label: 'Festplatte', value: stats.disk, desc: stats.disk > 80 ? 'Wenig Platz' : stats.disk > 50 ? 'Moderat' : 'Ausreichend' },
                    ].map(r => {
                      const c = r.value > 80 ? 'var(--s-red)' : r.value > 50 ? 'var(--s-amber)' : 'var(--s-green)';
                      return (
                        <div key={r.label} style={{ padding: '10px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderTop: `2px solid ${c}33` }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                            <span style={{ fontSize: '0.675rem', fontWeight: 600 }}>{r.label}</span>
                            <span style={{ fontSize: '0.8rem', fontWeight: 800, fontFamily: 'var(--s-font-display)', color: c }}>{r.value}%</span>
                          </div>
                          <div className="s-progress-bar" style={{ height: 4, marginBottom: 5, borderRadius: 2 }}>
                            <div className="s-progress-fill" style={{ width: `${r.value}%`, background: `linear-gradient(90deg, ${c}, ${c}66)`, boxShadow: `0 0 4px ${c}33` }} />
                          </div>
                          <div style={{ fontSize: '0.575rem', color: 'var(--s-text-dim)' }}>{r.desc}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* ─── Health Components ─── */}
                {health?.components && health.components.length > 0 && (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                      <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                        🔧 Systemkomponenten
                      </span>
                      <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, rgba(109,120,255,0.15), transparent)' }} />
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                      {health.components.map((comp, i) => {
                        const ok = comp.status === 'healthy' || comp.status === 'good' || comp.status === 'pass';
                        const warn = comp.status === 'warning' || comp.status === 'degraded';
                        return (
                          <div key={i} style={{
                            display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px',
                            borderRadius: 6, background: 'rgba(255,255,255,0.015)',
                          }}>
                            <span style={{ color: ok ? 'var(--s-green)' : warn ? 'var(--s-amber)' : 'var(--s-red)', fontSize: '0.7rem', fontWeight: 700, width: 14, textAlign: 'center', flexShrink: 0 }}>
                              {ok ? '✓' : warn ? '⚠' : '✕'}
                            </span>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ fontSize: '0.725rem', fontWeight: 600 }}>{comp.name}</div>
                              {comp.message && <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', marginTop: 1 }} className="s-truncate">{comp.message}</div>}
                            </div>
                            <span style={{
                              fontSize: '0.55rem', padding: '2px 6px', borderRadius: 6,
                              background: ok ? 'rgba(0,255,136,0.08)' : warn ? 'rgba(255,170,0,0.08)' : 'rgba(255,51,102,0.08)',
                              color: ok ? 'var(--s-green)' : warn ? 'var(--s-amber)' : 'var(--s-red)',
                              fontWeight: 600, textTransform: 'uppercase',
                            }}>
                              {comp.status}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* ─── Protection Status ─── */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                    <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      🛡 Schutzstatus
                    </span>
                    <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, rgba(109,120,255,0.15), transparent)' }} />
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                    {[
                      { label: 'Firewall', status: 'Aktiv', ok: true },
                      { label: 'Netzwerk-Monitor', status: 'Läuft', ok: true },
                      { label: 'ARGUS Backend', status: argusStatus?.online ? 'Online' : 'Offline', ok: !!argusStatus?.online },
                      { label: 'VPN Tunnel', status: vpnStatus?.active ? `${vpnStatus.provider}` : 'Nicht verbunden', ok: !!vpnStatus?.active },
                      { label: 'Scan-Engine', status: scanResult ? `Wert: ${scanResult.score}%` : 'Noch nicht gescannt', ok: scanResult ? scanResult.score >= 70 : false },
                      { label: 'Härtung', status: hardeningScore ? `${hardeningScore.percentage}%` : 'Noch nicht geprüft', ok: hardeningScore ? hardeningScore.percentage >= 70 : false },
                    ].map(p => (
                      <div key={p.label} style={{
                        display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px',
                        borderRadius: 6, background: 'rgba(255,255,255,0.015)',
                        borderLeft: `2px solid ${p.ok ? 'rgba(61,255,143,0.3)' : 'rgba(255,95,95,0.3)'}`,
                      }}>
                        <div style={{
                          width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                          background: p.ok ? 'var(--s-green)' : 'var(--s-red)',
                          boxShadow: `0 0 6px ${p.ok ? 'var(--s-green)' : 'var(--s-red)'}`,
                        }} />
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: '0.675rem', fontWeight: 600 }}>{p.label}</div>
                        </div>
                        <span style={{ fontSize: '0.6rem', color: p.ok ? 'var(--s-green)' : 'var(--s-red)', fontWeight: 600 }}>{p.status}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* ─── DSGVO Compliance ─── */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                    <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      🔒 Datenschutz (DSGVO)
                    </span>
                    <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, rgba(0,230,118,0.15), transparent)' }} />
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 5 }}>
                    {[
                      { label: 'Datenverarbeitung', value: '100% Lokal', ok: true, art: 'Art.5' },
                      { label: 'Verschl\u00fcsselung', value: 'AES-256-GCM', ok: true, art: 'Art.32' },
                      { label: 'Sitzung', value: osopSession?.active ? 'Ephemer (OSOP)' : 'Laden...', ok: !!osopSession?.active, art: 'Art.17' },
                      { label: 'Datenl\u00f6schung', value: 'Bei Exit', ok: true, art: 'Art.17' },
                      { label: 'IoC-Pr\u00fcfung', value: 'Lokal (kein API)', ok: true, art: 'Art.5' },
                      { label: 'PIN-Schutz', value: 'PBKDF2-SHA512', ok: true, art: 'Art.32' },
                      { label: 'MFA (TOTP)', value: 'RFC 6238', ok: true, art: 'Art.32' },
                      { label: 'Logging', value: 'Nur RAM (OSOP)', ok: true, art: 'Art.5' },
                    ].map(d => (
                      <div key={d.label} style={{
                        display: 'flex', alignItems: 'center', gap: 8, padding: '5px 8px',
                        borderRadius: 6, background: 'rgba(0,230,118,0.02)', border: '1px solid rgba(0,230,118,0.08)',
                      }}>
                        <div style={{ width: 5, height: 5, borderRadius: '50%', background: d.ok ? '#00e676' : 'var(--s-amber)', boxShadow: `0 0 4px ${d.ok ? '#00e676' : 'var(--s-amber)'}`, flexShrink: 0 }} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: '0.6rem', fontWeight: 600, color: 'var(--s-text-secondary)' }}>{d.label}</div>
                        </div>
                        <div style={{ textAlign: 'right', flexShrink: 0 }}>
                          <span style={{ fontSize: '0.55rem', color: 'var(--s-text-dim)' }}>{d.value} </span>
                          <span style={{ fontSize: '0.5rem', color: '#00e676', fontWeight: 700 }}>{d.art}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* ─── Empfehlungen ─── */}
                <div className="s-callout s-callout-info" style={{ flexDirection: 'column', gap: 6 }}>
                  <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--s-text-secondary)' }}>💡 Empfehlungen</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: '0.675rem', color: 'var(--s-text-secondary)' }}>
                    {!scanResult && <div>{'→ Führen Sie einen Tiefen-Scan durch für eine vollständige Bewertung'}</div>}
                    {!hardeningScore && <div>{'→ Starten Sie das Härtungs-Audit für Sicherheitskontrollen'}</div>}
                    {!vpnStatus?.active && <div>{'→ VPN aktivieren für mehr Netzwerk-Privatsphäre'}</div>}
                    {!argusStatus?.online && <div>{'→ ARGUS-Backend starten für Bedrohungserkennung'}</div>}
                    {stats.ram > 80 && <div>{'→ Hohe Speicherauslastung — Programme schließen'}</div>}
                    {stats.disk > 80 && <div>{'→ Wenig Festplattenspeicher — Bereinigung empfohlen'}</div>}
                    {scanResult && scanResult.score >= 80 && hardeningScore && hardeningScore.percentage >= 80 && vpnStatus?.active && argusStatus?.online && stats.ram <= 80 && stats.disk <= 80 && (
                      <div style={{ color: 'var(--s-green)' }}>{'✓ Alle Systeme optimal — keine Maßnahmen erforderlich'}</div>
                    )}
                  </div>
                </div>
              </div>
              <div className="s-modal-footer">
                <button className="s-btn s-btn-primary s-btn-sm" onClick={() => { setHealthDetailOpen(false); handleFullScan(); }}>⚡ Tiefen-Scan</button>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => { setHealthDetailOpen(false); handleHardeningAudit(); }}>{'🛡 Härtungs-Audit'}</button>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => { setHealthDetailOpen(false); navigate('/system'); }}>{'System →'}</button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default Dashboard;
