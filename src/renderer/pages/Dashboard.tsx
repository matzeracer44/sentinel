/**
 * SENTINEL UNIFIED — Dashboard Page
 * System health overview, threat summary, live stats, quick actions, and activity feed.
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { notify } from '../components/Common/SentinelNotification';
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
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, [fetchData]);

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
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 15000);
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* ─── Hero: Health Score + System Stats ─── */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 20 }}>
        {/* Health Score Ring — Premium animated */}
        <motion.div
          className="s-card-spacy"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.4, ease: 'easeOut' }}
          onClick={() => setHealthDetailOpen(true)}
          style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
            padding: 28, position: 'relative', cursor: 'pointer',
            background: 'linear-gradient(145deg, rgba(15,15,50,0.7), rgba(8,8,28,0.95))',
          }}
          whileHover={{ boxShadow: `0 0 30px ${scoreColor}18` }}
        >
          {/* Ambient glow behind ring */}
          <div style={{
            position: 'absolute', width: 180, height: 180, borderRadius: '50%',
            background: `radial-gradient(circle, ${scoreColor}15, transparent 70%)`,
            filter: 'blur(20px)', pointerEvents: 'none',
          }} />
          <svg width="170" height="170" viewBox="0 0 170 170" style={{ filter: `drop-shadow(0 0 16px ${scoreColor}66)`, position: 'relative', zIndex: 1 }}>
            {/* Outer glow ring */}
            <circle cx="85" cy="85" r="74" fill="none" stroke={`${scoreColor}08`} strokeWidth="14" />
            {/* Track */}
            <circle cx="85" cy="85" r="68" fill="none" stroke="rgba(109,120,255,0.08)" strokeWidth="7" />
            {/* Score arc */}
            <circle
              cx="85" cy="85" r="68" fill="none"
              stroke="url(#scoreGradient)" strokeWidth="7" strokeLinecap="round"
              strokeDasharray={`${(healthScore / 100) * 427} 427`}
              transform="rotate(-90 85 85)"
              style={{ transition: 'stroke-dasharray 1.2s cubic-bezier(0.4,0,0.2,1)' }}
            />
            {/* Inner glow arc */}
            <circle
              cx="85" cy="85" r="68" fill="none"
              stroke={scoreColor} strokeWidth="2" strokeLinecap="round"
              strokeDasharray={`${(healthScore / 100) * 427} 427`}
              transform="rotate(-90 85 85)"
              style={{ transition: 'stroke-dasharray 1.2s cubic-bezier(0.4,0,0.2,1)', filter: `blur(4px)`, opacity: 0.6 }}
            />
            <defs>
              <linearGradient id="scoreGradient" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor={scoreColor} />
                <stop offset="100%" stopColor={scoreColor} stopOpacity="0.5" />
              </linearGradient>
            </defs>
          </svg>
          <div style={{ position: 'absolute', textAlign: 'center', zIndex: 2 }}>
            <motion.div
              key={healthScore}
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ duration: 0.5, ease: 'easeOut' }}
              style={{
                fontSize: '2.75rem', fontWeight: 800, fontFamily: 'var(--s-font-display)',
                color: scoreColor, lineHeight: 1,
                textShadow: `0 0 30px ${scoreColor}44`,
              }}
            >
              {healthScore}
            </motion.div>
            <div style={{
              fontSize: '0.625rem', color: 'var(--s-text-dim)', marginTop: 6,
              textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 600,
            }}>
              {t('dashboard.healthScore')}
            </div>
          </div>
          <div style={{
            marginTop: 18, fontSize: '0.75rem', color: 'var(--s-text-secondary)', textAlign: 'center',
            padding: '6px 16px', borderRadius: 20,
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
              <div style={{ display: 'flex', gap: 16, marginTop: 12 }}>
                {[
                  { label: 'Security', value: secScore },
                  { label: 'Performance', value: perfScore },
                  { label: 'Privacy', value: privScore },
                ].map(sub => (
                  <div key={sub.label} style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '1rem', fontWeight: 700, fontFamily: 'var(--s-font-display)', color: scanScoreColor(sub.value) }}>
                      {sub.value}
                    </div>
                    <div style={{ fontSize: '0.5rem', color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      {sub.label}
                    </div>
                  </div>
                ))}
              </div>
            );
          })()}
        </motion.div>

        {/* System Stats Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
          {[
            { label: 'CPU', value: stats.cpu, unit: '%', color: stats.cpu > 80 ? 'var(--s-red)' : stats.cpu > 50 ? 'var(--s-amber)' : 'var(--s-cyan)', icon: '⚡' },
            { label: 'Memory', value: stats.ram, unit: '%', color: stats.ram > 80 ? 'var(--s-red)' : stats.ram > 50 ? 'var(--s-amber)' : 'var(--s-cyan)', icon: '◈' },
            { label: 'Disk', value: stats.disk, unit: '%', color: stats.disk > 80 ? 'var(--s-red)' : stats.disk > 50 ? 'var(--s-amber)' : 'var(--s-cyan)', icon: '◉' },
          ].map((stat, i) => (
            <motion.div
              key={stat.label}
              className="s-card-spacy"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 + i * 0.06 }}
              style={{
                display: 'flex', flexDirection: 'column', justifyContent: 'space-between',
                borderTop: `2px solid ${stat.color}44`,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                <span style={{ fontSize: '0.7rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--s-text-muted)' }}>
                  {stat.icon} {stat.label}
                </span>
                <span style={{
                  fontSize: '0.6rem', padding: '2px 6px', borderRadius: 8,
                  background: `${stat.color}12`, color: stat.color,
                  fontWeight: 700, fontFamily: 'var(--s-font-mono)',
                }}>
                  {stat.value > 80 ? 'HIGH' : stat.value > 50 ? 'MED' : 'LOW'}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
                <motion.span
                  key={stat.value}
                  initial={{ opacity: 0.5, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  style={{
                    fontSize: '2.25rem', fontWeight: 800, fontFamily: 'var(--s-font-display)',
                    color: stat.color, lineHeight: 1,
                    textShadow: `0 0 20px ${stat.color}33`,
                  }}
                >
                  {stat.value}
                </motion.span>
                <span style={{ fontSize: '0.875rem', color: 'var(--s-text-dim)', fontWeight: 500 }}>{stat.unit}</span>
              </div>
              <div className="s-progress-bar" style={{ marginTop: 14, height: 5, borderRadius: 3 }}>
                <div
                  className="s-progress-fill"
                  style={{
                    width: `${stat.value}%`,
                    background: `linear-gradient(90deg, ${stat.color}, ${stat.color}66)`,
                    boxShadow: `0 0 8px ${stat.color}44`,
                  }}
                />
              </div>
            </motion.div>
          ))}
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

      {/* ─── VPN + ARGUS + Hardening ─── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
        {/* VPN Status */}
        <motion.div
          className="s-card-spacy"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.25 }}
          style={{
            display: 'flex', alignItems: 'center', gap: 16,
            borderTop: `2px solid ${vpnStatus?.active ? 'rgba(61,255,143,0.3)' : 'rgba(255,95,95,0.2)'}`,
          }}
        >
          <div style={{
            width: 42, height: 42, borderRadius: 12,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: vpnStatus?.active ? 'rgba(61,255,143,0.08)' : 'rgba(255,95,95,0.08)',
            border: `1px solid ${vpnStatus?.active ? 'rgba(61,255,143,0.2)' : 'rgba(255,95,95,0.2)'}`,
            fontSize: 18,
          }}>
            {vpnStatus?.active ? '🔐' : '⚠'}
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>
              VPN {vpnStatus?.active ? t('dashboard.vpnActive') : t('dashboard.vpnInactive')}
            </div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
              {vpnStatus?.active
                ? `${vpnStatus.provider || 'Unknown'} • ${vpnStatus.protocol || ''} • ${vpnStatus.tunnelIP || ''}`
                : t('common.inactive')}
            </div>
          </div>
          <div style={{
            width: 8, height: 8, borderRadius: '50%',
            background: vpnStatus?.active ? 'var(--s-green)' : 'var(--s-red)',
            boxShadow: `0 0 10px ${vpnStatus?.active ? 'var(--s-green)' : 'var(--s-red)'}`,
            animation: vpnStatus?.active ? 'pulse-green 2s ease-in-out infinite' : 'none',
          }} />
        </motion.div>

        {/* Hardening Score — Clickable + expandable */}
        <motion.div
          className="s-card-spacy"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.28 }}
          style={{
            display: 'flex', flexDirection: 'column', gap: 0,
            cursor: hardeningScore ? 'pointer' : 'default',
            borderColor: hardeningExpanded ? 'rgba(109,120,255,0.3)' : undefined,
            transition: 'border-color 0.2s',
          }}
          onClick={() => { if (hardeningScore) setHardeningExpanded(!hardeningExpanded); }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            {hardeningScore ? (
              <>
                <div style={{
                  width: 40, height: 40, borderRadius: 10,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: (combinedSystemScore ?? 0) >= 80 ? 'rgba(0,255,136,0.12)' : (combinedSystemScore ?? 0) >= 50 ? 'rgba(255,170,0,0.12)' : 'rgba(255,51,102,0.12)',
                  border: `1px solid ${(combinedSystemScore ?? 0) >= 80 ? 'rgba(0,255,136,0.3)' : (combinedSystemScore ?? 0) >= 50 ? 'rgba(255,170,0,0.3)' : 'rgba(255,51,102,0.3)'}`,
                  fontSize: '0.875rem', fontWeight: 700,
                  color: (combinedSystemScore ?? 0) >= 80 ? 'var(--s-green)' : (combinedSystemScore ?? 0) >= 50 ? 'var(--s-amber)' : 'var(--s-red)',
                }}>
                  {combinedSystemScore ?? '—'}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>{t('dashboard.systemHealth')}</div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                    {hardeningScore.checks.filter(c => c.status === 'pass').length}/{hardeningScore.checks.length} {t('common.pass')}
                    {scanResult && <span style={{ marginLeft: 6, color: 'var(--s-cyan)', fontSize: '0.6rem' }}>+ Scan {scanResult.score}%</span>}
                  </div>
                  {!systemzustandComplete && (
                    <div style={{ fontSize: '0.5625rem', color: 'var(--s-amber)', marginTop: 2, opacity: 0.8 }}>
                      Vollst. Scan f. genauen Wert erforderlich
                    </div>
                  )}
                </div>
                <span style={{
                  color: 'var(--s-text-dim)', fontSize: '0.75rem',
                  transition: 'transform 0.2s',
                  transform: hardeningExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
                }}>
                  ▾
                </span>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={(e) => { e.stopPropagation(); handleHardeningAudit(); }} disabled={hardeningLoading}>
                  {hardeningLoading ? '...' : '↻'}
                </button>
              </>
            ) : (
              <>
                <div style={{
                  width: 40, height: 40, borderRadius: 10,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: 'rgba(109,120,255,0.08)', border: '1px solid rgba(109,120,255,0.2)',
                  fontSize: 18,
                }}>
                  🛡
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>{t('dashboard.securityStatus')}</div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                    {t('system.scans.hardeningScan')}
                  </div>
                </div>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={(e) => { e.stopPropagation(); handleHardeningAudit(); }} disabled={hardeningLoading}>
                  {hardeningLoading ? t('dashboard.scanning') : t('system.scans.runScan')}
                </button>
              </>
            )}
          </div>
          {/* Expanded hardening check details */}
          {hardeningExpanded && hardeningScore && (
            <div style={{
              marginTop: 12, paddingTop: 10, borderTop: '1px solid rgba(255,255,255,0.04)',
              display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 280, overflowY: 'auto',
            }}>
              {hardeningScore.checks.map((check) => {
                const passed = check.status === 'pass';
                return (
                  <div key={check.id} style={{
                    display: 'flex', alignItems: 'center', gap: 8, padding: '5px 6px',
                    borderRadius: 6, background: 'rgba(255,255,255,0.015)',
                    transition: 'background 0.1s',
                  }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.035)'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.015)'; }}
                  >
                    <span style={{ color: passed ? 'var(--s-green)' : 'var(--s-red)', fontSize: '0.75rem', fontWeight: 700, flexShrink: 0 }}>
                      {passed ? '✓' : '✕'}
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#e2e8f0', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {check.name}
                      </div>
                      <div style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)', marginTop: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {check.detail}
                      </div>
                    </div>
                    <span style={{
                      fontSize: '0.5625rem', color: 'var(--s-text-dim)',
                      padding: '1px 5px', borderRadius: 8,
                      background: 'rgba(255,255,255,0.04)', flexShrink: 0,
                    }}>
                      w{check.weight}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </motion.div>

        {/* ARGUS Backend Status */}
        <motion.div
          className="s-card-spacy"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.31 }}
          style={{
            display: 'flex', alignItems: 'center', gap: 16,
            borderTop: `2px solid ${argusStatus?.online ? 'rgba(61,255,143,0.3)' : 'rgba(255,95,95,0.2)'}`,
          }}
        >
          <div style={{
            width: 42, height: 42, borderRadius: 12,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: argusStatus?.online ? 'rgba(61,255,143,0.08)' : 'rgba(255,95,95,0.08)',
            border: `1px solid ${argusStatus?.online ? 'rgba(61,255,143,0.2)' : 'rgba(255,95,95,0.2)'}`,
            fontSize: 18,
          }}>
            {argusStatus?.online ? '🧠' : '💀'}
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>
              ARGUS {argusStatus?.online ? t('intel.argus.online') : argusStatus?.status === 'starting' ? t('intel.argus.starting') : t('intel.argus.offline')}
            </div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
              {argusStatus?.online
                ? `PID ${argusStatus.pid} • Uptime ${Math.floor((argusStatus.uptimeMs || 0) / 60000)}m`
                : argusStatus?.lastError || t('intel.argus.offline')}
            </div>
          </div>
          {!argusStatus?.online && (
            <button
              className="s-btn s-btn-ghost s-btn-sm"
              onClick={async () => { try { await api()?.argus?.start?.(); notify.success('ARGUS start requested'); } catch (e: any) { notify.error(e?.message || 'Failed to start ARGUS'); } }}
              style={{ color: 'var(--s-red)', borderRadius: 8 }}
            >
              {t('common.start')}
            </button>
          )}
          <div style={{
            width: 8, height: 8, borderRadius: '50%',
            background: argusStatus?.online ? 'var(--s-green)' : 'var(--s-red)',
            boxShadow: `0 0 10px ${argusStatus?.online ? 'var(--s-green)' : 'var(--s-red)'}`,
            animation: argusStatus?.online ? 'pulse-green 2s ease-in-out infinite' : 'none',
          }} />
        </motion.div>
      </div>

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

      {/* ─── Quick Actions + Activity Feed ─── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Quick Actions — Premium gradient buttons */}
        <motion.div
          className="s-card-spacy"
          initial={{ opacity: 0, x: -12 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.35 }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <span className="s-heading-sm">{t('dashboard.quickActions')}</span>
            <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, rgba(109,120,255,0.15), transparent)' }} />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            {QUICK_ACTIONS.map((action, ai) => {
              const actionColors = ['var(--s-cyan)', 'var(--s-green)', 'var(--s-purple)', 'var(--s-amber)'];
              const ac = actionColors[ai % actionColors.length];
              return (
                <motion.button
                  key={action.id}
                  whileHover={{ y: -2, boxShadow: `0 4px 16px ${ac}18` }}
                  whileTap={{ scale: 0.97 }}
                  style={{
                    display: 'flex', flexDirection: 'column', alignItems: 'center',
                    padding: '16px 12px', gap: 8, textAlign: 'center',
                    background: 'rgba(109,120,255,0.03)', border: `1px solid rgba(109,120,255,0.12)`,
                    borderRadius: 10, cursor: 'pointer', color: 'var(--s-text)',
                    borderTop: `2px solid ${ac}44`,
                    transition: 'all 0.2s ease',
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
                  <div style={{
                    width: 36, height: 36, borderRadius: 10,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: `${ac}10`, fontSize: 20,
                    filter: `drop-shadow(0 0 6px ${ac})`,
                  }}>
                    {action.icon}
                  </div>
                  <span style={{ fontSize: '0.75rem', fontWeight: 600 }}>{t(action.labelKey)}</span>
                  <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', lineHeight: 1.3 }}>{t(action.descKey)}</span>
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
              style={{ maxWidth: 560, borderTopColor: `${scoreColor}66`, borderTopWidth: 2 }}
            >
              <div className="s-modal-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div style={{
                    width: 40, height: 40, borderRadius: 10,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: `${scoreColor}12`, border: `1px solid ${scoreColor}33`,
                    fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--s-font-display)',
                    color: scoreColor,
                  }}>
                    {healthScore}
                  </div>
                  <div>
                    <span style={{ fontWeight: 700, fontSize: '0.9375rem' }}>System Health Report</span>
                    <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
                      {healthScore >= 80 ? 'System is well protected' : healthScore >= 50 ? 'Some areas need attention' : 'Critical issues detected'}
                    </div>
                  </div>
                </div>
                <button className="s-modal-close" onClick={() => setHealthDetailOpen(false)}>✕</button>
              </div>
              <div className="s-modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {/* Live System Resources */}
                <div>
                  <div style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
                    System Resources
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                    {[
                      { label: 'CPU', value: stats.cpu, desc: stats.cpu > 80 ? 'High load — check processes' : stats.cpu > 50 ? 'Moderate usage' : 'Normal operation' },
                      { label: 'Memory', value: stats.ram, desc: stats.ram > 80 ? 'Memory pressure — close unused apps' : stats.ram > 50 ? 'Moderate usage' : 'Plenty available' },
                      { label: 'Disk', value: stats.disk, desc: stats.disk > 80 ? 'Low disk space — cleanup recommended' : stats.disk > 50 ? 'Moderate usage' : 'Sufficient space' },
                    ].map(r => {
                      const c = r.value > 80 ? 'var(--s-red)' : r.value > 50 ? 'var(--s-amber)' : 'var(--s-green)';
                      return (
                        <div key={r.label} style={{ padding: '8px 10px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                            <span style={{ fontSize: '0.6875rem', fontWeight: 600 }}>{r.label}</span>
                            <span style={{ fontSize: '0.75rem', fontWeight: 700, fontFamily: 'var(--s-font-mono)', color: c }}>{r.value}%</span>
                          </div>
                          <div className="s-progress-bar" style={{ height: 3, marginBottom: 4 }}>
                            <div className="s-progress-fill" style={{ width: `${r.value}%`, background: c }} />
                          </div>
                          <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>{r.desc}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Health Components */}
                {health?.components && health.components.length > 0 && (
                  <div>
                    <div style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
                      Health Components
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {health.components.map((comp, i) => {
                        const ok = comp.status === 'healthy' || comp.status === 'good' || comp.status === 'pass';
                        const warn = comp.status === 'warning' || comp.status === 'degraded';
                        return (
                          <div key={i} style={{
                            display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px',
                            borderRadius: 6, background: 'rgba(255,255,255,0.015)',
                          }}>
                            <span style={{ color: ok ? 'var(--s-green)' : warn ? 'var(--s-amber)' : 'var(--s-red)', fontSize: '0.75rem', fontWeight: 700, width: 14, textAlign: 'center', flexShrink: 0 }}>
                              {ok ? '✓' : warn ? '⚠' : '✕'}
                            </span>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ fontSize: '0.75rem', fontWeight: 600 }}>{comp.name}</div>
                              {comp.message && <div style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)', marginTop: 1 }}>{comp.message}</div>}
                            </div>
                            <span style={{
                              fontSize: '0.5625rem', padding: '2px 6px', borderRadius: 8,
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

                {/* Protection Status Summary */}
                <div>
                  <div style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
                    Protection Status
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                    {[
                      { label: 'Firewall', status: 'Active', ok: true },
                      { label: 'Network Monitor', status: 'Running', ok: true },
                      { label: 'ARGUS Backend', status: argusStatus?.online ? 'Online' : 'Offline', ok: !!argusStatus?.online },
                      { label: 'VPN Tunnel', status: vpnStatus?.active ? `${vpnStatus.provider}` : 'Not connected', ok: !!vpnStatus?.active },
                      { label: 'Scan Engine', status: scanResult ? `Score: ${scanResult.score}%` : 'Not scanned yet', ok: scanResult ? scanResult.score >= 70 : false },
                      { label: 'Hardening', status: hardeningScore ? `${hardeningScore.percentage}%` : 'Not audited', ok: hardeningScore ? hardeningScore.percentage >= 70 : false },
                    ].map(p => (
                      <div key={p.label} style={{
                        display: 'flex', alignItems: 'center', gap: 8, padding: '5px 8px',
                        borderRadius: 6, background: 'rgba(255,255,255,0.015)',
                      }}>
                        <div style={{
                          width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                          background: p.ok ? 'var(--s-green)' : 'var(--s-red)',
                          boxShadow: `0 0 6px ${p.ok ? 'var(--s-green)' : 'var(--s-red)'}`,
                        }} />
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: '0.6875rem', fontWeight: 600 }}>{p.label}</div>
                        </div>
                        <span style={{ fontSize: '0.625rem', color: p.ok ? 'var(--s-green)' : 'var(--s-red)', fontWeight: 600 }}>{p.status}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recommendations */}
                <div style={{ padding: '10px 12px', borderRadius: 8, background: 'rgba(109,120,255,0.04)', border: '1px solid rgba(109,120,255,0.1)' }}>
                  <div style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--s-text-dim)', marginBottom: 6 }}>Recommendations</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: '0.6875rem', color: 'var(--s-text-secondary)' }}>
                    {!scanResult && <div>→ Run a Deep Scan to get a full security assessment</div>}
                    {!hardeningScore && <div>→ Run System Hardening Audit to check security controls</div>}
                    {!vpnStatus?.active && <div>→ Consider activating a VPN for network privacy</div>}
                    {!argusStatus?.online && <div>→ Start ARGUS backend for threat intelligence scanning</div>}
                    {stats.ram > 80 && <div>→ High memory usage — close unused applications</div>}
                    {stats.disk > 80 && <div>→ Low disk space — run Cleanup from Quick Actions</div>}
                    {scanResult && scanResult.score >= 80 && hardeningScore && hardeningScore.percentage >= 80 && vpnStatus?.active && argusStatus?.online && stats.ram <= 80 && stats.disk <= 80 && (
                      <div style={{ color: 'var(--s-green)' }}>✓ All systems optimal — no action needed</div>
                    )}
                  </div>
                </div>
              </div>
              <div className="s-modal-footer">
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => { setHealthDetailOpen(false); handleFullScan(); }}>Run Deep Scan</button>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => { setHealthDetailOpen(false); handleHardeningAudit(); }}>Run Hardening Audit</button>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => { setHealthDetailOpen(false); navigate('/system'); }}>Open System →</button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default Dashboard;
