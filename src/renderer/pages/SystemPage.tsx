/**
 * SENTINEL UNIFIED — System Page
 * CPU, RAM, Disk stats with live gauges, health report, startup items, services, quick actions.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { notify } from '../components/Common/SentinelNotification';
import InfoBadge from '../components/Common/InfoBadge';
import { LegacyScanCheckItem as ScanCheckItem } from '../components/Common/ScanCheckItem';
import { useTranslation } from 'react-i18next';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (): any => (window as any).electronAPI;

interface SystemData {
  cpu: { name: string; cores: number; threads: number; currentLoad: number };
  ram: { totalGB: number; usedGB: number; freeGB: number; usagePercent: number };
  disks: Array<{ drive: string; totalGB: number; usedGB: number; freeGB: number; usagePercent: number }>;
  system: { manufacturer: string; model: string; computerName: string; username: string };
  os: { name: string; version: string; build: string };
  gpu: Array<{ name: string; memory: number }>;
  network: Array<{ adapter: string; status: string; ipAddress: string; macAddress: string }>;
  battery: { status: string; percentage: number };
}

interface HealthReport {
  score: number;
  factors: { security: number; performance: number; privacy: number };
}

interface HardwareReport {
  gpu: Array<{ name: string; driver: string; driverDate: string; vramMB: number; resolution: string; refreshRate: number }>;
  ram: { totalGB: number; usedGB: number; freeGB: number; slots: Array<{ bank: string; capacityGB: number; speed: string; type: string; manufacturer: string }> };
  storage: {
    drives: Array<{ model: string; sizeGB: number; mediaType: string; busType: string; health: string }>;
    volumes: Array<{ letter: string; label: string; totalGB: number; freeGB: number; filesystem: string }>;
  };
  network: { adapters: Array<{ name: string; description: string; mac: string; speed: string; status: string; type: string }> };
  motherboard: { manufacturer: string; product: string; biosVersion: string; biosDate: string };
  security: { tpmPresent: boolean; tpmVersion: string; secureBoot: boolean };
  battery: { present: boolean; chargePercent: number; isCharging: boolean; estimatedRuntime: string; designCapacity: number; fullChargeCapacity: number; healthPercent: number; powerPlan: string } | null;
  audio: { devices: Array<{ name: string; status: string }> };
  bluetooth: { available: boolean; devices: Array<{ name: string; status: string }> };
  thermal: { available: boolean; sensors: Array<{ name: string; tempC: number; critical?: number }> };
  display: { monitors: Array<{ name: string; resolution: string; refreshRate: number; connection: string }> };
  usb: { devices: Array<{ name: string; type: string; status: string }> };
  bitlocker: { enabled: boolean; volumes: Array<{ letter: string; status: string; method: string }> };
  timestamp: string;
}

const GaugeRing: React.FC<{ value: number; label: string; color: string; size?: number }> = ({ value, label, color, size = 110 }) => {
  const r = (size - 14) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (value / 100) * circ;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, position: 'relative' }}>
      <div style={{
        position: 'absolute', width: size * 0.7, height: size * 0.7, borderRadius: '50%',
        background: `radial-gradient(circle, ${color}12, transparent 70%)`,
        filter: 'blur(12px)', pointerEvents: 'none', top: '10%',
      }} />
      <svg width={size} height={size} style={{ filter: `drop-shadow(0 0 10px ${color}33)`, position: 'relative', zIndex: 1 }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(109,120,255,0.08)" strokeWidth="7" />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke={color} strokeWidth="7" strokeLinecap="round"
          strokeDasharray={`${circ}`} strokeDashoffset={offset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: 'stroke-dashoffset 1s cubic-bezier(0.4,0,0.2,1)' }}
        />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke={color} strokeWidth="2" strokeLinecap="round"
          strokeDasharray={`${circ}`} strokeDashoffset={offset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: 'stroke-dashoffset 1s cubic-bezier(0.4,0,0.2,1)', filter: 'blur(4px)', opacity: 0.4 }}
        />
        <text x={size / 2} y={size / 2 - 2} textAnchor="middle" fill={color} fontSize="1.4rem" fontWeight="800" fontFamily="var(--s-font-display)">
          {value}%
        </text>
        <text x={size / 2} y={size / 2 + 16} textAnchor="middle" fill="rgba(160,168,220,0.5)" fontSize="0.5rem" style={{ textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600 }}>
          {label}
        </text>
      </svg>
    </div>
  );
};

interface ScanCheck {
  name: string;
  status: string;
  detail?: string;
  risk?: string;
}

interface ModuleScanResult {
  success: boolean;
  module: string;
  checks: ScanCheck[];
  passed: number;
  total: number;
  score: number;
}

const SystemPage: React.FC = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [data, setData] = useState<SystemData | null>(null);
  const [health, setHealth] = useState<HealthReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [perfScanning, setPerfScanning] = useState(false);
  const [perfResult, setPerfResult] = useState<ModuleScanResult | null>(null);
  const [kernelScanning, setKernelScanning] = useState(false);
  const [kernelResult, setKernelResult] = useState<ModuleScanResult | null>(null);
  const [hwReport, setHwReport] = useState<HardwareReport | null>(null);
  const [hwLoading, setHwLoading] = useState(false);
  const [secOverview, setSecOverview] = useState<any>(null);
  const perfRef = useRef<HTMLDivElement>(null);
  const kernelRef = useRef<HTMLDivElement>(null);
  const secRef = useRef<HTMLDivElement>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const a = api();
      if (a?.getRealSystemData) {
        const r = await a.getRealSystemData();
        if (r?.data) setData(r.data as SystemData);
      }
      if (a?.getSystemHealth) {
        const h = await a.getSystemHealth();
        if (h && typeof h.score === 'number') setHealth(h as HealthReport);
      }
    } catch (e: any) { console.warn('[SystemPage] fetchData:', e?.message); }
    setLoading(false);
  }, []);

  const fetchHardware = useCallback(async () => {
    setHwLoading(true);
    try {
      const r = await api()?.shield?.hardwareReport?.();
      if (r?.success && r.data) setHwReport(r.data as HardwareReport);
    } catch (e: any) { console.warn('[SystemPage] hardware report:', e?.message); }
    setHwLoading(false);
  }, []);

  useEffect(() => { fetchData(); fetchHardware(); const i = setInterval(fetchData, 5000); return () => clearInterval(i); }, [fetchData, fetchHardware]);

  // Restore persisted scan results on mount
  useEffect(() => {
    (async () => {
      try {
        const a = api();
        const [perfR, kernelR] = await Promise.all([
          a?.shield?.loadScanResult?.('performanceScan'),
          a?.shield?.loadScanResult?.('kernelScan'),
        ]);
        if (perfR?.success && perfR.entry?.data) setPerfResult(perfR.entry.data as ModuleScanResult);
        if (kernelR?.success && kernelR.entry?.data) setKernelResult(kernelR.entry.data as ModuleScanResult);
      } catch { /* no persisted results */ }
    })();
  }, []);

  const handlePerfScan = useCallback(async () => {
    setPerfScanning(true);
    try {
      const r = await api()?.shield?.performanceScan?.();
      if (r?.success) {
        setPerfResult(r as ModuleScanResult);
        try { await api()?.shield?.saveScanResult?.('performanceScan', r); } catch { /* best-effort */ }
        notify.success(`Performance scan: ${r.passed}/${r.total} passed (${r.score}%)`);
        setTimeout(() => perfRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
      } else {
        notify.error(r?.error || 'Performance scan failed');
      }
    } catch (e: any) { notify.error(e?.message || 'Performance scan failed'); }
    setPerfScanning(false);
  }, []);

  const handleKernelScan = useCallback(async () => {
    setKernelScanning(true);
    try {
      const r = await api()?.shield?.kernelScan?.();
      if (r?.success) {
        setKernelResult(r as ModuleScanResult);
        try { await api()?.shield?.saveScanResult?.('kernelScan', r); } catch { /* best-effort */ }
        notify.success(`Kernel scan: ${r.passed}/${r.total} passed (${r.score}%)`);
        setTimeout(() => kernelRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
      } else {
        notify.error(r?.error || 'Kernel scan failed');
      }
    } catch (e: any) { notify.error(e?.message || 'Kernel scan failed'); }
    setKernelScanning(false);
  }, []);

  const handleSecurityOverview = useCallback(async () => {
    try {
      const r = await api()?.shield?.getSecurityOverview?.();
      if (r?.success && r.data) {
        setSecOverview(r.data);
        notify.success('Security overview loaded');
        setTimeout(() => secRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
      } else {
        notify.error(r?.error || 'Security overview failed');
      }
    } catch (e: any) { notify.error(e?.message || 'Security overview failed'); }
  }, []);

  const checkColor = (s: string) => s === 'pass' ? 'var(--s-green)' : s === 'fail' ? 'var(--s-red)' : 'var(--s-amber)';
  const checkIcon = (s: string) => s === 'pass' ? '\u2713' : s === 'fail' ? '\u2715' : '\u26a0';

  const gaugeColor = (v: number) => v > 80 ? 'var(--s-red)' : v > 50 ? 'var(--s-amber)' : 'var(--s-green)';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* ═══ Live System Gauges ═══ */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
        <motion.div className="s-card-compact-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
          style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '18px 14px', borderTop: `2px solid ${gaugeColor(data?.cpu.currentLoad ?? 0)}33` }}>
          <GaugeRing value={data?.cpu.currentLoad ?? 0} label="CPU" color={gaugeColor(data?.cpu.currentLoad ?? 0)} />
          <div style={{ marginTop: 6, fontSize: '0.7rem', color: 'var(--s-text-muted)', textAlign: 'center' }} className="s-truncate">
            {data?.cpu.name || t('common.loading')}
          </div>
          <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>
            {data?.cpu.cores ?? 0} Kerne / {data?.cpu.threads ?? 0} Threads
          </div>
        </motion.div>

        <motion.div className="s-card-compact-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}
          style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '18px 14px', borderTop: `2px solid ${gaugeColor(data?.ram.usagePercent ?? 0)}33` }}>
          <GaugeRing value={data?.ram.usagePercent ?? 0} label="RAM" color={gaugeColor(data?.ram.usagePercent ?? 0)} />
          <div style={{ marginTop: 6, fontSize: '0.7rem', color: 'var(--s-text-muted)' }}>
            {data?.ram.usedGB ?? 0} / {data?.ram.totalGB ?? 0} GB
          </div>
          <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>
            {data?.ram.freeGB ?? 0} GB frei
          </div>
        </motion.div>

        {(data?.disks ?? [{ drive: 'C:', totalGB: 0, usedGB: 0, freeGB: 0, usagePercent: 0 }]).map((disk, i) => (
          <motion.div key={disk.drive} className="s-card-compact-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 + i * 0.05 }}
            style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '18px 14px', borderTop: `2px solid ${gaugeColor(disk.usagePercent)}33` }}>
            <GaugeRing value={disk.usagePercent} label={`Disk ${disk.drive}`} color={gaugeColor(disk.usagePercent)} />
            <div style={{ marginTop: 6, fontSize: '0.7rem', color: 'var(--s-text-muted)' }}>
              {disk.usedGB} / {disk.totalGB} GB
            </div>
            <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>
              {disk.freeGB} GB frei
            </div>
          </motion.div>
        ))}

        {health && (
          <motion.div className="s-card-compact-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}
            style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '18px 14px', borderTop: `2px solid ${gaugeColor(100 - health.score)}33` }}>
            <GaugeRing value={health.score} label="Zustand" color={gaugeColor(100 - health.score)} />
            <div style={{ marginTop: 6, display: 'flex', gap: 10 }}>
              {Object.entries(health.factors).map(([k, v]) => {
                const labels: Record<string, string> = { security: 'Sicherheit', performance: 'Leistung', privacy: 'Datenschutz' };
                return (
                  <div key={k} style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '0.8rem', fontWeight: 700, fontFamily: 'var(--s-font-display)', color: gaugeColor(100 - v) }}>{v}</div>
                    <div style={{ fontSize: '0.475rem', color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{labels[k] || k}</div>
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
      </div>

      {/* ─── System Info Cards ─── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* OS & System */}
        <motion.div className="s-card-spacy" initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.2 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-cyan), rgba(167,139,250,0.8))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>{t('system.title')}</span>
            <div className="s-section-divider" style={{ flex: 1 }} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[
              { label: t('system.overview.hostname'), value: data?.system.computerName },
              { label: t('system.overview.user'), value: data?.system.username },
              { label: t('system.overview.os'), value: data?.os.name },
              { label: t('system.overview.version'), value: data?.os.version },
              { label: t('system.overview.build'), value: data?.os.build },
              { label: t('system.hardware.motherboard'), value: data?.system.model },
            ].map((row) => (
              <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid rgba(109,120,255,0.06)' }}>
                <span style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)' }}>{row.label}</span>
                <span style={{ fontSize: '0.8125rem', fontFamily: 'var(--s-font-mono)' }}>{row.value || '—'}</span>
              </div>
            ))}
          </div>
        </motion.div>

        {/* GPU & Network */}
        <motion.div className="s-card-spacy" initial={{ opacity: 0, x: 8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.2 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-green), var(--s-cyan))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>{t('system.tabs.hardware')}</span>
            <div className="s-section-divider" style={{ flex: 1 }} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {(data?.gpu ?? []).map((g, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid rgba(109,120,255,0.06)' }}>
                <span style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)' }}>{t('system.hardware.gpu', { index: i + 1 })}</span>
                <span style={{ fontSize: '0.8125rem' }}>{g.name} ({g.memory} MB)</span>
              </div>
            ))}
            {(data?.network ?? []).map((n, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid rgba(109,120,255,0.06)' }}>
                <span style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)' }}>{n.adapter}</span>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '0.8125rem' }}>{n.ipAddress}</div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)' }}>{n.macAddress}</div>
                </div>
              </div>
            ))}
            {data?.battery && data.battery.status !== 'N/A' && (
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0' }}>
                <span style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)' }}>{t('system.hardware.battery')}</span>
                <span style={{ fontSize: '0.8125rem' }}>{data.battery.percentage}% ({data.battery.status})</span>
              </div>
            )}
          </div>
        </motion.div>
      </div>

      {/* ─── Full Hardware Discovery Grid ─── */}
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
        <div className="s-flex-between" style={{ marginBottom: 12 }}>
          <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-cyan), var(--s-purple))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>{t('system.hardware.title')}</span>
          <button className="s-btn s-btn-ghost s-btn-sm" onClick={fetchHardware} disabled={hwLoading}>
            {hwLoading ? t('common.loading') : `↻ ${t('common.refresh')}`}
          </button>
        </div>
        {hwReport ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            {/* GPU */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>{t('system.hardware.gpu')}</div>
              {hwReport.gpu.length > 0 ? hwReport.gpu.map((g, i) => (
                <div key={i} style={{ marginBottom: 6 }}>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#e2e8f0' }}>{g.name}</div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)' }}>
                    {g.vramMB > 0 ? `${g.vramMB} MB VRAM` : ''}{g.resolution !== '0x0' ? ` · ${g.resolution}` : ''}{g.refreshRate > 0 ? ` @ ${g.refreshRate}Hz` : ''}
                  </div>
                  <div style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)' }}>Driver: {g.driver || 'N/A'}</div>
                </div>
              )) : <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>{t('common.noData')}</div>}
            </div>

            {/* RAM Slots */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>{t('system.hardware.ram')}</div>
              <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#e2e8f0', marginBottom: 4 }}>{hwReport.ram.totalGB} GB ({hwReport.ram.usedGB} used / {hwReport.ram.freeGB} free)</div>
              {hwReport.ram.slots.map((s, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6875rem', color: 'var(--s-text-muted)', padding: '2px 0', borderBottom: '1px solid rgba(109,120,255,0.05)' }}>
                  <span>{s.bank}: {s.capacityGB}GB {s.type}</span>
                  <span style={{ fontFamily: 'var(--s-font-mono)' }}>{s.speed}</span>
                </div>
              ))}
            </div>

            {/* Storage */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>{t('system.hardware.disk')}</div>
              {hwReport.storage.drives.map((d, i) => (
                <div key={i} style={{ marginBottom: 6 }}>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#e2e8f0' }}>{d.model}</div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)' }}>{d.sizeGB} GB · {d.mediaType} · {d.busType}</div>
                  <div style={{ fontSize: '0.625rem', color: d.health === 'Healthy' ? 'var(--s-green)' : 'var(--s-amber)' }}>{d.health}</div>
                </div>
              ))}
              {hwReport.storage.volumes.map((v, i) => (
                <div key={`vol-${i}`} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6875rem', color: 'var(--s-text-muted)', padding: '2px 0' }}>
                  <span>{v.letter}: {v.label || 'Volume'} ({v.filesystem})</span>
                  <span>{v.freeGB}/{v.totalGB} GB free</span>
                </div>
              ))}
            </div>

            {/* Network Adapters */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>{t('system.hardware.network')}</div>
              {hwReport.network.adapters.map((a, i) => (
                <div key={i} style={{ marginBottom: 6, paddingBottom: 4, borderBottom: '1px solid rgba(109,120,255,0.05)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#e2e8f0' }}>{a.name}</span>
                    <span style={{
                      fontSize: '0.5625rem', padding: '1px 6px', borderRadius: 10,
                      background: a.status === 'Up' ? 'rgba(0,255,136,0.1)' : 'rgba(255,51,102,0.1)',
                      color: a.status === 'Up' ? 'var(--s-green)' : 'var(--s-red)',
                      border: `1px solid ${a.status === 'Up' ? 'rgba(0,255,136,0.3)' : 'rgba(255,51,102,0.3)'}`,
                    }}>{a.status}</span>
                  </div>
                  <div style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)' }}>{a.description}</div>
                  <div style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)' }}>{a.mac} · {a.speed} · {a.type}</div>
                </div>
              ))}
            </div>

            {/* Motherboard & BIOS */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>{t('system.hardware.motherboard')}</div>
              {[
                { label: 'Manufacturer', value: hwReport.motherboard.manufacturer },
                { label: 'Product', value: hwReport.motherboard.product },
                { label: 'BIOS Version', value: hwReport.motherboard.biosVersion },
                { label: 'BIOS Date', value: hwReport.motherboard.biosDate },
              ].map(row => (
                <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', padding: '2px 0', borderBottom: '1px solid rgba(109,120,255,0.05)' }}>
                  <span style={{ color: 'var(--s-text-muted)' }}>{row.label}</span>
                  <span style={{ color: '#e2e8f0', fontFamily: 'var(--s-font-mono)', fontSize: '0.6875rem' }}>{row.value || '—'}</span>
                </div>
              ))}
            </div>

            {/* Security (TPM, Secure Boot) */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>{t('nav.security')}</div>
              {[
                { label: 'TPM', value: hwReport.security.tpmPresent ? `Present (v${hwReport.security.tpmVersion || '?'})` : 'Not detected', ok: hwReport.security.tpmPresent },
                { label: 'Secure Boot', value: hwReport.security.secureBoot ? 'Enabled' : 'Disabled', ok: hwReport.security.secureBoot },
              ].map(row => (
                <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem', padding: '4px 0', borderBottom: '1px solid rgba(109,120,255,0.05)' }}>
                  <span style={{ color: 'var(--s-text-muted)' }}>{row.label}</span>
                  <span style={{ color: row.ok ? 'var(--s-green)' : 'var(--s-amber)', fontWeight: 600, fontSize: '0.6875rem' }}>{row.ok ? '✓' : '✕'} {row.value}</span>
                </div>
              ))}
            </div>

            {/* Battery */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Battery</div>
              {hwReport.battery ? (
                <>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 6 }}>
                    <span style={{ fontSize: '1.5rem', fontWeight: 700, fontFamily: 'var(--s-font-display)', color: hwReport.battery.chargePercent > 30 ? 'var(--s-green)' : 'var(--s-red)' }}>
                      {hwReport.battery.chargePercent}%
                    </span>
                    <span style={{ fontSize: '0.6875rem', color: hwReport.battery.isCharging ? 'var(--s-cyan)' : 'var(--s-text-muted)' }}>
                      {hwReport.battery.isCharging ? '⚡ Charging' : '🔋 On Battery'}
                    </span>
                  </div>
                  {[
                    { label: 'Runtime', value: hwReport.battery.estimatedRuntime },
                    { label: 'Health', value: `${hwReport.battery.healthPercent}% (${hwReport.battery.fullChargeCapacity}/${hwReport.battery.designCapacity} mWh)` },
                    { label: 'Power Plan', value: hwReport.battery.powerPlan || 'N/A' },
                  ].map(row => (
                    <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6875rem', color: 'var(--s-text-muted)', padding: '2px 0' }}>
                      <span>{row.label}</span><span style={{ fontFamily: 'var(--s-font-mono)' }}>{row.value}</span>
                    </div>
                  ))}
                </>
              ) : <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>{t('common.noData')}</div>}
            </div>

            {/* Audio */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Audio</div>
              {hwReport.audio.devices.length > 0 ? hwReport.audio.devices.map((d, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', padding: '2px 0', borderBottom: '1px solid rgba(109,120,255,0.05)' }}>
                  <span style={{ color: 'var(--s-text-muted)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.name}</span>
                  <span style={{ color: d.status === 'OK' ? 'var(--s-green)' : 'var(--s-amber)', fontSize: '0.625rem', flexShrink: 0 }}>{d.status}</span>
                </div>
              )) : <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>{t('common.noData')}</div>}
            </div>

            {/* Bluetooth */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Bluetooth</div>
              {hwReport.bluetooth.available ? (
                hwReport.bluetooth.devices.map((d, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', padding: '2px 0', borderBottom: '1px solid rgba(109,120,255,0.05)' }}>
                    <span style={{ color: 'var(--s-text-muted)' }}>{d.name}</span>
                    <span style={{ color: 'var(--s-green)', fontSize: '0.625rem' }}>{d.status}</span>
                  </div>
                ))
              ) : <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>{t('common.noData')}</div>}
            </div>

            {/* Thermal */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Temperature</div>
              {hwReport.thermal?.available ? (
                hwReport.thermal.sensors.map((s, i) => {
                  const hot = s.tempC > 80;
                  const warm = s.tempC > 60;
                  const color = hot ? 'var(--s-red)' : warm ? 'var(--s-amber)' : 'var(--s-green)';
                  return (
                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem', padding: '3px 0', borderBottom: '1px solid rgba(109,120,255,0.05)' }}>
                      <span style={{ color: 'var(--s-text-muted)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.name}</span>
                      <span style={{ color, fontWeight: 700, fontFamily: 'var(--s-font-mono)', fontSize: '0.8125rem', flexShrink: 0 }}>
                        {s.tempC}°C
                      </span>
                      {s.critical && s.critical > 0 && (
                        <span style={{ fontSize: '0.5625rem', color: 'var(--s-text-dim)', marginLeft: 4, flexShrink: 0 }}>
                          / {s.critical}°C max
                        </span>
                      )}
                    </div>
                  );
                })
              ) : <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>Requires admin privileges or WMI thermal zone support</div>}
            </div>

            {/* Display */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Display</div>
              {hwReport.display?.monitors?.length > 0 ? hwReport.display.monitors.map((m, i) => (
                <div key={i} style={{ marginBottom: 6 }}>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#e2e8f0' }}>{m.name}</div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)' }}>
                    {m.resolution} @ {m.refreshRate}Hz · {m.connection}
                  </div>
                </div>
              )) : <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>No monitor data available</div>}
            </div>

            {/* USB Devices */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
                USB ({hwReport.usb?.devices?.length || 0} devices)
              </div>
              {hwReport.usb?.devices?.length > 0 ? hwReport.usb.devices.slice(0, 8).map((u, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6875rem', padding: '2px 0', borderBottom: '1px solid rgba(109,120,255,0.05)' }}>
                  <span style={{ color: 'var(--s-text-muted)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{u.name}</span>
                  <span style={{ color: 'var(--s-green)', fontSize: '0.5625rem', flexShrink: 0, marginLeft: 6 }}>{u.status}</span>
                </div>
              )) : <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>No USB devices detected</div>}
              {(hwReport.usb?.devices?.length || 0) > 8 && (
                <div style={{ fontSize: '0.5625rem', color: 'var(--s-text-dim)', marginTop: 4 }}>+{hwReport.usb.devices.length - 8} more</div>
              )}
            </div>

            {/* BitLocker */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>BitLocker Encryption</div>
              {hwReport.bitlocker?.volumes?.length > 0 ? (
                <>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: hwReport.bitlocker.enabled ? 'var(--s-green)' : 'var(--s-amber)', marginBottom: 6 }}>
                    {hwReport.bitlocker.enabled ? '✓ Active' : '✕ Not Protected'}
                  </div>
                  {hwReport.bitlocker.volumes.map((v, i) => (
                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6875rem', padding: '2px 0', borderBottom: '1px solid rgba(109,120,255,0.05)' }}>
                      <span style={{ color: 'var(--s-text-muted)' }}>{v.letter}:</span>
                      <span style={{ color: v.status === 'Protected' ? 'var(--s-green)' : 'var(--s-amber)', fontWeight: 600 }}>{v.status}</span>
                      <span style={{ color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)', fontSize: '0.5625rem' }}>{v.method}</span>
                    </div>
                  ))}
                </>
              ) : <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>BitLocker status unavailable (requires admin)</div>}
            </div>
          </div>
        ) : (
          <div className="s-card-spacy" style={{ textAlign: 'center', padding: 24, color: 'var(--s-text-dim)' }}>
            {hwLoading ? 'Hardware wird erkannt...' : 'Aktualisieren klicken, um Hardware zu scannen'}
          </div>
        )}
      </motion.div>

      {/* ─── Quick Actions ─── */}
      <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-amber), var(--s-cyan))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Schnellaktionen</span>
          <div className="s-section-divider" style={{ flex: 1 }} />
        </div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {[
            { id: 'clear-cache', label: 'Standby-Cache leeren', icon: '🧹' },
            { id: 'perf-scan', label: 'Leistungs-Scan', icon: '⚡' },
            { id: 'kernel-scan', label: 'Kernel-Integrit\u00e4t', icon: '\ud83d\udd2c' },
            { id: 'security-overview', label: '\u00dcbersicht Sicherheit', icon: '\ud83d\udee1' },
          ].map((action) => (
            <button
              key={action.id}
              className="s-btn s-btn-ghost"
              disabled={(action.id === 'perf-scan' && perfScanning) || (action.id === 'kernel-scan' && kernelScanning)}
              onClick={async () => {
                const a = api();
                if (action.id === 'clear-cache') {
                  try { const r = await a?.forge?.clearStandbyCache?.(); notify.success(r?.message || `Cache bereinigt${r?.freedMB ? ` (${r.freedMB} MB freigegeben)` : ''}`); } catch (e: any) { notify.error(e?.message || 'Cache-Bereinigung fehlgeschlagen'); }
                  fetchData();
                }
                if (action.id === 'perf-scan') handlePerfScan();
                if (action.id === 'kernel-scan') handleKernelScan();
                if (action.id === 'security-overview') {
                  handleSecurityOverview();
                }
              }}
            >
              <span>{action.icon}</span> {action.label}
            </button>
          ))}
          <button className="s-btn s-btn-primary s-btn-sm" onClick={fetchData} disabled={loading} style={{ marginLeft: 'auto' }}>
            {loading ? '...' : '↻ Refresh'}
          </button>
        </div>
      </motion.div>

      {/* ─── SBOM Integrity & Supply-Chain Verification ─── */}
      <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.32 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-green), var(--s-cyan))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>System- & SENTINEL-Integrität</span>
          <InfoBadge glossaryKey="BSI APP.6" />
          <InfoBadge glossaryKey="LOKAL" />
          <div className="s-section-divider" style={{ flex: 1 }} />
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', marginBottom: 6, lineHeight: 1.6 }}>
          Prüfen Sie npm-Abhängigkeiten und das Python-Backend gegen ein signiertes SBOM-Manifest. Erkennt Supply-Chain-Manipulationen, Dateiänderungen und fehlende Komponenten.
        </div>
        <div style={{ fontSize: '0.675rem', color: 'var(--s-text-dim)', marginBottom: 14, lineHeight: 1.5, padding: '8px 12px', borderRadius: 8, background: 'rgba(109,120,255,0.02)', border: '1px dashed rgba(109,120,255,0.08)' }}>
          <strong style={{ color: 'var(--s-text-muted)' }}>Was ist SBOM?</strong> SBOM (Software Bill of Materials) ist eine vollständige Liste aller Software-Bestandteile Ihrer Installation mit kryptografischen Prüfsummen (SHA-256). Damit kann Sentinel erkennen, ob jemand heimlich Dateien verändert hat — zum Beispiel bei einem Supply-Chain-Angriff, bei dem Angreifer Schadsoftware in ein Update einschleusen. Alle Prüfungen laufen <strong style={{ color: 'var(--s-text-secondary)' }}>100% lokal</strong> auf Ihrem Gerät (DSGVO-konform).
        </div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <button className="s-btn s-btn-ghost" title="Erstellt ein neues SBOM-Manifest mit SHA-256-Hashes aller Sentinel-Dateien. Dient als Referenz für spätere Integritätsprüfungen." onClick={async () => {
            try {
              const r = await api()?.sbom?.generate?.();
              if (r?.success) notify.success(`SBOM erstellt: ${r.fileCount} Dateien gehasht (v${r.version})`);
              else notify.error(r?.error || 'Fehlgeschlagen');
            } catch (e: any) { notify.error(e?.message || 'Error'); }
          }}>
            {'📦'} SBOM erstellen
          </button>
          <button className="s-btn s-btn-primary" title="Vergleicht alle aktuellen Dateien mit dem gespeicherten SBOM-Manifest. Zeigt geänderte oder fehlende Dateien an." onClick={async () => {
            try {
              const r = await api()?.sbom?.verify?.();
              if (r?.valid) notify.success(`Integrität bestätigt: ${r.matched}/${r.totalFiles} Dateien OK`);
              else notify.error(`VERLETZUNG: ${r?.mismatched?.length || 0} geändert, ${r?.missing?.length || 0} fehlend`);
            } catch (e: any) { notify.error(e?.message || 'Error'); }
          }}>
            {'✓'} Integrität prüfen
          </button>
          <button className="s-btn s-btn-ghost" title="Prüft, ob Windows PowerShell Script Block Logging aktiviert ist — wichtig für die Erkennung von versteckten Skript-Angriffen." onClick={async () => {
            try {
              const r = await api()?.sbom?.checkScriptBlockLogging?.();
              if (r?.enabled) notify.success(r.detail);
              else notify.warning(r?.detail || 'Script Block Logging nicht aktiviert');
            } catch (e: any) { notify.error(e?.message || 'Error'); }
          }}>
            Script Block Logging prüfen
          </button>
        </div>
      </motion.div>

      {/* ─── Sentinel Performance Scan ─── */}
      {(perfScanning || perfResult) && (
        <motion.div ref={perfRef} className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
          <div className="s-flex-between" style={{ marginBottom: 12 }}>
            <div className="s-heading-sm">{'⚡ Leistung & Kernel-Tuning'} <span style={{ fontWeight: 400, color: 'var(--s-text-dim)' }}>{'— 25 Pr\u00fcfungen'}</span></div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {perfResult && <span style={{ fontWeight: 700, fontFamily: 'var(--s-font-display)', fontSize: '1.1rem', color: gaugeColor(100 - perfResult.score) }}>{perfResult.score}%</span>}
              {perfResult && <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)' }}>{perfResult.passed}/{perfResult.total} passed</span>}
              <button className="s-btn s-btn-ghost s-btn-sm" onClick={handlePerfScan} disabled={perfScanning}>{perfScanning ? 'Wird gescannt...' : '\u21bb Erneut scannen'}</button>
            </div>
          </div>
          {perfScanning && !perfResult && <div style={{ textAlign: 'center', padding: 20, color: 'var(--s-text-dim)' }}>{'25 Leistungspr\u00fcfungen werden durchgef\u00fchrt (DPC-Latenz, Timer-Aufl\u00f6sung, Core Parking, Speicherkompression...)'}</div>}
          {perfResult?.checks && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 6 }}>
              {perfResult.checks.map((c, i) => (
                <ScanCheckItem key={i} check={c} onNavigate={(p) => navigate(p)} />
              ))}
            </div>
          )}
        </motion.div>
      )}

      {/* ─── Sentinel Kernel Integrity ─── */}
      {(kernelScanning || kernelResult) && (
        <motion.div ref={kernelRef} className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
          <div className="s-flex-between" style={{ marginBottom: 12 }}>
            <div className="s-heading-sm">{'\ud83d\udd2c Kernel- & Firmware-Integrit\u00e4t'} <span style={{ fontWeight: 400, color: 'var(--s-text-dim)' }}>{'— 15 Pr\u00fcfungen'}</span></div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {kernelResult && <span style={{ fontWeight: 700, fontFamily: 'var(--s-font-display)', fontSize: '1.1rem', color: gaugeColor(100 - kernelResult.score) }}>{kernelResult.score}%</span>}
              {kernelResult && <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)' }}>{kernelResult.passed}/{kernelResult.total} passed</span>}
              <button className="s-btn s-btn-ghost s-btn-sm" onClick={handleKernelScan} disabled={kernelScanning}>{kernelScanning ? 'Wird gescannt...' : '\u21bb Erneut scannen'}</button>
            </div>
          </div>
          {kernelScanning && !kernelResult && <div style={{ textAlign: 'center', padding: 20, color: 'var(--s-text-dim)' }}>{'Pr\u00fcfe ELAM, VBS, TPM 2.0, Secure Boot, DSE, Shadow Stack, PatchGuard...'}</div>}
          {kernelResult?.checks && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 6 }}>
              {kernelResult.checks.map((c, i) => (
                <ScanCheckItem key={i} check={c} onNavigate={(p) => navigate(p)} />
              ))}
            </div>
          )}
        </motion.div>
      )}

      {/* ─── Security Overview ─── */}
      {secOverview && (
        <motion.div ref={secRef} className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
          <div className="s-flex-between" style={{ marginBottom: 12 }}>
            <div className="s-heading-sm">🛡 Security Overview</div>
            <button className="s-btn s-btn-ghost s-btn-sm" onClick={handleSecurityOverview}>↻ Refresh</button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 10 }}>
            {Object.entries(secOverview).map(([key, val]) => {
              const v = val as any;
              const isObj = typeof v === 'object' && v !== null;
              const display = isObj ? (v.status || v.value || JSON.stringify(v)) : String(v);
              const isGood = typeof display === 'string' && /enabled|active|running|true|pass|on|yes|protected/i.test(display);
              const isBad = typeof display === 'string' && /disabled|inactive|stopped|false|fail|off|no|vulnerable/i.test(display);
              return (
                <div key={key} className="s-card-compact-spacy" style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{key.replace(/([A-Z])/g, ' $1').replace(/_/g, ' ')}</span>
                  <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: isGood ? 'var(--s-green)' : isBad ? 'var(--s-red)' : 'var(--s-text-secondary)' }}>{display}</span>
                </div>
              );
            })}
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default SystemPage;
