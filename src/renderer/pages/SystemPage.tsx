/**
 * SENTINEL UNIFIED — System Page
 * CPU, RAM, Disk stats with live gauges, health report, startup items, services, quick actions.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { notify } from '../components/Common/SentinelNotification';
import { LegacyScanCheckItem as ScanCheckItem } from '../components/Common/ScanCheckItem';

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

const GaugeRing: React.FC<{ value: number; label: string; color: string; size?: number }> = ({ value, label, color, size = 100 }) => {
  const r = (size - 12) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (value / 100) * circ;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <svg width={size} height={size} style={{ filter: `drop-shadow(0 0 8px ${color}44)` }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(109,120,255,0.1)" strokeWidth="6" />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke={color} strokeWidth="6" strokeLinecap="round"
          strokeDasharray={`${circ}`} strokeDashoffset={offset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: 'stroke-dashoffset 0.8s ease-out' }}
        />
        <text x={size / 2} y={size / 2 - 4} textAnchor="middle" fill={color} fontSize="1.25rem" fontWeight="700" fontFamily="var(--s-font-display)">
          {value}%
        </text>
        <text x={size / 2} y={size / 2 + 14} textAnchor="middle" fill="rgba(160,168,220,0.55)" fontSize="0.55rem" style={{ textTransform: 'uppercase', letterSpacing: '0.08em' }}>
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

  const handlePerfScan = useCallback(async () => {
    setPerfScanning(true);
    try {
      const r = await api()?.shield?.performanceScan?.();
      if (r?.success) {
        setPerfResult(r as ModuleScanResult);
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
      {/* ─── Spacy Live Gauges ─── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
        <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: 20 }}>
          <GaugeRing value={data?.cpu.currentLoad ?? 0} label="CPU" color={gaugeColor(data?.cpu.currentLoad ?? 0)} />
          <div style={{ marginTop: 8, fontSize: '0.75rem', color: 'var(--s-text-muted)', textAlign: 'center' }}>
            {data?.cpu.name || 'Loading...'}
          </div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)' }}>
            {data?.cpu.cores ?? 0} Cores / {data?.cpu.threads ?? 0} Threads
          </div>
        </motion.div>

        <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: 20 }}>
          <GaugeRing value={data?.ram.usagePercent ?? 0} label="RAM" color={gaugeColor(data?.ram.usagePercent ?? 0)} />
          <div style={{ marginTop: 8, fontSize: '0.75rem', color: 'var(--s-text-muted)' }}>
            {data?.ram.usedGB ?? 0} / {data?.ram.totalGB ?? 0} GB
          </div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)' }}>
            {data?.ram.freeGB ?? 0} GB Free
          </div>
        </motion.div>

        {(data?.disks ?? [{ drive: 'C:', totalGB: 0, usedGB: 0, freeGB: 0, usagePercent: 0 }]).map((disk, i) => (
          <motion.div key={disk.drive} className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 + i * 0.05 }} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: 20 }}>
            <GaugeRing value={disk.usagePercent} label={`Disk ${disk.drive}`} color={gaugeColor(disk.usagePercent)} />
            <div style={{ marginTop: 8, fontSize: '0.75rem', color: 'var(--s-text-muted)' }}>
              {disk.usedGB} / {disk.totalGB} GB
            </div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)' }}>
              {disk.freeGB} GB Free
            </div>
          </motion.div>
        ))}

        {health && (
          <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: 20 }}>
            <GaugeRing value={health.score} label="Health" color={gaugeColor(100 - health.score)} />
            <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
              {Object.entries(health.factors).map(([k, v]) => (
                <div key={k} style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: gaugeColor(100 - v) }}>{v}</div>
                  <div style={{ fontSize: '0.55rem', color: 'var(--s-text-dim)', textTransform: 'capitalize' }}>{k}</div>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </div>

      {/* ─── System Info Cards ─── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* OS & System */}
        <motion.div className="s-card-spacy" initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.2 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-cyan), rgba(167,139,250,0.8))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>System Information</span>
            <div className="s-section-divider" style={{ flex: 1 }} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[
              { label: 'Computer', value: data?.system.computerName },
              { label: 'User', value: data?.system.username },
              { label: 'OS', value: data?.os.name },
              { label: 'Version', value: data?.os.version },
              { label: 'Build', value: data?.os.build },
              { label: 'Architecture', value: data?.system.model },
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
            <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-green), var(--s-cyan))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Hardware</span>
            <div className="s-section-divider" style={{ flex: 1 }} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {(data?.gpu ?? []).map((g, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid rgba(109,120,255,0.06)' }}>
                <span style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)' }}>GPU {i + 1}</span>
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
                <span style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)' }}>Battery</span>
                <span style={{ fontSize: '0.8125rem' }}>{data.battery.percentage}% ({data.battery.status})</span>
              </div>
            )}
          </div>
        </motion.div>
      </div>

      {/* ─── Full Hardware Discovery Grid ─── */}
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
        <div className="s-flex-between" style={{ marginBottom: 12 }}>
          <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-cyan), var(--s-purple))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Hardware Discovery</span>
          <button className="s-btn s-btn-ghost s-btn-sm" onClick={fetchHardware} disabled={hwLoading}>
            {hwLoading ? 'Scanning...' : '↻ Refresh'}
          </button>
        </div>
        {hwReport ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            {/* GPU */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>GPU</div>
              {hwReport.gpu.length > 0 ? hwReport.gpu.map((g, i) => (
                <div key={i} style={{ marginBottom: 6 }}>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#e2e8f0' }}>{g.name}</div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)' }}>
                    {g.vramMB > 0 ? `${g.vramMB} MB VRAM` : ''}{g.resolution !== '0x0' ? ` · ${g.resolution}` : ''}{g.refreshRate > 0 ? ` @ ${g.refreshRate}Hz` : ''}
                  </div>
                  <div style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)' }}>Driver: {g.driver || 'N/A'}</div>
                </div>
              )) : <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>No GPU detected</div>}
            </div>

            {/* RAM Slots */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Memory</div>
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
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Storage</div>
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
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Network Adapters</div>
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
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Motherboard</div>
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
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Security Hardware</div>
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
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Battery & Power</div>
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
              ) : <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>No battery detected (desktop)</div>}
            </div>

            {/* Audio */}
            <div className="s-card-spacy" style={{ padding: 14 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Audio</div>
              {hwReport.audio.devices.length > 0 ? hwReport.audio.devices.map((d, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', padding: '2px 0', borderBottom: '1px solid rgba(109,120,255,0.05)' }}>
                  <span style={{ color: 'var(--s-text-muted)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.name}</span>
                  <span style={{ color: d.status === 'OK' ? 'var(--s-green)' : 'var(--s-amber)', fontSize: '0.625rem', flexShrink: 0 }}>{d.status}</span>
                </div>
              )) : <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>No audio devices</div>}
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
              ) : <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>No Bluetooth adapter</div>}
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
            {hwLoading ? 'Discovering hardware...' : 'Click Refresh to scan hardware'}
          </div>
        )}
      </motion.div>

      {/* ─── Quick Actions ─── */}
      <motion.div className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <span style={{ fontWeight: 700, fontSize: '0.85rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-amber), var(--s-cyan))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Quick Actions</span>
          <div className="s-section-divider" style={{ flex: 1 }} />
        </div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {[
            { id: 'clear-cache', label: 'Clear Standby Cache', icon: '🧹' },
            { id: 'perf-scan', label: 'Performance Scan', icon: '⚡' },
            { id: 'kernel-scan', label: 'Kernel Integrity', icon: '�' },
            { id: 'security-overview', label: 'Security Overview', icon: '🛡' },
          ].map((action) => (
            <button
              key={action.id}
              className="s-btn s-btn-ghost"
              disabled={(action.id === 'perf-scan' && perfScanning) || (action.id === 'kernel-scan' && kernelScanning)}
              onClick={async () => {
                const a = api();
                if (action.id === 'clear-cache') {
                  try { const r = await a?.forge?.clearStandbyCache?.(); notify.success(r?.message || `Cache cleared${r?.freedMB ? ` (${r.freedMB} MB freed)` : ''}`); } catch (e: any) { notify.error(e?.message || 'Failed to clear cache'); }
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

      {/* ─── Sentinel Performance Scan ─── */}
      {(perfScanning || perfResult) && (
        <motion.div ref={perfRef} className="s-card-spacy" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
          <div className="s-flex-between" style={{ marginBottom: 12 }}>
            <div className="s-heading-sm">⚡ Performance & Kernel Tuning <span style={{ fontWeight: 400, color: 'var(--s-text-dim)' }}>— 25 checks</span></div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {perfResult && <span style={{ fontWeight: 700, fontFamily: 'var(--s-font-display)', fontSize: '1.1rem', color: gaugeColor(100 - perfResult.score) }}>{perfResult.score}%</span>}
              {perfResult && <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)' }}>{perfResult.passed}/{perfResult.total} passed</span>}
              <button className="s-btn s-btn-ghost s-btn-sm" onClick={handlePerfScan} disabled={perfScanning}>{perfScanning ? 'Scanning...' : '↻ Re-scan'}</button>
            </div>
          </div>
          {perfScanning && !perfResult && <div style={{ textAlign: 'center', padding: 20, color: 'var(--s-text-dim)' }}>Running 25 performance checks (DPC latency, timer resolution, core parking, memory compression...)</div>}
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
            <div className="s-heading-sm">🔬 Kernel & Firmware Integrity <span style={{ fontWeight: 400, color: 'var(--s-text-dim)' }}>— 15 checks</span></div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {kernelResult && <span style={{ fontWeight: 700, fontFamily: 'var(--s-font-display)', fontSize: '1.1rem', color: gaugeColor(100 - kernelResult.score) }}>{kernelResult.score}%</span>}
              {kernelResult && <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)' }}>{kernelResult.passed}/{kernelResult.total} passed</span>}
              <button className="s-btn s-btn-ghost s-btn-sm" onClick={handleKernelScan} disabled={kernelScanning}>{kernelScanning ? 'Scanning...' : '↻ Re-scan'}</button>
            </div>
          </div>
          {kernelScanning && !kernelResult && <div style={{ textAlign: 'center', padding: 20, color: 'var(--s-text-dim)' }}>Checking ELAM, VBS, TPM 2.0, Secure Boot, DSE, Shadow Stack, PatchGuard...</div>}
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
