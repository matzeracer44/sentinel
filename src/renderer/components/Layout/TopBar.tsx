/**
 * SENTINEL UNIFIED — TopBar
 * Contextual top bar with page title, search, status indicators, and quick actions.
 */

import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';

const PAGE_TITLES: Record<string, { title: string; subtitle: string }> = {
  '/': { title: 'Dashboard', subtitle: 'System overview & threat summary' },
  '/connector-map': { title: 'Connector Map', subtitle: 'Radial security topology' },
  '/firewall': { title: 'Firewall Engine', subtitle: 'Rules, blocking & policy management' },
  '/intel': { title: 'Threat Intelligence', subtitle: 'ARGUS scanning & Guardian stories' },
  '/network': { title: 'Network Monitor', subtitle: 'Live connections & TLS inspection' },
  '/dns': { title: 'DNS & Privacy', subtitle: 'DNS configuration & hosts management' },
  '/system': { title: 'System', subtitle: 'Performance, services & health' },
  '/vault': { title: 'Vault', subtitle: 'Encryption, notes & secure storage' },
  '/automation': { title: 'Automation', subtitle: 'Quick actions & playbooks' },
  '/settings': { title: 'Settings', subtitle: 'Configuration & preferences' },
};

interface SystemStats {
  cpu: number;
  ram: number;
}

const TopBar: React.FC = () => {
  const location = useLocation();
  const [stats, setStats] = useState<SystemStats>({ cpu: 0, ram: 0 });
  const [isAdmin, setIsAdmin] = useState(false);
  const [time, setTime] = useState(new Date());

  const pageInfo = (() => {
    if (location.pathname === '/') return PAGE_TITLES['/'];
    const match = Object.entries(PAGE_TITLES).find(
      ([path]) => path !== '/' && location.pathname.startsWith(path)
    );
    return match?.[1] ?? { title: 'Sentinel', subtitle: 'Unified Security Suite' };
  })();

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const eApi = (window as any).electronAPI;
        if (eApi?.getSystemStats) {
          const s = await eApi.getSystemStats();
          if (s && typeof s.cpu === 'number') setStats({ cpu: Math.round(s.cpu), ram: Math.round(s.ram) });
        }
        if (eApi?.admin?.checkAdminRights) {
          const r = await eApi.admin.checkAdminRights();
          if (r && typeof r.isAdmin === 'boolean') setIsAdmin(r.isAdmin);
        }
      } catch (e: any) { console.warn('[TopBar] fetchStats:', e?.message); }
    };
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  const cpuColor = stats.cpu > 80 ? 'var(--s-red)' : stats.cpu > 50 ? 'var(--s-amber)' : 'var(--s-green)';
  const ramColor = stats.ram > 80 ? 'var(--s-red)' : stats.ram > 50 ? 'var(--s-amber)' : 'var(--s-green)';

  const MiniArc: React.FC<{ value: number; color: string; size?: number }> = ({ value, color, size = 28 }) => {
    const r = (size - 4) / 2;
    const circ = Math.PI * r;
    return (
      <svg width={size} height={size / 2 + 2} viewBox={`0 0 ${size} ${size / 2 + 2}`} style={{ overflow: 'visible' }}>
        <path
          d={`M 2 ${size / 2} A ${r} ${r} 0 0 1 ${size - 2} ${size / 2}`}
          fill="none" stroke="rgba(109,120,255,0.1)" strokeWidth="3" strokeLinecap="round"
        />
        <path
          d={`M 2 ${size / 2} A ${r} ${r} 0 0 1 ${size - 2} ${size / 2}`}
          fill="none" stroke={color} strokeWidth="3" strokeLinecap="round"
          strokeDasharray={`${(value / 100) * circ} ${circ}`}
          style={{ transition: 'stroke-dasharray 0.8s ease-out', filter: `drop-shadow(0 0 4px ${color})` }}
        />
      </svg>
    );
  };

  return (
    <header className="app-topbar" style={{ position: 'relative' }}>
      {/* Subtle bottom glow line */}
      <div style={{
        position: 'absolute', bottom: 0, left: '10%', right: '10%', height: 1,
        background: 'linear-gradient(90deg, transparent, rgba(60,240,255,0.15), rgba(167,139,250,0.1), transparent)',
      }} />

      {/* Page Title — gradient text */}
      <AnimatePresence mode="wait">
        <motion.div
          key={location.pathname}
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 6 }}
          transition={{ duration: 0.2 }}
          style={{ flex: 1 }}
        >
          <div style={{
            fontSize: '0.9375rem', fontWeight: 700, fontFamily: 'var(--s-font-display)',
            background: 'linear-gradient(135deg, #f0f1ff 30%, var(--s-cyan))',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          }}>
            {pageInfo.title}
          </div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-muted)', marginTop: 2 }}>
            {pageInfo.subtitle}
          </div>
        </motion.div>
      </AnimatePresence>

      {/* Live Stats — glassmorphic pills */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        {[
          { label: 'CPU', value: stats.cpu, color: cpuColor },
          { label: 'RAM', value: stats.ram, color: ramColor },
        ].map((s) => (
          <div key={s.label} style={{
            display: 'flex', alignItems: 'center', gap: 6, padding: '4px 10px 4px 6px',
            borderRadius: 20, background: 'rgba(109,120,255,0.04)', border: '1px solid rgba(109,120,255,0.1)',
          }}>
            <MiniArc value={s.value} color={s.color} />
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', lineHeight: 1 }}>
              <span style={{ fontSize: '0.725rem', color: s.color, fontFamily: 'var(--s-font-mono)', fontWeight: 700 }}>
                {s.value}%
              </span>
              <span style={{ fontSize: '0.5rem', color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                {s.label}
              </span>
            </div>
          </div>
        ))}

        <div style={{ width: 1, height: 24, background: 'linear-gradient(180deg, transparent, var(--s-border), transparent)' }} />

        {/* Admin Badge — premium */}
        <motion.span
          animate={isAdmin ? { boxShadow: ['0 0 0px rgba(61,255,143,0)', '0 0 8px rgba(61,255,143,0.3)', '0 0 0px rgba(61,255,143,0)'] } : {}}
          transition={{ duration: 3, repeat: Infinity }}
          className={`s-badge ${isAdmin ? 's-badge-green' : 's-badge-amber'}`}
          style={{ fontSize: '0.575rem', letterSpacing: '0.06em' }}
        >
          {isAdmin ? '◆ ADMIN' : '◇ LIMITED'}
        </motion.span>

        {/* Clock — mono styled */}
        <div style={{
          fontSize: '0.725rem', fontFamily: 'var(--s-font-mono)', color: 'var(--s-text-secondary)',
          minWidth: 58, textAlign: 'right', fontWeight: 500,
          textShadow: '0 0 12px rgba(60,240,255,0.15)',
        }}>
          {time.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </div>
      </div>
    </header>
  );
};

export default TopBar;
