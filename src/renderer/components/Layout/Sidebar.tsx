/**
 * SENTINEL UNIFIED — Sidebar Navigation
 * Premium dark cyber sidebar with cluster-colored icons, active glow, and section grouping.
 */

import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';

interface NavItem {
  path: string;
  label: string;
  icon: string;
  cluster?: string;
  badge?: string | number;
}

interface NavSection {
  titleKey: string;
  items: (NavItem & { labelKey: string })[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    titleKey: 'nav.overview',
    items: [
      { path: '/', label: '', labelKey: 'nav.dashboard', icon: '⬡' },
      { path: '/connector-map', label: '', labelKey: 'nav.connectorMap', icon: '◎' },
    ],
  },
  {
    titleKey: 'nav.security',
    items: [
      { path: '/firewall', label: '', labelKey: 'nav.firewall', icon: '🛡', cluster: 'firewall' },
      { path: '/intel', label: '', labelKey: 'nav.threatIntel', icon: '🔍', cluster: 'intel' },
      { path: '/network', label: '', labelKey: 'nav.networkMonitor', icon: '🌐', cluster: 'network' },
    ],
  },
  {
    titleKey: 'nav.management',
    items: [
      { path: '/dns', label: '', labelKey: 'nav.dnsPrivacy', icon: '🔒', cluster: 'dns' },
      { path: '/system', label: '', labelKey: 'nav.system', icon: '⚙', cluster: 'system' },
      { path: '/vault', label: '', labelKey: 'nav.vault', icon: '🗝', cluster: 'vault' },
    ],
  },
  {
    titleKey: 'nav.tools',
    items: [
      { path: '/automation', label: '', labelKey: 'nav.automation', icon: '⚡', cluster: 'automation' },
      { path: '/settings', label: '', labelKey: 'nav.settings', icon: '☰' },
    ],
  },
];

const CLUSTER_COLORS: Record<string, string> = {
  firewall: 'var(--s-cluster-firewall)',
  intel: 'var(--s-cluster-intel)',
  automation: 'var(--s-cluster-automation)',
  network: 'var(--s-cluster-network)',
  dns: 'var(--s-cluster-dns)',
  system: 'var(--s-cluster-system)',
  vault: 'var(--s-cluster-vault)',
};

const Sidebar: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { t } = useTranslation();

  const isActive = (path: string): boolean => {
    if (path === '/') return location.pathname === '/';
    return location.pathname.startsWith(path);
  };

  return (
    <nav className="app-sidebar">
      {/* ─── Premium Logo ─── */}
      <div style={{ padding: '22px 20px 16px', display: 'flex', alignItems: 'center', gap: 14, position: 'relative', zIndex: 1 }}>
        <motion.div
          animate={{
            boxShadow: [
              '0 0 20px rgba(60, 240, 255, 0.15), 0 0 40px rgba(60, 240, 255, 0.05)',
              '0 0 25px rgba(167, 139, 250, 0.2), 0 0 50px rgba(167, 139, 250, 0.08)',
              '0 0 20px rgba(255, 63, 180, 0.15), 0 0 40px rgba(255, 63, 180, 0.05)',
              '0 0 20px rgba(60, 240, 255, 0.15), 0 0 40px rgba(60, 240, 255, 0.05)',
            ],
          }}
          transition={{ duration: 6, repeat: Infinity, ease: 'easeInOut' }}
          style={{
            width: 40, height: 40, borderRadius: 12,
            background: 'linear-gradient(135deg, rgba(60, 240, 255, 0.15), rgba(167, 139, 250, 0.12), rgba(255, 63, 180, 0.1))',
            border: '1px solid rgba(60, 240, 255, 0.25)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 20, position: 'relative', overflow: 'hidden',
          }}
        >
          <span style={{ position: 'relative', zIndex: 2, filter: 'drop-shadow(0 0 6px rgba(60,240,255,0.6))' }}>◆</span>
          <div style={{
            position: 'absolute', inset: 0,
            background: 'conic-gradient(from 0deg, rgba(60,240,255,0.08), rgba(167,139,250,0.08), rgba(255,63,180,0.08), rgba(60,240,255,0.08))',
            animation: 'spin-slow 8s linear infinite',
          }} />
        </motion.div>
        <div>
          <div style={{
            fontSize: '1.05rem', fontWeight: 700, fontFamily: 'var(--s-font-display)', letterSpacing: '0.04em',
            background: 'linear-gradient(135deg, #f0f1ff, #3cf0ff)',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          }}>
            SENTINEL
          </div>
          <div style={{ fontSize: '0.55rem', color: 'var(--s-text-dim)', letterSpacing: '0.14em', textTransform: 'uppercase', marginTop: 1 }}>
            {t('nav.securitySuite')}
          </div>
        </div>
      </div>

      {/* Gradient divider */}
      <div style={{
        height: 1, margin: '0 20px 8px',
        background: 'linear-gradient(90deg, var(--s-cyan), rgba(167,139,250,0.4), transparent)',
        opacity: 0.3,
      }} />

      {/* ─── Navigation Sections ─── */}
      <div style={{ flex: 1, overflowY: 'auto', paddingBottom: 16, position: 'relative', zIndex: 1 }}>
        {NAV_SECTIONS.map((section) => (
          <div key={section.titleKey}>
            <div className="s-nav-section" style={{
              display: 'flex', alignItems: 'center', gap: 8,
            }}>
              <span>{t(section.titleKey)}</span>
              <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, rgba(109,120,255,0.15), transparent)' }} />
            </div>
            {section.items.map((item) => {
              const active = isActive(item.path);
              const clusterColor = item.cluster ? CLUSTER_COLORS[item.cluster] : 'var(--s-cyan)';

              return (
                <motion.div
                  key={item.path}
                  className={`s-nav-item ${active ? 'active' : ''}`}
                  onClick={() => navigate(item.path)}
                  whileHover={{ x: 3 }}
                  whileTap={{ scale: 0.97 }}
                  style={{
                    ...(active ? {
                      borderLeftColor: clusterColor,
                      color: clusterColor,
                      background: `linear-gradient(90deg, ${clusterColor}14, transparent)`,
                    } : {}),
                  }}
                >
                  <motion.span
                    style={{
                      fontSize: 16, width: 24, textAlign: 'center', display: 'inline-block',
                      filter: active ? `drop-shadow(0 0 8px ${clusterColor})` : undefined,
                    }}
                    animate={active ? { scale: [1, 1.1, 1] } : {}}
                    transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
                  >
                    {item.icon}
                  </motion.span>
                  <span style={{ fontWeight: active ? 600 : 500 }}>{t((item as any).labelKey)}</span>
                  {item.badge !== undefined && (
                    <span className="s-badge s-badge-red" style={{ marginLeft: 'auto', fontSize: '0.6rem' }}>
                      {item.badge}
                    </span>
                  )}
                  {active && (
                    <motion.div
                      layoutId="nav-glow"
                      style={{
                        position: 'absolute', left: 0, top: '50%', transform: 'translateY(-50%)',
                        width: 3, height: '60%', borderRadius: '0 2px 2px 0',
                        background: clusterColor,
                        boxShadow: `0 0 12px ${clusterColor}, 0 0 30px ${clusterColor}44`,
                      }}
                      transition={{ type: 'spring', stiffness: 350, damping: 30 }}
                    />
                  )}
                </motion.div>
              );
            })}
          </div>
        ))}
      </div>

      {/* ─── Premium Footer ─── */}
      <div style={{
        padding: '14px 20px', borderTop: '1px solid rgba(109,120,255,0.12)',
        display: 'flex', alignItems: 'center', gap: 10, position: 'relative', zIndex: 1,
        background: 'linear-gradient(0deg, rgba(60,240,255,0.02), transparent)',
      }}>
        <motion.div
          animate={{ boxShadow: ['0 0 4px rgba(61,255,143,0.4)', '0 0 10px rgba(61,255,143,0.7)', '0 0 4px rgba(61,255,143,0.4)'] }}
          transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
          style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--s-green)', flexShrink: 0 }}
        />
        <span style={{ fontSize: '0.675rem', color: 'var(--s-text-muted)', flex: 1 }}>{t('nav.systemProtected')}</span>
        <span style={{
          fontSize: '0.55rem', padding: '2px 7px', borderRadius: 6,
          background: 'rgba(60,240,255,0.06)', border: '1px solid rgba(60,240,255,0.15)',
          color: 'var(--s-cyan)', fontWeight: 600, letterSpacing: '0.04em',
          fontFamily: 'var(--s-font-mono)',
        }}>
          v5.0
        </span>
      </div>
    </nav>
  );
};

export default Sidebar;
