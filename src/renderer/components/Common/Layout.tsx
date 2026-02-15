import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { useAdmin } from '../../contexts/AdminContext';
import HealthOverlay from '../Diagnostics/HealthOverlay';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { isAdmin, showLimitedBanner, setShowLimitedBanner } = useAdmin();
  const [diagnosticsOpen, setDiagnosticsOpen] = useState(false);

  const navItems = [
    { path: '/shield', label: 'Shield Command', icon: '🛡️' },
    { path: '/shield?view=network', label: 'Network Monitor', icon: '🌐' },
    { path: '/shield?view=firewall', label: 'Firewall Rules', icon: '🔥' },
    { path: '/map', label: 'Connector Map', icon: '⬡' },
  ];

  return (
    <div className="flex h-screen bg-dark-bg text-gray-100">
      {/* Sidebar */}
      <aside className="w-64 glass border-r border-dark-border flex flex-col">
        {/* Logo */}
        <div className="p-6 border-b border-dark-border">
          <h1 className="text-2xl font-bold text-accent-cyan-DEFAULT">SENTINEL SHIELD</h1>
          <p className="text-xs text-gray-400 mt-1">Network Control Center</p>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-2">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            return (
              <motion.button
                key={item.path}
                onClick={() => navigate(item.path)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-left transition-all ${
                  isActive
                    ? 'bg-accent-cyan-DEFAULT/20 text-accent-cyan-DEFAULT border border-accent-cyan-DEFAULT/30'
                    : 'hover:bg-dark-elevated text-gray-300 hover:text-white'
                }`}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <span className="text-xl">{item.icon}</span>
                <span className="font-medium">{item.label}</span>
              </motion.button>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="p-4 border-t border-dark-border">
          <div className="text-xs text-gray-500">
            <p>Version 1.0.0</p>
            <p className="mt-1">© 2024 Sentinel</p>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto flex flex-col relative">
        {/* Admin Status Header */}
        <div className="glass border-b border-dark-border px-6 py-3 flex items-center justify-between">
          <div>
            <p className="text-xs tracking-[0.4em] text-gray-500">SYSTEM</p>
            <h2 className="text-base font-semibold text-gray-200">Sentinel Operations</h2>
          </div>
          <div className="flex items-center gap-3">
            {/* Admin Status Indicator */}
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full ${
              isAdmin
                ? 'bg-accent-green-DEFAULT/20 border border-accent-green-DEFAULT/30'
                : 'bg-threat-warning/20 border border-threat-warning/30'
            }`}>
              <div className={`w-2 h-2 rounded-full ${
                isAdmin ? 'bg-accent-green-DEFAULT' : 'bg-threat-warning'
              } animate-pulse`} />
              <span className={`text-xs font-semibold ${
                isAdmin ? 'text-accent-green-DEFAULT' : 'text-threat-warning'
              }`}>
                {isAdmin ? `🛡️ ${t('admin.title')}` : `⚠️ ${t('admin.limited')}`}
              </span>
            </div>

            <button
              onClick={() => setDiagnosticsOpen(true)}
              className="px-3 py-1.5 rounded-full text-xs font-semibold border border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/10 transition-colors"
            >
              Diagnostics
            </button>
          </div>
        </div>

        {/* Warning Banner for Limited Mode */}
        <AnimatePresence>
          {showLimitedBanner && !isAdmin && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="bg-threat-warning/10 border-b border-threat-warning/30 px-6 py-3"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">⚠️</span>
                  <div>
                    <p className="text-sm font-bold text-threat-warning">{t('admin.limited')}</p>
                    <p className="text-xs text-gray-400">{t('admin.banner')}</p>
                  </div>
                </div>
                <button
                  onClick={() => setShowLimitedBanner(false)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <span className="text-xl">✕</span>
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Page Content */}
        <div className="flex-1">
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.2 }}
          >
            {children}
          </motion.div>
        </div>
      </main>

      <HealthOverlay open={diagnosticsOpen} onClose={() => setDiagnosticsOpen(false)} />
    </div>
  );
};

export default Layout;
