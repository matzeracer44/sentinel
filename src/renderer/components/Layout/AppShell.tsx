/**
 * SENTINEL UNIFIED — AppShell
 * Main layout grid: Sidebar | TopBar + Content + GlobalBar.
 */

import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import GlobalBar from './GlobalBar';
import LiveAuditLog from '../Common/LiveAuditLog';

const AppShell: React.FC = () => {
  const [auditOpen, setAuditOpen] = useState(true);

  return (
    <div className="app-shell">
      <Sidebar />
      <TopBar />
      <main className="app-content" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ flex: 1, overflowY: 'auto', padding: 'inherit' }}>
          <Outlet />
        </div>
        {/* Global Live Audit Log — visible on every page */}
        <div style={{
          borderTop: '1px solid rgba(0,240,255,0.08)',
          flexShrink: 0,
          transition: 'max-height 0.3s ease',
          maxHeight: auditOpen ? 280 : 32,
          overflow: 'hidden',
        }}>
          <div
            onClick={() => setAuditOpen(!auditOpen)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '4px 14px', cursor: 'pointer',
              background: 'rgba(0,240,255,0.02)',
              userSelect: 'none',
            }}
          >
            <div style={{
              width: 6, height: 6, borderRadius: '50%',
              background: '#00ff88', boxShadow: '0 0 6px #00ff88',
              animation: 'pulse-green 2s ease-in-out infinite',
            }} />
            <span style={{
              fontSize: '0.625rem', fontWeight: 700, color: 'rgba(0,240,255,0.7)',
              letterSpacing: '0.1em', textTransform: 'uppercase',
            }}>
              Live Audit Log
            </span>
            <span style={{
              fontSize: '0.75rem', color: 'var(--s-text-dim)',
              marginLeft: 'auto', transition: 'transform 0.2s',
              transform: auditOpen ? 'rotate(180deg)' : 'rotate(0deg)',
            }}>
              ▾
            </span>
          </div>
          {auditOpen && <LiveAuditLog maxHeight={240} compact />}
        </div>
      </main>
      <GlobalBar />
    </div>
  );
};

export default AppShell;
