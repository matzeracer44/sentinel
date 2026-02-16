/**
 * SENTINEL UNIFIED — AppShell
 * Main layout grid: Sidebar | TopBar + Content + GlobalBar.
 */

import React from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import GlobalBar from './GlobalBar';
import LiveAuditLog from '../Common/LiveAuditLog';

const AppShell: React.FC = () => {
  return (
    <div className="app-shell">
      <Sidebar />
      <TopBar />
      <main className="app-content" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ flex: 1, overflowY: 'auto', padding: 'inherit' }}>
          <Outlet />
        </div>
        {/* Global Live Audit Log — visible on every page, single header */}
        <div style={{ borderTop: '1px solid rgba(0,240,255,0.08)', flexShrink: 0 }}>
          <LiveAuditLog maxHeight={220} compact collapsible />
        </div>
      </main>
      <GlobalBar />
    </div>
  );
};

export default AppShell;
