/**
 * SENTINEL UNIFIED — AppShell
 * Main layout grid: Sidebar | TopBar + Content + GlobalBar.
 */

import React from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import GlobalBar from './GlobalBar';

const AppShell: React.FC = () => {
  return (
    <div className="app-shell">
      <Sidebar />
      <TopBar />
      <main className="app-content">
        <Outlet />
      </main>
      <GlobalBar />
    </div>
  );
};

export default AppShell;
