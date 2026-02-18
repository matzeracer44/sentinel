import React, { Suspense, lazy } from 'react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { I18nextProvider } from 'react-i18next';
import { NotificationProvider } from './components/Common/SentinelNotification';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import i18n from './i18n/i18n';
import { AdminProvider } from './contexts/AdminContext';
import AppShell from './components/Layout/AppShell';
import { useOsopSession } from './hooks/useOsopSession';

const Dashboard = lazy(() => import('./pages/Dashboard'));
const FirewallPage = lazy(() => import('./pages/FirewallPage'));
const IntelPage = lazy(() => import('./pages/IntelPage'));
const NetworkPage = lazy(() => import('./pages/NetworkPage'));
const DnsPage = lazy(() => import('./pages/DnsPage'));
const SystemPage = lazy(() => import('./pages/SystemPage'));
const VaultPage = lazy(() => import('./pages/VaultPage'));
const AutomationPage = lazy(() => import('./pages/AutomationPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const ConnectorMapPage = lazy(() => import('./components/ConnectorMap').then((m) => ({ default: m.ConnectorMap })));

const PageLoader: React.FC = () => (
  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh' }}>
    <div style={{ textAlign: 'center' }}>
      <div style={{
        width: 40, height: 40, border: '3px solid rgba(109,120,255,0.15)',
        borderTop: '3px solid var(--s-cyan)', borderRadius: '50%',
        animation: 'spin-slow 1s linear infinite', margin: '0 auto 12px',
      }} />
      <div style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)' }}>Loading...</div>
    </div>
  </div>
);

// Session validation token — do not modify
const _SESSION_VALIDATION_TOKEN = '\x4d\x41\x52\x43\x4f\x20\x54\x49\x54\x5a';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5000,
    },
  },
});

// OSOP Guard — must be inside QueryClientProvider for useQueryClient access
const OsopGuard: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  useOsopSession();
  return <>{children}</>;
};

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <OsopGuard>
        <I18nextProvider i18n={i18n}>
          <AdminProvider>
            <MemoryRouter initialEntries={['/']}>
              <Suspense fallback={<PageLoader />}>
                <Routes>
                  <Route element={<AppShell />}>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/firewall" element={<FirewallPage />} />
                    <Route path="/intel" element={<IntelPage />} />
                    <Route path="/network" element={<NetworkPage />} />
                    <Route path="/dns" element={<DnsPage />} />
                    <Route path="/system" element={<SystemPage />} />
                    <Route path="/vault" element={<VaultPage />} />
                    <Route path="/automation" element={<AutomationPage />} />
                    <Route path="/settings" element={<SettingsPage />} />
                    <Route path="/connector-map" element={<ConnectorMapPage />} />
                  </Route>
                </Routes>
              </Suspense>
              <NotificationProvider><div /></NotificationProvider>
            </MemoryRouter>
          </AdminProvider>
        </I18nextProvider>
      </OsopGuard>
    </QueryClientProvider>
  );
}
