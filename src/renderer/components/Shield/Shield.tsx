import React, { useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Badge from '../Common/Badge';
import { useAdmin } from '../../contexts/AdminContext';
import NetworkMonitor from './NetworkMonitor';
import FirewallRules from './FirewallRules';
import ThreatTimeline from './ThreatTimeline';
import PolicyComposer from './PolicyComposer';

type ShieldView = 'network' | 'timeline' | 'firewall' | 'policy';

const viewOptions: Array<{ key: ShieldView; label: string; icon: string }> = [
  { key: 'network', label: 'Network Monitor', icon: '🌐' },
  { key: 'timeline', label: 'Threat Timeline', icon: '⚠️' },
  { key: 'firewall', label: 'Firewall Rules', icon: '🔥' },
  { key: 'policy', label: 'Policy Composer', icon: '🧠' },
];

const Shield: React.FC = () => {
  const { isAdmin } = useAdmin();
  const location = useLocation();
  const navigate = useNavigate();
  const [firewallTarget, setFirewallTarget] = useState<{ ip: string; port?: number; process?: string; pid?: number } | null>(null);

  const params = useMemo(() => new URLSearchParams(location.search), [location.search]);
  const activeView: ShieldView = (params.get('view') as ShieldView) || 'network';

  const switchView = (nextView: ShieldView) => {
    const nextParams = new URLSearchParams(params);
    nextParams.set('view', nextView);
    navigate({ pathname: location.pathname, search: nextParams.toString() }, { replace: true });
  };

  return (
    <div className="h-full flex flex-col bg-[#04040a] text-white p-6 space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs tracking-[0.4em] text-gray-500">SENTINEL</p>
          <h1 className="text-3xl font-black tracking-tight">Shield Command Center</h1>
          <p className="text-sm text-gray-500">Real-time network telemetry • Advanced firewall control</p>
        </div>
        <Badge variant={isAdmin ? 'success' : 'warning'}>{isAdmin ? 'Admin' : 'Limited'}</Badge>
      </header>

      <nav className="flex flex-wrap gap-3">
        {viewOptions.map(({ key, label, icon }) => (
          <button
            key={key}
            onClick={() => switchView(key)}
            className={`px-4 py-2 rounded-xl text-sm font-semibold border transition-all flex items-center gap-2 ${
              activeView === key
                ? 'border-cyan-500 text-cyan-200 bg-cyan-500/10 shadow-[0_0_25px_rgba(34,211,238,0.25)]'
                : 'border-gray-800 text-gray-500 hover:text-cyan-200 hover:border-cyan-500/60'
            }`}
          >
            <span>{icon}</span>
            {label}
          </button>
        ))}
      </nav>

      {firewallTarget && (
        <div className="flex items-center justify-between px-4 py-3 border border-cyan-500/40 bg-cyan-500/5 rounded-xl text-xs text-cyan-200">
          <div className="space-y-1">
            <p className="font-semibold text-sm">Selected connection from Network Monitor</p>
            <p className="font-mono text-cyan-100">
              {firewallTarget.ip}
              {typeof firewallTarget.port === 'number' ? `:${firewallTarget.port}` : ''}
            </p>
            <p className="text-gray-400">
              {firewallTarget.process || 'Unknown'} • PID {firewallTarget.pid ?? '—'}
            </p>
          </div>
          <div className="flex gap-2">
            <button
              className="px-3 py-1.5 rounded-lg border border-cyan-400/60 text-cyan-200 text-xs hover:bg-cyan-500/10"
              onClick={() => navigator.clipboard?.writeText(`${firewallTarget.ip}${firewallTarget.port ? `:${firewallTarget.port}` : ''}`)}
            >
              📋 Copy
            </button>
            <button
              className="px-3 py-1.5 rounded-lg border border-gray-700 text-gray-400 text-xs hover:text-gray-200"
              onClick={() => setFirewallTarget(null)}
            >
              Clear
            </button>
          </div>
        </div>
      )}

      <div className="flex-1 min-h-0 overflow-y-auto pr-1">
        {activeView === 'network' && (
          <section
            id="shield-network"
            className="min-h-[420px] rounded-2xl border border-cyan-500/60 shadow-[0_0_40px_rgba(34,211,238,0.18)] overflow-hidden bg-[#05050b]"
          >
            <NetworkMonitor onSelectTarget={(target) => setFirewallTarget(target)} />
          </section>
        )}

        {activeView === 'timeline' && (
          <section
            id="shield-timeline"
            className="min-h-[420px] rounded-2xl border border-red-500/60 shadow-[0_0_40px_rgba(239,68,68,0.18)] overflow-hidden bg-[#05050b]"
          >
            <ThreatTimeline onSelectTarget={(target) => setFirewallTarget(target)} />
          </section>
        )}

        {activeView === 'firewall' && (
          <section
            id="shield-firewall"
            className="min-h-[420px] rounded-2xl border border-orange-500/60 shadow-[0_0_40px_rgba(249,115,22,0.18)] overflow-hidden bg-[#05050b]"
          >
            <FirewallRules
              targetIP={firewallTarget?.ip}
              targetPort={firewallTarget?.port}
              targetPid={firewallTarget?.pid}
              targetProcess={firewallTarget?.process}
              onClearTarget={() => setFirewallTarget(null)}
            />
          </section>
        )}

        {activeView === 'policy' && (
          <section
            id="shield-policy"
            className="min-h-[420px] rounded-2xl border border-emerald-500/60 shadow-[0_0_40px_rgba(16,185,129,0.18)] overflow-hidden bg-[#05050b]"
          >
            <PolicyComposer />
          </section>
        )}
      </div>
    </div>
  );
};

export default Shield;

