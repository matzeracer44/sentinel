import React from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { useHealthReport, type HealthCheckEntry } from '../../hooks/useHealthReport';

const STATUS_THEME: Record<string, { label: string; chip: string; border: string; glow: string }> = {
  pass: {
    label: 'Healthy',
    chip: 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40',
    border: 'border-emerald-500/40',
    glow: 'shadow-[0_0_25px_rgba(52,211,153,0.25)]',
  },
  warn: {
    label: 'Warning',
    chip: 'bg-amber-500/20 text-amber-200 border border-amber-500/40',
    border: 'border-amber-500/40',
    glow: 'shadow-[0_0_25px_rgba(251,191,36,0.25)]',
  },
  fail: {
    label: 'Critical',
    chip: 'bg-rose-500/20 text-rose-200 border border-rose-500/40',
    border: 'border-rose-500/40',
    glow: 'shadow-[0_0_25px_rgba(244,63,94,0.25)]',
  },
};

interface HealthOverlayProps {
  open: boolean;
  onClose: () => void;
}

const HealthOverlay: React.FC<HealthOverlayProps> = ({ open, onClose }) => {
  const { data, isLoading, isError, error, refetch, isRefetching } = useHealthReport();

  const renderEntry = (entry: HealthCheckEntry, idx: number) => {
    const theme = STATUS_THEME[entry.status] ?? STATUS_THEME.warn;
    return (
      <motion.div
        key={`${entry.component}-${idx}`}
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -8 }}
        transition={{ delay: idx * 0.05 }}
        className={`rounded-xl p-4 bg-[#0d101b] border ${theme.border} ${theme.glow}`}
      >
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm uppercase tracking-wide text-gray-400">{entry.component}</p>
            <p className="text-lg font-semibold text-white mt-1">{theme.label}</p>
          </div>
          <span className={`px-3 py-1 rounded-full text-xs font-semibold ${theme.chip}`}>
            {entry.status.toUpperCase()} · {entry.durationMs}ms
          </span>
        </div>
        {entry.details && <p className="text-sm text-gray-400 mt-3">{entry.details}</p>}
        {entry.error && <p className="text-sm text-rose-300 mt-3">{entry.error}</p>}
      </motion.div>
    );
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 20 }}
          transition={{ duration: 0.2 }}
          className="fixed right-6 top-24 z-50 w-[420px] text-white"
        >
          <div className="relative rounded-2xl border border-cyan-500/30 bg-[#05060c]/95 backdrop-blur-lg shadow-[0_25px_80px_rgba(0,0,0,0.55)]">
            <div className="flex items-center justify-between p-4 border-b border-white/5">
              <div>
                <p className="text-xs tracking-[0.3em] text-cyan-400/70">HEALTH</p>
                <h2 className="text-xl font-bold">Pre-Flight Diagnostics</h2>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => refetch({ cancelRefetch: true })}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold border border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/10"
                >
                  {isRefetching ? 'Refreshing…' : 'Refresh'}
                </button>
                <button
                  onClick={onClose}
                  className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/5"
                  aria-label="Close diagnostics overlay"
                >
                  ✕
                </button>
              </div>
            </div>

            <div className="p-4 space-y-4 max-h-[70vh] overflow-y-auto">
              {isLoading && (
                <div className="text-center text-gray-400 text-sm py-8">Running health checks…</div>
              )}

              {isError && (
                <div className="text-center text-rose-300 bg-rose-500/10 border border-rose-500/30 rounded-xl py-4 px-3 text-sm">
                  {(error as Error)?.message ?? 'Failed to load health report'}
                </div>
              )}

              {data && (
                <>
                  <div className="rounded-xl border border-white/10 bg-white/5 p-4 flex items-center justify-between">
                    <div>
                      <p className="text-xs uppercase tracking-[0.3em] text-gray-400">Status</p>
                      <p className="text-3xl font-black mt-1">
                        {data.summary.healthy ? 'READY' : data.summary.failing ? 'FAULT' : 'DEGRADED'}
                      </p>
                      <p className="text-xs text-gray-400 mt-1">
                        Updated {new Date(data.summary.generatedAt).toLocaleTimeString()} ·
                        {data.summary.cached ? ' Cached' : ' Fresh'}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-sm text-gray-400">Checks</p>
                      <p className="text-2xl font-semibold">
                        {Object.keys(data.checks).length - data.summary.failing} / {Object.keys(data.checks).length}
                      </p>
                      <p className="text-xs text-gray-500">
                        {data.summary.failing} failing · {data.summary.warning} warning
                      </p>
                    </div>
                  </div>

                  <div className="space-y-3">
                    {Object.values(data.checks).map((entry, idx) => renderEntry(entry, idx))}
                  </div>
                </>
              )}
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default HealthOverlay;
