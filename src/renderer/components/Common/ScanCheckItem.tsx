/**
 * SENTINEL — ScanCheckItem with Expandable Detail Panel
 * Displays a single security check result. Clicking expands to show:
 * what was checked, what was found, offenders, risk explanation,
 * fix actions, what won't change, and action buttons with inline confirmation.
 * Works for both passed AND failed/warned checks.
 */

import React, { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { notify } from './SentinelNotification';
import FixConfirmDialog, { FixImpactData } from './FixConfirmDialog';

export interface ScanCheckDetail {
  whatChecked: string;
  whatFound: string;
  offenders?: { label: string; detail: string; severity?: string }[];
  riskExplanation: string;
  fixActions: string[];
  preserves: string[];
  canUndo: boolean;
  undoPath?: string;
  references?: { label: string; url?: string }[];
}

export interface ScanCheckItemProps {
  name: string;
  status: 'pass' | 'warn' | 'fail';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  summary: string;
  detail?: ScanCheckDetail;
  onFix?: () => Promise<void>;
  onViewDetails?: () => void;
  onWhitelist?: () => void;
  fixInProgress?: boolean;
  compact?: boolean;
  undoAvailable?: boolean;
  onUndo?: () => Promise<void>;
  undoInProgress?: boolean;
}

const SEVERITY_STYLES: Record<string, { text: string; border: string; bg: string }> = {
  LOW: { text: 'var(--s-green)', border: 'rgba(0,255,136,0.3)', bg: 'rgba(0,255,136,0.08)' },
  MEDIUM: { text: 'var(--s-amber)', border: 'rgba(255,170,0,0.3)', bg: 'rgba(255,170,0,0.08)' },
  HIGH: { text: 'var(--s-red)', border: 'rgba(255,51,102,0.3)', bg: 'rgba(255,51,102,0.08)' },
  CRITICAL: { text: '#ff2244', border: 'rgba(255,34,68,0.5)', bg: 'rgba(255,34,68,0.15)' },
};

const STATUS_ICON: Record<string, string> = { pass: '✓', warn: '⚠', fail: '✕' };
const STATUS_COLOR: Record<string, string> = {
  pass: 'var(--s-green)', warn: 'var(--s-amber)', fail: 'var(--s-red)',
};

const ScanCheckItem: React.FC<ScanCheckItemProps> = ({
  name, status, severity, summary, detail,
  onFix, onViewDetails, onWhitelist, fixInProgress, compact,
  undoAvailable, onUndo, undoInProgress,
}) => {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);

  const sevStyle = SEVERITY_STYLES[severity] || SEVERITY_STYLES.LOW;
  const statusIcon = STATUS_ICON[status] || '●';
  const statusColor = STATUS_COLOR[status] || 'var(--s-text-muted)';

  return (
    <div style={{
      borderRadius: 10,
      border: `1px solid ${expanded ? 'rgba(0,240,255,0.2)' : 'rgba(255,255,255,0.04)'}`,
      background: 'rgba(255,255,255,0.015)',
      transition: 'all 0.2s ease',
      ...(expanded ? { boxShadow: '0 0 12px rgba(0,240,255,0.06)' } : {}),
    }}>
      {/* Collapsed header — always visible */}
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: compact ? '6px 10px' : '10px 14px', cursor: 'pointer', background: 'transparent', border: 'none',
          color: 'inherit', textAlign: 'left', transition: 'background 0.15s',
        }}
        onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.02)'; }}
        onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, minWidth: 0 }}>
          <span style={{ color: statusColor, fontSize: '1rem', fontWeight: 700, flexShrink: 0 }}>
            {statusIcon}
          </span>
          <span style={{ fontWeight: 600, fontSize: '0.8125rem', color: '#e2e8f0', whiteSpace: 'nowrap' }}>
            {name}
          </span>
          <span style={{
            fontSize: '0.6875rem', color: 'var(--s-text-dim)',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1,
          }}>
            {summary}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 12, flexShrink: 0 }}>
          <span style={{
            fontSize: '0.625rem', padding: '2px 8px', borderRadius: 20,
            border: `1px solid ${sevStyle.border}`, background: sevStyle.bg, color: sevStyle.text,
            fontWeight: 600, letterSpacing: '0.04em',
          }}>
            {severity}
          </span>
          {onFix && status !== 'pass' && (
            <span style={{
              fontSize: '0.625rem', padding: '2px 8px', borderRadius: 6,
              border: '1px solid rgba(0,240,255,0.25)', background: 'rgba(0,240,255,0.08)',
              color: 'var(--s-cyan)', fontWeight: 600,
            }}>
              Fix
            </span>
          )}
          <span style={{
            color: 'var(--s-text-dim)', fontSize: '0.75rem',
            transition: 'transform 0.2s',
            transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)',
          }}>
            ▾
          </span>
        </div>
      </button>

      {/* Expanded detail panel */}
      <AnimatePresence>
        {expanded && detail && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: 'easeOut' }}
            style={{ overflow: 'hidden' }}
          >
            <div style={{
              padding: '4px 14px 14px', borderTop: '1px solid rgba(255,255,255,0.04)',
              display: 'flex', flexDirection: 'column', gap: 14,
            }}>
              {/* What Was Checked */}
              <DetailSection title={t('scanDetail.whatChecked')} content={detail.whatChecked} />

              {/* What Was Found / Result */}
              <DetailSection
                title={status === 'pass' ? t('scanDetail.result') : t('scanDetail.whatFound')}
                content={detail.whatFound}
              />

              {/* Offenders */}
              {detail.offenders && detail.offenders.length > 0 && (
                <div>
                  <SectionHeading>
                    {status === 'pass' ? t('scanDetail.verifiedItems') : `${t('scanDetail.topOffenders')} (${detail.offenders.length}${detail.offenders.length >= 20 ? '+' : ''})`}
                  </SectionHeading>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 260, overflowY: 'auto' }}>
                    {detail.offenders.map((o, i) => {
                      const sevColor = o.severity === 'HIGH' ? '#f87171' : o.severity === 'MEDIUM' ? '#fbbf24' : '#94a3b8';
                      const sevBg = o.severity === 'HIGH' ? 'rgba(248,113,113,0.08)' : o.severity === 'MEDIUM' ? 'rgba(251,191,36,0.06)' : 'transparent';
                      return (
                        <div
                          key={i}
                          style={{
                            display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: '0.8125rem',
                            padding: '5px 8px', borderRadius: 6,
                            background: sevBg,
                            border: `1px solid ${o.severity === 'HIGH' ? 'rgba(248,113,113,0.15)' : o.severity === 'MEDIUM' ? 'rgba(251,191,36,0.12)' : 'rgba(255,255,255,0.04)'}`,
                          }}
                        >
                          <span style={{ color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)', fontSize: '0.6875rem', marginTop: 2, minWidth: 18, textAlign: 'right' }}>
                            {i + 1}.
                          </span>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ color: '#e2e8f0', fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                              {o.label}
                            </div>
                            {o.detail && (
                              <div style={{ color: 'var(--s-text-dim)', fontSize: '0.7rem', marginTop: 2 }}>
                                {o.detail}
                              </div>
                            )}
                          </div>
                          {o.severity && (
                            <span style={{
                              fontSize: '0.625rem', fontWeight: 600, padding: '1px 6px', borderRadius: 4,
                              color: sevColor, background: `${sevColor}20`, whiteSpace: 'nowrap', marginTop: 1,
                            }}>
                              {o.severity}
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Risk / Why This Matters */}
              <DetailSection
                title={status === 'pass' ? t('scanDetail.whyThisMatters') : t('scanDetail.riskIfUnfixed')}
                content={detail.riskExplanation}
              />

              {/* Fix Actions */}
              {status !== 'pass' && detail.fixActions.length > 0 && (
                <div>
                  <SectionHeading>{t('scanDetail.whatFixWillDo')}</SectionHeading>
                  <ol style={{ display: 'flex', flexDirection: 'column', gap: 3, margin: 0, padding: 0, listStyle: 'none' }}>
                    {detail.fixActions.map((action, i) => (
                      <li key={i} style={{ display: 'flex', gap: 6, fontSize: '0.8125rem', color: '#cbd5e1' }}>
                        <span style={{ color: 'var(--s-cyan)', fontFamily: 'var(--s-font-mono)', fontSize: '0.6875rem', marginTop: 1 }}>
                          {i + 1}.
                        </span>
                        {action}
                      </li>
                    ))}
                  </ol>
                </div>
              )}

              {/* What Won't Change */}
              {status !== 'pass' && detail.preserves.length > 0 && (
                <div>
                  <SectionHeading>{t('scanDetail.whatWontChange')}</SectionHeading>
                  <ul style={{ display: 'flex', flexDirection: 'column', gap: 2, margin: 0, padding: 0, listStyle: 'none' }}>
                    {detail.preserves.map((p, i) => (
                      <li key={i} style={{ fontSize: '0.8125rem', color: 'var(--s-text-dim)' }}>• {p}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Action buttons */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingTop: 6, flexWrap: 'wrap' }}>
                {/* Apply Fix — opens safety confirm dialog via LegacyScanCheckItem */}
                {onFix && status !== 'pass' && (
                  <button
                    onClick={(e) => { e.stopPropagation(); onFix(); }}
                    disabled={fixInProgress}
                    style={{
                      padding: '6px 14px', borderRadius: 8,
                      background: fixInProgress ? 'rgba(0,240,255,0.15)' : 'rgba(0,180,220,0.85)',
                      color: '#fff', fontSize: '0.8125rem', fontWeight: 600,
                      border: 'none', cursor: fixInProgress ? 'wait' : 'pointer',
                      transition: 'background 0.15s',
                    }}
                  >
                    {fixInProgress ? `⟳ ${t('scanDetail.analyzing')}` : `🛡 ${t('scanDetail.applyFix')}`}
                  </button>
                )}
                {/* Undo button — available for 24h after fix was applied */}
                {undoAvailable && onUndo && (
                  <button
                    onClick={(e) => { e.stopPropagation(); onUndo(); }}
                    disabled={undoInProgress}
                    style={{
                      padding: '6px 14px', borderRadius: 8,
                      background: undoInProgress ? 'rgba(255,170,0,0.15)' : 'rgba(255,170,0,0.12)',
                      color: '#ffaa00', fontSize: '0.8125rem', fontWeight: 600,
                      border: '1px solid rgba(255,170,0,0.25)', cursor: undoInProgress ? 'wait' : 'pointer',
                      transition: 'all 0.15s',
                    }}
                  >
                    {undoInProgress ? '⟳ Undo...' : `↩ ${t('scanDetail.undoFix')}`}
                  </button>
                )}
                {onViewDetails && (
                  <button
                    onClick={(e) => { e.stopPropagation(); onViewDetails(); }}
                    style={{
                      padding: '6px 12px', borderRadius: 8,
                      background: 'transparent', border: '1px solid rgba(255,255,255,0.1)',
                      color: '#cbd5e1', fontSize: '0.8125rem', cursor: 'pointer',
                    }}
                  >
                    {t('scanDetail.viewDetails')}
                  </button>
                )}
                {onWhitelist && (
                  <button
                    onClick={(e) => { e.stopPropagation(); onWhitelist(); }}
                    style={{
                      padding: '6px 12px', borderRadius: 8,
                      background: 'transparent', border: '1px solid rgba(255,255,255,0.1)',
                      color: '#cbd5e1', fontSize: '0.8125rem', cursor: 'pointer',
                    }}
                  >
                    {t('scanDetail.whitelist')}
                  </button>
                )}
                {undoAvailable && (
                  <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', marginLeft: 'auto' }}>
                    ⏱ {t('scanDetail.undoAvailable')}
                  </span>
                )}
                {detail.canUndo && detail.undoPath && !undoAvailable && (
                  <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', marginLeft: 'auto' }}>
                    ⟲ {t('scanDetail.undoVia')} {detail.undoPath}
                  </span>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

const SectionHeading: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div style={{
    fontSize: '0.625rem', fontWeight: 700, color: 'var(--s-text-dim)',
    textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4,
  }}>
    {children}
  </div>
);

const DetailSection: React.FC<{ title: string; content: string }> = ({ title, content }) => (
  <div>
    <SectionHeading>{title}</SectionHeading>
    <p style={{ fontSize: '0.8125rem', color: '#cbd5e1', margin: 0, lineHeight: 1.5 }}>{content}</p>
  </div>
);

/**
 * Legacy interface for backward compatibility with existing pages
 * (DnsPage, NetworkPage, SystemPage) that pass { check, onNavigate }.
 */
export interface ScanCheck {
  id?: string;
  name: string;
  status: string;
  detail?: string;
  risk?: string;
  fixChannel?: string;
  viewPath?: string;
  richDetail?: {
    whatChecked: string;
    whatFound: string;
    riskExplanation: string;
    fixActions: string[];
    preserves: string[];
    canUndo: boolean;
    undoPath?: string;
  };
}

interface LegacyProps {
  check: ScanCheck;
  onNavigate?: (path: string) => void;
  onAction?: (checkName: string, action: string) => void;
  compact?: boolean;
}

function mapRiskToSeverity(risk?: string): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (!risk) return 'LOW';
  const r = risk.toLowerCase();
  if (r === 'critical') return 'CRITICAL';
  if (r === 'high') return 'HIGH';
  if (r === 'medium') return 'MEDIUM';
  return 'LOW';
}

function mapStatus(s: string): 'pass' | 'warn' | 'fail' {
  if (s === 'pass') return 'pass';
  if (s === 'fail') return 'fail';
  return 'warn';
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (): any => (window as any).electronAPI;

const LegacyScanCheckItem: React.FC<LegacyProps> = ({ check, onNavigate, compact }) => {
  const [fixing, setFixing] = useState(false);
  const [fixApplied, setFixApplied] = useState(false);
  const [undoAvailable, setUndoAvailable] = useState(false);
  const [undoing, setUndoing] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [impactData, setImpactData] = useState<FixImpactData | null>(null);
  const [loadingImpact, setLoadingImpact] = useState(false);
  const [autoReverted, setAutoReverted] = useState(false);

  const detailData: ScanCheckDetail | undefined = check.richDetail ? {
    whatChecked: check.richDetail.whatChecked,
    whatFound: check.richDetail.whatFound,
    offenders: (check.richDetail as any).offenders,
    riskExplanation: check.richDetail.riskExplanation,
    fixActions: check.richDetail.fixActions,
    preserves: check.richDetail.preserves,
    canUndo: check.richDetail.canUndo,
    undoPath: check.richDetail.undoPath,
  } : undefined;

  // Step 1: User clicks "Apply Fix" → fetch impact assessment → show confirm dialog
  const handleRequestFix = useCallback(async () => {
    if (!check.id) return;
    setLoadingImpact(true);
    setAutoReverted(false);
    try {
      const r = await api()?.shield?.getFixImpact?.(check.id);
      if (r?.success && r.impact) {
        setImpactData(r.impact);
        if (r.forbidden) {
          // Show dialog but it will be blocked
          setImpactData({ ...r.impact, dangerLevel: 'forbidden' as const });
        }
        setShowConfirm(true);
      } else {
        notify.error(r?.error || 'Konnte Fix-Auswirkung nicht laden');
      }
    } catch (e: any) {
      notify.error(e?.message || 'Konnte Fix-Auswirkung nicht laden');
    }
    setLoadingImpact(false);
  }, [check.id]);

  // Step 2: User confirms in dialog → apply fix with full safety
  const handleConfirmFix = useCallback(async () => {
    if (!check.id) return;
    setFixing(true);
    try {
      const r = await api()?.shield?.applyScanFix?.(check.id);
      if (r?.success) {
        notify.success(`Fix angewendet: ${r.label || check.name}`);
        setFixApplied(true);
        setUndoAvailable(Boolean(r.undoAvailable));
        setShowConfirm(false);
      } else if (r?.autoReverted) {
        // Safety system auto-reverted the fix
        setAutoReverted(true);
        setShowConfirm(false);
        notify.warning(r.error || 'Fix wurde automatisch rückgängig gemacht');
      } else if (r?.forbidden) {
        notify.error('Dieser Fix wurde aus Sicherheitsgründen blockiert.');
        setShowConfirm(false);
      } else {
        notify.error(r?.error || `Fix fehlgeschlagen: ${check.name}`);
      }
    } catch (e: any) {
      notify.error(e?.message || 'Fix fehlgeschlagen');
    }
    setFixing(false);
  }, [check.id, check.name]);

  // Step 3: Undo a previously applied fix
  const handleUndo = useCallback(async () => {
    if (!check.id) return;
    setUndoing(true);
    try {
      const r = await api()?.shield?.undoFix?.(check.id);
      if (r?.success) {
        notify.success(`Fix rückgängig gemacht: ${check.name}`);
        setFixApplied(false);
        setUndoAvailable(false);
      } else {
        notify.error(r?.error || 'Undo fehlgeschlagen');
      }
    } catch (e: any) {
      notify.error(e?.message || 'Undo fehlgeschlagen');
    }
    setUndoing(false);
  }, [check.id, check.name]);

  const status = fixApplied ? 'pass' : mapStatus(check.status);

  return (
    <>
      <ScanCheckItem
        name={check.name}
        status={status}
        severity={mapRiskToSeverity(check.risk)}
        summary={
          autoReverted
            ? '🛡️ Fix wurde automatisch rückgängig gemacht (Konnektivität geschützt)'
            : fixApplied
              ? `Fixed: ${check.detail || ''}`
              : (check.detail || '')
        }
        detail={detailData}
        onFix={check.id && check.status !== 'pass' && !fixApplied ? handleRequestFix : undefined}
        fixInProgress={fixing || loadingImpact}
        onViewDetails={check.viewPath && onNavigate ? () => onNavigate(check.viewPath!) : undefined}
        compact={compact}
        undoAvailable={undoAvailable}
        onUndo={undoAvailable ? handleUndo : undefined}
        undoInProgress={undoing}
      />
      <FixConfirmDialog
        isOpen={showConfirm}
        onClose={() => { setShowConfirm(false); setFixing(false); }}
        onConfirm={handleConfirmFix}
        checkName={check.name}
        checkId={check.id || ''}
        impact={impactData}
        loading={fixing}
        loadingImpact={loadingImpact}
      />
    </>
  );
};

export { LegacyScanCheckItem };
export default ScanCheckItem;
