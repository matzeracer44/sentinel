/**
 * SENTINEL — Fix Confirm Dialog
 * Born from a real incident: "Apply Fix" set outbound firewall to BLOCK → no internet, no undo.
 * 
 * This dialog MUST appear before ANY scan fix is applied.
 * It shows: danger level, what changes, what could break, undo instructions.
 * Dangerous fixes require a checkbox confirmation. Forbidden fixes are blocked entirely.
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

export interface FixImpactData {
  dangerLevel: 'safe' | 'caution' | 'dangerous' | 'forbidden';
  whatChanges: string;
  whyNeeded: string;
  whatCouldBreak: string[];
  affectsConnectivity: boolean;
  affectsFirewall: boolean;
  affectsDNS: boolean;
  affectsRegistry: boolean;
  affectsServices: boolean;
  requiresReboot: boolean;
  undoable: boolean;
  undoCommand: string;
  undoDescription: string;
  estimatedTime: string;
}

export interface FixConfirmDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  checkName: string;
  checkId: string;
  impact: FixImpactData | null;
  loading?: boolean;
  loadingImpact?: boolean;
}

const DANGER_CONFIG: Record<string, { color: string; icon: string; label: string; labelDe: string; needsCheckbox: boolean }> = {
  safe: { color: '#00ff88', icon: '🟢', label: 'SAFE', labelDe: 'SICHER', needsCheckbox: false },
  caution: { color: '#ffaa00', icon: '🟡', label: 'CAUTION', labelDe: 'VORSICHT', needsCheckbox: false },
  dangerous: { color: '#ff3366', icon: '🔴', label: 'DANGEROUS', labelDe: 'GEFÄHRLICH', needsCheckbox: true },
  forbidden: { color: '#ff2244', icon: '⛔', label: 'FORBIDDEN', labelDe: 'VERBOTEN', needsCheckbox: false },
};

const FixConfirmDialog: React.FC<FixConfirmDialogProps> = ({
  isOpen, onClose, onConfirm, checkName, checkId, impact, loading, loadingImpact,
}) => {
  const [accepted, setAccepted] = useState(false);

  // Reset checkbox when dialog opens/closes
  useEffect(() => {
    if (isOpen) setAccepted(false);
  }, [isOpen]);

  if (!isOpen) return null;

  const dangerLevel = impact?.dangerLevel || 'caution';
  const config = DANGER_CONFIG[dangerLevel] || DANGER_CONFIG.caution;
  const canConfirm = dangerLevel !== 'forbidden' && (!config.needsCheckbox || accepted) && !loading && !loadingImpact && impact;

  const affectsBadges: { label: string; active: boolean }[] = [
    { label: 'Firewall', active: impact?.affectsFirewall || false },
    { label: 'DNS', active: impact?.affectsDNS || false },
    { label: 'Registry', active: impact?.affectsRegistry || false },
    { label: 'Services', active: impact?.affectsServices || false },
    { label: 'Connectivity', active: impact?.affectsConnectivity || false },
    { label: 'Reboot', active: impact?.requiresReboot || false },
  ].filter(b => b.active);

  return (
    <AnimatePresence>
      <div
        style={{
          position: 'fixed', inset: 0, zIndex: 99999,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(6px)',
        }}
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 10 }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
          onClick={(e) => e.stopPropagation()}
          style={{
            maxWidth: 520, width: '95%', borderRadius: 16,
            background: 'linear-gradient(180deg, rgba(15,18,28,0.98) 0%, rgba(10,12,20,0.99) 100%)',
            border: `1px solid ${config.color}30`,
            boxShadow: `0 0 40px ${config.color}15, 0 20px 60px rgba(0,0,0,0.5)`,
          }}
        >
          {/* Header */}
          <div style={{
            padding: '16px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            borderBottom: `1px solid ${config.color}20`,
          }}>
            <h3 style={{ margin: 0, color: '#e2e8f0', fontSize: '0.9375rem', fontWeight: 600 }}>
              {config.icon} Fix anwenden: {checkName}
            </h3>
            <button
              onClick={onClose}
              style={{
                background: 'transparent', border: 'none', color: 'rgba(255,255,255,0.4)',
                fontSize: '1.1rem', cursor: 'pointer', padding: '4px 8px', borderRadius: 6,
              }}
              onMouseEnter={(e) => { e.currentTarget.style.color = '#fff'; }}
              onMouseLeave={(e) => { e.currentTarget.style.color = 'rgba(255,255,255,0.4)'; }}
            >
              ✕
            </button>
          </div>

          {/* Body */}
          <div style={{
            padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14,
            maxHeight: '60vh', overflowY: 'auto',
          }}>
            {loadingImpact ? (
              <div style={{ textAlign: 'center', padding: 24, color: 'var(--s-text-dim)' }}>
                Analysiere Fix-Auswirkung...
              </div>
            ) : impact ? (
              <>
                {/* Danger Level Badge */}
                <div style={{
                  display: 'inline-flex', alignItems: 'center', gap: 8,
                  padding: '4px 12px', borderRadius: 20, alignSelf: 'flex-start',
                  background: `${config.color}12`, border: `1px solid ${config.color}25`,
                  color: config.color, fontSize: '0.75rem', fontWeight: 700, letterSpacing: '0.05em',
                }}>
                  {config.icon} GEFÄHRLICHKEIT: {config.labelDe}
                </div>

                {/* Affects Badges */}
                {affectsBadges.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {affectsBadges.map(b => (
                      <span key={b.label} style={{
                        fontSize: '0.625rem', padding: '2px 8px', borderRadius: 6,
                        background: 'rgba(255,170,0,0.08)', border: '1px solid rgba(255,170,0,0.2)',
                        color: '#ffaa00', fontWeight: 600, textTransform: 'uppercase',
                      }}>
                        {b.label}
                      </span>
                    ))}
                  </div>
                )}

                {/* What Changes */}
                <InfoSection title="Was wird geändert" color={config.color}>
                  {impact.whatChanges}
                </InfoSection>

                {/* What Could Break */}
                {impact.whatCouldBreak.length > 0 && (
                  <div style={{
                    padding: '10px 14px', borderRadius: 10,
                    background: `${config.color}08`, border: `1px solid ${config.color}18`,
                  }}>
                    <div style={{
                      fontSize: '0.6875rem', fontWeight: 700, color: config.color,
                      textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6,
                    }}>
                      ⚠ Was könnte schiefgehen
                    </div>
                    <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {impact.whatCouldBreak.map((risk, i) => (
                        <li key={i} style={{ fontSize: '0.8125rem', color: '#cbd5e1' }}>
                          • {risk}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Undo Info */}
                {impact.undoDescription && (
                  <div style={{
                    padding: '10px 14px', borderRadius: 10,
                    background: 'rgba(0,200,255,0.05)', border: '1px solid rgba(0,200,255,0.15)',
                  }}>
                    <div style={{
                      fontSize: '0.6875rem', fontWeight: 700, color: '#00c8ff',
                      textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4,
                    }}>
                      ↩ Rückgängig machen
                    </div>
                    <div style={{ fontSize: '0.8125rem', color: '#cbd5e1' }}>
                      {impact.undoDescription}
                    </div>
                    {impact.undoable && (
                      <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', marginTop: 4 }}>
                        ⏱ Undo verfügbar für 24 Stunden nach Anwendung
                      </div>
                    )}
                  </div>
                )}

                {/* Time Estimate */}
                <div style={{ fontSize: '0.75rem', color: 'var(--s-text-dim)' }}>
                  ⏱ Geschätzte Dauer: {impact.estimatedTime || '< 5 Sekunden'}
                  {impact.requiresReboot && (
                    <span style={{ color: '#ffaa00', marginLeft: 8 }}>
                      ⟳ Neustart erforderlich
                    </span>
                  )}
                </div>

                {/* Forbidden Block */}
                {dangerLevel === 'forbidden' && (
                  <div style={{
                    padding: '12px 14px', borderRadius: 10,
                    background: 'rgba(255,34,68,0.1)', border: '1px solid rgba(255,34,68,0.3)',
                  }}>
                    <div style={{ fontSize: '0.875rem', color: '#ff3366', fontWeight: 600 }}>
                      ⛔ Dieser Fix ist zu gefährlich für automatische Ausführung.
                    </div>
                    <div style={{ fontSize: '0.8125rem', color: '#cbd5e1', marginTop: 4 }}>
                      Er könnte dein System unbenutzbar machen. Dieser Fix wurde permanent blockiert.
                    </div>
                  </div>
                )}

                {/* Dangerous Checkbox */}
                {config.needsCheckbox && dangerLevel !== 'forbidden' && (
                  <label style={{
                    display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer',
                    padding: '8px 12px', borderRadius: 8,
                    background: accepted ? 'rgba(255,51,102,0.08)' : 'transparent',
                    border: `1px solid ${accepted ? 'rgba(255,51,102,0.25)' : 'rgba(255,255,255,0.06)'}`,
                    transition: 'all 0.15s',
                  }}>
                    <input
                      type="checkbox"
                      checked={accepted}
                      onChange={(e) => setAccepted(e.target.checked)}
                      style={{ width: 16, height: 16, accentColor: '#ff3366', cursor: 'pointer' }}
                    />
                    <span style={{ fontSize: '0.8125rem', color: '#e2e8f0' }}>
                      Ich verstehe das Risiko und möchte fortfahren
                    </span>
                  </label>
                )}

                {/* Connectivity safety note */}
                {impact.affectsConnectivity && dangerLevel !== 'forbidden' && (
                  <div style={{
                    fontSize: '0.6875rem', color: 'var(--s-text-dim)',
                    padding: '6px 10px', borderRadius: 6,
                    background: 'rgba(0,255,136,0.04)', border: '1px solid rgba(0,255,136,0.1)',
                  }}>
                    🛡️ Sentinel prüft nach dem Fix automatisch die Internet-Verbindung.
                    Falls die Verbindung unterbrochen wird, wird der Fix <strong style={{ color: '#00ff88' }}>sofort automatisch rückgängig</strong> gemacht.
                  </div>
                )}
              </>
            ) : (
              <div style={{ textAlign: 'center', padding: 24, color: '#ff5577' }}>
                Keine Impact-Daten verfügbar für diesen Fix.
              </div>
            )}
          </div>

          {/* Footer */}
          <div style={{
            padding: '12px 20px', borderTop: '1px solid rgba(255,255,255,0.04)',
            display: 'flex', justifyContent: 'flex-end', gap: 10,
          }}>
            <button
              onClick={onClose}
              style={{
                padding: '8px 18px', borderRadius: 8,
                background: 'transparent', border: '1px solid rgba(255,255,255,0.12)',
                color: '#94a3b8', fontSize: '0.8125rem', cursor: 'pointer',
                transition: 'all 0.15s',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.04)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
            >
              ✕ Abbrechen
            </button>
            <button
              disabled={!canConfirm}
              onClick={onConfirm}
              style={{
                padding: '8px 18px', borderRadius: 8,
                background: canConfirm ? `${config.color}cc` : 'rgba(255,255,255,0.04)',
                color: canConfirm ? '#fff' : 'rgba(255,255,255,0.2)',
                fontSize: '0.8125rem', fontWeight: 600,
                border: canConfirm ? `1px solid ${config.color}50` : '1px solid rgba(255,255,255,0.06)',
                cursor: canConfirm ? 'pointer' : 'not-allowed',
                transition: 'all 0.15s',
              }}
            >
              {loading ? '⟳ Wird angewendet...' : dangerLevel === 'forbidden' ? '⛔ Blockiert' : '✓ Fix anwenden'}
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};

/** Small helper for info sections */
const InfoSection: React.FC<{ title: string; color: string; children: React.ReactNode }> = ({ title, color, children }) => (
  <div>
    <div style={{
      fontSize: '0.6875rem', fontWeight: 700, color: 'rgba(255,255,255,0.5)',
      textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4,
    }}>
      {title}
    </div>
    <div style={{ fontSize: '0.8125rem', color: '#cbd5e1' }}>
      {children}
    </div>
  </div>
);

export default FixConfirmDialog;
