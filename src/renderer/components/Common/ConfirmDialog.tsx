/**
 * SENTINEL — ConfirmDialog Component
 * Non-blocking modal replacement for native confirm()/alert().
 * Renders a themed overlay with cancel/confirm actions.
 */

import React from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import type { ConfirmDialogState } from '../../hooks/useConfirmDialog';

interface ConfirmDialogProps extends ConfirmDialogState {
  onConfirm: () => void;
  onCancel: () => void;
}

const VARIANT_BORDER: Record<string, string> = {
  danger: 'rgba(255,51,102,0.5)',
  warning: 'rgba(255,170,0,0.5)',
  info: 'rgba(0,240,255,0.5)',
};

const VARIANT_BTN_BG: Record<string, string> = {
  danger: 'linear-gradient(135deg, #ff3366, #cc2952)',
  warning: 'linear-gradient(135deg, #ffaa00, #cc8800)',
  info: 'linear-gradient(135deg, #00f0ff, #00bfcc)',
};

const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open, title, message, confirmLabel, cancelLabel, variant, onConfirm, onCancel,
}) => {
  return (
    <AnimatePresence>
      {open && (
        <motion.div
          style={{
            position: 'fixed', inset: 0, zIndex: 9999,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
        >
          <div
            style={{
              position: 'absolute', inset: 0,
              background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(6px)',
            }}
            onClick={onCancel}
          />
          <motion.div
            style={{
              position: 'relative', width: 420, borderRadius: 16,
              border: `1px solid ${VARIANT_BORDER[variant] || VARIANT_BORDER.danger}`,
              background: 'rgba(10,14,26,0.95)', backdropFilter: 'blur(16px)',
              padding: 24, color: '#e2e8f0',
              boxShadow: `0 0 40px ${VARIANT_BORDER[variant] || VARIANT_BORDER.danger}33`,
            }}
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            transition={{ duration: 0.15 }}
          >
            <div style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: 8 }}>{title}</div>
            <div style={{ fontSize: '0.8125rem', color: '#94a3b8', marginBottom: 24, lineHeight: 1.5 }}>{message}</div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                onClick={onCancel}
                style={{
                  padding: '8px 16px', borderRadius: 8,
                  border: '1px solid rgba(109,120,255,0.15)', background: 'transparent',
                  color: '#94a3b8', fontSize: '0.8125rem', fontWeight: 500, cursor: 'pointer',
                }}
              >
                {cancelLabel}
              </button>
              <button
                onClick={onConfirm}
                style={{
                  padding: '8px 16px', borderRadius: 8, border: 'none',
                  background: VARIANT_BTN_BG[variant] || VARIANT_BTN_BG.danger,
                  color: '#fff', fontSize: '0.8125rem', fontWeight: 600, cursor: 'pointer',
                }}
              >
                {confirmLabel}
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default ConfirmDialog;
