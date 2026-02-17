/**
 * SENTINEL — InputModal Component
 * Themed modal replacement for native prompt() and alert() dialogs.
 * Supports input mode (prompt replacement) and alert mode (info/success/error display).
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';

export interface InputModalProps {
  open: boolean;
  title: string;
  message: string;
  /** 'input' = prompt replacement, 'alert' = alert replacement, 'confirm' = yes/no */
  mode?: 'input' | 'alert' | 'confirm';
  /** Placeholder for the input field (input mode only) */
  placeholder?: string;
  /** Initial value for the input field */
  defaultValue?: string;
  /** Input type (text, password, etc.) */
  inputType?: string;
  /** Visual variant */
  variant?: 'info' | 'success' | 'warning' | 'error';
  /** Confirm button label */
  confirmLabel?: string;
  /** Cancel button label */
  cancelLabel?: string;
  /** Whether input is multiline */
  multiline?: boolean;
  /** Called with value on confirm (input mode), or void (alert/confirm) */
  onConfirm: (value?: string) => void;
  /** Called on cancel/close */
  onCancel: () => void;
}

const VARIANT_COLORS: Record<string, { border: string; btn: string; icon: string }> = {
  info: {
    border: 'rgba(60,240,255,0.4)',
    btn: 'linear-gradient(135deg, #00c8ff, #0090cc)',
    icon: '\u24d8',
  },
  success: {
    border: 'rgba(0,230,118,0.4)',
    btn: 'linear-gradient(135deg, #00e676, #00b85c)',
    icon: '\u2713',
  },
  warning: {
    border: 'rgba(255,170,0,0.4)',
    btn: 'linear-gradient(135deg, #ffaa00, #cc8800)',
    icon: '\u26a0',
  },
  error: {
    border: 'rgba(255,51,102,0.4)',
    btn: 'linear-gradient(135deg, #ff3366, #cc2952)',
    icon: '\u26d4',
  },
};

const InputModal: React.FC<InputModalProps> = ({
  open,
  title,
  message,
  mode = 'input',
  placeholder = '',
  defaultValue = '',
  inputType = 'text',
  variant = 'info',
  confirmLabel,
  cancelLabel,
  multiline = false,
  onConfirm,
  onCancel,
}) => {
  const [value, setValue] = useState(defaultValue);
  const inputRef = useRef<HTMLInputElement | HTMLTextAreaElement>(null);
  const colors = VARIANT_COLORS[variant] || VARIANT_COLORS.info;

  useEffect(() => {
    if (open) {
      setValue(defaultValue);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [open, defaultValue]);

  const handleConfirm = useCallback(() => {
    if (mode === 'input') {
      if (value.trim()) onConfirm(value.trim());
    } else {
      onConfirm();
    }
  }, [mode, value, onConfirm]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey && !multiline) {
      e.preventDefault();
      handleConfirm();
    }
    if (e.key === 'Escape') onCancel();
  }, [handleConfirm, onCancel, multiline]);

  const defaultConfirmLabel = mode === 'alert' ? 'OK' : (confirmLabel || 'Best\u00e4tigen');
  const defaultCancelLabel = cancelLabel || 'Abbrechen';

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          style={{
            position: 'fixed', inset: 0, zIndex: 10001,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
        >
          {/* Backdrop */}
          <div
            style={{
              position: 'absolute', inset: 0,
              background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(8px)',
            }}
            onClick={onCancel}
          />
          {/* Modal */}
          <motion.div
            style={{
              position: 'relative',
              width: mode === 'alert' ? 400 : 460,
              maxWidth: '90vw',
              borderRadius: 16,
              border: `1px solid ${colors.border}`,
              background: 'rgba(10,14,26,0.97)',
              backdropFilter: 'blur(20px)',
              padding: '24px 28px',
              color: '#e2e8f0',
              boxShadow: `0 0 40px ${colors.border}33, 0 20px 60px rgba(0,0,0,0.4)`,
            }}
            initial={{ scale: 0.95, opacity: 0, y: 10 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.95, opacity: 0, y: 10 }}
            transition={{ duration: 0.15 }}
            onKeyDown={handleKeyDown}
          >
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <span style={{
                width: 28, height: 28, borderRadius: 8,
                background: colors.border.replace('0.4', '0.15'),
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: '0.9rem', flexShrink: 0,
              }}>{colors.icon}</span>
              <div style={{
                fontSize: '1rem', fontWeight: 700,
                fontFamily: 'var(--s-font-display)',
              }}>{title}</div>
            </div>

            {/* Message */}
            <div style={{
              fontSize: '0.8125rem', color: '#94a3b8', lineHeight: 1.6,
              marginBottom: mode === 'input' ? 16 : 24,
              whiteSpace: 'pre-line',
            }}>
              {message}
            </div>

            {/* Input field (input mode only) */}
            {mode === 'input' && (
              multiline ? (
                <textarea
                  ref={inputRef as React.RefObject<HTMLTextAreaElement>}
                  className="s-input"
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder={placeholder}
                  rows={4}
                  style={{
                    width: '100%', marginBottom: 20,
                    resize: 'vertical', fontFamily: 'var(--s-font-mono)',
                    fontSize: '0.8125rem',
                  }}
                />
              ) : (
                <input
                  ref={inputRef as React.RefObject<HTMLInputElement>}
                  className="s-input"
                  type={inputType}
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder={placeholder}
                  style={{
                    width: '100%', marginBottom: 20,
                    fontSize: '0.8125rem',
                    fontFamily: inputType === 'password' ? 'var(--s-font-mono)' : undefined,
                  }}
                />
              )
            )}

            {/* Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              {mode !== 'alert' && (
                <button
                  onClick={onCancel}
                  style={{
                    padding: '8px 18px', borderRadius: 8,
                    border: '1px solid rgba(109,120,255,0.15)', background: 'transparent',
                    color: '#94a3b8', fontSize: '0.8125rem', fontWeight: 500, cursor: 'pointer',
                    transition: 'all 0.15s',
                  }}
                >
                  {defaultCancelLabel}
                </button>
              )}
              <button
                onClick={handleConfirm}
                disabled={mode === 'input' && !value.trim()}
                style={{
                  padding: '8px 20px', borderRadius: 8, border: 'none',
                  background: mode === 'input' && !value.trim() ? 'rgba(109,120,255,0.2)' : colors.btn,
                  color: '#fff', fontSize: '0.8125rem', fontWeight: 600, cursor: 'pointer',
                  transition: 'all 0.15s',
                  opacity: mode === 'input' && !value.trim() ? 0.5 : 1,
                }}
              >
                {defaultConfirmLabel}
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default InputModal;

/* ─── Hook for easy usage ─── */

interface ModalState {
  open: boolean;
  title: string;
  message: string;
  mode: 'input' | 'alert' | 'confirm';
  placeholder: string;
  defaultValue: string;
  inputType: string;
  variant: 'info' | 'success' | 'warning' | 'error';
  confirmLabel?: string;
  cancelLabel?: string;
  multiline: boolean;
  resolve: ((value: string | null) => void) | null;
}

const initialState: ModalState = {
  open: false, title: '', message: '', mode: 'input',
  placeholder: '', defaultValue: '', inputType: 'text',
  variant: 'info', confirmLabel: undefined, cancelLabel: undefined,
  multiline: false, resolve: null,
};

export function useInputModal() {
  const [state, setState] = useState<ModalState>(initialState);

  const showInput = useCallback((opts: {
    title: string;
    message: string;
    placeholder?: string;
    defaultValue?: string;
    inputType?: string;
    variant?: 'info' | 'success' | 'warning' | 'error';
    confirmLabel?: string;
    multiline?: boolean;
  }): Promise<string | null> => {
    return new Promise((resolve) => {
      setState({
        open: true, mode: 'input',
        title: opts.title,
        message: opts.message,
        placeholder: opts.placeholder || '',
        defaultValue: opts.defaultValue || '',
        inputType: opts.inputType || 'text',
        variant: opts.variant || 'info',
        confirmLabel: opts.confirmLabel,
        cancelLabel: undefined,
        multiline: opts.multiline || false,
        resolve,
      });
    });
  }, []);

  const showAlert = useCallback((opts: {
    title: string;
    message: string;
    variant?: 'info' | 'success' | 'warning' | 'error';
  }): Promise<void> => {
    return new Promise((resolve) => {
      setState({
        open: true, mode: 'alert',
        title: opts.title,
        message: opts.message,
        placeholder: '', defaultValue: '', inputType: 'text',
        variant: opts.variant || 'info',
        confirmLabel: 'OK', cancelLabel: undefined,
        multiline: false,
        resolve: () => resolve(),
      });
    });
  }, []);

  const handleConfirm = useCallback((value?: string) => {
    state.resolve?.(value ?? null);
    setState(initialState);
  }, [state]);

  const handleCancel = useCallback(() => {
    state.resolve?.(null);
    setState(initialState);
  }, [state]);

  const modalProps: InputModalProps = {
    open: state.open,
    title: state.title,
    message: state.message,
    mode: state.mode,
    placeholder: state.placeholder,
    defaultValue: state.defaultValue,
    inputType: state.inputType,
    variant: state.variant,
    confirmLabel: state.confirmLabel,
    cancelLabel: state.cancelLabel,
    multiline: state.multiline,
    onConfirm: handleConfirm,
    onCancel: handleCancel,
  };

  return { showInput, showAlert, modalProps, InputModal };
}
