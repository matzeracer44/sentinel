/**
 * SENTINEL — useConfirmDialog Hook
 * Non-blocking confirmation dialog replacement for native alert()/confirm().
 * Returns a promise-based confirm function and dialog state for rendering.
 */

import { useState, useCallback } from 'react';

export interface ConfirmDialogState {
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel: string;
  variant: 'danger' | 'warning' | 'info';
}

export interface ConfirmOptions {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'danger' | 'warning' | 'info';
}

const INITIAL_STATE: ConfirmDialogState = {
  open: false,
  title: '',
  message: '',
  confirmLabel: 'Confirm',
  cancelLabel: 'Cancel',
  variant: 'danger',
};

export function useConfirmDialog() {
  const [state, setState] = useState<ConfirmDialogState>(INITIAL_STATE);
  const [resolver, setResolver] = useState<((value: boolean) => void) | null>(null);

  const confirm = useCallback((options: ConfirmOptions): Promise<boolean> => {
    return new Promise<boolean>((resolve) => {
      setResolver(() => resolve);
      setState({
        open: true,
        title: options.title,
        message: options.message,
        confirmLabel: options.confirmLabel ?? 'Confirm',
        cancelLabel: options.cancelLabel ?? 'Cancel',
        variant: options.variant ?? 'danger',
      });
    });
  }, []);

  const handleConfirm = useCallback(() => {
    resolver?.(true);
    setResolver(null);
    setState(INITIAL_STATE);
  }, [resolver]);

  const handleCancel = useCallback(() => {
    resolver?.(false);
    setResolver(null);
    setState(INITIAL_STATE);
  }, [resolver]);

  return { dialogState: state, confirm, handleConfirm, handleCancel };
}
