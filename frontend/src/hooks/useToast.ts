// frontend/src/hooks/useToast.ts
// Toast notification state management — queue with auto-dismiss
// WHY: Pipeline events, scan results, mesh broadcasts, errors — all need
// non-blocking notifications. Max 5 visible to prevent screen flooding.

import { useState, useCallback, useRef } from 'react';
import { TIMING } from '../utils/constants';

// ─── Types ────────────────────────────────────────────────────────────────────

export type ToastType = 'success' | 'error' | 'warning' | 'info' | 'threat';

export interface Toast {
  id: string;
  type: ToastType;
  title: string;
  message?: string;
  duration: number;
  action?: {
    label: string;
    onClick: () => void;
  };
  createdAt: number;
}

interface ToastOptions {
  type?: ToastType;
  title: string;
  message?: string;
  duration?: number;
  action?: {
    label: string;
    onClick: () => void;
  };
}

interface UseToastReturn {
  toasts: Toast[];
  addToast: (options: ToastOptions) => string;
  removeToast: (id: string) => void;
  clearAll: () => void;
  // Convenience methods
  success: (title: string, message?: string) => string;
  error: (title: string, message?: string) => string;
  warning: (title: string, message?: string) => string;
  info: (title: string, message?: string) => string;
  threat: (title: string, message?: string) => string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const MAX_TOASTS = 5;
let toastCounter = 0;

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useToast(): UseToastReturn {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const removeToast = useCallback((id: string) => {
    // Clear auto-dismiss timer
    const timer = timersRef.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timersRef.current.delete(id);
    }

    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback(
    (options: ToastOptions): string => {
      const id = `toast-${++toastCounter}-${Date.now()}`;
      const duration = options.duration ?? TIMING.TOAST_DURATION;

      const toast: Toast = {
        id,
        type: options.type ?? 'info',
        title: options.title,
        message: options.message,
        duration,
        action: options.action,
        createdAt: Date.now(),
      };

      setToasts((prev) => {
        // Remove oldest if at capacity
        const updated = prev.length >= MAX_TOASTS ? prev.slice(1) : prev;
        return [...updated, toast];
      });

      // Auto-dismiss after duration (0 = persistent)
      if (duration > 0) {
        const timer = setTimeout(() => {
          removeToast(id);
        }, duration);
        timersRef.current.set(id, timer);
      }

      return id;
    },
    [removeToast]
  );

  const clearAll = useCallback(() => {
    // Clear all timers
    timersRef.current.forEach((timer) => clearTimeout(timer));
    timersRef.current.clear();
    setToasts([]);
  }, []);

  // ─── Convenience Methods ──────────────────────────────────────────────────

  const success = useCallback(
    (title: string, message?: string) =>
      addToast({ type: 'success', title, message }),
    [addToast]
  );

  const error = useCallback(
    (title: string, message?: string) =>
      addToast({ type: 'error', title, message, duration: 8000 }),
    [addToast]
  );

  const warning = useCallback(
    (title: string, message?: string) =>
      addToast({ type: 'warning', title, message }),
    [addToast]
  );

  const info = useCallback(
    (title: string, message?: string) =>
      addToast({ type: 'info', title, message }),
    [addToast]
  );

  const threat = useCallback(
    (title: string, message?: string) =>
      addToast({ type: 'threat', title, message, duration: 10000 }),
    [addToast]
  );

  return {
    toasts,
    addToast,
    removeToast,
    clearAll,
    success,
    error,
    warning,
    info,
    threat,
  };
}

export default useToast;
