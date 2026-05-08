// frontend/src/components/common/Toast.tsx
// Toast notification — icon, progress bar, dismiss, action button
// WHY: Non-blocking feedback for pipeline events, scan results, mesh
// broadcasts, errors. Must be visually distinct by type and auto-dismiss
// with visible countdown.

import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import type { Toast as ToastType, ToastType as ToastVariant } from '../../hooks/useToast';
import { toastVariants } from '../../utils/animations';

// ─── Icons ────────────────────────────────────────────────────────────────────

const icons: Record<ToastVariant, React.ReactNode> = {
  success: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor" className="text-emerald-400">
      <path fillRule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm3.857-9.809a.75.75 0 0 0-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 1 0-1.06 1.061l2.5 2.5a.75.75 0 0 0 1.137-.089l4-5.5Z" clipRule="evenodd" />
    </svg>
  ),
  error: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor" className="text-red-400">
      <path fillRule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16ZM8.28 7.22a.75.75 0 0 0-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 1 0 1.06 1.06L10 11.06l1.72 1.72a.75.75 0 1 0 1.06-1.06L11.06 10l1.72-1.72a.75.75 0 0 0-1.06-1.06L10 8.94 8.28 7.22Z" clipRule="evenodd" />
    </svg>
  ),
  warning: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor" className="text-amber-400">
      <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495ZM10 6a.75.75 0 0 1 .75.75v3.5a.75.75 0 0 1-1.5 0v-3.5A.75.75 0 0 1 10 6Zm0 9a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z" clipRule="evenodd" />
    </svg>
  ),
  info: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor" className="text-blue-400">
      <path fillRule="evenodd" d="M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0Zm-7-4a1 1 0 1 1-2 0 1 1 0 0 1 2 0ZM9 9a.75.75 0 0 0 0 1.5h.253a.25.25 0 0 1 .244.304l-.459 2.066A1.75 1.75 0 0 0 10.747 15H11a.75.75 0 0 0 0-1.5h-.253a.25.25 0 0 1-.244-.304l.459-2.066A1.75 1.75 0 0 0 9.253 9H9Z" clipRule="evenodd" />
    </svg>
  ),
  threat: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor" className="text-red-400">
      <path fillRule="evenodd" d="M10 1a4.5 4.5 0 0 0-4.5 4.5V9H5a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2h-.5V5.5A4.5 4.5 0 0 0 10 1Zm3 8V5.5a3 3 0 1 0-6 0V9h6Z" clipRule="evenodd" />
    </svg>
  ),
};

const borderColors: Record<ToastVariant, string> = {
  success: 'border-l-emerald-400',
  error: 'border-l-red-400',
  warning: 'border-l-amber-400',
  info: 'border-l-blue-400',
  threat: 'border-l-red-500',
};

const progressColors: Record<ToastVariant, string> = {
  success: 'bg-emerald-400',
  error: 'bg-red-400',
  warning: 'bg-amber-400',
  info: 'bg-blue-400',
  threat: 'bg-red-500',
};

// ─── Component ────────────────────────────────────────────────────────────────

interface ToastItemProps {
  toast: ToastType;
  onDismiss: (id: string) => void;
}

export function ToastItem({ toast, onDismiss }: ToastItemProps) {
  const [progress, setProgress] = useState(100);

  // Countdown progress bar
  useEffect(() => {
    if (toast.duration <= 0) return;

    const startTime = toast.createdAt;
    const endTime = startTime + toast.duration;

    const interval = setInterval(() => {
      const now = Date.now();
      const remaining = Math.max(0, endTime - now);
      const pct = (remaining / toast.duration) * 100;
      setProgress(pct);

      if (pct <= 0) {
        clearInterval(interval);
      }
    }, 50);

    return () => clearInterval(interval);
  }, [toast.duration, toast.createdAt]);

  return (
    <motion.div
      layout
      variants={toastVariants}
      initial="hidden"
      animate="visible"
      exit="exit"
      className={[
        'relative w-80 rounded-lg overflow-hidden',
        'bg-[var(--bg-secondary)] border border-[var(--border-primary)] border-l-4',
        borderColors[toast.type],
        'shadow-[var(--shadow-lg)]',
      ].join(' ')}
    >
      <div className="flex items-start gap-3 p-4">
        {/* Icon */}
        <span className="flex-shrink-0 mt-0.5">{icons[toast.type]}</span>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-[var(--text-primary)]">
            {toast.title}
          </p>
          {toast.message && (
            <p className="mt-1 text-xs text-[var(--text-muted)] line-clamp-2">
              {toast.message}
            </p>
          )}
          {toast.action && (
            <button
              onClick={toast.action.onClick}
              className="mt-2 text-xs font-medium text-[var(--color-immune)] hover:underline"
            >
              {toast.action.label}
            </button>
          )}
        </div>

        {/* Dismiss */}
        <button
          onClick={() => onDismiss(toast.id)}
          className="flex-shrink-0 p-0.5 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
          aria-label="Dismiss notification"
        >
          <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor">
            <path d="M4.17 4.17a.75.75 0 0 1 1.06 0L7 5.94l1.77-1.77a.75.75 0 1 1 1.06 1.06L8.06 7l1.77 1.77a.75.75 0 1 1-1.06 1.06L7 8.06l-1.77 1.77a.75.75 0 0 1-1.06-1.06L5.94 7 4.17 5.23a.75.75 0 0 1 0-1.06Z" />
          </svg>
        </button>
      </div>

      {/* Progress bar */}
      {toast.duration > 0 && (
        <div className="h-0.5 bg-[var(--bg-tertiary)]">
          <div
            className={`h-full transition-all duration-100 ease-linear ${progressColors[toast.type]}`}
            style={{ width: `${progress}%` }}
          />
        </div>
      )}
    </motion.div>
  );
}

// ─── Toast Container ──────────────────────────────────────────────────────────

interface ToastContainerProps {
  toasts: ToastType[];
  onDismiss: (id: string) => void;
}

export function ToastContainer({ toasts, onDismiss }: ToastContainerProps) {
  return (
    <div className="fixed top-4 right-4 z-[60] flex flex-col gap-2">
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <ToastItem key={toast.id} toast={toast} onDismiss={onDismiss} />
        ))}
      </AnimatePresence>
    </div>
  );
}

export type { ToastItemProps, ToastContainerProps };
export default ToastContainer;
