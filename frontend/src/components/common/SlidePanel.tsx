// frontend/src/components/common/SlidePanel.tsx
// Slide-in panel — right-edge detail view, animated, portal
// WHY: Level 3 navigation. Click a threat → slide panel shows details.
// Click an antibody → slide panel shows verification. Click a mesh node →
// slide panel shows connection info. Non-destructive — main view stays visible.

import React, { useEffect, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';

// ─── Types ────────────────────────────────────────────────────────────────────

type PanelSize = 'sm' | 'md' | 'lg';

interface SlidePanelProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  subtitle?: string;
  size?: PanelSize;
  footer?: React.ReactNode;
  className?: string;
  children: React.ReactNode;
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const sizeStyles: Record<PanelSize, string> = {
  sm: 'w-80',
  md: 'w-[480px]',
  lg: 'w-[640px]',
};

// ─── Animation ────────────────────────────────────────────────────────────────

const backdropVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1 },
  exit: { opacity: 0 },
};

const panelVariants = {
  hidden: { x: '100%' },
  visible: {
    x: 0,
    transition: { type: 'spring', stiffness: 300, damping: 30 },
  },
  exit: {
    x: '100%',
    transition: { type: 'spring', stiffness: 300, damping: 30 },
  },
};

// ─── Component ────────────────────────────────────────────────────────────────

export function SlidePanel({
  isOpen,
  onClose,
  title,
  subtitle,
  size = 'md',
  footer,
  className = '',
  children,
}: SlidePanelProps) {
  // Escape key
  useEffect(() => {
    if (!isOpen) return;

    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, onClose]);

  // Lock body scroll
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  const handleBackdropClick = useCallback(
    (e: React.MouseEvent) => {
      if (e.target === e.currentTarget) onClose();
    },
    [onClose]
  );

  return createPortal(
    <AnimatePresence>
      {isOpen && (
        <motion.div
          variants={backdropVariants}
          initial="hidden"
          animate="visible"
          exit="exit"
          onClick={handleBackdropClick}
          className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm"
        >
          <motion.div
            variants={panelVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            className={[
              'absolute top-0 right-0 h-full flex flex-col',
              'bg-[var(--bg-secondary)] border-l border-[var(--border-primary)]',
              'shadow-[var(--shadow-xl)]',
              sizeStyles[size],
              className,
            ]
              .filter(Boolean)
              .join(' ')}
          >
            {/* Header */}
            <div className="flex items-start justify-between px-6 py-4 border-b border-[var(--border-subtle)] flex-shrink-0">
              <div>
                {title && (
                  <h2 className="text-lg font-semibold text-[var(--text-primary)]">
                    {title}
                  </h2>
                )}
                {subtitle && (
                  <p className="mt-0.5 text-sm text-[var(--text-muted)]">
                    {subtitle}
                  </p>
                )}
              </div>
              <button
                onClick={onClose}
                className="p-1 rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)] transition-colors"
                aria-label="Close panel"
              >
                <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M6.28 5.22a.75.75 0 0 0-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 1 0 1.06 1.06L10 11.06l3.72 3.72a.75.75 0 1 0 1.06-1.06L11.06 10l3.72-3.72a.75.75 0 0 0-1.06-1.06L10 8.94 6.28 5.22Z" />
                </svg>
              </button>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto px-6 py-4">
              {children}
            </div>

            {/* Footer */}
            {footer && (
              <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[var(--border-subtle)] flex-shrink-0">
                {footer}
              </div>
            )}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body
  );
}

export type { SlidePanelProps, PanelSize };
export default SlidePanel;
