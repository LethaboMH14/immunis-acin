// frontend/src/components/layout/RightPanel.tsx
// Right panel — contextual sidebar for details and quick actions
// WHY: Some pages benefit from a persistent detail panel alongside the main
// content (e.g., threat list + selected threat details). Unlike SlidePanel,
// this doesn't overlay — it shares horizontal space.

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';

// ─── Types ────────────────────────────────────────────────────────────────────

interface RightPanelProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  width?: number;
  children: React.ReactNode;
  className?: string;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function RightPanel({
  isOpen,
  onClose,
  title,
  width = 320,
  children,
  className = '',
}: RightPanelProps) {
  return (
    <AnimatePresence>
      {isOpen && (
        <motion.aside
          initial={{ width: 0, opacity: 0 }}
          animate={{ width, opacity: 1 }}
          exit={{ width: 0, opacity: 0 }}
          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
          className={[
            'flex flex-col h-full overflow-hidden flex-shrink-0',
            'bg-[var(--bg-secondary)] border-l border-[var(--border-primary)]',
            className,
          ]
            .filter(Boolean)
            .join(' ')}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)] flex-shrink-0">
            {title && (
              <h3 className="text-sm font-semibold text-[var(--text-primary)]">
                {title}
              </h3>
            )}
            <button
              onClick={onClose}
              className="p-1 rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)] transition-colors ml-auto"
              aria-label="Close panel"
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                <path d="M4.28 3.22a.75.75 0 0 0-1.06 1.06L6.94 8l-3.72 3.72a.75.75 0 1 0 1.06 1.06L8 9.06l3.72 3.72a.75.75 0 1 0 1.06-1.06L9.06 8l3.72-3.72a.75.75 0 0 0-1.06-1.06L8 6.94 4.28 3.22Z" />
              </svg>
            </button>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-4">
            {children}
          </div>
        </motion.aside>
      )}
    </AnimatePresence>
  );
}

export type { RightPanelProps };
export default RightPanel;
