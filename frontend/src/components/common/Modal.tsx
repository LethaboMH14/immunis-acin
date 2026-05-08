// frontend/src/components/common/Modal.tsx
// Modal dialog — portal, focus trap, backdrop blur, animated
// WHY: Threat details, antibody inspection, scan configuration, compliance
// reports, settings confirmation — all need modal overlays. Must trap focus
// for accessibility and animate smoothly for polish.

import React, { useEffect, useRef, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { modalOverlayVariants, modalContentVariants } from '../../utils/animations';

// ─── Types ────────────────────────────────────────────────────────────────────

type ModalSize = 'sm' | 'md' | 'lg' | 'xl' | 'full';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  description?: string;
  footer?: React.ReactNode;
  size?: ModalSize;
  closeOnBackdrop?: boolean;
  closeOnEscape?: boolean;
  showCloseButton?: boolean;
  className?: string;
  children: React.ReactNode;
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const sizeStyles: Record<ModalSize, string> = {
  sm: 'max-w-sm',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
  full: 'max-w-[calc(100vw-2rem)] max-h-[calc(100vh-2rem)]',
};

// ─── Focus Trap ───────────────────────────────────────────────────────────────

function useFocusTrap(isOpen: boolean) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen || !containerRef.current) return;

    const container = containerRef.current;
    const focusableSelector =
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

    const focusableElements = container.querySelectorAll(focusableSelector);
    const firstFocusable = focusableElements[0] as HTMLElement;
    const lastFocusable = focusableElements[focusableElements.length - 1] as HTMLElement;

    // Focus first element
    firstFocusable?.focus();

    const handleTab = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;

      if (e.shiftKey) {
        if (document.activeElement === firstFocusable) {
          e.preventDefault();
          lastFocusable?.focus();
        }
      } else {
        if (document.activeElement === lastFocusable) {
          e.preventDefault();
          firstFocusable?.focus();
        }
      }
    };

    container.addEventListener('keydown', handleTab);
    return () => container.removeEventListener('keydown', handleTab);
  }, [isOpen]);

  return containerRef;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function Modal({
  isOpen,
  onClose,
  title,
  description,
  footer,
  size = 'md',
  closeOnBackdrop = true,
  closeOnEscape = true,
  showCloseButton = true,
  className = '',
  children,
}: ModalProps) {
  const containerRef = useFocusTrap(isOpen);

  // Escape key handler
  useEffect(() => {
    if (!isOpen || !closeOnEscape) return;

    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, closeOnEscape, onClose]);

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
      if (e.target === e.currentTarget && closeOnBackdrop) {
        onClose();
      }
    },
    [closeOnBackdrop, onClose]
  );

  return createPortal(
    <AnimatePresence>
      {isOpen && (
        <motion.div
          variants={modalOverlayVariants}
          initial="hidden"
          animate="visible"
          exit="exit"
          onClick={handleBackdropClick}
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
          aria-modal="true"
          role="dialog"
          aria-labelledby={title ? 'modal-title' : undefined}
          aria-describedby={description ? 'modal-description' : undefined}
        >
          <motion.div
            ref={containerRef}
            variants={modalContentVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            className={[
              'w-full rounded-xl overflow-hidden',
              'bg-[var(--bg-secondary)] border border-[var(--border-primary)]',
              'shadow-[var(--shadow-xl)]',
              sizeStyles[size],
              className,
            ]
              .filter(Boolean)
              .join(' ')}
          >
            {/* Header */}
            {(title || showCloseButton) && (
              <div className="flex items-start justify-between px-6 py-4 border-b border-[var(--border-subtle)]">
                <div>
                  {title && (
                    <h2
                      id="modal-title"
                      className="text-lg font-semibold text-[var(--text-primary)]"
                    >
                      {title}
                    </h2>
                  )}
                  {description && (
                    <p
                      id="modal-description"
                      className="mt-1 text-sm text-[var(--text-muted)]"
                    >
                      {description}
                    </p>
                  )}
                </div>
                {showCloseButton && (
                  <button
                    onClick={onClose}
                    className="p-1 rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)] transition-colors"
                    aria-label="Close modal"
                  >
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                      <path d="M6.28 5.22a.75.75 0 0 0-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 1 0 1.06 1.06L10 11.06l3.72 3.72a.75.75 0 1 0 1.06-1.06L11.06 10l3.72-3.72a.75.75 0 0 0-1.06-1.06L10 8.94 6.28 5.22Z" />
                    </svg>
                  </button>
                )}
              </div>
            )}

            {/* Body */}
            <div className="px-6 py-4 overflow-y-auto max-h-[60vh]">
              {children}
            </div>

            {/* Footer */}
            {footer && (
              <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[var(--border-subtle)]">
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

export type { ModalProps, ModalSize };
export default Modal;
