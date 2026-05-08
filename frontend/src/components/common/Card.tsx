// frontend/src/components/common/Card.tsx
// Card container — 3 variants, optional header/footer, hover animation
// WHY: Primary content container across all pages. Metrics, feeds, panels,
// charts — everything lives in a card. Must support glass morphism for
// the cinematic visualization overlay panels.

import React from 'react';
import { motion } from 'framer-motion';
import { cardVariants } from '../../utils/animations';

// ─── Types ────────────────────────────────────────────────────────────────────

type CardVariant = 'default' | 'flat' | 'glass';
type CardPadding = 'none' | 'sm' | 'md' | 'lg';

interface CardProps {
  variant?: CardVariant;
  padding?: CardPadding;
  header?: React.ReactNode;
  title?: string;
  actions?: React.ReactNode;
  footer?: React.ReactNode;
  onClick?: () => void;
  hoverable?: boolean;
  className?: string;
  children: React.ReactNode;
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const variantStyles: Record<CardVariant, string> = {
  default:
    'bg-[var(--bg-secondary)] border border-[var(--border-primary)] shadow-[var(--shadow-md)]',
  flat:
    'bg-[var(--bg-secondary)] border border-[var(--border-subtle)]',
  glass:
    'bg-[var(--glass-bg)] backdrop-blur-[var(--glass-blur)] border border-[var(--glass-border)] shadow-[var(--shadow-lg)]',
};

const paddingStyles: Record<CardPadding, string> = {
  none: '',
  sm: 'p-3',
  md: 'p-4',
  lg: 'p-6',
};

// ─── Component ────────────────────────────────────────────────────────────────

export function Card({
  variant = 'default',
  padding = 'md',
  header,
  title,
  actions,
  footer,
  onClick,
  hoverable = false,
  className = '',
  children,
}: CardProps) {
  const isClickable = !!onClick;
  const shouldHover = hoverable || isClickable;

  const cardContent = (
    <>
      {/* Header */}
      {(header || title || actions) && (
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)]">
          {header ?? (
            <h3 className="text-sm font-semibold text-[var(--text-primary)]">
              {title}
            </h3>
          )}
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}

      {/* Body */}
      <div className={paddingStyles[padding]}>{children}</div>

      {/* Footer */}
      {footer && (
        <div className="px-4 py-3 border-t border-[var(--border-subtle)]">
          {footer}
        </div>
      )}
    </>
  );

  if (shouldHover) {
    return (
      <motion.div
        variants={cardVariants}
        initial="hidden"
        animate="visible"
        whileHover="hover"
        whileTap={isClickable ? 'tap' : undefined}
        onClick={onClick}
        role={isClickable ? 'button' : undefined}
        tabIndex={isClickable ? 0 : undefined}
        onKeyDown={
          isClickable
            ? (e: React.KeyboardEvent) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onClick?.();
                }
              }
            : undefined
        }
        className={[
          'rounded-xl overflow-hidden transition-colors',
          variantStyles[variant],
          isClickable ? 'cursor-pointer' : '',
          className,
        ]
          .filter(Boolean)
          .join(' ')}
      >
        {cardContent}
      </motion.div>
    );
  }

  return (
    <div
      className={[
        'rounded-xl overflow-hidden',
        variantStyles[variant],
        className,
      ]
        .filter(Boolean)
        .join(' ')}
    >
      {cardContent}
    </div>
  );
}

export type { CardProps, CardVariant, CardPadding };
export default Card;
