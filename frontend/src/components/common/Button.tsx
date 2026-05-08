// frontend/src/components/common/Button.tsx
// Design-system button — 5 variants, 3 sizes, loading, icon support
// WHY: Every interactive element in the app. Must be consistent, accessible,
// and theme-aware. Framer Motion for micro-interactions.

import React from 'react';
import { motion } from 'framer-motion';
import { hoverLift, tapScale } from '../../utils/animations';

// ─── Types ────────────────────────────────────────────────────────────────────

type ButtonVariant = 'primary' | 'danger' | 'warning' | 'ghost' | 'outline';
type ButtonSize = 'sm' | 'md' | 'lg';

interface ButtonProps extends Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, 'style'> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  isLoading?: boolean;
  iconLeft?: React.ReactNode;
  iconRight?: React.ReactNode;
  fullWidth?: boolean;
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const variantStyles: Record<ButtonVariant, string> = {
  primary:
    'bg-[var(--color-immune)] text-[#0A0E1A] hover:brightness-110 shadow-[0_0_20px_rgba(0,229,160,0.2)]',
  danger:
    'bg-[var(--color-threat)] text-white hover:brightness-110 shadow-[0_0_20px_rgba(255,77,106,0.2)]',
  warning:
    'bg-[var(--color-warning)] text-[#0A0E1A] hover:brightness-110',
  ghost:
    'bg-transparent text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)]',
  outline:
    'bg-transparent text-[var(--text-primary)] border border-[var(--border-primary)] hover:bg-[var(--bg-tertiary)] hover:border-[var(--border-hover)]',
};

const sizeStyles: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-xs gap-1.5 rounded-md',
  md: 'h-10 px-4 text-sm gap-2 rounded-lg',
  lg: 'h-12 px-6 text-base gap-2.5 rounded-lg',
};

// ─── Spinner ──────────────────────────────────────────────────────────────────

function Spinner({ size }: { size: ButtonSize }) {
  const dim = size === 'sm' ? 'w-3 h-3' : size === 'lg' ? 'w-5 h-5' : 'w-4 h-4';
  return (
    <svg
      className={`${dim} animate-spin`}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <circle
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
        className="opacity-25"
      />
      <path
        d="M12 2a10 10 0 0 1 10 10"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
        className="opacity-75"
      />
    </svg>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = 'primary',
      size = 'md',
      isLoading = false,
      iconLeft,
      iconRight,
      fullWidth = false,
      disabled,
      children,
      className = '',
      ...props
    },
    ref
  ) => {
    const isDisabled = disabled || isLoading;

    return (
      <motion.button
        ref={ref}
        whileHover={isDisabled ? undefined : hoverLift}
        whileTap={isDisabled ? undefined : tapScale}
        disabled={isDisabled}
        className={[
          'inline-flex items-center justify-center font-medium transition-all duration-150',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-immune)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg-primary)]',
          'disabled:opacity-50 disabled:cursor-not-allowed disabled:pointer-events-none',
          variantStyles[variant],
          sizeStyles[size],
          fullWidth ? 'w-full' : '',
          className,
        ]
          .filter(Boolean)
          .join(' ')}
        {...(props as React.ComponentPropsWithoutRef<typeof motion.button>)}
      >
        {isLoading ? (
          <Spinner size={size} />
        ) : (
          iconLeft && <span className="flex-shrink-0">{iconLeft}</span>
        )}
        {children && <span>{children}</span>}
        {iconRight && !isLoading && (
          <span className="flex-shrink-0">{iconRight}</span>
        )}
      </motion.button>
    );
  }
);

Button.displayName = 'Button';

export { Button };
export type { ButtonProps, ButtonVariant, ButtonSize };
export default Button;
