// frontend/src/components/common/Toggle.tsx
// Toggle switch — animated knob, accessible, theme-aware
// WHY: Settings page, feature flags, notification preferences, scan toggles.
// Must be keyboard accessible and screen-reader friendly.

import React from 'react';
import { motion } from 'framer-motion';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ToggleProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: string;
  labelPosition?: 'left' | 'right';
  disabled?: boolean;
  size?: 'sm' | 'md';
  className?: string;
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const trackSize = {
  sm: 'w-8 h-[18px]',
  md: 'w-11 h-6',
};

const knobSize = {
  sm: 'w-3.5 h-3.5',
  md: 'w-5 h-5',
};

const knobTranslate = {
  sm: { off: 2, on: 16 },
  md: { off: 2, on: 22 },
};

// ─── Component ────────────────────────────────────────────────────────────────

export function Toggle({
  checked,
  onChange,
  label,
  labelPosition = 'right',
  disabled = false,
  size = 'md',
  className = '',
}: ToggleProps) {
  const handleClick = () => {
    if (!disabled) {
      onChange(!checked);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleClick();
    }
  };

  const track = (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      className={[
        'relative inline-flex items-center rounded-full transition-colors duration-200',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-immune)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg-primary)]',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        trackSize[size],
        checked
          ? 'bg-[var(--color-immune)]'
          : 'bg-[var(--bg-tertiary)] border border-[var(--border-primary)]',
      ]
        .filter(Boolean)
        .join(' ')}
    >
      <motion.span
        className={[
          'block rounded-full shadow-sm',
          knobSize[size],
          checked ? 'bg-[#0A0E1A]' : 'bg-[var(--text-muted)]',
        ].join(' ')}
        animate={{
          x: checked ? knobTranslate[size].on : knobTranslate[size].off,
        }}
        transition={{ type: 'spring', stiffness: 500, damping: 30 }}
      />
    </button>
  );

  if (!label) {
    return <div className={className}>{track}</div>;
  }

  return (
    <div
      className={[
        'inline-flex items-center gap-2.5',
        disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer',
        className,
      ]
        .filter(Boolean)
        .join(' ')}
      onClick={disabled ? undefined : handleClick}
    >
      {labelPosition === 'left' && (
        <span className="text-sm text-[var(--text-secondary)] select-none">
          {label}
        </span>
      )}
      {track}
      {labelPosition === 'right' && (
        <span className="text-sm text-[var(--text-secondary)] select-none">
          {label}
        </span>
      )}
    </div>
  );
}

export type { ToggleProps };
export default Toggle;
