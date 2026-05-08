// frontend/src/components/common/ProgressBar.tsx
// Progress bar + circular progress — determinate, indeterminate, themed
// WHY: Pipeline progress, scan completion, compliance posture, immunity score,
// upload progress — many things need visual progress indication.

import React from 'react';
import { motion } from 'framer-motion';

// ─── Types ────────────────────────────────────────────────────────────────────

type ProgressVariant = 'immune' | 'threat' | 'warning' | 'info' | 'neutral';
type ProgressSize = 'sm' | 'md' | 'lg';

interface ProgressBarProps {
  value?: number; // 0-100, undefined = indeterminate
  variant?: ProgressVariant;
  size?: ProgressSize;
  label?: string;
  showPercent?: boolean;
  className?: string;
}

interface CircularProgressProps {
  value: number; // 0-100
  size?: number; // px
  strokeWidth?: number;
  variant?: ProgressVariant;
  label?: string;
  showValue?: boolean;
  className?: string;
}

// ─── Styles ─────────────────────────────────────────────────────────────────--

const variantColors: Record<ProgressVariant, string> = {
  immune: 'bg-[var(--color-immune)]',
  threat: 'bg-[var(--color-threat)]',
  warning: 'bg-[var(--color-warning)]',
  info: 'bg-blue-400',
  neutral: 'bg-[var(--text-muted)]',
};

const variantStrokeColors: Record<ProgressVariant, string> = {
  immune: 'var(--color-immune)',
  threat: 'var(--color-threat)',
  warning: 'var(--color-warning)',
  info: '#60A5FA',
  neutral: 'var(--text-muted)',
};

const sizeHeights: Record<ProgressSize, string> = {
  sm: 'h-0.5',
  md: 'h-1',
  lg: 'h-2',
};

// ─── Linear Progress Bar ──────────────────────────────────────────────────────

export function ProgressBar({
  value,
  variant = 'immune',
  size = 'md',
  label,
  showPercent = false,
  className = '',
}: ProgressBarProps) {
  const isIndeterminate = value === undefined;
  const clampedValue = value !== undefined ? Math.max(0, Math.min(100, value)) : 0;

  return (
    <div className={className}>
      {(label || showPercent) && (
        <div className="flex items-center justify-between mb-1.5">
          {label && (
            <span className="text-xs font-medium text-[var(--text-secondary)]">
              {label}
            </span>
          )}
          {showPercent && !isIndeterminate && (
            <span className="text-xs font-mono text-[var(--text-muted)]">
              {Math.round(clampedValue)}%
            </span>
          )}
        </div>
      )}
      <div
        className={[
          'w-full rounded-full overflow-hidden bg-[var(--bg-tertiary)]',
          sizeHeights[size],
        ].join(' ')}
      >
        {isIndeterminate ? (
          <div
            className={[
              'h-full w-1/3 rounded-full animate-[indeterminate_1.5s_ease-in-out_infinite]',
              variantColors[variant],
            ].join(' ')}
          />
        ) : (
          <motion.div
            className={[
              'h-full rounded-full',
              variantColors[variant],
            ].join(' ')}
            initial={{ width: 0 }}
            animate={{ width: `${clampedValue}%` }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
          />
        )}
      </div>
    </div>
  );
}

// ─── Circular Progress ────────────────────────────────────────────────────────

export function CircularProgress({
  value,
  size = 64,
  strokeWidth = 4,
  variant = 'immune',
  label,
  showValue = true,
  className = '',
}: CircularProgressProps) {
  const clampedValue = Math.max(0, Math.min(100, value));
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (clampedValue / 100) * circumference;

  return (
    <div className={`inline-flex flex-col items-center gap-1 ${className}`}>
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          {/* Background circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--bg-tertiary)"
            strokeWidth={strokeWidth}
          />
          {/* Progress circle */}
          <motion.circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={variantStrokeColors[variant]}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1, ease: 'easeOut' }}
          />
        </svg>
        {showValue && (
          <div className="absolute inset-0 flex items-center justify-center">
            <span
              className="font-mono font-semibold text-[var(--text-primary)]"
              style={{ fontSize: size * 0.22 }}
            >
              {Math.round(clampedValue)}
            </span>
          </div>
        )}
      </div>
      {label && (
        <span className="text-xs text-[var(--text-muted)]">{label}</span>
      )}
    </div>
  );
}

export type { ProgressBarProps, CircularProgressProps, ProgressVariant, ProgressSize };
export default ProgressBar;
