// frontend/src/components/common/Badge.tsx
// Semantic badge — severity levels, status indicators, dismissible tags
// WHY: Threats, antibodies, compliance controls, scan findings — everything
// has a severity or status that needs a compact visual indicator.

import React from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

type BadgeVariant =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'info'
  | 'immune'
  | 'threat'
  | 'novel'
  | 'mesh'
  | 'neutral';

interface BadgeProps {
  variant?: BadgeVariant;
  children: React.ReactNode;
  dot?: boolean;
  onDismiss?: () => void;
  className?: string;
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const variantStyles: Record<BadgeVariant, { bg: string; text: string; dot: string }> = {
  critical: {
    bg: 'bg-red-500/15',
    text: 'text-red-400',
    dot: 'bg-red-400',
  },
  high: {
    bg: 'bg-orange-500/15',
    text: 'text-orange-400',
    dot: 'bg-orange-400',
  },
  medium: {
    bg: 'bg-amber-500/15',
    text: 'text-amber-400',
    dot: 'bg-amber-400',
  },
  low: {
    bg: 'bg-blue-500/15',
    text: 'text-blue-400',
    dot: 'bg-blue-400',
  },
  info: {
    bg: 'bg-slate-500/15',
    text: 'text-slate-400',
    dot: 'bg-slate-400',
  },
  immune: {
    bg: 'bg-emerald-500/15',
    text: 'text-emerald-400',
    dot: 'bg-emerald-400',
  },
  threat: {
    bg: 'bg-red-500/15',
    text: 'text-red-400',
    dot: 'bg-red-400',
  },
  novel: {
    bg: 'bg-purple-500/15',
    text: 'text-purple-400',
    dot: 'bg-purple-400',
  },
  mesh: {
    bg: 'bg-cyan-500/15',
    text: 'text-cyan-400',
    dot: 'bg-cyan-400',
  },
  neutral: {
    bg: 'bg-slate-500/10',
    text: 'text-slate-400',
    dot: 'bg-slate-400',
  },
};

// ─── Component ────────────────────────────────────────────────────────────────

export function Badge({
  variant = 'neutral',
  children,
  dot = false,
  onDismiss,
  className = '',
}: BadgeProps) {
  const styles = variantStyles[variant];

  return (
    <span
      className={[
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium',
        styles.bg,
        styles.text,
        className,
      ]
        .filter(Boolean)
        .join(' ')}
    >
      {dot && (
        <span
          className={`w-1.5 h-1.5 rounded-full ${styles.dot} animate-pulse`}
        />
      )}
      {children}
      {onDismiss && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDismiss();
          }}
          className="ml-0.5 hover:opacity-70 transition-opacity"
          aria-label="Dismiss"
        >
          <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
            <path d="M3.17 3.17a.75.75 0 0 1 1.06 0L6 4.94l1.77-1.77a.75.75 0 1 1 1.06 1.06L7.06 6l1.77 1.77a.75.75 0 1 1-1.06 1.06L6 7.06 4.23 8.83a.75.75 0 0 1-1.06-1.06L4.94 6 3.17 4.23a.75.75 0 0 1 0-1.06Z" />
          </svg>
        </button>
      )}
    </span>
  );
}

export type { BadgeProps, BadgeVariant };
export default Badge;
