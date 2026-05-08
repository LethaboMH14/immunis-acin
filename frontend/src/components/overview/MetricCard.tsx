// frontend/src/components/overview/MetricCard.tsx
// Metric card — compact KPI display with trend indicator
// WHY: Four key metrics at a glance. Each must be immediately readable
// with a clear trend direction (getting better or worse?).

import React from 'react';
import { motion } from 'framer-motion';
import { Card } from '../common/Card';

// ─── Types ────────────────────────────────────────────────────────────────────

type MetricIcon = 'threats' | 'antibodies' | 'mesh' | 'pipeline';

interface Trend {
  value: number | string;
  direction: 'up' | 'down' | 'neutral';
  isPositive: boolean;
}

interface MetricCardProps {
  label: string;
  value: number | string;
  subtitle?: string;
  trend?: Trend;
  icon: MetricIcon;
  className?: string;
}

// ─── Icons ────────────────────────────────────────────────────────────────────

const iconMap: Record<MetricIcon, { svg: React.ReactNode; color: string; bg: string }> = {
  threats: {
    svg: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M8 1.5L2 5v4c0 3.5 2.5 6.8 6 7.5 3.5-.7 6-4 6-7.5V5L8 1.5Z" />
        <path d="M8 5.5v3M8 11h.01" strokeLinecap="round" />
      </svg>
    ),
    color: 'text-[var(--color-threat)]',
    bg: 'bg-[var(--color-threat)]/10',
  },
  antibodies: {
    svg: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="8" cy="8" r="5.5" />
        <path d="M5.5 8h5M8 5.5v5" strokeLinecap="round" />
      </svg>
    ),
    color: 'text-[var(--color-immune)]',
    bg: 'bg-[var(--color-immune)]/10',
  },
  mesh: {
    svg: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="8" cy="3" r="1.5" />
        <circle cx="3.5" cy="11.5" r="1.5" />
        <circle cx="12.5" cy="11.5" r="1.5" />
        <path d="M8 4.5v3M6.5 9.5l-2 1.5M9.5 9.5l2 1.5" />
      </svg>
    ),
    color: 'text-[var(--color-mesh,#38BDF8)]',
    bg: 'bg-[#38BDF8]/10',
  },
  pipeline: {
    svg: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="3" cy="8" r="1.5" />
        <circle cx="8" cy="8" r="1.5" />
        <circle cx="13" cy="8" r="1.5" />
        <path d="M4.5 8h2M9.5 8h2" />
      </svg>
    ),
    color: 'text-purple-400',
    bg: 'bg-purple-400/10',
  },
};

// ─── Component ────────────────────────────────────────────────────────────────

export function MetricCard({
  label,
  value,
  subtitle,
  trend,
  icon,
  className = '',
}: MetricCardProps) {
  const iconConfig = iconMap[icon];

  return (
    <Card variant="default" padding="md" hoverable className={className}>
      <div className="flex items-start justify-between">
        {/* Icon */}
        <div
          className={[
            'w-8 h-8 rounded-lg flex items-center justify-center',
            iconConfig.bg,
            iconConfig.color,
          ].join(' ')}
        >
          {iconConfig.svg}
        </div>

        {/* Trend */}
        {trend && (
          <div
            className={[
              'flex items-center gap-0.5 text-[10px] font-medium',
              trend.direction === 'up'
                ? trend.isPositive
                  ? 'text-emerald-400'
                  : 'text-red-400'
                : trend.direction === 'down'
                ? trend.isPositive
                  ? 'text-emerald-400'
                  : 'text-red-400'
                : 'text-[var(--text-muted)]',
            ].join(' ')}
          >
            {trend.direction === 'up' && (
              <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor">
                <path d="M5 2l3.5 4H1.5L5 2Z" />
              </svg>
            )}
            {trend.direction === 'down' && (
              <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor">
                <path d="M5 8L1.5 4h7L5 8Z" />
              </svg>
            )}
            <span>{trend.value}</span>
          </div>
        )}
      </div>

      {/* Value */}
      <div className="mt-3">
        <motion.p
          className="text-2xl font-bold tabular-nums text-[var(--text-primary)]"
          key={String(value)}
          initial={{ opacity: 0.5, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
        >
          {value}
        </motion.p>
      </div>

      {/* Label */}
      <p className="text-xs text-[var(--text-muted)] mt-1">
        {subtitle || label}
      </p>
    </Card>
  );
}

export type { MetricCardProps, MetricIcon, Trend };
export default MetricCard;
