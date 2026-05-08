// frontend/src/components/overview/RecentAntibodies.tsx
// Recent antibodies — compact list showing latest synthesised defences
// WHY: Demonstrates the output of the pipeline. Judges see antibodies
// appearing with strength scores and promotion status.

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { EmptyAntibodies } from '../common/EmptyState';
import { formatRelativeTime } from '../../utils/formatters';
import type { Antibody } from '../../utils/types';

// ─── Types ────────────────────────────────────────────────────────────────────

interface RecentAntibodiesProps {
  antibodies: Antibody[];
  onAntibodyClick?: (antibody: Antibody) => void;
  className?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getStrengthColor(strength: number): string {
  if (strength >= 0.8) return 'bg-[var(--color-immune)]';
  if (strength >= 0.6) return 'bg-emerald-400';
  if (strength >= 0.4) return 'bg-[var(--color-warning)]';
  return 'bg-[var(--color-threat)]';
}

function getStatusVariant(status: string) {
  switch (status?.toLowerCase()) {
    case 'promoted': return 'immune' as const;
    case 'testing': return 'warning' as const;
    case 'failed': return 'threat' as const;
    default: return 'neutral' as const;
  }
}

// ─── Component ────────────────────────────────────────────────────────────────

export function RecentAntibodies({
  antibodies,
  onAntibodyClick,
  className = '',
}: RecentAntibodiesProps) {
  return (
    <Card
      title="Recent Antibodies"
      actions={
        <span className="text-[10px] text-[var(--text-muted)] tabular-nums">
          {antibodies.length} active
        </span>
      }
      padding="none"
      className={className}
    >
      {antibodies.length === 0 ? (
        <EmptyAntibodies />
      ) : (
        <div className="overflow-x-auto">
          {/* Header */}
          <div className="flex items-center gap-4 px-4 py-2 border-b border-[var(--border-subtle)] text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            <span className="w-24">ID</span>
            <span className="flex-1">Family</span>
            <span className="w-28">Strength</span>
            <span className="w-20 text-center">Status</span>
            <span className="w-16 text-right">Time</span>
          </div>

          {/* Rows */}
          <AnimatePresence initial={false}>
            {antibodies.map((ab) => {
              const strength = typeof ab.strength === 'number' ? ab.strength : 0;
              const strengthPct = Math.round(strength * 100);

              return (
                <motion.div
                  key={ab.id}
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  onClick={() => onAntibodyClick?.(ab)}
                  className={[
                    'flex items-center gap-4 px-4 py-2.5 border-b border-[var(--border-subtle)] last:border-b-0',
                    onAntibodyClick ? 'cursor-pointer hover:bg-[var(--bg-tertiary)] transition-colors' : '',
                  ].join(' ')}
                >
                  {/* ID */}
                  <span className="w-24 text-xs font-mono text-[var(--text-muted)] truncate">
                    {ab.id?.slice(0, 12) || 'AB-???'}
                  </span>

                  {/* Family */}
                  <span className="flex-1 text-sm font-medium text-[var(--text-primary)] truncate">
                    {ab.family || ab.type || 'Unknown'}
                  </span>

                  {/* Strength bar */}
                  <div className="w-28 flex items-center gap-2">
                    <div className="flex-1 h-1.5 rounded-full bg-[var(--bg-tertiary)] overflow-hidden">
                      <motion.div
                        className={`h-full rounded-full ${getStrengthColor(strength)}`}
                        initial={{ width: 0 }}
                        animate={{ width: `${strengthPct}%` }}
                        transition={{ duration: 0.5, ease: 'easeOut' }}
                      />
                    </div>
                    <span className="text-[10px] font-mono text-[var(--text-muted)] w-8 text-right tabular-nums">
                      {strengthPct}%
                    </span>
                  </div>

                  {/* Status */}
                  <div className="w-20 flex justify-center">
                    <Badge variant={getStatusVariant(ab.status)}>
                      {ab.status || 'pending'}
                    </Badge>
                  </div>

                  {/* Time */}
                  <span className="w-16 text-[10px] text-[var(--text-muted)] text-right tabular-nums">
                    {formatRelativeTime(ab.created_at || ab.timestamp)}
                  </span>
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>
      )}
    </Card>
  );
}

export type { RecentAntibodiesProps };
export default RecentAntibodies;
