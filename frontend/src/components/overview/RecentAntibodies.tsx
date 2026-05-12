// frontend/src/components/overview/RecentAntibodies.tsx
//
// Recent antibodies — compact list of latest synthesised defences.
// Shown on the Overview page so judges see live antibody output
// of the 7-stage AIR pipeline.
//
// Field contract: matches frontend/src/utils/types.ts → Antibody,
// which mirrors backend/models/schemas.py exactly.

import { motion, AnimatePresence } from 'framer-motion';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { EmptyAntibodies } from '../common/EmptyState';
import { formatRelativeTime } from '../../utils/formatters';
import type { Antibody, AntibodyStatus } from '../../utils/types';

interface RecentAntibodiesProps {
  antibodies: Antibody[];
  onAntibodyClick?: (antibody: Antibody) => void;
  className?: string;
}

function getStrengthColor(strength: number): string {
  if (strength >= 0.8) return 'bg-[var(--color-immune)]';
  if (strength >= 0.6) return 'bg-emerald-400';
  if (strength >= 0.4) return 'bg-[var(--color-warning)]';
  return 'bg-[var(--color-threat)]';
}

function getStatusVariant(status: AntibodyStatus | undefined) {
  switch (status) {
    case 'promoted':
    case 'validated':
    case 'broadcast':
      return 'immune' as const;
    case 'testing':
    case 'pending':
      return 'warning' as const;
    case 'failed':
    case 'deprecated':
      return 'threat' as const;
    default:
      return 'neutral' as const;
  }
}

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
              const strength =
                typeof ab.strength_score === 'number' ? ab.strength_score : 0;
              const strengthPct = Math.round(strength * 100);
              const familyLabel =
                ab.attack_family || ab.attack_type || 'Unknown';

              return (
                <motion.div
                  key={ab.antibody_id}
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  onClick={() => onAntibodyClick?.(ab)}
                  className={[
                    'flex items-center gap-4 px-4 py-2.5 border-b border-[var(--border-subtle)] last:border-b-0',
                    onAntibodyClick
                      ? 'cursor-pointer hover:bg-[var(--bg-tertiary)] transition-colors'
                      : '',
                  ].join(' ')}
                >
                  {/* ID */}
                  <span className="w-24 text-xs font-mono text-[var(--text-muted)] truncate">
                    {ab.antibody_id?.slice(0, 12) || 'AB-???'}
                  </span>

                  {/* Family */}
                  <span className="flex-1 text-sm font-medium text-[var(--text-primary)] truncate">
                    {familyLabel}
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
                  <div className="w-16 text-right text-[10px] text-[var(--text-muted)] tabular-nums">
                    {ab.synthesised_at
                      ? formatRelativeTime(ab.synthesised_at)
                      : '—'}
                  </div>
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
