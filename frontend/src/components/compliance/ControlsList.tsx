// frontend/src/components/compliance/ControlsList.tsx
// Compliance controls — per-control status with evidence
// WHY: Auditors need control-level detail. Each control must show status,
// evidence, and the specific gap if not passing.

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Card } from '../common/Card';
import { ProgressBar } from '../common/ProgressBar';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ControlAssessment {
  id: string;
  name: string;
  description: string;
  status: 'pass' | 'partial' | 'fail' | 'not_assessed';
  score: number;
  evidence?: string;
}

interface ControlsListProps {
  controls: ControlAssessment[];
  className?: string;
}

// ─── Status Icons ─────────────────────────────────────────────────────────────

const statusIcons: Record<string, React.ReactNode> = {
  pass: (
    <div className="w-5 h-5 rounded-full bg-emerald-400/20 flex items-center justify-center">
      <svg width="10" height="10" viewBox="0 0 10 10" fill="none" className="text-emerald-400">
        <path d="M2.5 5l2 2 3.5-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  ),
  partial: (
    <div className="w-5 h-5 rounded-full bg-amber-400/20 flex items-center justify-center">
      <svg width="10" height="10" viewBox="0 0 10 10" fill="none" className="text-amber-400">
        <path d="M3 5h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    </div>
  ),
  fail: (
    <div className="w-5 h-5 rounded-full bg-red-400/20 flex items-center justify-center">
      <svg width="10" height="10" viewBox="0 0 10 10" fill="none" className="text-red-400">
        <path d="M3 3l4 4M7 3l-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    </div>
  ),
  not_assessed: (
    <div className="w-5 h-5 rounded-full bg-slate-400/20 flex items-center justify-center">
      <div className="w-2 h-2 rounded-full bg-slate-400" />
    </div>
  ),
};

const statusVariant: Record<string, 'immune' | 'warning' | 'threat' | 'neutral'> = {
  pass: 'immune',
  partial: 'warning',
  fail: 'threat',
  not_assessed: 'neutral',
};

// ─── Component ────────────────────────────────────────────────────────────────

export function ControlsList({ controls, className = '' }: ControlsListProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  return (
    <Card title="Controls" padding="none" className={className}>
      <div className="divide-y divide-[var(--border-subtle)]">
        {controls.map((control) => {
          const isExpanded = expandedId === control.id;

          return (
            <div key={control.id}>
              <button
                onClick={() => setExpandedId(isExpanded ? null : control.id)}
                className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-[var(--bg-tertiary)] transition-colors"
              >
                {/* Status icon */}
                {statusIcons[control.status]}

                {/* Control ID */}
                <span className="text-[10px] font-mono text-[var(--text-muted)] w-16 flex-shrink-0">
                  {control.id}
                </span>

                {/* Name */}
                <span className="flex-1 text-sm font-medium text-[var(--text-primary)] truncate">
                  {control.name}
                </span>

                {/* Score */}
                <div className="w-20 flex-shrink-0">
                  <ProgressBar
                    value={control.score}
                    variant={statusVariant[control.status]}
                    size="sm"
                  />
                </div>

                {/* Score number */}
                <span className="text-[10px] font-mono text-[var(--text-muted)] w-8 text-right tabular-nums">
                  {control.score}%
                </span>

                {/* Chevron */}
                <motion.svg
                  width="14"
                  height="14"
                  viewBox="0 0 14 14"
                  fill="currentColor"
                  className="text-[var(--text-muted)] flex-shrink-0"
                  animate={{ rotate: isExpanded ? 90 : 0 }}
                  transition={{ duration: 0.15 }}
                >
                  <path d="M5.22 3.22a.75.75 0 0 1 1.06 0l3.25 3.25a.75.75 0 0 1 0 1.06l-3.25 3.25a.75.75 0 0 1-1.06-1.06L7.94 7 5.22 4.28a.75.75 0 0 1 0-1.06Z" />
                </motion.svg>
              </button>

              <AnimatePresence>
                {isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="overflow-hidden"
                  >
                    <div className="px-4 pb-3 pl-12 space-y-2">
                      <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                        {control.description}
                      </p>
                      {control.evidence && (
                        <div className="p-2 rounded bg-[var(--bg-tertiary)]">
                          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] mb-1">
                            Evidence
                          </p>
                          <p className="text-xs text-[var(--text-secondary)]">
                            {control.evidence}
                          </p>
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

export type { ControlsListProps };
export default ControlsList;
