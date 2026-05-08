// frontend/src/components/overview/PipelineStatus.tsx
// Pipeline status — 7-stage AIR protocol stepper
// WHY: Shows judges exactly what's happening inside the system. Each stage
// lights up in sequence during processing, demonstrating the full protocol.

import React from 'react';
import { motion } from 'framer-motion';
import { Card } from '../common/Card';
import type { PipelineState } from '../../utils/types';

// ─── Types ────────────────────────────────────────────────────────────────────

interface PipelineStatusProps {
  pipelineState: PipelineState | null;
  className?: string;
}

// ─── Stage Data ─────────────────────────────────────────────────────────────--

const STAGES = [
  { id: 1, name: 'Surprise Detection', target: '<200ms' },
  { id: 2, name: 'Polymorphic Containment', target: '<500ms' },
  { id: 3, name: 'Adaptive Deception', target: 'Simultaneous' },
  { id: 4, name: 'Analogical Bridge', target: '<2s' },
  { id: 5, name: 'Deep Synthesis', target: '30-60s' },
  { id: 6, name: 'Adversarial Stress Test', target: '30s-5min' },
  { id: 7, name: 'Mesh Broadcast', target: '<300ms' },
];

// ─── Component ────────────────────────────────────────────────────────────────

export function PipelineStatus({
  pipelineState,
  className = '',
}: PipelineStatusProps) {
  const currentStage = pipelineState?.stage ?? 0;
  const isActive = pipelineState !== null;

  return (
    <Card
      title="AIR Pipeline"
      actions={
        <span
          className={[
            'text-[10px] font-medium px-2 py-0.5 rounded-full',
            isActive
              ? 'bg-[var(--color-immune)]/10 text-[var(--color-immune)]'
              : 'bg-[var(--bg-tertiary)] text-[var(--text-muted)]',
          ].join(' ')}
        >
          {isActive ? `Stage ${currentStage}/7` : 'Idle'}
        </span>
      }
      padding="none"
      className={className}
    >
      <div className="px-4 py-3 space-y-0">
        {STAGES.map((stage) => {
          const isCompleted = currentStage > stage.id;
          const isCurrent = currentStage === stage.id && isActive;
          const isPending = currentStage < stage.id || !isActive;

          return (
            <div key={stage.id} className="flex items-center gap-3 py-2">
              {/* Status indicator */}
              <div className="flex-shrink-0 relative">
                {isCompleted ? (
                  <div className="w-6 h-6 rounded-full bg-[var(--color-immune)]/20 flex items-center justify-center">
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none" className="text-[var(--color-immune)]">
                      <path d="M3 6l2.5 2.5L9 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </div>
                ) : isCurrent ? (
                  <motion.div
                    className="w-6 h-6 rounded-full bg-[var(--color-immune)] flex items-center justify-center"
                    animate={{ boxShadow: ['0 0 0 0 rgba(0,229,160,0.4)', '0 0 0 8px rgba(0,229,160,0)', '0 0 0 0 rgba(0,229,160,0.4)'] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  >
                    <span className="text-[10px] font-bold text-[#0A0E1A]">{stage.id}</span>
                  </motion.div>
                ) : (
                  <div className="w-6 h-6 rounded-full bg-[var(--bg-tertiary)] flex items-center justify-center">
                    <span className="text-[10px] font-medium text-[var(--text-muted)]">{stage.id}</span>
                  </div>
                )}

                {/* Connector line */}
                {stage.id < 7 && (
                  <div
                    className={[
                      'absolute left-1/2 top-6 w-px h-4 -translate-x-1/2',
                      isCompleted ? 'bg-[var(--color-immune)]/30' : 'bg-[var(--border-subtle)]',
                    ].join(' ')}
                  />
                )}
              </div>

              {/* Label */}
              <div className="flex-1 min-w-0">
                <p
                  className={[
                    'text-xs font-medium',
                    isCurrent
                      ? 'text-[var(--color-immune)]'
                      : isCompleted
                      ? 'text-[var(--text-primary)]'
                      : 'text-[var(--text-muted)]',
                  ].join(' ')}
                >
                  {stage.name}
                </p>
              </div>

              {/* Target time */}
              <span
                className={[
                  'text-[10px] tabular-nums flex-shrink-0',
                  isCurrent ? 'text-[var(--color-immune)]' : 'text-[var(--text-muted)]',
                ].join(' ')}
              >
                {stage.target}
              </span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

export type { PipelineStatusProps };
export default PipelineStatus;
