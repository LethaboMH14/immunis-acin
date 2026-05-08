// frontend/src/components/overview/ThreatFeed.tsx
// Live threat feed — real-time scrolling list of detected threats
// WHY: Demonstrates the system is alive and processing. Every new threat
// animates in, showing judges the pipeline is working in real time.

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { EmptyThreats } from '../common/EmptyState';
import { formatRelativeTime } from '../../utils/formatters';
import type { Threat } from '../../utils/types';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ThreatFeedProps {
  threats: Threat[];
  onThreatClick?: (threat: Threat) => void;
  className?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getSeverityVariant(severity: string) {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'critical' as const;
    case 'high': return 'high' as const;
    case 'medium': return 'medium' as const;
    case 'low': return 'low' as const;
    default: return 'info' as const;
  }
}

function getClassificationVariant(classification: string) {
  switch (classification?.toLowerCase()) {
    case 'novel': return 'novel' as const;
    case 'variant': return 'warning' as const;
    case 'known': return 'immune' as const;
    default: return 'neutral' as const;
  }
}

// ─── Item Animation ─────────────────────────────────────────────────────────--

const itemVariants = {
  hidden: { opacity: 0, x: -20, height: 0 },
  visible: {
    opacity: 1,
    x: 0,
    height: 'auto',
    transition: { duration: 0.3, ease: 'easeOut' },
  },
  exit: {
    opacity: 0,
    x: 20,
    height: 0,
    transition: { duration: 0.2 },
  },
};

// ─── Component ────────────────────────────────────────────────────────────────

export function ThreatFeed({
  threats,
  onThreatClick,
  className = '',
}: ThreatFeedProps) {
  return (
    <Card
      title="Threat Feed"
      actions={
        <span className="text-[10px] text-[var(--text-muted)] tabular-nums">
          {threats.length} events
        </span>
      }
      padding="none"
      className={className}
    >
      {threats.length === 0 ? (
        <EmptyThreats />
      ) : (
        <div className="max-h-[360px] overflow-y-auto">
          <AnimatePresence initial={false}>
            {threats.map((threat) => (
              <motion.div
                key={threat.id}
                variants={itemVariants}
                initial="hidden"
                animate="visible"
                exit="exit"
                layout
                onClick={() => onThreatClick?.(threat)}
                className={[
                  'flex items-start gap-3 px-4 py-3 border-b border-[var(--border-subtle)] last:border-b-0',
                  onThreatClick ? 'cursor-pointer hover:bg-[var(--bg-tertiary)] transition-colors' : '',
                ].join(' ')}
              >
                {/* Severity dot */}
                <div className="mt-1.5 flex-shrink-0">
                  <Badge variant={getSeverityVariant(threat.severity)} dot>
                    {threat.severity}
                  </Badge>
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-[var(--text-primary)] truncate">
                      {threat.family || threat.type || 'Unknown Threat'}
                    </p>
                    <Badge variant={getClassificationVariant(threat.classification)}>
                      {threat.classification}
                    </Badge>
                  </div>
                  <p className="text-xs text-[var(--text-muted)] mt-0.5 truncate">
                    {threat.summary || `Detected via ${threat.vector}`}
                  </p>
                </div>

                {/* Meta */}
                <div className="flex flex-col items-end gap-1 flex-shrink-0">
                  <span className="text-[10px] text-[var(--text-muted)] tabular-nums">
                    {formatRelativeTime(threat.timestamp)}
                  </span>
                  {threat.language && (
                    <Badge variant="neutral">
                      {threat.language.toUpperCase()}
                    </Badge>
                  )}
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      )}
    </Card>
  );
}

export type { ThreatFeedProps };
export default ThreatFeed;
