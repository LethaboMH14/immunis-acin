// frontend/src/components/scanner/ScanResultsList.tsx
// Scan results — expandable vulnerability findings list
// WHY: Every finding needs enough detail for a SOC analyst to act on it,
// but the list must stay scannable. Expand on click for full context.

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Badge } from '../common/Badge';
import { Button } from '../common/Button';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ScanResult {
  id: string;
  type: 'sast' | 'dast' | 'infrastructure';
  severity: string;
  title: string;
  description: string;
  location?: string;
  remediation?: string;
  confidence?: number;
  timestamp: string;
}

interface ScanResultsListProps {
  results: ScanResult[];
  onAskCopilot?: (result: ScanResult) => void;
  className?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function getSeverityVariant(severity: string) {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'critical' as const;
    case 'high': return 'high' as const;
    case 'medium': return 'medium' as const;
    case 'low': return 'low' as const;
    default: return 'info' as const;
  }
}

function getTypeColor(type: string) {
  switch (type) {
    case 'sast': return 'novel' as const;
    case 'dast': return 'mesh' as const;
    case 'infrastructure': return 'warning' as const;
    default: return 'neutral' as const;
  }
}

// ─── Component ────────────────────────────────────────────────────────────────

export function ScanResultsList({
  results,
  onAskCopilot,
  className = '',
}: ScanResultsListProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const sorted = [...results].sort(
    (a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  );

  return (
    <div className={`space-y-2 ${className}`}>
      {sorted.map((result) => {
        const isExpanded = expandedId === result.id;

        return (
          <div
            key={result.id}
            className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-secondary)] overflow-hidden"
          >
            {/* Header row */}
            <button
              onClick={() => setExpandedId(isExpanded ? null : result.id)}
              className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-[var(--bg-tertiary)] transition-colors"
            >
              {/* Expand chevron */}
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

              {/* Severity */}
              <Badge variant={getSeverityVariant(result.severity)}>
                {result.severity}
              </Badge>

              {/* Title */}
              <span className="flex-1 text-sm font-medium text-[var(--text-primary)] truncate">
                {result.title}
              </span>

              {/* Type */}
              <Badge variant={getTypeColor(result.type)}>
                {result.type.toUpperCase()}
              </Badge>

              {/* Location */}
              {result.location && (
                <span className="hidden md:inline text-[10px] font-mono text-[var(--text-muted)] truncate max-w-[200px]">
                  {result.location}
                </span>
              )}

              {/* Confidence */}
              {result.confidence !== undefined && (
                <span className="text-[10px] font-mono text-[var(--text-muted)] tabular-nums">
                  {(result.confidence * 100).toFixed(0)}%
                </span>
              )}
            </button>

            {/* Expanded detail */}
            <AnimatePresence>
              {isExpanded && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  className="overflow-hidden"
                >
                  <div className="px-4 pb-4 pt-1 border-t border-[var(--border-subtle)]">
                    {/* Description */}
                    <div className="mb-3">
                      <h5 className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] mb-1">
                        Description
                      </h5>
                      <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                        {result.description}
                      </p>
                    </div>

                    {/* Location */}
                    {result.location && (
                      <div className="mb-3">
                        <h5 className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] mb-1">
                          Location
                        </h5>
                        <code className="text-xs font-mono text-[var(--text-primary)] bg-[var(--bg-tertiary)] px-2 py-1 rounded">
                          {result.location}
                        </code>
                      </div>
                    )}

                    {/* Remediation */}
                    {result.remediation && (
                      <div className="mb-3">
                        <h5 className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] mb-1">
                          Remediation
                        </h5>
                        <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                          {result.remediation}
                        </p>
                      </div>
                    )}

                    {/* Actions */}
                    {onAskCopilot && (
                      <div className="flex items-center gap-2 pt-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => onAskCopilot(result)}
                        >
                          Ask Copilot
                        </Button>
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
  );
}

export type { ScanResultsListProps };
export default ScanResultsList;
