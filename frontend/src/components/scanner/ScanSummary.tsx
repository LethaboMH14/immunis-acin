// frontend/src/components/scanner/ScanSummary.tsx
// Scan summary — severity breakdown in metric cards
// WHY: Instant overview of vulnerability landscape. Critical count
// is the number judges and CISOs look at first.

import React from 'react';
import { Card } from '../common/Card';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ScanSummaryProps {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  className?: string;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function ScanSummary({
  totalFindings,
  critical,
  high,
  medium,
  low,
  className = '',
}: ScanSummaryProps) {
  const items = [
    { label: 'Total', count: totalFindings, color: 'text-[var(--text-primary)]', bg: 'bg-[var(--bg-tertiary)]' },
    { label: 'Critical', count: critical, color: 'text-red-400', bg: 'bg-red-400/10' },
    { label: 'High', count: high, color: 'text-orange-400', bg: 'bg-orange-400/10' },
    { label: 'Medium', count: medium, color: 'text-amber-400', bg: 'bg-amber-400/10' },
    { label: 'Low', count: low, color: 'text-blue-400', bg: 'bg-blue-400/10' },
  ];

  return (
    <div className={`grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 ${className}`}>
      {items.map((item) => (
        <Card key={item.label} variant="flat" padding="md">
          <div className={`inline-flex items-center justify-center w-8 h-8 rounded-lg ${item.bg} mb-2`}>
            <span className={`text-sm font-bold tabular-nums ${item.color}`}>
              {item.count}
            </span>
          </div>
          <p className="text-xs text-[var(--text-muted)]">{item.label}</p>
          {totalFindings > 0 && item.label !== 'Total' && (
            <p className={`text-[10px] font-mono tabular-nums mt-0.5 ${item.color}`}>
              {((item.count / totalFindings) * 100).toFixed(0)}%
            </p>
          )}
        </Card>
      ))}
    </div>
  );
}

export type { ScanSummaryProps };
export default ScanSummary;
