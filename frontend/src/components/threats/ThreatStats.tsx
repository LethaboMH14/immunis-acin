// frontend/src/components/threats/ThreatStats.tsx
// Threat statistics — aggregate analysis of all detected threats
// WHY: Judges and CISOs want the big picture. Not just individual threats,
// but patterns: what types dominate, what vectors are exploited, how novel
// are the attacks we're seeing.

import React, { useMemo } from 'react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { ProgressBar } from '../common/ProgressBar';
import type { Threat } from '../../utils/types';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ThreatStatsProps {
  threats: Threat[];
  className?: string;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function ThreatStats({ threats, className = '' }: ThreatStatsProps) {
  const stats = useMemo(() => {
    const severity: Record<string, number> = {};
    const classification: Record<string, number> = {};
    const vectors: Record<string, number> = {};
    const families: Record<string, number> = {};
    let totalSurprise = 0;
    let surpriseCount = 0;

    for (const t of threats) {
      // Severity
      const sev = t.severity || 'unknown';
      severity[sev] = (severity[sev] || 0) + 1;

      // Classification
      const cls = t.classification || 'unknown';
      classification[cls] = (classification[cls] || 0) + 1;

      // Vector
      const vec = t.vector || 'unknown';
      vectors[vec] = (vectors[vec] || 0) + 1;

      // Family
      const fam = t.family || t.type || 'Unknown';
      families[fam] = (families[fam] || 0) + 1;

      // Surprise
      if (t.surprise_score !== undefined) {
        totalSurprise += t.surprise_score;
        surpriseCount++;
      }
    }

    const topFamilies = Object.entries(families)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    return {
      total: threats.length,
      severity,
      classification,
      vectors,
      topFamilies,
      avgSurprise: surpriseCount > 0 ? totalSurprise / surpriseCount : 0,
    };
  }, [threats]);

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const severityColors = {
    critical: 'threat',
    high: 'warning',
    medium: 'warning',
    low: 'info',
    info: 'neutral',
  } as const;

  return (
    <div className={`grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 ${className}`}>
      {/* Total + Average Surprise */}
      <Card padding="lg">
        <div className="text-center mb-4">
          <p className="text-3xl font-bold text-[var(--text-primary)] tabular-nums">
            {stats.total}
          </p>
          <p className="text-xs text-[var(--text-muted)] mt-1">Total Threats</p>
        </div>
        <div className="pt-3 border-t border-[var(--border-subtle)]">
          <div className="flex items-center justify-between">
            <span className="text-xs text-[var(--text-muted)]">Avg Surprise</span>
            <span className="text-sm font-mono font-semibold text-[var(--text-primary)]">
              {stats.avgSurprise.toFixed(2)} bits
            </span>
          </div>
        </div>
      </Card>

      {/* Severity Breakdown */}
      <Card title="By Severity" padding="md">
        <div className="space-y-3">
          {severityOrder.map((sev) => {
            const count = stats.severity[sev] || 0;
            const pct = stats.total > 0 ? (count / stats.total) * 100 : 0;
            return (
              <div key={sev}>
                <div className="flex items-center justify-between mb-1">
                  <Badge variant={severityColors[sev as keyof typeof severityColors] || 'neutral'}>
                    {sev}
                  </Badge>
                  <span className="text-xs font-mono text-[var(--text-muted)] tabular-nums">
                    {count}
                  </span>
                </div>
                <ProgressBar
                  value={pct}
                  variant={
                    sev === 'critical' || sev === 'high' ? 'threat' :
                    sev === 'medium' ? 'warning' : 'neutral'
                  }
                  size="sm"
                />
              </div>
            );
          })}
        </div>
      </Card>

      {/* Classification Breakdown */}
      <Card title="By Classification" padding="md">
        <div className="space-y-3">
          {['novel', 'variant', 'known'].map((cls) => {
            const count = stats.classification[cls] || 0;
            const pct = stats.total > 0 ? (count / stats.total) * 100 : 0;
            const variant = cls === 'novel' ? 'novel' : cls === 'variant' ? 'warning' : 'immune';
            return (
              <div key={cls}>
                <div className="flex items-center justify-between mb-1">
                  <Badge variant={variant as any}>{cls}</Badge>
                  <span className="text-xs font-mono text-[var(--text-muted)] tabular-nums">
                    {count} ({pct.toFixed(0)}%)
                  </span>
                </div>
                <ProgressBar value={pct} variant={variant as any} size="sm" />
              </div>
            );
          })}
        </div>
      </Card>

      {/* Vector Breakdown */}
      <Card title="By Vector" padding="md">
        <div className="space-y-2">
          {Object.entries(stats.vectors)
            .sort((a, b) => b[1] - a[1])
            .map(([vec, count]) => (
              <div key={vec} className="flex items-center justify-between py-1">
                <span className="text-xs text-[var(--text-secondary)] capitalize">{vec}</span>
                <span className="text-xs font-mono text-[var(--text-muted)] tabular-nums">{count}</span>
              </div>
            ))}
        </div>
      </Card>

      {/* Top Families */}
      <Card title="Top Threat Families" padding="md" className="md:col-span-2">
        <div className="space-y-3">
          {stats.topFamilies.map(([family, count], i) => {
            const pct = stats.total > 0 ? (count / stats.total) * 100 : 0;
            return (
              <div key={family}>
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-[var(--text-muted)] w-4">{i + 1}.</span>
                    <span className="text-xs font-medium text-[var(--text-primary)] truncate max-w-[200px]">
                      {family}
                    </span>
                  </div>
                  <span className="text-xs font-mono text-[var(--text-muted)] tabular-nums">
                    {count} ({pct.toFixed(0)}%)
                  </span>
                </div>
                <ProgressBar value={pct} variant="info" size="sm" />
              </div>
            );
          })}
          {stats.topFamilies.length === 0 && (
            <p className="text-xs text-[var(--text-muted)] text-center py-4">
              No threat families detected yet
            </p>
          )}
        </div>
      </Card>
    </div>
  );
}

export type { ThreatStatsProps };
export default ThreatStats;
