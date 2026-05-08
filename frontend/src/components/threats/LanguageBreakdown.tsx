// frontend/src/components/threats/LanguageBreakdown.tsx
// Language breakdown — distribution of threat languages
// WHY: One of IMMUNIS's key differentiators is 40+ language support.
// This chart visually proves it works across languages.

import React, { useMemo } from 'react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { formatLanguage } from '../../utils/formatters';

// ─── Types ────────────────────────────────────────────────────────────────────

interface LanguageBreakdownProps {
  threats: { language?: string }[];
  className?: string;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function LanguageBreakdown({
  threats,
  className = '',
}: LanguageBreakdownProps) {
  const breakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const t of threats) {
      const lang = t.language || 'unknown';
      counts[lang] = (counts[lang] || 0) + 1;
    }
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .map(([lang, count]) => ({
        code: lang,
        name: formatLanguage(lang),
        count,
        pct: threats.length > 0 ? (count / threats.length) * 100 : 0,
      }));
  }, [threats]);

  const maxCount = breakdown.length > 0 ? breakdown[0].count : 1;

  return (
    <Card
      title="Languages Detected"
      actions={
        <Badge variant="mesh">{breakdown.length} languages</Badge>
      }
      padding="sm"
      className={className}
    >
      {breakdown.length === 0 ? (
        <div className="py-6 text-center">
          <p className="text-xs text-[var(--text-muted)]">
            No languages detected yet
          </p>
        </div>
      ) : (
        <div className="space-y-2.5 max-h-[300px] overflow-y-auto">
          {breakdown.map((lang) => (
            <div key={lang.code} className="group">
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <Badge variant="neutral">{lang.code.toUpperCase()}</Badge>
                  <span className="text-xs text-[var(--text-secondary)]">
                    {lang.name}
                  </span>
                </div>
                <span className="text-[10px] font-mono text-[var(--text-muted)] tabular-nums">
                  {lang.count} ({lang.pct.toFixed(0)}%)
                </span>
              </div>
              <div className="h-1 rounded-full bg-[var(--bg-tertiary)] overflow-hidden">
                <div
                  className="h-full rounded-full bg-[var(--color-mesh,#38BDF8)] transition-all duration-500"
                  style={{ width: `${(lang.count / maxCount) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

export type { LanguageBreakdownProps };
export default LanguageBreakdown;
