// frontend/src/components/overview/EvolutionSparkline.tsx
// Evolution sparkline — immunity score over time
// WHY: Shows the trajectory. Is the system getting stronger or weaker?
// The upward trend is the visual proof that coevolution works.

import React, { useMemo, useState } from 'react';
import { Card } from '../common/Card';
import { formatDateTime } from '../../utils/formatters';

// ─── Types ────────────────────────────────────────────────────────────────────

interface EvolutionPoint {
  timestamp: string;
  immunity_score: number;
  red_wins?: number;
  blue_wins?: number;
}

interface EvolutionSparklineProps {
  timeline: EvolutionPoint[];
  className?: string;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function EvolutionSparkline({
  timeline,
  className = '',
}: EvolutionSparklineProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  // SVG dimensions
  const width = 460;
  const height = 160;
  const padding = { top: 10, right: 10, bottom: 20, left: 10 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  // Compute path
  const { linePath, areaPath, points } = useMemo(() => {
    if (timeline.length < 2) {
      return { linePath: '', areaPath: '', points: [] };
    }

    const pts = timeline.map((d, i) => ({
      x: padding.left + (i / (timeline.length - 1)) * chartW,
      y: padding.top + chartH - (d.immunity_score / 100) * chartH,
      data: d,
    }));

    const lineSegments = pts.map((p, i) => (i === 0 ? `M${p.x},${p.y}` : `L${p.x},${p.y}`)).join(' ');
    const areaSegments = lineSegments + ` L${pts[pts.length - 1].x},${padding.top + chartH} L${pts[0].x},${padding.top + chartH} Z`;

    return { linePath: lineSegments, areaPath: areaSegments, points: pts };
  }, [timeline, chartW, chartH, padding.left, padding.top]);

  const hoveredPoint = hoveredIndex !== null ? points[hoveredIndex] : null;

  const currentScore = timeline.length > 0 ? timeline[timeline.length - 1].immunity_score : 0;
  const startScore = timeline.length > 0 ? timeline[0].immunity_score : 0;
  const delta = currentScore - startScore;

  return (
    <Card
      title="Evolution Timeline"
      actions={
        <div className="flex items-center gap-2">
          <span
            className={[
              'text-[10px] font-medium',
              delta >= 0 ? 'text-emerald-400' : 'text-red-400',
            ].join(' ')}
          >
            {delta >= 0 ? '+' : ''}{delta.toFixed(1)}
          </span>
          <span className="text-[10px] text-[var(--text-muted)]">
            {timeline.length} points
          </span>
        </div>
      }
      padding="sm"
      className={className}
    >
      {timeline.length < 2 ? (
        <div className="flex items-center justify-center h-40">
          <p className="text-xs text-[var(--text-muted)]">
            Waiting for evolution data...
          </p>
        </div>
      ) : (
        <div className="relative">
          <svg
            width="100%"
            height={height}
            viewBox={`0 0 ${width} ${height}`}
            preserveAspectRatio="none"
            className="overflow-visible"
          >
            {/* Gradient */}
            <defs>
              <linearGradient id="sparkline-gradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--color-immune)" stopOpacity="0.3" />
                <stop offset="100%" stopColor="var(--color-immune)" stopOpacity="0" />
              </linearGradient>
            </defs>

            {/* Grid lines */}
            {[0, 25, 50, 75, 100].map((v) => {
              const y = padding.top + chartH - (v / 100) * chartH;
              return (
                <line
                  key={v}
                  x1={padding.left}
                  y1={y}
                  x2={width - padding.right}
                  y2={y}
                  stroke="var(--border-subtle)"
                  strokeWidth="0.5"
                  strokeDasharray="4 4"
                />
              );
            })}

            {/* Area fill */}
            <path d={areaPath} fill="url(#sparkline-gradient)" />

            {/* Line */}
            <path
              d={linePath}
              fill="none"
              stroke="var(--color-immune)"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />

            {/* Hover zones */}
            {points.map((p, i) => (
              <rect
                key={i}
                x={p.x - chartW / points.length / 2}
                y={padding.top}
                width={chartW / points.length}
                height={chartH}
                fill="transparent"
                onMouseEnter={() => setHoveredIndex(i)}
                onMouseLeave={() => setHoveredIndex(null)}
              />
            ))}

            {/* Hover dot */}
            {hoveredPoint && (
              <>
                <line
                  x1={hoveredPoint.x}
                  y1={padding.top}
                  x2={hoveredPoint.x}
                  y2={padding.top + chartH}
                  stroke="var(--color-immune)"
                  strokeWidth="1"
                  strokeDasharray="3 3"
                  opacity="0.5"
                />
                <circle
                  cx={hoveredPoint.x}
                  cy={hoveredPoint.y}
                  r="4"
                  fill="var(--color-immune)"
                  stroke="var(--bg-secondary)"
                  strokeWidth="2"
                />
              </>
            )}
          </svg>

          {/* Tooltip */}
          {hoveredPoint && (
            <div
              className="absolute z-10 px-2.5 py-1.5 rounded-md bg-[var(--bg-primary)] border border-[var(--border-primary)] shadow-lg pointer-events-none"
              style={{
                left: Math.min(hoveredPoint.x, width - 140),
                top: hoveredPoint.y - 50,
              }}
            >
              <p className="text-xs font-mono font-semibold text-[var(--color-immune)]">
                Score: {hoveredPoint.data.immunity_score}
              </p>
              <p className="text-[10px] text-[var(--text-muted)]">
                {formatDateTime(hoveredPoint.data.timestamp)}
              </p>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

export type { EvolutionSparklineProps };
export default EvolutionSparkline;
