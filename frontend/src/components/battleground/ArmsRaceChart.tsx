// frontend/src/components/battleground/ArmsRaceChart.tsx
// Arms race chart — Red vs Blue coevolution over time
// WHY: The visual proof of adversarial coevolution. Both lines trending
// upward means both attack and defence are improving — which is exactly
// what the Lotka-Volterra model predicts.

import React, { useMemo, useState } from 'react';
import { Card } from '../common/Card';
import type { BattleSession } from '../../utils/types';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ArmsRaceChartProps {
  history: BattleSession[];
  className?: string;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function ArmsRaceChart({ history, className = '' }: ArmsRaceChartProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  const width = 500;
  const height = 200;
  const padding = { top: 15, right: 15, bottom: 25, left: 15 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const { redPath, bluePath, points, maxVal } = useMemo(() => {
    if (history.length < 2) {
      return { redPath: '', bluePath: '', points: [], maxVal: 1 };
    }

    // Cumulative wins over time
    let cumRed = 0;
    let cumBlue = 0;
    const pts = history
      .slice()
      .reverse()
      .map((session, i) => {
        cumRed += session.red_wins ?? 0;
        cumBlue += session.blue_wins ?? 0;
        return { red: cumRed, blue: cumBlue, session, index: i };
      });

    const max = Math.max(...pts.map((p) => Math.max(p.red, p.blue)), 1);

    const toX = (i: number) => padding.left + (i / (pts.length - 1)) * chartW;
    const toY = (v: number) => padding.top + chartH - (v / max) * chartH;

    const redSegments = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${toX(i)},${toY(p.red)}`).join(' ');
    const blueSegments = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${toX(i)},${toY(p.blue)}`).join(' ');

    const mappedPoints = pts.map((p, i) => ({
      x: toX(i),
      redY: toY(p.red),
      blueY: toY(p.blue),
      data: p,
    }));

    return { redPath: redSegments, bluePath: blueSegments, points: mappedPoints, maxVal: max };
  }, [history, chartW, chartH, padding.left, padding.top]);

  const hoveredPoint = hoveredIndex !== null ? points[hoveredIndex] : null;

  return (
    <Card
      title="Arms Race Timeline"
      actions={
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1">
            <div className="w-2.5 h-0.5 rounded bg-red-400" />
            <span className="text-[10px] text-[var(--text-muted)]">Red</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-2.5 h-0.5 rounded bg-[var(--color-immune)]" />
            <span className="text-[10px] text-[var(--text-muted)]">Blue</span>
          </div>
        </div>
      }
      padding="sm"
      className={className}
    >
      {history.length < 2 ? (
        <div className="flex items-center justify-center h-48">
          <p className="text-xs text-[var(--text-muted)]">
            Waiting for battle data...
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
            {/* Grid lines */}
            {[0, 0.25, 0.5, 0.75, 1].map((pct) => {
              const y = padding.top + chartH * (1 - pct);
              return (
                <line
                  key={pct}
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

            {/* Red line */}
            <path
              d={redPath}
              fill="none"
              stroke="#F87171"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />

            {/* Blue line */}
            <path
              d={bluePath}
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

            {/* Hover indicators */}
            {hoveredPoint && (
              <>
                <line
                  x1={hoveredPoint.x}
                  y1={padding.top}
                  x2={hoveredPoint.x}
                  y2={padding.top + chartH}
                  stroke="var(--text-muted)"
                  strokeWidth="0.5"
                  strokeDasharray="3 3"
                />
                <circle cx={hoveredPoint.x} cy={hoveredPoint.redY} r="3" fill="#F87171" stroke="var(--bg-secondary)" strokeWidth="1.5" />
                <circle cx={hoveredPoint.x} cy={hoveredPoint.blueY} r="3" fill="var(--color-immune)" stroke="var(--bg-secondary)" strokeWidth="1.5" />
              </>
            )}
          </svg>

          {/* Tooltip */}
          {hoveredPoint && (
            <div
              className="absolute z-10 px-2.5 py-1.5 rounded-md bg-[var(--bg-primary)] border border-[var(--border-primary)] shadow-lg pointer-events-none"
              style={{
                left: Math.min(hoveredPoint.x, width - 120),
                top: Math.min(hoveredPoint.redY, hoveredPoint.blueY) - 55,
              }}
            >
              <p className="text-[10px] text-red-400 font-mono">Red: {hoveredPoint.data?.red || 0}</p>
              <p className="text-[10px] text-[var(--color-immune)] font-mono">Blue: {(hoveredPoint.data as any)?.blue || 0}</p>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

export type { ArmsRaceChartProps };
export default ArmsRaceChart;
