// frontend/src/components/overview/ImmunityGauge.tsx
// Immunity score gauge — the centrepiece visual, first thing judges see
// WHY: Communicates system health instantly. A single number that summarises
// the entire state of the immune system. Animated to feel alive.

import React, { useEffect, useState } from 'react';
import { motion, useSpring, useTransform } from 'framer-motion';
import { Card } from '../common/Card';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ImmunityGaugeProps {
  score: number;
  isConnected: boolean;
  className?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getScoreColor(score: number): string {
  if (score >= 80) return 'var(--color-immune)';
  if (score >= 60) return '#34D399';
  if (score >= 40) return 'var(--color-warning)';
  if (score >= 20) return '#F97316';
  return 'var(--color-threat)';
}

function getScoreLabel(score: number): string {
  if (score >= 80) return 'Immune';
  if (score >= 60) return 'Protected';
  if (score >= 40) return 'Developing';
  if (score >= 20) return 'Vulnerable';
  return 'Critical';
}

function getScoreDescription(score: number): string {
  if (score >= 80) return 'System fully protected against known threat families';
  if (score >= 60) return 'Good coverage with some gaps in novel threats';
  if (score >= 40) return 'Building immunity — more antibodies needed';
  if (score >= 20) return 'Limited protection — high exposure to attacks';
  return 'Minimal immunity — immediate action required';
}

// ─── Component ────────────────────────────────────────────────────────────────

export function ImmunityGauge({
  score,
  isConnected,
  className = '',
}: ImmunityGaugeProps) {
  const [prevScore, setPrevScore] = useState(score);
  const [isUpdating, setIsUpdating] = useState(false);

  // Animated score value
  const springValue = useSpring(0, { stiffness: 50, damping: 20 });
  const displayScore = useTransform(springValue, (v) => Math.round(v));

  useEffect(() => {
    springValue.set(score);
    if (score !== prevScore) {
      setIsUpdating(true);
      setPrevScore(score);
      const timer = setTimeout(() => setIsUpdating(false), 1000);
      return () => clearTimeout(timer);
    }
  }, [score, prevScore, springValue]);

  // SVG arc calculations
  const size = 200;
  const strokeWidth = 12;
  const radius = (size - strokeWidth) / 2;
  const circumference = Math.PI * radius; // Semi-circle
  const progress = (score / 100) * circumference;

  const color = getScoreColor(score);
  const label = getScoreLabel(score);
  const description = getScoreDescription(score);

  return (
    <Card
      variant="default"
      padding="lg"
      className={`flex flex-col items-center ${className}`}
    >
      {/* Title */}
      <div className="flex items-center gap-2 mb-4">
        <h3 className="text-sm font-semibold text-[var(--text-primary)]">
          Immunity Score
        </h3>
        <span
          className={[
            'w-2 h-2 rounded-full',
            isConnected ? 'bg-emerald-400' : 'bg-red-400',
          ].join(' ')}
          title={isConnected ? 'Live' : 'Disconnected'}
        />
      </div>

      {/* Gauge SVG */}
      <div className="relative" style={{ width: size, height: size / 2 + 40 }}>
        <svg
          width={size}
          height={size / 2 + strokeWidth}
          viewBox={`0 0 ${size} ${size / 2 + strokeWidth}`}
          className="overflow-visible"
        >
          {/* Background arc */}
          <path
            d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
            fill="none"
            stroke="var(--bg-tertiary)"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />

          {/* Progress arc */}
          <motion.path
            d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: circumference - progress }}
            transition={{ duration: 1.2, ease: 'easeOut' }}
            style={{
              filter: `drop-shadow(0 0 8px ${color}40)`,
            }}
          />
        </svg>

        {/* Score number */}
        <div className="absolute inset-0 flex flex-col items-center justify-end pb-2">
          <motion.span
            className="text-4xl font-bold tabular-nums"
            style={{ color }}
            animate={isUpdating ? { scale: [1, 1.1, 1] } : {}}
            transition={{ duration: 0.3 }}
          >
            <motion.span>{displayScore}</motion.span>
          </motion.span>
          <span
            className="text-xs font-semibold uppercase tracking-wider mt-1"
            style={{ color }}
          >
            {label}
          </span>
        </div>
      </div>

      {/* Description */}
      <p className="text-xs text-[var(--text-muted)] text-center mt-2 max-w-[220px]">
        {description}
      </p>
    </Card>
  );
}

export type { ImmunityGaugeProps };
export default ImmunityGauge;
