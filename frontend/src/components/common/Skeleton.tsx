// frontend/src/components/common/Skeleton.tsx
// Skeleton loading — shimmer placeholders for every content type
// WHY: Every API call has latency. Skeleton loading is better than spinners
// because it communicates the shape of incoming content, reducing perceived
// wait time and preventing layout shift.

import React from 'react';

// ─── Base Skeleton ────────────────────────────────────────────────────────────

interface SkeletonProps {
  width?: string | number;
  height?: string | number;
  borderRadius?: string | number;
  className?: string;
  variant?: 'line' | 'circle' | 'rect';
}

export function Skeleton({
  width,
  height,
  borderRadius,
  className = '',
  variant = 'rect',
}: SkeletonProps) {
  const variantStyles = {
    line: {
      width: width ?? '100%',
      height: height ?? '14px',
      borderRadius: borderRadius ?? '4px',
    },
    circle: {
      width: width ?? '40px',
      height: height ?? width ?? '40px',
      borderRadius: '50%',
    },
    rect: {
      width: width ?? '100%',
      height: height ?? '100px',
      borderRadius: borderRadius ?? '12px',
    },
  };

  const style = variantStyles[variant];

  return (
    <div
      className={[
        'animate-[shimmer_2s_infinite] bg-gradient-to-r',
        'from-[var(--bg-tertiary)] via-[var(--border-subtle)] to-[var(--bg-tertiary)]',
        'bg-[length:200%_100%]',
        className,
      ]
        .filter(Boolean)
        .join(' ')}
      style={{
        width: typeof style.width === 'number' ? `${style.width}px` : style.width,
        height: typeof style.height === 'number' ? `${style.height}px` : style.height,
        borderRadius:
          typeof style.borderRadius === 'number'
            ? `${style.borderRadius}px` 
            : style.borderRadius,
      }}
      aria-hidden="true"
    />
  );
}

// ─── Preset: Metric Card ──────────────────────────────────────────────────────

export function SkeletonMetric({ className = '' }: { className?: string }) {
  return (
    <div
      className={`p-4 rounded-xl bg-[var(--bg-secondary)] border border-[var(--border-subtle)] ${className}`}
    >
      <Skeleton variant="line" width="60%" height={12} />
      <div className="mt-3">
        <Skeleton variant="line" width="40%" height={32} />
      </div>
      <div className="mt-2">
        <Skeleton variant="line" width="50%" height={12} />
      </div>
    </div>
  );
}

// ─── Preset: Card ─────────────────────────────────────────────────────────────

export function SkeletonCard({ className = '' }: { className?: string }) {
  return (
    <div
      className={`p-4 rounded-xl bg-[var(--bg-secondary)] border border-[var(--border-subtle)] ${className}`}
    >
      <div className="flex items-center gap-3 mb-4">
        <Skeleton variant="circle" width={36} />
        <div className="flex-1">
          <Skeleton variant="line" width="70%" height={14} />
          <div className="mt-1.5">
            <Skeleton variant="line" width="40%" height={12} />
          </div>
        </div>
      </div>
      <Skeleton variant="line" width="100%" height={12} />
      <div className="mt-2">
        <Skeleton variant="line" width="85%" height={12} />
      </div>
      <div className="mt-2">
        <Skeleton variant="line" width="60%" height={12} />
      </div>
    </div>
  );
}

// ─── Preset: Feed Item ────────────────────────────────────────────────────────

export function SkeletonFeedItem({ className = '' }: { className?: string }) {
  return (
    <div
      className={`flex items-start gap-3 p-3 rounded-lg ${className}`}
    >
      <Skeleton variant="circle" width={32} />
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <Skeleton variant="line" width="30%" height={12} />
          <Skeleton variant="line" width={48} height={18} borderRadius={9} />
        </div>
        <div className="mt-1.5">
          <Skeleton variant="line" width="90%" height={12} />
        </div>
        <div className="mt-1">
          <Skeleton variant="line" width="60%" height={12} />
        </div>
      </div>
    </div>
  );
}

// ─── Preset: List ─────────────────────────────────────────────────────────────

export function SkeletonList({
  count = 5,
  className = '',
}: {
  count?: number;
  className?: string;
}) {
  return (
    <div className={`flex flex-col gap-2 ${className}`}>
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonFeedItem key={i} />
      ))}
    </div>
  );
}

// ─── Preset: Chart ────────────────────────────────────────────────────────────

export function SkeletonChart({ className = '' }: { className?: string }) {
  return (
    <div
      className={`p-4 rounded-xl bg-[var(--bg-secondary)] border border-[var(--border-subtle)] ${className}`}
    >
      <Skeleton variant="line" width="40%" height={14} />
      <div className="mt-4">
        <Skeleton variant="rect" width="100%" height={200} />
      </div>
    </div>
  );
}

export type { SkeletonProps };
export default Skeleton;
