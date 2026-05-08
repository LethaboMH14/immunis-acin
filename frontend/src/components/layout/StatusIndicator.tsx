// frontend/src/components/layout/StatusIndicator.tsx
// Status indicator — colored dot with optional label
// WHY: WebSocket connection, mesh node status, agent health, pipeline stage —
// many things need a compact visual status indicator.

import React from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

type Status = 'online' | 'offline' | 'warning' | 'syncing' | 'idle';

interface StatusIndicatorProps {
  status: Status;
  label?: string;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  className?: string;
}

// ─── Styles ─────────────────────────────────────────────────────────────────--

const dotColors: Record<Status, string> = {
  online: 'bg-emerald-400',
  offline: 'bg-red-400',
  warning: 'bg-amber-400',
  syncing: 'bg-blue-400 animate-pulse',
  idle: 'bg-slate-400',
};

const dotSizes: Record<'sm' | 'md' | 'lg', string> = {
  sm: 'w-1.5 h-1.5',
  md: 'w-2 h-2',
  lg: 'w-2.5 h-2.5',
};

const labelSizes: Record<'sm' | 'md' | 'lg', string> = {
  sm: 'text-[10px]',
  md: 'text-xs',
  lg: 'text-sm',
};

const defaultLabels: Record<Status, string> = {
  online: 'Online',
  offline: 'Offline',
  warning: 'Warning',
  syncing: 'Syncing',
  idle: 'Idle',
};

// ─── Component ────────────────────────────────────────────────────────────────

export function StatusIndicator({
  status,
  label,
  size = 'md',
  showLabel = true,
  className = '',
}: StatusIndicatorProps) {
  const displayLabel = label ?? defaultLabels[status];

  return (
    <div
      className={`inline-flex items-center gap-1.5 ${className}`}
      title={displayLabel}
    >
      <span
        className={[
          'rounded-full flex-shrink-0',
          dotColors[status],
          dotSizes[size],
        ].join(' ')}
      />
      {showLabel && (
        <span
          className={[
            'text-[var(--text-muted)] font-medium',
            labelSizes[size],
          ].join(' ')}
        >
          {displayLabel}
        </span>
      )}
    </div>
  );
}

export type { StatusIndicatorProps, Status };
export default StatusIndicator;
