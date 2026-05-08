// frontend/src/components/overview/SystemStatus.tsx
// System status — connection health, uptime, provider info
// WHY: Quick diagnostic view. Is the system connected? How long has it
// been running? Which AI provider is responding?

import React from 'react';
import { Card } from '../common/Card';
import { StatusIndicator } from '../layout/StatusIndicator';
import { formatDurationSeconds } from '../../utils/formatters';

// ─── Types ────────────────────────────────────────────────────────────────────

interface SystemStatusProps {
  isConnected: boolean;
  uptime: number; // seconds
  className?: string;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function SystemStatus({
  isConnected,
  uptime,
  className = '',
}: SystemStatusProps) {
  const items = [
    {
      label: 'WebSocket',
      status: isConnected ? ('online' as const) : ('offline' as const),
    },
    {
      label: 'Pipeline',
      status: isConnected ? ('online' as const) : ('idle' as const),
    },
    {
      label: 'Mesh Network',
      status: isConnected ? ('syncing' as const) : ('offline' as const),
    },
  ];

  return (
    <Card title="System Status" padding="sm" className={className}>
      <div className="space-y-3">
        {items.map((item) => (
          <div key={item.label} className="flex items-center justify-between">
            <span className="text-xs text-[var(--text-secondary)]">
              {item.label}
            </span>
            <StatusIndicator status={item.status} size="sm" />
          </div>
        ))}

        {/* Uptime */}
        <div className="flex items-center justify-between pt-2 border-t border-[var(--border-subtle)]">
          <span className="text-xs text-[var(--text-secondary)]">Uptime</span>
          <span className="text-xs font-mono text-[var(--text-muted)] tabular-nums">
            {uptime > 0 ? formatDurationSeconds(uptime) : '—'}
          </span>
        </div>
      </div>
    </Card>
  );
}

export type { SystemStatusProps };
export default SystemStatus;
