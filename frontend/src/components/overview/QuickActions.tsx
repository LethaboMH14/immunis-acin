// frontend/src/components/overview/QuickActions.tsx
// Quick actions — one-click access to primary workflows
// WHY: Judges need to see things happen. These buttons are the fastest
// path to demonstrating each feature. No navigation required.

import React from 'react';
import { Card } from '../common/Card';

// ─── Types ────────────────────────────────────────────────────────────────────

interface QuickActionsProps {
  onSubmitThreat?: () => void;
  onRunScan?: () => void;
  onViewReports?: () => void;
  onOpenCopilot?: () => void;
  className?: string;
}

// ─── Action Data ──────────────────────────────────────────────────────────────

const actions = [
  {
    id: 'submit',
    label: 'Submit Threat',
    color: 'text-[var(--color-threat)]',
    bg: 'bg-[var(--color-threat)]/10 hover:bg-[var(--color-threat)]/20',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
        <path d="M8 2v12M2 8h12" />
      </svg>
    ),
  },
  {
    id: 'scan',
    label: 'Run Scan',
    color: 'text-purple-400',
    bg: 'bg-purple-400/10 hover:bg-purple-400/20',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
        <circle cx="7" cy="7" r="4.5" />
        <path d="M10.5 10.5L14 14" />
      </svg>
    ),
  },
  {
    id: 'reports',
    label: 'Reports',
    color: 'text-amber-400',
    bg: 'bg-amber-400/10 hover:bg-amber-400/20',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
        <rect x="3" y="2" width="10" height="12" rx="1.5" />
        <path d="M6 6h4M6 9h3" />
      </svg>
    ),
  },
  {
    id: 'copilot',
    label: 'Copilot',
    color: 'text-[var(--color-immune)]',
    bg: 'bg-[var(--color-immune)]/10 hover:bg-[var(--color-immune)]/20',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
        <path d="M3 12l3-6 3 6" />
        <path d="M4.5 10h3" />
        <circle cx="12" cy="7" r="2.5" />
        <path d="M12 9.5v2" />
      </svg>
    ),
  },
];

// ─── Component ────────────────────────────────────────────────────────────────

export function QuickActions({
  onSubmitThreat,
  onRunScan,
  onViewReports,
  onOpenCopilot,
  className = '',
}: QuickActionsProps) {
  const handlers: Record<string, (() => void) | undefined> = {
    submit: onSubmitThreat,
    scan: onRunScan,
    reports: onViewReports,
    copilot: onOpenCopilot,
  };

  return (
    <Card title="Quick Actions" padding="sm" className={className}>
      <div className="grid grid-cols-2 gap-2">
        {actions.map((action) => (
          <button
            key={action.id}
            onClick={handlers[action.id]}
            className={[
              'flex flex-col items-center gap-1.5 py-3 px-2 rounded-lg transition-colors',
              action.bg,
              action.color,
            ].join(' ')}
          >
            {action.icon}
            <span className="text-[10px] font-medium">{action.label}</span>
          </button>
        ))}
      </div>
    </Card>
  );
}

export type { QuickActionsProps };
export default QuickActions;
