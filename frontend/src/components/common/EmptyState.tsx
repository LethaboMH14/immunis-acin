// frontend/src/components/common/EmptyState.tsx
// Empty state — centered placeholder when no data exists
// WHY: First-run experience. Before any threats are submitted, every list
// and chart is empty. Empty states guide users to take action.

import React from 'react';
import { Button } from './Button';

// ─── Types ────────────────────────────────────────────────────────────────────

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
  className?: string;
}

// ─── Default Icon ─────────────────────────────────────────────────────────────

function DefaultIcon() {
  return (
    <svg
      width="48"
      height="48"
      viewBox="0 0 48 48"
      fill="none"
      className="text-[var(--text-muted)]"
    >
      <rect
        x="4"
        y="4"
        width="40"
        height="40"
        rx="8"
        stroke="currentColor"
        strokeWidth="2"
        strokeDasharray="4 4"
      />
      <path
        d="M18 24h12M24 18v12"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

export function EmptyState({
  icon,
  title,
  description,
  action,
  className = '',
}: EmptyStateProps) {
  return (
    <div
      className={[
        'flex flex-col items-center justify-center py-12 px-6 text-center',
        className,
      ]
        .filter(Boolean)
        .join(' ')}
    >
      <div className="mb-4 opacity-50">{icon ?? <DefaultIcon />}</div>
      <h3 className="text-sm font-semibold text-[var(--text-primary)]">
        {title}
      </h3>
      {description && (
        <p className="mt-1.5 text-xs text-[var(--text-muted)] max-w-sm">
          {description}
        </p>
      )}
      {action && (
        <div className="mt-4">
          <Button variant="outline" size="sm" onClick={action.onClick}>
            {action.label}
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── Presets ──────────────────────────────────────────────────────────────────

export function EmptyThreats({ onSubmit }: { onSubmit?: () => void }) {
  return (
    <EmptyState
      icon={
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none" className="text-[var(--color-immune)]">
          <circle cx="24" cy="24" r="20" stroke="currentColor" strokeWidth="2" />
          <path d="M16 24l6 6 10-12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      }
      title="No threats detected"
      description="Submit a threat sample to begin analysis. IMMUNIS will detect, classify, and synthesise antibodies automatically."
      action={onSubmit ? { label: 'Submit Threat', onClick: onSubmit } : undefined}
    />
  );
}

export function EmptyAntibodies() {
  return (
    <EmptyState
      icon={
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none" className="text-[var(--color-immune)]">
          <path d="M24 4v40M4 24h40M12 12l24 24M36 12L12 36" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          <circle cx="24" cy="24" r="6" stroke="currentColor" strokeWidth="2" />
        </svg>
      }
      title="No antibodies synthesised"
      description="Antibodies are created when threats are analysed. Each antibody is formally verified and stress-tested before deployment."
    />
  );
}

export function EmptyScanResults({ onScan }: { onScan?: () => void }) {
  return (
    <EmptyState
      icon={
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none" className="text-[var(--text-muted)]">
          <circle cx="20" cy="20" r="14" stroke="currentColor" strokeWidth="2" />
          <path d="M30 30l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      }
      title="No scan results"
      description="Run a vulnerability scan to identify security issues in your code, infrastructure, and configuration."
      action={onScan ? { label: 'Run Scan', onClick: onScan } : undefined}
    />
  );
}

export function EmptyCompliance() {
  return (
    <EmptyState
      icon={
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none" className="text-[var(--text-muted)]">
          <rect x="8" y="6" width="32" height="36" rx="4" stroke="currentColor" strokeWidth="2" />
          <path d="M16 18h16M16 24h12M16 30h8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      }
      title="No compliance data"
      description="Run a compliance assessment to evaluate your security posture against POPIA, NIST, MITRE ATT&CK, and other frameworks."
    />
  );
}

export type { EmptyStateProps };
export default EmptyState;
