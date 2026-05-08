// frontend/src/components/threats/ThreatDetail.tsx
// Threat detail — full incident information in slide panel
// WHY: Clicking a threat in the feed opens this view. SOC analysts need
// complete context: what was detected, how it was classified, what defence
// was synthesised, and the raw evidence.

import React from 'react';
import { Badge } from '../common/Badge';
import { ProgressBar } from '../common/ProgressBar';
import { formatDateTime, formatRelativeTime } from '../../utils/formatters';
import type { Threat } from '../../utils/types';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ThreatDetailProps {
  threat: Threat;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getSeverityVariant(severity: string) {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'critical' as const;
    case 'high': return 'high' as const;
    case 'medium': return 'medium' as const;
    case 'low': return 'low' as const;
    default: return 'info' as const;
  }
}

function getClassificationVariant(classification: string) {
  switch (classification?.toLowerCase()) {
    case 'novel': return 'novel' as const;
    case 'variant': return 'warning' as const;
    case 'known': return 'immune' as const;
    default: return 'neutral' as const;
  }
}

// ─── Section Component ────────────────────────────────────────────────────────

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="py-3 border-b border-[var(--border-subtle)] last:border-b-0">
      <h4 className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] mb-2">
        {label}
      </h4>
      {children}
    </div>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between py-1">
      <span className="text-xs text-[var(--text-muted)]">{label}</span>
      <span className="text-xs font-medium text-[var(--text-primary)] text-right max-w-[60%]">
        {value || '—'}
      </span>
    </div>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

export function ThreatDetail({ threat }: ThreatDetailProps) {
  return (
    <div className="space-y-0">
      {/* Classification header */}
      <Section label="Classification">
        <div className="flex flex-wrap gap-2 mb-2">
          <Badge variant={getSeverityVariant(threat.severity)} dot>
            {threat.severity}
          </Badge>
          <Badge variant={getClassificationVariant(threat.classification)}>
            {threat.classification}
          </Badge>
          {threat.language && (
            <Badge variant="neutral">
              {threat.language.toUpperCase()}
            </Badge>
          )}
        </div>
        <Field label="Family" value={threat.family || threat.type} />
        <Field label="Vector" value={threat.vector} />
        <Field label="Incident ID" value={
          <span className="font-mono text-[10px]">{threat.id}</span>
        } />
      </Section>

      {/* Timing */}
      <Section label="Timeline">
        <Field label="Detected" value={formatDateTime(threat.timestamp)} />
        <Field label="Relative" value={formatRelativeTime(threat.timestamp)} />
      </Section>

      {/* Scores */}
      <Section label="Analysis Scores">
        {threat.surprise_score !== undefined && (
          <div className="mb-2">
            <Field label="Surprise Score" value={`${threat.surprise_score?.toFixed(2)} bits`} />
            <ProgressBar
              value={Math.min((threat.surprise_score || 0) / 12 * 100, 100)}
              variant={
                (threat.surprise_score || 0) >= 8 ? 'threat' :
                (threat.surprise_score || 0) >= 3 ? 'warning' : 'immune'
              }
              size="sm"
            />
          </div>
        )}
        {threat.confidence !== undefined && (
          <Field label="Confidence" value={`${(threat.confidence * 100).toFixed(1)}%`} />
        )}
      </Section>

      {/* Summary */}
      {threat.summary && (
        <Section label="Summary">
          <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
            {threat.summary}
          </p>
        </Section>
      )}

      {/* Raw Content */}
      <Section label="Raw Content">
        <div className="p-3 rounded-lg bg-[var(--bg-tertiary)] max-h-48 overflow-y-auto">
          <pre className="text-xs font-mono text-[var(--text-secondary)] whitespace-pre-wrap break-words">
            {threat.content || '[Content redacted]'}
          </pre>
        </div>
      </Section>

      {/* Fingerprint */}
      {threat.fingerprint && (
        <Section label="Fingerprint">
          <div className="p-2 rounded bg-[var(--bg-tertiary)]">
            <span className="text-[10px] font-mono text-[var(--text-muted)] break-all">
              {typeof threat.fingerprint === 'string'
                ? threat.fingerprint
                : JSON.stringify(threat.fingerprint).slice(0, 120) + '...'}
            </span>
          </div>
        </Section>
      )}
    </div>
  );
}

export type { ThreatDetailProps };
export default ThreatDetail;
