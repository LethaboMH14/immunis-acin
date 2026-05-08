// frontend/src/components/compliance/ReportGenerator.tsx
// Report generator — 6 auto-generated regulatory report types
// WHY: Compliance reporting is tedious manual work. IMMUNIS generates
// statutory reports (POPIA S22, Cybercrimes S54) automatically, complete
// with Merkle-anchored evidence chains and regulatory references.

import React, { useState } from 'react';
import { Card } from '../common/Card';
import { Button } from '../common/Button';
import { Badge } from '../common/Badge';
import { useMutation } from '../../hooks/useApi';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ReportType {
  id: string;
  name: string;
  description: string;
  badge: string;
  badgeVariant: 'critical' | 'high' | 'medium' | 'info' | 'immune' | 'novel' | 'neutral';
}

interface GeneratedReport {
  report_id: string;
  type: string;
  status: string;
  download_url?: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const REPORT_TYPES: ReportType[] = [
  {
    id: 'popia_s22',
    name: 'POPIA Section 22',
    description: 'Breach notification to the Information Regulator. 7 statutory sections.',
    badge: 'Mandatory',
    badgeVariant: 'critical',
  },
  {
    id: 'cybercrimes_s54',
    name: 'Cybercrimes Act S54',
    description: 'SAPS reporting within 72 hours. 5 required sections.',
    badge: 'Mandatory',
    badgeVariant: 'critical',
  },
  {
    id: 'gdpr_art33',
    name: 'GDPR Article 33',
    description: 'Supervisory authority notification. 5 sections with DPA mapping.',
    badge: 'EU',
    badgeVariant: 'novel',
  },
  {
    id: 'executive_summary',
    name: 'Executive Summary',
    description: 'Board-ready compliance posture with risk quantification.',
    badge: 'CISO',
    badgeVariant: 'info',
  },
  {
    id: 'audit_package',
    name: 'Audit Package',
    description: 'Complete evidence package for external auditors. 7 sections.',
    badge: 'Auditor',
    badgeVariant: 'neutral',
  },
  {
    id: 'incident_report',
    name: 'Incident Report',
    description: 'Internal IR team documentation with timeline and evidence.',
    badge: 'IR',
    badgeVariant: 'immune',
  },
];

// ─── Component ────────────────────────────────────────────────────────────────

export function ReportGenerator({ className = '' }: { className?: string }) {
  const [generatedReports, setGeneratedReports] = useState<Record<string, GeneratedReport>>({});

  const reportMutation = useMutation<
    { report_type: string },
    GeneratedReport
  >('/api/compliance/report');

  const handleGenerate = async (reportType: string) => {
    const result = await reportMutation.mutate({ report_type: reportType });
    if (result) {
      setGeneratedReports((prev) => ({
        ...prev,
        [reportType]: result,
      }));
    }
  };

  return (
    <Card
      title="Generate Reports"
      actions={
        <span className="text-[10px] text-[var(--text-muted)]">
          SHA-256 integrity · Merkle-anchored · UTC timestamps
        </span>
      }
      padding="md"
      className={className}
    >
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {REPORT_TYPES.map((report) => {
          const generated = generatedReports[report.id];
          const isGenerating = reportMutation.isLoading;

          return (
            <div
              key={report.id}
              className="p-3 rounded-lg border border-[var(--border-subtle)] hover:border-[var(--border-primary)] transition-colors"
            >
              <div className="flex items-start justify-between mb-2">
                <h4 className="text-sm font-semibold text-[var(--text-primary)]">
                  {report.name}
                </h4>
                <Badge variant={report.badgeVariant}>{report.badge}</Badge>
              </div>
              <p className="text-xs text-[var(--text-muted)] mb-3 leading-relaxed">
                {report.description}
              </p>
              <div className="flex items-center gap-2">
                {generated ? (
                  <Badge variant="immune">Generated</Badge>
                ) : (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleGenerate(report.id)}
                    isLoading={isGenerating}
                  >
                    Generate
                  </Button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

export type { ReportGenerator as ReportGeneratorComponent };
export default ReportGenerator;
