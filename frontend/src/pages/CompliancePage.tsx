// frontend/src/pages/CompliancePage.tsx
// Compliance — 8 frameworks, posture scoring, auto-generated reports
// WHY: Compliance is non-negotiable for South African organisations.
// POPIA and the Cybercrimes Act are mandatory. This page proves IMMUNIS
// can auto-assess and auto-report.

import React, { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Tabs } from '../components/common/Tabs';
import { Card } from '../components/common/Card';
import { Button } from '../components/common/Button';
import { Badge } from '../components/common/Badge';
import { CircularProgress } from '../components/common/ProgressBar';
import { EmptyCompliance } from '../components/common/EmptyState';
import { ControlsList } from '../components/compliance/ControlsList';
import { ReportGenerator } from '../components/compliance/ReportGenerator';
import { useApi, useMutation } from '../hooks/useApi';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ControlAssessment {
  id: string;
  name: string;
  description: string;
  status: 'pass' | 'partial' | 'fail' | 'not_assessed';
  score: number;
  evidence?: string;
}

interface FrameworkPosture {
  framework: string;
  label: string;
  score: number;
  controls: ControlAssessment[];
  last_assessed?: string;
}

interface CompliancePosture {
  overall_score: number;
  frameworks: FrameworkPosture[];
}

// ─── Constants ────────────────────────────────────────────────────────────────

const FRAMEWORK_TABS = [
  { id: 'all', label: 'Overview' },
  { id: 'popia', label: 'POPIA' },
  { id: 'nist', label: 'NIST CSF' },
  { id: 'mitre', label: 'MITRE ATT&CK' },
  { id: 'cis', label: 'CIS Controls' },
  { id: 'owasp_web', label: 'OWASP Top 10' },
  { id: 'owasp_llm', label: 'OWASP LLM' },
  { id: 'cybercrimes', label: 'Cybercrimes Act' },
  { id: 'gdpr', label: 'GDPR' },
];

// ─── Component ────────────────────────────────────────────────────────────────

function CompliancePage() {
  const [activeTab, setActiveTab] = useState('all');

  const postureQuery = useApi<CompliancePosture>('/api/compliance/posture', {
    immediate: true,
  });

  const assessMutation = useMutation<
    { framework?: string },
    { status: string }
  >('/api/compliance/assess');

  const posture = postureQuery.data;
  const frameworks = posture?.frameworks ?? [];

  const handleAssess = useCallback(async () => {
    const framework = activeTab === 'all' ? undefined : activeTab;
    await assessMutation.mutate({ framework });
    postureQuery.fetch();
  }, [activeTab, assessMutation, postureQuery]);

  const activeFramework = activeTab !== 'all'
    ? frameworks.find((f) => f.framework === activeTab)
    : null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-[var(--text-primary)]">
            Compliance Engine
          </h2>
          <p className="text-sm text-[var(--text-muted)]">
            8 regulatory frameworks · 70+ controls · Auto-generated reports
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleAssess}
            isLoading={assessMutation.isLoading}
          >
            {activeTab === 'all' ? 'Assess All' : `Assess ${activeTab.toUpperCase()}`}
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <Tabs
        tabs={FRAMEWORK_TABS}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        variant="pill"
        size="sm"
      />

      {/* Overview mode */}
      {activeTab === 'all' && (
        <>
          {frameworks.length === 0 ? (
            <EmptyCompliance />
          ) : (
            <>
              {/* Overall score */}
              <div className="flex items-center gap-6 mb-4">
                <CircularProgress
                  value={posture?.overall_score ?? 0}
                  size={80}
                  strokeWidth={6}
                  variant={
                    (posture?.overall_score ?? 0) >= 80 ? 'immune' :
                    (posture?.overall_score ?? 0) >= 60 ? 'warning' : 'threat'
                  }
                  label="Overall"
                />
                <div>
                  <p className="text-sm font-medium text-[var(--text-primary)]">
                    Overall Compliance Posture
                  </p>
                  <p className="text-xs text-[var(--text-muted)] mt-0.5">
                    Across {frameworks.length} frameworks, {frameworks.reduce((sum, f) => sum + f.controls.length, 0)} controls
                  </p>
                </div>
              </div>

              {/* Framework grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {frameworks.map((fw) => (
                  <Card
                    key={fw.framework}
                    variant="default"
                    padding="md"
                    hoverable
                    onClick={() => setActiveTab(fw.framework)}
                  >
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="text-sm font-semibold text-[var(--text-primary)]">
                        {fw.label}
                      </h4>
                      <CircularProgress
                        value={fw.score}
                        size={40}
                        strokeWidth={3}
                        variant={
                          fw.score >= 80 ? 'immune' :
                          fw.score >= 60 ? 'warning' : 'threat'
                        }
                        showValue
                      />
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-[var(--text-muted)]">
                        {fw.controls.length} controls
                      </span>
                      <span className="text-[10px] text-[var(--text-muted)]">·</span>
                      <span className="text-[10px] text-emerald-400">
                        {fw.controls.filter((c) => c.status === 'pass').length} pass
                      </span>
                      <span className="text-[10px] text-red-400">
                        {fw.controls.filter((c) => c.status === 'fail').length} fail
                      </span>
                    </div>
                  </Card>
                ))}
              </div>

              {/* Report generator */}
              <ReportGenerator />
            </>
          )}
        </>
      )}

      {/* Single framework mode */}
      {activeTab !== 'all' && activeFramework && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Score + metadata */}
          <div className="lg:col-span-4">
            <Card padding="lg">
              <div className="flex flex-col items-center">
                <CircularProgress
                  value={activeFramework.score}
                  size={100}
                  strokeWidth={8}
                  variant={
                    activeFramework.score >= 80 ? 'immune' :
                    activeFramework.score >= 60 ? 'warning' : 'threat'
                  }
                  label={activeFramework.label}
                />
                <div className="mt-4 w-full space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-[var(--text-muted)]">Pass</span>
                    <span className="text-emerald-400 font-mono tabular-nums">
                      {activeFramework.controls.filter((c) => c.status === 'pass').length}
                    </span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-[var(--text-muted)]">Partial</span>
                    <span className="text-amber-400 font-mono tabular-nums">
                      {activeFramework.controls.filter((c) => c.status === 'partial').length}
                    </span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-[var(--text-muted)]">Fail</span>
                    <span className="text-red-400 font-mono tabular-nums">
                      {activeFramework.controls.filter((c) => c.status === 'fail').length}
                    </span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-[var(--text-muted)]">Not Assessed</span>
                    <span className="text-[var(--text-muted)] font-mono tabular-nums">
                      {activeFramework.controls.filter((c) => c.status === 'not_assessed').length}
                    </span>
                  </div>
                </div>
              </div>
            </Card>
          </div>

          {/* Controls list */}
          <div className="lg:col-span-8">
            <ControlsList controls={activeFramework.controls} />
          </div>
        </div>
      )}

      {/* Framework not found */}
      {activeTab !== 'all' && !activeFramework && (
        <EmptyCompliance />
      )}
    </motion.div>
  );
}

export default CompliancePage;
