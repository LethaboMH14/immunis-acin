// frontend/src/pages/ScannerPage.tsx
// Scanner — 4-layer vulnerability scanning with AI copilot
// WHY: IMMUNIS doesn't just defend against external threats — it examines
// its own infrastructure. This page demonstrates self-assessment capability.

import React, { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Tabs } from '../components/common/Tabs';
import { Card } from '../components/common/Card';
import { Button } from '../components/common/Button';
import { Badge } from '../components/common/Badge';
import { ProgressBar } from '../components/common/ProgressBar';
import { EmptyScanResults } from '../components/common/EmptyState';
import { ScanResultsList } from '../components/scanner/ScanResultsList';
import { ScanSummary } from '../components/scanner/ScanSummary';
import { useMutation, useApi } from '../hooks/useApi';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ScanResult {
  id: string;
  type: 'sast' | 'dast' | 'infrastructure';
  severity: string;
  title: string;
  description: string;
  location?: string;
  remediation?: string;
  confidence?: number;
  timestamp: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'sast', label: 'SAST', count: 0 },
  { id: 'dast', label: 'DAST', count: 0 },
  { id: 'infra', label: 'Infrastructure', count: 0 },
  { id: 'results', label: 'All Results' },
];

// ─── Component ────────────────────────────────────────────────────────────────

function ScannerPage() {
  const [activeTab, setActiveTab] = useState('results');

  // API
  const resultsQuery = useApi<{ results: ScanResult[] }>('/api/scanner/results', {
    immediate: true,
    pollInterval: 10000,
  });

  const sastMutation = useMutation<{ target?: string }, { status: string }>('/api/scanner/static');
  const dastMutation = useMutation<{ target_url?: string }, { status: string }>('/api/scanner/dynamic');
  const infraMutation = useMutation<Record<string, never>, { status: string }>('/api/scanner/infra');

  const results = resultsQuery.data?.results ?? [];
  const isScanning = sastMutation.isLoading || dastMutation.isLoading || infraMutation.isLoading;

  // Group results by type
  const sastResults = results.filter((r) => r.type === 'sast');
  const dastResults = results.filter((r) => r.type === 'dast');
  const infraResults = results.filter((r) => r.type === 'infrastructure');

  const handleRunSast = useCallback(async () => {
    await sastMutation.mutate({ target: 'backend/' });
    resultsQuery.fetch();
  }, [sastMutation, resultsQuery]);

  const handleRunDast = useCallback(async () => {
    await dastMutation.mutate({ target_url: 'http://localhost:8000' });
    resultsQuery.fetch();
  }, [dastMutation, resultsQuery]);

  const handleRunInfra = useCallback(async () => {
    await infraMutation.mutate({});
    resultsQuery.fetch();
  }, [infraMutation, resultsQuery]);

  const handleRunAll = useCallback(async () => {
    await Promise.all([
      sastMutation.mutate({ target: 'backend/' }),
      dastMutation.mutate({ target_url: 'http://localhost:8000' }),
      infraMutation.mutate({}),
    ]);
    resultsQuery.fetch();
  }, [sastMutation, dastMutation, infraMutation, resultsQuery]);

  // Update tab counts
  const tabsWithCounts = TABS.map((tab) => {
    if (tab.id === 'sast') return { ...tab, count: sastResults.length };
    if (tab.id === 'dast') return { ...tab, count: dastResults.length };
    if (tab.id === 'infra') return { ...tab, count: infraResults.length };
    return tab;
  });

  const activeResults =
    activeTab === 'sast' ? sastResults :
    activeTab === 'dast' ? dastResults :
    activeTab === 'infra' ? infraResults :
    results;

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
            Vulnerability Scanner
          </h2>
          <p className="text-sm text-[var(--text-muted)]">
            SAST + DAST + Infrastructure audit with AI copilot
          </p>
        </div>
        <div className="flex items-center gap-2">
          {isScanning && (
            <Badge variant="warning" dot>Scanning...</Badge>
          )}
          <Button
            variant="primary"
            size="sm"
            onClick={handleRunAll}
            isLoading={isScanning}
          >
            Run All Scans
          </Button>
        </div>
      </div>

      {/* Summary cards */}
      <ScanSummary
        totalFindings={results.length}
        critical={results.filter((r) => r.severity === 'critical').length}
        high={results.filter((r) => r.severity === 'high').length}
        medium={results.filter((r) => r.severity === 'medium').length}
        low={results.filter((r) => r.severity === 'low').length}
      />

      {/* Tabs */}
      <div className="flex items-center justify-between">
        <Tabs tabs={tabsWithCounts} activeTab={activeTab} onTabChange={setActiveTab} />

        {/* Per-tab scan button */}
        {activeTab !== 'results' && (
          <Button
            variant="outline"
            size="sm"
            onClick={
              activeTab === 'sast' ? handleRunSast :
              activeTab === 'dast' ? handleRunDast :
              handleRunInfra
            }
            isLoading={
              activeTab === 'sast' ? sastMutation.isLoading :
              activeTab === 'dast' ? dastMutation.isLoading :
              infraMutation.isLoading
            }
          >
            Run {activeTab.toUpperCase()} Scan
          </Button>
        )}
      </div>

      {/* Results */}
      {activeResults.length === 0 ? (
        <EmptyScanResults onScan={handleRunAll} />
      ) : (
        <ScanResultsList results={activeResults} />
      )}
    </motion.div>
  );
}

export default ScannerPage;
