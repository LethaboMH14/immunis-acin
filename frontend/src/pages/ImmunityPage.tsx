// frontend/src/pages/ImmunityPage.tsx
// Immunity library — all synthesised antibodies
// WHY: The antibody library is the immune memory. This page shows every
// defence the system has learned, with verification and strength data.

import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useImmunis } from '../hooks/useImmunis';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { Input } from '../components/common/Input';
import { Select } from '../components/common/Select';
import { ProgressBar } from '../components/common/ProgressBar';
import { SlidePanel } from '../components/common/SlidePanel';
import { EmptyAntibodies } from '../components/common/EmptyState';
import { formatRelativeTime } from '../utils/formatters';
import type { Antibody } from '../utils/types';

// ─── Constants ────────────────────────────────────────────────────────────────

const STATUS_OPTIONS = [
  { value: '', label: 'All Statuses' },
  { value: 'promoted', label: 'Promoted' },
  { value: 'testing', label: 'Testing' },
  { value: 'pending', label: 'Pending' },
  { value: 'failed', label: 'Failed' },
];

// ─── Component ────────────────────────────────────────────────────────────────

function ImmunityPage() {
  const { antibodies } = useImmunis();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [selectedAntibody, setSelectedAntibody] = useState<Antibody | null>(null);

  const filtered = useMemo(() => {
    return antibodies.filter((ab) => {
      if (statusFilter && ab.status !== statusFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        const matchId = ab.id?.toLowerCase().includes(q);
        const matchFamily = (ab.family || ab.type || '').toLowerCase().includes(q);
        if (!matchId && !matchFamily) return false;
      }
      return true;
    });
  }, [antibodies, search, statusFilter]);

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
            Immune Library
          </h2>
          <p className="text-sm text-[var(--text-muted)]">
            {antibodies.length} antibodies · Z3 verified · Battleground tested
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-end gap-4">
        <div className="flex-1 max-w-xs">
          <Input
            placeholder="Search by ID or family..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            clearable
            onClear={() => setSearch('')}
            inputSize="sm"
          />
        </div>
        <div className="w-40">
          <Select
            options={STATUS_OPTIONS}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            selectSize="sm"
          />
        </div>
        <span className="text-xs text-[var(--text-muted)] pb-2">
          {filtered.length} of {antibodies.length}
        </span>
      </div>

      {/* Grid */}
      {filtered.length === 0 ? (
        antibodies.length === 0 ? (
          <EmptyAntibodies />
        ) : (
          <div className="py-12 text-center">
            <p className="text-sm text-[var(--text-muted)]">No antibodies match your filters</p>
          </div>
        )
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <AnimatePresence>
            {filtered.map((ab, i) => {
              const strength = typeof ab.strength === 'number' ? ab.strength : 0;
              const strengthPct = Math.round(strength * 100);

              return (
                <motion.div
                  key={ab.id}
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  transition={{ delay: i * 0.02, duration: 0.2 }}
                >
                  <Card
                    variant="default"
                    padding="md"
                    hoverable
                    onClick={() => setSelectedAntibody(ab)}
                  >
                    {/* Header */}
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <p className="text-sm font-semibold text-[var(--text-primary)]">
                          {ab.family || ab.type || 'Unknown'}
                        </p>
                        <p className="text-[10px] font-mono text-[var(--text-muted)] mt-0.5">
                          {ab.id?.slice(0, 16)}
                        </p>
                      </div>
                      <Badge
                        variant={
                          ab.status === 'promoted' ? 'immune' :
                          ab.status === 'testing' ? 'warning' :
                          ab.status === 'failed' ? 'threat' : 'neutral'
                        }
                      >
                        {ab.status || 'pending'}
                      </Badge>
                    </div>

                    {/* Strength */}
                    <div className="mb-3">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[10px] text-[var(--text-muted)]">Strength</span>
                        <span className="text-[10px] font-mono text-[var(--text-muted)] tabular-nums">
                          {strengthPct}%
                        </span>
                      </div>
                      <ProgressBar
                        value={strengthPct}
                        variant={strengthPct >= 80 ? 'immune' : strengthPct >= 50 ? 'warning' : 'threat'}
                        size="sm"
                      />
                    </div>

                    {/* Footer */}
                    <div className="flex items-center justify-between text-[10px] text-[var(--text-muted)]">
                      <span>{formatRelativeTime(ab.created_at || ab.timestamp)}</span>
                      {ab.verified && (
                        <Badge variant="immune">Z3 ✓</Badge>
                      )}
                    </div>
                  </Card>
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>
      )}

      {/* Detail panel */}
      <SlidePanel
        isOpen={!!selectedAntibody}
        onClose={() => setSelectedAntibody(null)}
        title="Antibody Details"
        subtitle={selectedAntibody?.id}
        size="md"
      >
        {selectedAntibody && (
          <div className="space-y-4">
            <div className="space-y-2">
              <p className="text-xs text-[var(--text-muted)]">Family</p>
              <p className="text-sm font-medium text-[var(--text-primary)]">
                {selectedAntibody.family || selectedAntibody.type}
              </p>
            </div>
            <div className="space-y-2">
              <p className="text-xs text-[var(--text-muted)]">Status</p>
              <Badge
                variant={
                  selectedAntibody.status === 'promoted' ? 'immune' :
                  selectedAntibody.status === 'failed' ? 'threat' : 'neutral'
                }
              >
                {selectedAntibody.status}
              </Badge>
            </div>
            <div className="space-y-2">
              <p className="text-xs text-[var(--text-muted)]">Detection Rule</p>
              <pre className="p-3 rounded-lg bg-[var(--bg-tertiary)] text-xs font-mono text-[var(--text-secondary)] whitespace-pre-wrap overflow-x-auto max-h-48">
                {selectedAntibody.rule || selectedAntibody.detection_logic || '[Rule data not available]'}
              </pre>
            </div>
          </div>
        )}
      </SlidePanel>
    </motion.div>
  );
}

export default ImmunityPage;
