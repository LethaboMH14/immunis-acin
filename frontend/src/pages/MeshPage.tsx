// frontend/src/pages/MeshPage.tsx
// Mesh Network — P2P antibody distribution visualization
// WHY: The mesh is what makes IMMUNIS collective. One organisation's
// immunity becomes everyone's immunity. This page shows it happening.

import React from 'react';
import { motion } from 'framer-motion';
import { useImmunis } from '../hooks/useImmunis';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { StatusIndicator } from '../components/layout/StatusIndicator';
import { EmptyState } from '../components/common/EmptyState';
import { formatRelativeTime } from '../utils/formatters';
import { MeshVisualization } from '../components/visualizations/MeshVisualization';

// ─── Component ────────────────────────────────────────────────────────────────

function MeshPage() {
  const { meshNodes, epidemiologicalState } = useImmunis();

  const connectedNodes = meshNodes.filter((n) => n.status === 'connected');
  const r0 = epidemiologicalState?.r0 ?? 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      {/* Header */}
      <div>
        <h2 className="text-lg font-semibold text-[var(--text-primary)]">
          Antibody Mesh Network
        </h2>
        <p className="text-sm text-[var(--text-muted)]">
          Hybrid Ed25519 + CRYSTALS-Dilithium · R₀-priority gossip · STIX/TAXII 2.1
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card variant="flat" padding="md">
          <p className="text-2xl font-bold text-[var(--text-primary)] tabular-nums">{meshNodes.length}</p>
          <p className="text-xs text-[var(--text-muted)]">Total Nodes</p>
        </Card>
        <Card variant="flat" padding="md">
          <p className="text-2xl font-bold text-[var(--color-immune)] tabular-nums">{connectedNodes.length}</p>
          <p className="text-xs text-[var(--text-muted)]">Connected</p>
        </Card>
        <Card variant="flat" padding="md">
          <p className="text-2xl font-bold text-[var(--color-mesh,#38BDF8)] tabular-nums">{r0.toFixed(2)}</p>
          <p className="text-xs text-[var(--text-muted)]">R₀ (Immunity)</p>
        </Card>
        <Card variant="flat" padding="md">
          <p className="text-2xl font-bold text-purple-400 tabular-nums">
            {epidemiologicalState?.herd_immunity_pct?.toFixed(0) ?? 0}%
          </p>
          <p className="text-xs text-[var(--text-muted)]">Herd Immunity</p>
        </Card>
      </div>

      {meshNodes.length === 0 ? (
        <EmptyState
          title="No mesh nodes"
          description="Mesh nodes appear when the P2P network is active. Antibody broadcasts will propagate across connected nodes."
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Network visualization */}
          <div className="lg:col-span-5">
            <MeshVisualization nodes={meshNodes} />
          </div>

          {/* Node list */}
          <div className="lg:col-span-7">
            <Card title="Nodes" padding="none">
              <div className="divide-y divide-[var(--border-subtle)]">
                {meshNodes.map((node, i) => (
                  <div
                    key={node.node_id || i}
                    className="flex items-center gap-3 px-4 py-3 hover:bg-[var(--bg-tertiary)] transition-colors"
                  >
                    <StatusIndicator
                      status={node.status === 'connected' ? 'online' : 'offline'}
                      showLabel={false}
                    />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-[var(--text-primary)]">
                        {node.hostname || node.city || `Node ${node.node_id?.slice(0, 8)}`}
                      </p>
                      <p className="text-[10px] text-[var(--text-muted)] font-mono">
                        {node.ip_address || node.node_id}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      {node.latency_ms !== undefined && (
                        <span className="text-[10px] font-mono text-[var(--text-muted)] tabular-nums">
                          {node.latency_ms}ms
                        </span>
                      )}
                      <Badge variant={node.status === 'connected' ? 'immune' : 'threat'}>
                        {node.status}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      )}
    </motion.div>
  );
}

export default MeshPage;
