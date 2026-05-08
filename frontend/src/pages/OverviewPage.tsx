// frontend/src/pages/OverviewPage.tsx
// Overview — system health at a glance, first impression for judges
// WHY: The hackathon demo starts here. Within 3 seconds, judges must
// understand: this is a living immune system, it's working, it's beautiful.

import React from 'react';
import { motion } from 'framer-motion';
import { useImmunis } from '../hooks/useImmunis';
import { ImmunityRing } from '../components/visualizations/ImmunityRing';
import { MetricCard } from '../components/overview/MetricCard';
import { ThreatFeed } from '../components/overview/ThreatFeed';
import { PipelineStatus } from '../components/overview/PipelineStatus';
import { RecentAntibodies } from '../components/overview/RecentAntibodies';
import { EvolutionSparkline } from '../components/overview/EvolutionSparkline';
import { SystemStatus } from '../components/overview/SystemStatus';
import { QuickActions } from '../components/overview/QuickActions';

// ─── Animation ────────────────────────────────────────────────────────────────

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.06 },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.3, ease: 'easeOut' },
  },
};

// ─── Types ────────────────────────────────────────────────────────────────

interface OverviewPageProps {
  onNavigate: (route: string) => void;
}

// ─── Component ────────────────────────────────────────────────────────────────

function OverviewPage({ onNavigate }: OverviewPageProps) {
  const {
    threats,
    antibodies,
    meshNodes,
    pipelineState,
    immunityScore,
    systemHealth,
    evolutionTimeline,
    isConnected,
  } = useImmunis();

  const threatsToday = threats.filter((t) => {
    const today = new Date();
    const threatDate = new Date(t.timestamp);
    return threatDate.toDateString() === today.toDateString();
  }).length;

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-6"
    >
      {/* Row 1: Hero metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Immunity Gauge — large central element */}
        <motion.div variants={itemVariants} className="lg:col-span-4">
          <ImmunityRing
            score={immunityScore}
            antibodyCount={antibodies.length}
            threatsBlocked={systemHealth?.threats_processed ?? threats.length}
          />
        </motion.div>

        {/* Metric cards */}
        <div className="lg:col-span-8 grid grid-cols-2 md:grid-cols-4 gap-4">
          <motion.div variants={itemVariants}>
            <MetricCard
              label="Threats Processed"
              value={systemHealth?.threats_processed ?? threats.length}
              trend={{ value: threatsToday, direction: threatsToday > 0 ? 'up' : 'neutral', isPositive: false }}
              icon="threats"
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <MetricCard
              label="Antibodies Active"
              value={systemHealth?.antibodies_active ?? antibodies.length}
              trend={{ value: antibodies.length, direction: 'up', isPositive: true }}
              icon="antibodies"
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <MetricCard
              label="Mesh Nodes"
              value={systemHealth?.mesh_nodes ?? meshNodes.length}
              trend={{ value: meshNodes.filter(n => n.status === 'connected').length, direction: 'neutral', isPositive: true }}
              icon="mesh"
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <MetricCard
              label="Pipeline Speed"
              value={pipelineState ? `${pipelineState.stage}/7` : 'Idle'}
              subtitle={pipelineState ? pipelineState.stage_name : 'Ready'}
              icon="pipeline"
            />
          </motion.div>
        </div>
      </div>

      {/* Row 2: Activity + Pipeline */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Threat Feed */}
        <motion.div variants={itemVariants} className="lg:col-span-5">
          <ThreatFeed threats={threats.slice(0, 20)} />
        </motion.div>

        {/* Pipeline Status */}
        <motion.div variants={itemVariants} className="lg:col-span-4">
          <PipelineStatus pipelineState={pipelineState} />
        </motion.div>

        {/* Quick Actions + System Status */}
        <motion.div variants={itemVariants} className="lg:col-span-3 space-y-4">
          <QuickActions
            onSubmitThreat={() => onNavigate('threats')}
            onRunScan={() => onNavigate('scanner')}
            onViewReports={() => onNavigate('compliance')}
            onOpenCopilot={() => onNavigate('copilot')}
          />
          <SystemStatus
            isConnected={isConnected}
            uptime={systemHealth?.uptime ?? 0}
          />
        </motion.div>
      </div>

      {/* Row 3: Antibodies + Evolution */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Recent Antibodies */}
        <motion.div variants={itemVariants} className="lg:col-span-7">
          <RecentAntibodies antibodies={antibodies.slice(0, 8)} />
        </motion.div>

        {/* Evolution Sparkline */}
        <motion.div variants={itemVariants} className="lg:col-span-5">
          <EvolutionSparkline timeline={evolutionTimeline.slice(-50)} />
        </motion.div>
      </div>
    </motion.div>
  );
}

export default OverviewPage;
