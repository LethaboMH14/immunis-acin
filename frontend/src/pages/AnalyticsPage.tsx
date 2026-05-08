// frontend/src/pages/AnalyticsPage.tsx
// Analytics — aggregate metrics, trends, and mathematical engine outputs
// WHY: This page showcases the 7 mathematical engines. Judges see actuarial
// risk, game theory, epidemiology, and portfolio optimisation — all computed
// from real data, not mock values.

import React from 'react';
import { motion } from 'framer-motion';
import { useImmunis } from '../hooks/useImmunis';
import { useApi } from '../hooks/useApi';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { ProgressBar, CircularProgress } from '../components/common/ProgressBar';
import { EvolutionSparkline } from '../components/overview/EvolutionSparkline';

// ─── Types ────────────────────────────────────────────────────────────────────

interface RiskPortfolio {
  expected_loss: number;
  var_95: number;
  cvar_95: number;
  annual_expected_loss: number;
  deterrence_index: number;
}

interface PortfolioAllocation {
  assets: { name: string; weight: number; sharpe: number }[];
  total_budget: number;
  expected_return: number;
}

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
  visible: { opacity: 1, y: 0, transition: { duration: 0.3 } },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatZAR(value: number): string {
  if (value >= 1_000_000) return `R${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `R${(value / 1_000).toFixed(0)}K`;
  return `R${value.toFixed(0)}`;
}

// ─── Component ────────────────────────────────────────────────────────────────

function AnalyticsPage() {
  const { evolutionTimeline, epidemiologicalState, immunityScore, threats, antibodies } = useImmunis();

  const riskQuery = useApi<RiskPortfolio>('/api/risk/portfolio', { immediate: true });
  const portfolioQuery = useApi<PortfolioAllocation>('/api/risk/allocation', { immediate: true });

  const risk = riskQuery.data;
  const portfolio = portfolioQuery.data;

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-6"
    >
      {/* Header */}
      <div>
        <h2 className="text-lg font-semibold text-[var(--text-primary)]">
          Analytics & Mathematical Engines
        </h2>
        <p className="text-sm text-[var(--text-muted)]">
          7 engines: KDE · GPD · SIR · Stackelberg · PID · Lotka-Volterra · Markowitz
        </p>
      </div>

      {/* Row 1: Key metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <motion.div variants={itemVariants}>
          <Card variant="flat" padding="md">
            <p className="text-2xl font-bold text-[var(--color-immune)] tabular-nums">{immunityScore}</p>
            <p className="text-xs text-[var(--text-muted)]">Immunity Score</p>
            <p className="text-[10px] text-[var(--text-muted)] mt-1">PID-controlled</p>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card variant="flat" padding="md">
            <p className="text-2xl font-bold text-[var(--text-primary)] tabular-nums">{threats.length}</p>
            <p className="text-xs text-[var(--text-muted)]">Threats Analysed</p>
            <p className="text-[10px] text-[var(--text-muted)] mt-1">KDE surprise</p>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card variant="flat" padding="md">
            <p className="text-2xl font-bold text-[var(--text-primary)] tabular-nums">{antibodies.length}</p>
            <p className="text-xs text-[var(--text-muted)]">Antibodies</p>
            <p className="text-[10px] text-[var(--text-muted)] mt-1">Z3 verified</p>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card variant="flat" padding="md">
            <p className="text-2xl font-bold text-[var(--color-mesh,#38BDF8)] tabular-nums">
              {epidemiologicalState?.r0?.toFixed(2) ?? '—'}
            </p>
            <p className="text-xs text-[var(--text-muted)]">R₀ (Immunity)</p>
            <p className="text-[10px] text-[var(--text-muted)] mt-1">SIR model</p>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card variant="flat" padding="md">
            <p className="text-2xl font-bold text-amber-400 tabular-nums">
              {risk?.deterrence_index?.toFixed(2) ?? '—'}
            </p>
            <p className="text-xs text-[var(--text-muted)]">Deterrence Index</p>
            <p className="text-[10px] text-[var(--text-muted)] mt-1">Stackelberg SSE</p>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card variant="flat" padding="md">
            <p className="text-2xl font-bold text-purple-400 tabular-nums">
              {risk ? formatZAR(risk.annual_expected_loss) : '—'}
            </p>
            <p className="text-xs text-[var(--text-muted)]">Annual Exp. Loss</p>
            <p className="text-[10px] text-[var(--text-muted)] mt-1">GPD actuarial</p>
          </Card>
        </motion.div>
      </div>

      {/* Row 2: Evolution + Actuarial */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <motion.div variants={itemVariants} className="lg:col-span-7">
          <EvolutionSparkline timeline={evolutionTimeline.slice(-50)} />
        </motion.div>

        <motion.div variants={itemVariants} className="lg:col-span-5">
          <Card title="Actuarial Risk Profile" padding="md">
            {risk ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-[var(--text-muted)]">Expected Loss</span>
                  <span className="text-sm font-mono font-semibold text-[var(--text-primary)]">
                    {formatZAR(risk.expected_loss)}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-[var(--text-muted)]">VaR (95%)</span>
                  <span className="text-sm font-mono font-semibold text-amber-400">
                    {formatZAR(risk.var_95)}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-[var(--text-muted)]">CVaR (95%)</span>
                  <span className="text-sm font-mono font-semibold text-red-400">
                    {formatZAR(risk.cvar_95)}
                  </span>
                </div>
                <div className="pt-2 border-t border-[var(--border-subtle)]">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-[var(--text-muted)]">Deterrence Index</span>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-mono font-semibold text-[var(--text-primary)]">
                        {risk.deterrence_index.toFixed(2)}
                      </span>
                      <Badge variant={risk.deterrence_index > 1 ? 'immune' : 'threat'}>
                        {risk.deterrence_index > 1 ? 'Deterring' : 'Vulnerable'}
                      </Badge>
                    </div>
                  </div>
                  <p className="text-[10px] text-[var(--text-muted)] mt-1">
                    DI {'>'} 1 means attacking is unprofitable (Stackelberg equilibrium)
                  </p>
                </div>
              </div>
            ) : (
              <p className="text-xs text-[var(--text-muted)] text-center py-8">
                No risk data available yet
              </p>
            )}
          </Card>
        </motion.div>
      </div>

      {/* Row 3: Portfolio + Epidemiological */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Portfolio allocation */}
        <motion.div variants={itemVariants} className="lg:col-span-7">
          <Card title="Defensive Portfolio (Markowitz)" padding="md">
            {portfolio && portfolio.assets?.length > 0 ? (
              <div className="space-y-2">
                {portfolio.assets
                  .sort((a, b) => b.weight - a.weight)
                  .slice(0, 8)
                  .map((asset) => (
                    <div key={asset.name}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs text-[var(--text-secondary)] truncate max-w-[200px]">
                          {asset.name}
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono text-[var(--text-muted)] tabular-nums">
                            SR: {asset.sharpe.toFixed(2)}
                          </span>
                          <span className="text-[10px] font-mono text-[var(--text-primary)] tabular-nums w-10 text-right">
                            {(asset.weight * 100).toFixed(1)}%
                          </span>
                        </div>
                      </div>
                      <ProgressBar value={asset.weight * 100} variant="info" size="sm" />
                    </div>
                  ))}
              </div>
            ) : (
              <p className="text-xs text-[var(--text-muted)] text-center py-8">
                No portfolio data available yet
              </p>
            )}
          </Card>
        </motion.div>

        {/* Epidemiological state */}
        <motion.div variants={itemVariants} className="lg:col-span-5">
          <Card title="Epidemiological Model (SIR)" padding="md">
            {epidemiologicalState ? (
              <div className="space-y-4">
                <div className="flex items-center justify-around">
                  <CircularProgress
                    value={((epidemiologicalState.susceptible ?? 0) / (epidemiologicalState.total ?? 1)) * 100}
                    size={60}
                    strokeWidth={5}
                    variant="warning"
                    label="Susceptible"
                  />
                  <CircularProgress
                    value={((epidemiologicalState.infected ?? 0) / (epidemiologicalState.total ?? 1)) * 100}
                    size={60}
                    strokeWidth={5}
                    variant="threat"
                    label="Infected"
                  />
                  <CircularProgress
                    value={((epidemiologicalState.recovered ?? 0) / (epidemiologicalState.total ?? 1)) * 100}
                    size={60}
                    strokeWidth={5}
                    variant="immune"
                    label="Immune"
                  />
                </div>
                <div className="pt-3 border-t border-[var(--border-subtle)] space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-[var(--text-muted)]">R₀</span>
                    <span className="font-mono text-[var(--text-primary)]">
                      {epidemiologicalState.r0?.toFixed(3)}
                    </span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-[var(--text-muted)]">Herd Immunity Threshold</span>
                    <span className="font-mono text-[var(--text-primary)]">
                      {epidemiologicalState.herd_immunity_pct?.toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-[var(--text-muted)]">β (transmission)</span>
                    <span className="font-mono text-[var(--text-primary)]">
                      {epidemiologicalState.beta?.toFixed(4) ?? '—'}
                    </span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-[var(--text-muted)]">γ (recovery)</span>
                    <span className="font-mono text-[var(--text-primary)]">
                      {epidemiologicalState.gamma?.toFixed(4) ?? '—'}
                    </span>
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-xs text-[var(--text-muted)] text-center py-8">
                No epidemiological data available yet
              </p>
            )}
          </Card>
        </motion.div>
      </div>
    </motion.div>
  );
}

export default AnalyticsPage;
