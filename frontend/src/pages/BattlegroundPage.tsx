// frontend/src/pages/BattlegroundPage.tsx
// Battleground — Red vs Blue adversarial coevolution arena
// WHY: The most visually dramatic page. Red Agent attacks, Blue defends,
// Arbiter judges. This is the WGAN-GP loop made visible.

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useImmunis } from '../hooks/useImmunis';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { ProgressBar } from '../components/common/ProgressBar';
import { EmptyState } from '../components/common/EmptyState';
import { BattlegroundArena } from '../components/visualizations/BattlegroundArena';
import { HoneypotSandbox } from '../components/visualizations/HoneypotSandbox';
import { ArmsRaceChart, BattleHistory } from '../components/battleground';

// ─── Component ────────────────────────────────────────────────────────────────

function BattlegroundPage() {
  const { battlegroundHistory, evolutionTimeline } = useImmunis();
  
  // Autonomous loop state
  const [autonomousStatus, setAutonomousStatus] = useState(null);
  const [isLoadingStatus, setIsLoadingStatus] = useState(false);

  const latestBattle = battlegroundHistory.length > 0 ? battlegroundHistory[0] : null;

  // Fetch autonomous status on mount and periodically
  useEffect(() => {
    const fetchAutonomousStatus = async () => {
      try {
        setIsLoadingStatus(true);
        const response = await fetch('/api/battleground/autonomous/status');
        if (response.ok) {
          const status = await response.json();
          setAutonomousStatus(status);
        }
      } catch (error) {
        console.error('Failed to fetch autonomous status:', error);
      } finally {
        setIsLoadingStatus(false);
      }
    };

    fetchAutonomousStatus();
    const interval = setInterval(fetchAutonomousStatus, 5000); // Update every 5s
    return () => clearInterval(interval);
  }, []);

  // Control functions
  const handleStartAutonomous = async () => {
    try {
      const response = await fetch('/api/battleground/autonomous/start', { method: 'POST' });
      if (response.ok) {
        const result = await response.json();
        setAutonomousStatus(result.status);
      }
    } catch (error) {
      console.error('Failed to start autonomous loop:', error);
    }
  };

  const handleStopAutonomous = async () => {
    try {
      const response = await fetch('/api/battleground/autonomous/stop', { method: 'POST' });
      if (response.ok) {
        const result = await response.json();
        setAutonomousStatus(result.status);
      }
    } catch (error) {
      console.error('Failed to stop autonomous loop:', error);
    }
  };

  const handleTriggerRound = async () => {
    try {
      const response = await fetch('/api/battleground/autonomous/trigger', { method: 'POST' });
      if (response.ok) {
        const result = await response.json();
        console.log('Round triggered:', result);
      }
    } catch (error) {
      console.error('Failed to trigger round:', error);
    }
  };

  // Format next round time
  const getNextRoundText = () => {
    if (!autonomousStatus?.next_round_in_seconds) return '';
    const seconds = Math.round(autonomousStatus.next_round_in_seconds);
    if (seconds <= 0) return 'starting now...';
    if (seconds < 60) return `next in ${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `next in ${minutes}m ${remainingSeconds}s`;
  };

  // Aggregate stats
  const totalRounds = battlegroundHistory.reduce(
    (sum, b) => sum + (b.rounds?.length ?? 0), 0
  );
  const redWins = battlegroundHistory.reduce(
    (sum, b) => sum + (b.red_wins ?? 0), 0
  );
  const blueWins = battlegroundHistory.reduce(
    (sum, b) => sum + (b.blue_wins ?? 0), 0
  );
  const blueRate = totalRounds > 0 ? (blueWins / (redWins + blueWins)) * 100 : 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      {/* Header */}
      <div className="flex flex-col space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-[var(--text-primary)]">
              Adversarial Battleground
            </h2>
            <p className="text-sm text-[var(--text-muted)]">
              WGAN-GP coevolution — Red Agent vs Blue Defender
            </p>
          </div>
          {latestBattle && (
            <Badge variant={latestBattle.result === 'blue_wins' ? 'immune' : 'threat'} dot>
              {latestBattle.result === 'blue_wins' ? 'Blue Dominant' : 'Red Advancing'}
            </Badge>
          )}
        </div>
        
        {/* Autonomous Loop Status & Controls */}
        <div className="flex items-center justify-between bg-[var(--bg-secondary)] rounded-lg p-3">
          <div className="flex items-center space-x-3">
            {/* Status Badge */}
            {isLoadingStatus ? (
              <Badge variant="neutral">Loading...</Badge>
            ) : autonomousStatus ? (
              <Badge 
                variant={autonomousStatus.enabled ? 'immune' : 'neutral'} 
                dot={autonomousStatus.running}
              >
                {autonomousStatus.enabled ? '🟢 Autonomous Loop Active' : '🟡 Autonomous Loop Paused'}
                {autonomousStatus.enabled && (
                  <span className="ml-2 text-xs">
                    — Round {autonomousStatus.rounds_completed} ({getNextRoundText()})
                  </span>
                )}
              </Badge>
            ) : (
              <Badge variant="neutral">Status unavailable</Badge>
            )}
            
            {/* Quick Stats */}
            {autonomousStatus && (
              <div className="flex items-center space-x-4 text-xs text-[var(--text-muted)]">
                <span>Antibodies: {autonomousStatus.antibodies_synthesised}</span>
                <span>Red: {autonomousStatus.red_wins}</span>
                <span>Blue: {autonomousStatus.blue_wins}</span>
                <span>Errors: {autonomousStatus.consecutive_errors}</span>
              </div>
            )}
          </div>
          
          {/* Control Buttons */}
          <div className="flex items-center space-x-2">
            <button
              onClick={handleTriggerRound}
              className="px-3 py-1 text-xs bg-[var(--color-primary)] text-white rounded hover:opacity-80 transition-opacity"
              disabled={!autonomousStatus?.enabled}
            >
              Force Round Now
            </button>
            {autonomousStatus?.enabled ? (
              <button
                onClick={handleStopAutonomous}
                className="px-3 py-1 text-xs bg-red-500 text-white rounded hover:opacity-80 transition-opacity"
              >
                Pause Loop
              </button>
            ) : (
              <button
                onClick={handleStartAutonomous}
                className="px-3 py-1 text-xs bg-green-500 text-white rounded hover:opacity-80 transition-opacity"
              >
                Resume Loop
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card variant="flat" padding="md">
          <p className="text-2xl font-bold text-[var(--text-primary)] tabular-nums">
            {battlegroundHistory.length}
          </p>
          <p className="text-xs text-[var(--text-muted)]">Battle Sessions</p>
        </Card>
        <Card variant="flat" padding="md">
          <p className="text-2xl font-bold text-red-400 tabular-nums">{redWins}</p>
          <p className="text-xs text-[var(--text-muted)]">Red Wins</p>
        </Card>
        <Card variant="flat" padding="md">
          <p className="text-2xl font-bold text-[var(--color-immune)] tabular-nums">{blueWins}</p>
          <p className="text-xs text-[var(--text-muted)]">Blue Wins</p>
        </Card>
        <Card variant="flat" padding="md">
          <p className="text-2xl font-bold text-[var(--text-primary)] tabular-nums">
            {blueRate.toFixed(0)}%
          </p>
          <p className="text-xs text-[var(--text-muted)]">Blue Win Rate</p>
          <ProgressBar value={blueRate} variant="immune" size="sm" className="mt-2" />
        </Card>
      </div>

      {/* Cinematic visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7">
          <BattlegroundArena
            redWins={redWins}
            blueWins={blueWins}
            isActive={battlegroundHistory.length > 0}
            currentRound={latestBattle?.rounds?.length ?? 0}
          />
        </div>
        <div className="lg:col-span-5">
          <HoneypotSandbox isActive={true} />
        </div>
      </div>

      {/* Content */}
      {battlegroundHistory.length === 0 ? (
        <EmptyState
          title="No battles yet"
          description="Battle sessions begin automatically when antibodies are synthesised. Submit a threat to trigger the adversarial stress test."
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Arms race chart */}
          <div className="lg:col-span-7">
            <ArmsRaceChart history={battlegroundHistory} />
          </div>

          {/* Battle history */}
          <div className="lg:col-span-5">
            <BattleHistory sessions={battlegroundHistory.slice(0, 15)} />
          </div>
        </div>
      )}
    </motion.div>
  );
}

export default BattlegroundPage;
