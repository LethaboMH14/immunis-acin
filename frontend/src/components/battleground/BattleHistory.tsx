// frontend/src/components/battleground/BattleHistory.tsx
// Battle history — recent adversarial sessions
// WHY: Shows the arms race in action. Each session's red/blue ratio
// tells the story of attack and defence evolution.

import React from 'react';
import { motion } from 'framer-motion';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { formatRelativeTime } from '../../utils/formatters';
import type { BattleSession } from '../../utils/types';

// ─── Types ────────────────────────────────────────────────────────────────────

interface BattleHistoryProps {
  sessions: BattleSession[];
  className?: string;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function BattleHistory({ sessions, className = '' }: BattleHistoryProps) {
  return (
    <Card
      title="Battle History"
      actions={
        <span className="text-[10px] text-[var(--text-muted)] tabular-nums">
          {sessions.length} sessions
        </span>
      }
      padding="none"
      className={className}
    >
      <div className="max-h-[400px] overflow-y-auto">
        {sessions.map((session, i) => {
          const totalRounds = (session.red_wins ?? 0) + (session.blue_wins ?? 0);
          const redPct = totalRounds > 0 ? ((session.red_wins ?? 0) / totalRounds) * 100 : 50;
          const bluePct = 100 - redPct;
          const isPromoted = session.result === 'blue_wins' || session.result === 'promoted';

          return (
            <motion.div
              key={session.session_id || session.antibody_id || i}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.03, duration: 0.2 }}
              className="px-4 py-3 border-b border-[var(--border-subtle)] last:border-b-0 hover:bg-[var(--bg-tertiary)] transition-colors"
            >
              {/* Top row */}
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-[var(--text-muted)]">
                    {session.antibody_id?.slice(0, 10) || `Session ${i + 1}`}
                  </span>
                  <Badge variant={isPromoted ? 'immune' : 'threat'}>
                    {isPromoted ? 'Promoted' : 'Failed'}
                  </Badge>
                </div>
                <span className="text-[10px] text-[var(--text-muted)] tabular-nums">
                  {formatRelativeTime(session.timestamp)}
                </span>
              </div>

              {/* Red vs Blue bar */}
              <div className="flex h-2 rounded-full overflow-hidden mb-1.5">
                <div
                  className="bg-red-400 transition-all duration-500"
                  style={{ width: `${redPct}%` }}
                />
                <div
                  className="bg-[var(--color-immune)] transition-all duration-500"
                  style={{ width: `${bluePct}%` }}
                />
              </div>

              {/* Stats row */}
              <div className="flex items-center justify-between text-[10px]">
                <span className="text-red-400 font-mono tabular-nums">
                  Red: {session.red_wins ?? 0}
                </span>
                <span className="text-[var(--text-muted)]">
                  {totalRounds} rounds
                </span>
                <span className="text-[var(--color-immune)] font-mono tabular-nums">
                  Blue: {session.blue_wins ?? 0}
                </span>
              </div>
            </motion.div>
          );
        })}
      </div>
    </Card>
  );
}

export type { BattleHistoryProps };
export default BattleHistory;
