// frontend/src/hooks/useImmunis.ts
// Enhanced main state management hook — single source of truth for app state
// WHY: The original useImmunis managed WebSocket directly. This version
// delegates connection management to WebSocketProvider and focuses purely
// on state: what threats exist, what antibodies are active, what's the
// immunity score, what's happening in the pipeline right now.

import { useState, useEffect, useCallback } from 'react';
import { useWebSocket } from '../providers/WebSocketProvider';
import { useApi, useMutation } from './useApi';
import type {
  Threat,
  Antibody,
  PipelineState,
  MeshNode,
  BattleSession,
  EpidemiologicalState,
} from '../utils/types';

// ─── Types ────────────────────────────────────────────────────────────────────

interface SystemHealth {
  status: string;
  immunity_score: number;
  threats_processed: number;
  antibodies_active: number;
  mesh_nodes: number;
  uptime: number;
}

interface EvolutionPoint {
  timestamp: string;
  immunity_score: number;
  red_wins: number;
  blue_wins: number;
  antibodies_promoted: number;
}

interface ImmunisState {
  // Core data
  threats: Threat[];
  antibodies: Antibody[];
  meshNodes: MeshNode[];

  // Real-time state
  pipelineState: PipelineState | null;
  immunityScore: number;
  systemHealth: SystemHealth | null;

  // History
  evolutionTimeline: EvolutionPoint[];
  battlegroundHistory: BattleSession[];
  epidemiologicalState: EpidemiologicalState | null;

  // Connection
  isConnected: boolean;
  isLoading: boolean;

  // Actions
  submitThreat: (content: string, vector?: string, languageHint?: string) => Promise<void>;
  refreshAll: () => void;
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useImmunis(): ImmunisState {
  // ─── Local State ────────────────────────────────────────────────────────

  const [threats, setThreats] = useState<Threat[]>([]);
  const [antibodies, setAntibodies] = useState<Antibody[]>([]);
  const [meshNodes, setMeshNodes] = useState<MeshNode[]>([]);
  const [pipelineState, setPipelineState] = useState<PipelineState | null>(null);
  const [immunityScore, setImmunityScore] = useState(0);
  const [evolutionTimeline, setEvolutionTimeline] = useState<EvolutionPoint[]>([]);
  const [battlegroundHistory, setBattlegroundHistory] = useState<BattleSession[]>([]);
  const [epidemiologicalState, setEpidemiologicalState] =
    useState<EpidemiologicalState | null>(null);

  // ─── WebSocket ──────────────────────────────────────────────────────────

  const { status, subscribe } = useWebSocket();
  const isConnected = status === 'connected';

  // ─── API Queries ────────────────────────────────────────────────────────

  const healthQuery = useApi<SystemHealth>('/api/health', {
    immediate: true,
    pollInterval: 30000,
  });

  const evolutionQuery = useApi<{ timeline: EvolutionPoint[] }>(
    '/api/evolution/timeline',
    { immediate: true }
  );

  const battlegroundQuery = useApi<{ history: BattleSession[] }>(
    '/api/battleground/history',
    { immediate: true }
  );

  const epiQuery = useApi<EpidemiologicalState>('/api/epidemiological', {
    immediate: true,
  });

  // ─── Mutation ───────────────────────────────────────────────────────────

  const threatMutation = useMutation<
    { content: string; vector?: string; language_hint?: string },
    { incident_id: string; status: string }
  >('/api/threats', 'POST');

  // ─── Sync API data to local state ───────────────────────────────────────

  useEffect(() => {
    if (healthQuery.data) {
      setImmunityScore(healthQuery.data.immunity_score);
    }
  }, [healthQuery.data]);

  useEffect(() => {
    if (evolutionQuery.data?.timeline) {
      setEvolutionTimeline(evolutionQuery.data.timeline);
    }
  }, [evolutionQuery.data]);

  useEffect(() => {
    if (battlegroundQuery.data?.history) {
      setBattlegroundHistory(battlegroundQuery.data.history);
    }
  }, [battlegroundQuery.data]);

  useEffect(() => {
    if (epiQuery.data) {
      setEpidemiologicalState(epiQuery.data);
    }
  }, [epiQuery.data]);

  // ─── WebSocket Subscriptions ────────────────────────────────────────────

  useEffect(() => {
    const unsubscribers: (() => void)[] = [];

    // Pipeline stage updates
    unsubscribers.push(
      subscribe('pipeline_stage', (payload) => {
        setPipelineState(payload as PipelineState);
      })
    );

    // New threat detected
    unsubscribers.push(
      subscribe('threat_detected', (payload) => {
        const threat = payload as Threat;
        setThreats((prev) => [threat, ...prev].slice(0, 100));
      })
    );

    // Antibody synthesised
    unsubscribers.push(
      subscribe('antibody_synthesised', (payload) => {
        const antibody = payload as Antibody;
        setAntibodies((prev) => [antibody, ...prev].slice(0, 100));
      })
    );

    // Antibody promoted (passed battleground)
    unsubscribers.push(
      subscribe('antibody_promoted', (payload) => {
        const promoted = payload as Antibody;
        setAntibodies((prev) =>
          prev.map((ab) =>
            ab.id === promoted.id ? { ...ab, ...promoted } : ab
          )
        );
      })
    );

    // Immunity score update
    unsubscribers.push(
      subscribe('immunity_update', (payload) => {
        const update = payload as { score: number };
        setImmunityScore(update.score);
      })
    );

    // Mesh node update
    unsubscribers.push(
      subscribe('mesh_update', (payload) => {
        const node = payload as MeshNode;
        setMeshNodes((prev) => {
          const existing = prev.findIndex((n) => n.id === node.id);
          if (existing >= 0) {
            const updated = [...prev];
            updated[existing] = node;
            return updated;
          }
          return [...prev, node];
        });
      })
    );

    // Battleground round
    unsubscribers.push(
      subscribe('battleground_round', (payload) => {
        const session = payload as BattleSession;
        setBattlegroundHistory((prev) => [session, ...prev].slice(0, 50));
      })
    );

    // Evolution update
    unsubscribers.push(
      subscribe('evolution_update', (payload) => {
        const point = payload as EvolutionPoint;
        setEvolutionTimeline((prev) => [...prev, point].slice(-200));
      })
    );

    // Epidemiological update
    unsubscribers.push(
      subscribe('epidemiological_update', (payload) => {
        setEpidemiologicalState(payload as EpidemiologicalState);
      })
    );

    // Pipeline complete
    unsubscribers.push(
      subscribe('pipeline_complete', () => {
        setPipelineState(null);
      })
    );

    return () => {
      unsubscribers.forEach((unsub) => unsub());
    };
  }, [subscribe]);

  // ─── Actions ────────────────────────────────────────────────────────────

  const submitThreat = useCallback(
    async (content: string, vector = 'email', languageHint?: string) => {
      await threatMutation.mutate({
        content,
        vector,
        language_hint: languageHint,
      });
    },
    [threatMutation]
  );

  const refreshAll = useCallback(() => {
    healthQuery.fetch();
    evolutionQuery.fetch();
    battlegroundQuery.fetch();
    epiQuery.fetch();
  }, [healthQuery, evolutionQuery, battlegroundQuery, epiQuery]);

  // ─── Return ─────────────────────────────────────────────────────────────

  return {
    threats,
    antibodies,
    meshNodes,
    pipelineState,
    immunityScore,
    systemHealth: healthQuery.data ?? null,
    evolutionTimeline,
    battlegroundHistory,
    epidemiologicalState,
    isConnected,
    isLoading: healthQuery.isLoading,
    submitThreat,
    refreshAll,
  };
}

export default useImmunis;
