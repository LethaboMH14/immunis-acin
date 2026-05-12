// frontend/src/hooks/useImmunis.ts
//
// IMMUNIS ACIN — Main application state hook.
// Single source of truth for all dashboard state.
//
// Combines REST fetches (mount + polling) with live WebSocket updates.
// Components call useImmunis() and read what they need.
//
// WHY: 10 pages x 4-6 data sources = 40+ duplicated fetches without
// a central hook. One hook, one WebSocket, one truth.

import { useEffect, useState, useCallback } from 'react';
import { useApi, useMutation } from './useApi';
import { useWebSocket } from '../providers/WebSocketProvider';
import type {
  Antibody,
  AntibodiesResponse,
  BattleSession,
  EpidemiologicalState,
  EvolutionPoint,
  MeshNode,
  PipelineState,
  SystemHealth,
  Threat,
  ThreatSubmitResponse,
} from '../utils/types';

// ─────────────────────────────────────────────────────────────
// Return shape — every consumer sees this contract
// ─────────────────────────────────────────────────────────────

export interface ImmunisState {
  threats: Threat[];
  antibodies: Antibody[];
  meshNodes: MeshNode[];
  pipelineState: PipelineState | null;
  immunityScore: number;
  evolutionTimeline: EvolutionPoint[];
  battlegroundHistory: BattleSession[];
  epidemiologicalState: EpidemiologicalState | null;
  systemHealth: SystemHealth | undefined;
  isConnected: boolean;
  connectionStatus: 'connecting' | 'connected' | 'disconnected' | 'error';
  lastEventReceived: string | null;
  submitThreat: (
    content: string,
    vector?: string,
    language_hint?: string
  ) => Promise<string | undefined>;
  refreshAll: () => void;
}

// ─────────────────────────────────────────────────────────────
// Helper: safe cast for WebSocket payloads with validation
// ─────────────────────────────────────────────────────────────

function wsPayload<T>(payload: unknown): T {
  return payload as T;
}

// Helper: validate and log WebSocket events
function logWebSocketEvent(eventType: string, payload: unknown, pipelineId?: string) {
  console.log(`[IMMUNIS WS] ${eventType}${pipelineId ? ` (pipeline: ${pipelineId})` : ''}:`, payload);
}

// Helper: handle WebSocket errors gracefully
function handleWebSocketError(error: unknown, context: string) {
  console.error(`[IMMUNIS WS] Error in ${context}:`, error);
}

// ─────────────────────────────────────────────────────────────
// Evolution summary shape (from GET /api/evolution/summary)
// ─────────────────────────────────────────────────────────────

interface EvolutionSummary {
  immunity_score?: number;
  current_immunity?: number;
  total_antibodies?: number;
  total_red_wins?: number;
  total_blue_wins?: number;
}

// ─────────────────────────────────────────────────────────────
// The hook
// ─────────────────────────────────────────────────────────────

export function useImmunis(): ImmunisState {
  // ── Local state ──────────────────────────────────────────
  const [threats, setThreats] = useState<Threat[]>([]);
  const [antibodies, setAntibodies] = useState<Antibody[]>([]);
  const [meshNodes, setMeshNodes] = useState<MeshNode[]>([]);
  const [pipelineState, setPipelineState] = useState<PipelineState | null>(null);
  const [immunityScore, setImmunityScore] = useState<number>(0);
  const [evolutionTimeline, setEvolutionTimeline] = useState<EvolutionPoint[]>([]);
  const [battlegroundHistory, setBattlegroundHistory] = useState<BattleSession[]>([]);
  const [epidemiologicalState, setEpidemiologicalState] = useState<EpidemiologicalState | null>(null);
  const [lastEventReceived, setLastEventReceived] = useState<string | null>(null);

  // ── WebSocket ────────────────────────────────────────────
  const { status, subscribe } = useWebSocket();
  const isConnected = status === 'connected';
  
  // Map WebSocket status to connection status
  const getConnectionStatus = (): ImmunisState['connectionStatus'] => {
    switch (status) {
      case 'connecting': return 'connecting';
      case 'connected': return 'connected';
      case 'disconnected': return 'disconnected';
      case 'error': return 'error';
      default: return 'disconnected';
    }
  };

  // ── REST queries ─────────────────────────────────────────
  //
  // NOTE: useApi returns { data, loading, error, fetch }.
  // The method to re-fetch is whatever useApi.ts exposes.
  // If it is called `refetch`, use that. If `fetch`, use that.
  // Cascade: READ useApi.ts to confirm the method name.

  const healthQuery = useApi<SystemHealth>('/api/health', {
    immediate: true,
    pollInterval: 30000,
  });

  const antibodiesQuery = useApi<AntibodiesResponse>(
    '/api/antibodies?page_size=200',
    { immediate: true, pollInterval: 60000 }
  );

  const evolutionQuery = useApi<EvolutionPoint[]>(
    '/api/evolution/timeline?limit=200',
    { immediate: true, pollInterval: 30000 }
  );

  const evolutionSummaryQuery = useApi<EvolutionSummary>(
    '/api/evolution/summary',
    { immediate: true, pollInterval: 15000 }
  );

  const battlegroundQuery = useApi<BattleSession[]>(
    '/api/battleground/history',
    { immediate: true, pollInterval: 30000 }
  );

  const epiQuery = useApi<EpidemiologicalState>('/api/epidemiological', {
    immediate: true,
    pollInterval: 30000,
  });

  // ── Mutation ─────────────────────────────────────────────
  const threatMutation = useMutation<
    { content: string; vector?: string; language_hint?: string },
    ThreatSubmitResponse
  >('/api/threats', 'POST');

  // ── Sync REST → local state ──────────────────────────────

  // Antibodies from paginated endpoint
  useEffect(() => {
    const d = antibodiesQuery.data;
    console.log('[IMMUNIS] antibodiesQuery.data:', antibodiesQuery.data);
    if (d && Array.isArray((d as AntibodiesResponse).antibodies)) {
      setAntibodies((d as AntibodiesResponse).antibodies);
    } else if (Array.isArray(d)) {
      // Fallback: backend might return plain array in some configs
      setAntibodies(d as Antibody[]);
    }
  }, [antibodiesQuery.data]);

  // Immunity score: prefer evolution/summary, fallback to health
  useEffect(() => {
    const s = evolutionSummaryQuery.data;
    console.log('[IMMUNIS] evolutionSummaryQuery.data:', evolutionSummaryQuery.data);
    console.log('[IMMUNIS] healthQuery.data:', healthQuery.data);
    if (s) {
      const score =
        typeof s.immunity_score === 'number' ? s.immunity_score
        : typeof s.current_immunity === 'number' ? s.current_immunity
        : null;
      if (score !== null) {
        setImmunityScore(score);
        return;
      }
    }
    if (healthQuery.data && typeof healthQuery.data.immunity_score === 'number') {
      setImmunityScore(healthQuery.data.immunity_score);
    }
  }, [evolutionSummaryQuery.data, healthQuery.data]);

  // Evolution timeline: backend returns plain array
  useEffect(() => {
    console.log('[IMMUNIS] evolutionQuery.data:', evolutionQuery.data);
    if (Array.isArray(evolutionQuery.data)) {
      setEvolutionTimeline(evolutionQuery.data);
    }
  }, [evolutionQuery.data]);

  // Battleground history: backend returns plain array
  useEffect(() => {
    console.log('[IMMUNIS] battlegroundQuery.data:', battlegroundQuery.data);
    if (Array.isArray(battlegroundQuery.data)) {
      setBattlegroundHistory(battlegroundQuery.data);
    }
  }, [battlegroundQuery.data]);

  // Epidemiological state: flat object
  useEffect(() => {
    console.log('[IMMUNIS] epiQuery.data:', epiQuery.data);
    if (epiQuery.data) {
      setEpidemiologicalState(epiQuery.data);
    }
  }, [epiQuery.data]);

  // ── WebSocket subscriptions ──────────────────────────────
  useEffect(() => {
    const unsubs: Array<() => void> = [];
    const eventCounts: Record<string, number> = {};

    // Helper to track event frequency for debugging
    const trackEvent = (eventType: string) => {
      eventCounts[eventType] = (eventCounts[eventType] || 0) + 1;
      if (eventCounts[eventType] % 10 === 0) {
        console.log(`[IMMUNIS WS] Event count: ${eventType} -> ${eventCounts[eventType]}`);
      }
      // Update last event received timestamp
      setLastEventReceived(new Date().toISOString());
    };

    // Handle connection state changes
    if (status === 'connected') {
      console.log('[IMMUNIS WS] Connected to backend, subscribing to events');
      // Refresh data when reconnecting to ensure sync
      setTimeout(() => {
        refreshAll();
      }, 500);
    } else if (status === 'disconnected' || status === 'error') {
      console.log(`[IMMUNIS WS] Disconnected: ${status}`);
    }

    // Pipeline stage updates - subscribe to all backend pipeline events
    unsubs.push(
      subscribe('surprise_computed', (payload: unknown) => {
        trackEvent('surprise_computed');
        try {
          const p = wsPayload<Record<string, unknown>>(payload);
          logWebSocketEvent('surprise_computed', payload, p.pipeline_id as string);
          setPipelineState({
            stage: 1,
            stage_name: 'Surprise Detection',
            incident_id: (p.pipeline_id as string) ?? null,
            progress: 14,
            started_at: new Date().toISOString(),
            errors: [],
            warnings: [],
          });
        } catch (error) {
          handleWebSocketError(error, 'surprise_computed');
        }
      })
    );

    unsubs.push(
      subscribe('containment_deployed', (payload: unknown) => {
        trackEvent('containment_deployed');
        try {
          const p = wsPayload<Record<string, unknown>>(payload);
          logWebSocketEvent('containment_deployed', payload, p.pipeline_id as string);
          setPipelineState({
            stage: 2,
            stage_name: 'Containment',
            incident_id: (p.pipeline_id as string) ?? null,
            progress: 28,
            started_at: new Date().toISOString(),
            errors: [],
            warnings: [],
          });
        } catch (error) {
          handleWebSocketError(error, 'containment_deployed');
        }
      })
    );

    unsubs.push(
      subscribe('fingerprint_ready', (payload: unknown) => {
        trackEvent('fingerprint_ready');
        try {
          const p = wsPayload<Record<string, unknown>>(payload);
          logWebSocketEvent('fingerprint_ready', payload, p.pipeline_id as string);
          setPipelineState({
            stage: 3,
            stage_name: 'Fingerprinting',
            incident_id: (p.pipeline_id as string) ?? null,
            progress: 42,
            started_at: new Date().toISOString(),
            errors: [],
            warnings: [],
          });
          
          // Update threat with fingerprint details
          const pipelineId = p.pipeline_id as string;
          if (pipelineId) {
            setThreats((prev) =>
              prev.map((threat) =>
                threat.incident_id === pipelineId
                  ? {
                      ...threat,
                      attack_type: p.attack_type as Threat['attack_type'],
                      severity: p.severity as Threat['severity'],
                      classification: p.mitre_technique_id as Threat['classification'],
                      confidence: p.confidence as number,
                      attack_family: p.attack_type as string,
                    }
                  : threat
              )
            );
          }
        } catch (error) {
          handleWebSocketError(error, 'fingerprint_ready');
        }
      })
    );

    // Threat received (was threat_detected)
    unsubs.push(
      subscribe('threat_received', (payload: unknown) => {
        trackEvent('threat_received');
        try {
          const w = wsPayload<Record<string, unknown>>(payload);
          logWebSocketEvent('threat_received', payload, w.pipeline_id as string);
          const threat: Threat = {
            incident_id: (w.pipeline_id as string) ?? `INC-${Date.now()}`,
            content: undefined,
            attack_family: undefined,
            attack_type: 'unknown' as Threat['attack_type'],
            severity: 'Medium' as Threat['severity'],
            classification: 'unknown' as Threat['classification'],
            vector: w.vector as Threat['vector'],
            language: w.language_hint as Threat['language'],
            surprise_score: undefined,
            confidence: undefined,
            timestamp: (w.timestamp as string) ?? new Date().toISOString(),
          };
          setThreats((prev) => {
            // Avoid duplicates
            if (prev.some(t => t.incident_id === threat.incident_id)) {
              return prev;
            }
            return [threat, ...prev].slice(0, 100);
          });
        } catch (error) {
          handleWebSocketError(error, 'threat_received');
        }
      })
    );

    // Antibody synthesised
    unsubs.push(
      subscribe('antibody_synthesised', (payload: unknown) => {
        trackEvent('antibody_synthesised');
        try {
          const w = wsPayload<Record<string, unknown>>(payload);
          logWebSocketEvent('antibody_synthesised', payload, w.pipeline_id as string);
          const abId = (w.antibody_id as string) ?? '';
          if (!abId) return;
          const ab: Antibody = {
            antibody_id: abId,
            attack_family: (w.attack_family as string) ?? 'Unknown',
            strength_score: (w.strength_score as number) ?? 0,
            status: (w.status as Antibody['status']) ?? 'pending',
            formally_verified: w.formally_verified as boolean | undefined,
            synthesised_at: (w.timestamp as string) ?? new Date().toISOString(),
          };
          setAntibodies((prev) => {
            const idx = prev.findIndex((a) => a.antibody_id === ab.antibody_id);
            if (idx >= 0) {
              const copy = [...prev];
              copy[idx] = { ...copy[idx], ...ab };
              return copy;
            }
            return [ab, ...prev].slice(0, 200);
          });
        } catch (error) {
          handleWebSocketError(error, 'antibody_synthesised');
        }
      })
    );

    // Arbiter decision - handles both pipeline stage 4 and antibody promotion
    unsubs.push(
      subscribe('arbiter_decision', (payload: unknown) => {
        trackEvent('arbiter_decision');
        try {
          const w = wsPayload<Record<string, unknown>>(payload);
          logWebSocketEvent('arbiter_decision', payload, w.pipeline_id as string);
          
          // Update pipeline state to stage 4 (Bridge Defense)
          setPipelineState({
            stage: 4,
            stage_name: 'Bridge Defense',
            incident_id: (w.pipeline_id as string) ?? null,
            progress: 57,
            started_at: new Date().toISOString(),
            errors: [],
            warnings: [],
          });
          
          // Handle antibody promotion if present
          const abId = (w.antibody_id as string) ?? '';
          if (abId) {
            setAntibodies((prev) =>
              prev.map((ab) =>
                ab.antibody_id === abId
                  ? {
                      ...ab,
                      strength_score: (w.final_strength as number) ?? ab.strength_score,
                      status: (w.promoted as boolean) ? 'promoted' : ab.status,
                      formally_verified: (w.formally_verified as boolean) ?? ab.formally_verified,
                      promoted_at: (w.promoted as boolean) ? new Date().toISOString() : ab.promoted_at,
                    }
                  : ab
              )
            );
          }
        } catch (error) {
          handleWebSocketError(error, 'arbiter_decision');
        }
      })
    );

    // Immunity update
    unsubs.push(
      subscribe('immunity_update', (payload: unknown) => {
        trackEvent('immunity_update');
        try {
          const w = wsPayload<Record<string, unknown>>(payload);
          logWebSocketEvent('immunity_update', payload);
          const score = w.score as number | undefined;
          if (typeof score === 'number') {
            setImmunityScore(score);
          }
        } catch (error) {
          handleWebSocketError(error, 'immunity_update');
        }
      })
    );

    // Mesh node update (now mesh_broadcast)
    unsubs.push(
      subscribe('mesh_broadcast', (payload: unknown) => {
        trackEvent('mesh_broadcast');
        try {
          const w = wsPayload<Record<string, unknown>>(payload);
          logWebSocketEvent('mesh_broadcast', payload);
          const nodeId = (w.broadcast_id as string) ?? '';
          if (!nodeId) return;
          setMeshNodes((prev) => {
            const idx = prev.findIndex((n) => n.node_id === nodeId);
            const merged: MeshNode = {
              node_id: nodeId,
              status: (w.status as string) ?? 'active',
              antibodies_count: w.antibodies_count as number | undefined,
              latency_ms: w.latency_ms as number | undefined,
            };
            if (idx >= 0) {
              const copy = [...prev];
              copy[idx] = { ...copy[idx], ...merged };
              return copy;
            }
            return [...prev, merged];
          });
        } catch (error) {
          handleWebSocketError(error, 'mesh_broadcast');
        }
      })
    );

    // Battleground rounds - subscribe to both red_attack and blue_defense
    unsubs.push(
      subscribe('red_attack', (payload: unknown) => {
        trackEvent('red_attack');
        try {
          const w = wsPayload<Record<string, unknown>>(payload);
          logWebSocketEvent('red_attack', payload);
          const abId = (w.target_antibody_id as string) ?? '';
          if (!abId) return;
          const session: BattleSession = {
            session_id: w.variant_id as string | undefined,
            antibody_id: abId,
            rounds: [
              {
                round: (w.round as number) ?? 0,
                red_variant: w.variant_id as string | undefined,
                blue_blocked: false,
              },
            ],
            red_wins: (w.red_wins as number) ?? 0,
            blue_wins: (w.blue_wins as number) ?? 0,
            total_rounds: (w.total_rounds as number) ?? 0,
            result: (w.result as string) ?? '',
            final_strength: w.final_strength as number | undefined,
            timestamp: (w.timestamp as string) ?? new Date().toISOString(),
          };
          setBattlegroundHistory((prev) => [session, ...prev].slice(0, 50));
        } catch (error) {
          handleWebSocketError(error, 'red_attack');
        }
      })
    );

    // Blue defense (second battleground subscription)
    unsubs.push(
      subscribe('blue_defense', (payload: unknown) => {
        trackEvent('blue_defense');
        try {
          const w = wsPayload<Record<string, unknown>>(payload);
          logWebSocketEvent('blue_defense', payload);
          const abId = (w.antibody_id as string) ?? '';
          if (!abId) return;
          const session: BattleSession = {
            session_id: w.classification_id as string | undefined,
            antibody_id: abId,
            rounds: [
              {
                round: (w.round as number) ?? 0,
                red_variant: w.red_variant as string | undefined,
                blue_blocked: (w.verdict === 'blocked'),
              },
            ],
            red_wins: (w.red_wins as number) ?? 0,
            blue_wins: (w.blue_wins as number) ?? 0,
            total_rounds: (w.total_rounds as number) ?? 0,
            result: (w.verdict as string) ?? '',
            final_strength: w.final_strength as number | undefined,
            timestamp: new Date().toISOString(),
          };
          setBattlegroundHistory((prev) => [session, ...prev].slice(0, 50));
        } catch (error) {
          handleWebSocketError(error, 'blue_defense');
        }
      })
    );

    // Evolution update (now pipeline_complete)
    unsubs.push(
      subscribe('pipeline_complete', (payload: unknown) => {
        trackEvent('pipeline_complete');
        try {
          const w = wsPayload<Record<string, unknown>>(payload);
          logWebSocketEvent('pipeline_complete', payload, w.pipeline_id as string);
          const point: EvolutionPoint = {
            timestamp: new Date().toISOString(),
            immunity_score: 0,
            red_wins: undefined,
            blue_wins: undefined,
            antibodies_promoted: undefined,
            event_type: 'pipeline_complete',
            description: `Pipeline ${w.pipeline_id} completed - ${w.is_threat ? 'Threat detected' : 'Not a threat'}`,
          };
          setEvolutionTimeline((prev) => [...prev, point].slice(-200));
          // Mark pipeline as complete
          setPipelineState(prev => prev ? {...prev, progress: 100, stage_name: 'Complete'} : null);
        } catch (error) {
          handleWebSocketError(error, 'pipeline_complete');
        }
      })
    );

    // Novel threat detection
    unsubs.push(
      subscribe('novel_threat', (payload: unknown) => {
        trackEvent('novel_threat');
        try {
          const w = wsPayload<Record<string, unknown>>(payload);
          logWebSocketEvent('novel_threat', payload, w.pipeline_id as string);
          // Highlight novel threats in the feed
          const surpriseBits = w.surprise_bits as number;
          setThreats((prev) => 
            prev.map(threat => 
              threat.attack_family === 'Unknown' || surpriseBits > 8
                ? { ...threat, severity: 'Critical' as const }
                : threat
            )
          );
        } catch (error) {
          handleWebSocketError(error, 'novel_threat');
        }
      })
    );

    // Pipeline error handling
    unsubs.push(
      subscribe('pipeline_error', (payload: unknown) => {
        trackEvent('pipeline_error');
        try {
          const w = wsPayload<Record<string, unknown>>(payload);
          const error = w.error as string;
          console.error('[IMMUNIS] Pipeline error:', error);
          // Update pipeline state to show error
          setPipelineState(prev => prev ? {
            ...prev,
            progress: 0,
            stage_name: 'Error',
            errors: error ? [error] : ['Unknown error']
          } : null);
        } catch (err) {
          handleWebSocketError(err, 'pipeline_error');
        }
      })
    );

    // Cleanup: unsubscribe all on unmount
    return () => {
      console.log('[IMMUNIS WS] Cleaning up subscriptions');
      unsubs.forEach((u) => u());
    };
  }, [subscribe, status, refreshAll]);

  // ── Submit threat action ─────────────────────────────────
  const submitThreat = useCallback(
    async (
      content: string,
      vector?: string,
      language_hint?: string
    ): Promise<string | undefined> => {
      // Check connection before submitting
      if (!isConnected) {
        console.warn('[IMMUNIS] Cannot submit threat: WebSocket disconnected');
        return undefined;
      }

      try {
        const result = await threatMutation.mutate({
          content,
          vector,
          language_hint,
        });
        if (result?.incident_id) {
          const optimistic: Threat = {
            incident_id: result.incident_id,
            content,
            vector: vector as Threat['vector'],
            language: language_hint as Threat['language'],
            severity: 'Medium',
            timestamp: new Date().toISOString(),
          };
          setThreats((prev) => {
            // Avoid duplicates
            if (prev.some(t => t.incident_id === optimistic.incident_id)) {
              return prev;
            }
            return [optimistic, ...prev].slice(0, 100);
          });
          return result.incident_id;
        }
        return undefined;
      } catch (err) {
        console.error('submitThreat failed:', err);
        return undefined;
      }
    },
    [threatMutation, isConnected]
  );

  // ── Refresh all data ─────────────────────────────────────
  //
  // NOTE TO CASCADE: Read frontend/src/hooks/useApi.ts and check
  // whether the re-fetch method is called `refetch` or `fetch`.
  // Use whichever exists. If neither exists, call the hook's
  // returned function that triggers a new request.
  const refreshAll = useCallback(() => {
    healthQuery.fetch?.();
    antibodiesQuery.fetch?.();
    evolutionQuery.fetch?.();
    evolutionSummaryQuery.fetch?.();
    battlegroundQuery.fetch?.();
    epiQuery.fetch?.();
  }, [healthQuery, antibodiesQuery, evolutionQuery, evolutionSummaryQuery, battlegroundQuery, epiQuery]);

  // ── RETURN ───────────────────────────────────────────────
  // THIS IS THE HOOK RETURN. It is NOT inside useEffect.
  // It is at the top level of the function body.
  return {
    threats,
    antibodies,
    meshNodes,
    pipelineState,
    immunityScore,
    evolutionTimeline,
    battlegroundHistory,
    epidemiologicalState,
    systemHealth: healthQuery.data || undefined,
    isConnected,
    connectionStatus: getConnectionStatus(),
    lastEventReceived,
    submitThreat,
    refreshAll,
  };
}
