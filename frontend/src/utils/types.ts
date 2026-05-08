// frontend/src/utils/types.ts
// TypeScript interfaces — mirrors backend Pydantic models
// WHY: Type safety across the entire frontend.

// ─── Core Entities ────────────────────────────────────────────────────────────

export interface Threat {
  id: string;
  content?: string;
  type?: string;
  family?: string;
  severity: string;
  classification: string;
  vector: string;
  language?: string;
  summary?: string;
  timestamp: string;
  surprise_score?: number;
  confidence?: number;
  fingerprint?: string | number[];
  antibody_id?: string;
}

export interface Antibody {
  id: string;
  type?: string;
  family?: string;
  strength: number;
  status: string;
  rule?: string;
  detection_logic?: string;
  verified?: boolean;
  verification?: AntibodyVerification;
  created_at?: string;
  timestamp?: string;
}

export interface AntibodyVerification {
  is_sound: boolean;
  is_complete: boolean;
  is_consistent: boolean;
  proof_hash?: string;
  properties_checked: number;
  properties_passed: number;
}

export interface PipelineState {
  stage: number;
  stage_name: string;
  incident_id?: string;
  started_at?: string;
  progress?: number;
}

export interface MeshNode {
  id: string;
  name?: string;
  address?: string;
  status: string;
  latency?: number;
  last_seen?: string;
  antibodies_count?: number;
}

export interface BattleSession {
  id?: string;
  antibody_id?: string;
  rounds?: BattleRound[];
  red_wins?: number;
  blue_wins?: number;
  result?: string;
  timestamp?: string;
}

export interface BattleRound {
  round: number;
  red_variant: string;
  blue_blocked: boolean;
  confidence?: number;
}

export interface EpidemiologicalState {
  susceptible?: number;
  infected?: number;
  recovered?: number;
  total?: number;
  r0?: number;
  beta?: number;
  gamma?: number;
  herd_immunity_pct?: number;
}

// ─── WebSocket Events ─────────────────────────────────────────────────────────

export interface WebSocketEvent {
  type: string;
  payload: unknown;
  timestamp?: string;
}
