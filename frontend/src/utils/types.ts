// frontend/src/utils/types.ts
//
// IMMUNIS ACIN — TypeScript Type Contracts
//
// Single source of truth for all frontend types. Mirrors backend Pydantic
// models in `backend/models/schemas.py` and `backend/models/enums.py` 
// EXACTLY — same field names, same casing (snake_case), same optionality.
//
// WHY snake_case: backend serialises Pydantic models to JSON with
// snake_case field names. Frontend code consumes those names directly.
// No casing translation layer = no drift = no bugs.
//
// WHY string unions instead of TypeScript enums: backend enums extend
// str (Pydantic StrEnum), so wire format is plain strings. String
// unions are zero-cost at runtime and match the wire format perfectly.
//
// CONTRACT: When backend schemas change, this file MUST be updated
// before any component is updated. This file is the contract.

// ─────────────────────────────────────────────────────────────────────
// ENUMS (mirror backend/models/enums.py)
// ─────────────────────────────────────────────────────────────────────

export type AttackType =
  | 'BEC'
  | 'Phishing'
  | 'Spearphishing'
  | 'Vishing'
  | 'Ransomware'
  | 'CredentialHarvesting'
  | 'InvoiceFraud'
  | 'CEOFraud'
  | 'VendorImpersonation'
  | 'ITSupportImpersonation'
  | 'GovernmentImpersonation'
  | 'InsiderThreat'
  | 'NetworkIntrusion'
  | 'Malware'
  | 'APT'
  | 'QRPhishing'
  | 'Deepfake'
  | 'DocumentForgery'
  | 'Steganography'
  | 'Benign'
  | 'Other';

export type ThreatVerdict = 'known' | 'variant' | 'novel' | 'benign';

export type SurpriseLevel = 'expected' | 'moderate' | 'novel';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type AntibodyStatus =
  | 'pending'
  | 'testing'
  | 'validated'
  | 'promoted'
  | 'broadcast'
  | 'deprecated'
  | 'failed';

export type MitrePhase =
  | 'Reconnaissance'
  | 'ResourceDevelopment'
  | 'InitialAccess'
  | 'Execution'
  | 'Persistence'
  | 'PrivilegeEscalation'
  | 'DefenseEvasion'
  | 'CredentialAccess'
  | 'Discovery'
  | 'LateralMovement'
  | 'Collection'
  | 'CommandAndControl'
  | 'Exfiltration'
  | 'Impact';

export type ThreatVector =
  | 'email'
  | 'voice'
  | 'network'
  | 'endpoint'
  | 'image'
  | 'document'
  | 'qr_code'
  | 'video'
  | 'url'
  | 'api'
  | 'sms'
  | 'whatsapp'
  | 'unknown';

export type Language =
  | 'en' | 'zu' | 'st' | 'af' | 'xh' | 'nso' | 'tn'
  | 'ar' | 'fa' | 'tr' | 'he' | 'ur'
  | 'zh' | 'hi' | 'id' | 'ms' | 'ja' | 'ko' | 'th' | 'vi' | 'tl'
  | 'fr' | 'de' | 'es' | 'it' | 'pl' | 'ro' | 'sv' | 'no' | 'da' | 'fi'
  | 'yo' | 'ig' | 'ha' | 'sw' | 'am'
  | 'mixed' | 'unknown';

export type VulnerabilitySeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type MeshEventType =
  | 'antibody_broadcast'
  | 'antibody_received'
  | 'node_joined'
  | 'node_left'
  | 'node_quarantined'
  | 'lockout_alert'
  | 'anti_entropy_sync'
  | 'trust_score_update';

export type ManipulationTechnique =
  | 'Authority'
  | 'Urgency'
  | 'Scarcity'
  | 'SocialProof'
  | 'Reciprocity'
  | 'Fear'
  | 'Greed'
  | 'Curiosity'
  | 'Trust'
  | 'Intimidation'
  | 'None';

export type ComplianceFramework =
  | 'POPIA'
  | 'CybercrimesAct'
  | 'NCPF'
  | 'NIST_CSF'
  | 'MITRE_ATT&CK'
  | 'ISO27001'
  | 'GDPR'
  | 'SOC2'
  | 'PCI_DSS'
  | 'SWIFT_CSP'
  | 'CIS';

export type ThreatActorType =
  | 'LocalCriminal'
  | 'Hacktivist'
  | 'RansomwareGroup'
  | 'NationStateAPT'
  | 'InsiderThreat'
  | 'Unknown';

// ─────────────────────────────────────────────────────────────────────
// CORE ENTITIES (mirror backend/models/schemas.py)
// ─────────────────────────────────────────────────────────────────────

/**
 * Antibody — atomic unit of IMMUNIS.
 * A structured, reusable, language-agnostic detection rule.
 * Mirrors: backend/models/schemas.py → class Antibody
 */
export interface Antibody {
  antibody_id: string;
  parent_fingerprint_id?: string;
  attack_family: string;
  attack_type?: AttackType;
  detection_signals?: Record<string, boolean>;
  detection_signals_description?: string[];
  cross_lingual_pattern?: string;
  language_variants?: Language[];
  mitre_technique?: string;
  mitre_phase?: MitrePhase;
  severity?: Severity;
  confidence_threshold?: number;
  false_positive_guards?: string[];
  strength_score: number;
  red_agent_tests?: number;
  red_agent_evasions?: number;
  status: AntibodyStatus;
  formally_verified?: boolean;
  verification_result?: AntibodyVerification;
  stix_indicator_id?: string | null;
  expected_loss_zar?: number;
  var_95_zar?: number;
  cvar_95_zar?: number;
  risk_reduction_factor?: number;
  node_origin?: string;
  synthesised_at?: string;
  promoted_at?: string | null;
  broadcast_at?: string | null;
}

/**
 * Z3 formal verification result embedded in Antibody.
 */
export interface AntibodyVerification {
  sound?: boolean;
  non_trivial?: boolean;
  consistent?: boolean;
  method?: string;
  signals_verified?: number;
  reason?: string;
}

/**
 * ThreatInput — raw threat data arriving at IMMUNIS.
 * Mirrors: backend/models/schemas.py → class ThreatInput
 * This is what frontend SENDS to POST /api/threats.
 */
export interface ThreatInput {
  content: string;
  vector?: ThreatVector;
  language_hint?: Language;
  metadata?: Record<string, unknown>;
  image_base64?: string | null;
  audio_base64?: string | null;
  source_node_id?: string | null;
}

/**
 * Threat — a processed threat as displayed in dashboard.
 * This is NOT a direct Pydantic model — it's assembled from pipeline
 * events (WebSocket) and stored state. Fields are a superset of what
 * different pipeline stages emit.
 */
export interface Threat {
  incident_id: string;
  content?: string;
  attack_family?: string;
  attack_type?: AttackType;
  severity?: Severity;
  classification?: ThreatVerdict;
  vector?: ThreatVector;
  language?: Language;
  summary?: string;
  timestamp: string;
  surprise_score?: number;
  confidence?: number;
  fingerprint_id?: string;
  antibody_id?: string;
  mitre_technique?: string;
  mitre_phase?: MitrePhase;
  status?: string;
}

/**
 * MeshNodeStatus — status of a single mesh node.
 * Mirrors: backend/models/schemas.py → class MeshNodeStatus
 */
export interface MeshNode {
  node_id: string;
  org_type?: string;
  node_type?: string;
  hostname?: string;
  ip_address?: string;
  city?: string;
  country?: string;
  status: string;
  last_seen?: string | null;
  antibodies_count?: number;
  latency_ms?: number | null;
  uptime_seconds?: number;
  cpu_usage?: number;
  memory_usage?: number;
  disk_usage?: number;
  network_in?: number;
  network_out?: number;
  created_at?: string;
  last_heartbeat?: string | null;
  version?: string;
  capabilities?: string[];
}

/**
 * MeshBroadcast — an antibody broadcast package.
 * Mirrors: backend/models/schemas.py → class MeshBroadcast
 */
export interface MeshBroadcast {
  broadcast_id: string;
  antibody: Antibody;
  source_node_id: string;
  destination_nodes: string[];
  classical_signature?: string;
  broadcast_type?: MeshEventType;
  payload_hash?: string;
  created_at?: string;
  expires_at?: string | null;
  confirmed_by?: string[] | null;
  confirmations?: number;
  rejection_reasons?: string[];
  broadcast_success?: boolean;
  mesh_coverage?: number;
}

/**
 * Mesh status summary from GET /api/mesh/status.
 * This is NOT a Pydantic model — it's assembled in route handler.
 */
export interface MeshStatus {
  node_id: string;
  connected_peers: string[];
  total_peers: number;
  r0_immunity: number;
  herd_immunity_threshold: number;
  herd_immunity_reached: boolean;
  immune_fraction: number;
  time_to_herd_immunity_hours: number;
  mesh_effectiveness: number;
}

/**
 * VulnerabilityFinding — a single vulnerability found by scanner.
 * Mirrors: backend/models/schemas.py → class VulnerabilityFinding
 */
export interface VulnerabilityFinding {
  finding_id: string;
  scan_id: string;
  target: string;
  vulnerability_type: string;
  severity: VulnerabilitySeverity;
  cvss_score?: number | null;
  description: string;
  affected_component: string;
  affected_version: string;
  cve_id?: string | null;
  remediation: string;
  remediation_complexity?: string;
  remediation_priority?: string;
  references?: string[];
  confidence?: number;
  false_positive?: boolean;
  exploit_available?: boolean;
  exploit_maturity?: string;
  business_impact?: string;
  technical_impact?: string;
  found_at?: string;
  scan_duration_ms?: number;
  scanner_version?: string;
  scan_metadata?: Record<string, unknown>;
}

/**
 * ScanReport — complete vulnerability scan report.
 * Mirrors: backend/models/schemas.py → class ScanReport
 */
export interface ScanReport {
  scan_id: string;
  target?: string;
  scan_type?: string;
  total_files_scanned?: number;
  findings: VulnerabilityFinding[];
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  info_count?: number;
  security_score?: number;
  scan_duration_ms?: number;
  scanned_at?: string;
  scan_metadata?: Record<string, unknown>;
}

/**
 * ActuarialRiskProfile — output of actuarial risk engine.
 * Mirrors: backend/models/schemas.py → class ActuarialRiskProfile
 */
export interface ActuarialRiskProfile {
  expected_loss_zar: number;
  var_95_zar: number;
  cvar_95_zar: number;
  annual_frequency?: number;
  detection_rate_without?: number;
  detection_rate_with?: number;
  risk_reduction?: number;
  roi_per_node_zar?: number;
  deterrence_index?: number;
}

/**
 * EpidemiologicalState — output of epidemiological model.
 * Mirrors: backend/models/schemas.py → class EpidemiologicalState
 */
export interface EpidemiologicalState {
  susceptible: number;
  infected: number;
  recovered: number;
  total: number;
  r0: number;
  beta: number;
  gamma: number;
  herd_immunity_pct: number;
  herd_immunity_threshold?: number;
  herd_immunity_reached: boolean;
  immune_fraction: number;
  time_to_herd_immunity_hours: number;
  mesh_effectiveness: number;
}

/**
 * PipelineState — current state of 7-stage AIR pipeline.
 * Mirrors: backend/models/schemas.py → class PipelineState
 */
export interface PipelineState {
  stage: number;
  stage_name: string;
  incident_id?: string | null;
  started_at?: string;
  progress: number;
  estimated_completion?: string | null;
  sub_stages?: Record<string, unknown>[];
  errors?: string[];
  warnings?: string[];
  processor_load?: number;
  memory_load?: number;
  next_stage_eta?: number | null;
}

// ─────────────────────────────────────────────────────────────────────
// BATTLEGROUND (no Pydantic model — backend returns raw dicts)
// These types are inferred from arena.get_battle_history() output
// and WebSocket battleground_round events.
// ─────────────────────────────────────────────────────────────────────

/**
 * A single round in a Red vs Blue battle.
 */
export interface BattleRound {
  round: number;
  red_variant?: string;
  blue_blocked: boolean;
  confidence?: number;
  evasion_technique?: string;
  detection_method?: string;
}

/**
 * A complete battle session (Red Agent stress-testing one antibody).
 */
export interface BattleSession {
  session_id?: string;
  antibody_id: string;
  rounds: BattleRound[];
  red_wins: number;
  blue_wins: number;
  total_rounds: number;
  result: string;
  final_strength?: number;
  timestamp: string;
}

// ─────────────────────────────────────────────────────────────────────
// EVOLUTION TIMELINE
// ─────────────────────────────────────────────────────────────────────

/**
 * A single point on the evolution timeline.
 * Emitted by Agent 6 (Evolution Tracker) after each event.
 */
export interface EvolutionPoint {
  timestamp: string;
  immunity_score: number;
  red_wins?: number;
  blue_wins?: number;
  antibodies_promoted?: number;
  event_type?: string;
  description?: string;
}

// ─────────────────────────────────────────────────────────────────────
// RISK PORTFOLIO (from GET /api/risk/portfolio)
// ─────────────────────────────────────────────────────────────────────

export interface RiskPortfolioByType {
  antibody_count: number;
  ael_without: number;
  ael_with: number;
  reduction: number;
}

export interface RiskPortfolio {
  total_annual_expected_loss_without: number;
  total_annual_expected_loss_with: number;
  total_risk_reduction_zar: number;
  total_risk_reduction_pct: number;
  average_deterrence: number;
  by_attack_type: Record<string, RiskPortfolioByType>;
}

// ─────────────────────────────────────────────────────────────────────
// COMPLIANCE (no Pydantic model — backend returns raw dicts)
// Defensive types with optional fields.
// ─────────────────────────────────────────────────────────────────────

export interface ControlAssessment {
  control_id: string;
  control_name: string;
  status: string;
  score?: number;
  evidence?: string[];
  gaps?: string[];
  recommendations?: string[];
}

export interface FrameworkAssessment {
  framework: ComplianceFramework;
  framework_name?: string;
  overall_score: number;
  controls: ControlAssessment[];
  assessed_at?: string;
}

export interface CompliancePosture {
  overall_score: number;
  frameworks: FrameworkAssessment[];
  last_assessed?: string;
}

export interface ComplianceReport {
  report_id?: string;
  report_type: string;
  framework?: ComplianceFramework;
  content?: string;
  generated_at?: string;
  status?: string;
}

// ─────────────────────────────────────────────────────────────────────
// API RESPONSE WRAPPERS
// These match the exact JSON shape returned by each endpoint.
// ─────────────────────────────────────────────────────────────────────

/** GET /api/antibodies */
export interface AntibodiesResponse {
  antibodies: Antibody[];
  total: number;
  page: number;
  page_size: number;
}

/** GET /api/health */
export interface SystemHealth {
  status: string;
  version: string;
  node_id: string;
  provider: string;
  immunity_score: number;
  antibody_count: number;
  mesh_nodes: number;
  uptime_seconds: number;
}

/** POST /api/threats response */
export interface ThreatSubmitResponse {
  incident_id: string;
  status: string;
}

// ─────────────────────────────────────────────────────────────────────
// WEBSOCKET EVENT PAYLOADS
// These match the exact JSON shape emitted by backend WebSocket.
// ─────────────────────────────────────────────────────────────────────

export type WebSocketEventType =
  | 'ping'
  | 'pipeline_stage'
  | 'threat_detected'
  | 'antibody_synthesised'
  | 'antibody_promoted'
  | 'immunity_update'
  | 'mesh_update'
  | 'battleground_round'
  | 'evolution_update';

export interface WebSocketMessage {
  type: WebSocketEventType;
  data: unknown;
  timestamp?: string;
}

/** Payload for 'threat_detected' event */
export interface WsThreatDetected {
  incident_id: string;
  content?: string;
  attack_family?: string;
  attack_type?: AttackType;
  severity?: Severity;
  classification?: ThreatVerdict;
  vector?: ThreatVector;
  language?: Language;
  surprise_score?: number;
  confidence?: number;
  timestamp: string;
}

/** Payload for 'antibody_synthesised' and 'antibody_promoted' events */
export interface WsAntibodyEvent {
  antibody_id: string;
  attack_family?: string;
  strength_score: number;
  status: AntibodyStatus;
  formally_verified?: boolean;
  timestamp?: string;
}

/** Payload for 'immunity_update' event */
export interface WsImmunityUpdate {
  score: number;
  delta?: number;
  reason?: string;
}

/** Payload for 'mesh_update' event */
export interface WsMeshUpdate {
  node_id: string;
  status: string;
  antibodies_count?: number;
  latency_ms?: number;
  event?: MeshEventType;
}

/** Payload for 'battleground_round' event */
export interface WsBattlegroundRound {
  session_id?: string;
  antibody_id: string;
  round: number;
  red_variant?: string;
  blue_blocked: boolean;
  red_wins: number;
  blue_wins: number;
  total_rounds: number;
  result?: string;
  final_strength?: number;
  timestamp: string;
}

/** Payload for 'evolution_update' event */
export interface WsEvolutionUpdate {
  timestamp: string;
  immunity_score: number;
  red_wins?: number;
  blue_wins?: number;
  antibodies_promoted?: number;
  event_type?: string;
  description?: string;
}

/** Payload for 'pipeline_stage' event */
export interface WsPipelineStage {
  stage: number;
  stage_name: string;
  incident_id?: string;
  progress: number;
  started_at?: string;
  errors?: string[];
  warnings?: string[];
}

// ─────────────────────────────────────────────────────────────────────
// UI STATE TYPES (frontend-only, not mirroring backend)
// ─────────────────────────────────────────────────────────────────────

export type ThemeMode = 'midnight' | 'twilight' | 'overcast';
export type DensityMode = 'compact' | 'comfortable' | 'spacious';
export type AudienceLevel = 'soc' | 'ir' | 'ciso' | 'it' | 'finance' | 'auditor';

export interface UserPreferences {
  theme: ThemeMode;
  density: DensityMode;
  audience: AudienceLevel;
  notifications_enabled: boolean;
  sound_enabled: boolean;
  auto_demo: boolean;
}

export interface ToastNotification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info' | 'immune';
  title: string;
  message?: string;
  duration?: number;
  action?: { label: string; onClick: () => void };
}

export interface CommandPaletteItem {
  id: string;
  label: string;
  description?: string;
  icon?: string;
  category: string;
  action: () => void;
  keywords?: string[];
}

// ─────────────────────────────────────────────────────────────────────
// COPILOT
// ─────────────────────────────────────────────────────────────────────

export interface CopilotMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  audience?: AudienceLevel;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface RemediationPlan {
  plan_id?: string;
  finding_id?: string;
  steps: string[];
  estimated_effort?: string;
  priority?: string;
  generated_at?: string;
}

// ─────────────────────────────────────────────────────────────────────
// HONEYPOT / DECEPTION
// ─────────────────────────────────────────────────────────────────────

export interface HoneypotSession {
  session_id: string;
  honeypot_type: string;
  attacker_ip?: string;
  commands: string[];
  tools_detected?: string[];
  mitre_techniques?: string[];
  threat_level?: string;
  started_at: string;
  ended_at?: string;
  duration_seconds?: number;
}

export interface CanaryToken {
  token_id: string;
  token_type: string;
  deployed_at?: string;
  triggered: boolean;
  triggered_at?: string | null;
  trigger_count?: number;
  location?: string;
}

// ─────────────────────────────────────────────────────────────────────
// THREAT ACTOR FINGERPRINTING
// ─────────────────────────────────────────────────────────────────────

export interface ThreatActor {
  actor_id: string;
  actor_type?: ThreatActorType;
  cluster_label?: string;
  fingerprint?: number[];
  techniques?: string[];
  active_hours?: number[];
  sophistication_score?: number;
  predicted_next_attack?: string;
  risk_score?: number;
  first_seen?: string;
  last_seen?: string;
  incident_count?: number;
}

// ─────────────────────────────────────────────────────────────────────
// PROVIDER INFO (for settings page)
// ─────────────────────────────────────────────────────────────────────

export interface ProviderInfo {
  name: string;
  status: 'active' | 'inactive' | 'error' | 'rate_limited';
  model?: string;
  latency_ms?: number;
  requests_today?: number;
  errors_today?: number;
}


export interface AntibodyVerification {
  sound?: boolean;
  non_trivial?: boolean;
  consistent?: boolean;
  method?: string;
  signals_verified?: number;
  reason?: string;
}

export interface PipelineState {
  stage: number;
  stage_name: string;
  incident_id?: string | null;
  started_at?: string;
  progress: number;
  estimated_completion?: string | null;
  sub_stages?: Record<string, unknown>[];
  errors?: string[];
  warnings?: string[];
  processor_load?: number;
  memory_load?: number;
  next_stage_eta?: number | null;
}

export interface MeshNode {
  node_id: string;
  org_type?: string;
  node_type?: string;
  hostname?: string;
  ip_address?: string;
  city?: string;
  country?: string;
  status: string;
  last_seen?: string | null;
  antibodies_count?: number;
  latency_ms?: number | null;
  uptime_seconds?: number;
  cpu_usage?: number;
  memory_usage?: number;
  disk_usage?: number;
  network_in?: number;
  network_out?: number;
  created_at?: string;
  last_heartbeat?: string | null;
  version?: string;
  capabilities?: string[];
}

export interface BattleSession {
  session_id?: string;
  antibody_id: string;
  rounds: BattleRound[];
  red_wins: number;
  blue_wins: number;
  total_rounds: number;
  result: string;
  final_strength?: number;
  timestamp: string;
}

export interface BattleRound {
  round: number;
  red_variant?: string;
  blue_blocked: boolean;
  confidence?: number;
  evasion_technique?: string;
  detection_method?: string;
}

export interface EpidemiologicalState {
  susceptible: number;
  infected: number;
  recovered: number;
  total: number;
  r0: number;
  beta: number;
  gamma: number;
  herd_immunity_pct: number;
  herd_immunity_threshold?: number;
  herd_immunity_reached: boolean;
  immune_fraction: number;
  time_to_herd_immunity_hours: number;
  mesh_effectiveness: number;
}

// ─── WebSocket Events ─────────────────────────────────────────────────────────

export interface WebSocketEvent {
  type: string;
  payload: unknown;
  timestamp?: string;
}
