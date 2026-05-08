"""
IMMUNIS ACIN — Pydantic Schemas

Single source of truth for ALL data structures in the system.
Every agent input, every agent output, every API request, every API response,
every WebSocket event, every database record — defined HERE.

Design principles:
1. Strict mode everywhere — no implicit type coercion
2. Every field has a description — self-documenting API
3. Validators catch LLM output inconsistencies at the boundary
4. Optional fields have sensible defaults — degraded results are valid results
5. Immutable where possible — data flows forward, never mutated in place

Temperature: 0.3 (data definitions must be precise)
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from backend.models.enums import (
    AIProvider,
    AntibodyStatus,
    AttackType,
    ComplianceFramework,
    ContainmentAction,
    Language,
    ManipulationTechnique,
    MeshEventType,
    MitrePhase,
    PipelineStage,
    Severity,
    SurpriseLevel,
    ThreatActorType,
    ThreatVector,
    ThreatVerdict,
    VisualThreatType,
    VulnerabilitySeverity,
)


# ============================================================================
# UTILITY
# ============================================================================

def generate_id(prefix: str = "") -> str:
    """Generate a unique ID with optional prefix. E.g., 'ATK-a3f8b2c1'."""
    uid = uuid.uuid4().hex[:12]
    return f"{prefix}-{uid}" if prefix else uid


def utc_now() -> datetime:
    """Current UTC timestamp — always timezone-aware."""
    return datetime.now(timezone.utc)


def content_hash(content: str) -> str:
    """
    Truncated SHA-256 hash for deduplication.
    16 hex chars = 64 bits. Collision probability at 10K items: ~1 in 10^14.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


# ============================================================================
# LAYER 1 — THREAT INPUT
# ============================================================================

class ThreatInput(BaseModel):
    """
    Raw threat data arriving at IMMUNIS.
    This is the entry point — everything starts here.
    Can come from email gateway, network sensor, API call, or manual upload.
    """
    content: str = Field(
        ...,
        min_length=1,
        max_length=1_000_000,
        description="Raw threat content (email body, log entry, transcript, URL)",
    )
    vector: ThreatVector = Field(
        default=ThreatVector.UNKNOWN,
        description="How the threat arrived",
    )
    language_hint: Optional[Language] = Field(
        default=None,
        description="Language hint from upstream (email headers, user selection)",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context (email headers, sender, subject, IP, etc.)",
    )
    image_base64: Optional[str] = Field(
        default=None,
        description="Base64-encoded image for visual analysis (QR code, screenshot, document)",
    )
    audio_base64: Optional[str] = Field(
        default=None,
        description="Base64-encoded audio for vishing analysis",
    )
    source_node_id: Optional[str] = Field(
        default=None,
        description="Originating mesh node ID (if received from mesh)",
    )
    timestamp: datetime = Field(
        default_factory=utc_now,
        description="When the threat was received",
    )

    @field_validator("content")
    @classmethod
    def strip_null_bytes(cls, v: str) -> str:
        """Remove null bytes that can corrupt downstream processing."""
        return v.replace("\x00", "")

    @property
    def content_hash(self) -> str:
        """Deterministic hash for deduplication."""
        return content_hash(self.content)

    @property
    def is_multimodal(self) -> bool:
        """Whether this threat has both text and visual/audio components."""
        return bool(self.image_base64 or self.audio_base64)


# ============================================================================
# STAGE 1 — SURPRISE DETECTION
# ============================================================================

class SurpriseResult(BaseModel):
    """Output of the information-theoretic surprise detector."""
    surprise_bits: float = Field(
        ...,
        ge=0.0,
        description="Information-theoretic surprise in bits. Higher = more novel.",
    )
    level: SurpriseLevel = Field(
        ...,
        description="Classified surprise level",
    )
    nearest_antibody_id: Optional[str] = Field(
        default=None,
        description="ID of the most similar antibody in the library",
    )
    nearest_similarity: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Cosine similarity to nearest antibody",
    )
    library_size: int = Field(
        default=0,
        ge=0,
        description="Number of antibodies in library at time of evaluation",
    )
    computation_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Time taken for surprise computation in milliseconds",
    )


# ============================================================================
# STAGE 2 — CONTAINMENT
# ============================================================================

class ContainmentPlan(BaseModel):
    """Output of the polymorphic containment engine."""
    containment_id: str = Field(
        default_factory=lambda: generate_id("CTN"),
    )
    actions: list[ContainmentAction] = Field(
        ...,
        min_length=1,
        description="Ordered list of containment actions to execute",
    )
    jaccard_distance_from_previous: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="How different this containment is from the last 10 (polymorphic property)",
    )
    blast_radius_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Estimated disruption to legitimate operations (lower = better)",
    )
    generated_at: datetime = Field(default_factory=utc_now)


# ============================================================================
# AGENT 1 — SEMANTIC FINGERPRINT
# ============================================================================

class SemanticFingerprint(BaseModel):
    """
    Output of Agent 1 (Incident Analyst).
    The structured semantic representation of a threat.
    Language-agnostic — a Sesotho BEC and an English BEC produce similar fingerprints.
    """
    fingerprint_id: str = Field(
        default_factory=lambda: generate_id("FP"),
    )
    attack_type: AttackType = Field(
        ...,
        description="Classification of the attack",
    )
    mitre_phase: MitrePhase = Field(
        default=MitrePhase.INITIAL_ACCESS,
        description="MITRE ATT&CK kill chain phase",
    )
    mitre_technique_id: str = Field(
        default="T1566",
        description="MITRE ATT&CK technique ID (e.g., T1566.001)",
    )
    manipulation_technique: ManipulationTechnique = Field(
        default=ManipulationTechnique.NONE,
        description="Primary psychological manipulation technique",
    )
    language_detected: Language = Field(
        default=Language.UNKNOWN,
        description="Detected language of the threat content",
    )
    code_switching_detected: bool = Field(
        default=False,
        description="Whether language switching was detected within the content",
    )
    severity: Severity = Field(
        default=Severity.MEDIUM,
        description="Assessed severity of the threat",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Agent confidence in this fingerprint (0.0 = no confidence, 1.0 = certain)",
    )
    intent: str = Field(
        default="",
        description="One sentence describing what the attacker wanted",
    )
    semantic_pattern: str = Field(
        default="",
        description="Language-agnostic description of the manipulation pattern",
    )
    target_asset: str = Field(
        default="",
        description="What was targeted (payment system, credentials, data, etc.)",
    )
    indicators_of_compromise: list[str] = Field(
        default_factory=list,
        description="Technical IOCs (domains, IPs, hashes, email headers)",
    )
    social_engineering_vectors: list[str] = Field(
        default_factory=list,
        description="Social engineering techniques identified",
    )
    urgency_signals: list[str] = Field(
        default_factory=list,
        description="Urgency markers found in the content",
    )
    financial_triggers: list[str] = Field(
        default_factory=list,
        description="Financial manipulation triggers found",
    )
    content_hash: str = Field(
        default="",
        description="SHA-256 truncated hash of original content for deduplication",
    )
    raw_input_summary: str = Field(
        default="",
        max_length=500,
        description="Brief summary of what was received (never raw content)",
    )
    processing_agent: str = Field(
        default="incident_analyst_v2",
        description="Which agent version produced this fingerprint",
    )
    degraded: bool = Field(
        default=False,
        description="Whether this is a degraded result from a failed LLM call",
    )
    degraded_reason: str = Field(
        default="",
        description="Why the result is degraded (if applicable)",
    )
    generated_at: datetime = Field(default_factory=utc_now)

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        """Clamp confidence to valid range."""
        return max(0.0, min(1.0, v))

    @field_validator("mitre_technique_id")
    @classmethod
    def validate_mitre_id(cls, v: str) -> str:
        """Basic validation of MITRE technique ID format."""
        v = v.strip().upper()
        if v and not v.startswith("T"):
            v = f"T{v}"
        return v


# ============================================================================
# AGENT 8 — VISUAL THREAT ASSESSMENT
# ============================================================================

class VisualIndicator(BaseModel):
    """A single visual indicator of a threat found in an image."""
    indicator_type: str = Field(
        ...,
        description="Type of visual indicator (url_bar_mismatch, logo_inconsistency, etc.)",
    )
    description: str = Field(
        ...,
        description="Human-readable description of what was found",
    )
    severity: Severity = Field(default=Severity.MEDIUM)
    bounding_box: Optional[list[int]] = Field(
        default=None,
        description="[x, y, width, height] of the indicator in the image",
    )


class VisualThreatAssessment(BaseModel):
    """Output of Agent 8 (Visual Threat Analyst)."""
    assessment_id: str = Field(
        default_factory=lambda: generate_id("VIS"),
    )
    threat_detected: bool = Field(default=False)
    threat_type: VisualThreatType = Field(default=VisualThreatType.BENIGN)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    visual_indicators: list[VisualIndicator] = Field(default_factory=list)
    decoded_content: str = Field(
        default="",
        description="Decoded content (e.g., URL from QR code)",
    )
    statistical_anomaly: Optional[dict[str, Any]] = Field(
        default=None,
        description="Steganographic analysis results (chi-squared, LSB entropy)",
    )
    recommendation: str = Field(default="")
    generated_at: datetime = Field(default_factory=utc_now)


# ============================================================================
# MULTIMODAL FUSION
# ============================================================================

class MultimodalFusionResult(BaseModel):
    """Combined result from text + visual + audio analysis."""
    fusion_id: str = Field(
        default_factory=lambda: generate_id("FUS"),
    )
    threat_detected: bool = Field(default=False)
    combined_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Noisy-OR fusion: 1 - (1-P_text)(1-P_visual)(1-P_audio)",
    )
    text_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    visual_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    audio_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    dominant_modality: str = Field(
        default="text",
        description="Which modality contributed most to the detection",
    )
    modalities_used: list[str] = Field(default_factory=lambda: ["text"])
    fingerprint: Optional[SemanticFingerprint] = Field(default=None)
    visual_assessment: Optional[VisualThreatAssessment] = Field(default=None)


# ============================================================================
# AGENT 2 — ANTIBODY
# ============================================================================

class Antibody(BaseModel):
    """
    The atomic unit of IMMUNIS.
    A structured, reusable, language-agnostic detection rule.
    Every other component exists to create, test, store, or distribute antibodies.
    """
    antibody_id: str = Field(
        default_factory=lambda: generate_id("AB"),
    )
    parent_fingerprint_id: str = Field(
        default="",
        description="ID of the fingerprint this antibody was synthesised from",
    )
    attack_family: str = Field(
        ...,
        description="Short name for the class of attack this detects",
    )
    attack_type: AttackType = Field(default=AttackType.OTHER)
    detection_signals: dict[str, bool] = Field(
        default_factory=dict,
        description="Named detection signals — each is a boolean check",
    )
    detection_signals_description: list[str] = Field(
        default_factory=list,
        description="Human-readable description of each detection signal",
    )
    cross_lingual_pattern: str = Field(
        default="",
        description="Language-agnostic description of the manipulation pattern",
    )
    language_variants: list[Language] = Field(
        default_factory=list,
        description="Languages this antibody has been validated against",
    )
    mitre_technique: str = Field(default="T1566")
    mitre_phase: MitrePhase = Field(default=MitrePhase.INITIAL_ACCESS)
    severity: Severity = Field(default=Severity.MEDIUM)
    confidence_threshold: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Minimum confidence to trigger this antibody",
    )
    false_positive_guards: list[str] = Field(
        default_factory=list,
        description="Conditions under which this antibody should NOT fire",
    )
    strength_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Antibody strength from Red Agent stress testing",
    )
    red_agent_tests: int = Field(
        default=0,
        ge=0,
        description="Number of Red Agent variants tested against this antibody",
    )
    red_agent_evasions: int = Field(
        default=0,
        ge=0,
        description="Number of Red Agent variants that evaded this antibody",
    )
    status: AntibodyStatus = Field(default=AntibodyStatus.PENDING)
    formally_verified: bool = Field(
        default=False,
        description="Whether Z3 formal verification passed",
    )
    verification_result: Optional[dict[str, Any]] = Field(
        default=None,
        description="Z3 verification details (sound, non-trivial, consistent)",
    )
    stix_indicator_id: Optional[str] = Field(
        default=None,
        description="STIX 2.1 indicator ID for interoperability",
    )
    # Actuarial risk metrics
    expected_loss_zar: float = Field(
        default=0.0,
        ge=0.0,
        description="Expected loss in ZAR if this attack succeeds",
    )
    var_95_zar: float = Field(
        default=0.0,
        ge=0.0,
        description="Value at Risk (95%) in ZAR",
    )
    cvar_95_zar: float = Field(
        default=0.0,
        ge=0.0,
        description="Conditional VaR (expected shortfall) in ZAR",
    )
    risk_reduction_factor: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="How much this antibody reduces the expected loss",
    )
    node_origin: str = Field(
        default="",
        description="Node ID that synthesised this antibody",
    )
    synthesised_at: datetime = Field(default_factory=utc_now)
    promoted_at: Optional[datetime] = Field(default=None)
    broadcast_at: Optional[datetime] = Field(default=None)

    @property
    def evasion_rate(self) -> float:
        """Fraction of Red Agent variants that evaded detection."""
        if self.red_agent_tests == 0:
            return 0.0
        return self.red_agent_evasions / self.red_agent_tests

    @property
    def is_broadcast_ready(self) -> bool:
        """Whether this antibody meets all criteria for mesh broadcast."""
        return (
            self.status in (AntibodyStatus.VALIDATED, AntibodyStatus.PROMOTED)
            and self.strength_score >= 0.85
            and self.formally_verified
        )


# ============================================================================
# AGENT 3 — IMMUNE MEMORY
# ============================================================================

class MemorySearchResult(BaseModel):
    """Result of searching the antibody library."""
    query_vector_hash: str = Field(default="")
    matches: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of {antibody_id, similarity, antibody_summary}",
    )
    best_match_id: Optional[str] = Field(default=None)
    best_match_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    verdict: ThreatVerdict = Field(default=ThreatVerdict.NOVEL)
    bridge_antibody_ids: list[str] = Field(
        default_factory=list,
        description="Antibody IDs to use as bridge defense (for novel threats)",
    )
    library_size: int = Field(default=0)
    search_ms: float = Field(default=0.0)


class MemoryStoreResult(BaseModel):
    """Result of storing an antibody in the library."""
    action: str = Field(
        ...,
        description="stored | deduplicated | clustered",
    )
    antibody_id: str = Field(...)
    family_id: str = Field(default="")
    family_name: str = Field(default="")
    family_size: int = Field(default=0)
    is_variant_of: Optional[str] = Field(default=None)
    library_size: int = Field(default=0)


# ============================================================================
# AGENT 4 — RED AGENT
# ============================================================================

class EvasionVariant(BaseModel):
    """A single evasion variant generated by the Red Agent."""
    variant_id: str = Field(
        default_factory=lambda: generate_id("RED"),
    )
    target_antibody_id: str = Field(
        ...,
        description="The antibody this variant is trying to evade",
    )
    evasion_vector: str = Field(
        ...,
        description="Which evasion vector was used (language_switch, semantic_rephrase, etc.)",
    )
    evasion_strategy: str = Field(
        default="",
        description="Description of how this variant tries to evade detection",
    )
    synthetic_attack: str = Field(
        default="",
        max_length=5000,
        description="The crafted attack content",
    )
    predicted_evasion_success: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Red Agent's estimate of evasion probability",
    )
    weakness_exploited: str = Field(
        default="",
        description="What gap in the antibody this exploits",
    )
    actor_type_constraint: ThreatActorType = Field(
        default=ThreatActorType.UNKNOWN,
        description="Threat actor type this variant is constrained to",
    )
    generated_at: datetime = Field(default_factory=utc_now)


class RedAgentResult(BaseModel):
    """Complete output of a Red Agent stress test round."""
    round_id: str = Field(
        default_factory=lambda: generate_id("RND"),
    )
    antibody_id: str = Field(...)
    variants: list[EvasionVariant] = Field(default_factory=list)
    total_variants: int = Field(default=0)
    evasions_succeeded: int = Field(default=0)
    evasion_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    vectors_attempted: list[str] = Field(default_factory=list)
    duration_ms: float = Field(default=0.0)


# ============================================================================
# AGENT 5 — VARIANT RECOGNISER (BLUE)
# ============================================================================

class ClassificationResult(BaseModel):
    """Output of Agent 5 classifying a threat or Red Agent variant."""
    classification_id: str = Field(
        default_factory=lambda: generate_id("CLS"),
    )
    verdict: ThreatVerdict = Field(...)
    matched_antibody_id: Optional[str] = Field(default=None)
    similarity_score: float = Field(default=0.0, ge=0.0, le=1.0)
    variant_of_family: Optional[str] = Field(default=None)
    variant_delta: str = Field(
        default="",
        description="What is different from the known attack",
    )
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = Field(
        default="",
        description="Why this classification was made",
    )
    blue_learning_signal: Optional[str] = Field(
        default=None,
        description="If NOVEL: what the antibody missed and should learn",
    )
    classified_at: datetime = Field(default_factory=utc_now)


# ============================================================================
# AGENT 6 — EVOLUTION TRACKER
# ============================================================================

class EvolutionEvent(BaseModel):
    """A single event in the arms race history."""
    event_id: str = Field(
        default_factory=lambda: generate_id("EVT"),
    )
    event_type: PipelineStage = Field(...)
    agent_source: str = Field(default="")
    antibody_id: Optional[str] = Field(default=None)
    attack_family: Optional[str] = Field(default=None)
    description: str = Field(default="")
    immunity_score_before: float = Field(default=0.0)
    immunity_score_after: float = Field(default=0.0)
    immunity_delta: float = Field(default=0.0)
    timestamp: datetime = Field(default_factory=utc_now)


class ImmunityState(BaseModel):
    """Current state of the immune system — powers the dashboard."""
    immunity_score: float = Field(default=50.0, ge=0.0, le=100.0)
    trend: str = Field(default="stable", description="improving | stable | degrading")
    total_antibodies: int = Field(default=0)
    total_threats_processed: int = Field(default=0)
    total_threats_blocked: int = Field(default=0)
    total_novel_detected: int = Field(default=0)
    total_red_attacks: int = Field(default=0)
    total_blue_wins: int = Field(default=0)
    total_red_wins: int = Field(default=0)
    active_containments: int = Field(default=0)
    mesh_nodes_connected: int = Field(default=0)
    last_threat_at: Optional[datetime] = Field(default=None)
    last_antibody_at: Optional[datetime] = Field(default=None)
    # PID controller state
    pid_error: float = Field(default=0.0)
    pid_integral: float = Field(default=0.0)
    pid_derivative: float = Field(default=0.0)


# ============================================================================
# AGENTS 9-11 — MATHEMATICAL ENGINES
# ============================================================================

class EpidemiologicalState(BaseModel):
    """Output of the epidemiological model (Agent 9)."""
    susceptible: int = Field(default=0, description="Nodes without antibody for this threat")
    infected: int = Field(default=0, description="Nodes currently under attack")
    recovered: int = Field(default=0, description="Nodes with antibody (immune)")
    total_nodes: int = Field(default=0)
    r0_immunity: float = Field(
        default=0.0,
        description="Basic reproduction number of immunity (>1 = immunity spreads faster than attacks)",
    )
    herd_immunity_threshold: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Fraction of nodes that must be immune for herd immunity",
    )
    time_to_herd_immunity_hours: Optional[float] = Field(
        default=None,
        description="Estimated hours until herd immunity is reached",
    )


class ActuarialRiskProfile(BaseModel):
    """Output of the actuarial risk engine (Agent 10)."""
    expected_loss_zar: float = Field(default=0.0, ge=0.0)
    var_95_zar: float = Field(default=0.0, ge=0.0, description="Value at Risk 95%")
    cvar_95_zar: float = Field(default=0.0, ge=0.0, description="Conditional VaR 95%")
    annual_frequency: float = Field(default=0.0, ge=0.0, description="Expected attacks per year")
    annual_expected_loss_zar: float = Field(default=0.0, ge=0.0)
    risk_reduction_factor: float = Field(default=0.0, ge=0.0, le=1.0)
    roi_per_node_zar: float = Field(default=0.0, description="ROI of deploying this antibody")
    deterrence_index: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="How unprofitable it is to attack (1.0 = completely unprofitable)",
    )


class DefenseAllocation(BaseModel):
    """Output of the game-theoretic defense allocator (Agent 11)."""
    allocation: dict[str, float] = Field(
        default_factory=dict,
        description="Threat category → fraction of defensive resources",
    )
    expected_risk_reduction_zar: float = Field(default=0.0)
    efficient_frontier_point: bool = Field(
        default=False,
        description="Whether this allocation is on the efficient frontier",
    )
    recommendation: str = Field(default="")


# ============================================================================
# ARBITER — BATTLEGROUND JUDGE
# ============================================================================

class ArbiterDecision(BaseModel):
    """Output of the Arbiter after evaluating an antibody in the Battleground."""
    decision_id: str = Field(
        default_factory=lambda: generate_id("ARB"),
    )
    antibody_id: str = Field(...)
    rounds_completed: int = Field(default=0)
    final_strength: float = Field(default=0.0, ge=0.0, le=1.0)
    promoted: bool = Field(default=False)
    promotion_reason: str = Field(default="")
    resistance_report: Optional[dict[str, Any]] = Field(
        default=None,
        description="Generated when antibody cannot reach threshold after max iterations",
    )
    escalated_to_human: bool = Field(default=False)
    decided_at: datetime = Field(default_factory=utc_now)


# ============================================================================
# MESH NETWORK
# ============================================================================

class MeshBroadcast(BaseModel):
    """An antibody broadcast package for the mesh network."""
    broadcast_id: str = Field(
        default_factory=lambda: generate_id("MESH"),
    )
    antibody: Antibody = Field(...)
    source_node_id: str = Field(...)
    classical_signature: str = Field(
        default="",
        description="Ed25519 signature (base64)",
    )
    post_quantum_signature: str = Field(
        default="",
        description="CRYSTALS-Dilithium signature (base64)",
    )
    ttl_hops: int = Field(default=7, ge=0, le=20)
    broadcast_at: datetime = Field(default_factory=utc_now)
    epidemiological_priority: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="R₀-based priority score — higher = more urgent distribution",
    )
    stix_bundle: Optional[dict[str, Any]] = Field(
        default=None,
        description="STIX 2.1 bundle for interoperability export",
    )

    @property
    def is_valid_signature(self) -> bool:
        """Quick check that signatures are present (actual verification done in crypto.py)."""
        return bool(self.classical_signature)


class MeshNodeStatus(BaseModel):
    """Status of a single mesh node."""
    node_id: str = Field(...)
    org_type: str = Field(default="PublicSector")
    region: str = Field(default="gauteng")
    immunity_score: float = Field(default=0.0, ge=0.0, le=100.0)
    antibody_count: int = Field(default=0)
    last_seen: datetime = Field(default_factory=utc_now)
    healthy: bool = Field(default=True)
    trust_score: float = Field(default=1.0, ge=0.0, le=1.0)
    quarantined: bool = Field(default=False)


# ============================================================================
# COMPLIANCE
# ============================================================================

class ComplianceMapping(BaseModel):
    """Mapping of an antibody to regulatory frameworks."""
    antibody_id: str = Field(...)
    frameworks: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Framework name → list of relevant sections/controls",
    )
    composite_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Weighted composite compliance score (0-100)",
    )
    popia_notification_required: bool = Field(default=False)
    popia_notification_draft: Optional[str] = Field(default=None)
    cybercrimes_report_draft: Optional[str] = Field(default=None)
    executive_brief: Optional[str] = Field(default=None)


# ============================================================================
# VULNERABILITY SCANNER
# ============================================================================

class VulnerabilityFinding(BaseModel):
    """A single vulnerability found by the scanner."""
    finding_id: str = Field(
        default_factory=lambda: generate_id("VULN"),
    )
    cwe: str = Field(default="CWE-Unknown", description="Common Weakness Enumeration ID")
    cve: Optional[str] = Field(default=None, description="CVE ID if known")
    severity: VulnerabilitySeverity = Field(default=VulnerabilitySeverity.MEDIUM)
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    file_path: str = Field(default="")
    line_number: int = Field(default=0, ge=0)
    function_name: str = Field(default="")
    description: str = Field(default="")
    exploitation_scenario: str = Field(default="")
    fix_suggestion: Optional[str] = Field(default=None)
    fix_diff: Optional[str] = Field(default=None)
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    source: str = Field(
        default="semantic",
        description="How it was found: semantic | pattern | dependency | dynamic",
    )
    found_at: datetime = Field(default_factory=utc_now)


class ScanReport(BaseModel):
    """Complete vulnerability scan report."""
    scan_id: str = Field(
        default_factory=lambda: generate_id("SCAN"),
    )
    target: str = Field(default="", description="What was scanned (repo path, URL, etc.)")
    scan_type: str = Field(default="static", description="static | dynamic | infrastructure")
    total_files_scanned: int = Field(default=0)
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)
    info_count: int = Field(default=0)
    security_score: float = Field(
        default=100.0,
        ge=0.0,
        le=100.0,
        description="100 minus weighted deductions per finding",
    )
    scan_duration_ms: float = Field(default=0.0)
    scanned_at: datetime = Field(default_factory=utc_now)


# ============================================================================
# THREAT ACTOR FRAMEWORK
# ============================================================================

class ThreatActorCluster(BaseModel):
    """A cluster of attacks attributed to the same threat actor."""
    cluster_id: str = Field(
        default_factory=lambda: generate_id("TAC"),
    )
    actor_type: ThreatActorType = Field(default=ThreatActorType.UNKNOWN)
    attack_count: int = Field(default=0)
    dominant_technique: str = Field(default="")
    dominant_language: Language = Field(default=Language.UNKNOWN)
    target_sector_preference: str = Field(default="")
    patience_index: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="0=impulsive, 1=extremely patient",
    )
    novelty_appetite: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="0=uses known TTPs, 1=generates novel variants",
    )
    persistence_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="How many times they retry after a block",
    )
    escalation_pattern: str = Field(
        default="gradual",
        description="gradual | sudden | no_escalation",
    )
    predicted_next_techniques: list[str] = Field(
        default_factory=list,
        description="Top 3 MITRE techniques predicted for next attack",
    )
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    member_antibody_ids: list[str] = Field(default_factory=list)


# ============================================================================
# DECEPTION LAYER
# ============================================================================

class CanaryToken(BaseModel):
    """A cryptographically signed bait token."""
    token_id: str = Field(
        default_factory=lambda: generate_id("CNR"),
    )
    token_string: str = Field(default="", description="Opaque base64url token for URLs")
    antibody_id: str = Field(default="", description="Which antibody triggered bait generation")
    bait_type: str = Field(
        default="email_address",
        description="email_address | document_link | banking_form | otp_page | credential_form",
    )
    active: bool = Field(default=True)
    interaction_count: int = Field(default=0)
    created_at: datetime = Field(default_factory=utc_now)
    last_triggered: Optional[datetime] = Field(default=None)


class HoneypotInteraction(BaseModel):
    """A captured interaction with the adaptive honeypot."""
    interaction_id: str = Field(
        default_factory=lambda: generate_id("HP"),
    )
    canary_token_id: str = Field(default="")
    # POPIA-compliant: no PII, behavior only
    country_code: str = Field(default="ZZ", max_length=2, description="ISO 3166-1 alpha-2")
    user_agent_hash: str = Field(default="", description="SHA-256 of User-Agent, not raw UA")
    tool_signature_hash: str = Field(default="", description="SHA-256 of HTTP signature")
    request_method: str = Field(default="GET")
    interaction_depth: int = Field(default=0, ge=0, le=3)
    time_spent_seconds: float = Field(default=0.0, ge=0.0)
    actions_taken: list[str] = Field(default_factory=list)
    captured_at: datetime = Field(default_factory=utc_now)


# ============================================================================
# PIPELINE RESULT — THE COMPLETE OUTPUT
# ============================================================================

class PipelineResult(BaseModel):
    """
    Complete output of the 7-stage AIR pipeline.
    This is what the frontend receives via WebSocket.
    This is what gets stored in the audit trail.
    This is what powers every dashboard component.
    """
    pipeline_id: str = Field(
        default_factory=lambda: generate_id("PL"),
    )
    threat_input_hash: str = Field(default="")
    
    # Stage 1: Surprise
    surprise: Optional[SurpriseResult] = Field(default=None)
    
    # Stage 2: Containment
    containment: Optional[ContainmentPlan] = Field(default=None)
    
    # Stage 3: Deception
    honeypot_activated: bool = Field(default=False)
    canary_tokens_deployed: int = Field(default=0)
    
    # Agent 1: Fingerprint
    fingerprint: Optional[SemanticFingerprint] = Field(default=None)
    
    # Agent 8: Visual
    visual_assessment: Optional[VisualThreatAssessment] = Field(default=None)
    
    # Multimodal fusion
    fusion: Optional[MultimodalFusionResult] = Field(default=None)
    
    # Agent 2: Antibody
    antibody: Optional[Antibody] = Field(default=None)
    
    # Agent 3: Memory
    memory_result: Optional[MemoryStoreResult] = Field(default=None)
    memory_search: Optional[MemorySearchResult] = Field(default=None)
    
    # Agent 5: Classification
    classification: Optional[ClassificationResult] = Field(default=None)
    
    # Battleground
    red_agent_result: Optional[RedAgentResult] = Field(default=None)
    arbiter_decision: Optional[ArbiterDecision] = Field(default=None)
    
    # Agent 6: Evolution
    immunity_state: Optional[ImmunityState] = Field(default=None)
    evolution_events: list[EvolutionEvent] = Field(default_factory=list)
    
    # Mathematical engines
    epidemiological: Optional[EpidemiologicalState] = Field(default=None)
    actuarial_risk: Optional[ActuarialRiskProfile] = Field(default=None)
    defense_allocation: Optional[DefenseAllocation] = Field(default=None)
    
    # Compliance
    compliance: Optional[ComplianceMapping] = Field(default=None)
    
    # TAF
    threat_actor: Optional[ThreatActorCluster] = Field(default=None)
    
    # Mesh
    mesh_broadcast: Optional[MeshBroadcast] = Field(default=None)
    
    # Response layer
    soc_narrative: str = Field(default="")
    architect_plan: str = Field(default="")
    executive_brief: str = Field(default="")
    
    # Pipeline metadata
    stages_completed: list[PipelineStage] = Field(default_factory=list)
    total_duration_ms: float = Field(default=0.0)
    success: bool = Field(default=True)
    error_message: str = Field(default="")
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = Field(default=None)

    @property
    def is_threat(self) -> bool:
        """Whether this pipeline result represents a detected threat."""
        if self.fingerprint and self.fingerprint.attack_type != AttackType.BENIGN:
            return True
        if self.fusion and self.fusion.threat_detected:
            return True
        return False

    @property
    def highest_confidence(self) -> float:
        """Highest confidence across all detection modalities."""
        confidences = []
        if self.fingerprint:
            confidences.append(self.fingerprint.confidence)
        if self.visual_assessment:
            confidences.append(self.visual_assessment.confidence)
        if self.fusion:
            confidences.append(self.fusion.combined_confidence)
        return max(confidences) if confidences else 0.0


# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

class WebSocketEvent(BaseModel):
    """
    Every WebSocket message sent to the frontend.
    Typed events enable the frontend to handle unknown future event types gracefully.
    """
    event_type: str = Field(
        ...,
        description="Event type identifier for frontend routing",
    )
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Event-specific data",
    )
    timestamp: datetime = Field(default_factory=utc_now)
    pipeline_id: Optional[str] = Field(default=None)

    @classmethod
    def threat_received(cls, threat_input: ThreatInput, pipeline_id: str) -> "WebSocketEvent":
        return cls(
            event_type="threat_received",
            payload={
                "vector": threat_input.vector.value,
                "language_hint": threat_input.language_hint.value if threat_input.language_hint else None,
                "content_hash": threat_input.content_hash,
                "is_multimodal": threat_input.is_multimodal,
                "timestamp": threat_input.timestamp.isoformat(),
            },
            pipeline_id=pipeline_id,
        )

    @classmethod
    def surprise_computed(cls, result: SurpriseResult, pipeline_id: str) -> "WebSocketEvent":
        return cls(
            event_type="surprise_computed",
            payload={
                "surprise_bits": result.surprise_bits,
                "level": result.level.value,
                "nearest_similarity": result.nearest_similarity,
                "computation_ms": result.computation_ms,
            },
            pipeline_id=pipeline_id,
        )

    @classmethod
    def fingerprint_ready(cls, fp: SemanticFingerprint, pipeline_id: str) -> "WebSocketEvent":
        return cls(
            event_type="fingerprint_ready",
            payload={
                "fingerprint_id": fp.fingerprint_id,
                "attack_type": fp.attack_type.value,
                "severity": fp.severity.value,
                "confidence": fp.confidence,
                "language": fp.language_detected.value,
                "manipulation": fp.manipulation_technique.value,
                "intent": fp.intent,
                "mitre_technique": fp.mitre_technique_id,
            },
            pipeline_id=pipeline_id,
        )

    @classmethod
    def antibody_synthesised(cls, ab: Antibody, pipeline_id: str) -> "WebSocketEvent":
        return cls(
            event_type="antibody_synthesised",
            payload={
                "antibody_id": ab.antibody_id,
                "attack_family": ab.attack_family,
                "severity": ab.severity.value,
                "formally_verified": ab.formally_verified,
                "strength_score": ab.strength_score,
                "status": ab.status.value,
            },
            pipeline_id=pipeline_id,
        )

    @classmethod
    def red_attack(cls, variant: EvasionVariant, pipeline_id: str) -> "WebSocketEvent":
        return cls(
            event_type="red_attack",
            payload={
                "variant_id": variant.variant_id,
                "target_antibody_id": variant.target_antibody_id,
                "evasion_vector": variant.evasion_vector,
                "predicted_success": variant.predicted_evasion_success,
            },
            pipeline_id=pipeline_id,
        )

    @classmethod
    def blue_defense(cls, classification: ClassificationResult, pipeline_id: str) -> "WebSocketEvent":
        return cls(
            event_type="blue_defense",
            payload={
                "classification_id": classification.classification_id,
                "verdict": classification.verdict.value,
                "confidence": classification.confidence,
                "matched_antibody_id": classification.matched_antibody_id,
            },
            pipeline_id=pipeline_id,
        )

    @classmethod
    def immunity_update(cls, state: ImmunityState) -> "WebSocketEvent":
        return cls(
            event_type="immunity_update",
            payload={
                "score": state.immunity_score,
                "trend": state.trend,
                "total_antibodies": state.total_antibodies,
                "total_blocked": state.total_threats_blocked,
                "total_novel": state.total_novel_detected,
                "red_wins": state.total_red_wins,
                "blue_wins": state.total_blue_wins,
                "mesh_nodes": state.mesh_nodes_connected,
            },
        )

    @classmethod
    def mesh_broadcast_sent(cls, broadcast: MeshBroadcast) -> "WebSocketEvent":
        return cls(
            event_type="mesh_broadcast",
            payload={
                "broadcast_id": broadcast.broadcast_id,
                "antibody_id": broadcast.antibody.antibody_id,
                "source_node": broadcast.source_node_id,
                "priority": broadcast.epidemiological_priority,
                "ttl": broadcast.ttl_hops,
            },
        )

    @classmethod
    def containment_deployed(cls, plan: ContainmentPlan, pipeline_id: str) -> "WebSocketEvent":
        return cls(
            event_type="containment_deployed",
            payload={
                "containment_id": plan.containment_id,
                "actions": [a.value for a in plan.actions],
                "polymorphic_distance": plan.jaccard_distance_from_previous,
                "blast_radius": plan.blast_radius_score,
            },
            pipeline_id=pipeline_id,
        )

    @classmethod
    def arbiter_decision_made(cls, decision: ArbiterDecision, pipeline_id: str) -> "WebSocketEvent":
        return cls(
            event_type="arbiter_decision",
            payload={
                "decision_id": decision.decision_id,
                "antibody_id": decision.antibody_id,
                "promoted": decision.promoted,
                "final_strength": decision.final_strength,
                "rounds": decision.rounds_completed,
                "escalated": decision.escalated_to_human,
            },
            pipeline_id=pipeline_id,
        )

    @classmethod
    def novel_threat_detected(cls, surprise: SurpriseResult, pipeline_id: str) -> "WebSocketEvent":
        return cls(
            event_type="novel_threat",
            payload={
                "surprise_bits": surprise.surprise_bits,
                "level": surprise.level.value,
                "nearest_similarity": surprise.nearest_similarity,
            },
            pipeline_id=pipeline_id,
        )

    @classmethod
    def pipeline_complete(cls, result: "PipelineResult") -> "WebSocketEvent":
        return cls(
            event_type="pipeline_complete",
            payload={
                "pipeline_id": result.pipeline_id,
                "is_threat": result.is_threat,
                "highest_confidence": result.highest_confidence,
                "stages_completed": [s.value for s in result.stages_completed],
                "duration_ms": result.total_duration_ms,
                "antibody_id": result.antibody.antibody_id if result.antibody else None,
                "mesh_broadcast": result.mesh_broadcast is not None,
            },
            pipeline_id=result.pipeline_id,
        )

    @classmethod
    def pipeline_error(cls, pipeline_id: str, error: str) -> "WebSocketEvent":
        return cls(
            event_type="pipeline_error",
            payload={
                "error": error,
                # Never include raw threat content in error events
            },
            pipeline_id=pipeline_id,
        )


# ============================================================================
# API REQUEST/RESPONSE MODELS
# ============================================================================

class AnalyzeThreatRequest(BaseModel):
    """API request to analyze a threat."""
    content: str = Field(..., min_length=1, max_length=1_000_000)
    vector: ThreatVector = Field(default=ThreatVector.EMAIL)
    language_hint: Optional[str] = Field(default=None)
    metadata: dict[str, Any] = Field(default_factory=dict)
    image_base64: Optional[str] = Field(default=None)
    audio_base64: Optional[str] = Field(default=None)


class AnalyzeThreatResponse(BaseModel):
    """API response for threat analysis."""
    pipeline_id: str
    status: str = Field(default="processing", description="processing | complete | error")
    message: str = Field(default="Threat received. Processing via WebSocket events.")


class HealthResponse(BaseModel):
    """API health check response."""
    status: str = Field(default="healthy")
    version: str = Field(default="1.0.0")
    node_id: str = Field(default="")
    provider: str = Field(default="")
    immunity_score: float = Field(default=0.0)
    antibody_count: int = Field(default=0)
    mesh_nodes: int = Field(default=0)
    uptime_seconds: float = Field(default=0.0)


class AntibodyListResponse(BaseModel):
    """API response for listing antibodies."""
    antibodies: list[Antibody] = Field(default_factory=list)
    total: int = Field(default=0)
    page: int = Field(default=1)
    page_size: int = Field(default=50)


class MeshStatusResponse(BaseModel):
    """API response for mesh network status."""
    node_id: str = Field(default="")
    connected_peers: list[MeshNodeStatus] = Field(default_factory=list)
    total_peers: int = Field(default=0)
    r0_immunity: float = Field(default=0.0)
    herd_immunity_threshold: float = Field(default=0.0)
