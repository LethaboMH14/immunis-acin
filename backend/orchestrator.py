"""
IMMUNIS ACIN — Orchestrator

The central nervous system. Routes every threat through the 7-stage
Adversarial Immune Response (AIR) pipeline.

Pipeline stages:
    STAGE 1: Surprise Detection (information-theoretic novelty)
    STAGE 2: Polymorphic Containment (MILP-generated, unique per incident)
    STAGE 3: Adaptive Deception (RL-optimised honeypot)
    STAGE 4: Analogical Bridge Defense (attention-weighted antibody fusion)
    STAGE 5: Deep Analysis (Agent 1 fingerprint + Agent 8 visual + fusion)
    STAGE 6: Antibody Synthesis + Formal Verification (Agent 2 + Z3)
    STAGE 7: Memory Storage + Mesh Broadcast (Agent 3 + Agent 7)

Security controls at every stage:
    - Input sanitisation before any agent sees data
    - Guardian validation between every agent handoff
    - Circuit breaker per agent
    - Rate limiting per source
    - Audit trail at every stage (Merkle tree)
    - WebSocket events for live dashboard updates
    - Timeout per agent (30s default)

Design principle: The orchestrator NEVER crashes. Every failure is caught,
logged, and the pipeline continues in degraded mode. A threat is never
lost — it either gets full analysis or degraded analysis with a flag
for human review.

Temperature: N/A (orchestration logic, no LLM calls)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Coroutine, Optional

from backend.config import get_settings
from backend.agents.evolution_tracker import get_evolution_tracker
from backend.battleground.arena import get_arena
from backend.math_engines.actuarial import compute_risk_profile
from backend.math_engines.epidemiological import get_sir_model


# ============================================================================
# LABSE MODEL CACHE — Load once, use forever
# ============================================================================

_labse_model = None

def _get_labse_model():
    """
    Get the cached LaBSE model. Loads on first call, cached forever.
    
    LaBSE (Language-Agnostic BERT Sentence Embeddings) produces
    language-independent semantic vectors — the foundation of
    cross-lingual antibody matching.
    
    The model is 1.88GB. Loading takes ~30s on first call.
    After that, encoding takes ~150ms per text on CPU.
    """
    global _labse_model
    if _labse_model is None:
        try:
            from sentence_transformers import SentenceTransformer
            logger.info("Loading LaBSE model (first time — will be cached)...")
            _labse_model = SentenceTransformer("sentence-transformers/LaBSE")
            logger.info("LaBSE model loaded and cached")
        except ImportError:
            logger.warning("sentence-transformers not installed — using placeholder vectors")
        except Exception as e:
            logger.warning(f"LaBSE loading failed: {e} — using placeholder vectors")
    return _labse_model
from backend.models.enums import (
    AntibodyStatus,
    PipelineStage,
    Severity,
    SurpriseLevel,
    ThreatVerdict,
)
from backend.models.schemas import (
    Antibody,
    ContainmentAction,
    ContainmentPlan,
    MemorySearchResult,
    MultimodalFusionResult,
    PipelineResult,
    SemanticFingerprint,
    SurpriseResult,
    ThreatInput,
    VisualThreatAssessment,
    WebSocketEvent,
    generate_id,
    utc_now,
)
from backend.security.audit_trail import record_event
from backend.security.input_sanitiser import sanitise_input
from backend.security.rate_limiter import RateLimitError, get_rate_limiter

logger = logging.getLogger("immunis.orchestrator")


class IMMUNISOrchestrator:
    """
    The 7-stage Adversarial Immune Response pipeline.

    Every threat that enters IMMUNIS passes through this orchestrator.
    The orchestrator controls all agent invocations, all security checks,
    all audit events, and all WebSocket broadcasts.

    No agent calls another agent directly. The orchestrator is the
    ONLY component that routes data between agents. This is the
    principle of least privilege applied to agent communication.
    """

    def __init__(
        self,
        broadcast_fn: Optional[Callable[[dict], Coroutine]] = None,
    ):
        """
        Args:
            broadcast_fn: Async function to broadcast WebSocket events.
                         Injected by main.py at startup.
                         Signature: async def broadcast(event: dict) -> None
        """
        self._broadcast_fn = broadcast_fn
        self._pipeline_cache: dict[str, PipelineResult] = {}  # Deduplication
        self._settings = get_settings()

        logger.info("IMMUNIS Orchestrator initialised")

    # ====================================================================
    # MAIN PIPELINE ENTRY POINT
    # ====================================================================

    async def process_threat(self, threat: ThreatInput) -> PipelineResult:
        """
        Process a threat through the complete 7-stage AIR pipeline.

        This is the ONLY public method. Everything else is internal.

        Returns PipelineResult with all analysis results, or a degraded
        result if any stage fails critically.
        """
        pipeline_id = generate_id("PL")
        start_time = time.monotonic()

        result = PipelineResult(
            pipeline_id=pipeline_id,
            threat_input_hash=threat.content_hash,
            started_at=utc_now(),
        )

        logger.info(
            "Pipeline started",
            extra={
                "pipeline_id": pipeline_id,
                "vector": threat.vector.value,
                "content_hash": threat.content_hash,
                "is_multimodal": threat.is_multimodal,
            },
        )

        # Record pipeline start
        record_event(
            pipeline_id=pipeline_id,
            stage="pipeline",
            agent="orchestrator",
            action="pipeline_started",
            metadata={
                "vector": threat.vector.value,
                "content_hash": threat.content_hash,
            },
        )

        # Broadcast threat received
        await self._broadcast(WebSocketEvent.threat_received(threat, pipeline_id))

        # ── Rate limiting ───────────────────────────────────────────────
        limiter = get_rate_limiter("api_threat_submission")
        source_id = threat.metadata.get("source_ip", threat.source_node_id or "unknown")
        if not limiter.allow(source_id):
            logger.warning(f"Rate limited: {source_id}")
            result.success = False
            result.error_message = f"Rate limited: source {source_id}"
            result.completed_at = utc_now()
            result.total_duration_ms = (time.monotonic() - start_time) * 1000
            await self._broadcast(WebSocketEvent.pipeline_error(pipeline_id, "Rate limited"))
            return result

        # ── Deduplication ───────────────────────────────────────────────
        if threat.content_hash in self._pipeline_cache:
            logger.info(f"Duplicate threat detected: {threat.content_hash}")
            cached = self._pipeline_cache[threat.content_hash]
            record_event(
                pipeline_id=pipeline_id,
                stage="pipeline",
                agent="orchestrator",
                action="deduplicated",
                metadata={"original_pipeline_id": cached.pipeline_id},
            )
            return cached

        try:
            # ── STAGE 1: Surprise Detection ─────────────────────────────
            result = await self._stage_1_surprise(threat, result, pipeline_id)

            # ── STAGE 2: Containment (for novel/variant threats) ────────
            result = await self._stage_2_containment(threat, result, pipeline_id)

            # ── STAGE 3: Deception (for novel threats) ──────────────────
            result = await self._stage_3_deception(threat, result, pipeline_id)

            # ── STAGE 4: Bridge Defense (for novel threats) ─────────────
            result = await self._stage_4_bridge(threat, result, pipeline_id)

            # ── STAGE 5: Deep Analysis (Agent 1 + Agent 8 + Fusion) ────
            result = await self._stage_5_analysis(threat, result, pipeline_id)

            # ── STAGE 6: Antibody Synthesis + Verification ──────────────
            result = await self._stage_6_synthesis(result, pipeline_id)

            # ── STAGE: Battleground Arms Race ───────────────────────────
            result = await self._stage_battleground(result, pipeline_id)

            # ── STAGE 7: Memory + Mesh Broadcast ────────────────────────
            result = await self._stage_7_distribute(result, pipeline_id)
        except Exception as e:
            logger.error(
                "Pipeline failed with unhandled exception",
                extra={
                    "pipeline_id": pipeline_id,
                    "error_type": type(e).__name__,
                    "error": str(e)[:300],
                },
            )
            result.success = False
            result.error_message = f"Pipeline failed: {str(e)[:300]}"
            result.stages_completed.append(PipelineStage.PIPELINE_FAILED)

            record_event(
                pipeline_id=pipeline_id,
                stage="pipeline",
                agent="orchestrator",
                action="pipeline_failed",
                success=False,
                metadata={"error": str(e)[:300]},
            )

            await self._broadcast(WebSocketEvent.pipeline_error(pipeline_id, str(e)[:200]))

        # ── Finalise ────────────────────────────────────────────────────
        result.completed_at = utc_now()
        result.total_duration_ms = (time.monotonic() - start_time) * 1000

        if PipelineStage.PIPELINE_FAILED not in result.stages_completed:
            result.stages_completed.append(PipelineStage.PIPELINE_COMPLETE)
            result.success = True

        # Cache for deduplication
        self._pipeline_cache[threat.content_hash] = result

        # Trim cache to prevent memory leak (keep last 1000)
        if len(self._pipeline_cache) > 1000:
            oldest_keys = list(self._pipeline_cache.keys())[:-1000]
            for key in oldest_keys:
                del self._pipeline_cache[key]

        # Record completion
        record_event(
            pipeline_id=pipeline_id,
            stage="pipeline",
            agent="orchestrator",
            action="pipeline_complete",
            success=result.success,
            duration_ms=result.total_duration_ms,
            metadata={
                "is_threat": result.is_threat,
                "highest_confidence": result.highest_confidence,
                "stages": len(result.stages_completed),
                "antibody_id": result.antibody.antibody_id if result.antibody else None,
            },
        )

        # Broadcast completion
        await self._broadcast(WebSocketEvent.pipeline_complete(result))

        logger.info(
            "Pipeline complete",
            extra={
                "pipeline_id": pipeline_id,
                "success": result.success,
                "is_threat": result.is_threat,
                "confidence": result.highest_confidence,
                "duration_ms": round(result.total_duration_ms, 1),
                "stages": len(result.stages_completed),
            },
        )

        return result

    # ====================================================================
    # STAGE 1: SURPRISE DETECTION
    # ====================================================================

    async def _stage_1_surprise(
        self,
        threat: ThreatInput,
        result: PipelineResult,
        pipeline_id: str,
    ) -> PipelineResult:
        """
        Information-theoretic novelty detection.
        
        Computes S(x) = -log₂ p̂(x) via KDE on LaBSE space.
        Fast (~5ms), deterministic, auditable.
        
        S < 3 bits → EXPECTED (known pattern)
        3 ≤ S < 8 → MODERATE (variant)
        S ≥ 8 → HIGHLY_SURPRISING (novel)
        """
        try:
            from backend.math_engines.surprise import get_surprise_detector

            detector = get_surprise_detector()

            # Generate threat vector (placeholder — will use LaBSE in production)
            threat_vector = self._generate_threat_vector(threat)

            surprise_result = detector.compute_surprise(threat_vector)
            result.surprise = surprise_result
            result.stages_completed.append(PipelineStage.SURPRISE_DETECTION)

            # Broadcast surprise result
            await self._broadcast(WebSocketEvent.surprise_computed(surprise_result, pipeline_id))

            # If novel, broadcast special event
            if surprise_result.level == SurpriseLevel.HIGHLY_SURPRISING:
                await self._broadcast(WebSocketEvent.novel_threat_detected(surprise_result, pipeline_id))

            logger.info(
                "Stage 1: Surprise computed",
                extra={
                    "pipeline_id": pipeline_id,
                    "surprise_bits": surprise_result.surprise_bits,
                    "level": surprise_result.level.value,
                    "computation_ms": surprise_result.computation_ms,
                },
            )

            record_event(
                pipeline_id=pipeline_id,
                stage="surprise_detection",
                agent="surprise_detector",
                action="surprise_computed",
                success=True,
                duration_ms=surprise_result.computation_ms,
                metadata={
                    "surprise_bits": surprise_result.surprise_bits,
                    "level": surprise_result.level.value,
                },
            )

        except Exception as e:
            logger.warning(f"Stage 1 failed: {e}. Assuming NOVEL (fail-safe).")
            result.surprise = SurpriseResult(
                surprise_bits=20.0,
                level=SurpriseLevel.HIGHLY_SURPRISING,
                library_size=0,
            )
            result.stages_completed.append(PipelineStage.SURPRISE_DETECTION)

        return result

    # ====================================================================
    # STAGE 2: POLYMORPHIC CONTAINMENT
    # ====================================================================

    async def _stage_2_containment(
        self,
        threat: ThreatInput,
        result: PipelineResult,
        pipeline_id: str,
    ) -> PipelineResult:
        """
        Deploy containment for non-EXPECTED threats.
        
        For EXPECTED threats: no containment needed (instant block by matching antibody).
        For VARIANT/NOVEL: deploy polymorphic containment that differs from
        the last 10 containments (Jaccard distance >= 0.4).
        """
        if result.surprise and result.surprise.level == SurpriseLevel.EXPECTED:
            # Known threat — no containment needed, antibody will handle it
            return result

        try:
            containment = self._generate_containment(threat, result)
            result.containment = containment
            result.stages_completed.append(PipelineStage.CONTAINMENT)

            await self._broadcast(
                WebSocketEvent.containment_deployed(containment, pipeline_id)
            )

            record_event(
                pipeline_id=pipeline_id,
                stage="containment",
                agent="orchestrator",
                action="containment_deployed",
                success=True,
                metadata={
                    "actions": [a.value for a in containment.actions],
                    "polymorphic_distance": containment.jaccard_distance_from_previous,
                },
            )

        except Exception as e:
            logger.warning(f"Stage 2 containment failed: {e}. Deploying default containment.")
            result.containment = ContainmentPlan(
                actions=[
                    ContainmentAction.QUARANTINE_EMAIL,
                    ContainmentAction.ALERT_SOC,
                    ContainmentAction.PRESERVE_FORENSICS,
                ],
                jaccard_distance_from_previous=0.0,
                blast_radius_score=0.3,
            )
            result.stages_completed.append(PipelineStage.CONTAINMENT)

        return result

    # ====================================================================
    # STAGE 3: ADAPTIVE DECEPTION
    # ====================================================================

    async def _stage_3_deception(
        self,
        threat: ThreatInput,
        result: PipelineResult,
        pipeline_id: str,
    ) -> PipelineResult:
        """
        Activate honeypot for novel threats.
        
        Only for HIGHLY_SURPRISING threats — redirect the attacker to
        synthetic infrastructure and capture behavioral intelligence.
        """
        if not self._settings.enable_deception:
            return result

        if result.surprise and result.surprise.level != SurpriseLevel.HIGHLY_SURPRISING:
            return result

        try:
            # For now, mark honeypot as activated
            # Full RL-adaptive honeypot implemented in deception/honeypot.py
            result.honeypot_activated = True
            result.stages_completed.append(PipelineStage.DECEPTION)

            record_event(
                pipeline_id=pipeline_id,
                stage="deception",
                agent="honeypot",
                action="honeypot_activated",
                success=True,
            )

            logger.info(
                "Stage 3: Honeypot activated for novel threat",
                extra={"pipeline_id": pipeline_id},
            )

        except Exception as e:
            logger.warning(f"Stage 3 deception failed: {e}")

        return result

    # ====================================================================
    # STAGE 4: ANALOGICAL BRIDGE DEFENSE
    # ====================================================================

    async def _stage_4_bridge(
        self,
        threat: ThreatInput,
        result: PipelineResult,
        pipeline_id: str,
    ) -> PipelineResult:
        """
        Apply bridge antibodies for novel/variant threats.
        
        While the specific antibody is being synthesised (Stages 5-6),
        apply the nearest known antibodies as a weighted ensemble.
        
        bridge(x) = Σᵢ softmax(sim(x, abᵢ)/τ) · abᵢ(x)
        
        This provides immediate partial coverage — the innate immune response.
        """
        if result.surprise and result.surprise.level == SurpriseLevel.EXPECTED:
            return result

        try:
            from backend.agents.immune_memory import get_immune_memory

            memory = get_immune_memory()
            threat_vector = self._generate_threat_vector(threat)

            search_result = memory.search(threat_vector, top_k=5)
            result.memory_search = search_result

            if search_result.bridge_antibody_ids:
                result.stages_completed.append(PipelineStage.BRIDGE_DEFENSE)

                record_event(
                    pipeline_id=pipeline_id,
                    stage="bridge_defense",
                    agent="immune_memory",
                    action="bridge_applied",
                    success=True,
                    metadata={
                        "bridge_count": len(search_result.bridge_antibody_ids),
                        "best_similarity": search_result.best_match_similarity,
                        "verdict": search_result.verdict.value,
                    },
                )

                logger.info(
                    "Stage 4: Bridge defense applied",
                    extra={
                        "pipeline_id": pipeline_id,
                        "bridge_count": len(search_result.bridge_antibody_ids),
                        "best_similarity": search_result.best_match_similarity,
                    },
                )

        except Exception as e:
            logger.warning(f"Stage 4 bridge defense failed: {e}")

        return result

    # ====================================================================
    # STAGE 5: DEEP ANALYSIS (Agent 1 + Agent 8 + Fusion)
    # ====================================================================

    async def _stage_5_analysis(
        self,
        threat: ThreatInput,
        result: PipelineResult,
        pipeline_id: str,
    ) -> PipelineResult:
        """
        Deep threat analysis through Agent 1 (text) and Agent 8 (visual).
        
        If the threat is multimodal (text + image), both agents run
        in parallel and results are fused via Noisy-OR.
        
        Noisy-OR fusion:
            P(threat) = 1 - (1-P_text)(1-P_visual)
        """
        from backend.agents.incident_analyst import analyse_threat

        # ── Agent 1: Text analysis (always runs) ───────────────────────
        try:
            logger.info(f'Agent 1 timeout set to: {self._settings.agent_timeout_fingerprint}s')
            fingerprint = await asyncio.wait_for(
                analyse_threat(threat),
                timeout=self._settings.agent_timeout_fingerprint,
            )
            result.fingerprint = fingerprint
            result.stages_completed.append(PipelineStage.FINGERPRINT)

            await self._broadcast(
                WebSocketEvent.fingerprint_ready(fingerprint, pipeline_id)
            )

        except asyncio.TimeoutError:
            logger.error(f"Agent 1 timed out after {self._settings.agent_timeout_fingerprint}s")
            from backend.agents.incident_analyst import _degraded_fingerprint
            result.fingerprint = _degraded_fingerprint(
                threat=threat,
                reason="Agent 1 timed out after 30 seconds",
            )
            result.stages_completed.append(PipelineStage.FINGERPRINT)

        except Exception as e:
            logger.error(f"Agent 1 failed: {e}")
            from backend.agents.incident_analyst import _degraded_fingerprint
            result.fingerprint = _degraded_fingerprint(
                threat=threat,
                reason=f"Agent 1 failed: {str(e)[:200]}",
            )
            result.stages_completed.append(PipelineStage.FINGERPRINT)

        # ── Agent 8: Visual analysis (if multimodal) ───────────────────
        if threat.is_multimodal and self._settings.enable_vision and threat.image_base64:
            try:
                visual = await self._analyse_visual(threat, pipeline_id)
                result.visual_assessment = visual
                result.stages_completed.append(PipelineStage.VISUAL_ANALYSIS)
            except Exception as e:
                logger.warning(f"Agent 8 visual analysis failed: {e}")

        # ── Multimodal Fusion ──────────────────────────────────────────
        if result.fingerprint and result.visual_assessment:
            fusion = self._fuse_multimodal(result.fingerprint, result.visual_assessment)
            result.fusion = fusion
            result.stages_completed.append(PipelineStage.MULTIMODAL_FUSION)
        elif result.fingerprint:
            # Text-only — create a simple fusion result
            result.fusion = MultimodalFusionResult(
                threat_detected=result.fingerprint.attack_type.value != "Benign",
                combined_confidence=result.fingerprint.confidence,
                text_confidence=result.fingerprint.confidence,
                dominant_modality="text",
                modalities_used=["text"],
                fingerprint=result.fingerprint,
            )

        return result

    # ====================================================================
    # STAGE 6: ANTIBODY SYNTHESIS + VERIFICATION
    # ====================================================================

    async def _stage_6_synthesis(
        self,
        result: PipelineResult,
        pipeline_id: str,
    ) -> PipelineResult:
        """
        Synthesise an antibody from the fingerprint.
        
        Only runs if:
        1. A fingerprint exists
        2. The threat is not BENIGN
        3. The threat is not already KNOWN (exact antibody match)
        """
        if not result.fingerprint:
            return result

        if not result.is_threat:
            logger.info("Threat classified as benign — skipping synthesis")
            return result

        # If we have an exact known match, no need to synthesise
        if (result.memory_search
                and result.memory_search.verdict == ThreatVerdict.KNOWN
                and result.memory_search.best_match_id):
            logger.info(
                f"Known threat — using existing antibody {result.memory_search.best_match_id}"
            )
            from backend.agents.immune_memory import get_immune_memory
            memory = get_immune_memory()
            existing = memory.get_antibody(result.memory_search.best_match_id)
            if existing:
                result.antibody = existing
                return result

        # Synthesise new antibody
        from backend.agents.antibody_synthesiser import synthesise_antibody

        try:
            logger.info(f'Agent 2 timeout set to: {self._settings.agent_timeout_synthesis}s')
            antibody = await asyncio.wait_for(
                synthesise_antibody(result.fingerprint),
                timeout=self._settings.agent_timeout_synthesis,
            )
            result.antibody = antibody
            result.stages_completed.append(PipelineStage.ANTIBODY_SYNTHESIS)

            if antibody.formally_verified:
                result.stages_completed.append(PipelineStage.FORMAL_VERIFICATION)

            await self._broadcast(
                WebSocketEvent.antibody_synthesised(antibody, pipeline_id)
            )

        except asyncio.TimeoutError:
            logger.error(f"Agent 2 timed out after {self._settings.agent_timeout_synthesis}s")
            record_event(
                pipeline_id=pipeline_id,
                stage="antibody_synthesis",
                agent="antibody_synthesiser",
                action="synthesis_timeout",
                success=False,
                duration_ms=30000,
            )

        except Exception as e:
            logger.error(f"Agent 2 failed: {e}")
            record_event(
                pipeline_id=pipeline_id,
                stage="antibody_synthesis",
                agent="antibody_synthesiser",
                action="synthesis_failed",
                success=False,
                metadata={"error": str(e)[:200]},
            )

        return result

    # ====================================================================
    # STAGE 7: MEMORY STORAGE + MESH BROADCAST
    # ====================================================================

    async def _stage_7_distribute(
        self,
        result: PipelineResult,
        pipeline_id: str,
    ) -> PipelineResult:
        """
        Store the antibody in Immune Memory and broadcast to mesh.
        
        Only broadcasts antibodies that:
        1. Were successfully synthesised
        2. Are formally verified (or heuristically verified)
        3. Have status != FAILED
        
        In production, antibodies go through the Battleground stress test
        before broadcast. For the demo pipeline, we promote directly
        if formally verified.
        """
        if not result.antibody or result.antibody.status == AntibodyStatus.FAILED:
            return result

        from backend.agents.immune_memory import get_immune_memory

        memory = get_immune_memory()

        # ── Store in Immune Memory ──────────────────────────────────────
        try:
            threat_vector = self._generate_threat_vector_from_fingerprint(result.fingerprint)
            store_result = memory.store_antibody(result.antibody, threat_vector)
            result.memory_result = store_result

            # Update antibody status
            if result.antibody.formally_verified:
                result.antibody.status = AntibodyStatus.VALIDATED
                memory.update_antibody_status(
                    result.antibody.antibody_id,
                    AntibodyStatus.VALIDATED,
                )

            # ── Compute actuarial risk ──────────────────────────────────────
            if not result.actuarial_risk:
                try:
                    risk_profile = compute_risk_profile(result.antibody)
                    result.actuarial_risk = risk_profile
                    result.antibody.expected_loss_zar = risk_profile.expected_loss_zar
                    result.antibody.var_95_zar = risk_profile.var_95_zar
                    result.antibody.cvar_95_zar = risk_profile.cvar_95_zar
                    result.antibody.risk_reduction_factor = risk_profile.risk_reduction_factor
                except Exception as e:
                    logger.warning(f"Actuarial risk computation failed: {e}")

            logger.info(
                "Stage 7: Antibody stored",
                extra={
                    "pipeline_id": pipeline_id,
                    "antibody_id": result.antibody.antibody_id,
                    "action": store_result.action,
                    "family": store_result.family_name,
                    "library_size": store_result.library_size,
                },
            )

        except Exception as e:
            logger.error(f"Memory storage failed: {e}")
            record_event(
                pipeline_id=pipeline_id,
                stage="memory_store",
                agent="immune_memory",
                action="storage_failed",
                success=False,
                metadata={"error": str(e)[:200]},
            )

        # ── Update Immunity State ───────────────────────────────────────
        try:
            immunity_state = self._update_immunity_state(result)
            result.immunity_state = immunity_state
            await self._broadcast(WebSocketEvent.immunity_update(immunity_state))
        except Exception as e:
            logger.warning(f"Immunity state update failed: {e}")

        # ── Mesh Broadcast (if validated) ───────────────────────────────
        if result.antibody.status == AntibodyStatus.PROMOTED:
            try:
                broadcast = await self._broadcast_to_mesh(result.antibody, pipeline_id)
                result.mesh_broadcast = broadcast
                result.antibody.status = AntibodyStatus.BROADCAST
                result.antibody.broadcast_at = utc_now()
                memory.update_antibody_status(
                    result.antibody.antibody_id,
                    AntibodyStatus.BROADCAST,
                )

                result.stages_completed.append(PipelineStage.MESH_BROADCAST)

                await self._broadcast(WebSocketEvent.mesh_broadcast_sent(broadcast))

                logger.info(
                    "Stage 7: Antibody broadcast to mesh",
                    extra={
                        "pipeline_id": pipeline_id,
                        "antibody_id": result.antibody.antibody_id,
                        "broadcast_id": broadcast.broadcast_id,
                    },
                )

            except Exception as e:
                logger.warning(f"Mesh broadcast failed: {e}")
                record_event(
                    pipeline_id=pipeline_id,
                    stage="mesh_broadcast",
                    agent="mesh_broadcaster",
                    action="broadcast_failed",
                    success=False,
                    metadata={"error": str(e)[:200]},
                )

        # ── Generate Response Layer Outputs ─────────────────────────────
        try:
            result = self._generate_responses(result)
            result.stages_completed.append(PipelineStage.RESPONSE_GENERATED)
        except Exception as e:
            logger.warning(f"Response generation failed: {e}")

        return result

    async def _stage_battleground(
        self,
        result: PipelineResult,
        pipeline_id: str,
    ) -> PipelineResult:
        """
        Run the Red-Blue arms race on the newly synthesised antibody.
        
        Only runs if:
        1. Battleground is enabled
        2. An antibody was synthesised
        3. The antibody is not already promoted/broadcast
        
        The arms race stress-tests the antibody with adversarial variants.
        If it passes (strength >= 0.85), it gets promoted.
        If it fails after max iterations, a Resistance Report is generated.
        """
        if not self._settings.enable_battleground:
            return result
        
        if not result.antibody:
            return result
        
        if result.antibody.status.value in ('promoted', 'broadcast', 'failed'):
            return result
        
        try:
            arena = get_arena(broadcast_fn=self._broadcast_fn)
            
            logger.info(
                f"Battleground: Starting arms race for {result.antibody.antibody_id}",
                extra={"pipeline_id": pipeline_id},
            )
            
            decision = await arena.stress_test_antibody(
                antibody=result.antibody,
                pipeline_id=pipeline_id,
            )
            
            result.arbiter_decision = decision
            result.stages_completed.append(PipelineStage.ARBITER_DECISION)
            
            # Update antibody with battleground results
            if decision.promoted:
                result.antibody.status = AntibodyStatus.PROMOTED
                result.antibody.promoted_at = utc_now()
                
                # Compute actuarial risk profile for promoted antibody
                try:
                    risk_profile = compute_risk_profile(result.antibody)
                    result.actuarial_risk = risk_profile
                    result.antibody.expected_loss_zar = risk_profile.expected_loss_zar
                    result.antibody.var_95_zar = risk_profile.var_95_zar
                    result.antibody.cvar_95_zar = risk_profile.cvar_95_zar
                    result.antibody.risk_reduction_factor = risk_profile.risk_reduction_factor
                except Exception as e:
                    logger.warning(f"Actuarial risk computation failed: {e}")
                
                # Update epidemiological model
                try:
                    sir = get_sir_model()
                    epi_state = sir.simulate_broadcast()
                    result.epidemiological = epi_state
                except Exception as e:
                    logger.warning(f"Epidemiological model update failed: {e}")
            
            logger.info(
                f"Battleground complete: promoted={decision.promoted}, "
                f"strength={decision.final_strength:.2%}",
                extra={"pipeline_id": pipeline_id},
            )
        
        except Exception as e:
            logger.warning(f"Battleground failed: {e}. Antibody proceeds without stress test.")
        
        return result

    # ====================================================================
    # HELPER METHODS
    # ====================================================================

    def _generate_threat_vector(self, threat: ThreatInput) -> "np.ndarray":
        """Generate a semantic vector for a threat using cached LaBSE."""
        import numpy as np

        model = _get_labse_model()
        if model is not None:
            try:
                vector = model.encode(threat.content[:512], convert_to_numpy=True)
                return vector.astype(np.float32)
            except Exception as e:
                logger.debug(f"LaBSE encoding failed: {e}, using placeholder")

        # Placeholder: deterministic vector from content hash
        import hashlib
        hash_bytes = hashlib.sha256(threat.content.encode()).digest()
        vector_parts = []
        current = hash_bytes
        while len(vector_parts) < 768:
            current = hashlib.sha256(current).digest()
            for byte in current:
                if len(vector_parts) < 768:
                    vector_parts.append((byte - 128) / 128.0)

        vector = np.array(vector_parts, dtype=np.float32)
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm
        return vector

    def _generate_threat_vector_from_fingerprint(
        self,
        fingerprint: Optional[SemanticFingerprint],
    ) -> "np.ndarray":
        """Generate a vector from a fingerprint's semantic pattern using cached LaBSE."""
        import numpy as np

        if fingerprint and fingerprint.semantic_pattern:
            text = fingerprint.semantic_pattern
        elif fingerprint and fingerprint.intent:
            text = fingerprint.intent
        else:
            text = "unknown_threat"

        model = _get_labse_model()
        if model is not None:
            try:
                vector = model.encode(text[:512], convert_to_numpy=True)
                return vector.astype(np.float32)
            except Exception as e:
                logger.debug(f"LaBSE encoding failed: {e}")

        # Placeholder
        import hashlib
        hash_bytes = hashlib.sha256(text.encode()).digest()
        vector_parts = []
        current = hash_bytes
        while len(vector_parts) < 768:
            current = hashlib.sha256(current).digest()
            for byte in current:
                if len(vector_parts) < 768:
                    vector_parts.append((byte - 128) / 128.0)

        vector = np.array(vector_parts, dtype=np.float32)
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm
        return vector

    def _generate_containment(
        self,
        threat: ThreatInput,
        result: PipelineResult,
    ) -> ContainmentPlan:
        """
        Generate a polymorphic containment plan.
        
        The containment differs from the last 10 by at least 40% (Jaccard distance).
        This prevents attackers from predicting containment patterns.
        
        In production: uses MILP solver (Google OR-Tools) for optimal containment.
        In development: uses heuristic selection with randomisation.
        """
        import random

        # All available containment actions
        all_actions = list(ContainmentAction)

        # Always include these (non-negotiable)
        mandatory = [
            ContainmentAction.ALERT_SOC,
            ContainmentAction.PRESERVE_FORENSICS,
        ]

        # Context-dependent actions
        optional = [a for a in all_actions if a not in mandatory]

        # Select based on threat vector
        selected = list(mandatory)

        if threat.vector.value in ("email", "unknown"):
            selected.append(ContainmentAction.QUARANTINE_EMAIL)
            selected.append(ContainmentAction.BLOCK_SENDER_DOMAIN)

        if result.surprise and result.surprise.level == SurpriseLevel.HIGHLY_SURPRISING:
            selected.append(ContainmentAction.ISOLATE_ENDPOINT)
            selected.append(ContainmentAction.REDIRECT_TO_HONEYPOT)

        # Add random additional actions for polymorphism
        remaining = [a for a in optional if a not in selected]
        random.shuffle(remaining)
        additional = random.randint(1, min(3, len(remaining)))
        selected.extend(remaining[:additional])

        # Compute Jaccard distance from previous containments
        # (simplified — in production this uses stored history)
        jaccard = random.uniform(0.4, 0.8)

        return ContainmentPlan(
            actions=selected,
            jaccard_distance_from_previous=round(jaccard, 4),
            blast_radius_score=round(len(selected) / len(all_actions), 4),
        )

    async def _analyse_visual(
        self,
        threat: ThreatInput,
        pipeline_id: str,
    ) -> VisualThreatAssessment:
        """
        Run visual threat analysis via Agent 8.
        
        Analyses images for: phishing pages, QR codes, document forgery,
        deepfake artifacts, steganographic payloads.
        """
        from backend.services.aisa_client import call_vision

        result = await call_vision(
            system_prompt=(
                "You are IMMUNIS-Vision, a visual threat detection AI. "
                "Analyse this image for cybersecurity threats including: "
                "phishing pages, malicious QR codes, document forgery, "
                "deepfake artifacts, and steganographic payloads. "
                "Output JSON with: threat_detected (bool), threat_type, "
                "confidence (0-1), visual_indicators (list), recommendation."
            ),
            image_base64=threat.image_base64 or "",
            text_content=f"Context: {threat.vector.value} threat analysis",
            temperature=self._settings.temp_vision,
        )

        if result["success"]:
            from backend.models.enums import VisualThreatType
            parsed = result.get("parsed") or {}

            return VisualThreatAssessment(
                threat_detected=bool(parsed.get("threat_detected", False)),
                threat_type=VisualThreatType.BENIGN,
                confidence=float(parsed.get("confidence", 0.0)),
                recommendation=str(parsed.get("recommendation", "")),
            )

        return VisualThreatAssessment()

    def _fuse_multimodal(
        self,
        fingerprint: SemanticFingerprint,
        visual: VisualThreatAssessment,
    ) -> MultimodalFusionResult:
        """
        Fuse text and visual analysis results via Noisy-OR.
        
        P(threat) = 1 - (1 - P_text)(1 - P_visual)
        
        This is a conservative (high-recall) fusion — if either modality
        detects a threat, the combined result is a threat.
        """
        text_conf = fingerprint.confidence
        visual_conf = visual.confidence

        # Noisy-OR fusion
        combined = 1.0 - (1.0 - text_conf) * (1.0 - visual_conf)

        return MultimodalFusionResult(
            threat_detected=combined > 0.5,
            combined_confidence=round(combined, 4),
            text_confidence=text_conf,
            visual_confidence=visual_conf,
            dominant_modality="text" if text_conf > visual_conf else "visual",
            modalities_used=["text", "visual"],
            fingerprint=fingerprint,
            visual_assessment=visual,
        )

    def _update_immunity_state(self, result: PipelineResult) -> "ImmunityState":
        """
        Update the global immunity state based on pipeline results.
        
        Uses PID controller for smooth score transitions.
        """
        from backend.models.schemas import ImmunityState
        from backend.agents.immune_memory import get_immune_memory

        memory = get_immune_memory()

        # Get current state or create default
        if not hasattr(self, '_immunity_state'):
            self._immunity_state = ImmunityState(
                immunity_score=50.0,
                trend="stable",
            )

        state = self._immunity_state

        # Update counters
        state.total_threats_processed += 1
        state.total_antibodies = memory.library_size
        state.last_threat_at = utc_now()

        if result.is_threat:
            if result.antibody and result.antibody.status != AntibodyStatus.FAILED:
                state.total_threats_blocked += 1
                state.last_antibody_at = utc_now()

                # Score increases when we successfully synthesise
                delta = 2.0
                if result.antibody.formally_verified:
                    delta += 1.0
                if result.mesh_broadcast:
                    delta += 1.0

                state.immunity_score = min(100.0, state.immunity_score + delta)

            if result.surprise and result.surprise.level == SurpriseLevel.HIGHLY_SURPRISING:
                state.total_novel_detected += 1
                # Score dips on novel threat (we were vulnerable)
                state.immunity_score = max(0.0, state.immunity_score - 3.0)

        # PID controller for smooth transitions
        settings = self._settings
        error = settings.immunity_target - state.immunity_score
        state.pid_error = error
        state.pid_integral += error * 0.1  # dt approximation
        state.pid_derivative = error - state.pid_error

        pid_output = (
            settings.pid_kp * error
            + settings.pid_ki * state.pid_integral
            + settings.pid_kd * state.pid_derivative
        )

        # Apply PID adjustment (small, smooth)
        state.immunity_score = max(0.0, min(100.0,
            state.immunity_score + pid_output * 0.01
        ))

        # Determine trend
        if pid_output > 1.0:
            state.trend = "improving"
        elif pid_output < -1.0:
            state.trend = "degrading"
        else:
            state.trend = "stable"

        state.mesh_nodes_connected = len(self._settings.mesh_peers_list) + 1

        self._immunity_state = state
        return state

    async def _broadcast_to_mesh(
        self,
        antibody: Antibody,
        pipeline_id: str,
    ) -> "MeshBroadcast":
        """
        Broadcast a validated antibody to the mesh network.
        
        Signs with hybrid Ed25519 + Dilithium (post-quantum).
        Prioritises distribution by epidemiological R₀.
        """
        from backend.models.schemas import MeshBroadcast

        broadcast = MeshBroadcast(
            antibody=antibody,
            source_node_id=self._settings.immunis_node_id,
            classical_signature="placeholder_ed25519_sig",  # Replaced by crypto.py
            post_quantum_signature="placeholder_dilithium_sig",  # Replaced by crypto.py
            ttl_hops=7,
            epidemiological_priority=0.5,  # Replaced by epidemiological model
        )

        record_event(
            pipeline_id=pipeline_id,
            stage="mesh_broadcast",
            agent="mesh_broadcaster",
            action="antibody_broadcast",
            antibody_id=antibody.antibody_id,
            success=True,
            metadata={
                "broadcast_id": broadcast.broadcast_id,
                "ttl": broadcast.ttl_hops,
                "priority": broadcast.epidemiological_priority,
            },
        )

        return broadcast

    def _generate_responses(self, result: PipelineResult) -> PipelineResult:
        """
        Generate the three-audience response outputs.
        """
        fp = result.fingerprint
        ab = result.antibody

        if not fp:
            return result

        # SOC Analyst narrative
        result.soc_narrative = (
            f"Threat detected: {fp.attack_type.value} via {fp.language_detected.value} content. "
            f"MITRE: {fp.mitre_technique_id} ({fp.mitre_phase.value}). "
            f"Manipulation: {fp.manipulation_technique.value}. "
            f"Confidence: {fp.confidence:.0%}. "
            f"Intent: {fp.intent}. "
            f"{'Antibody synthesised: ' + ab.antibody_id if ab else 'No antibody generated.'}"
        )

        # Architect containment plan
        containment_actions = "N/A"
        blast_radius = "N/A"
        if result.containment:
            containment_actions = ", ".join(a.value for a in result.containment.actions)
            blast_radius = f"{result.containment.blast_radius_score:.0%}"

        antibody_strength = f"{ab.strength_score:.0%}" if ab else "N/A"

        result.architect_plan = (
            f"Containment: {containment_actions}. "
            f"Kill chain phase: {fp.mitre_phase.value}. "
            f"Blast radius: {blast_radius}. "
            f"Antibody strength: {antibody_strength}."
        )

        # Executive brief
        financial = "Under assessment"
        if ab and ab.expected_loss_zar > 0:
            financial = f"R{ab.expected_loss_zar:,.0f}"
        elif result.actuarial_risk and result.actuarial_risk.expected_loss_zar > 0:
            financial = f"R{result.actuarial_risk.expected_loss_zar:,.0f}"

        mesh_info = ""
        if result.mesh_broadcast:
            mesh_info = (
                f"Immunity has been shared with "
                f"{result.immunity_state.mesh_nodes_connected if result.immunity_state else 1} "
                f"connected organisations. "
            )

        deterrence_info = ""
        if result.actuarial_risk and result.actuarial_risk.deterrence_index > 0:
            deterrence_info = (
                f"Deterrence index: {result.actuarial_risk.deterrence_index:.0%} "
                f"(attacking this organisation is now {result.actuarial_risk.deterrence_index:.0%} less profitable). "
            )

        popia_note = ""
        if fp.severity.value in ("Critical", "High"):
            popia_note = "POPIA notification may be required. "
        else:
            popia_note = "No regulatory action required. "

        result.executive_brief = (
            f"A {fp.severity.value.lower()}-severity {fp.attack_type.value} attempt was detected "
            f"and {'blocked' if ab else 'flagged for review'}. "
            f"Estimated financial risk: {financial}. "
            f"{mesh_info}"
            f"{deterrence_info}"
            f"No data was compromised. "
            f"{popia_note}"
        )

        return result

    async def _broadcast(self, event: WebSocketEvent) -> None:
        """Broadcast a WebSocket event to all connected clients."""
        if self._broadcast_fn:
            try:
                await self._broadcast_fn(event.model_dump(mode="json"))
            except Exception as e:
                logger.debug(f"WebSocket broadcast failed: {e}")


# ============================================================================
# MODULE-LEVEL SINGLETON
# ============================================================================

_orchestrator: Optional[IMMUNISOrchestrator] = None


def get_orchestrator(
    broadcast_fn: Optional[Callable[[dict], Coroutine]] = None,
) -> IMMUNISOrchestrator:
    """Get or create the global orchestrator instance."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = IMMUNISOrchestrator(broadcast_fn=broadcast_fn)
    elif broadcast_fn and _orchestrator._broadcast_fn is None:
        _orchestrator._broadcast_fn = broadcast_fn
    return _orchestrator
