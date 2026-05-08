"""
IMMUNIS ACIN — Battleground Arena

The arena where Red-Blue adversarial arms race runs.

For each antibody that enters the Battleground:
    1. Red Agent generates evasion variants (6 vectors)
    2. Blue Agent (Variant Recogniser) classifies each variant
    3. For each Red win (evasion): new antibody synthesised for that gap
    4. For each Blue win (detection): antibody strength increases
    5. Evolution Tracker records every outcome
    6. Arbiter decides: promote (strength ≥ 0.85) or iterate or escalate

The arms race continues until:
    - Antibody reaches promotion threshold (0.85) → promoted to production
    - Maximum iterations reached (20) → Resistance Report generated
    - All 6 vectors exhausted with no evasions → antibody is strong

This is the technical heart of IMMUNIS. The coevolutionary pressure
between Red and Blue is what makes the system antifragile.

Red winning is NOT a failure. Red winning is the mechanism by which
IMMUNIS discovers and patches its own weaknesses.

Temperature: N/A (orchestration logic, no direct LLM calls)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

from backend.config import get_settings
from backend.models.enums import AntibodyStatus, ThreatActorType, ThreatVerdict
from backend.models.schemas import (
    Antibody,
    ArbiterDecision,
    ClassificationResult,
    RedAgentResult,
    WebSocketEvent,
    generate_id,
    utc_now,
)

logger = logging.getLogger("immunis.battleground.arena")


class BattlegroundArena:
    """
    Orchestrates the Red-Blue adversarial arms race.
    
    Each antibody is stress-tested through multiple rounds.
    The arena tracks outcomes and determines when an antibody
    is strong enough for production deployment.
    """

    def __init__(
        self,
        broadcast_fn=None,
        max_iterations: int = 20,
        promotion_threshold: float = 0.85,
        variants_per_round: int = 3,
    ):
        settings = get_settings()
        self._broadcast_fn = broadcast_fn
        self._max_iterations = max_iterations or settings.battleground_max_iterations
        self._promotion_threshold = promotion_threshold or settings.battleground_promotion_threshold
        self._variants_per_round = variants_per_round

        # Battle history
        self._battle_history: list[dict[str, Any]] = []

        logger.info(
            "Battleground Arena initialised",
            extra={
                "max_iterations": self._max_iterations,
                "promotion_threshold": self._promotion_threshold,
                "variants_per_round": self._variants_per_round,
            },
        )

    async def stress_test_antibody(
        self,
        antibody: Antibody,
        actor_type: ThreatActorType = ThreatActorType.UNKNOWN,
        pipeline_id: str = "",
    ) -> ArbiterDecision:
        """
        Run a full stress test on an antibody.
        
        This is the main entry point. Called by the orchestrator
        after Agent 2 synthesises a new antibody.
        
        The test runs multiple rounds of Red vs Blue until:
        - Antibody strength reaches promotion threshold
        - Maximum iterations exhausted
        - Red Agent can't find any more evasions
        
        Returns an ArbiterDecision with the final verdict.
        """
        from backend.agents.red_agent import generate_variants
        from backend.agents.variant_recogniser import classify_batch
        from backend.agents.evolution_tracker import get_evolution_tracker
        from backend.agents.immune_memory import get_immune_memory

        tracker = get_evolution_tracker()
        memory = get_immune_memory()

        start_time = time.monotonic()
        total_variants = 0
        total_evasions = 0
        total_blocked = 0
        rounds_completed = 0

        logger.info(
            f"Battleground: Starting stress test for {antibody.antibody_id}",
            extra={
                "attack_family": antibody.attack_family,
                "initial_strength": antibody.strength_score,
            },
        )

        for round_num in range(1, self._max_iterations + 1):
            rounds_completed = round_num

            # ── Red Agent attacks ───────────────────────────────────
            try:
                red_result = await generate_variants(
                    antibody=antibody,
                    num_variants=self._variants_per_round,
                    actor_type=actor_type,
                )
            except Exception as e:
                logger.warning(f"Red Agent failed in round {round_num}: {e}")
                break

            if not red_result.variants:
                logger.info(f"Red Agent produced no variants in round {round_num} — exhausted")
                break

            total_variants += len(red_result.variants)

            # Broadcast Red attacks
            for variant in red_result.variants:
                await self._broadcast(
                    WebSocketEvent.red_attack(variant, pipeline_id)
                )

            # ── Blue Agent defends ──────────────────────────────────
            try:
                classifications = await classify_batch(
                    variants=red_result.variants,
                    target_antibody=antibody,
                )
            except Exception as e:
                logger.warning(f"Blue Agent failed in round {round_num}: {e}")
                break

            # ── Score the round ─────────────────────────────────────
            round_evasions = 0
            round_blocked = 0

            for variant, classification in zip(red_result.variants, classifications):
                blue_won = classification.verdict in (
                    ThreatVerdict.KNOWN, ThreatVerdict.VARIANT
                )

                if blue_won:
                    round_blocked += 1
                    total_blocked += 1
                else:
                    round_evasions += 1
                    total_evasions += 1

                    # Red won — synthesise new antibody for this evasion
                    if classification.blue_learning_signal:
                        logger.info(
                            f"Red evaded with {variant.evasion_vector}. "
                            f"Learning signal: {classification.blue_learning_signal[:100]}"
                        )

                # Broadcast Blue defense
                await self._broadcast(
                    WebSocketEvent.blue_defense(classification, pipeline_id)
                )

            # Record in evolution tracker
            tracker.record_arms_race_round(antibody, red_result, classifications)

            # ── Update antibody strength ────────────────────────────
            if total_variants > 0:
                antibody.strength_score = total_blocked / total_variants
                antibody.red_agent_tests = total_variants
                antibody.red_agent_evasions = total_evasions

            # Update in memory
            memory.update_antibody_strength(
                antibody.antibody_id,
                antibody.strength_score,
                tests=len(red_result.variants),
                evasions=round_evasions,
            )

            logger.info(
                f"Round {round_num}: Red {round_evasions} evasions, "
                f"Blue {round_blocked} blocks. "
                f"Strength: {antibody.strength_score:.2%}",
            )

            # ── Check promotion threshold ───────────────────────────
            if antibody.strength_score >= self._promotion_threshold:
                logger.info(
                    f"Antibody {antibody.antibody_id} reached promotion threshold "
                    f"({antibody.strength_score:.2%} >= {self._promotion_threshold:.2%})"
                )
                break

            # ── Check if Red is exhausted ───────────────────────────
            if round_evasions == 0 and round_num >= 2:
                logger.info(
                    f"Red Agent found no evasions in round {round_num} — "
                    f"antibody is robust"
                )
                break

        # ── Arbiter decision ────────────────────────────────────────
        duration_ms = (time.monotonic() - start_time) * 1000
        promoted = antibody.strength_score >= self._promotion_threshold

        # Generate resistance report if not promoted after max iterations
        resistance_report = None
        if not promoted and rounds_completed >= self._max_iterations:
            resistance_report = {
                "antibody_id": antibody.antibody_id,
                "iterations_attempted": rounds_completed,
                "best_strength": antibody.strength_score,
                "total_variants": total_variants,
                "total_evasions": total_evasions,
                "recommendation": "Escalate to human SOC analyst for guided synthesis",
            }
            logger.warning(
                f"Resistance Report: Antibody {antibody.antibody_id} "
                f"could not reach threshold after {rounds_completed} rounds"
            )

        decision = ArbiterDecision(
            decision_id=generate_id("ARB"),
            antibody_id=antibody.antibody_id,
            rounds_completed=rounds_completed,
            final_strength=round(antibody.strength_score, 4),
            promoted=promoted,
            promotion_reason=(
                f"Strength {antibody.strength_score:.2%} >= {self._promotion_threshold:.2%} "
                f"after {rounds_completed} rounds ({total_blocked}/{total_variants} blocked)"
                if promoted
                else f"Strength {antibody.strength_score:.2%} < {self._promotion_threshold:.2%} "
                     f"after {rounds_completed} rounds"
            ),
            resistance_report=resistance_report,
            escalated_to_human=resistance_report is not None,
            decided_at=utc_now(),
        )

        # Update antibody status
        if promoted:
            antibody.status = AntibodyStatus.PROMOTED
            antibody.promoted_at = utc_now()
            memory.update_antibody_status(antibody.antibody_id, AntibodyStatus.PROMOTED)

            tracker.record_event(
                event_type="antibody_promoted",
                agent_source="arbiter",
                antibody_id=antibody.antibody_id,
                attack_family=antibody.attack_family,
                description=f"Promoted with strength {antibody.strength_score:.2%}",
            )

        # Broadcast decision
        await self._broadcast(
            WebSocketEvent.arbiter_decision_made(decision, pipeline_id)
        )

        # Record battle
        self._battle_history.append({
            "antibody_id": antibody.antibody_id,
            "rounds": rounds_completed,
            "total_variants": total_variants,
            "total_evasions": total_evasions,
            "final_strength": antibody.strength_score,
            "promoted": promoted,
            "duration_ms": duration_ms,
        })

        logger.info(
            f"Battleground complete: {antibody.antibody_id}",
            extra={
                "promoted": promoted,
                "strength": round(antibody.strength_score, 4),
                "rounds": rounds_completed,
                "variants": total_variants,
                "evasions": total_evasions,
                "duration_ms": round(duration_ms, 1),
            },
        )

        return decision

    def get_battle_history(self) -> list[dict[str, Any]]:
        """Get battle history for dashboard display."""
        return list(self._battle_history)

    async def _broadcast(self, event: WebSocketEvent) -> None:
        """Broadcast a WebSocket event."""
        if self._broadcast_fn:
            try:
                await self._broadcast_fn(event.model_dump(mode="json"))
            except Exception:
                pass


# ============================================================================
# MODULE-LEVEL SINGLETON
# ============================================================================

_arena: Optional[BattlegroundArena] = None


def get_arena(broadcast_fn=None) -> BattlegroundArena:
    """Get or create the global Battleground Arena."""
    global _arena
    if _arena is None:
        _arena = BattlegroundArena(broadcast_fn=broadcast_fn)
    elif broadcast_fn and _arena._broadcast_fn is None:
        _arena._broadcast_fn = broadcast_fn
    return _arena
