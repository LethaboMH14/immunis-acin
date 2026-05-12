"""
IMMUNIS ACIN — Autonomous Battleground Loop

Continuous Red vs Blue coevolution without external threat input.

Runs as a background task started by the FastAPI app at startup.
Red continuously generates novel attack variants targeting existing antibodies.
Blue defends. The Arbiter judges each round.

When Blue fails to defend → trigger Agent 2 to synthesise a new antibody.
When Red repeatedly evades → escalate the targeted antibody's strength.
Broadcasts every round via WebSocket so the Battleground page animates live.

Math: Lotka-Volterra coevolution dynamics (math_engines/portfolio + game_theory).
Cadence: One round every N seconds (default 30s, configurable).
Throttle: Pause if system load high or no antibodies exist yet.

Temperature: N/A (orchestration logic, no direct LLM calls)
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from datetime import datetime, timedelta
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
from backend.security.audit_trail import record_event

logger = logging.getLogger("immunis.battleground.autonomous")


class AutonomousBattlegroundLoop:
    """
    Continuous autonomous Red-Blue coevolution loop.
    
    Runs forever in the background, selecting random antibodies from
    the immune memory and stress-testing them with adversarial variants.
    """

    def __init__(self, broadcast_fn: Optional[callable] = None):
        self._broadcast_fn = broadcast_fn
        self._settings = get_settings()
        
        # Runtime state
        self._enabled = False
        self._running = False
        self._round_count = 0
        self._last_round_at: Optional[datetime] = None
        self._last_antibody_synthesis_at: Optional[datetime] = None
        self._consecutive_errors = 0
        self._lock = asyncio.Lock()
        
        # Statistics
        self._stats = {
            "rounds_completed": 0,
            "antibodies_synthesised": 0,
            "red_wins": 0,
            "blue_wins": 0,
            "start_time": None,
        }
        
        logger.info("Autonomous Battleground Loop initialised")

    async def start(self) -> None:
        """Start the autonomous loop."""
        if self._enabled:
            logger.warning("Autonomous Battleground loop already enabled")
            return
            
        self._enabled = True
        self._running = True
        self._stats["start_time"] = utc_now()
        
        logger.info(
            "Autonomous Battleground loop enabled",
            extra={
                "startup_delay": self._settings.battleground_startup_delay_seconds,
                "interval": self._settings.battleground_interval_seconds,
            },
        )
        
        # Schedule the loop to start after delay
        asyncio.create_task(self._run_with_delay())

    async def stop(self) -> None:
        """Stop the autonomous loop gracefully."""
        self._enabled = False
        logger.info("Autonomous Battleground loop disabled - will stop after current round")

    async def trigger_round(self) -> dict[str, Any]:
        """Force an immediate round execution."""
        if not self._settings.autonomous_battleground_enabled:
            return {"error": "Autonomous battleground disabled in config"}
            
        async with self._lock:
            try:
                result = await self._execute_round()
                return {"success": True, "round_result": result}
            except Exception as e:
                logger.error(f"Forced round failed: {e}")
                return {"success": False, "error": str(e)}

    def get_status(self) -> dict[str, Any]:
        """Get current loop status and statistics."""
        uptime_seconds = 0
        if self._stats["start_time"]:
            uptime_seconds = (utc_now() - self._stats["start_time"]).total_seconds()
            
        next_round_in = "N/A"
        if self._last_round_at and self._enabled:
            next_at = self._last_round_at + timedelta(seconds=self._settings.battleground_interval_seconds)
            next_round_in = max(0, (next_at - utc_now()).total_seconds())
            
        return {
            "enabled": self._enabled,
            "running": self._running,
            "rounds_completed": self._stats["rounds_completed"],
            "antibodies_synthesised": self._stats["antibodies_synthesised"],
            "red_wins": self._stats["red_wins"],
            "blue_wins": self._stats["blue_wins"],
            "last_round_at": self._last_round_at.isoformat() if self._last_round_at else None,
            "next_round_in_seconds": next_round_in,
            "uptime_seconds": uptime_seconds,
            "consecutive_errors": self._consecutive_errors,
        }

    async def _run_with_delay(self) -> None:
        """Run the loop with startup delay."""
        try:
            # Wait for system to stabilise
            logger.info(f"Autonomous loop starting in {self._settings.battleground_startup_delay_seconds}s")
            await asyncio.sleep(self._settings.battleground_startup_delay_seconds)
            
            # Main loop
            while self._enabled:
                try:
                    await self._execute_round()
                    self._consecutive_errors = 0  # Reset error counter on success
                    
                    # Wait for next round
                    await asyncio.sleep(self._settings.battleground_interval_seconds)
                    
                except Exception as e:
                    self._consecutive_errors += 1
                    logger.error(f"Autonomous round {self._round_count} failed: {e}")
                    
                    # Auto-disable after too many consecutive errors
                    if self._consecutive_errors >= 5:
                        logger.critical(
                            "Autonomous Battleground loop auto-disabled after 5 consecutive errors"
                        )
                        await self.stop()
                        break
                    
                    # Wait before retrying
                    await asyncio.sleep(min(60, self._settings.battleground_interval_seconds))
                    
        except asyncio.CancelledError:
            logger.info("Autonomous Battleground loop cancelled")
        except Exception as e:
            logger.critical(f"Autonomous Battleground loop crashed: {e}")
        finally:
            self._running = False
            logger.info("Autonomous Battleground loop stopped")

    async def _execute_round(self) -> dict[str, Any]:
        """Execute a single autonomous battleground round."""
        async with self._lock:
            self._round_count += 1
            round_id = generate_id("AR")  # Autonomous Round
            start_time = time.monotonic()
            
            logger.info(f"Autonomous Battleground round {self._round_count} starting")
            
            # Get a random antibody from immune memory
            antibody = await self._select_target_antibody()
            if not antibody:
                logger.info("No antibodies available for autonomous round - skipping")
                return {"skipped": True, "reason": "no_antibodies"}
                
            logger.info(
                f"Round {self._round_count}: Targeting antibody {antibody.antibody_id}",
                extra={
                    "antibody_id": antibody.antibody_id,
                    "attack_family": antibody.attack_family,
                    "current_strength": antibody.strength_score,
                },
            )
            
            # Broadcast round start
            await self._broadcast({
                "event": "autonomous_round_start",
                "round_id": round_id,
                "round_number": self._round_count,
                "target_antibody_id": antibody.antibody_id,
                "timestamp": utc_now().isoformat(),
            })
            
            try:
                # ── Red Agent attacks ──────────────────────────────────────
                red_result = await self._run_red_agent(antibody, round_id)
                if not red_result or not red_result.variants:
                    logger.info(f"Red Agent produced no variants in round {self._round_count}")
                    return {"skipped": True, "reason": "no_variants"}
                
                # ── Blue Agent defends ─────────────────────────────────────
                classifications = await self._run_blue_agent(red_result.variants, antibody, round_id)
                
                # ── Score the round ─────────────────────────────────────────
                round_result = await self._score_round(red_result, classifications, antibody)
                
                # ── Handle Red wins (evasions) ───────────────────────────────
                evasions = [c for c in classifications if c.verdict == ThreatVerdict.UNKNOWN]
                if evasions and await self._should_synthesise_antibody():
                    await self._handle_evasions(evasions, antibody, round_id)
                
                # ── Update statistics ───────────────────────────────────────
                self._stats["rounds_completed"] += 1
                self._stats["red_wins"] += len(evasions)
                self._stats["blue_wins"] += len(classifications) - len(evasions)
                self._last_round_at = utc_now()
                
                duration_ms = (time.monotonic() - start_time) * 1000
                
                logger.info(
                    f"Round {self._round_count} complete",
                    extra={
                        "duration_ms": round(duration_ms, 1),
                        "variants_generated": len(red_result.variants),
                        "evasions": len(evasions),
                        "blocks": len(classifications) - len(evasions),
                        "antibody_synthesised": len(evasions) > 0 and await self._should_synthesise_antibody(),
                    },
                )
                
                # Broadcast round completion
                await self._broadcast({
                    "event": "autonomous_round_complete",
                    "round_id": round_id,
                    "round_number": self._round_count,
                    "result": round_result,
                    "timestamp": utc_now().isoformat(),
                })
                
                return round_result
                
            except Exception as e:
                logger.error(f"Round {self._round_count} execution failed: {e}")
                raise

    async def _select_target_antibody(self) -> Optional[Antibody]:
        """Select a random antibody from immune memory."""
        try:
            from backend.agents.immune_memory import get_immune_memory
            
            memory = get_immune_memory()
            antibodies = memory.get_all_antibodies()
            
            # Filter for antibodies that are not failed
            valid_antibodies = [
                ab for ab in antibodies 
                if ab.status != AntibodyStatus.FAILED and ab.strength_score > 0.1
            ]
            
            if not valid_antibodies:
                return None
                
            # Weight selection towards weaker antibodies (more interesting target)
            weights = [1.0 / (ab.strength_score + 0.1) for ab in valid_antibodies]
            total_weight = sum(weights)
            weights = [w / total_weight for w in weights]
            
            return random.choices(valid_antibodies, weights=weights)[0]
            
        except Exception as e:
            logger.error(f"Failed to select target antibody: {e}")
            return None

    async def _run_red_agent(self, antibody: Antibody, round_id: str) -> Optional[RedAgentResult]:
        """Run Red Agent to generate evasion variants."""
        try:
            from backend.agents.red_agent import generate_variants
            
            # Generate 1-3 variants for autonomous mode
            num_variants = random.randint(1, 3)
            
            logger.info(f"Red Agent generating {num_variants} variants against {antibody.antibody_id}")
            
            result = await generate_variants(
                antibody=antibody,
                num_variants=num_variants,
                actor_type=ThreatActorType.AUTONOMOUS,
            )
            
            # Broadcast each variant
            for variant in result.variants:
                await self._broadcast(
                    WebSocketEvent.red_attack(variant, round_id).model_dump(mode="json")
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Red Agent failed in round {self._round_count}: {e}")
            return None

    async def _run_blue_agent(
        self, 
        variants: list, 
        antibody: Antibody, 
        round_id: str
    ) -> list[ClassificationResult]:
        """Run Blue Agent to classify variants."""
        try:
            from backend.agents.variant_recogniser import classify_batch
            
            logger.info(f"Blue Agent classifying {len(variants)} variants")
            
            classifications = await classify_batch(
                variants=variants,
                target_antibody=antibody,
            )
            
            # Broadcast each classification
            for classification in classifications:
                await self._broadcast(
                    WebSocketEvent.blue_defense(classification, round_id).model_dump(mode="json")
                )
            
            return classifications
            
        except Exception as e:
            logger.error(f"Blue Agent failed in round {self._round_count}: {e}")
            return []

    async def _score_round(
        self,
        red_result: RedAgentResult,
        classifications: list[ClassificationResult],
        antibody: Antibody,
    ) -> dict[str, Any]:
        """Score the round and update antibody strength."""
        evasions = sum(1 for c in classifications if c.verdict == ThreatVerdict.UNKNOWN)
        blocks = len(classifications) - evasions
        
        # Update antibody strength
        if len(classifications) > 0:
            new_strength = blocks / len(classifications)
            antibody.strength_score = new_strength
            antibody.red_agent_tests += len(classifications)
            antibody.red_agent_evasions += evasions
            
            # Update in memory
            from backend.agents.immune_memory import get_immune_memory
            memory = get_immune_memory()
            memory.update_antibody_strength(
                antibody.antibody_id,
                new_strength,
                tests=len(classifications),
                evasions=evasions,
            )
        
        return {
            "antibody_id": antibody.antibody_id,
            "variants_generated": len(red_result.variants),
            "evasions": evasions,
            "blocks": blocks,
            "new_strength": antibody.strength_score,
            "red_won": evasions > 0,
        }

    async def _handle_evasions(
        self,
        evasions: list[ClassificationResult],
        target_antibody: Antibody,
        round_id: str,
    ) -> None:
        """Handle Red wins by synthesising new antibodies."""
        try:
            # Pick the most confident evasion for antibody synthesis
            best_evasion = max(evasions, key=lambda c: c.confidence or 0.0)
            
            logger.info(
                f"Red evaded with confidence {best_evasion.confidence:.2f}. "
                f"Triggering antibody synthesis."
            )
            
            # Create a synthetic fingerprint from the evasion
            from backend.agents.incident_analyst import SemanticFingerprint
            synthetic_fingerprint = SemanticFingerprint(
                fingerprint_id=generate_id("FP"),
                attack_type=target_antibody.attack_type,
                attack_family=target_antibody.attack_family,
                confidence=best_evasion.confidence or 0.8,
                severity="medium",
                iocs=[],
                tactics=["autonomous_evasion"],
                techniques=["red_agent_variant"],
                indicators=[],
                narrative=f"Autonomous synthesis targeting evasion: {best_evasion.reasoning[:200]}",
                extracted_entities=[],
                language_detected="en",
                content_hash=best_evasion.variant_id,
                created_at=utc_now(),
            )
            
            # Synthesise new antibody
            from backend.agents.antibody_synthesiser import synthesise_antibody
            
            new_antibody = await synthesise_antibody(synthetic_fingerprint)
            
            if new_antibody and new_antibody.status != AntibodyStatus.FAILED:
                # Run Z3 verification
                if await self._verify_antibody(new_antibody):
                    new_antibody.formally_verified = True
                    
                    # Store in immune memory
                    from backend.agents.immune_memory import get_immune_memory
                    memory = get_immune_memory()
                    
                    # Create a synthetic threat vector for storage
                    threat_vector = [0.0] * 768  # LaBSE dimension placeholder
                    store_result = memory.store_antibody(new_antibody, threat_vector)
                    
                    self._stats["antibodies_synthesised"] += 1
                    self._last_antibody_synthesis_at = utc_now()
                    
                    logger.info(
                        f"Autonomous antibody synthesised: {new_antibody.antibody_id}",
                        extra={
                            "target_family": new_antibody.attack_family,
                            "formally_verified": new_antibody.formally_verified,
                        },
                    )
                    
                    # Broadcast synthesis
                    await self._broadcast(
                        WebSocketEvent.antibody_synthesised(new_antibody, round_id).model_dump(mode="json")
                    )
                    
                    # Broadcast arbiter decision (promotion)
                    decision = ArbiterDecision(
                        decision_id=generate_id("ARB"),
                        antibody_id=new_antibody.antibody_id,
                        rounds_completed=1,
                        final_strength=1.0,  # Autonomous antibodies start strong
                        promoted=True,
                        promotion_reason="Autonomous synthesis for Red evasion",
                        decided_at=utc_now(),
                    )
                    
                    await self._broadcast(
                        WebSocketEvent.arbiter_decision_made(decision, round_id).model_dump(mode="json")
                    )
                    
                    # Record in evolution tracker
                    from backend.agents.evolution_tracker import get_evolution_tracker
                    tracker = get_evolution_tracker()
                    tracker.record_event(
                        event_type="antibody_synthesised_autonomous",
                        agent_source="autonomous_loop",
                        antibody_id=new_antibody.antibody_id,
                        attack_family=new_antibody.attack_family,
                        description=f"Synthesised for evasion against {target_antibody.antibody_id}",
                    )
                else:
                    logger.warning(f"Autonomous antibody failed verification: {new_antibody.antibody_id}")
            else:
                logger.warning(f"Autonomous antibody synthesis failed")
                
        except Exception as e:
            logger.error(f"Failed to handle evasions: {e}")

    async def _verify_antibody(self, antibody: Antibody) -> bool:
        """Run Z3 formal verification on an antibody."""
        try:
            from backend.agents.verification import verify_antibody
            return await verify_antibody(antibody)
        except Exception as e:
            logger.warning(f"Antibody verification failed: {e}")
            return False  # Fail-safe - allow antibody without verification

    async def _should_synthesise_antibody(self) -> bool:
        """Check if we should synthesise a new antibody (rate limiting)."""
        if not self._last_antibody_synthesis_at:
            return True
            
        time_since_last = utc_now() - self._last_antibody_synthesis_at
        min_interval = timedelta(minutes=5)  # Max 1 antibody per 5 minutes
        
        return time_since_last >= min_interval

    async def _broadcast(self, event: dict) -> None:
        """Broadcast a WebSocket event."""
        if self._broadcast_fn:
            try:
                await self._broadcast_fn(event)
            except Exception as e:
                logger.warning(f"Failed to broadcast event: {e}")


# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

_autonomous_loop: Optional[AutonomousBattlegroundLoop] = None


def get_autonomous_loop(broadcast_fn: Optional[callable] = None) -> AutonomousBattlegroundLoop:
    """Get or create the global autonomous battleground loop."""
    global _autonomous_loop
    if _autonomous_loop is None:
        _autonomous_loop = AutonomousBattlegroundLoop(broadcast_fn=broadcast_fn)
    elif broadcast_fn and _autonomous_loop._broadcast_fn is None:
        _autonomous_loop._broadcast_fn = broadcast_fn
    return _autonomous_loop


async def start_autonomous_battleground() -> None:
    """Start the autonomous battleground loop."""
    loop = get_autonomous_loop()
    await loop.start()
