"""
IMMUNIS ACIN — Agent 6: Evolution Tracker

The historian and scorekeeper of the immune system.

Responsibilities:
    1. Record every event in the arms race (attacks, defenses, syntheses, broadcasts)
    2. Compute the immunity score using a PID controller for smooth transitions
    3. Track trends (improving/stable/degrading)
    4. Provide data for ArmsRaceTimeline and ImmunityGauge dashboard components
    5. Detect streaks (Red winning streak = system weakening, Blue streak = strengthening)

The immunity score is DETERMINISTIC — not LLM-dependent.
The math is auditable. A judge can verify every calculation.

The PID controller prevents wild oscillations:
    u(t) = K_p·e(t) + K_i·∫e(τ)dτ + K_d·de/dt
    
    K_p: React to current gap between target and actual immunity
    K_i: React to persistent weakness (accumulated error)
    K_d: React to sudden changes (novel threat spike)

Temperature: N/A (no LLM calls — pure math)
"""

from __future__ import annotations

import logging
import time
from collections import deque
from typing import Any, Optional

from backend.config import get_settings
from backend.models.enums import PipelineStage
from backend.models.schemas import (
    Antibody,
    ClassificationResult,
    EvolutionEvent,
    EvasionVariant,
    ImmunityState,
    RedAgentResult,
    generate_id,
    utc_now,
)

logger = logging.getLogger("immunis.agent.evolution_tracker")


# ============================================================================
# SCORE DELTAS — How much each event type affects immunity
# ============================================================================

SCORE_DELTAS = {
    "antibody_synthesised": +3.0,
    "antibody_verified": +2.0,        # Z3 formal verification passed
    "antibody_promoted": +2.0,        # Arbiter approved
    "antibody_broadcast": +1.5,       # Shared to mesh
    "threat_blocked_known": +1.0,     # Known threat instantly blocked
    "threat_blocked_variant": +1.5,   # Variant detected and blocked
    "novel_threat_detected": -3.0,    # Novel = we were vulnerable
    "red_agent_evaded": -2.0,         # Red found a gap
    "red_agent_blocked": +1.5,        # Blue defended successfully
    "bridge_defense_applied": +0.5,   # Partial coverage deployed
    "honeypot_activated": +0.5,       # Deception layer engaged
    "containment_deployed": +0.5,     # Threat contained
    "mesh_antibody_received": +1.0,   # Inherited immunity from peer
}

# Streak bonuses/penalties
STREAK_THRESHOLD = 3
RED_STREAK_MULTIPLIER = 1.5    # Red winning 3+ in a row = 1.5x penalty
BLUE_STREAK_MULTIPLIER = 1.3   # Blue winning 3+ in a row = 1.3x bonus


class EvolutionTracker:
    """
    Tracks the complete evolution of the immune system.
    
    Every significant event is recorded with its impact on immunity.
    The PID controller smooths the score transitions.
    The timeline provides data for the ArmsRaceTimeline dashboard component.
    """

    def __init__(self):
        settings = get_settings()

        # Immunity state
        self._state = ImmunityState(
            immunity_score=50.0,
            trend="stable",
        )

        # PID controller parameters
        self._kp = settings.pid_kp
        self._ki = settings.pid_ki
        self._kd = settings.pid_kd
        self._target = settings.immunity_target
        self._integral = 0.0
        self._last_error = 0.0

        # Event history
        self._events: deque[EvolutionEvent] = deque(maxlen=1000)
        self._recent_scores: deque[float] = deque(maxlen=50)

        # Streak tracking
        self._red_streak = 0
        self._blue_streak = 0

        # Arms race statistics
        self._total_red_attacks = 0
        self._total_blue_wins = 0
        self._total_red_wins = 0

        logger.info("Evolution Tracker initialised")

    @property
    def state(self) -> ImmunityState:
        """Current immunity state."""
        return self._state

    @property
    def immunity_score(self) -> float:
        """Current immunity score (0-100)."""
        return self._state.immunity_score

    def record_event(
        self,
        event_type: str,
        agent_source: str = "",
        antibody_id: Optional[str] = None,
        attack_family: Optional[str] = None,
        description: str = "",
        custom_delta: Optional[float] = None,
    ) -> EvolutionEvent:
        """
        Record an event and update the immunity score.
        
        This is the main entry point. Called by the orchestrator
        and battleground at every significant moment.
        
        Args:
            event_type: Key from SCORE_DELTAS (e.g., "antibody_synthesised")
            agent_source: Which agent generated this event
            antibody_id: Related antibody if applicable
            attack_family: Related attack family if applicable
            description: Human-readable description
            custom_delta: Override the default score delta
        
        Returns:
            The recorded EvolutionEvent
        """
        score_before = self._state.immunity_score

        # Calculate score delta
        if custom_delta is not None:
            delta = custom_delta
        else:
            delta = SCORE_DELTAS.get(event_type, 0.0)

        # Apply streak multipliers
        delta = self._apply_streak(event_type, delta)

        # Apply PID controller for smooth transitions
        raw_new_score = score_before + delta
        smoothed_score = self._pid_smooth(raw_new_score)

        # Clamp to valid range
        self._state.immunity_score = max(0.0, min(100.0, smoothed_score))

        # Update trend
        self._recent_scores.append(self._state.immunity_score)
        self._state.trend = self._compute_trend()

        # Update counters
        self._update_counters(event_type)

        # Create event record
        event = EvolutionEvent(
            event_id=generate_id("EVT"),
            event_type=PipelineStage.RED_ATTACK if "red" in event_type else PipelineStage.BLUE_DEFENSE,
            agent_source=agent_source,
            antibody_id=antibody_id,
            attack_family=attack_family,
            description=description or f"{event_type}: {delta:+.1f} immunity",
            immunity_score_before=round(score_before, 4),
            immunity_score_after=round(self._state.immunity_score, 4),
            immunity_delta=round(self._state.immunity_score - score_before, 4),
            timestamp=utc_now(),
        )

        self._events.append(event)

        logger.info(
            f"Evolution: {event_type}",
            extra={
                "delta": round(delta, 2),
                "score_before": round(score_before, 2),
                "score_after": round(self._state.immunity_score, 2),
                "trend": self._state.trend,
                "red_streak": self._red_streak,
                "blue_streak": self._blue_streak,
            },
        )

        return event

    def record_arms_race_round(
        self,
        antibody: Antibody,
        red_result: RedAgentResult,
        classifications: list[ClassificationResult],
    ) -> list[EvolutionEvent]:
        """
        Record a complete arms race round (Red attack + Blue defense).
        
        Called by the Battleground after each round.
        Returns all events generated.
        """
        events = []

        for i, (variant, classification) in enumerate(
            zip(red_result.variants, classifications)
        ):
            blue_won = classification.verdict.value in ("known", "variant")

            if blue_won:
                event = self.record_event(
                    event_type="red_agent_blocked",
                    agent_source="variant_recogniser",
                    antibody_id=antibody.antibody_id,
                    attack_family=antibody.attack_family,
                    description=(
                        f"Blue blocked Red's {variant.evasion_vector} variant "
                        f"(confidence: {classification.confidence:.2f})"
                    ),
                )
            else:
                event = self.record_event(
                    event_type="red_agent_evaded",
                    agent_source="red_agent",
                    antibody_id=antibody.antibody_id,
                    attack_family=antibody.attack_family,
                    description=(
                        f"Red evaded with {variant.evasion_vector} "
                        f"(predicted: {variant.predicted_evasion_success:.2f})"
                    ),
                )

            events.append(event)

        return events

    def _apply_streak(self, event_type: str, delta: float) -> float:
        """Apply streak bonuses/penalties."""
        if event_type == "red_agent_evaded":
            self._red_streak += 1
            self._blue_streak = 0
            if self._red_streak >= STREAK_THRESHOLD:
                delta *= RED_STREAK_MULTIPLIER
                logger.warning(
                    f"Red on {self._red_streak}-win streak! "
                    f"Penalty multiplied by {RED_STREAK_MULTIPLIER}x"
                )

        elif event_type == "red_agent_blocked":
            self._blue_streak += 1
            self._red_streak = 0
            if self._blue_streak >= STREAK_THRESHOLD:
                delta *= BLUE_STREAK_MULTIPLIER

        elif event_type in ("antibody_synthesised", "antibody_promoted"):
            # Synthesis breaks Red streak
            self._red_streak = 0

        return delta

    def _pid_smooth(self, raw_score: float) -> float:
        """
        Apply PID controller for smooth immunity score transitions.
        
        Prevents wild oscillations while allowing the score to respond
        to real changes in the threat landscape.
        
        u(t) = K_p·e(t) + K_i·∫e(τ)dτ + K_d·de/dt
        """
        error = self._target - raw_score

        # Proportional term
        p_term = self._kp * error

        # Integral term (accumulated error — persistent weaknesses)
        self._integral += error * 0.1  # dt approximation
        # Anti-windup: clamp integral to prevent runaway
        self._integral = max(-50.0, min(50.0, self._integral))
        i_term = self._ki * self._integral

        # Derivative term (rate of change — sudden attacks)
        d_term = self._kd * (error - self._last_error)
        self._last_error = error

        # PID output — small adjustment to smooth the transition
        pid_adjustment = (p_term + i_term + d_term) * 0.01

        return raw_score + pid_adjustment

    def _compute_trend(self) -> str:
        """Compute trend from recent score history."""
        if len(self._recent_scores) < 3:
            return "stable"

        recent = list(self._recent_scores)
        first_half = sum(recent[:len(recent)//2]) / (len(recent)//2)
        second_half = sum(recent[len(recent)//2:]) / (len(recent) - len(recent)//2)

        diff = second_half - first_half
        if diff > 1.0:
            return "improving"
        elif diff < -1.0:
            return "degrading"
        return "stable"

    def _update_counters(self, event_type: str) -> None:
        """Update state counters based on event type."""
        if event_type == "red_agent_evaded":
            self._total_red_attacks += 1
            self._total_red_wins += 1
            self._state.total_red_attacks += 1
            self._state.total_red_wins += 1

        elif event_type == "red_agent_blocked":
            self._total_red_attacks += 1
            self._total_blue_wins += 1
            self._state.total_red_attacks += 1
            self._state.total_blue_wins += 1

        elif event_type == "novel_threat_detected":
            self._state.total_novel_detected += 1

        elif event_type in ("threat_blocked_known", "threat_blocked_variant"):
            self._state.total_threats_blocked += 1

    # ====================================================================
    # DASHBOARD DATA
    # ====================================================================

    def get_timeline(self, limit: int = 100) -> list[dict[str, Any]]:
        """
        Get the arms race timeline for the ArmsRaceTimeline component.
        
        Returns events formatted for the frontend visualization.
        """
        events = list(self._events)[-limit:]
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "type": "red" if "red" in e.description.lower() or e.immunity_delta < 0 else "blue",
                "description": e.description,
                "immunity_before": e.immunity_score_before,
                "immunity_after": e.immunity_score_after,
                "delta": e.immunity_delta,
                "antibody_id": e.antibody_id,
                "attack_family": e.attack_family,
            }
            for e in events
        ]

    def get_dashboard_summary(self) -> dict[str, Any]:
        """Get everything the dashboard needs in one call."""
        return {
            "immunity_score": round(self._state.immunity_score, 2),
            "trend": self._state.trend,
            "total_events": len(self._events),
            "total_red_attacks": self._total_red_attacks,
            "total_blue_wins": self._total_blue_wins,
            "total_red_wins": self._total_red_wins,
            "blue_win_rate": round(
                self._total_blue_wins / max(1, self._total_red_attacks), 4
            ),
            "red_streak": self._red_streak,
            "blue_streak": self._blue_streak,
            "recent_events": self.get_timeline(20),
        }

    def get_state(self) -> ImmunityState:
        """Get the full immunity state for WebSocket broadcast."""
        self._state.total_red_attacks = self._total_red_attacks
        self._state.total_blue_wins = self._total_blue_wins
        self._state.total_red_wins = self._total_red_wins
        self._state.pid_error = round(self._last_error, 4)
        self._state.pid_integral = round(self._integral, 4)
        return self._state


# ============================================================================
# MODULE-LEVEL SINGLETON
# ============================================================================

_tracker: Optional[EvolutionTracker] = None


def get_evolution_tracker() -> EvolutionTracker:
    """Get or create the global Evolution Tracker."""
    global _tracker
    if _tracker is None:
        _tracker = EvolutionTracker()
    return _tracker
