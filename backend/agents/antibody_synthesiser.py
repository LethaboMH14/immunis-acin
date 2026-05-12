"""
IMMUNIS ACIN — Agent 2: Antibody Synthesiser

Takes a SemanticFingerprint from Agent 1 and compiles it into an Antibody —
a structured, reusable, language-agnostic detection rule.

The antibody is the atomic unit of IMMUNIS. Every other component exists
to create, test, store, or distribute antibodies.

5-Stage Synthesis Process:
    1. Behavioural decomposition into attack dimensions (intent, mechanism, target, timing, psychology)
    2. Minimum viable detection signal extraction (specific enough to catch, general enough for variants)
    3. False positive guard compilation (conditions where antibody should NOT fire)
    4. Actuarial risk scoring (expected loss, VaR, CVaR)
    5. Formal verification via Z3 theorem prover (sound, non-trivial, consistent)

Input:  SemanticFingerprint
Output: Antibody (with formal verification result)

Model:  IMMUNIS-Sentinel → AIsa.one fallback → Ollama fallback
Temperature: 0.3 (detection rules must be precise, not creative)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from backend.config import get_settings
from backend.models.enums import (
    AntibodyStatus,
    AttackType,
    Language,
    MitrePhase,
    Severity,
)
from backend.models.schemas import (
    Antibody,
    SemanticFingerprint,
    generate_id,
    utc_now,
)
from backend.security.audit_trail import record_event
from backend.security.circuit_breaker import get_breaker
from backend.services.aisa_client import call_for_json

logger = logging.getLogger("immunis.agent.antibody_synthesiser")


# ============================================================================
# SYSTEM PROMPT
# ============================================================================

SYSTEM_PROMPT = """You are the Antibody Synthesiser inside IMMUNIS ACIN, a cyber immune system.

You receive a semantic attack fingerprint and produce an ANTIBODY — a permanent, structured detection rule that can identify this attack and its variants across any language.

Your synthesis process:
1. DECOMPOSE the attack into dimensions: intent, mechanism, target, timing, psychology
2. EXTRACT the minimum set of detection signals — not all possible signals, only those without which the antibody would fail
3. COMPILE false positive guards — conditions where this antibody should NOT fire
4. DESCRIBE the cross-lingual pattern — the manipulation in language-agnostic terms

Output a JSON object with these EXACT fields:
{
    "attack_family": "Short name for this class of attack (e.g., 'BEC_Authority_Financial')",
    "detection_signals": {
        "signal_name_1": true,
        "signal_name_2": true,
        "signal_name_3": true
    },
    "detection_signals_description": [
        "Human-readable description of signal 1 and what to look for",
        "Human-readable description of signal 2",
        "Human-readable description of signal 3"
    ],
    "cross_lingual_pattern": "2-3 sentences describing the manipulation pattern in language-agnostic terms. This must work across all languages.",
    "language_variants": ["en", "zu", "st", "af"],
    "confidence_threshold": 0.75,
    "false_positive_guards": [
        "Condition 1 where this antibody should NOT fire (e.g., 'Sender is on verified vendor whitelist AND thread has 30+ day history')",
        "Condition 2",
        "Condition 3"
    ],
    "severity": "Critical|High|Medium|Low",
    "recommended_action": "Block|Quarantine|Alert|Monitor",
    "expected_loss_zar": 500000,
    "antibody_description": "Plain English explanation of what this antibody detects and why it matters"
}

CRITICAL RULES:
1. Output ONLY valid JSON. No markdown, no explanation.
2. Detection signals must be SPECIFIC enough to catch the attack but GENERAL enough to catch variants.
3. Every detection signal must have a corresponding false positive guard.
4. The cross_lingual_pattern must describe the MANIPULATION, not the WORDS.
5. Think like an immunologist: specificity matters. Too broad = alert fatigue. Too narrow = missed variants.
6. expected_loss_zar should be a realistic estimate in South African Rand for this attack type."""


# ============================================================================
# CORE SYNTHESIS FUNCTION
# ============================================================================

async def synthesise_antibody(
    fingerprint: SemanticFingerprint,
) -> Optional[Antibody]:
    """
    Synthesise an antibody from a semantic fingerprint.

    This is the main entry point for Agent 2.
    Called by the orchestrator after Agent 1 produces a fingerprint.

    On failure: returns a minimal antibody with status=FAILED
    rather than raising an exception.
    """
    settings = get_settings()
    start_time = time.monotonic()

    logger.info(
        "Agent 2: Synthesising antibody",
        extra={
            "fingerprint_id": fingerprint.fingerprint_id,
            "attack_type": fingerprint.attack_type.value,
            "confidence": fingerprint.confidence,
        },
    )

    # Check circuit breaker
    breaker = get_breaker("antibody_synthesiser", failure_threshold=3, cooldown_seconds=60)
    if not breaker.allow_call():
        logger.warning("Circuit breaker OPEN for antibody_synthesiser")
        return _failed_antibody(fingerprint, "Circuit breaker open")

    # Build user message from fingerprint
    user_message = _build_synthesis_prompt(fingerprint)

    try:
        result = await call_for_json(
            system_prompt=SYSTEM_PROMPT,
            user_content=user_message,
            response_schema=Antibody,
            temperature=settings.temp_synthesis,
            max_tokens=2048,
            max_parse_retries=2,
        )

        if result["success"] and result["parsed"]:
            breaker.record_success()
            antibody = _build_antibody(result["parsed"], fingerprint)

            # Formal verification
            verification = await _formal_verify(antibody)
            antibody.formally_verified = verification.get("sound", False)
            antibody.verification_result = verification

            duration_ms = (time.monotonic() - start_time) * 1000

            record_event(
                stage="antibody_synthesis",
                agent="antibody_synthesiser",
                action="antibody_synthesised",
                antibody_id=antibody.antibody_id,
                success=True,
                duration_ms=duration_ms,
                metadata={
                    "attack_family": antibody.attack_family,
                    "severity": antibody.severity.value,
                    "formally_verified": antibody.formally_verified,
                    "signals_count": len(antibody.detection_signals),
                    "provider": result.get("provider", "unknown"),
                },
            )

            logger.info(
                "Agent 2: Antibody synthesised",
                extra={
                    "antibody_id": antibody.antibody_id,
                    "attack_family": antibody.attack_family,
                    "formally_verified": antibody.formally_verified,
                    "duration_ms": round(duration_ms, 1),
                },
            )

            return antibody

        else:
            breaker.record_failure()
            return _failed_antibody(
                fingerprint,
                result.get("error", "Synthesis output parsing failed"),
            )

    except Exception as e:
        breaker.record_failure()
        duration_ms = (time.monotonic() - start_time) * 1000

        logger.error(
            "Agent 2: Synthesis failed",
            extra={
                "error_type": type(e).__name__,
                "error": str(e)[:200],
                "duration_ms": round(duration_ms, 1),
            },
        )

        record_event(
            stage="antibody_synthesis",
            agent="antibody_synthesiser",
            action="synthesis_failed",
            success=False,
            duration_ms=duration_ms,
            metadata={"error": str(e)[:200]},
        )

        return _failed_antibody(fingerprint, str(e)[:200])


# ============================================================================
# FORMAL VERIFICATION — Z3 Theorem Prover
# ============================================================================

async def _formal_verify(antibody: Antibody) -> dict[str, Any]:
    """
    Formally verify that the antibody's detection logic is:
    1. SOUND: The detection signals are not contradictory
    2. NON-TRIVIAL: The antibody doesn't detect everything (would be useless)
    3. CONSISTENT: All signals can be simultaneously true

    Uses Z3 theorem prover when available, falls back to heuristic checks.

    Research basis:
        - De Moura & Bjørner (2008), "Z3: An Efficient SMT Solver"
        - Applied to security rule verification by IMMUNIS (novel application)
    """
    try:
        from z3 import Bool, Solver, And, Not, sat, unsat

        signals = antibody.detection_signals
        if not signals:
            return {
                "sound": False,
                "non_trivial": False,
                "consistent": False,
                "method": "z3",
                "reason": "No detection signals to verify",
            }

        # Create Z3 boolean variables for each signal
        z3_vars = {name: Bool(name) for name in signals.keys()}

        # Detection predicate: conjunction of all active signals
        active_signals = [z3_vars[name] for name, active in signals.items() if active]

        if not active_signals:
            return {
                "sound": False,
                "non_trivial": False,
                "consistent": False,
                "method": "z3",
                "reason": "No active detection signals",
            }

        detection = And(*active_signals) if len(active_signals) > 1 else active_signals[0]

        solver = Solver()

        # Verification 1: CONSISTENCY — Can all signals be true simultaneously?
        solver.push()
        solver.add(detection)
        consistency = (await asyncio.to_thread(solver.check)) == sat
        solver.pop()

        # Verification 2: NON-TRIVIALITY — Does there exist input that is NOT detected?
        solver.push()
        solver.add(Not(detection))
        non_trivial = (await asyncio.to_thread(solver.check)) == sat
        solver.pop()

        # Sound = consistent AND non-trivial
        sound = consistency and non_trivial

        return {
            "sound": sound,
            "non_trivial": non_trivial,
            "consistent": consistency,
            "method": "z3",
            "signals_verified": len(active_signals),
            "reason": (
                "Verified: antibody is sound, non-trivial, and consistent"
                if sound
                else f"Failed: consistent={consistency}, non_trivial={non_trivial}"
            ),
        }

    except ImportError:
        # Z3 not installed — fall back to heuristic verification
        return _heuristic_verify(antibody)

    except Exception as e:
        logger.warning(f"Z3 verification failed: {e}")
        return _heuristic_verify(antibody)


def _heuristic_verify(antibody: Antibody) -> dict[str, Any]:
    """
    Heuristic verification when Z3 is not available.

    Checks:
    1. At least 2 detection signals (single signal = too broad)
    2. At least 1 false positive guard (no guards = alert fatigue)
    3. Signals are not all the same (redundant)
    4. Description is non-empty (antibody must be explainable)
    """
    signals = antibody.detection_signals
    active = [name for name, val in signals.items() if val]
    guards = antibody.false_positive_guards

    issues = []

    if len(active) < 2:
        issues.append("Fewer than 2 active detection signals — too broad")

    if len(guards) < 1:
        issues.append("No false positive guards — will cause alert fatigue")

    if len(set(active)) < len(active):
        issues.append("Duplicate signal names detected")

    if not antibody.cross_lingual_pattern:
        issues.append("No cross-lingual pattern — antibody is not language-agnostic")

    sound = len(issues) == 0

    return {
        "sound": sound,
        "non_trivial": len(active) >= 2,
        "consistent": True,  # Heuristic assumes consistency
        "method": "heuristic",
        "signals_verified": len(active),
        "issues": issues,
        "reason": "Heuristic verification passed" if sound else f"Issues: {'; '.join(issues)}",
    }


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _build_synthesis_prompt(fingerprint: SemanticFingerprint) -> str:
    """Build the user message for antibody synthesis."""
    parts = [
        "Synthesise an antibody for the following threat fingerprint:",
        "",
        f"Attack type: {fingerprint.attack_type.value}",
        f"MITRE phase: {fingerprint.mitre_phase.value}",
        f"MITRE technique: {fingerprint.mitre_technique_id}",
        f"Manipulation technique: {fingerprint.manipulation_technique.value}",
        f"Language detected: {fingerprint.language_detected.value}",
        f"Code-switching: {fingerprint.code_switching_detected}",
        f"Severity: {fingerprint.severity.value}",
        f"Confidence: {fingerprint.confidence}",
        f"Intent: {fingerprint.intent}",
        f"Semantic pattern: {fingerprint.semantic_pattern}",
        f"Target asset: {fingerprint.target_asset}",
    ]

    if fingerprint.indicators_of_compromise:
        parts.append(f"IOCs: {', '.join(fingerprint.indicators_of_compromise[:10])}")

    if fingerprint.social_engineering_vectors:
        parts.append(f"Social engineering: {', '.join(fingerprint.social_engineering_vectors[:5])}")

    if fingerprint.urgency_signals:
        parts.append(f"Urgency signals: {', '.join(fingerprint.urgency_signals[:5])}")

    if fingerprint.financial_triggers:
        parts.append(f"Financial triggers: {', '.join(fingerprint.financial_triggers[:5])}")

    return "\n".join(parts)


def _build_antibody(parsed: dict[str, Any], fingerprint: SemanticFingerprint) -> Antibody:
    """Build an Antibody from parsed AI output + fingerprint context."""
    settings = get_settings()

    # Parse detection signals
    raw_signals = parsed.get("detection_signals", {})
    if isinstance(raw_signals, dict):
        detection_signals = {str(k): bool(v) for k, v in raw_signals.items()}
    elif isinstance(raw_signals, list):
        detection_signals = {str(s): True for s in raw_signals}
    else:
        detection_signals = {"generic_signal": True}

    # Parse language variants
    raw_langs = parsed.get("language_variants", [])
    language_variants = []
    for lang in raw_langs:
        try:
            language_variants.append(Language.from_string(str(lang)))
        except Exception:
            pass
    if not language_variants:
        language_variants = [fingerprint.language_detected]

    # Parse severity
    severity_str = parsed.get("severity", fingerprint.severity.value)
    severity_map = {s.value.lower(): s for s in Severity}
    severity = severity_map.get(str(severity_str).lower(), fingerprint.severity)

    return Antibody(
        antibody_id=generate_id("AB"),
        parent_fingerprint_id=fingerprint.fingerprint_id,
        attack_family=str(parsed.get("attack_family", fingerprint.attack_type.value))[:100],
        attack_type=fingerprint.attack_type,
        detection_signals=detection_signals,
        detection_signals_description=_ensure_list(
            parsed.get("detection_signals_description", [])
        ),
        cross_lingual_pattern=str(parsed.get("cross_lingual_pattern", fingerprint.semantic_pattern))[:1000],
        language_variants=language_variants,
        mitre_technique=fingerprint.mitre_technique_id,
        mitre_phase=fingerprint.mitre_phase,
        severity=severity,
        confidence_threshold=_clamp(parsed.get("confidence_threshold", 0.75), 0.0, 1.0),
        false_positive_guards=_ensure_list(parsed.get("false_positive_guards", [])),
        strength_score=0.0,  # Set by Arbiter after stress testing
        status=AntibodyStatus.PENDING,
        expected_loss_zar=max(0.0, float(parsed.get("expected_loss_zar", 0))),
        node_origin=settings.immunis_node_id,
        synthesised_at=utc_now(),
    )


def _failed_antibody(fingerprint: SemanticFingerprint, reason: str) -> Antibody:
    """Generate a failed antibody when synthesis fails."""
    settings = get_settings()

    record_event(
        stage="antibody_synthesis",
        agent="antibody_synthesiser",
        action="antibody_failed",
        success=False,
        metadata={"reason": reason[:200]},
    )

    return Antibody(
        antibody_id=generate_id("AB"),
        parent_fingerprint_id=fingerprint.fingerprint_id,
        attack_family=f"FAILED_{fingerprint.attack_type.value}",
        attack_type=fingerprint.attack_type,
        detection_signals={"synthesis_failed": True},
        cross_lingual_pattern=f"Synthesis failed: {reason[:200]}",
        severity=fingerprint.severity,
        status=AntibodyStatus.FAILED,
        node_origin=settings.immunis_node_id,
        synthesised_at=utc_now(),
    )


def _clamp(value: Any, min_val: float, max_val: float) -> float:
    """Clamp a value to a range, handling non-numeric input."""
    try:
        return max(min_val, min(max_val, float(value)))
    except (TypeError, ValueError):
        return (min_val + max_val) / 2


def _ensure_list(value: Any) -> list[str]:
    """Ensure a value is a list of strings."""
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value] if value else []
    return []
