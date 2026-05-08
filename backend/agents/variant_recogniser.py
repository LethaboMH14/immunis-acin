"""
IMMUNIS ACIN — Agent 5: Variant Recogniser (Blue Defender)

The Blue side of the adversarial arms race. Classifies every incoming
threat and every Red Agent variant against the antibody library.

Responsibilities:
    1. Classify threats: KNOWN (block) / VARIANT (bridge + learn) / NOVEL (full AIR)
    2. Classify Red Agent variants: detected (Blue wins) / evaded (Red wins)
    3. Generate blue_learning_signal when a variant evades (what was missed)
    4. Maintain confidence calibration (tighten thresholds when variants evade)

The Blue defender must be as tactically impressive as the Red attacker.
Blue learning from defeat is MORE impressive than Red winning.

Model: IMMUNIS-Sentinel → AIsa.one fallback
Temperature: 0.1 (classification must be deterministic and consistent)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from backend.config import get_settings
from backend.models.enums import (
    AttackType,
    Language,
    ManipulationTechnique,
    Severity,
    ThreatVerdict,
)
from backend.models.schemas import (
    Antibody,
    ClassificationResult,
    EvasionVariant,
    SemanticFingerprint,
    generate_id,
    utc_now,
)
from backend.security.audit_trail import record_event
from backend.security.circuit_breaker import get_breaker
from backend.services.aisa_client import call_for_json

logger = logging.getLogger("immunis.agent.variant_recogniser")


# ============================================================================
# SYSTEM PROMPT
# ============================================================================

SYSTEM_PROMPT = """You are the Variant Recogniser (Blue Defender) inside IMMUNIS ACIN.

Your job: determine whether an incoming threat or attack variant is DETECTED by the
existing antibody library, or whether it EVADES detection.

You receive:
1. The attack content (a threat or Red Agent variant)
2. The antibody library summary (detection signals and patterns)

You must classify:
- "known": The attack matches an existing antibody with high confidence. DETECTED.
- "variant": The attack is related to a known pattern but has differences. PARTIALLY DETECTED.
- "novel": The attack does not match any known antibody. EVADED / NOT DETECTED.
- "benign": The content is not an attack at all. FALSE ALARM.

Output JSON:
{
    "verdict": "known|variant|novel|benign",
    "matched_antibody_id": "AB-xxx or null if no match",
    "similarity_score": 0.0-1.0,
    "confidence": 0.0-1.0,
    "reasoning": "2-3 sentences explaining WHY this classification was made",
    "variant_delta": "If variant: what is different from the known attack",
    "blue_learning_signal": "If novel/evaded: what the antibody library MISSED and should learn to detect"
}

CRITICAL RULES:
1. Output ONLY valid JSON. No markdown, no explanation.
2. Be CONSERVATIVE. If uncertain, classify as "variant" not "known". False negatives are worse than false positives.
3. The similarity_score must reflect actual semantic similarity to the nearest antibody, not just surface text overlap.
4. The blue_learning_signal is CRITICAL when verdict is "novel" — it tells Agent 2 what to synthesise next.
5. Consider ALL detection signals in the antibody, not just one. An attack that evades ONE signal but matches others is a "variant", not "novel".
6. Language switching alone does NOT make an attack "novel" if the manipulation pattern is the same."""


# ============================================================================
# CLASSIFICATION THRESHOLDS
# ============================================================================

# These thresholds determine the verdict
KNOWN_THRESHOLD = 0.85      # Above this = KNOWN (instant block)
VARIANT_THRESHOLD = 0.55    # Above this = VARIANT (bridge + learn)
# Below VARIANT_THRESHOLD = NOVEL (full AIR protocol)


# ============================================================================
# CORE CLASSIFICATION FUNCTION
# ============================================================================

async def classify_threat(
    content: str,
    antibody_library_summary: str,
    source_antibody_id: Optional[str] = None,
) -> ClassificationResult:
    """
    Classify a threat or Red Agent variant against the antibody library.
    
    This is the main entry point for Agent 5.
    Called by:
    - The orchestrator (for incoming threats)
    - The Battleground/Arena (for Red Agent variants)
    
    Args:
        content: The threat content or Red Agent variant to classify
        antibody_library_summary: Summary of relevant antibodies for context
        source_antibody_id: If classifying a Red Agent variant, which antibody it targets
    
    Returns:
        ClassificationResult with verdict, confidence, and learning signal
    """
    settings = get_settings()
    start_time = time.monotonic()

    logger.info(
        "Agent 5: Classifying threat",
        extra={
            "content_length": len(content),
            "source_antibody": source_antibody_id,
        },
    )

    # Check circuit breaker
    breaker = get_breaker("variant_recogniser", failure_threshold=3, cooldown_seconds=60)
    if not breaker.allow_call():
        logger.warning("Circuit breaker OPEN for variant_recogniser")
        # Fail-safe: classify as NOVEL (conservative — triggers full AIR)
        return ClassificationResult(
            verdict=ThreatVerdict.NOVEL,
            confidence=0.0,
            reasoning="Circuit breaker open — defaulting to NOVEL for safety",
        )

    # Build user message
    user_message = _build_classification_prompt(content, antibody_library_summary, source_antibody_id)

    try:
        result = await call_for_json(
            system_prompt=SYSTEM_PROMPT,
            user_content=user_message,
            response_schema=ClassificationResult,
            temperature=settings.temp_blue_agent,
            max_tokens=1024,
            max_parse_retries=2,
        )

        if result["success"] and result["parsed"]:
            breaker.record_success()
            classification = _build_classification(result["parsed"], source_antibody_id)

            duration_ms = (time.monotonic() - start_time) * 1000

            record_event(
                stage="blue_defense",
                agent="variant_recogniser",
                action="threat_classified",
                antibody_id=source_antibody_id,
                success=True,
                duration_ms=duration_ms,
                metadata={
                    "verdict": classification.verdict.value,
                    "confidence": classification.confidence,
                    "matched_antibody": classification.matched_antibody_id,
                    "provider": result.get("provider", "unknown"),
                },
            )

            logger.info(
                "Agent 5: Classification complete",
                extra={
                    "verdict": classification.verdict.value,
                    "confidence": classification.confidence,
                    "duration_ms": round(duration_ms, 1),
                },
            )

            return classification

        else:
            breaker.record_failure()
            # Fail-safe: NOVEL
            return ClassificationResult(
                verdict=ThreatVerdict.NOVEL,
                confidence=0.0,
                reasoning=f"Classification failed: {result.get('error', 'unknown')}. Defaulting to NOVEL.",
            )

    except Exception as e:
        breaker.record_failure()
        duration_ms = (time.monotonic() - start_time) * 1000

        logger.error(
            "Agent 5: Classification failed",
            extra={
                "error_type": type(e).__name__,
                "error": str(e)[:200],
                "duration_ms": round(duration_ms, 1),
            },
        )

        # Fail-safe: NOVEL (conservative — better to over-alert than miss)
        return ClassificationResult(
            verdict=ThreatVerdict.NOVEL,
            confidence=0.0,
            reasoning=f"Classification error: {str(e)[:200]}. Defaulting to NOVEL for safety.",
        )


# ============================================================================
# RED AGENT VARIANT CLASSIFICATION
# ============================================================================

async def classify_red_variant(
    variant: EvasionVariant,
    target_antibody: Antibody,
) -> ClassificationResult:
    """
    Classify a Red Agent variant — did it evade the target antibody?
    
    This is the Blue side of the arms race. For each Red Agent variant,
    Blue must determine: would this variant be caught by the antibody?
    
    If Blue says "known" or "variant" → Blue wins (variant detected)
    If Blue says "novel" → Red wins (variant evaded)
    
    The blue_learning_signal from a Red win is what drives antibody evolution.
    """
    # Build antibody summary for context
    antibody_summary = _antibody_to_summary(target_antibody)

    # Classify the variant's synthetic attack content
    classification = await classify_threat(
        content=variant.synthetic_attack,
        antibody_library_summary=antibody_summary,
        source_antibody_id=target_antibody.antibody_id,
    )

    # Log the arms race outcome
    blue_won = classification.verdict in (ThreatVerdict.KNOWN, ThreatVerdict.VARIANT)

    record_event(
        stage="blue_defense" if blue_won else "red_attack",
        agent="variant_recogniser",
        action="blue_win" if blue_won else "red_win",
        antibody_id=target_antibody.antibody_id,
        success=blue_won,
        metadata={
            "variant_id": variant.variant_id,
            "evasion_vector": variant.evasion_vector,
            "blue_verdict": classification.verdict.value,
            "blue_confidence": classification.confidence,
            "red_predicted_success": variant.predicted_evasion_success,
        },
    )

    logger.info(
        f"Arms race: {'BLUE WINS' if blue_won else 'RED WINS'}",
        extra={
            "variant_id": variant.variant_id,
            "evasion_vector": variant.evasion_vector,
            "verdict": classification.verdict.value,
            "confidence": classification.confidence,
        },
    )

    return classification


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _build_classification_prompt(
    content: str,
    antibody_summary: str,
    source_antibody_id: Optional[str],
) -> str:
    """Build the user message for classification."""
    # Truncate content to prevent token overflow
    truncated_content = content[:3000] if len(content) > 3000 else content

    parts = [
        "Classify the following content against the antibody library.",
        "",
        "=== CONTENT TO CLASSIFY ===",
        truncated_content,
        "",
        "=== ANTIBODY LIBRARY SUMMARY ===",
        antibody_summary,
    ]

    if source_antibody_id:
        parts.append(f"\nNote: This is a Red Agent variant targeting antibody {source_antibody_id}.")
        parts.append("Determine if this variant would be DETECTED or would EVADE the antibody.")

    parts.append("\nOutput ONLY as JSON classification object.")

    return "\n".join(parts)


def _antibody_to_summary(antibody: Antibody) -> str:
    """Convert an antibody to a summary string for classification prompt."""
    signals = ", ".join(
        f"{name}={'active' if val else 'inactive'}"
        for name, val in antibody.detection_signals.items()
    )

    descriptions = "\n  ".join(antibody.detection_signals_description[:5])

    return (
        f"Antibody {antibody.antibody_id}:\n"
        f"  Attack family: {antibody.attack_family}\n"
        f"  Detection signals: {signals}\n"
        f"  Signal descriptions:\n  {descriptions}\n"
        f"  Cross-lingual pattern: {antibody.cross_lingual_pattern}\n"
        f"  Languages validated: {[l.value for l in antibody.language_variants]}\n"
        f"  Confidence threshold: {antibody.confidence_threshold}\n"
        f"  False positive guards: {', '.join(antibody.false_positive_guards[:3])}"
    )


def _build_classification(
    parsed: dict[str, Any],
    source_antibody_id: Optional[str],
) -> ClassificationResult:
    """Build a ClassificationResult from parsed AI output."""
    # Parse verdict
    verdict_str = str(parsed.get("verdict", "novel")).lower().strip()
    verdict_map = {
        "known": ThreatVerdict.KNOWN,
        "variant": ThreatVerdict.VARIANT,
        "novel": ThreatVerdict.NOVEL,
        "benign": ThreatVerdict.BENIGN,
    }
    verdict = verdict_map.get(verdict_str, ThreatVerdict.NOVEL)

    # Parse confidence
    confidence = parsed.get("confidence", 0.5)
    try:
        confidence = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence = 0.5

    # Parse similarity
    similarity = parsed.get("similarity_score", 0.0)
    try:
        similarity = max(0.0, min(1.0, float(similarity)))
    except (TypeError, ValueError):
        similarity = 0.0

    return ClassificationResult(
        classification_id=generate_id("CLS"),
        verdict=verdict,
        matched_antibody_id=parsed.get("matched_antibody_id") or source_antibody_id,
        similarity_score=similarity,
        variant_of_family=parsed.get("variant_of_family"),
        variant_delta=str(parsed.get("variant_delta", ""))[:500],
        confidence=confidence,
        reasoning=str(parsed.get("reasoning", ""))[:500],
        blue_learning_signal=parsed.get("blue_learning_signal"),
        classified_at=utc_now(),
    )


# ============================================================================
# BATCH CLASSIFICATION (for Battleground efficiency)
# ============================================================================

async def classify_batch(
    variants: list[EvasionVariant],
    target_antibody: Antibody,
) -> list[ClassificationResult]:
    """
    Classify a batch of Red Agent variants.
    
    Runs classifications concurrently for speed (the Battleground
    needs to process many variants quickly).
    
    Returns results in the same order as input variants.
    """
    import asyncio

    tasks = [
        classify_red_variant(variant, target_antibody)
        for variant in variants
    ]

    # Run concurrently with a semaphore to prevent overwhelming the AI provider
    semaphore = asyncio.Semaphore(3)  # Max 3 concurrent classifications

    async def limited_classify(task):
        async with semaphore:
            return await task

    results = await asyncio.gather(
        *[limited_classify(task) for task in tasks],
        return_exceptions=True,
    )

    # Replace exceptions with fail-safe NOVEL classifications
    final_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.warning(f"Batch classification {i} failed: {result}")
            final_results.append(ClassificationResult(
                verdict=ThreatVerdict.NOVEL,
                confidence=0.0,
                reasoning=f"Batch classification failed: {str(result)[:200]}",
            ))
        else:
            final_results.append(result)

    return final_results
