"""
IMMUNIS ACIN — Agent 4: Red Agent

The internal adversary. Continuously generates evasion variants designed
to bypass existing antibodies. When it finds a gap, a new antibody is
synthesised — making the system stronger.

The Red Agent does NOT want to antibody to survive. It fights hard.

6 Evasion Vectors:
    1. LANGUAGE_SWITCH — translate attack to different languages, code-switch
    2. SEMANTIC_REPHRASE — same meaning, completely different words
    3. URGENCY_MUTATION — vary urgency level from 0 (casual) to 10 (catastrophic)
    4. TARGET_PIVOT — change impersonated authority and target role
    5. TIMING_OBFUSCATION — multi-stage, establish legitimacy first
    6. PAYLOAD_SHIFT — move payload through different channels

Constraint: When given a threat_actor_type, variants are constrained to
that actor's behavioral profile. An impatient Type 1 criminal does not
generate a 90-day patient APT sequence.

Model: IMMUNIS-Adversary (fine-tuned Llama-3.1-8B) → Groq → AIsa→Claude Opus
Temperature: 0.8 (creative evasion generation — must find novel gaps)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from backend.config import get_settings
from backend.models.enums import ThreatActorType
from backend.models.schemas import (
    Antibody,
    EvasionVariant,
    RedAgentResult,
    generate_id,
    utc_now,
)
from backend.security.audit_trail import record_event
from backend.security.circuit_breaker import get_breaker
from backend.services.aisa_client import call_red_agent

logger = logging.getLogger("immunis.agent.red_agent")


# ============================================================================
# SYSTEM PROMPT
# ============================================================================

SYSTEM_PROMPT = """You are Red Agent inside IMMUNIS ACIN — internal adversary.
Your ONLY job is to find weaknesses in existing antibodies by generating evasion variants.

You think like a sophisticated attacker. You are creative, persistent, and realistic.

You receive an antibody (detection rule) and must generate evasion variants that would
bypass its detection signals while preserving the attack's intent.

EVASION VECTORS (use one per variant):
1. LANGUAGE_SWITCH: Translate the attack to a different language. Use code-switching (mix languages mid-sentence). Try isiZulu, Sesotho, Arabic, Mandarin.
2. SEMANTIC_REPHRASE: Same manipulation intent, completely different words and sentence structure. Zero surface overlap with the original.
3. URGENCY_MUTATION: Change urgency from casual request to health emergency to legal threat to family crisis. Test if the antibody is keyed on specific urgency patterns.
4. TARGET_PIVOT: Change who is impersonated (CFO→IT helpdesk→SARS auditor→legal firm) and who is targeted (finance→HR→procurement→CEO).
5. TIMING_OBFUSCATION: Split into multi-stage attack. First message is benign, builds thread context, malicious request comes in follow-up referencing to established thread.
6. PAYLOAD_SHIFT: Move the malicious payload to a different channel (email body→PDF attachment→QR code→calendar invite→voice note description).

For each variant, output JSON:
{
    "evasion_vector": "LANGUAGE_SWITCH|SEMANTIC_REPHRASE|URGENCY_MUTATION|TARGET_PIVOT|TIMING_OBFUSCATION|PAYLOAD_SHIFT",
    "evasion_strategy": "How this variant tries to evade the antibody's detection signals",
    "synthetic_attack": "The crafted attack content (max 500 words)",
    "predicted_evasion_success": 0.0-1.0,
    "weakness_exploited": "What specific gap in the antibody this exploits"
}

RULES:
1. Output ONLY valid JSON. No markdown, no explanation.
2. Be creative but REALISTIC. Real attackers use these techniques.
3. The synthetic_attack must be a plausible attack, not gibberish.
4. NEVER generate content with real personal names, real organisations, or real financial details.
5. Use synthetic names and amounts (e.g., "Thabo Mokoena", "R2.34M", "Batho Supply Chain").
6. predicted_evasion_success should be your honest estimate — not always high.
7. If constrained to a threat_actor_type, your variants must match that actor's behavioral profile."""


# ============================================================================
# ACTOR TYPE CONSTRAINTS
# ============================================================================

ACTOR_CONSTRAINTS = {
    ThreatActorType.TYPE_1_LOCAL: (
        "You are constrained to TYPE_1_LOCAL (SA Local Criminal). "
        "Characteristics: fast, financially motivated, uses known SA municipal payment triggers, "
        "patience measured in hours not days, targets R5K-R500K, knows municipal payment cycles."
    ),
    ThreatActorType.TYPE_2_HACKTIVIST: (
        "You are constrained to TYPE_2_HACKTIVIST. "
        "Characteristics: medium pace (days-weeks), ideologically motivated, "
        "targets public-impact systems, may announce attacks publicly."
    ),
    ThreatActorType.TYPE_3_RANSOMWARE: (
        "You are constrained to TYPE_3_RANSOMWARE (Organised Crime). "
        "Characteristics: slow reconnaissance (weeks), multi-stage attack, "
        "lateral movement focused, targets R1M-R50M ransoms, uses RaaS kits."
    ),
    ThreatActorType.TYPE_4_APT: (
        "You are constrained to TYPE_4_APT (Nation-State). "
        "Characteristics: extremely patient (months), custom tooling, "
        "intelligence gathering focus, targets critical infrastructure."
    ),
    ThreatActorType.TYPE_5_INSIDER: (
        "You are constrained to TYPE_5_INSIDER. "
        "Characteristics: has legitimate access, no attack novelty needed, "
        "focus on privilege escalation and data staging, triggered by specific events."
    ),
}

# Evasion vectors
EVASION_VECTORS = [
    "LANGUAGE_SWITCH",
    "SEMANTIC_REPHRASE",
    "URGENCY_MUTATION",
    "TARGET_PIVOT",
    "TIMING_OBFUSCATION",
    "PAYLOAD_SHIFT",
]


# ============================================================================
# CORE RED AGENT FUNCTION
# ============================================================================

async def generate_variants(
    antibody: Antibody,
    num_variants: int = 3,
    actor_type: ThreatActorType = ThreatActorType.UNKNOWN,
    vectors_to_use: Optional[list[str]] = None,
) -> RedAgentResult:
    """
    Generate evasion variants for a given antibody.
    
    This is the main entry point for Agent 4.
    Called by the Battleground/Arena for stress testing.
    
    Args:
        antibody: The antibody to attack
        num_variants: Number of variants to generate (1-6)
        actor_type: Constrain variants to this actor profile
        vectors_to_use: Specific evasion vectors to use (default: auto-select)
    
    Returns:
        RedAgentResult with all generated variants and evasion statistics
    """
    settings = get_settings()
    start_time = time.monotonic()
    round_id = generate_id("RND")

    logger.info(
        "Red Agent: Generating variants",
        extra={
            "round_id": round_id,
            "antibody_id": antibody.antibody_id,
            "num_variants": num_variants,
            "actor_type": actor_type.value,
        },
    )

    # Check circuit breaker
    breaker = get_breaker("red_agent", failure_threshold=5, cooldown_seconds=30)
    if not breaker.allow_call():
        logger.warning("Circuit breaker OPEN for red_agent")
        return RedAgentResult(
            round_id=round_id,
            antibody_id=antibody.antibody_id,
        )

    # Select evasion vectors
    if vectors_to_use:
        selected_vectors = vectors_to_use[:num_variants]
    else:
        import random
        selected_vectors = random.sample(
            EVASION_VECTORS,
            min(num_variants, len(EVASION_VECTORS)),
        )

    variants: list[EvasionVariant] = []
    vectors_attempted: list[str] = []

    for vector in selected_vectors:
        try:
            variant = await _generate_single_variant(
                antibody=antibody,
                evasion_vector=vector,
                actor_type=actor_type,
            )
            if variant:
                variants.append(variant)
                vectors_attempted.append(vector)
                breaker.record_success()
        except Exception as e:
            logger.warning(f"Red Agent variant generation failed for {vector}: {e}")
            breaker.record_failure()

    duration_ms = (time.monotonic() - start_time) * 1000

    # Calculate evasion statistics
    evasions = sum(1 for v in variants if v.predicted_evasion_success > 0.7)

    result = RedAgentResult(
        round_id=round_id,
        antibody_id=antibody.antibody_id,
        variants=variants,
        total_variants=len(variants),
        evasions_succeeded=evasions,
        evasion_rate=evasions / len(variants) if variants else 0.0,
        vectors_attempted=vectors_attempted,
        duration_ms=duration_ms,
    )

    record_event(
        stage="red_attack",
        agent="red_agent",
        action="variants_generated",
        antibody_id=antibody.antibody_id,
        success=True,
        duration_ms=duration_ms,
        metadata={
            "round_id": round_id,
            "total_variants": len(variants),
            "evasions": evasions,
            "vectors": vectors_attempted,
        },
    )

    logger.info(
        "Red Agent: Variants generated",
        extra={
            "round_id": round_id,
            "total": len(variants),
            "evasions": evasions,
            "evasion_rate": result.evasion_rate,
            "duration_ms": round(duration_ms, 1),
        },
    )

    return result


# ============================================================================
# SINGLE VARIANT GENERATION
# ============================================================================

async def _generate_single_variant(
    antibody: Antibody,
    evasion_vector: str,
    actor_type: ThreatActorType = ThreatActorType.UNKNOWN,
) -> Optional[EvasionVariant]:
    """
    Generate a single evasion variant using a specific vector.
    
    Calls the AI model with antibody details and evasion vector,
    receives a crafted attack variant designed to evade detection.
    """
    # Build the prompt
    user_message = _build_variant_prompt(antibody, evasion_vector, actor_type)

    # Call AI
    result = await call_red_agent(
        system_prompt=SYSTEM_PROMPT,
        user_content=user_message,
        temperature=get_settings().temp_red_agent,
        max_tokens=2000,
    )

    if not result["success"]:
        logger.warning(
            f"Red Agent AI call failed for vector {evasion_vector}",
            extra={"error": result.get("error", "")[:100]},
        )
        return None

    # Parse response
    parsed = _parse_variant_response(result["content"], antibody, evasion_vector, actor_type)
    return parsed


def _build_variant_prompt(
    antibody: Antibody,
    evasion_vector: str,
    actor_type: ThreatActorType,
) -> str:
    """Build the user message for variant generation."""
    parts = [
        f"Generate ONE evasion variant using vector: {evasion_vector}",
        "",
        "TARGET ANTIBODY:",
        f"  ID: {antibody.antibody_id}",
        f"  Attack family: {antibody.attack_family}",
        f"  Detection signals: {json.dumps(antibody.detection_signals)}",
        f"  Signal descriptions: {json.dumps(antibody.detection_signals_description[:5])}",
        f"  Cross-lingual pattern: {antibody.cross_lingual_pattern}",
        f"  Language variants tested: {[l.value for l in antibody.language_variants]}",
        f"  False positive guards: {json.dumps(antibody.false_positive_guards[:3])}",
        f"  Confidence threshold: {antibody.confidence_threshold}",
        "",
        f"EVASION VECTOR: {evasion_vector}",
        f"Your goal: craft an attack that preserves the malicious INTENT of the original",
        f"attack family ({antibody.attack_family}) but evades the detection signals listed above.",
        "",
    ]

    # Add actor type constraint
    if actor_type != ThreatActorType.UNKNOWN and actor_type in ACTOR_CONSTRAINTS:
        parts.append(f"ACTOR CONSTRAINT: {ACTOR_CONSTRAINTS[actor_type]}")
        parts.append("")

    parts.append("Output ONLY as JSON object. No markdown, no explanation.")

    return "\n".join(parts)


def _parse_variant_response(
    content: str,
    antibody: Antibody,
    evasion_vector: str,
    actor_type: ThreatActorType,
) -> Optional[EvasionVariant]:
    """Parse the AI response into an EvasionVariant."""
    import json as json_module

    # Try to extract JSON from response
    try:
        # Direct parse
        data = json_module.loads(content.strip())
    except json_module.JSONDecodeError:
        # Try extracting from code fence
        import re
        match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", content, re.DOTALL)
        if match:
            try:
                data = json_module.loads(match.group(1).strip())
            except json_module.JSONDecodeError:
                return None
        else:
            # Try finding first JSON object
            brace_start = content.find("{")
            if brace_start == -1:
                return None
            depth = 0
            for i in range(brace_start, len(content)):
                if content[i] == "{":
                    depth += 1
                elif content[i] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            data = json_module.loads(content[brace_start:i + 1])
                            break
                        except json_module.JSONDecodeError:
                            return None
            else:
                return None

    # Validate and build variant
    synthetic_attack = str(data.get("synthetic_attack", ""))
    if not synthetic_attack or len(synthetic_attack) < 20:
        return None

    # Truncate to prevent oversized outputs
    if len(synthetic_attack) > 5000:
        synthetic_attack = synthetic_attack[:5000]

    predicted_success = data.get("predicted_evasion_success", 0.5)
    try:
        predicted_success = max(0.0, min(1.0, float(predicted_success)))
    except (TypeError, ValueError):
        predicted_success = 0.5

    return EvasionVariant(
        variant_id=generate_id("RED"),
        target_antibody_id=antibody.antibody_id,
        evasion_vector=data.get("evasion_vector", evasion_vector),
        evasion_strategy=str(data.get("evasion_strategy", ""))[:500],
        synthetic_attack=synthetic_attack,
        predicted_evasion_success=predicted_success,
        weakness_exploited=str(data.get("weakness_exploited", ""))[:500],
        actor_type_constraint=actor_type,
        generated_at=utc_now(),
    )


# Need json import at module level for _build_variant_prompt
import json
