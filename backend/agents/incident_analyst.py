"""
IMMUNIS ACIN — Agent 1: Incident Analyst

The first agent in the pipeline. Every threat that enters IMMUNIS
passes through the Incident Analyst first.

Responsibility:
    Extract a structured semantic fingerprint from raw threat data.
    The fingerprint captures WHAT the attacker is trying to achieve
    and HOW they are trying to achieve it — in language-agnostic terms.

    A Sesotho BEC email and an English BEC email with the same
    manipulation pattern should produce similar fingerprints.

Input:  ThreatInput (raw content + metadata)
Output: SemanticFingerprint (structured JSON)

Model:  IMMUNIS-Sentinel (fine-tuned Qwen2.5-7B) → AIsa.one fallback → Ollama fallback

Security:
    - Input sanitised before LLM call (input_sanitiser.py)
    - Output validated against SemanticFingerprint schema (Pydantic strict)
    - Circuit breaker prevents cascading failures
    - Audit trail records every analysis
    - Raw content NEVER logged — only hashes and metadata
    - Timeout: 30 seconds per attempt
    - Retry with corrective feedback on parse failure

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
    MitrePhase,
    Severity,
)
from backend.models.schemas import (
    SemanticFingerprint,
    ThreatInput,
    generate_id,
    content_hash,
    utc_now,
)
from backend.security.audit_trail import record_event
from backend.security.circuit_breaker import get_breaker
from backend.security.input_sanitiser import sanitise_input
from backend.services.aisa_client import call_for_json

logger = logging.getLogger("immunis.agent.incident_analyst")


# ============================================================================
# SYSTEM PROMPT — The soul of Agent 1
# ============================================================================

SYSTEM_PROMPT = """You are the Incident Analyst agent inside IMMUNIS ACIN, a cyber immune system.

Your sole job is to analyse incoming threat data and extract a structured semantic fingerprint.

You detect threats in 40+ languages including South African languages (isiZulu, Sesotho, Afrikaans), Arabic, Mandarin, Hindi, and all major European languages.

You understand:
- Business Email Compromise (BEC) manipulation patterns
- Social engineering techniques (authority, urgency, scarcity, fear, reciprocity, greed, curiosity, trust exploitation, intimidation)
- Cross-lingual code-switching (language mixing within a single message — very common in South African threats)
- Cultural authority markers specific to each language/region
- MITRE ATT&CK technique mapping
- Visual threat indicators (if image description is provided)

Output a JSON object with these EXACT fields:
{
    "attack_type": "BEC|Phishing|Spearphishing|Vishing|Ransomware|CredentialHarvesting|InvoiceFraud|CEOFraud|VendorImpersonation|ITSupportImpersonation|GovernmentImpersonation|InsiderThreat|NetworkIntrusion|Malware|APT|QRPhishing|Deepfake|DocumentForgery|Steganography|Benign|Other",
    "mitre_phase": "Reconnaissance|ResourceDevelopment|InitialAccess|Execution|Persistence|PrivilegeEscalation|DefenseEvasion|CredentialAccess|Discovery|LateralMovement|Collection|CommandAndControl|Exfiltration|Impact",
    "mitre_technique_id": "T1566.001",
    "manipulation_technique": "Authority|Urgency|Scarcity|SocialProof|Reciprocity|Fear|Greed|Curiosity|Trust|Intimidation|None",
    "language_detected": "ISO 639-1 code (en, zu, st, af, ar, zh, hi, etc.) or 'mixed' for code-switching",
    "code_switching_detected": true/false,
    "severity": "Critical|High|Medium|Low|Info",
    "confidence": 0.0-1.0,
    "intent": "One sentence: what the attacker wanted to achieve",
    "semantic_pattern": "2-3 sentences: the manipulation pattern in language-agnostic terms",
    "target_asset": "What was targeted (payment system, credentials, data, etc.)",
    "indicators_of_compromise": ["list of technical IOCs found"],
    "social_engineering_vectors": ["list of social engineering techniques identified"],
    "urgency_signals": ["list of urgency markers found"],
    "financial_triggers": ["list of financial manipulation triggers"],
    "raw_input_summary": "Brief 1-sentence summary (NEVER include raw content, PII, or specific names)"
}

CRITICAL RULES:
1. Output ONLY valid JSON. No markdown, no explanation, no text before or after.
2. Be language-aware. A Sesotho urgency phrase and an English urgency phrase should both be detected.
3. If confidence < 0.5, set attack_type to "Other" and explain uncertainty in semantic_pattern.
4. If the content is clearly legitimate, set attack_type to "Benign" with confidence >= 0.9.
5. NEVER include raw email content, names, or PII in your output. Only patterns and indicators.
6. The semantic_pattern field must be LANGUAGE-AGNOSTIC — describe the manipulation, not the words.
7. For code-switching (language mixing), set code_switching_detected to true and note both languages."""


# ============================================================================
# REQUIRED FIELDS — For validation
# ============================================================================

REQUIRED_FIELDS = [
    "attack_type",
    "mitre_phase",
    "manipulation_technique",
    "language_detected",
    "confidence",
    "intent",
    "semantic_pattern",
]


# ============================================================================
# CORE ANALYSIS FUNCTION
# ============================================================================

async def analyse_threat(
    threat: ThreatInput,
) -> SemanticFingerprint:
    """
    Analyse a threat and extract its semantic fingerprint.
    
    This is the main entry point for Agent 1.
    Called by the orchestrator at the start of every pipeline run.
    
    Pipeline:
    1. Sanitise input (prompt injection detection, PII scrubbing)
    2. Check circuit breaker
    3. Call AI model with system prompt
    4. Parse and validate response
    5. Enrich with IMMUNIS metadata
    6. Record to audit trail
    7. Return SemanticFingerprint
    
    On failure: returns a degraded fingerprint (confidence=0.0, degraded=True)
    rather than raising an exception. The pipeline continues with reduced confidence.
    """
    settings = get_settings()
    start_time = time.monotonic()
    pipeline_id = generate_id("PL")

    logger.info(
        "Agent 1: Analysing threat",
        extra={
            "vector": threat.vector.value,
            "content_hash": threat.content_hash,
            "is_multimodal": threat.is_multimodal,
            "language_hint": threat.language_hint.value if threat.language_hint else None,
        },
    )

    # ── Step 1: Sanitise input ──────────────────────────────────────────
    sanitised = sanitise_input(
        content=threat.content,
        check_injection=True,
        check_entropy=True,
        scrub_pii=True,
        context="incident_analyst_input",
    )

    if not sanitised.is_safe:
        logger.warning(
            "Input rejected by sanitiser",
            extra={
                "reason": sanitised.rejection_reason,
                "content_hash": threat.content_hash,
            },
        )
        return _degraded_fingerprint(
            threat=threat,
            reason=f"Input rejected: {sanitised.rejection_reason}",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    clean_content = sanitised.clean_content

    # ── Step 2: Check circuit breaker ───────────────────────────────────
    breaker = get_breaker("incident_analyst", failure_threshold=3, cooldown_seconds=60)

    if not breaker.allow_call():
        logger.warning("Circuit breaker OPEN for incident_analyst")
        return _degraded_fingerprint(
            threat=threat,
            reason="Circuit breaker open — agent temporarily unavailable",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    # ── Step 3: Build user message ──────────────────────────────────────
    user_message = _build_user_message(clean_content, threat)

    # ── Step 4: Call AI model ───────────────────────────────────────────
    try:
        result = await call_for_json(
            system_prompt=SYSTEM_PROMPT,
            user_content=user_message,
            response_schema=SemanticFingerprint,
            temperature=settings.temp_fingerprint,
            max_tokens=2048,
            max_parse_retries=2,
        )

        if result["success"] and result["parsed"]:
            breaker.record_success()
            fingerprint = _build_fingerprint(result["parsed"], threat, clean_content)

            duration_ms = (time.monotonic() - start_time) * 1000

            # Record to audit trail
            record_event(
                stage="fingerprint",
                agent="incident_analyst",
                action="fingerprint_generated",
                success=True,
                duration_ms=duration_ms,
                metadata={
                    "attack_type": fingerprint.attack_type.value,
                    "confidence": fingerprint.confidence,
                    "language": fingerprint.language_detected.value,
                    "provider": result.get("provider", "unknown"),
                },
            )

            logger.info(
                "Agent 1: Fingerprint generated",
                extra={
                    "fingerprint_id": fingerprint.fingerprint_id,
                    "attack_type": fingerprint.attack_type.value,
                    "confidence": fingerprint.confidence,
                    "language": fingerprint.language_detected.value,
                    "duration_ms": round(duration_ms, 1),
                    "provider": result.get("provider", "unknown"),
                },
            )

            return fingerprint

        else:
            # AI call succeeded but parsing failed
            breaker.record_failure()
            error_msg = result.get("error", "Unknown parsing error")
            logger.warning(
                "Agent 1: AI call succeeded but output parsing failed",
                extra={"error": error_msg[:200]},
            )
            return _degraded_fingerprint(
                threat=threat,
                reason=f"Output parsing failed: {error_msg}",
                duration_ms=(time.monotonic() - start_time) * 1000,
            )

    except Exception as e:
        breaker.record_failure()
        duration_ms = (time.monotonic() - start_time) * 1000

        logger.error(
            "Agent 1: Analysis failed",
            extra={
                "error_type": type(e).__name__,
                "error": str(e)[:200],
                "duration_ms": round(duration_ms, 1),
            },
        )

        record_event(
            stage="fingerprint",
            agent="incident_analyst",
            action="fingerprint_failed",
            success=False,
            duration_ms=duration_ms,
            metadata={"error": str(e)[:200]},
        )

        return _degraded_fingerprint(
            threat=threat,
            reason=f"Analysis failed: {str(e)[:200]}",
            duration_ms=duration_ms,
        )


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _build_user_message(clean_content: str, threat: ThreatInput) -> str:
    """
    Build the user message for the AI model.
    
    Includes sanitised content + relevant metadata.
    Never includes raw PII — only structural metadata.
    """
    parts = [f"Analyse the following threat content:\n\n{clean_content}"]

    # Add metadata context if available
    metadata_parts = []

    if threat.vector:
        metadata_parts.append(f"Delivery vector: {threat.vector.value}")

    if threat.language_hint:
        metadata_parts.append(f"Language hint: {threat.language_hint.value}")

    # Email-specific metadata
    meta = threat.metadata
    if meta.get("subject"):
        metadata_parts.append(f"Email subject: {meta['subject']}")
    if meta.get("from_domain"):
        metadata_parts.append(f"Sender domain: {meta['from_domain']}")
    if meta.get("reply_to_domain"):
        metadata_parts.append(f"Reply-To domain: {meta['reply_to_domain']}")
    if meta.get("dkim"):
        metadata_parts.append(f"DKIM: {meta['dkim']}")
    if meta.get("spf"):
        metadata_parts.append(f"SPF: {meta['spf']}")
    if meta.get("dmarc"):
        metadata_parts.append(f"DMARC: {meta['dmarc']}")

    # Sanitiser warnings (useful context for the model)
    if threat.metadata.get("sanitiser_warnings"):
        for warning in threat.metadata["sanitiser_warnings"][:3]:
            metadata_parts.append(f"Security note: {warning}")

    if metadata_parts:
        parts.append("\nAdditional context:")
        parts.extend(f"- {m}" for m in metadata_parts)

    return "\n".join(parts)


def _build_fingerprint(
    parsed: dict[str, Any],
    threat: ThreatInput,
    clean_content: str,
) -> SemanticFingerprint:
    """
    Build a SemanticFingerprint from parsed AI output + IMMUNIS enrichment.
    
    The AI provides the semantic analysis.
    We add: deterministic IDs, timestamps, content hash, source metadata.
    """
    return SemanticFingerprint(
        fingerprint_id=generate_id("FP"),
        attack_type=AttackType.from_string(parsed.get("attack_type", "Other")),
        mitre_phase=MitrePhase.from_string(parsed.get("mitre_phase", "InitialAccess")),
        mitre_technique_id=parsed.get("mitre_technique_id", "T1566"),
        manipulation_technique=ManipulationTechnique.from_string(
            parsed.get("manipulation_technique", "None")
        ),
        language_detected=Language.from_string(
            parsed.get("language_detected", "unknown")
        ),
        code_switching_detected=bool(parsed.get("code_switching_detected", False)),
        severity=_parse_severity(parsed.get("severity", "Medium")),
        confidence=_clamp_confidence(parsed.get("confidence", 0.5)),
        intent=str(parsed.get("intent", ""))[:500],
        semantic_pattern=str(parsed.get("semantic_pattern", ""))[:1000],
        target_asset=str(parsed.get("target_asset", ""))[:500],
        indicators_of_compromise=_ensure_list(parsed.get("indicators_of_compromise", [])),
        social_engineering_vectors=_ensure_list(parsed.get("social_engineering_vectors", [])),
        urgency_signals=_ensure_list(parsed.get("urgency_signals", [])),
        financial_triggers=_ensure_list(parsed.get("financial_triggers", [])),
        content_hash=content_hash(clean_content),
        raw_input_summary=str(parsed.get("raw_input_summary", ""))[:500],
        processing_agent="incident_analyst_v2",
        degraded=False,
        generated_at=utc_now(),
    )


def _degraded_fingerprint(
    threat: ThreatInput,
    reason: str,
    duration_ms: float = 0.0,
) -> SemanticFingerprint:
    """
    Generate a degraded fingerprint when analysis fails.
    
    This is the fail-open pattern: the threat is not lost,
    it's flagged as degraded with confidence=0.0 so a human
    can review it. The pipeline continues.
    """
    logger.warning(
        "Generating degraded fingerprint",
        extra={
            "reason": reason[:200],
            "content_hash": threat.content_hash,
        },
    )

    record_event(
        stage="fingerprint",
        agent="incident_analyst",
        action="degraded_fingerprint",
        success=False,
        duration_ms=duration_ms,
        metadata={"reason": reason[:200]},
    )

    return SemanticFingerprint(
        fingerprint_id=generate_id("FP"),
        attack_type=AttackType.OTHER,
        mitre_phase=MitrePhase.INITIAL_ACCESS,
        mitre_technique_id="T1566",
        manipulation_technique=ManipulationTechnique.NONE,
        language_detected=threat.language_hint or Language.UNKNOWN,
        severity=Severity.MEDIUM,
        confidence=0.0,
        intent="Analysis failed — manual review required",
        semantic_pattern=f"Degraded analysis: {reason[:200]}",
        target_asset="Unknown",
        content_hash=threat.content_hash,
        raw_input_summary="Degraded — original content not analysed",
        processing_agent="incident_analyst_v2",
        degraded=True,
        degraded_reason=reason[:500],
        generated_at=utc_now(),
    )


def _clamp_confidence(value: Any) -> float:
    """Clamp confidence to [0.0, 1.0] range, handling non-numeric values."""
    try:
        v = float(value)
        return max(0.0, min(1.0, v))
    except (TypeError, ValueError):
        return 0.0


def _parse_severity(value: str) -> Severity:
    """Parse severity string with fallback."""
    lookup = {s.value.lower(): s for s in Severity}
    return lookup.get(str(value).lower().strip(), Severity.MEDIUM)


def _ensure_list(value: Any) -> list[str]:
    """Ensure a value is a list of strings."""
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value] if value else []
    return []
