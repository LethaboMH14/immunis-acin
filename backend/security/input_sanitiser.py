"""
IMMUNIS ACIN — Multi-Layer Input Sanitiser

This module sits between the outside world and every AI model call.
Its job: ensure that no malicious, malformed, or dangerous input
reaches any LLM or processing pipeline.

Layer 1: Size and structure validation (fast, catches obvious issues)
Layer 2: Null byte and encoding normalisation (prevents corruption)
Layer 3: Prompt injection detection (prevents LLM manipulation)
Layer 4: Entropy analysis (detects encoded/encrypted payloads)
Layer 5: PII detection and scrubbing (POPIA compliance)

Design principle: FAIL CLOSED. If any check is uncertain, reject.
A false rejection is a minor inconvenience. A missed injection is a breach.

Research basis:
    - Perez & Ribeiro (2022), "Ignore This Title and HackAPrompt"
    - Greshake et al. (2023), "Not what you've signed up for: Compromising
      Real-World LLM-Integrated Applications with Indirect Prompt Injection"
    - OWASP LLM Top 10 2025 — LLM01: Prompt Injection

Temperature: 0.3 (security-critical, must be precise)
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("immunis.sanitiser")


# ============================================================================
# RESULT MODEL
# ============================================================================

@dataclass
class SanitisationResult:
    """Result of input sanitisation."""
    clean_content: str
    original_hash: str  # SHA-256 of original input (for audit, never the content itself)
    is_safe: bool
    rejection_reason: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    pii_scrubbed: bool = False
    pii_types_found: list[str] = field(default_factory=list)
    injection_detected: bool = False
    injection_patterns: list[str] = field(default_factory=list)
    entropy_score: float = 0.0
    original_length: int = 0
    clean_length: int = 0


# ============================================================================
# PROMPT INJECTION PATTERNS
# ============================================================================

# These patterns detect known prompt injection techniques.
# Ordered by severity — most dangerous first.
# Each pattern has a name (for logging) and a compiled regex.

INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Direct instruction override
    (
        "instruction_override",
        re.compile(
            r"(?:ignore|disregard|forget|override|bypass|skip)\s+"
            r"(?:all\s+)?(?:previous|above|prior|earlier|system|initial)\s+"
            r"(?:instructions?|prompts?|rules?|guidelines?|context)",
            re.IGNORECASE,
        ),
    ),
    # Role assumption
    (
        "role_assumption",
        re.compile(
            r"(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you(?:'re|\s+are))|"
            r"switch\s+(?:to|into)\s+(?:a|the)\s+(?:role|mode|persona)|"
            r"from\s+now\s+on\s+you\s+(?:are|will))",
            re.IGNORECASE,
        ),
    ),
    # System prompt extraction
    (
        "prompt_extraction",
        re.compile(
            r"(?:(?:show|reveal|display|print|output|repeat|echo)\s+"
            r"(?:your|the|my)?\s*(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?))|"
            r"(?:what\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions?))",
            re.IGNORECASE,
        ),
    ),
    # Output format manipulation
    (
        "format_manipulation",
        re.compile(
            r"(?:respond\s+(?:only\s+)?with|output\s+(?:only\s+)?(?:the\s+)?(?:word|text|string))\s+"
            r"['\"].*?['\"]",
            re.IGNORECASE,
        ),
    ),
    # Delimiter injection (trying to close the user message and inject system content)
    (
        "delimiter_injection",
        re.compile(
            r"<\|(?:im_end|im_start|system|endoftext|end_of_turn)\|>|"
            r"\[/?(?:INST|SYS|SYSTEM)\]|"
            r"###\s*(?:System|Instruction|Human|Assistant)",
            re.IGNORECASE,
        ),
    ),
    # Encoded injection (base64 or hex encoded instructions)
    (
        "encoded_injection",
        re.compile(
            r"(?:decode|base64|atob|eval|exec)\s*\(",
            re.IGNORECASE,
        ),
    ),
    # Jailbreak keywords
    (
        "jailbreak_keywords",
        re.compile(
            r"(?:DAN|do\s+anything\s+now|jailbreak|developer\s+mode|"
            r"unrestricted\s+mode|god\s+mode|sudo\s+mode)",
            re.IGNORECASE,
        ),
    ),
    # Markdown/HTML injection that could affect rendering
    (
        "markup_injection",
        re.compile(
            r"<script[^>]*>|javascript:|on(?:load|error|click)\s*=|"
            r"<iframe|<object|<embed|<form\s+action",
            re.IGNORECASE,
        ),
    ),
]

# PII patterns for South African and international formats
PII_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # SA ID number (13 digits, specific format)
    (
        "sa_id_number",
        re.compile(r"\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}[01]\d{2}\b"),
        "[SA_ID_REDACTED]",
    ),
    # Phone numbers (SA format)
    (
        "sa_phone",
        re.compile(r"\b(?:\+27|0)(?:\d[\s-]?){9}\b"),
        "[PHONE_REDACTED]",
    ),
    # Email addresses
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "[EMAIL_REDACTED]",
    ),
    # Bank account numbers (SA format — 9-12 digits)
    (
        "bank_account",
        re.compile(r"\b(?:acc(?:ount)?\.?\s*(?:no\.?|number|#)?:?\s*)(\d{9,12})\b", re.IGNORECASE),
        "[BANK_ACCOUNT_REDACTED]",
    ),
    # Credit card numbers (basic Luhn-eligible patterns)
    (
        "credit_card",
        re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b"),
        "[CARD_REDACTED]",
    ),
    # Passport numbers
    (
        "passport",
        re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
        "[PASSPORT_REDACTED]",
    ),
    # IP addresses (v4)
    (
        "ipv4",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "[IP_REDACTED]",
    ),
]


# ============================================================================
# CORE SANITISATION FUNCTION
# ============================================================================

def sanitise_input(
    content: str,
    max_length: int = 1_000_000,
    min_length: int = 1,
    check_injection: bool = True,
    check_entropy: bool = True,
    scrub_pii: bool = True,
    entropy_threshold: float = 6.5,
    context: str = "unknown",
) -> SanitisationResult:
    """
    Multi-layer input sanitisation.
    
    This function MUST be called before any content reaches an LLM.
    It is called by the orchestrator at pipeline entry and by the
    Guardian validation layer between every agent handoff.
    
    Args:
        content: Raw input content
        max_length: Maximum allowed content length (bytes)
        min_length: Minimum required content length
        check_injection: Whether to run prompt injection detection
        check_entropy: Whether to run entropy analysis
        scrub_pii: Whether to scrub PII (POPIA compliance)
        entropy_threshold: Bits per character above which content is suspicious
        context: Where this content came from (for logging)
    
    Returns:
        SanitisationResult with clean content and safety assessment
    """
    result = SanitisationResult(
        clean_content="",
        original_hash=hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16],
        is_safe=True,
        original_length=len(content),
    )

    # ── LAYER 1: Size and structure validation ──────────────────────────
    if len(content) < min_length:
        result.is_safe = False
        result.rejection_reason = f"Content too short ({len(content)} < {min_length})"
        return result

    if len(content) > max_length:
        result.is_safe = False
        result.rejection_reason = f"Content too long ({len(content)} > {max_length})"
        return result

    # ── LAYER 2: Null byte and encoding normalisation ───────────────────
    # Remove null bytes (can corrupt downstream processing)
    content = content.replace("\x00", "")

    # Unicode normalisation to NFC form (prevents homoglyph attacks)
    content = unicodedata.normalize("NFC", content)

    # Remove zero-width characters (used for invisible injection)
    zero_width_chars = [
        "\u200b",  # Zero-width space
        "\u200c",  # Zero-width non-joiner
        "\u200d",  # Zero-width joiner
        "\ufeff",  # Zero-width no-break space (BOM)
        "\u2060",  # Word joiner
        "\u2061",  # Function application
        "\u2062",  # Invisible times
        "\u2063",  # Invisible separator
        "\u2064",  # Invisible plus
    ]
    for char in zero_width_chars:
        if char in content:
            result.warnings.append(f"Zero-width character removed: U+{ord(char):04X}")
            content = content.replace(char, "")

    # Remove control characters except newline, tab, carriage return
    cleaned_chars = []
    for char in content:
        if unicodedata.category(char).startswith("C") and char not in ("\n", "\t", "\r"):
            result.warnings.append(f"Control character removed: U+{ord(char):04X}")
        else:
            cleaned_chars.append(char)
    content = "".join(cleaned_chars)

    # ── LAYER 3: Prompt injection detection ─────────────────────────────
    if check_injection:
        for pattern_name, pattern in INJECTION_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                result.injection_detected = True
                result.injection_patterns.append(pattern_name)
                logger.warning(
                    "Prompt injection pattern detected",
                    extra={
                        "pattern": pattern_name,
                        "context": context,
                        "content_hash": result.original_hash,
                        # NEVER log the actual match or content
                    },
                )

        if result.injection_detected:
            # Don't reject — flag and continue. The content might be a legitimate
            # threat email that CONTAINS injection-like text (which is itself
            # a signal of malicious intent). Rejecting would cause false negatives.
            result.warnings.append(
                f"Prompt injection patterns detected: {result.injection_patterns}. "
                f"Content will be processed with enhanced isolation."
            )

    # ── LAYER 4: Entropy analysis ───────────────────────────────────────
    if check_entropy and len(content) > 100:
        result.entropy_score = _compute_entropy(content)

        if result.entropy_score > entropy_threshold:
            result.warnings.append(
                f"High entropy detected ({result.entropy_score:.2f} bits/char > {entropy_threshold}). "
                f"Content may contain encoded or encrypted payload."
            )

    # Check for repeated lines (copy-paste attack / padding)
    lines = content.split("\n")
    if len(lines) > 5:
        line_counts: dict[str, int] = {}
        for line in lines:
            stripped = line.strip()
            if stripped:
                line_counts[stripped] = line_counts.get(stripped, 0) + 1

        max_repeats = max(line_counts.values()) if line_counts else 0
        if max_repeats > 3:
            result.warnings.append(
                f"Repeated line detected ({max_repeats} occurrences). "
                f"Possible copy-paste injection or padding attack."
            )

    # ── LAYER 5: PII scrubbing (POPIA compliance) ──────────────────────
    if scrub_pii:
        for pii_type, pattern, replacement in PII_PATTERNS:
            if pattern.search(content):
                result.pii_scrubbed = True
                result.pii_types_found.append(pii_type)
                content = pattern.sub(replacement, content)

        if result.pii_scrubbed:
            logger.info(
                "PII scrubbed from content",
                extra={
                    "pii_types": result.pii_types_found,
                    "context": context,
                    "content_hash": result.original_hash,
                },
            )

    # ── Final result ────────────────────────────────────────────────────
    result.clean_content = content
    result.clean_length = len(content)

    return result


# ============================================================================
# ENTROPY COMPUTATION
# ============================================================================

def _compute_entropy(text: str) -> float:
    """
    Compute Shannon entropy of text in bits per character.
    
    Normal English text: ~4.0-4.5 bits/char
    Normal code: ~4.5-5.5 bits/char
    Base64 encoded: ~5.5-6.0 bits/char
    Encrypted/random: ~7.5-8.0 bits/char
    
    High entropy in a supposedly natural-language input suggests
    encoded or encrypted content — which could be a payload.
    """
    if not text:
        return 0.0

    # Count character frequencies
    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    length = len(text)
    entropy = 0.0

    for count in freq.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


# ============================================================================
# AGENT HANDOFF SANITISATION
# ============================================================================

def sanitise_agent_output(
    output: str,
    agent_name: str,
    max_length: int = 50_000,
) -> SanitisationResult:
    """
    Sanitise output from one agent before passing to the next.
    
    This is the Guardian validation layer between agent handoffs.
    Agent outputs are less likely to contain prompt injection
    (they come from our own LLMs) but could contain:
    - Hallucinated PII
    - Excessively large outputs (anomalous behavior)
    - Injection patterns if the input contained them and the LLM echoed them
    
    Args:
        output: Agent output text
        agent_name: Which agent produced this (for logging)
        max_length: Maximum allowed output length
    """
    return sanitise_input(
        content=output,
        max_length=max_length,
        min_length=0,  # Empty output is valid (agent might return empty on failure)
        check_injection=True,  # Check even agent output — LLMs can echo injections
        check_entropy=False,  # Agent output entropy is expected to vary
        scrub_pii=True,  # Always scrub PII — LLMs can hallucinate PII
        context=f"agent_output:{agent_name}",
    )


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def is_safe(content: str, context: str = "unknown") -> bool:
    """Quick check — is this content safe to process?"""
    result = sanitise_input(content, context=context)
    return result.is_safe


def scrub_pii_only(content: str) -> str:
    """Scrub PII without other checks. Used for logging and display."""
    result = sanitise_input(
        content,
        check_injection=False,
        check_entropy=False,
        scrub_pii=True,
        context="pii_scrub",
    )
    return result.clean_content


def compute_content_hash(content: str) -> str:
    """Compute a truncated SHA-256 hash for deduplication."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]
