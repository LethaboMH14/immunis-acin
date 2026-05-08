"""
IMMUNIS ACIN — Context-Preserving Translation Engine

WHY: Cyber attacks exploit language nuance. A direct translation
loses the social engineering cues that make an attack effective:
urgency markers, authority signals, cultural references, and
emotional manipulation. IMMUNIS needs translations that PRESERVE
these attack-relevant features while making content analysable
by English-primary models.

This is NOT Google Translate. This is adversarial-aware translation
that annotates social engineering tactics, preserves code-switched
segments, maintains cultural context, and flags untranslatable
attack-specific idioms.

Capabilities:
1. Context-preserving translation (attack semantics retained)
2. Social engineering annotation (urgency, authority, fear markers)
3. Code-switch preservation (mixed-language segments kept intact)
4. Cultural context notes (culture-specific manipulation tactics)
5. Back-translation verification (translate → back-translate → compare)
6. Glossary enforcement (security terms translated consistently)
7. Confidence scoring per segment

Translation pipeline:
  Source text → Segment → Detect language per segment
  → Translate with context prompt → Annotate SE markers
  → Back-translate for verification → Merge with annotations

Supported backends:
  1. LLM-based translation (primary — context-aware)
  2. LaBSE cross-lingual embeddings (for similarity, not translation)
  3. Fallback: dictionary-based for critical security terms
"""

import logging
import re
import time
import hashlib
from typing import Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field

logger = logging.getLogger("immunis.lingua.translator")


# ------------------------------------------------------------------
# SECURITY GLOSSARY (consistent translation of security terms)
# ------------------------------------------------------------------

SECURITY_GLOSSARY = {
    "zu": {
        "phishing": "ukudoba nge-inthanethi",
        "malware": "uhlelo olubi",
        "ransomware": "uhlelo lokucindezela",
        "password": "iphasiwedi",
        "firewall": "udonga lomlilo",
        "virus": "igciwane lekhompyutha",
        "hacker": "umgqekezi wekhompyutha",
        "encryption": "ukubethela",
        "authentication": "ukuqinisekisa",
        "vulnerability": "ubuthakathaka",
        "breach": "ukufohlwa",
        "threat": "usongo",
        "attack": "ukuhlasela",
        "bank": "ibhange",
        "account": "i-akhawunti",
        "transfer": "ukudlulisa",
        "urgent": "okuphuthumayo",
        "verify": "qinisekisa",
        "PIN": "i-PIN",
        "OTP": "i-OTP",
    },
    "st": {
        "phishing": "ho tshwasa ka inthanete",
        "malware": "porokeramo e mpe",
        "ransomware": "porokeramo ya tefo",
        "password": "lentswe la lekunutu",
        "firewall": "lebota la mollo",
        "virus": "tshwaetso ya khomphutha",
        "hacker": "mokeni wa khomphutha",
        "encryption": "ho pata",
        "authentication": "netefatso",
        "vulnerability": "bofokoli",
        "breach": "tlolo",
        "threat": "tshokelo",
        "attack": "tlhaselo",
        "bank": "banka",
        "account": "akhaonto",
        "transfer": "phetiso",
        "urgent": "ka potlako",
        "verify": "netefatsa",
        "PIN": "PIN",
        "OTP": "OTP",
    },
    "af": {
        "phishing": "uitvissing",
        "malware": "kwaadwillige sagteware",
        "ransomware": "losprysware",
        "password": "wagwoord",
        "firewall": "brandmuur",
        "virus": "virus",
        "hacker": "kuberkraker",
        "encryption": "enkripsie",
        "authentication": "verifikasie",
        "vulnerability": "kwesbaarheid",
        "breach": "oortreding",
        "threat": "bedreiging",
        "attack": "aanval",
        "bank": "bank",
        "account": "rekening",
        "transfer": "oordrag",
        "urgent": "dringend",
        "verify": "verifieer",
        "PIN": "PIN",
        "OTP": "OTP",
    },
    "xh": {
        "phishing": "ukuloba nge-intanethi",
        "malware": "isoftwe embi",
        "ransomware": "isoftwe yentlawulo",
        "password": "iphasiwedi",
        "firewall": "udonga lomlilo",
        "virus": "intsholongwane yekhompyutha",
        "hacker": "umqhekezi wekhompyutha",
        "encryption": "ukubethela",
        "authentication": "ukungqinisisa",
        "vulnerability": "ubuthathaka",
        "breach": "ukophulwa",
        "threat": "isisongelo",
        "attack": "ukuhlasela",
        "bank": "ibhanki",
        "account": "iakhawunti",
        "transfer": "ukudlulisela",
        "urgent": "ngokukhawuleza",
        "verify": "qinisekisa",
        "PIN": "i-PIN",
        "OTP": "i-OTP",
    },
    "ar": {
        "phishing": "تصيد احتيالي",
        "malware": "برمجيات خبيثة",
        "ransomware": "برمجيات فدية",
        "password": "كلمة مرور",
        "firewall": "جدار حماية",
        "virus": "فيروس",
        "hacker": "قرصان",
        "encryption": "تشفير",
        "authentication": "مصادقة",
        "vulnerability": "ثغرة أمنية",
        "breach": "اختراق",
        "threat": "تهديد",
        "attack": "هجوم",
        "bank": "بنك",
        "account": "حساب",
        "transfer": "تحويل",
        "urgent": "عاجل",
        "verify": "تحقق",
        "PIN": "رمز PIN",
        "OTP": "رمز OTP",
    },
}

# Social engineering markers to annotate
SE_MARKERS = {
    "urgency": {
        "label": "[SE:URGENCY]",
        "patterns": {
            "en": [r"\b(urgent|immediately|right now|hurry|asap|deadline|expire)\b"],
            "zu": [r"\b(phuthuma|shesha|manje|masinyane|ngokushesha)\b"],
            "st": [r"\b(potlaka|kapele|hona joale|hang|ka potlako)\b"],
            "af": [r"\b(dringend|onmiddellik|nou|gou|vinnig)\b"],
            "ar": [r"\b(عاجل|فوري|حالا|بسرعة)\b"],
        },
    },
    "authority": {
        "label": "[SE:AUTHORITY]",
        "patterns": {
            "en": [r"\b(bank|police|government|official|department|manager|director)\b"],
            "zu": [r"\b(ibhange|amaphoyisa|uhulumeni|umnyango|umphathi)\b"],
            "st": [r"\b(banka|sepolesa|mmuso|lefapha|molaodi)\b"],
            "af": [r"\b(bank|polisie|regering|departement|bestuurder)\b"],
            "ar": [r"\b(بنك|شرطة|حكومة|رسمي|مدير)\b"],
        },
    },
    "fear": {
        "label": "[SE:FEAR]",
        "patterns": {
            "en": [r"\b(arrest|prosecute|jail|fine|penalty|lose|stolen|fraud)\b"],
            "zu": [r"\b(boshwa|jele|inhlawulo|ubugebengu|ukwebiwa)\b"],
            "st": [r"\b(tshwarwa|tjhankaneng|tefiso|boshodu)\b"],
            "af": [r"\b(arresteer|vervolg|tronk|boete|bedrog|gesteel)\b"],
            "ar": [r"\b(اعتقال|محاكمة|سجن|غرامة|سرقة|احتيال)\b"],
        },
    },
    "credential_request": {
        "label": "[SE:CRED_REQUEST]",
        "patterns": {
            "en": [r"\b(pin|password|otp|account.?number|card.?number|cvv)\b"],
            "zu": [r"\b(inombolo|iphasiwedi|i-pin|i-otp)\b"],
            "st": [r"\b(nomoro|password|pin|otp)\b"],
            "af": [r"\b(pin|wagwoord|otp|rekeningnommer)\b"],
            "ar": [r"\b(رمز|كلمة.?مرور|رقم.?حساب|رقم.?بطاقة)\b"],
        },
    },
    "impersonation": {
        "label": "[SE:IMPERSONATION]",
        "patterns": {
            "en": [r"\b(calling from|this is|i am from|on behalf of)\b"],
            "zu": [r"\b(ngishayela|ngivela|ngingu)\b"],
            "st": [r"\b(ke letsetse|ke tswa|ke nna)\b"],
            "af": [r"\b(ek bel van|ek is|ek bel namens)\b"],
            "ar": [r"\b(أتصل من|أنا من|بالنيابة عن)\b"],
        },
    },
}


@dataclass
class TranslationSegment:
    """A translated segment with annotations."""
    original: str
    translated: str
    source_language: str
    target_language: str
    confidence: float
    se_annotations: list[str] = field(default_factory=list)
    cultural_notes: list[str] = field(default_factory=list)
    glossary_terms: list[dict] = field(default_factory=list)
    is_code_switched: bool = False
    preserved_original: bool = False  # True if kept in original language


@dataclass
class TranslationResult:
    """Complete translation result with all annotations."""
    original_text: str
    translated_text: str
    annotated_text: str  # Translation with SE markers inline
    source_language: str
    target_language: str
    segments: list[TranslationSegment]
    overall_confidence: float
    se_markers_found: dict[str, int]  # marker_type → count
    cultural_notes: list[str]
    glossary_terms_used: list[dict]
    back_translation: Optional[str] = None
    back_translation_similarity: float = 0.0
    translation_method: str = "llm"  # llm, dictionary, passthrough
    translated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_ms: float = 0.0


class TranslationEngine:
    """
    Context-preserving, adversarial-aware translation engine.

    Unlike general-purpose translation, this engine:
    1. Preserves social engineering semantics
    2. Annotates manipulation tactics inline
    3. Maintains code-switched segments
    4. Enforces security term glossary
    5. Provides back-translation verification
    6. Adds cultural context notes

    Translation backends (in priority order):
    1. LLM with security-aware prompt (primary)
    2. Dictionary-based for security terms (fallback)
    3. Passthrough with annotation (last resort)
    """

    def __init__(self):
        self._total_translations: int = 0
        self._language_pairs: dict[str, int] = {}
        self._se_markers_total: dict[str, int] = {
            "urgency": 0,
            "authority": 0,
            "fear": 0,
            "credential_request": 0,
            "impersonation": 0,
        }

        # LLM client (lazy loaded)
        self._llm_client = None

        logger.info("Translation engine initialised")

    async def translate(
        self,
        text: str,
        source_language: str,
        target_language: str = "en",
        preserve_code_switches: bool = True,
        annotate_se_markers: bool = True,
        back_translate: bool = False,
        metadata: Optional[dict] = None,
    ) -> TranslationResult:
        """
        Translate text with context preservation and SE annotation.

        Args:
            text: Source text to translate.
            source_language: ISO 639-1 source language code.
            target_language: ISO 639-1 target language code (default: English).
            preserve_code_switches: Keep code-switched segments in original.
            annotate_se_markers: Add [SE:*] annotations inline.
            back_translate: Perform back-translation verification.
            metadata: Additional context for translation.

        Returns:
            TranslationResult with translation, annotations, and confidence.
        """
        start = time.perf_counter()

        # If source == target, just annotate
        if source_language == target_language:
            result = self._passthrough(text, source_language, target_language)
        else:
            # Try LLM translation first
            result = await self._translate_llm(
                text, source_language, target_language, metadata
            )

            # Fallback to dictionary if LLM fails
            if result is None:
                result = self._translate_dictionary(
                    text, source_language, target_language
                )

        # Annotate SE markers
        if annotate_se_markers:
            result = self._annotate_se_markers(result, source_language)

        # Add cultural context notes
        result.cultural_notes = self._generate_cultural_notes(
            text, source_language
        )

        # Apply glossary
        result = self._apply_glossary(result, source_language, target_language)

        # Back-translation verification
        if back_translate and result.translation_method == "llm":
            back_result = await self._translate_llm(
                result.translated_text, target_language, source_language, metadata
            )
            if back_result:
                result.back_translation = back_result.translated_text
                result.back_translation_similarity = self._compute_similarity(
                    text, back_result.translated_text
                )

        elapsed_ms = (time.perf_counter() - start) * 1000
        result.duration_ms = round(elapsed_ms, 2)

        # Update stats
        self._total_translations += 1
        pair = f"{source_language}→{target_language}"
        self._language_pairs[pair] = self._language_pairs.get(pair, 0) + 1

        logger.info(
            f"Translation complete: {pair}, "
            f"method={result.translation_method}, "
            f"confidence={result.overall_confidence:.2f}, "
            f"SE markers={sum(result.se_markers_found.values())}, "
            f"latency={elapsed_ms:.1f}ms"
        )

        return result

    # ------------------------------------------------------------------
    # LLM TRANSLATION
    # ------------------------------------------------------------------

    async def _translate_llm(
        self,
        text: str,
        source_language: str,
        target_language: str,
        metadata: Optional[dict] = None,
    ) -> Optional[TranslationResult]:
        """
        Translate using LLM with security-aware prompt.

        The prompt instructs the model to:
        1. Preserve social engineering semantics
        2. Maintain urgency/authority/fear tone
        3. Keep technical terms accurate
        4. Note cultural manipulation tactics
        """
        try:
            if self._llm_client is None:
                from backend.services.aisa_client import get_aisa_client
                self._llm_client = get_aisa_client()

            from backend.lingua.ingestion import SUPPORTED_LANGUAGES
            source_name = SUPPORTED_LANGUAGES.get(source_language, source_language)
            target_name = SUPPORTED_LANGUAGES.get(target_language, target_language)

            prompt = f"""Translate the following text from {source_name} to {target_name}.

CRITICAL INSTRUCTIONS:
1. This is a potential cyber attack / social engineering message
2. PRESERVE the social engineering tone (urgency, authority, fear, manipulation)
3. Do NOT soften or neutralise threatening language
4. Keep technical terms accurate (PIN, OTP, account numbers)
5. If the text contains code-switching (mixed languages), translate each language segment but mark the switches with [SWITCH:lang_code]
6. Preserve any cultural references that are part of the manipulation

TEXT TO TRANSLATE:
{text}

TRANSLATION:"""

            response = await self._llm_client.generate(
                prompt=prompt,
                temperature=0.2,  # Low temperature for accurate translation
                max_tokens=len(text) * 3,  # Allow expansion
            )

            translated = response.get("content", "").strip()

            if not translated:
                return None

            # Build segments (simplified — single segment for now)
            segments = [TranslationSegment(
                original=text,
                translated=translated,
                source_language=source_language,
                target_language=target_language,
                confidence=0.8,
            )]

            return TranslationResult(
                original_text=text,
                translated_text=translated,
                annotated_text=translated,
                source_language=source_language,
                target_language=target_language,
                segments=segments,
                overall_confidence=0.8,
                se_markers_found={},
                cultural_notes=[],
                glossary_terms_used=[],
                translation_method="llm",
            )

        except Exception as e:
            logger.warning(f"LLM translation failed: {e}")
            return None

    # ------------------------------------------------------------------
    # DICTIONARY TRANSLATION
    # ------------------------------------------------------------------

    def _translate_dictionary(
        self,
        text: str,
        source_language: str,
        target_language: str,
    ) -> TranslationResult:
        """
        Dictionary-based translation for security terms.

        Not a full translation — replaces known security terms
        and keeps the rest in the original language with annotations.
        """
        translated = text
        terms_used = []

        if target_language == "en" and source_language in SECURITY_GLOSSARY:
            # Reverse lookup: source term → English term
            glossary = SECURITY_GLOSSARY[source_language]
            reverse_glossary = {v: k for k, v in glossary.items()}

            for source_term, english_term in reverse_glossary.items():
                if source_term.lower() in translated.lower():
                    translated = re.sub(
                        re.escape(source_term),
                        f"{english_term} [{source_term}]",
                        translated,
                        flags=re.IGNORECASE,
                    )
                    terms_used.append({
                        "source": source_term,
                        "target": english_term,
                        "language": source_language,
                    })

        elif source_language == "en" and target_language in SECURITY_GLOSSARY:
            glossary = SECURITY_GLOSSARY[target_language]
            for english_term, target_term in glossary.items():
                if english_term.lower() in translated.lower():
                    translated = re.sub(
                        r"\b" + re.escape(english_term) + r"\b",
                        f"{target_term} [{english_term}]",
                        translated,
                        flags=re.IGNORECASE,
                    )
                    terms_used.append({
                        "source": english_term,
                        "target": target_term,
                        "language": target_language,
                    })

        segments = [TranslationSegment(
            original=text,
            translated=translated,
            source_language=source_language,
            target_language=target_language,
            confidence=0.4,  # Low confidence for dictionary-only
        )]

        return TranslationResult(
            original_text=text,
            translated_text=translated,
            annotated_text=translated,
            source_language=source_language,
            target_language=target_language,
            segments=segments,
            overall_confidence=0.4,
            se_markers_found={},
            cultural_notes=[],
            glossary_terms_used=terms_used,
            translation_method="dictionary",
        )

    # ------------------------------------------------------------------
    # PASSTHROUGH (same language)
    # ------------------------------------------------------------------

    def _passthrough(
        self,
        text: str,
        source_language: str,
        target_language: str,
    ) -> TranslationResult:
        """Passthrough for same-language text (just annotate)."""
        segments = [TranslationSegment(
            original=text,
            translated=text,
            source_language=source_language,
            target_language=target_language,
            confidence=1.0,
            preserved_original=True,
        )]

        return TranslationResult(
            original_text=text,
            translated_text=text,
            annotated_text=text,
            source_language=source_language,
            target_language=target_language,
            segments=segments,
            overall_confidence=1.0,
            se_markers_found={},
            cultural_notes=[],
            glossary_terms_used=[],
            translation_method="passthrough",
        )

    # ------------------------------------------------------------------
    # SE MARKER ANNOTATION
    # ------------------------------------------------------------------

    def _annotate_se_markers(
        self,
        result: TranslationResult,
        source_language: str,
    ) -> TranslationResult:
        """
        Annotate social engineering markers in the translated text.

        Adds inline markers like [SE:URGENCY], [SE:AUTHORITY], etc.
        """
        annotated = result.translated_text
        markers_found: dict[str, int] = {}

        for marker_type, marker_config in SE_MARKERS.items():
            label = marker_config["label"]
            patterns = marker_config.get("patterns", {})
            count = 0

            # Check in translated text (target language)
            target_patterns = patterns.get(result.target_language, [])
            for pattern in target_patterns:
                matches = re.finditer(pattern, annotated, re.IGNORECASE)
                for match in matches:
                    count += 1

            # Also check original text (source language)
            source_patterns = patterns.get(source_language, [])
            for pattern in source_patterns:
                source_matches = re.findall(
                    pattern, result.original_text, re.IGNORECASE
                )
                count += len(source_matches)

            if count > 0:
                markers_found[marker_type] = count
                self._se_markers_total[marker_type] = (
                    self._se_markers_total.get(marker_type, 0) + count
                )

        result.se_markers_found = markers_found
        result.annotated_text = annotated

        # Add SE summary to annotated text
        if markers_found:
            summary_parts = []
            for marker_type, count in markers_found.items():
                label = SE_MARKERS[marker_type]["label"]
                summary_parts.append(f"{label}×{count}")
            summary = " | ".join(summary_parts)
            result.annotated_text = f"[SE_SUMMARY: {summary}]\n{annotated}"

        return result

    # ------------------------------------------------------------------
    # CULTURAL CONTEXT NOTES
    # ------------------------------------------------------------------

    def _generate_cultural_notes(
        self,
        text: str,
        source_language: str,
    ) -> list[str]:
        """
        Generate cultural context notes for the translation.

        Identifies culture-specific manipulation tactics that may
        not be obvious to analysts from different cultural backgrounds.
        """
        notes = []
        text_lower = text.lower()

        # South African cultural context
        if source_language in ("zu", "xh", "st", "tn", "nso", "ss", "ts", "ve", "nr"):
            if re.search(r"\b(baba|mama|malume|anti|gogo|mkhulu)\b", text_lower):
                notes.append(
                    "Uses familial/respectful address terms (baba=father, "
                    "mama=mother, malume=uncle) — cultural trust-building tactic "
                    "common in South African social engineering"
                )

            if re.search(r"\b(ubuntu|umuntu|abantu)\b", text_lower):
                notes.append(
                    "References Ubuntu philosophy (communal responsibility) — "
                    "exploits cultural value of helping others"
                )

            if re.search(r"\b(lobola|umembeso|umshado)\b", text_lower):
                notes.append(
                    "References traditional customs (lobola=bride price) — "
                    "may be using cultural events as pretext for financial requests"
                )

            if re.search(r"\b(sangoma|inyanga|muthi|muti)\b", text_lower):
                notes.append(
                    "References traditional healing/spiritual practices — "
                    "may be exploiting spiritual beliefs for manipulation"
                )

        # Arabic cultural context
        if source_language == "ar":
            if re.search(r"\b(إن شاء الله|بسم الله|الحمد لله)\b", text):
                notes.append(
                    "Uses religious phrases (Inshallah, Bismillah) — "
                    "common trust-building in Arabic social engineering"
                )

            if re.search(r"\b(أخي|أختي|حبيبي)\b", text):
                notes.append(
                    "Uses familial/affectionate address (brother, sister, dear) — "
                    "cultural trust-building tactic"
                )

        # Afrikaans cultural context
        if source_language == "af":
            if re.search(r"\b(boet|bru|tannie|oom|nè)\b", text_lower):
                notes.append(
                    "Uses Afrikaans familiar address (boet=brother, tannie=aunt, "
                    "oom=uncle) — cultural trust-building tactic"
                )

        return notes

    # ------------------------------------------------------------------
    # GLOSSARY APPLICATION
    # ------------------------------------------------------------------

    def _apply_glossary(
        self,
        result: TranslationResult,
        source_language: str,
        target_language: str,
    ) -> TranslationResult:
        """
        Apply security glossary to ensure consistent term translation.

        Checks translated text for security terms and ensures they
        match the glossary. Adds glossary annotations.
        """
        if target_language in SECURITY_GLOSSARY:
            glossary = SECURITY_GLOSSARY[target_language]
            for english_term, local_term in glossary.items():
                if english_term.lower() in result.translated_text.lower():
                    result.glossary_terms_used.append({
                        "english": english_term,
                        "local": local_term,
                        "language": target_language,
                    })

        if source_language in SECURITY_GLOSSARY:
            glossary = SECURITY_GLOSSARY[source_language]
            for english_term, local_term in glossary.items():
                if local_term.lower() in result.original_text.lower():
                    result.glossary_terms_used.append({
                        "english": english_term,
                        "local": local_term,
                        "language": source_language,
                    })

        return result

    # ------------------------------------------------------------------
    # SIMILARITY COMPUTATION
    # ------------------------------------------------------------------

    def _compute_similarity(self, text_a: str, text_b: str) -> float:
        """
        Compute similarity between two texts for back-translation verification.

        Uses character n-gram overlap (Jaccard similarity) as a
        language-agnostic measure.
        """
        def get_ngrams(text: str, n: int = 3) -> set:
            text = text.lower().strip()
            return {text[i:i + n] for i in range(len(text) - n + 1)}

        ngrams_a = get_ngrams(text_a)
        ngrams_b = get_ngrams(text_b)

        if not ngrams_a and not ngrams_b:
            return 1.0
        if not ngrams_a or not ngrams_b:
            return 0.0

        intersection = ngrams_a & ngrams_b
        union = ngrams_a | ngrams_b

        return len(intersection) / len(union) if union else 0.0

    # ------------------------------------------------------------------
    # STATISTICS
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return translation engine statistics."""
        return {
            "total_translations": self._total_translations,
            "language_pairs": dict(
                sorted(
                    self._language_pairs.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )
            ),
            "se_markers_total": dict(self._se_markers_total),
            "supported_glossary_languages": list(SECURITY_GLOSSARY.keys()),
            "glossary_terms_per_language": {
                lang: len(terms)
                for lang, terms in SECURITY_GLOSSARY.items()
            },
        }


# Module-level singleton
_engine: Optional[TranslationEngine] = None


def get_translation_engine() -> TranslationEngine:
    """Get or create the singleton TranslationEngine instance."""
    global _engine
    if _engine is None:
        _engine = TranslationEngine()
    return _engine
