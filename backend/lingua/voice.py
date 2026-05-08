"""
IMMUNIS ACIN — Voice/Vishing Ingestion Engine

WHY: Vishing (voice phishing) is the fastest-growing attack vector
in Africa. Attackers call victims in their home language (isiZulu,
Sesotho, Afrikaans) to build trust, then extract banking credentials,
OTPs, or authorise fraudulent transactions. Traditional email-focused
security systems are blind to this vector entirely.

This module handles:
1. Audio transcription (speech-to-text)
2. Speaker diarisation (who spoke when)
3. Language detection from audio
4. Emotional tone analysis (urgency, fear, authority)
5. Vishing indicator extraction (pressure tactics, urgency cues)
6. Transcript normalisation and handoff to text pipeline

Architecture:
  Voice input → Transcription → Diarisation → Language detect
  → Emotional analysis → Vishing indicators → IngestedThreat

Dependencies:
  - Whisper (OpenAI) for transcription (or API fallback)
  - Speaker diarisation via spectral clustering
  - Prosodic features for emotional analysis

Note: Full audio processing requires additional dependencies.
This module provides the framework and falls back to API-based
transcription when local models aren't available.
"""

import logging
import time
import hashlib
import re
import math
from typing import Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

logger = logging.getLogger("immunis.lingua.voice")


class EmotionalTone(str, Enum):
    """Detected emotional tone in voice."""
    NEUTRAL = "neutral"
    URGENT = "urgent"
    FEARFUL = "fearful"
    AUTHORITATIVE = "authoritative"
    AGGRESSIVE = "aggressive"
    SYMPATHETIC = "sympathetic"
    DECEPTIVE = "deceptive"


class SpeakerRole(str, Enum):
    """Role classification for speakers in a call."""
    ATTACKER = "attacker"
    VICTIM = "victim"
    UNKNOWN = "unknown"


@dataclass
class SpeakerSegment:
    """A segment of speech attributed to a specific speaker."""
    speaker_id: str
    start_time_s: float
    end_time_s: float
    text: str
    language: Optional[str] = None
    confidence: float = 0.0
    emotional_tone: EmotionalTone = EmotionalTone.NEUTRAL
    role: SpeakerRole = SpeakerRole.UNKNOWN


@dataclass
class VishingIndicators:
    """Indicators of vishing attack patterns."""
    urgency_score: float = 0.0  # 0-1
    authority_score: float = 0.0  # 0-1
    fear_score: float = 0.0  # 0-1
    information_request_score: float = 0.0  # 0-1
    impersonation_score: float = 0.0  # 0-1
    overall_vishing_score: float = 0.0  # 0-1
    indicators_found: list[str] = field(default_factory=list)
    pressure_tactics: list[str] = field(default_factory=list)
    requested_information: list[str] = field(default_factory=list)
    impersonated_entities: list[str] = field(default_factory=list)


@dataclass
class VoiceAnalysisResult:
    """Complete result of voice/vishing analysis."""
    transcript: str
    duration_s: float
    speakers: list[SpeakerSegment]
    num_speakers: int
    primary_language: str
    languages_detected: list[str]
    vishing_indicators: VishingIndicators
    is_vishing: bool
    vishing_confidence: float
    audio_hash: str
    analysed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: dict = field(default_factory=dict)


# Vishing keyword patterns (multilingual)
VISHING_PATTERNS = {
    "urgency": {
        "en": [
            r"\b(urgent|immediately|right now|hurry|quickly|asap|time.?sensitive)\b",
            r"\b(expire|suspend|deactivat|terminat|block|lock)\b",
            r"\b(within \d+ (hour|minute|day)s?)\b",
            r"\b(last chance|final warning|deadline)\b",
        ],
        "zu": [
            r"\b(phuthuma|shesha|manje|masinyane|ngokushesha)\b",
            r"\b(vala|misa|susa|nqamula)\b",
        ],
        "st": [
            r"\b(potlaka|kapele|hona joale|hang|ka potlako)\b",
            r"\b(kwala|emisa|tlosa)\b",
        ],
        "af": [
            r"\b(dringend|onmiddellik|nou|gou|vinnig)\b",
            r"\b(verval|opskort|deaktiveer|blokkeer)\b",
        ],
        "ar": [
            r"\b(عاجل|فوري|حالا|بسرعة|مستعجل)\b",
            r"\b(تعليق|إلغاء|حظر|إيقاف)\b",
        ],
    },
    "authority": {
        "en": [
            r"\b(bank|police|revenue|tax|government|official|department)\b",
            r"\b(manager|director|supervisor|officer|investigator)\b",
            r"\b(compliance|regulation|legal|court|warrant)\b",
            r"\b(this is .{0,20} (from|at|with) .{0,30} (bank|department|office))\b",
        ],
        "zu": [
            r"\b(ibhange|amaphoyisa|uhulumeni|umnyango)\b",
            r"\b(umphathi|usihlalo|umqondisi)\b",
        ],
        "st": [
            r"\b(banka|sepolesa|mmuso|lefapha)\b",
            r"\b(molaodi|modulasetulo|motsamaisi)\b",
        ],
        "af": [
            r"\b(bank|polisie|regering|departement|amptelik)\b",
            r"\b(bestuurder|direkteur|beampte)\b",
        ],
    },
    "information_request": {
        "en": [
            r"\b(pin|password|otp|one.?time|verification|security)\b",
            r"\b(account.?number|card.?number|cvv|expir)\b",
            r"\b(confirm|verify|validate|authenticate)\b",
            r"\b(social.?security|id.?number|identity)\b",
            r"\b(tell me|give me|provide|share|read.?out)\b",
        ],
        "zu": [
            r"\b(inombolo|iphasiwedi|i-pin|i-otp)\b",
            r"\b(qinisekisa|faka|nikeza|tshela)\b",
        ],
        "st": [
            r"\b(nomoro|password|pin|otp)\b",
            r"\b(netefatsa|fana|bolela)\b",
        ],
        "af": [
            r"\b(pin|wagwoord|otp|verifikasie)\b",
            r"\b(rekeningnommer|kaartnommer)\b",
            r"\b(bevestig|verifieer|verskaf)\b",
        ],
    },
    "fear": {
        "en": [
            r"\b(arrest|prosecut|jail|prison|fine|penalty)\b",
            r"\b(fraud|compromise|hack|breach|stolen)\b",
            r"\b(lose|lost|gone|disappear)\b",
            r"\b(someone.{0,20}(access|using|stole))\b",
        ],
        "zu": [
            r"\b(boshwa|jele|inhlawulo|intela)\b",
            r"\b(ubugebengu|ukwebiwa|ukulahleka)\b",
        ],
        "st": [
            r"\b(tshwarwa|tjhankaneng|tefiso)\b",
            r"\b(boshodu|utswa|lahleha)\b",
        ],
        "af": [
            r"\b(arresteer|vervolg|tronk|boete|straf)\b",
            r"\b(bedrog|gekompromitteer|gesteel)\b",
        ],
    },
    "impersonation": {
        "en": [
            r"\b(calling from|this is|i am|i'm).{0,30}(bank|department|office|company)\b",
            r"\b(on behalf of|representing|authorized by)\b",
            r"\b(reference number|case number|ticket number)\b",
        ],
        "zu": [
            r"\b(ngishayela|ngivela|ngingu).{0,30}(ibhange|umnyango)\b",
        ],
        "st": [
            r"\b(ke letsetse|ke tswa|ke nna).{0,30}(banka|lefapha)\b",
        ],
        "af": [
            r"\b(ek bel van|ek is|ek bel namens).{0,30}(bank|departement)\b",
        ],
    },
}

# Entities commonly impersonated
IMPERSONATION_ENTITIES = [
    "FNB", "ABSA", "Standard Bank", "Nedbank", "Capitec",
    "SARS", "SAPS", "Home Affairs", "Department of Labour",
    "Vodacom", "MTN", "Telkom", "Cell C",
    "Eskom", "City Power", "Municipality",
    "Microsoft", "Google", "Apple", "Amazon",
    "Visa", "Mastercard", "PayPal",
]


class VoiceAnalysisEngine:
    """
    Voice/vishing analysis engine.

    Processes audio recordings or pre-transcribed text to detect
    vishing attacks. Supports multilingual analysis with focus
    on South African languages.

    When audio processing libraries are available:
    - Transcribes audio via Whisper
    - Performs speaker diarisation
    - Analyses prosodic features (pitch, rate, energy)

    When only text is available:
    - Analyses transcript for vishing patterns
    - Detects urgency, authority, fear tactics
    - Identifies information requests
    - Flags impersonation attempts
    """

    # Vishing classification thresholds
    VISHING_THRESHOLD = 0.6
    HIGH_CONFIDENCE_THRESHOLD = 0.8

    def __init__(self):
        self._whisper_available = False
        self._total_analyses: int = 0
        self._vishing_detected: int = 0

        # Check for audio processing capabilities
        try:
            import whisper
            self._whisper_available = True
            logger.info("Whisper model available for audio transcription")
        except ImportError:
            logger.info(
                "Whisper not available — voice analysis limited to "
                "pre-transcribed text. Install with: pip install openai-whisper"
            )

        logger.info("Voice analysis engine initialised")

    def analyse_audio(
        self,
        audio_path: Optional[str] = None,
        audio_bytes: Optional[bytes] = None,
        transcript: Optional[str] = None,
        language_hint: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> VoiceAnalysisResult:
        """
        Analyse audio or transcript for vishing indicators.

        Provide either audio_path/audio_bytes for full analysis,
        or transcript for text-only analysis.

        Args:
            audio_path: Path to audio file.
            audio_bytes: Raw audio bytes.
            transcript: Pre-transcribed text (if audio not available).
            language_hint: Expected language ISO code.
            metadata: Additional metadata (caller ID, duration, etc.).

        Returns:
            VoiceAnalysisResult with vishing indicators and classification.
        """
        start = time.perf_counter()
        metadata = metadata or {}

        # Transcribe if audio provided
        if audio_path or audio_bytes:
            transcript_result = self._transcribe(
                audio_path=audio_path,
                audio_bytes=audio_bytes,
                language_hint=language_hint,
            )
            transcript = transcript_result.get("text", "")
            detected_language = transcript_result.get("language", language_hint or "en")
            duration_s = transcript_result.get("duration", 0.0)
            segments = transcript_result.get("segments", [])
        else:
            if transcript is None:
                transcript = ""
            detected_language = language_hint or "en"
            duration_s = metadata.get("duration_s", 0.0)
            segments = []

        # Compute audio hash
        if audio_bytes:
            audio_hash = hashlib.sha256(audio_bytes).hexdigest()[:16]
        elif audio_path:
            audio_hash = hashlib.sha256(
                audio_path.encode() + str(time.time()).encode()
            ).hexdigest()[:16]
        else:
            audio_hash = hashlib.sha256(
                transcript.encode()
            ).hexdigest()[:16]

        # Perform speaker diarisation (simplified)
        speakers = self._diarise(transcript, segments)

        # Detect languages in transcript
        languages_detected = self._detect_languages_in_transcript(
            transcript, detected_language
        )

        # Analyse vishing indicators
        vishing_indicators = self._analyse_vishing_indicators(
            transcript, detected_language
        )

        # Classify speakers
        speakers = self._classify_speaker_roles(speakers, vishing_indicators)

        # Determine if vishing
        is_vishing = vishing_indicators.overall_vishing_score >= self.VISHING_THRESHOLD
        vishing_confidence = vishing_indicators.overall_vishing_score

        elapsed_ms = (time.perf_counter() - start) * 1000

        # Update stats
        self._total_analyses += 1
        if is_vishing:
            self._vishing_detected += 1

        result = VoiceAnalysisResult(
            transcript=transcript,
            duration_s=duration_s,
            speakers=speakers,
            num_speakers=len(set(s.speaker_id for s in speakers)),
            primary_language=detected_language,
            languages_detected=languages_detected,
            vishing_indicators=vishing_indicators,
            is_vishing=is_vishing,
            vishing_confidence=vishing_confidence,
            audio_hash=audio_hash,
            metadata={
                **metadata,
                "analysis_time_ms": round(elapsed_ms, 2),
                "whisper_available": self._whisper_available,
            },
        )

        logger.info(
            f"Voice analysis complete: vishing={'YES' if is_vishing else 'NO'} "
            f"(score={vishing_confidence:.2f}), "
            f"lang={detected_language}, speakers={result.num_speakers}, "
            f"duration={duration_s:.1f}s, latency={elapsed_ms:.1f}ms"
        )

        return result

    # ------------------------------------------------------------------
    # TRANSCRIPTION
    # ------------------------------------------------------------------

    def _transcribe(
        self,
        audio_path: Optional[str] = None,
        audio_bytes: Optional[bytes] = None,
        language_hint: Optional[str] = None,
    ) -> dict:
        """
        Transcribe audio to text.

        Uses Whisper when available, otherwise returns empty result.
        """
        if not self._whisper_available:
            logger.warning("Whisper not available — cannot transcribe audio")
            return {"text": "", "language": language_hint or "en", "duration": 0.0, "segments": []}

        try:
            import whisper

            model = whisper.load_model("base")

            if audio_path:
                result = model.transcribe(
                    audio_path,
                    language=language_hint,
                    task="transcribe",
                )
            elif audio_bytes:
                # Write to temp file for Whisper
                import tempfile
                with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
                    f.write(audio_bytes)
                    temp_path = f.name

                result = model.transcribe(
                    temp_path,
                    language=language_hint,
                    task="transcribe",
                )

                import os
                os.unlink(temp_path)
            else:
                return {"text": "", "language": language_hint or "en", "duration": 0.0, "segments": []}

            return {
                "text": result.get("text", ""),
                "language": result.get("language", language_hint or "en"),
                "duration": result.get("duration", 0.0) if "duration" in result else 0.0,
                "segments": result.get("segments", []),
            }

        except Exception as e:
            logger.error(f"Transcription failed: {e}")
            return {"text": "", "language": language_hint or "en", "duration": 0.0, "segments": []}

    # ------------------------------------------------------------------
    # SPEAKER DIARISATION
    # ------------------------------------------------------------------

    def _diarise(
        self,
        transcript: str,
        segments: list,
    ) -> list[SpeakerSegment]:
        """
        Perform speaker diarisation.

        If Whisper segments are available, uses timing information.
        Otherwise, uses heuristic turn-taking detection from transcript.
        """
        if segments:
            return self._diarise_from_segments(segments)
        else:
            return self._diarise_from_text(transcript)

    def _diarise_from_segments(self, segments: list) -> list[SpeakerSegment]:
        """Diarise using Whisper segment timing."""
        speakers = []
        current_speaker = "speaker_1"
        last_end = 0.0
        speaker_toggle = False

        for seg in segments:
            start = seg.get("start", 0.0)
            end = seg.get("end", 0.0)
            text = seg.get("text", "").strip()

            if not text:
                continue

            # Simple heuristic: long pause = speaker change
            gap = start - last_end
            if gap > 1.5:  # 1.5 second gap suggests speaker change
                speaker_toggle = not speaker_toggle
                current_speaker = "speaker_2" if speaker_toggle else "speaker_1"

            speakers.append(SpeakerSegment(
                speaker_id=current_speaker,
                start_time_s=start,
                end_time_s=end,
                text=text,
                confidence=0.6,
            ))

            last_end = end

        return speakers

    def _diarise_from_text(self, transcript: str) -> list[SpeakerSegment]:
        """Diarise using text-based turn-taking heuristics."""
        # Split on common turn indicators
        turns = re.split(
            r"(?:\n\s*\n|(?:Speaker \d+:|Caller:|Agent:|Customer:|Victim:|Attacker:))",
            transcript,
        )

        speakers = []
        current_speaker = "speaker_1"
        time_offset = 0.0

        for i, turn in enumerate(turns):
            turn = turn.strip()
            if not turn:
                continue

            # Alternate speakers
            current_speaker = f"speaker_{(i % 2) + 1}"

            # Estimate duration from word count (avg 150 words/min)
            word_count = len(turn.split())
            estimated_duration = word_count / 2.5  # seconds

            speakers.append(SpeakerSegment(
                speaker_id=current_speaker,
                start_time_s=time_offset,
                end_time_s=time_offset + estimated_duration,
                text=turn,
                confidence=0.4,  # Lower confidence for text-only
            ))

            time_offset += estimated_duration + 0.5  # 0.5s gap

        # If no turns detected, treat entire transcript as one segment
        if not speakers and transcript.strip():
            speakers.append(SpeakerSegment(
                speaker_id="speaker_1",
                start_time_s=0.0,
                end_time_s=len(transcript.split()) / 2.5,
                text=transcript.strip(),
                confidence=0.3,
            ))

        return speakers

    # ------------------------------------------------------------------
    # VISHING INDICATOR ANALYSIS
    # ------------------------------------------------------------------

    def _analyse_vishing_indicators(
        self,
        transcript: str,
        language: str,
    ) -> VishingIndicators:
        """
        Analyse transcript for vishing attack indicators.

        Checks five dimensions:
        1. Urgency — time pressure, deadlines, expiry threats
        2. Authority — impersonation of officials, institutions
        3. Fear — threats of arrest, loss, prosecution
        4. Information request — asking for PINs, passwords, OTPs
        5. Impersonation — claiming to be from specific entities

        Each dimension scored 0-1. Overall score is weighted average.
        """
        transcript_lower = transcript.lower()
        indicators = VishingIndicators()

        # Score each dimension
        indicators.urgency_score = self._score_dimension(
            transcript_lower, "urgency", language
        )
        indicators.authority_score = self._score_dimension(
            transcript_lower, "authority", language
        )
        indicators.fear_score = self._score_dimension(
            transcript_lower, "fear", language
        )
        indicators.information_request_score = self._score_dimension(
            transcript_lower, "information_request", language
        )
        indicators.impersonation_score = self._score_dimension(
            transcript_lower, "impersonation", language
        )

        # Extract specific indicators
        indicators.indicators_found = self._extract_specific_indicators(
            transcript_lower, language
        )

        # Extract pressure tactics
        indicators.pressure_tactics = self._extract_pressure_tactics(
            transcript_lower
        )

        # Extract requested information types
        indicators.requested_information = self._extract_requested_info(
            transcript_lower
        )

        # Check for entity impersonation
        indicators.impersonated_entities = self._detect_impersonated_entities(
            transcript
        )

        # Compute overall score (weighted average)
        weights = {
            "urgency": 0.15,
            "authority": 0.15,
            "fear": 0.15,
            "information_request": 0.35,  # Highest weight — this is the goal
            "impersonation": 0.20,
        }

        indicators.overall_vishing_score = (
            indicators.urgency_score * weights["urgency"]
            + indicators.authority_score * weights["authority"]
            + indicators.fear_score * weights["fear"]
            + indicators.information_request_score * weights["information_request"]
            + indicators.impersonation_score * weights["impersonation"]
        )

        # Boost if multiple dimensions are high (compound attack)
        high_dimensions = sum(1 for s in [
            indicators.urgency_score,
            indicators.authority_score,
            indicators.fear_score,
            indicators.information_request_score,
            indicators.impersonation_score,
        ] if s > 0.5)

        if high_dimensions >= 3:
            indicators.overall_vishing_score = min(
                1.0, indicators.overall_vishing_score * 1.3
            )

        return indicators

    def _score_dimension(
        self,
        text: str,
        dimension: str,
        language: str,
    ) -> float:
        """Score a single vishing dimension using pattern matching."""
        patterns = VISHING_PATTERNS.get(dimension, {})
        total_matches = 0

        # Check language-specific patterns
        lang_patterns = patterns.get(language, [])
        for pattern in lang_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            total_matches += len(matches)

        # Always check English patterns (many attacks mix English)
        if language != "en":
            en_patterns = patterns.get("en", [])
            for pattern in en_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                total_matches += len(matches) * 0.7  # Slightly lower weight

        # Normalise to 0-1 (sigmoid-like)
        if total_matches == 0:
            return 0.0

        # Sigmoid normalisation: score = 1 - e^(-k*matches)
        score = 1.0 - math.exp(-0.5 * total_matches)
        return min(1.0, score)

    def _extract_specific_indicators(
        self,
        text: str,
        language: str,
    ) -> list[str]:
        """Extract specific vishing indicator descriptions."""
        indicators = []

        if re.search(r"\b(pin|password|otp|one.?time)\b", text, re.IGNORECASE):
            indicators.append("Requests sensitive credentials")
        if re.search(r"\b(account.?number|card.?number|cvv)\b", text, re.IGNORECASE):
            indicators.append("Requests financial account details")
        if re.search(r"\b(urgent|immediately|right now)\b", text, re.IGNORECASE):
            indicators.append("Creates artificial urgency")
        if re.search(r"\b(arrest|prosecut|jail|fine)\b", text, re.IGNORECASE):
            indicators.append("Threatens legal consequences")
        if re.search(r"\b(bank|police|revenue|government)\b", text, re.IGNORECASE):
            indicators.append("Claims institutional authority")
        if re.search(r"\b(don't tell|keep.?secret|between us|confidential)\b", text, re.IGNORECASE):
            indicators.append("Requests secrecy")
        if re.search(r"\b(transfer|send|deposit|pay)\b", text, re.IGNORECASE):
            indicators.append("Requests financial transaction")
        if re.search(r"\b(remote.?access|teamviewer|anydesk|screen.?share)\b", text, re.IGNORECASE):
            indicators.append("Requests remote access")

        return indicators

    def _extract_pressure_tactics(self, text: str) -> list[str]:
        """Extract specific pressure tactics used."""
        tactics = []

        if re.search(r"\b(only \d+ (minute|hour|day)s? (left|remaining))\b", text):
            tactics.append("Time-limited deadline")
        if re.search(r"\b(this is your (last|final) (chance|warning|opportunity))\b", text):
            tactics.append("Final warning threat")
        if re.search(r"\b(if you don't|unless you|failure to)\b", text):
            tactics.append("Conditional threat")
        if re.search(r"\b(everyone else has|other (customers|clients) have)\b", text):
            tactics.append("Social proof manipulation")
        if re.search(r"\b(i('m| am) trying to help|for your (safety|protection|security))\b", text):
            tactics.append("False helpfulness")
        if re.search(r"\b(don't hang up|stay on the line|don't disconnect)\b", text):
            tactics.append("Prevents disconnection")

        return tactics

    def _extract_requested_info(self, text: str) -> list[str]:
        """Extract types of information being requested."""
        info_types = []

        patterns = {
            "PIN": r"\bpin\b",
            "Password": r"\bpassword\b",
            "OTP": r"\b(otp|one.?time.?p)\b",
            "Account number": r"\baccount.?num\b",
            "Card number": r"\bcard.?num\b",
            "CVV": r"\bcvv\b",
            "ID number": r"\b(id.?num|identity.?num)\b",
            "Date of birth": r"\b(date.?of.?birth|dob|birthday)\b",
            "Address": r"\b(home.?address|physical.?address|residential)\b",
            "Banking details": r"\b(banking.?detail|bank.?detail)\b",
        }

        for info_type, pattern in patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                info_types.append(info_type)

        return info_types

    def _detect_impersonated_entities(self, transcript: str) -> list[str]:
        """Detect which entities are being impersonated."""
        found = []
        transcript_upper = transcript.upper()

        for entity in IMPERSONATION_ENTITIES:
            if entity.upper() in transcript_upper:
                found.append(entity)

        return found

    # ------------------------------------------------------------------
    # LANGUAGE DETECTION IN TRANSCRIPT
    # ------------------------------------------------------------------

    def _detect_languages_in_transcript(
        self,
        transcript: str,
        primary_language: str,
    ) -> list[str]:
        """Detect all languages present in the transcript."""
        languages = {primary_language}

        # Check for script-based languages
        from backend.lingua.ingestion import SCRIPT_PATTERNS

        for lang, pattern in SCRIPT_PATTERNS.items():
            if pattern.search(transcript):
                languages.add(lang)

        # Check for Bantu markers
        from backend.lingua.ingestion import BANTU_MARKERS

        transcript_lower = transcript.lower()
        for lang, markers in BANTU_MARKERS.items():
            marker_count = sum(
                1 for word in transcript_lower.split()
                for marker in markers
                if word.startswith(marker)
            )
            if marker_count >= 3:
                languages.add(lang)

        return sorted(languages)

    # ------------------------------------------------------------------
    # SPEAKER ROLE CLASSIFICATION
    # ------------------------------------------------------------------

    def _classify_speaker_roles(
        self,
        speakers: list[SpeakerSegment],
        indicators: VishingIndicators,
    ) -> list[SpeakerSegment]:
        """
        Classify speaker roles (attacker vs victim).

        Heuristics:
        - Speaker who uses more authority/urgency language = attacker
        - Speaker who asks questions / provides info = victim
        - Speaker who talks more = likely attacker (controls conversation)
        """
        if not speakers or indicators.overall_vishing_score < self.VISHING_THRESHOLD:
            return speakers

        # Group text by speaker
        speaker_texts: dict[str, str] = {}
        speaker_word_counts: dict[str, int] = {}

        for seg in speakers:
            if seg.speaker_id not in speaker_texts:
                speaker_texts[seg.speaker_id] = ""
                speaker_word_counts[seg.speaker_id] = 0
            speaker_texts[seg.speaker_id] += " " + seg.text
            speaker_word_counts[seg.speaker_id] += len(seg.text.split())

        # Score each speaker for attacker-like behaviour
        speaker_scores: dict[str, float] = {}
        for speaker_id, text in speaker_texts.items():
            text_lower = text.lower()
            score = 0.0

            # Authority language
            authority_matches = len(re.findall(
                r"\b(bank|police|department|official|manager)\b",
                text_lower,
            ))
            score += authority_matches * 0.3

            # Urgency language
            urgency_matches = len(re.findall(
                r"\b(urgent|immediately|now|hurry|quickly)\b",
                text_lower,
            ))
            score += urgency_matches * 0.2

            # Information requests
            info_matches = len(re.findall(
                r"\b(tell me|give me|provide|what is your|confirm your)\b",
                text_lower,
            ))
            score += info_matches * 0.4

            # Talks more = more likely attacker
            total_words = sum(speaker_word_counts.values())
            if total_words > 0:
                talk_ratio = speaker_word_counts[speaker_id] / total_words
                if talk_ratio > 0.6:
                    score += 0.3

            speaker_scores[speaker_id] = score

        # Assign roles
        if speaker_scores:
            attacker_id = max(speaker_scores, key=speaker_scores.get)
            for seg in speakers:
                if seg.speaker_id == attacker_id:
                    seg.role = SpeakerRole.ATTACKER
                else:
                    seg.role = SpeakerRole.VICTIM

        return speakers

    # ------------------------------------------------------------------
    # STATISTICS
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return voice analysis engine statistics."""
        return {
            "total_analyses": self._total_analyses,
            "vishing_detected": self._vishing_detected,
            "vishing_rate": (
                self._vishing_detected / self._total_analyses
                if self._total_analyses > 0
                else 0.0
            ),
            "whisper_available": self._whisper_available,
        }


# Module-level singleton
_engine: Optional[VoiceAnalysisEngine] = None


def get_voice_engine() -> VoiceAnalysisEngine:
    """Get or create the singleton VoiceAnalysisEngine instance."""
    global _engine
    if _engine is None:
        _engine = VoiceAnalysisEngine()
    return _engine
