"""
IMMUNIS ACIN — Psychographic Attacker Profiling

WHY: Understanding WHY an attacker attacks is as important as
understanding HOW. A financially motivated criminal responds to
different deterrents than an ideologically motivated hacktivist
or a state-sponsored espionage operator.

The psychographic profiler classifies attackers into five profiles
based on their behavioural fingerprint, technique choices, timing
patterns, and target selection. Each profile has different:
- Motivations (money, ideology, espionage, thrill, revenge)
- Risk tolerance (how much risk they'll accept)
- Persistence (how long they'll keep trying)
- Sophistication ceiling (maximum capability)
- Deterrence sensitivity (what makes them stop)

The Five Profiles:
1. MERCENARY — Financially motivated, professional, risk-averse
   Tools: commodity malware, phishing kits, ransomware
   Deterrence: increase cost of attack, reduce expected profit

2. HACKTIVIST — Ideologically motivated, public-facing, moderate risk
   Tools: DDoS, defacement, data leaks
   Deterrence: reduce publicity value, increase attribution risk

3. OPERATIVE — State-sponsored, patient, high sophistication
   Tools: custom malware, zero-days, supply chain
   Deterrence: diplomatic channels, attribution, active defence

4. THRILL-SEEKER — Curiosity-driven, low sophistication, impulsive
   Tools: script kiddie tools, public exploits
   Deterrence: any detection, legal warnings

5. INSIDER — Authorised access, knowledge of systems, personal motive
   Tools: legitimate tools, data exfiltration
   Deterrence: monitoring awareness, access controls, HR intervention

Mathematical foundation:
  Profile classification uses a weighted feature scoring model:
    score(profile) = Σ wᵢ · fᵢ(fingerprint)
  Where wᵢ are profile-specific weights and fᵢ are feature functions.

  Confidence = max_score / Σ scores (softmax normalisation)
"""

import logging
import math
from typing import Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger("immunis.taf.psychographic")


class AttackerProfile:
    """Enumeration of attacker psychographic profiles."""
    MERCENARY = "mercenary"
    HACKTIVIST = "hacktivist"
    OPERATIVE = "operative"
    THRILL_SEEKER = "thrill_seeker"
    INSIDER = "insider"


@dataclass
class ProfileScore:
    """Score for a single psychographic profile."""
    profile: str
    score: float
    confidence: float
    indicators: list[str] = field(default_factory=list)


@dataclass
class PsychographicAssessment:
    """Complete psychographic assessment of a threat actor."""
    assessment_id: str
    primary_profile: str
    primary_confidence: float
    secondary_profile: Optional[str] = None
    secondary_confidence: float = 0.0
    all_scores: list[ProfileScore] = field(default_factory=list)

    # Profile-specific attributes
    motivation: str = ""
    risk_tolerance: str = ""  # low, medium, high
    persistence_level: str = ""  # low, medium, high
    sophistication_ceiling: str = ""  # script_kiddie, intermediate, advanced, nation_state
    estimated_resources: str = ""  # individual, small_group, organisation, state

    # Deterrence recommendations
    deterrence_strategy: str = ""
    deterrence_actions: list[str] = field(default_factory=list)

    # Response recommendations
    response_priority: str = ""  # routine, elevated, high, critical
    response_actions: list[str] = field(default_factory=list)

    assessed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "assessment_id": self.assessment_id,
            "primary_profile": self.primary_profile,
            "primary_confidence": round(self.primary_confidence, 3),
            "secondary_profile": self.secondary_profile,
            "secondary_confidence": round(self.secondary_confidence, 3),
            "all_scores": [
                {
                    "profile": s.profile,
                    "score": round(s.score, 3),
                    "confidence": round(s.confidence, 3),
                    "indicators": s.indicators,
                }
                for s in self.all_scores
            ],
            "motivation": self.motivation,
            "risk_tolerance": self.risk_tolerance,
            "persistence_level": self.persistence_level,
            "sophistication_ceiling": self.sophistication_ceiling,
            "estimated_resources": self.estimated_resources,
            "deterrence_strategy": self.deterrence_strategy,
            "deterrence_actions": self.deterrence_actions,
            "response_priority": self.response_priority,
            "response_actions": self.response_actions,
            "assessed_at": self.assessed_at,
        }


# Profile feature weights
# Each profile has weights for behavioural features
PROFILE_WEIGHTS = {
    AttackerProfile.MERCENARY: {
        "sophistication": 0.6,  # Moderate — professional but not cutting-edge
        "automation": 0.8,  # High — uses commodity tools at scale
        "stealth": 0.5,  # Moderate — cares about not getting caught
        "persistence": 0.4,  # Low-moderate — moves on if too hard
        "adaptability": 0.3,  # Low — sticks to known playbook
        "knowledge": 0.5,  # Moderate
        "time_pressure": 0.7,  # High — wants quick ROI
        "credential_focus": 0.8,  # High — wants credentials/money
        "data_exfil_focus": 0.6,  # Moderate-high
        "destruction_focus": 0.3,  # Low — destruction doesn't pay
        "recon_focus": 0.4,  # Low-moderate
        "business_hours": 0.6,  # Moderate — works regular hours
    },
    AttackerProfile.HACKTIVIST: {
        "sophistication": 0.3,  # Low-moderate
        "automation": 0.6,  # Moderate — uses available tools
        "stealth": 0.2,  # Low — WANTS to be noticed
        "persistence": 0.7,  # High — ideologically driven
        "adaptability": 0.4,  # Low-moderate
        "knowledge": 0.4,  # Moderate
        "time_pressure": 0.3,  # Low — patient for the cause
        "credential_focus": 0.3,  # Low
        "data_exfil_focus": 0.7,  # High — wants to leak data
        "destruction_focus": 0.8,  # High — defacement, DDoS
        "recon_focus": 0.3,  # Low
        "business_hours": 0.3,  # Low — works odd hours
    },
    AttackerProfile.OPERATIVE: {
        "sophistication": 0.9,  # Very high
        "automation": 0.5,  # Moderate — mix of custom and automated
        "stealth": 0.9,  # Very high — avoids detection
        "persistence": 0.9,  # Very high — months/years
        "adaptability": 0.9,  # Very high — adapts to defences
        "knowledge": 0.9,  # Very high
        "time_pressure": 0.1,  # Very low — patient
        "credential_focus": 0.5,  # Moderate
        "data_exfil_focus": 0.8,  # High — intelligence collection
        "destruction_focus": 0.2,  # Low — wants to stay hidden
        "recon_focus": 0.9,  # Very high — extensive recon
        "business_hours": 0.5,  # Moderate — follows target's hours
    },
    AttackerProfile.THRILL_SEEKER: {
        "sophistication": 0.1,  # Very low
        "automation": 0.3,  # Low — uses tools they don't understand
        "stealth": 0.1,  # Very low — noisy
        "persistence": 0.2,  # Very low — gives up quickly
        "adaptability": 0.1,  # Very low — can't adapt
        "knowledge": 0.2,  # Low
        "time_pressure": 0.5,  # Moderate — impulsive
        "credential_focus": 0.3,  # Low
        "data_exfil_focus": 0.2,  # Low
        "destruction_focus": 0.5,  # Moderate — likes to break things
        "recon_focus": 0.2,  # Low — jumps straight in
        "business_hours": 0.2,  # Low — late night/weekends
    },
    AttackerProfile.INSIDER: {
        "sophistication": 0.4,  # Moderate — knows the system
        "automation": 0.2,  # Low — manual, careful
        "stealth": 0.7,  # High — knows what's monitored
        "persistence": 0.6,  # Moderate-high — has ongoing access
        "adaptability": 0.5,  # Moderate
        "knowledge": 0.8,  # High — knows the environment
        "time_pressure": 0.4,  # Moderate
        "credential_focus": 0.3,  # Low — already has credentials
        "data_exfil_focus": 0.9,  # Very high — primary objective
        "destruction_focus": 0.4,  # Moderate — revenge possible
        "recon_focus": 0.2,  # Low — already knows the environment
        "business_hours": 0.8,  # High — acts during normal hours
    },
}

# Profile metadata
PROFILE_METADATA = {
    AttackerProfile.MERCENARY: {
        "motivation": "Financial gain",
        "risk_tolerance": "medium",
        "persistence_level": "medium",
        "sophistication_ceiling": "intermediate",
        "estimated_resources": "small_group",
        "deterrence_strategy": "Economic deterrence — make attacking unprofitable",
        "deterrence_actions": [
            "Increase detection rate to raise attacker cost",
            "Deploy deception to waste attacker time",
            "Publicise successful prosecutions as deterrent",
            "Implement multi-factor authentication to block credential theft",
            "Reduce attack surface to limit profitable targets",
        ],
        "response_priority": "elevated",
        "response_actions": [
            "Block and rotate compromised credentials immediately",
            "Check for lateral movement indicators",
            "Review financial transaction logs for fraud",
            "Engage law enforcement if financial loss confirmed",
            "Deploy additional monitoring on financial systems",
        ],
    },
    AttackerProfile.HACKTIVIST: {
        "motivation": "Ideological / political",
        "risk_tolerance": "high",
        "persistence_level": "high",
        "sophistication_ceiling": "intermediate",
        "estimated_resources": "small_group",
        "deterrence_strategy": "Reduce publicity value and increase attribution risk",
        "deterrence_actions": [
            "Prepare incident communication plan (control narrative)",
            "Harden public-facing assets (primary targets)",
            "Monitor social media for campaign indicators",
            "Implement DDoS mitigation",
            "Reduce data exposure to limit leak impact",
        ],
        "response_priority": "high",
        "response_actions": [
            "Activate DDoS mitigation immediately",
            "Check for data exfiltration (leak preparation)",
            "Monitor for website defacement",
            "Prepare public communication (don't amplify)",
            "Engage PR/communications team",
        ],
    },
    AttackerProfile.OPERATIVE: {
        "motivation": "Intelligence collection / strategic advantage",
        "risk_tolerance": "low",
        "persistence_level": "high",
        "sophistication_ceiling": "nation_state",
        "estimated_resources": "state",
        "deterrence_strategy": "Active defence, attribution, and diplomatic channels",
        "deterrence_actions": [
            "Deploy advanced threat hunting (assume breach)",
            "Implement network segmentation to limit lateral movement",
            "Deploy deception at scale (waste their resources)",
            "Engage national CERT and intelligence agencies",
            "Consider attribution and diplomatic response",
        ],
        "response_priority": "critical",
        "response_actions": [
            "Activate incident response team immediately",
            "Assume full network compromise — verify from clean systems",
            "Preserve forensic evidence (do not alert attacker)",
            "Engage specialised APT response firm",
            "Brief executive leadership and board",
            "Consider regulatory notification obligations",
        ],
    },
    AttackerProfile.THRILL_SEEKER: {
        "motivation": "Curiosity / bragging rights",
        "risk_tolerance": "low",
        "persistence_level": "low",
        "sophistication_ceiling": "script_kiddie",
        "estimated_resources": "individual",
        "deterrence_strategy": "Any visible detection deters — show them they're caught",
        "deterrence_actions": [
            "Display warning banners on honeypots",
            "Block and blacklist IP immediately",
            "Automated response is sufficient",
            "No need for advanced countermeasures",
            "Log for pattern analysis (may escalate over time)",
        ],
        "response_priority": "routine",
        "response_actions": [
            "Block source IP",
            "Verify no actual compromise occurred",
            "Log for trend analysis",
            "No executive notification needed",
            "Update automated blocking rules",
        ],
    },
    AttackerProfile.INSIDER: {
        "motivation": "Personal (revenge, financial, ideological)",
        "risk_tolerance": "medium",
        "persistence_level": "high",
        "sophistication_ceiling": "advanced",
        "estimated_resources": "individual",
        "deterrence_strategy": "Monitoring awareness and access controls",
        "deterrence_actions": [
            "Implement and publicise DLP (data loss prevention)",
            "Deploy behavioural analytics on privileged users",
            "Enforce least-privilege access controls",
            "Conduct regular access reviews",
            "Establish anonymous reporting channels",
        ],
        "response_priority": "critical",
        "response_actions": [
            "Do NOT alert the suspected insider",
            "Engage HR and legal counsel immediately",
            "Preserve forensic evidence with chain of custody",
            "Review access logs for scope of compromise",
            "Prepare for potential legal proceedings",
            "Consider immediate access revocation (with legal approval)",
        ],
    },
}


class PsychographicProfiler:
    """
    Classifies threat actors into psychographic profiles
    based on their behavioural fingerprint.

    Usage:
        profiler = PsychographicProfiler()

        assessment = profiler.assess(fingerprint)
        print(assessment.primary_profile)  # "mercenary"
        print(assessment.deterrence_actions)  # ["Increase detection rate..."]
    """

    def __init__(self):
        self._total_assessments: int = 0
        self._profile_counts: dict[str, int] = {
            p: 0 for p in [
                AttackerProfile.MERCENARY,
                AttackerProfile.HACKTIVIST,
                AttackerProfile.OPERATIVE,
                AttackerProfile.THRILL_SEEKER,
                AttackerProfile.INSIDER,
            ]
        }

        logger.info("Psychographic profiler initialised")

    def assess(
        self,
        fingerprint,
        technique_sequence: Optional[list[str]] = None,
        additional_context: Optional[dict] = None,
    ) -> PsychographicAssessment:
        """
        Assess a threat actor's psychographic profile.

        Args:
            fingerprint: BehaviouralFingerprint from the extractor.
            technique_sequence: Observed MITRE ATT&CK techniques.
            additional_context: Extra context (target type, timing, etc.).

        Returns:
            PsychographicAssessment with profile, deterrence, and response.
        """
        # Extract features from fingerprint
        features = self._extract_features(
            fingerprint, technique_sequence, additional_context
        )

        # Score each profile
        profile_scores = []
        for profile, weights in PROFILE_WEIGHTS.items():
            score, indicators = self._score_profile(profile, weights, features)
            profile_scores.append(ProfileScore(
                profile=profile,
                score=score,
                confidence=0.0,  # Computed after softmax
                indicators=indicators,
            ))

        # Softmax normalisation for confidence
        scores = np.array([ps.score for ps in profile_scores])
        # Temperature scaling for sharper distribution
        temperature = 0.5
        exp_scores = np.exp((scores - np.max(scores)) / temperature)
        softmax = exp_scores / exp_scores.sum()

        for i, ps in enumerate(profile_scores):
            ps.confidence = float(softmax[i])

        # Sort by confidence
        profile_scores.sort(key=lambda ps: ps.confidence, reverse=True)

        primary = profile_scores[0]
        secondary = profile_scores[1] if len(profile_scores) > 1 else None

        # Get profile metadata
        metadata = PROFILE_METADATA.get(primary.profile, {})

        import hashlib
        assessment_id = hashlib.sha256(
            f"{getattr(fingerprint, 'fingerprint_id', '')}:{primary.profile}".encode()
        ).hexdigest()[:12]

        assessment = PsychographicAssessment(
            assessment_id=assessment_id,
            primary_profile=primary.profile,
            primary_confidence=primary.confidence,
            secondary_profile=secondary.profile if secondary else None,
            secondary_confidence=secondary.confidence if secondary else 0.0,
            all_scores=profile_scores,
            motivation=metadata.get("motivation", ""),
            risk_tolerance=metadata.get("risk_tolerance", ""),
            persistence_level=metadata.get("persistence_level", ""),
            sophistication_ceiling=metadata.get("sophistication_ceiling", ""),
            estimated_resources=metadata.get("estimated_resources", ""),
            deterrence_strategy=metadata.get("deterrence_strategy", ""),
            deterrence_actions=metadata.get("deterrence_actions", []),
            response_priority=metadata.get("response_priority", ""),
            response_actions=metadata.get("response_actions", []),
        )

        self._total_assessments += 1
        self._profile_counts[primary.profile] = (
            self._profile_counts.get(primary.profile, 0) + 1
        )

        logger.info(
            f"Psychographic assessment: {primary.profile} "
            f"({primary.confidence:.0%}), "
            f"secondary={secondary.profile if secondary else 'none'} "
            f"({secondary.confidence:.0%} if secondary else ''), "
            f"motivation={metadata.get('motivation', '')}"
        )

        return assessment

    def _extract_features(
        self,
        fingerprint,
        technique_sequence: Optional[list[str]] = None,
        context: Optional[dict] = None,
    ) -> dict:
        """Extract scoring features from fingerprint and context."""
        features = {
            "sophistication": getattr(fingerprint, "sophistication", 0.5),
            "automation": getattr(fingerprint, "automation", 0.5),
            "stealth": getattr(fingerprint, "stealth", 0.5),
            "persistence": getattr(fingerprint, "persistence", 0.5),
            "adaptability": getattr(fingerprint, "adaptability", 0.5),
            "knowledge": getattr(fingerprint, "knowledge", 0.5),
            "time_pressure": 0.5,
            "credential_focus": 0.0,
            "data_exfil_focus": 0.0,
            "destruction_focus": 0.0,
            "recon_focus": 0.0,
            "business_hours": 0.5,
        }

        # Derive focus areas from technique sequence
        if technique_sequence:
            technique_set = set(technique_sequence)

            # Credential focus
            cred_techniques = {"T1003", "T1087", "T1098"}
            features["credential_focus"] = min(
                1.0, len(technique_set & cred_techniques) / 2
            )

            # Data exfiltration focus
            exfil_techniques = {"T1005", "T1041", "T1083"}
            features["data_exfil_focus"] = min(
                1.0, len(technique_set & exfil_techniques) / 2
            )

            # Destruction focus
            destruct_techniques = {"T1486", "T1070"}
            features["destruction_focus"] = min(
                1.0, len(technique_set & destruct_techniques)
            )

            # Recon focus
            recon_techniques = {"T1087", "T1082", "T1016", "T1049", "T1083"}
            features["recon_focus"] = min(
                1.0, len(technique_set & recon_techniques) / 3
            )

        # Time pressure from fingerprint vector
        vector = getattr(fingerprint, "vector", None)
        if vector is not None and len(vector) > 6:
            features["time_pressure"] = float(vector[6])

        # Business hours from active hours
        active_hours = getattr(fingerprint, "active_hours_peak", 12)
        if 8 <= active_hours <= 18:
            features["business_hours"] = 0.8
        elif 0 <= active_hours <= 5 or active_hours >= 22:
            features["business_hours"] = 0.2
        else:
            features["business_hours"] = 0.5

        # Additional context
        if context:
            for key, value in context.items():
                if key in features:
                    features[key] = float(value)

        return features

    def _score_profile(
        self,
        profile: str,
        weights: dict,
        features: dict,
    ) -> tuple[float, list[str]]:
        """
        Score a profile against observed features.

        Uses weighted cosine-like similarity between
        profile weights and observed features.
        """
        score = 0.0
        indicators = []

        for feature_name, profile_weight in weights.items():
            observed = features.get(feature_name, 0.5)

            # Similarity: 1 - |profile_weight - observed|
            similarity = 1.0 - abs(profile_weight - observed)
            weighted_similarity = similarity * profile_weight

            score += weighted_similarity

            # Track strong indicators
            if similarity > 0.8 and profile_weight > 0.6:
                indicators.append(
                    f"{feature_name}: observed={observed:.2f} "
                    f"matches profile weight={profile_weight:.2f}"
                )

        # Normalise by number of features
        score /= len(weights) if weights else 1

        return score, indicators

    def get_profile_description(self, profile: str) -> dict:
        """Get detailed description of a profile."""
        metadata = PROFILE_METADATA.get(profile, {})
        weights = PROFILE_WEIGHTS.get(profile, {})

        return {
            "profile": profile,
            "metadata": metadata,
            "feature_weights": weights,
        }

    def get_all_profiles(self) -> list[dict]:
        """Get descriptions of all profiles."""
        return [
            self.get_profile_description(p)
            for p in [
                AttackerProfile.MERCENARY,
                AttackerProfile.HACKTIVIST,
                AttackerProfile.OPERATIVE,
                AttackerProfile.THRILL_SEEKER,
                AttackerProfile.INSIDER,
            ]
        ]

    def get_stats(self) -> dict:
        """Return profiler statistics."""
        return {
            "total_assessments": self._total_assessments,
            "profile_distribution": dict(self._profile_counts),
            "profiles_available": 5,
        }


# Module-level singleton
_profiler: Optional[PsychographicProfiler] = None


def get_psychographic_profiler() -> PsychographicProfiler:
    """Get or create the singleton PsychographicProfiler instance."""
    global _profiler
    if _profiler is None:
        _profiler = PsychographicProfiler()
    return _profiler
