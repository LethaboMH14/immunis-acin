"""
IMMUNIS ACIN — Next-Attack Predictor

WHY: If you know WHO is attacking and HOW they've behaved before,
you can predict WHAT they'll do next. The predictor uses Markov
chains on technique sequences, hot buffer analysis for active
campaigns, and cluster-based prediction for new actors.

Prediction types:
1. Next technique — what MITRE ATT&CK technique comes next?
2. Next target — which asset will be targeted next?
3. Escalation probability — will the attacker escalate?
4. Campaign duration — how long will this campaign last?
5. Objective prediction — what is the attacker's end goal?

Mathematical foundation:
  Technique Markov chain:
    P(T_{n+1} = j | T_n = i) = transition_matrix[i][j]
    Built from historical technique sequences

  Hot buffer:
    Active campaigns in the last N hours
    Weighted by recency: w(t) = e^(-λ·age_hours)

  Escalation probability:
    P(escalate) = σ(w · features)
    Features: sophistication, persistence, depth, time_invested
    σ = logistic sigmoid
"""

import logging
import math
import time
from typing import Optional
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from collections import defaultdict

import numpy as np

logger = logging.getLogger("immunis.taf.predictor")


@dataclass
class TechniquePrediction:
    """Prediction of the next MITRE ATT&CK technique."""
    predicted_technique: str
    technique_name: str
    probability: float
    alternatives: list[dict] = field(default_factory=list)  # [{technique, name, probability}]
    confidence: float = 0.0
    basis: str = ""  # "markov", "cluster", "heuristic"


@dataclass
class EscalationPrediction:
    """Prediction of attacker escalation."""
    will_escalate: bool
    probability: float
    predicted_escalation_type: str  # privilege_escalation, lateral_movement, etc.
    time_to_escalation_min: float = 0.0
    confidence: float = 0.0
    risk_factors: list[str] = field(default_factory=list)


@dataclass
class CampaignPrediction:
    """Prediction about an ongoing campaign."""
    campaign_cluster_id: Optional[str] = None
    predicted_objective: str = "unknown"
    objective_confidence: float = 0.0
    predicted_duration_hours: float = 0.0
    predicted_next_target: str = ""
    predicted_next_technique: Optional[TechniquePrediction] = None
    escalation: Optional[EscalationPrediction] = None
    risk_score: float = 0.0
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "campaign_cluster_id": self.campaign_cluster_id,
            "predicted_objective": self.predicted_objective,
            "objective_confidence": round(self.objective_confidence, 3),
            "predicted_duration_hours": round(self.predicted_duration_hours, 1),
            "predicted_next_target": self.predicted_next_target,
            "predicted_next_technique": {
                "technique": self.predicted_next_technique.predicted_technique,
                "name": self.predicted_next_technique.technique_name,
                "probability": round(self.predicted_next_technique.probability, 3),
            } if self.predicted_next_technique else None,
            "escalation": {
                "will_escalate": self.escalation.will_escalate,
                "probability": round(self.escalation.probability, 3),
                "type": self.escalation.predicted_escalation_type,
            } if self.escalation else None,
            "risk_score": round(self.risk_score, 3),
            "recommendations": self.recommendations,
        }


# Common technique sequences (learned from threat intelligence)
TECHNIQUE_NAMES = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Unix Shell",
    "T1059.006": "Python",
    "T1003": "OS Credential Dumping",
    "T1087": "Account Discovery",
    "T1082": "System Information Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1049": "System Network Connections Discovery",
    "T1083": "File and Directory Discovery",
    "T1005": "Data from Local System",
    "T1041": "Exfiltration Over C2 Channel",
    "T1053": "Scheduled Task/Job",
    "T1098": "Account Manipulation",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1070": "Indicator Removal",
    "T1021": "Remote Services",
    "T1486": "Data Encrypted for Impact",
}

# Objective indicators (technique patterns → likely objective)
OBJECTIVE_PATTERNS = {
    "data_theft": ["T1005", "T1041", "T1083", "T1003"],
    "ransomware": ["T1486", "T1059", "T1548"],
    "espionage": ["T1087", "T1082", "T1016", "T1049", "T1005"],
    "credential_harvesting": ["T1003", "T1087", "T1098"],
    "lateral_movement": ["T1021", "T1087", "T1016"],
    "persistence": ["T1053", "T1098", "T1059"],
    "destruction": ["T1486", "T1070"],
}


class NextAttackPredictor:
    """
    Predicts attacker next moves using Markov chains,
    cluster analysis, and heuristic rules.

    Usage:
        predictor = NextAttackPredictor()

        # Train from historical data
        predictor.train_from_captures(captures)

        # Predict next technique
        prediction = predictor.predict_next_technique(["T1087", "T1082", "T1003"])

        # Full campaign prediction
        campaign = predictor.predict_campaign(fingerprint, technique_sequence)
    """

    HOT_BUFFER_HOURS = 24
    HOT_BUFFER_DECAY = 0.1  # λ for exponential decay

    def __init__(self):
        # Technique transition matrix (Markov chain)
        self._transition_counts: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._transition_matrix: dict[str, dict[str, float]] = {}
        self._technique_counts: dict[str, int] = defaultdict(int)

        # Hot buffer (recent active campaigns)
        self._hot_buffer: list[dict] = []

        # Statistics
        self._total_predictions: int = 0
        self._training_sequences: int = 0

        logger.info("Next-attack predictor initialised")

    def train_from_captures(self, captures: list) -> None:
        """
        Train the Markov chain from historical capture data.

        Extracts technique sequences from each capture and
        builds the transition probability matrix.
        """
        for capture in captures:
            techniques = getattr(capture, "techniques_observed", [])
            if len(techniques) < 2:
                continue

            sequence = [
                getattr(t, "technique_id", "")
                for t in techniques
                if getattr(t, "technique_id", "")
            ]

            self._add_sequence(sequence)

        self._rebuild_transition_matrix()

        logger.info(
            f"Predictor trained: {self._training_sequences} sequences, "
            f"{len(self._transition_matrix)} states"
        )

    def train_from_sequences(self, sequences: list[list[str]]) -> None:
        """Train from raw technique ID sequences."""
        for sequence in sequences:
            self._add_sequence(sequence)
        self._rebuild_transition_matrix()

    def _add_sequence(self, sequence: list[str]) -> None:
        """Add a technique sequence to the training data."""
        if len(sequence) < 2:
            return

        for i in range(len(sequence) - 1):
            current = sequence[i]
            next_tech = sequence[i + 1]
            self._transition_counts[current][next_tech] += 1
            self._technique_counts[current] += 1

        self._technique_counts[sequence[-1]] += 1
        self._training_sequences += 1

    def _rebuild_transition_matrix(self) -> None:
        """Rebuild normalised transition probabilities."""
        self._transition_matrix = {}

        for from_tech, to_counts in self._transition_counts.items():
            total = sum(to_counts.values())
            if total > 0:
                self._transition_matrix[from_tech] = {
                    to_tech: count / total
                    for to_tech, count in to_counts.items()
                }

    def predict_next_technique(
        self,
        technique_sequence: list[str],
        top_k: int = 5,
    ) -> TechniquePrediction:
        """
        Predict the next technique given a sequence.

        Uses:
        1. Markov chain (if trained)
        2. Heuristic rules (fallback)
        """
        if not technique_sequence:
            return TechniquePrediction(
                predicted_technique="T1087",
                technique_name="Account Discovery",
                probability=0.3,
                basis="heuristic",
                confidence=0.2,
            )

        last_technique = technique_sequence[-1]

        # Try Markov chain
        if last_technique in self._transition_matrix:
            transitions = self._transition_matrix[last_technique]
            sorted_transitions = sorted(
                transitions.items(),
                key=lambda x: x[1],
                reverse=True,
            )

            if sorted_transitions:
                best = sorted_transitions[0]
                alternatives = [
                    {
                        "technique": t,
                        "name": TECHNIQUE_NAMES.get(t, t),
                        "probability": round(p, 3),
                    }
                    for t, p in sorted_transitions[1:top_k]
                ]

                return TechniquePrediction(
                    predicted_technique=best[0],
                    technique_name=TECHNIQUE_NAMES.get(best[0], best[0]),
                    probability=best[1],
                    alternatives=alternatives,
                    confidence=min(1.0, best[1] + 0.2),
                    basis="markov",
                )

        # Fallback: heuristic prediction based on common attack chains
        return self._heuristic_prediction(technique_sequence)

    def _heuristic_prediction(
        self,
        sequence: list[str],
    ) -> TechniquePrediction:
        """Heuristic next-technique prediction."""
        # Common attack progression
        progression = {
            "T1087": ("T1082", "System Information Discovery"),
            "T1082": ("T1016", "System Network Configuration Discovery"),
            "T1016": ("T1049", "System Network Connections Discovery"),
            "T1049": ("T1083", "File and Directory Discovery"),
            "T1083": ("T1005", "Data from Local System"),
            "T1005": ("T1041", "Exfiltration Over C2 Channel"),
            "T1003": ("T1548", "Abuse Elevation Control Mechanism"),
            "T1548": ("T1021", "Remote Services"),
            "T1021": ("T1005", "Data from Local System"),
            "T1059": ("T1083", "File and Directory Discovery"),
            "T1059.004": ("T1083", "File and Directory Discovery"),
        }

        last = sequence[-1] if sequence else ""
        if last in progression:
            next_tech, next_name = progression[last]
            return TechniquePrediction(
                predicted_technique=next_tech,
                technique_name=next_name,
                probability=0.4,
                basis="heuristic",
                confidence=0.3,
            )

        # Default: discovery
        return TechniquePrediction(
            predicted_technique="T1083",
            technique_name="File and Directory Discovery",
            probability=0.2,
            basis="heuristic",
            confidence=0.1,
        )

    def predict_escalation(
        self,
        fingerprint,
        technique_sequence: list[str],
        dwell_time_s: float = 0,
    ) -> EscalationPrediction:
        """
        Predict whether the attacker will escalate.

        Uses logistic regression on behavioural features.
        """
        # Feature extraction
        sophistication = getattr(fingerprint, "sophistication", 0.5)
        persistence = getattr(fingerprint, "persistence", 0.5)
        knowledge = getattr(fingerprint, "knowledge", 0.5)
        depth = len(technique_sequence)
        time_invested = min(1.0, dwell_time_s / 1800)

        # Has the attacker already shown escalation behaviour?
        escalation_techniques = {"T1548", "T1021", "T1053", "T1098"}
        has_escalated = any(t in escalation_techniques for t in technique_sequence)

        # Logistic regression (hand-tuned weights)
        features = np.array([
            sophistication,
            persistence,
            knowledge,
            min(1.0, depth / 10),
            time_invested,
            1.0 if has_escalated else 0.0,
        ])

        weights = np.array([0.8, 0.6, 0.5, 0.4, 0.3, 1.5])
        bias = -2.0

        logit = np.dot(features, weights) + bias
        probability = 1.0 / (1.0 + math.exp(-logit))

        will_escalate = probability > 0.5

        # Predict escalation type
        if has_escalated:
            escalation_type = "lateral_movement"
        elif sophistication > 0.6:
            escalation_type = "privilege_escalation"
        else:
            escalation_type = "persistence"

        # Time to escalation estimate
        if will_escalate and dwell_time_s > 0:
            # Estimate based on current pace
            time_to_escalation = max(5.0, (1.0 - probability) * 60)
        else:
            time_to_escalation = 0.0

        # Risk factors
        risk_factors = []
        if sophistication > 0.6:
            risk_factors.append("High sophistication attacker")
        if persistence > 0.7:
            risk_factors.append("Persistent attacker (long dwell time)")
        if has_escalated:
            risk_factors.append("Already demonstrated escalation techniques")
        if depth > 5:
            risk_factors.append(f"Deep technique chain ({depth} techniques)")

        return EscalationPrediction(
            will_escalate=will_escalate,
            probability=round(float(probability), 3),
            predicted_escalation_type=escalation_type,
            time_to_escalation_min=round(time_to_escalation, 1),
            confidence=round(abs(probability - 0.5) * 2, 3),
            risk_factors=risk_factors,
        )

    def predict_objective(
        self,
        technique_sequence: list[str],
    ) -> tuple[str, float]:
        """
        Predict the attacker's objective from technique sequence.

        Matches observed techniques against known objective patterns.
        """
        if not technique_sequence:
            return "unknown", 0.0

        technique_set = set(technique_sequence)
        best_objective = "unknown"
        best_score = 0.0

        for objective, pattern_techniques in OBJECTIVE_PATTERNS.items():
            overlap = len(technique_set & set(pattern_techniques))
            if len(pattern_techniques) > 0:
                score = overlap / len(pattern_techniques)
                if score > best_score:
                    best_score = score
                    best_objective = objective

        return best_objective, round(best_score, 3)

    def predict_campaign(
        self,
        fingerprint,
        technique_sequence: list[str],
        dwell_time_s: float = 0,
        cluster_id: Optional[str] = None,
    ) -> CampaignPrediction:
        """
        Full campaign prediction combining all prediction types.
        """
        self._total_predictions += 1

        # Next technique
        next_technique = self.predict_next_technique(technique_sequence)

        # Escalation
        escalation = self.predict_escalation(
            fingerprint, technique_sequence, dwell_time_s
        )

        # Objective
        objective, obj_confidence = self.predict_objective(technique_sequence)

        # Duration estimate (based on sophistication and persistence)
        sophistication = getattr(fingerprint, "sophistication", 0.5)
        persistence = getattr(fingerprint, "persistence", 0.5)
        estimated_duration = (sophistication * 12 + persistence * 24) / 2

        # Risk score
        risk_score = (
            sophistication * 0.3
            + escalation.probability * 0.3
            + obj_confidence * 0.2
            + min(1.0, dwell_time_s / 3600) * 0.2
        )

        # Recommendations
        recommendations = []
        if escalation.will_escalate:
            recommendations.append(
                f"Attacker likely to escalate via {escalation.predicted_escalation_type} — "
                f"reinforce defences on privileged access"
            )
        if objective == "data_theft":
            recommendations.append(
                "Objective appears to be data theft — monitor data egress points"
            )
        elif objective == "ransomware":
            recommendations.append(
                "Ransomware indicators detected — verify backup integrity immediately"
            )
        elif objective == "credential_harvesting":
            recommendations.append(
                "Credential harvesting in progress — rotate exposed credentials"
            )

        if risk_score > 0.7:
            recommendations.append(
                "HIGH RISK: Consider isolating affected systems"
            )

        prediction = CampaignPrediction(
            campaign_cluster_id=cluster_id,
            predicted_objective=objective,
            objective_confidence=obj_confidence,
            predicted_duration_hours=round(estimated_duration, 1),
            predicted_next_target="",
            predicted_next_technique=next_technique,
            escalation=escalation,
            risk_score=round(risk_score, 3),
            recommendations=recommendations,
        )

        logger.info(
            f"Campaign prediction: objective={objective} ({obj_confidence:.0%}), "
            f"next={next_technique.predicted_technique}, "
            f"escalation={escalation.probability:.0%}, "
            f"risk={risk_score:.2f}"
        )

        return prediction

    def update_hot_buffer(
        self,
        attacker_ip: str,
        technique: str,
        timestamp: Optional[str] = None,
    ) -> None:
        """Add an observation to the hot buffer."""
        self._hot_buffer.append({
            "attacker_ip": attacker_ip,
            "technique": technique,
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        })

        # Prune old entries
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.HOT_BUFFER_HOURS)
        self._hot_buffer = [
            entry for entry in self._hot_buffer
            if entry["timestamp"] > cutoff.isoformat()
        ]

    def get_hot_buffer_summary(self) -> dict:
        """Get summary of the hot buffer (active campaigns)."""
        if not self._hot_buffer:
            return {"active_campaigns": 0, "entries": 0}

        # Group by attacker IP
        ip_groups: dict[str, list[dict]] = defaultdict(list)
        for entry in self._hot_buffer:
            ip_groups[entry["attacker_ip"]].append(entry)

        campaigns = []
        for ip, entries in ip_groups.items():
            techniques = [e["technique"] for e in entries]
            campaigns.append({
                "attacker_ip": ip,
                "technique_count": len(techniques),
                "unique_techniques": len(set(techniques)),
                "last_seen": max(e["timestamp"] for e in entries),
                "techniques": techniques[-10:],  # Last 10
            })

        return {
            "active_campaigns": len(campaigns),
            "entries": len(self._hot_buffer),
            "campaigns": campaigns,
        }

    def get_stats(self) -> dict:
        """Return predictor statistics."""
        return {
            "total_predictions": self._total_predictions,
            "training_sequences": self._training_sequences,
            "transition_states": len(self._transition_matrix),
            "technique_vocabulary": len(self._technique_counts),
            "hot_buffer_size": len(self._hot_buffer),
        }


# Module-level singleton
_predictor: Optional[NextAttackPredictor] = None


def get_predictor() -> NextAttackPredictor:
    """Get or create the singleton NextAttackPredictor instance."""
    global _predictor
    if _predictor is None:
        _predictor = NextAttackPredictor()
    return _predictor
