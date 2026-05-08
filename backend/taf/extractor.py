"""
IMMUNIS ACIN — Threat Actor Fingerprint Extractor

WHY: Every attacker leaves a behavioural signature — their choice
of tools, the order of their techniques, their timing patterns,
their objectives, and their response to defences. This signature
is as unique as a fingerprint and far harder to forge than an IP
address or user agent string.

The extractor converts raw capture data into a dense 128-dimensional
behavioural vector that can be clustered, compared, and tracked
across sessions, campaigns, and even organisations (via the mesh).

Feature engineering:
  Dimensions 0-7:   Hand-crafted behavioural features
  Dimensions 8-27:  MITRE ATT&CK tactic distribution
  Dimensions 28-47: Temporal features (timing, rhythm)
  Dimensions 48-67: Command diversity features
  Dimensions 68-87: Active hours encoding (circadian)
  Dimensions 88-107: Tool and technique co-occurrence
  Dimensions 108-127: Session dynamics (escalation pattern)

Mathematical foundation:
  Feature vector: f ∈ ℝ¹²⁸, L2-normalised
  Similarity: cos(f₁, f₂) = f₁ · f₂ / (‖f₁‖ · ‖f₂‖)
  Distance: d(f₁, f₂) = 1 - cos(f₁, f₂)

  For temporal features, we use circular statistics:
    mean_angle = atan2(Σ sin(2π·hᵢ/24), Σ cos(2π·hᵢ/24))
    concentration = ‖Σ e^(j·2π·hᵢ/24)‖ / n  (von Mises κ)
"""

import logging
import math
import hashlib
from typing import Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger("immunis.taf.extractor")

VECTOR_DIM = 128

# Tool indices for co-occurrence encoding
TOOL_INDEX = {
    "nmap": 0, "metasploit": 1, "sqlmap": 2, "hydra": 3,
    "john_the_ripper": 4, "hashcat": 5, "burp_suite": 6,
    "nikto": 7, "dirb": 8, "gobuster": 9, "netcat": 10,
    "python_script": 11, "perl_script": 12, "powershell": 13,
    "cobalt_strike": 14, "empire": 15, "bloodhound": 16,
    "mimikatz": 17, "custom_tool": 18, "wget": 19,
}

# Tactic indices for distribution encoding
TACTIC_INDEX = {
    "reconnaissance": 0, "resource_development": 1,
    "initial_access": 2, "execution": 3,
    "persistence": 4, "privilege_escalation": 5,
    "defense_evasion": 6, "credential_access": 7,
    "discovery": 8, "lateral_movement": 9,
    "collection": 10, "command_and_control": 11,
    "exfiltration": 12, "impact": 13,
}


@dataclass
class BehaviouralFingerprint:
    """A computed behavioural fingerprint for a threat actor."""
    fingerprint_id: str
    vector: np.ndarray  # 128-dim L2-normalised
    source_capture_ids: list[str] = field(default_factory=list)
    attacker_ip: str = ""
    computed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Summary features (human-readable)
    sophistication: float = 0.0
    automation: float = 0.0
    stealth: float = 0.0
    persistence: float = 0.0
    adaptability: float = 0.0
    knowledge: float = 0.0
    primary_tactic: str = ""
    primary_tools: list[str] = field(default_factory=list)
    active_hours_peak: int = 0  # 0-23
    threat_level: str = "unknown"

    def similarity(self, other: "BehaviouralFingerprint") -> float:
        """Compute cosine similarity with another fingerprint."""
        dot = np.dot(self.vector, other.vector)
        norm_a = np.linalg.norm(self.vector)
        norm_b = np.linalg.norm(other.vector)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return float(dot / (norm_a * norm_b))

    def distance(self, other: "BehaviouralFingerprint") -> float:
        """Compute cosine distance (1 - similarity)."""
        return 1.0 - self.similarity(other)

    def to_dict(self) -> dict:
        return {
            "fingerprint_id": self.fingerprint_id,
            "vector_dim": len(self.vector),
            "source_captures": self.source_capture_ids,
            "attacker_ip": self.attacker_ip,
            "computed_at": self.computed_at,
            "sophistication": round(self.sophistication, 3),
            "automation": round(self.automation, 3),
            "stealth": round(self.stealth, 3),
            "persistence": round(self.persistence, 3),
            "adaptability": round(self.adaptability, 3),
            "knowledge": round(self.knowledge, 3),
            "primary_tactic": self.primary_tactic,
            "primary_tools": self.primary_tools,
            "active_hours_peak": self.active_hours_peak,
            "threat_level": self.threat_level,
        }


class FingerprintExtractor:
    """
    Extracts 128-dimensional behavioural fingerprints from
    attacker session captures.

    Can extract from:
    1. A single capture session
    2. Multiple sessions (aggregated profile)
    3. Raw feature dicts (for external data)

    All vectors are L2-normalised for cosine similarity.
    """

    def __init__(self):
        self._total_extractions: int = 0
        self._fingerprints: dict[str, BehaviouralFingerprint] = {}

        logger.info("Fingerprint extractor initialised")

    def extract_from_capture(self, capture) -> BehaviouralFingerprint:
        """
        Extract fingerprint from a SessionCapture object.

        Args:
            capture: SessionCapture from the capture engine.

        Returns:
            BehaviouralFingerprint with 128-dim vector.
        """
        vector = np.zeros(VECTOR_DIM, dtype=np.float64)

        # --- Dimensions 0-7: Hand-crafted behavioural features ---
        vector[0] = getattr(capture, "sophistication_score", 0.0)
        vector[1] = self._compute_automation(capture)
        vector[2] = self._compute_stealth(capture)
        vector[3] = self._compute_objective_clarity(capture)
        vector[4] = min(1.0, getattr(capture, "duration_s", 0) / 1800)
        vector[5] = self._compute_adaptability(capture)
        vector[6] = self._compute_time_pressure(capture)
        vector[7] = self._compute_knowledge(capture)

        # --- Dimensions 8-27: MITRE ATT&CK tactic distribution ---
        techniques = getattr(capture, "techniques_observed", [])
        tactic_counts = {}
        for t in techniques:
            tactic = getattr(t, "tactic", "")
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

        total_techniques = sum(tactic_counts.values()) or 1
        for tactic, idx in TACTIC_INDEX.items():
            vector[8 + idx] = tactic_counts.get(tactic, 0) / total_techniques

        # --- Dimensions 28-47: Temporal features ---
        intervals = getattr(capture, "inter_command_intervals", [])
        if intervals:
            arr = np.array(intervals)
            vector[28] = min(1.0, np.mean(arr) / 60)
            vector[29] = min(1.0, np.std(arr) / 30)
            vector[30] = min(1.0, np.median(arr) / 60)
            vector[31] = min(1.0, np.min(arr) / 10) if len(arr) > 0 else 0
            vector[32] = min(1.0, np.max(arr) / 300) if len(arr) > 0 else 0

            # Rhythm regularity (coefficient of variation)
            mean_interval = np.mean(arr)
            if mean_interval > 0:
                cv = np.std(arr) / mean_interval
                vector[33] = min(1.0, cv)

            # Acceleration (are they speeding up or slowing down?)
            if len(arr) > 5:
                first_half = np.mean(arr[:len(arr)//2])
                second_half = np.mean(arr[len(arr)//2:])
                if first_half > 0:
                    vector[34] = min(1.0, max(0.0, (first_half - second_half) / first_half))

            # Burst detection (clusters of rapid commands)
            burst_threshold = 1.0  # seconds
            bursts = sum(1 for i in arr if i < burst_threshold)
            vector[35] = min(1.0, bursts / (len(arr) + 1))

        # Circadian encoding
        active_hours = getattr(capture, "active_hours", [])
        if active_hours:
            # Von Mises circular statistics
            angles = [2 * math.pi * h / 24 for h in active_hours]
            sin_sum = sum(math.sin(a) for a in angles)
            cos_sum = sum(math.cos(a) for a in angles)
            mean_angle = math.atan2(sin_sum, cos_sum)
            concentration = math.sqrt(sin_sum**2 + cos_sum**2) / len(angles)

            vector[36] = (mean_angle + math.pi) / (2 * math.pi)  # Normalise to 0-1
            vector[37] = concentration

            # Peak hour
            peak_hour = int((mean_angle / (2 * math.pi)) * 24) % 24
            vector[38] = peak_hour / 24.0

        # --- Dimensions 48-67: Command diversity features ---
        commands = getattr(capture, "commands", [])
        if commands:
            unique_cmds = set()
            cmd_lengths = []
            for cmd in commands:
                inp = cmd.get("input", "") if isinstance(cmd, dict) else ""
                if inp:
                    unique_cmds.add(inp.split()[0] if inp.split() else "")
                    cmd_lengths.append(len(inp))

            vector[48] = min(1.0, len(unique_cmds) / 20)
            vector[49] = min(1.0, len(commands) / 100)

            if cmd_lengths:
                vector[50] = min(1.0, np.mean(cmd_lengths) / 100)
                vector[51] = min(1.0, np.std(cmd_lengths) / 50)
                vector[52] = min(1.0, max(cmd_lengths) / 500)

        cred_attempts = getattr(capture, "credential_attempts", [])
        vector[53] = min(1.0, len(cred_attempts) / 10)

        payloads = getattr(capture, "payload_samples", [])
        vector[54] = min(1.0, len(payloads) / 5)

        # Unique usernames tried
        if cred_attempts:
            unique_users = len(set(
                getattr(c, "username", "") for c in cred_attempts
            ))
            vector[55] = min(1.0, unique_users / 10)

        # --- Dimensions 68-87: Active hours circular encoding ---
        for hour in active_hours:
            angle = 2 * math.pi * hour / 24
            idx = 68 + (hour % 20)
            vector[idx] = max(vector[idx], math.cos(angle) * 0.5 + 0.5)

        # --- Dimensions 88-107: Tool co-occurrence ---
        tools = getattr(capture, "tools_detected", [])
        for tool in tools:
            idx = TOOL_INDEX.get(tool)
            if idx is not None and (88 + idx) < 108:
                vector[88 + idx] = 1.0

        # --- Dimensions 108-127: Session dynamics ---
        # Technique progression (what order do they use tactics?)
        if techniques:
            for i, t in enumerate(techniques[:20]):
                tactic = getattr(t, "tactic", "")
                tactic_idx = TACTIC_INDEX.get(tactic, 0)
                dim = 108 + min(i, 19)
                vector[dim] = tactic_idx / 14.0  # Normalise

        # L2 normalise
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm

        # Build fingerprint
        fp_id = hashlib.sha256(
            f"{getattr(capture, 'capture_id', '')}:{id(vector)}".encode()
        ).hexdigest()[:16]

        # Determine primary tactic
        primary_tactic = ""
        if tactic_counts:
            primary_tactic = max(tactic_counts, key=tactic_counts.get)

        # Determine peak hour
        peak_hour = 0
        if active_hours:
            angles = [2 * math.pi * h / 24 for h in active_hours]
            mean_angle = math.atan2(
                sum(math.sin(a) for a in angles),
                sum(math.cos(a) for a in angles),
            )
            peak_hour = int((mean_angle / (2 * math.pi)) * 24) % 24

        fingerprint = BehaviouralFingerprint(
            fingerprint_id=fp_id,
            vector=vector,
            source_capture_ids=[getattr(capture, "capture_id", "")],
            attacker_ip=getattr(capture, "attacker_ip", ""),
            sophistication=float(vector[0]),
            automation=float(vector[1]),
            stealth=float(vector[2]),
            persistence=float(vector[4]),
            adaptability=float(vector[5]),
            knowledge=float(vector[7]),
            primary_tactic=primary_tactic,
            primary_tools=tools[:5],
            active_hours_peak=peak_hour,
            threat_level=getattr(capture, "threat_level", "unknown"),
        )

        self._fingerprints[fp_id] = fingerprint
        self._total_extractions += 1

        logger.info(
            f"Fingerprint extracted: {fp_id} from {fingerprint.attacker_ip}, "
            f"sophistication={fingerprint.sophistication:.2f}, "
            f"primary_tactic={primary_tactic}"
        )

        return fingerprint

    def extract_from_features(self, features: dict) -> BehaviouralFingerprint:
        """
        Extract fingerprint from a raw feature dictionary.

        Useful for external data or manual feature specification.
        """
        vector = np.zeros(VECTOR_DIM, dtype=np.float64)

        # Map known features to vector dimensions
        feature_map = {
            "sophistication": 0, "automation": 1, "stealth": 2,
            "objective_clarity": 3, "persistence": 4, "adaptability": 5,
            "time_pressure": 6, "knowledge": 7,
        }

        for name, idx in feature_map.items():
            if name in features:
                vector[idx] = float(features[name])

        # Tactic distribution
        tactics = features.get("tactic_distribution", {})
        for tactic, weight in tactics.items():
            idx = TACTIC_INDEX.get(tactic)
            if idx is not None:
                vector[8 + idx] = float(weight)

        # Tools
        tools = features.get("tools", [])
        for tool in tools:
            idx = TOOL_INDEX.get(tool)
            if idx is not None and (88 + idx) < 108:
                vector[88 + idx] = 1.0

        # L2 normalise
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm

        fp_id = hashlib.sha256(
            str(features).encode()
        ).hexdigest()[:16]

        fingerprint = BehaviouralFingerprint(
            fingerprint_id=fp_id,
            vector=vector,
            attacker_ip=features.get("attacker_ip", ""),
            sophistication=float(vector[0]),
            automation=float(vector[1]),
            stealth=float(vector[2]),
            persistence=float(vector[4]),
            adaptability=float(vector[5]),
            knowledge=float(vector[7]),
            primary_tools=tools[:5],
            threat_level=features.get("threat_level", "unknown"),
        )

        self._fingerprints[fp_id] = fingerprint
        self._total_extractions += 1

        return fingerprint

    def aggregate_fingerprints(
        self,
        fingerprints: list[BehaviouralFingerprint],
    ) -> BehaviouralFingerprint:
        """
        Aggregate multiple fingerprints into a single profile.

        Uses weighted average where more recent fingerprints
        have higher weight (exponential decay).
        """
        if not fingerprints:
            return BehaviouralFingerprint(
                fingerprint_id="empty",
                vector=np.zeros(VECTOR_DIM),
            )

        if len(fingerprints) == 1:
            return fingerprints[0]

        # Exponential decay weighting (most recent = highest weight)
        n = len(fingerprints)
        weights = np.array([math.exp(-0.5 * (n - 1 - i)) for i in range(n)])
        weights /= weights.sum()

        # Weighted average of vectors
        vectors = np.array([fp.vector for fp in fingerprints])
        aggregated = np.average(vectors, axis=0, weights=weights)

        # L2 normalise
        norm = np.linalg.norm(aggregated)
        if norm > 0:
            aggregated = aggregated / norm

        fp_id = hashlib.sha256(
            "|".join(fp.fingerprint_id for fp in fingerprints).encode()
        ).hexdigest()[:16]

        all_capture_ids = []
        all_tools = set()
        for fp in fingerprints:
            all_capture_ids.extend(fp.source_capture_ids)
            all_tools.update(fp.primary_tools)

        return BehaviouralFingerprint(
            fingerprint_id=fp_id,
            vector=aggregated,
            source_capture_ids=all_capture_ids,
            attacker_ip=fingerprints[-1].attacker_ip,
            sophistication=float(aggregated[0]),
            automation=float(aggregated[1]),
            stealth=float(aggregated[2]),
            persistence=float(aggregated[4]),
            adaptability=float(aggregated[5]),
            knowledge=float(aggregated[7]),
            primary_tools=sorted(all_tools)[:5],
            threat_level=fingerprints[-1].threat_level,
        )

    def find_similar(
        self,
        fingerprint: BehaviouralFingerprint,
        threshold: float = 0.7,
        limit: int = 10,
    ) -> list[tuple[BehaviouralFingerprint, float]]:
        """Find fingerprints similar to the given one."""
        results = []

        for fp in self._fingerprints.values():
            if fp.fingerprint_id == fingerprint.fingerprint_id:
                continue
            sim = fingerprint.similarity(fp)
            if sim >= threshold:
                results.append((fp, sim))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:limit]

    # ------------------------------------------------------------------
    # FEATURE COMPUTATION HELPERS
    # ------------------------------------------------------------------

    def _compute_automation(self, capture) -> float:
        intervals = getattr(capture, "inter_command_intervals", [])
        if not intervals:
            return 0.5
        arr = np.array(intervals)
        if len(arr) > 3:
            cv = np.std(arr) / (np.mean(arr) + 0.001)
            if cv < 0.1:
                return 0.9
            elif cv < 0.3:
                return 0.6
        if len(arr) > 0 and np.mean(arr) < 0.5:
            return 0.95
        return 0.4

    def _compute_stealth(self, capture) -> float:
        score = 0.5
        techniques = getattr(capture, "techniques_observed", [])
        if any(getattr(t, "technique_id", "") == "T1070" for t in techniques):
            score += 0.2
        total_cmds = getattr(capture, "total_commands", 0)
        duration = getattr(capture, "duration_s", 0)
        if total_cmds < 10 and duration > 60:
            score += 0.15
        creds = getattr(capture, "credential_attempts", [])
        if len(creds) > 20:
            score -= 0.3
        return max(0.0, min(1.0, score))

    def _compute_objective_clarity(self, capture) -> float:
        score = 0.3
        commands = getattr(capture, "commands", [])
        targets = [".env", "credentials", "password", "secret", "config", "key"]
        for cmd in commands:
            inp = cmd.get("input", "").lower() if isinstance(cmd, dict) else ""
            if any(t in inp for t in targets):
                score += 0.1
        return min(1.0, score)

    def _compute_adaptability(self, capture) -> float:
        techniques = getattr(capture, "techniques_observed", [])
        unique = len(set(getattr(t, "technique_id", "") for t in techniques))
        return min(1.0, unique / 10)

    def _compute_time_pressure(self, capture) -> float:
        intervals = getattr(capture, "inter_command_intervals", [])
        if intervals:
            avg = np.mean(intervals)
            return max(0.0, 1.0 - (avg / 30))
        return 0.5

    def _compute_knowledge(self, capture) -> float:
        score = 0.2
        commands = getattr(capture, "commands", [])
        if commands:
            errors = sum(
                1 for c in commands
                if "not found" in (c.get("output", "") if isinstance(c, dict) else "")
            )
            if len(commands) > 0:
                score += (1.0 - errors / len(commands)) * 0.3
        techniques = getattr(capture, "techniques_observed", [])
        advanced = {"privilege_escalation", "defense_evasion", "lateral_movement"}
        if any(getattr(t, "tactic", "") in advanced for t in techniques):
            score += 0.2
        tools = getattr(capture, "tools_detected", [])
        if len(tools) > 3:
            score += 0.15
        return min(1.0, score)

    def get_all_fingerprints(self) -> list[dict]:
        """Get all stored fingerprints."""
        return [fp.to_dict() for fp in self._fingerprints.values()]

    def get_stats(self) -> dict:
        return {
            "total_extractions": self._total_extractions,
            "stored_fingerprints": len(self._fingerprints),
            "vector_dimension": VECTOR_DIM,
        }


# Module-level singleton
_extractor: Optional[FingerprintExtractor] = None


def get_fingerprint_extractor() -> FingerprintExtractor:
    """Get or create the singleton FingerprintExtractor instance."""
    global _extractor
    if _extractor is None:
        _extractor = FingerprintExtractor()
    return _extractor
