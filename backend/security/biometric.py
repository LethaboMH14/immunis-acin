"""
IMMUNIS ACIN — Behavioural Biometric Engine

WHY: Passwords and tokens can be stolen. Hardware keys can be cloned.
But HOW a human interacts with a system — their typing rhythm,
mouse movement patterns, command sequences, and session behaviour —
is unique and extremely difficult to forge in real time.

Behavioural biometrics provides CONTINUOUS authentication: not just
"are you who you claim to be at login?" but "are you STILL who you
claim to be, right now, during this privileged session?"

This is critical for IMMUNIS because:
1. A compromised operator session could poison the antibody library
2. An attacker who steals a session token could issue false lockouts
3. Autonomous operations (mesh broadcast, antibody promotion) need
   assurance that the authorising human is genuinely present

Mathematical foundation:
  Keystroke dynamics: digraph latency vector D ∈ ℝⁿ
  Baseline profile: μ_D, Σ_D from enrollment samples
  Mahalanobis distance: d(x) = √((x-μ)ᵀ Σ⁻¹ (x-μ))
  Authentication: d(x) < τ → genuine, d(x) ≥ τ → anomalous

  Session behaviour: command sequence as Markov chain
  Transition matrix P[i,j] = P(cmd_j | cmd_i)
  Cross-entropy: H(p,q) = -Σ p(x) log q(x)
  Anomaly when H(baseline, observed) > threshold

Feature flags: ENABLE_BIOMETRICS=true to activate (default: false)
"""

import logging
import time
import math
import hashlib
from typing import Optional
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger("immunis.security.biometric")


# ------------------------------------------------------------------
# DATA STRUCTURES
# ------------------------------------------------------------------

@dataclass
class KeystrokeSample:
    """A single keystroke timing sample."""
    key: str
    press_time: float  # epoch seconds
    release_time: float  # epoch seconds
    hold_duration_ms: float  # release - press
    flight_time_ms: Optional[float] = None  # time since previous key release


@dataclass
class CommandEvent:
    """A single command/action event in a session."""
    command: str
    timestamp: float
    parameters_hash: Optional[str] = None  # hash of parameters, not raw


@dataclass
class BiometricProfile:
    """
    Enrolled biometric profile for an operator.

    Contains baseline statistics computed from enrollment samples.
    """
    operator_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Keystroke dynamics
    digraph_means: dict[str, float] = field(default_factory=dict)
    digraph_stds: dict[str, float] = field(default_factory=dict)
    hold_mean_ms: float = 0.0
    hold_std_ms: float = 0.0
    typing_speed_cpm: float = 0.0  # characters per minute

    # Command sequence Markov chain
    transition_matrix: dict[str, dict[str, float]] = field(default_factory=dict)
    command_frequencies: dict[str, float] = field(default_factory=dict)

    # Session behaviour
    avg_session_duration_min: float = 0.0
    avg_commands_per_session: float = 0.0
    typical_active_hours: list[int] = field(default_factory=list)  # 0-23

    # Enrollment metadata
    enrollment_samples: int = 0
    min_enrollment_samples: int = 10


@dataclass
class SessionState:
    """Active session biometric state."""
    session_id: str
    operator_id: str
    started_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    keystroke_buffer: list[KeystrokeSample] = field(default_factory=list)
    command_history: list[CommandEvent] = field(default_factory=list)
    anomaly_scores: list[float] = field(default_factory=list)
    is_locked: bool = False
    confidence: float = 1.0  # 1.0 = fully trusted, 0.0 = fully anomalous


class BiometricEngine:
    """
    Continuous behavioural biometric authentication engine.

    Monitors operator behaviour during privileged sessions and
    raises alerts when behaviour deviates from enrolled profile.

    Three signal types:
    1. Keystroke dynamics — typing rhythm (digraph latencies, hold times)
    2. Command sequences — Markov chain of actions
    3. Session patterns — timing, duration, activity hours

    Anomaly detection uses Mahalanobis distance for keystroke dynamics
    and cross-entropy for command sequences.
    """

    # Thresholds
    MAHALANOBIS_THRESHOLD = 3.0  # standard deviations
    CROSS_ENTROPY_THRESHOLD = 2.5  # bits above baseline
    CONFIDENCE_DECAY_RATE = 0.05  # per anomalous event
    CONFIDENCE_RECOVERY_RATE = 0.02  # per normal event
    LOCKOUT_CONFIDENCE = 0.3  # lock session below this
    WARNING_CONFIDENCE = 0.5  # warn below this

    # Buffers
    KEYSTROKE_WINDOW = 50  # keystrokes to analyse at once
    COMMAND_WINDOW = 20  # commands to analyse at once
    MAX_ANOMALY_HISTORY = 100

    def __init__(self, enabled: bool = False):
        self._enabled = enabled
        self._profiles: dict[str, BiometricProfile] = {}
        self._sessions: dict[str, SessionState] = {}
        self._enrollment_buffers: dict[str, list[list[KeystrokeSample]]] = defaultdict(list)
        self._command_enrollment: dict[str, list[list[CommandEvent]]] = defaultdict(list)

        if enabled:
            logger.info("Behavioural biometric engine ENABLED")
        else:
            logger.info(
                "Behavioural biometric engine DISABLED "
                "(set ENABLE_BIOMETRICS=true to activate)"
            )

    @property
    def enabled(self) -> bool:
        return self._enabled

    # ------------------------------------------------------------------
    # ENROLLMENT
    # ------------------------------------------------------------------

    def start_enrollment(self, operator_id: str) -> str:
        """
        Begin enrollment for a new operator.

        Returns enrollment session ID. Operator must provide at least
        10 typing samples and 5 command sessions to build a profile.
        """
        if not self._enabled:
            return "biometrics_disabled"

        session_id = hashlib.sha256(
            f"{operator_id}:{time.time()}".encode()
        ).hexdigest()[:16]

        self._enrollment_buffers[operator_id] = []
        self._command_enrollment[operator_id] = []

        logger.info(f"Enrollment started for {operator_id} — session {session_id}")
        return session_id

    def submit_enrollment_sample(
        self,
        operator_id: str,
        keystrokes: list[KeystrokeSample],
        commands: Optional[list[CommandEvent]] = None,
    ) -> dict:
        """
        Submit a typing/command sample for enrollment.

        Returns enrollment progress.
        """
        if not self._enabled:
            return {"status": "disabled"}

        self._enrollment_buffers[operator_id].append(keystrokes)
        if commands:
            self._command_enrollment[operator_id].append(commands)

        keystroke_samples = len(self._enrollment_buffers[operator_id])
        command_samples = len(self._command_enrollment[operator_id])

        min_samples = 10
        ready = keystroke_samples >= min_samples

        progress = {
            "operator_id": operator_id,
            "keystroke_samples": keystroke_samples,
            "command_samples": command_samples,
            "min_required": min_samples,
            "ready_to_finalize": ready,
            "progress_pct": min(100, round(keystroke_samples / min_samples * 100)),
        }

        logger.debug(
            f"Enrollment sample {keystroke_samples} for {operator_id} "
            f"({progress['progress_pct']}%)"
        )

        return progress

    def finalize_enrollment(self, operator_id: str) -> BiometricProfile:
        """
        Compute biometric profile from enrollment samples.

        Builds:
        1. Digraph latency statistics (mean, std per key pair)
        2. Hold duration statistics
        3. Command transition matrix (Markov chain)
        4. Session behaviour baselines
        """
        if not self._enabled:
            return BiometricProfile(operator_id=operator_id)

        keystroke_sessions = self._enrollment_buffers.get(operator_id, [])
        command_sessions = self._command_enrollment.get(operator_id, [])

        if len(keystroke_sessions) < 5:
            raise ValueError(
                f"Insufficient enrollment data: {len(keystroke_sessions)} samples "
                f"(minimum 5 required)"
            )

        profile = BiometricProfile(
            operator_id=operator_id,
            enrollment_samples=len(keystroke_sessions),
        )

        # --- Keystroke dynamics ---
        all_digraphs: dict[str, list[float]] = defaultdict(list)
        all_holds: list[float] = []
        total_chars = 0
        total_time = 0.0

        for session_keystrokes in keystroke_sessions:
            for i, ks in enumerate(session_keystrokes):
                all_holds.append(ks.hold_duration_ms)
                if ks.flight_time_ms is not None and i > 0:
                    prev_key = session_keystrokes[i - 1].key
                    digraph = f"{prev_key}→{ks.key}"
                    all_digraphs[digraph].append(ks.flight_time_ms)

            if len(session_keystrokes) >= 2:
                duration = (
                    session_keystrokes[-1].release_time
                    - session_keystrokes[0].press_time
                )
                if duration > 0:
                    total_chars += len(session_keystrokes)
                    total_time += duration

        # Compute digraph statistics
        for digraph, latencies in all_digraphs.items():
            if len(latencies) >= 3:
                profile.digraph_means[digraph] = float(np.mean(latencies))
                profile.digraph_stds[digraph] = max(
                    float(np.std(latencies)), 5.0  # minimum 5ms std
                )

        # Hold duration statistics
        if all_holds:
            profile.hold_mean_ms = float(np.mean(all_holds))
            profile.hold_std_ms = max(float(np.std(all_holds)), 5.0)

        # Typing speed
        if total_time > 0:
            profile.typing_speed_cpm = (total_chars / total_time) * 60

        # --- Command sequence Markov chain ---
        transition_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        command_counts: dict[str, int] = defaultdict(int)

        for session_commands in command_sessions:
            for i, cmd in enumerate(session_commands):
                command_counts[cmd.command] += 1
                if i > 0:
                    prev_cmd = session_commands[i - 1].command
                    transition_counts[prev_cmd][cmd.command] += 1

        # Normalise to probabilities
        total_commands = sum(command_counts.values()) or 1
        profile.command_frequencies = {
            cmd: count / total_commands
            for cmd, count in command_counts.items()
        }

        for from_cmd, to_counts in transition_counts.items():
            total = sum(to_counts.values())
            if total > 0:
                profile.transition_matrix[from_cmd] = {
                    to_cmd: count / total
                    for to_cmd, count in to_counts.items()
                }

        # --- Session patterns ---
        if command_sessions:
            session_durations = []
            session_command_counts = []
            active_hours: set[int] = set()

            for session_commands in command_sessions:
                if session_commands:
                    duration_min = (
                        session_commands[-1].timestamp
                        - session_commands[0].timestamp
                    ) / 60
                    session_durations.append(duration_min)
                    session_command_counts.append(len(session_commands))

                    for cmd in session_commands:
                        hour = datetime.fromtimestamp(
                            cmd.timestamp, tz=timezone.utc
                        ).hour
                        active_hours.add(hour)

            if session_durations:
                profile.avg_session_duration_min = float(np.mean(session_durations))
            if session_command_counts:
                profile.avg_commands_per_session = float(np.mean(session_command_counts))
            profile.typical_active_hours = sorted(active_hours)

        # Store profile
        self._profiles[operator_id] = profile

        # Clean up enrollment buffers
        self._enrollment_buffers.pop(operator_id, None)
        self._command_enrollment.pop(operator_id, None)

        logger.info(
            f"Enrollment finalised for {operator_id}: "
            f"{len(profile.digraph_means)} digraphs, "
            f"{len(profile.transition_matrix)} command transitions, "
            f"typing speed {profile.typing_speed_cpm:.0f} CPM"
        )

        return profile

    # ------------------------------------------------------------------
    # CONTINUOUS AUTHENTICATION
    # ------------------------------------------------------------------

    def start_session(self, operator_id: str, session_id: str) -> dict:
        """
        Start monitoring a privileged session.

        Returns initial session state.
        """
        if not self._enabled:
            return {"status": "disabled", "confidence": 1.0}

        state = SessionState(
            session_id=session_id,
            operator_id=operator_id,
        )
        self._sessions[session_id] = state

        has_profile = operator_id in self._profiles

        logger.info(
            f"Biometric session started: {session_id} for {operator_id} "
            f"(profile: {'yes' if has_profile else 'no — learning mode'})"
        )

        return {
            "status": "monitoring",
            "session_id": session_id,
            "has_profile": has_profile,
            "confidence": state.confidence,
        }

    def record_keystrokes(
        self,
        session_id: str,
        keystrokes: list[KeystrokeSample],
    ) -> dict:
        """
        Record keystroke events and evaluate against profile.

        Returns current confidence and any anomaly alerts.
        """
        if not self._enabled:
            return {"status": "disabled", "confidence": 1.0}

        state = self._sessions.get(session_id)
        if state is None:
            return {"status": "unknown_session", "confidence": 0.0}

        if state.is_locked:
            return {"status": "locked", "confidence": 0.0}

        state.keystroke_buffer.extend(keystrokes)
        state.last_activity = time.time()

        # Only analyse when we have enough keystrokes
        if len(state.keystroke_buffer) < self.KEYSTROKE_WINDOW:
            return {
                "status": "collecting",
                "confidence": state.confidence,
                "buffer_size": len(state.keystroke_buffer),
                "needed": self.KEYSTROKE_WINDOW,
            }

        # Analyse window
        window = state.keystroke_buffer[-self.KEYSTROKE_WINDOW:]
        anomaly_score = self._analyse_keystrokes(state.operator_id, window)

        # Update confidence
        if anomaly_score > self.MAHALANOBIS_THRESHOLD:
            state.confidence = max(
                0.0, state.confidence - self.CONFIDENCE_DECAY_RATE
            )
        else:
            state.confidence = min(
                1.0, state.confidence + self.CONFIDENCE_RECOVERY_RATE
            )

        state.anomaly_scores.append(anomaly_score)
        if len(state.anomaly_scores) > self.MAX_ANOMALY_HISTORY:
            state.anomaly_scores = state.anomaly_scores[-self.MAX_ANOMALY_HISTORY:]

        # Trim keystroke buffer
        if len(state.keystroke_buffer) > self.KEYSTROKE_WINDOW * 3:
            state.keystroke_buffer = state.keystroke_buffer[-self.KEYSTROKE_WINDOW * 2:]

        # Check thresholds
        alert = None
        if state.confidence < self.LOCKOUT_CONFIDENCE:
            state.is_locked = True
            alert = "SESSION_LOCKED"
            logger.critical(
                f"Biometric lockout: session {session_id} for "
                f"{state.operator_id} — confidence {state.confidence:.2f}"
            )
        elif state.confidence < self.WARNING_CONFIDENCE:
            alert = "ANOMALY_WARNING"
            logger.warning(
                f"Biometric warning: session {session_id} — "
                f"confidence {state.confidence:.2f}"
            )

        return {
            "status": "locked" if state.is_locked else "monitoring",
            "confidence": round(state.confidence, 3),
            "anomaly_score": round(anomaly_score, 3),
            "threshold": self.MAHALANOBIS_THRESHOLD,
            "alert": alert,
        }

    def record_command(
        self,
        session_id: str,
        command: str,
        parameters_hash: Optional[str] = None,
    ) -> dict:
        """
        Record a command event and evaluate against profile.

        Returns current confidence and any anomaly alerts.
        """
        if not self._enabled:
            return {"status": "disabled", "confidence": 1.0}

        state = self._sessions.get(session_id)
        if state is None:
            return {"status": "unknown_session", "confidence": 0.0}

        if state.is_locked:
            return {"status": "locked", "confidence": 0.0}

        event = CommandEvent(
            command=command,
            timestamp=time.time(),
            parameters_hash=parameters_hash,
        )
        state.command_history.append(event)
        state.last_activity = time.time()

        # Analyse command sequence when we have enough
        if len(state.command_history) < 5:
            return {
                "status": "collecting",
                "confidence": state.confidence,
                "commands_recorded": len(state.command_history),
            }

        window = state.command_history[-self.COMMAND_WINDOW:]
        anomaly_score = self._analyse_commands(state.operator_id, window)

        # Update confidence
        if anomaly_score > self.CROSS_ENTROPY_THRESHOLD:
            state.confidence = max(
                0.0, state.confidence - self.CONFIDENCE_DECAY_RATE * 1.5
            )
        else:
            state.confidence = min(
                1.0, state.confidence + self.CONFIDENCE_RECOVERY_RATE
            )

        state.anomaly_scores.append(anomaly_score)

        # Check thresholds
        alert = None
        if state.confidence < self.LOCKOUT_CONFIDENCE:
            state.is_locked = True
            alert = "SESSION_LOCKED"
            logger.critical(
                f"Biometric command lockout: session {session_id} — "
                f"confidence {state.confidence:.2f}, "
                f"anomaly {anomaly_score:.2f}"
            )
        elif state.confidence < self.WARNING_CONFIDENCE:
            alert = "ANOMALY_WARNING"

        return {
            "status": "locked" if state.is_locked else "monitoring",
            "confidence": round(state.confidence, 3),
            "anomaly_score": round(anomaly_score, 3),
            "threshold": self.CROSS_ENTROPY_THRESHOLD,
            "alert": alert,
        }

    def end_session(self, session_id: str) -> dict:
        """End a monitored session and return summary."""
        if not self._enabled:
            return {"status": "disabled"}

        state = self._sessions.pop(session_id, None)
        if state is None:
            return {"status": "unknown_session"}

        duration_min = (time.time() - state.started_at) / 60
        avg_anomaly = (
            float(np.mean(state.anomaly_scores))
            if state.anomaly_scores
            else 0.0
        )

        summary = {
            "session_id": session_id,
            "operator_id": state.operator_id,
            "duration_min": round(duration_min, 2),
            "total_keystrokes": len(state.keystroke_buffer),
            "total_commands": len(state.command_history),
            "final_confidence": round(state.confidence, 3),
            "avg_anomaly_score": round(avg_anomaly, 3),
            "was_locked": state.is_locked,
            "anomaly_events": sum(
                1 for s in state.anomaly_scores
                if s > self.MAHALANOBIS_THRESHOLD
            ),
        }

        logger.info(
            f"Biometric session ended: {session_id} — "
            f"{duration_min:.1f}min, confidence {state.confidence:.2f}, "
            f"{'LOCKED' if state.is_locked else 'clean'}"
        )

        return summary

    # ------------------------------------------------------------------
    # ANALYSIS METHODS
    # ------------------------------------------------------------------

    def _analyse_keystrokes(
        self,
        operator_id: str,
        keystrokes: list[KeystrokeSample],
    ) -> float:
        """
        Analyse keystroke dynamics using Mahalanobis distance.

        Compares observed digraph latencies against enrolled profile.
        Returns anomaly score (higher = more anomalous).

        If no profile exists, returns 0.0 (learning mode).
        """
        profile = self._profiles.get(operator_id)
        if profile is None or not profile.digraph_means:
            return 0.0  # No profile — learning mode

        # Extract observed digraph latencies
        observed_digraphs: dict[str, list[float]] = defaultdict(list)
        for i in range(1, len(keystrokes)):
            if keystrokes[i].flight_time_ms is not None:
                digraph = f"{keystrokes[i-1].key}→{keystrokes[i].key}"
                observed_digraphs[digraph].append(keystrokes[i].flight_time_ms)

        if not observed_digraphs:
            return 0.0

        # Compute Mahalanobis distance for each matching digraph
        distances = []
        for digraph, latencies in observed_digraphs.items():
            if digraph in profile.digraph_means and digraph in profile.digraph_stds:
                mean = profile.digraph_means[digraph]
                std = profile.digraph_stds[digraph]
                if std > 0:
                    observed_mean = float(np.mean(latencies))
                    d = abs(observed_mean - mean) / std
                    distances.append(d)

        if not distances:
            # No matching digraphs — check hold duration instead
            observed_holds = [ks.hold_duration_ms for ks in keystrokes]
            if observed_holds and profile.hold_std_ms > 0:
                hold_mean = float(np.mean(observed_holds))
                d = abs(hold_mean - profile.hold_mean_ms) / profile.hold_std_ms
                return d

            return 0.0

        # Return RMS of individual distances (multivariate Mahalanobis approximation)
        return float(np.sqrt(np.mean(np.array(distances) ** 2)))

    def _analyse_commands(
        self,
        operator_id: str,
        commands: list[CommandEvent],
    ) -> float:
        """
        Analyse command sequence using cross-entropy against Markov model.

        H(p, q) = -Σ p(x) log₂ q(x)

        Where p is the observed transition distribution and q is
        enrolled baseline. Higher cross-entropy = more anomalous.

        If no profile exists, returns 0.0 (learning mode).
        """
        profile = self._profiles.get(operator_id)
        if profile is None or not profile.transition_matrix:
            return 0.0

        # Build observed transitions
        observed_transitions: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for i in range(1, len(commands)):
            from_cmd = commands[i - 1].command
            to_cmd = commands[i].command
            observed_transitions[from_cmd][to_cmd] += 1

        if not observed_transitions:
            return 0.0

        # Compute cross-entropy
        total_log_prob = 0.0
        total_transitions = 0
        smoothing = 1e-6  # Laplace smoothing for unseen transitions

        for from_cmd, to_counts in observed_transitions.items():
            baseline = profile.transition_matrix.get(from_cmd, {})
            total_from = sum(to_counts.values())

            for to_cmd, count in to_counts.items():
                observed_prob = count / total_from
                baseline_prob = baseline.get(to_cmd, smoothing)

                # Cross-entropy contribution
                total_log_prob += observed_prob * math.log2(
                    max(baseline_prob, smoothing)
                )
                total_transitions += 1

        if total_transitions == 0:
            return 0.0

        # Cross-entropy (negated because log of probability is negative)
        cross_entropy = -total_log_prob / total_transitions

        # Baseline self-entropy for comparison
        baseline_entropy = self._compute_baseline_entropy(profile)

        # Anomaly = excess cross-entropy above baseline
        excess = max(0.0, cross_entropy - baseline_entropy)

        return excess

    def _compute_baseline_entropy(self, profile: BiometricProfile) -> float:
        """Compute the self-entropy of the baseline Markov chain."""
        total_entropy = 0.0
        total_states = 0

        for from_cmd, transitions in profile.transition_matrix.items():
            for to_cmd, prob in transitions.items():
                if prob > 0:
                    total_entropy -= prob * math.log2(prob)
            total_states += 1

        if total_states == 0:
            return 0.0

        return total_entropy / total_states

    # ------------------------------------------------------------------
    # PROFILE MANAGEMENT
    # ------------------------------------------------------------------

    def has_profile(self, operator_id: str) -> bool:
        """Check if an operator has an enrolled profile."""
        return operator_id in self._profiles

    def get_profile_summary(self, operator_id: str) -> Optional[dict]:
        """Get summary of an operator's biometric profile."""
        profile = self._profiles.get(operator_id)
        if profile is None:
            return None

        return {
            "operator_id": profile.operator_id,
            "created_at": profile.created_at.isoformat(),
            "updated_at": profile.updated_at.isoformat(),
            "enrollment_samples": profile.enrollment_samples,
            "digraph_count": len(profile.digraph_means),
            "command_transitions": len(profile.transition_matrix),
            "typing_speed_cpm": round(profile.typing_speed_cpm, 1),
            "typical_active_hours": profile.typical_active_hours,
            "avg_session_duration_min": round(profile.avg_session_duration_min, 1),
        }

    def delete_profile(self, operator_id: str) -> bool:
        """Delete an operator's biometric profile."""
        if operator_id in self._profiles:
            del self._profiles[operator_id]
            logger.info(f"Biometric profile deleted for {operator_id}")
            return True
        return False

    def get_active_sessions(self) -> list[dict]:
        """Return summary of all active monitored sessions."""
        now = time.time()
        return [
            {
                "session_id": state.session_id,
                "operator_id": state.operator_id,
                "duration_min": round((now - state.started_at) / 60, 2),
                "confidence": round(state.confidence, 3),
                "is_locked": state.is_locked,
                "keystrokes": len(state.keystroke_buffer),
                "commands": len(state.command_history),
                "idle_seconds": round(now - state.last_activity, 1),
            }
            for state in self._sessions.values()
        ]

    def get_stats(self) -> dict:
        """Return biometric engine statistics."""
        return {
            "enabled": self._enabled,
            "enrolled_operators": len(self._profiles),
            "active_sessions": len(self._sessions),
            "locked_sessions": sum(
                1 for s in self._sessions.values() if s.is_locked
            ),
            "pending_enrollments": len(self._enrollment_buffers),
        }


# Module-level singleton
_engine: Optional[BiometricEngine] = None


def get_biometric_engine(enabled: Optional[bool] = None) -> BiometricEngine:
    """Get or create the singleton BiometricEngine instance."""
    global _engine
    if _engine is None:
        if enabled is None:
            try:
                from backend.config import config
                enabled = config.enable_biometrics
            except (ImportError, AttributeError):
                enabled = False
        _engine = BiometricEngine(enabled=enabled)
    return _engine
