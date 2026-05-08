"""
IMMUNIS ACIN — Attacker Behavioural Capture Engine

WHY: Every attacker interaction is intelligence. The capture engine
records, structures, and analyses attacker behaviour from honeypots,
canary triggers, and deception interactions. This data feeds into
the Threat Actor Fingerprinting (TAF) engine for attacker profiling
and next-attack prediction.

The capture engine is the bridge between deception (what we show
the attacker) and intelligence (what we learn from them).

Captures:
1. Session recordings — full command/response transcripts
2. Tool signatures — identified tools and frameworks
3. Technique sequences — ordered list of MITRE ATT&CK techniques
4. Timing patterns — inter-command intervals, active hours
5. Credential attempts — usernames/passwords tried
6. Payload samples — malware, scripts, exploits deployed
7. Network behaviour — IPs, ports, protocols used
8. Behavioural fingerprint — 128-dim vector for clustering

The behavioural fingerprint is a dense vector that encodes:
- Tool sophistication (0=script kiddie, 1=APT)
- Automation level (0=manual, 1=fully automated)
- Stealth level (0=noisy, 1=careful)
- Objective clarity (0=exploring, 1=targeted)
- Persistence (0=gives up quickly, 1=persistent)
- Adaptability (0=rigid, 1=adapts to defences)
- Time pressure (0=patient, 1=rushed)
- Knowledge level (0=novice, 1=expert)

Mathematical foundation:
  Behavioural vector b ∈ ℝ¹²⁸
  First 8 dimensions: hand-crafted features (above)
  Remaining 120: learned features from interaction embeddings
  Clustering: DBSCAN(b, ε=0.3, min_samples=3)
  Similarity: cosine(b₁, b₂) for actor matching
"""

import logging
import time
import hashlib
import json
import math
from typing import Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field
from collections import defaultdict

import numpy as np

logger = logging.getLogger("immunis.deception.capture")


@dataclass
class CredentialAttempt:
    """A captured credential attempt."""
    username: str
    password_hash: str  # SHA256 hash — never store raw passwords
    timestamp: str
    source_ip: str
    service: str  # ssh, http, database, etc.
    success: bool = False  # Always False in honeypot


@dataclass
class PayloadSample:
    """A captured payload/malware sample."""
    sample_id: str
    sha256_hash: str
    file_type: str
    size_bytes: int
    captured_at: str
    source_ip: str
    delivery_method: str  # upload, download, injection
    content_preview: str = ""  # First 200 chars (sanitised)
    is_known_malware: bool = False
    malware_family: Optional[str] = None


@dataclass
class TechniqueObservation:
    """An observed MITRE ATT&CK technique."""
    technique_id: str  # e.g., T1059
    technique_name: str
    tactic: str  # e.g., execution, persistence
    timestamp: str
    confidence: float  # 0-1
    evidence: str  # What triggered the detection
    command: str = ""  # The command that exhibited this technique


@dataclass
class SessionCapture:
    """Complete capture of an attacker session."""
    capture_id: str
    session_id: str
    attacker_ip: str
    started_at: str
    ended_at: Optional[str] = None
    duration_s: float = 0.0

    # Transcript
    commands: list[dict] = field(default_factory=list)  # {timestamp, input, output}
    total_commands: int = 0

    # Intelligence
    tools_detected: list[str] = field(default_factory=list)
    techniques_observed: list[TechniqueObservation] = field(default_factory=list)
    credential_attempts: list[CredentialAttempt] = field(default_factory=list)
    payload_samples: list[PayloadSample] = field(default_factory=list)

    # Timing
    inter_command_intervals: list[float] = field(default_factory=list)
    active_hours: list[int] = field(default_factory=list)  # 0-23

    # Behavioural fingerprint
    behavioural_vector: Optional[list[float]] = None

    # Classification
    sophistication_score: float = 0.0  # 0=script kiddie, 1=APT
    automation_score: float = 0.0  # 0=manual, 1=automated
    threat_level: str = "unknown"  # low, medium, high, critical

    def to_dict(self) -> dict:
        return {
            "capture_id": self.capture_id,
            "session_id": self.session_id,
            "attacker_ip": self.attacker_ip,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_s": round(self.duration_s, 1),
            "total_commands": self.total_commands,
            "tools_detected": self.tools_detected,
            "techniques_count": len(self.techniques_observed),
            "credential_attempts": len(self.credential_attempts),
            "payload_samples": len(self.payload_samples),
            "sophistication_score": round(self.sophistication_score, 3),
            "automation_score": round(self.automation_score, 3),
            "threat_level": self.threat_level,
        }


# MITRE ATT&CK technique mapping from commands
TECHNIQUE_PATTERNS = {
    "T1059.004": {
        "name": "Unix Shell",
        "tactic": "execution",
        "patterns": ["bash", "sh -c", "/bin/sh", "#!/bin"],
    },
    "T1059.006": {
        "name": "Python",
        "tactic": "execution",
        "patterns": ["python", "python3", "import os", "import subprocess"],
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "credential_access",
        "patterns": ["/etc/shadow", "/etc/passwd", "hashdump", "mimikatz"],
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "discovery",
        "patterns": ["whoami", "id", "who", "w ", "last", "finger"],
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "discovery",
        "patterns": ["uname", "hostname", "cat /proc", "lsb_release", "dmidecode"],
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactic": "discovery",
        "patterns": ["ifconfig", "ip addr", "netstat", "ss -", "route", "arp"],
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "tactic": "discovery",
        "patterns": ["netstat -", "ss -tlnp", "lsof -i", "nmap"],
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "discovery",
        "patterns": ["ls", "dir", "find /", "locate", "tree"],
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "collection",
        "patterns": ["cat ", "head ", "tail ", "less ", "more ", "strings "],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "exfiltration",
        "patterns": ["curl -X POST", "wget --post", "nc ", "scp ", "rsync"],
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "persistence",
        "patterns": ["crontab", "at ", "systemctl enable", "rc.local"],
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "persistence",
        "patterns": ["useradd", "adduser", "usermod", "passwd", "chpasswd"],
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "privilege_escalation",
        "patterns": ["sudo", "su -", "chmod +s", "setuid", "pkexec"],
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "defense_evasion",
        "patterns": ["rm -rf", "shred", "history -c", "unset HISTFILE", "wipe"],
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "lateral_movement",
        "patterns": ["ssh ", "rdp", "psexec", "wmic", "winrm"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "impact",
        "patterns": ["openssl enc", "gpg -c", "7z a -p", "encrypt", "ransom"],
    },
}

# Tool sophistication scores
TOOL_SOPHISTICATION = {
    "nmap": 0.3,
    "metasploit": 0.6,
    "sqlmap": 0.4,
    "hydra": 0.3,
    "john_the_ripper": 0.4,
    "hashcat": 0.5,
    "burp_suite": 0.6,
    "nikto": 0.3,
    "dirb": 0.2,
    "gobuster": 0.3,
    "wget": 0.1,
    "curl": 0.1,
    "netcat": 0.3,
    "python_script": 0.5,
    "perl_script": 0.4,
    "powershell": 0.5,
    "cobalt_strike": 0.9,
    "empire": 0.7,
    "covenant": 0.7,
    "bloodhound": 0.8,
    "mimikatz": 0.7,
    "custom_tool": 0.8,
}


class CaptureEngine:
    """
    Attacker behavioural capture and analysis engine.

    Records all attacker interactions from honeypots and canary
    triggers, extracts intelligence, maps to MITRE ATT&CK,
    computes behavioural fingerprints, and classifies threat level.

    Usage:
        engine = CaptureEngine()

        # Start capture for a honeypot session
        capture = engine.start_capture("session-001", "192.168.1.100")

        # Record commands
        engine.record_command(capture.capture_id, "ls -la", "/home/admin output...")
        engine.record_command(capture.capture_id, "cat /etc/passwd", "root:x:0:0...")

        # End capture
        result = engine.end_capture(capture.capture_id)
        # result contains full analysis, techniques, fingerprint
    """

    BEHAVIOURAL_VECTOR_DIM = 128

    def __init__(self):
        self._captures: dict[str, SessionCapture] = {}
        self._completed_captures: list[SessionCapture] = []
        self._attacker_profiles: dict[str, list[str]] = defaultdict(list)  # IP → capture_ids

        # Statistics
        self._total_captures: int = 0
        self._total_commands_captured: int = 0
        self._total_credentials_captured: int = 0
        self._total_payloads_captured: int = 0
        self._total_techniques_observed: int = 0

        logger.info("Capture engine initialised")

    def start_capture(
        self,
        session_id: str,
        attacker_ip: str,
        honeypot_type: Optional[str] = None,
    ) -> SessionCapture:
        """Start capturing an attacker session."""
        capture_id = hashlib.sha256(
            f"{session_id}:{attacker_ip}:{time.time()}".encode()
        ).hexdigest()[:16]

        capture = SessionCapture(
            capture_id=capture_id,
            session_id=session_id,
            attacker_ip=attacker_ip,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        self._captures[capture_id] = capture
        self._attacker_profiles[attacker_ip].append(capture_id)
        self._total_captures += 1

        logger.info(
            f"Capture started: {capture_id} for session {session_id} "
            f"from {attacker_ip}"
        )

        return capture

    def record_command(
        self,
        capture_id: str,
        command: str,
        response: str = "",
        timestamp: Optional[str] = None,
    ) -> Optional[list[TechniqueObservation]]:
        """
        Record a command and its response.

        Analyses the command for:
        - MITRE ATT&CK technique mapping
        - Tool detection
        - Credential attempts
        - Timing patterns

        Returns list of techniques observed (if any).
        """
        capture = self._captures.get(capture_id)
        if capture is None:
            return None

        now = timestamp or datetime.now(timezone.utc).isoformat()

        # Record command
        entry = {
            "timestamp": now,
            "input": command[:500],  # Limit size
            "output": response[:1000],  # Limit size
        }
        capture.commands.append(entry)
        capture.total_commands += 1
        self._total_commands_captured += 1

        # Compute inter-command interval
        if len(capture.commands) > 1:
            try:
                prev_ts = capture.commands[-2]["timestamp"]
                prev_dt = datetime.fromisoformat(prev_ts.replace("Z", "+00:00"))
                curr_dt = datetime.fromisoformat(now.replace("Z", "+00:00"))
                interval = (curr_dt - prev_dt).total_seconds()
                capture.inter_command_intervals.append(interval)
            except (ValueError, TypeError):
                pass

        # Record active hour
        try:
            dt = datetime.fromisoformat(now.replace("Z", "+00:00"))
            hour = dt.hour
            if hour not in capture.active_hours:
                capture.active_hours.append(hour)
        except (ValueError, TypeError):
            pass

        # Detect techniques
        techniques = self._detect_techniques(command, now)
        capture.techniques_observed.extend(techniques)
        self._total_techniques_observed += len(techniques)

        # Detect tools
        tools = self._detect_tools(command)
        for tool in tools:
            if tool not in capture.tools_detected:
                capture.tools_detected.append(tool)

        return techniques if techniques else None

    def record_credential_attempt(
        self,
        capture_id: str,
        username: str,
        password: str,
        service: str = "ssh",
        source_ip: str = "",
    ) -> None:
        """Record a credential attempt (password is hashed, never stored raw)."""
        capture = self._captures.get(capture_id)
        if capture is None:
            return

        attempt = CredentialAttempt(
            username=username,
            password_hash=hashlib.sha256(password.encode()).hexdigest(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip or capture.attacker_ip,
            service=service,
            success=False,
        )

        capture.credential_attempts.append(attempt)
        self._total_credentials_captured += 1

        logger.debug(
            f"Credential captured: user={username}, "
            f"service={service}, ip={source_ip}"
        )

    def record_payload(
        self,
        capture_id: str,
        payload_bytes: bytes,
        file_type: str = "unknown",
        delivery_method: str = "upload",
    ) -> Optional[PayloadSample]:
        """Record a captured payload/malware sample."""
        capture = self._captures.get(capture_id)
        if capture is None:
            return None

        sha256 = hashlib.sha256(payload_bytes).hexdigest()
        sample_id = sha256[:16]

        sample = PayloadSample(
            sample_id=sample_id,
            sha256_hash=sha256,
            file_type=file_type,
            size_bytes=len(payload_bytes),
            captured_at=datetime.now(timezone.utc).isoformat(),
            source_ip=capture.attacker_ip,
            delivery_method=delivery_method,
            content_preview=payload_bytes[:200].decode("utf-8", errors="replace"),
        )

        capture.payload_samples.append(sample)
        self._total_payloads_captured += 1

        # Store payload in blob store
        try:
            from backend.storage.blob_store import get_blob_store, BlobCategory
            store = get_blob_store()
            store.store(
                data=payload_bytes,
                category=BlobCategory.PAYLOADS,
                incident_id=capture.session_id,
                tags=["honeypot_capture", capture.attacker_ip],
            )
        except Exception as e:
            logger.debug(f"Failed to store payload in blob store: {e}")

        logger.info(
            f"Payload captured: {sample_id} ({len(payload_bytes)} bytes, "
            f"type={file_type}, method={delivery_method})"
        )

        return sample

    def end_capture(self, capture_id: str) -> Optional[SessionCapture]:
        """
        End a capture session and perform final analysis.

        Computes:
        - Behavioural fingerprint (128-dim vector)
        - Sophistication score
        - Automation score
        - Threat level classification
        """
        capture = self._captures.pop(capture_id, None)
        if capture is None:
            return None

        now = datetime.now(timezone.utc)
        capture.ended_at = now.isoformat()

        # Compute duration
        try:
            started = datetime.fromisoformat(
                capture.started_at.replace("Z", "+00:00")
            )
            capture.duration_s = (now - started).total_seconds()
        except (ValueError, TypeError):
            capture.duration_s = 0.0

        # Compute behavioural fingerprint
        capture.behavioural_vector = self._compute_behavioural_vector(capture)

        # Compute sophistication score
        capture.sophistication_score = self._compute_sophistication(capture)

        # Compute automation score
        capture.automation_score = self._compute_automation_score(capture)

        # Classify threat level
        capture.threat_level = self._classify_threat_level(capture)

        # Store completed capture
        self._completed_captures.append(capture)

        # Store in database
        try:
            from backend.storage.database import get_database
            db = get_database()
            db.insert_audit_event({
                "event_id": f"capture-{capture_id}",
                "event_type": "honeypot_capture",
                "actor": capture.attacker_ip,
                "action": "attacker_session",
                "target": capture.session_id,
                "details": capture.to_dict(),
            })
        except Exception:
            pass

        logger.info(
            f"Capture complete: {capture_id}, "
            f"duration={capture.duration_s:.1f}s, "
            f"commands={capture.total_commands}, "
            f"tools={capture.tools_detected}, "
            f"techniques={len(capture.techniques_observed)}, "
            f"sophistication={capture.sophistication_score:.2f}, "
            f"automation={capture.automation_score:.2f}, "
            f"threat={capture.threat_level}"
        )

        return capture

    # ------------------------------------------------------------------
    # TECHNIQUE DETECTION
    # ------------------------------------------------------------------

    def _detect_techniques(
        self,
        command: str,
        timestamp: str,
    ) -> list[TechniqueObservation]:
        """Map a command to MITRE ATT&CK techniques."""
        techniques = []
        command_lower = command.lower()

        for technique_id, info in TECHNIQUE_PATTERNS.items():
            for pattern in info["patterns"]:
                if pattern in command_lower:
                    techniques.append(TechniqueObservation(
                        technique_id=technique_id,
                        technique_name=info["name"],
                        tactic=info["tactic"],
                        timestamp=timestamp,
                        confidence=0.8,
                        evidence=f"Pattern '{pattern}' matched",
                        command=command[:200],
                    ))
                    break  # One match per technique per command

        return techniques

    def _detect_tools(self, command: str) -> list[str]:
        """Detect tools from command input."""
        tools = []
        command_lower = command.lower()

        tool_keywords = {
            "nmap": "nmap",
            "msfconsole": "metasploit",
            "msf": "metasploit",
            "sqlmap": "sqlmap",
            "hydra": "hydra",
            "john": "john_the_ripper",
            "hashcat": "hashcat",
            "nikto": "nikto",
            "dirb": "dirb",
            "gobuster": "gobuster",
            "burp": "burp_suite",
            "bloodhound": "bloodhound",
            "mimikatz": "mimikatz",
            "empire": "empire",
            "covenant": "covenant",
            "cobalt": "cobalt_strike",
        }

        for keyword, tool_name in tool_keywords.items():
            if keyword in command_lower:
                tools.append(tool_name)

        return tools

    # ------------------------------------------------------------------
    # BEHAVIOURAL FINGERPRINT
    # ------------------------------------------------------------------

    def _compute_behavioural_vector(
        self,
        capture: SessionCapture,
    ) -> list[float]:
        """
        Compute 128-dimensional behavioural fingerprint.

        First 8 dimensions: hand-crafted features
        Remaining 120: derived from interaction patterns
        """
        vector = np.zeros(self.BEHAVIOURAL_VECTOR_DIM, dtype=np.float64)

        # Dim 0: Tool sophistication (0-1)
        if capture.tools_detected:
            scores = [
                TOOL_SOPHISTICATION.get(t, 0.3)
                for t in capture.tools_detected
            ]
            vector[0] = max(scores)
        else:
            vector[0] = 0.1

        # Dim 1: Automation level (0-1)
        vector[1] = self._compute_automation_score(capture)

        # Dim 2: Stealth level (0-1)
        vector[2] = self._compute_stealth_score(capture)

        # Dim 3: Objective clarity (0-1)
        vector[3] = self._compute_objective_clarity(capture)

        # Dim 4: Persistence (0-1)
        vector[4] = min(1.0, capture.duration_s / 1800)  # Normalise to 30min

        # Dim 5: Adaptability (0-1)
        unique_techniques = len(set(
            t.technique_id for t in capture.techniques_observed
        ))
        vector[5] = min(1.0, unique_techniques / 10)

        # Dim 6: Time pressure (0-1)
        if capture.inter_command_intervals:
            avg_interval = np.mean(capture.inter_command_intervals)
            vector[6] = max(0, 1.0 - (avg_interval / 30))  # Fast = pressured
        else:
            vector[6] = 0.5

        # Dim 7: Knowledge level (0-1)
        vector[7] = self._compute_knowledge_score(capture)

        # Dims 8-27: Technique tactic distribution (one-hot-ish)
        tactic_indices = {
            "execution": 8, "persistence": 9, "privilege_escalation": 10,
            "defense_evasion": 11, "credential_access": 12, "discovery": 13,
            "lateral_movement": 14, "collection": 15, "exfiltration": 16,
            "impact": 17,
        }
        for technique in capture.techniques_observed:
            idx = tactic_indices.get(technique.tactic)
            if idx is not None:
                vector[idx] = min(1.0, vector[idx] + 0.2)

        # Dims 28-47: Timing features
        if capture.inter_command_intervals:
            intervals = np.array(capture.inter_command_intervals)
            vector[28] = min(1.0, np.mean(intervals) / 60)
            vector[29] = min(1.0, np.std(intervals) / 30)
            vector[30] = min(1.0, np.median(intervals) / 60)
            vector[31] = min(1.0, np.min(intervals) / 10) if len(intervals) > 0 else 0
            vector[32] = min(1.0, np.max(intervals) / 300) if len(intervals) > 0 else 0

        # Dims 48-67: Command diversity features
        if capture.commands:
            unique_commands = len(set(
                cmd["input"].split()[0]
                for cmd in capture.commands
                if cmd.get("input")
            ))
            vector[48] = min(1.0, unique_commands / 20)
            vector[49] = min(1.0, capture.total_commands / 100)
            vector[50] = min(1.0, len(capture.credential_attempts) / 10)
            vector[51] = min(1.0, len(capture.payload_samples) / 5)

        # Dims 68-87: Active hours encoding (circular)
        for hour in capture.active_hours:
            # Circular encoding
            angle = 2 * math.pi * hour / 24
            idx_base = 68 + (hour % 20)
            vector[idx_base] = max(vector[idx_base], math.cos(angle) * 0.5 + 0.5)

        # Dims 88-127: Reserved for learned features (zero for now)
        # In production, these would be filled by an autoencoder
        # trained on historical captures

        # L2 normalise
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm

        return vector.tolist()

    # ------------------------------------------------------------------
    # SCORING FUNCTIONS
    # ------------------------------------------------------------------

    def _compute_sophistication(self, capture: SessionCapture) -> float:
        """Compute attacker sophistication score (0-1)."""
        score = 0.0

        # Tool sophistication
        if capture.tools_detected:
            tool_scores = [
                TOOL_SOPHISTICATION.get(t, 0.3)
                for t in capture.tools_detected
            ]
            score += max(tool_scores) * 0.3

        # Technique diversity
        unique_tactics = len(set(
            t.tactic for t in capture.techniques_observed
        ))
        score += min(0.3, unique_tactics * 0.05)

        # Anti-forensics awareness
        has_cleanup = any(
            t.technique_id == "T1070"
            for t in capture.techniques_observed
        )
        if has_cleanup:
            score += 0.2

        # Credential sophistication
        if capture.credential_attempts:
            unique_users = len(set(
                c.username for c in capture.credential_attempts
            ))
            if unique_users > 5:
                score += 0.1  # Dictionary attack
            elif unique_users <= 2:
                score += 0.2  # Targeted attack (knows usernames)

        return min(1.0, score)

    def _compute_automation_score(self, capture: SessionCapture) -> float:
        """Compute automation level (0=manual, 1=fully automated)."""
        if not capture.inter_command_intervals:
            return 0.5

        intervals = np.array(capture.inter_command_intervals)

        # Very consistent timing = automated
        if len(intervals) > 3:
            cv = np.std(intervals) / (np.mean(intervals) + 0.001)
            if cv < 0.1:
                return 0.9  # Very consistent = automated
            elif cv < 0.3:
                return 0.6  # Semi-automated
            elif cv > 1.0:
                return 0.2  # Very variable = manual

        # Very fast commands = automated
        if len(intervals) > 0:
            avg_interval = np.mean(intervals)
            if avg_interval < 0.5:
                return 0.95  # Sub-second = definitely automated
            elif avg_interval < 2.0:
                return 0.7  # Fast but could be experienced human
            elif avg_interval > 10.0:
                return 0.2  # Slow = manual

        # High command count in short time = automated
        if capture.duration_s > 0:
            commands_per_minute = capture.total_commands / (capture.duration_s / 60)
            if commands_per_minute > 30:
                return 0.9
            elif commands_per_minute > 10:
                return 0.6

        return 0.4  # Default: slightly manual

    def _compute_stealth_score(self, capture: SessionCapture) -> float:
        """Compute stealth level (0=noisy, 1=careful)."""
        score = 0.5

        # Anti-forensics = stealthy
        has_cleanup = any(
            t.technique_id == "T1070"
            for t in capture.techniques_observed
        )
        if has_cleanup:
            score += 0.2

        # Few commands = stealthy (knows what they want)
        if capture.total_commands < 10 and capture.duration_s > 60:
            score += 0.15

        # No credential brute-force = stealthy
        if len(capture.credential_attempts) == 0:
            score += 0.1
        elif len(capture.credential_attempts) > 20:
            score -= 0.3  # Brute force = noisy

        # Slow, deliberate pace = stealthy
        if capture.inter_command_intervals:
            avg = np.mean(capture.inter_command_intervals)
            if 5.0 < avg < 30.0:
                score += 0.1  # Deliberate pace

        # Discovery before action = stealthy
        techniques = [t.tactic for t in capture.techniques_observed]
        if techniques:
            first_non_discovery = next(
                (i for i, t in enumerate(techniques) if t != "discovery"),
                len(techniques),
            )
            discovery_count = sum(1 for t in techniques if t == "discovery")
            if first_non_discovery > 2 and discovery_count > 3:
                score += 0.15  # Recon before action

        return max(0.0, min(1.0, score))

    def _compute_objective_clarity(self, capture: SessionCapture) -> float:
        """Compute how clear the attacker's objective is (0=exploring, 1=targeted)."""
        score = 0.3  # Base: some exploration

        # Specific file access = targeted
        targeted_files = [
            ".env", "credentials", "password", "secret",
            "config", "database", "backup", "key",
        ]
        for cmd in capture.commands:
            cmd_input = cmd.get("input", "").lower()
            for target in targeted_files:
                if target in cmd_input:
                    score += 0.1
                    break

        # Direct path to objective (few discovery commands before action)
        if capture.total_commands < 5 and capture.techniques_observed:
            non_discovery = [
                t for t in capture.techniques_observed
                if t.tactic != "discovery"
            ]
            if non_discovery:
                score += 0.2  # Went straight to action

        # Credential harvesting focus
        if len(capture.credential_attempts) > 0:
            score += 0.15

        # Data exfiltration attempt
        has_exfil = any(
            t.tactic == "exfiltration"
            for t in capture.techniques_observed
        )
        if has_exfil:
            score += 0.2

        return min(1.0, score)

    def _compute_knowledge_score(self, capture: SessionCapture) -> float:
        """Compute attacker's knowledge level (0=novice, 1=expert)."""
        score = 0.2  # Base

        # Correct command syntax = knowledge
        error_commands = sum(
            1 for cmd in capture.commands
            if "command not found" in cmd.get("output", "")
            or "No such file" in cmd.get("output", "")
        )
        if capture.total_commands > 0:
            error_rate = error_commands / capture.total_commands
            score += (1.0 - error_rate) * 0.3

        # Advanced techniques = knowledge
        advanced_tactics = {"privilege_escalation", "defense_evasion", "lateral_movement"}
        has_advanced = any(
            t.tactic in advanced_tactics
            for t in capture.techniques_observed
        )
        if has_advanced:
            score += 0.2

        # Tool diversity = knowledge
        if len(capture.tools_detected) > 3:
            score += 0.15

        # Payload deployment = knowledge
        if capture.payload_samples:
            score += 0.15

        return min(1.0, score)

    def _classify_threat_level(self, capture: SessionCapture) -> str:
        """Classify overall threat level."""
        # Weighted combination
        combined = (
            capture.sophistication_score * 0.4
            + capture.automation_score * 0.2
            + (len(capture.techniques_observed) / 20) * 0.2
            + (len(capture.payload_samples) > 0) * 0.2
        )

        if combined >= 0.7:
            return "critical"
        elif combined >= 0.5:
            return "high"
        elif combined >= 0.3:
            return "medium"
        else:
            return "low"

    # ------------------------------------------------------------------
    # QUERY METHODS
    # ------------------------------------------------------------------

    def get_capture(self, capture_id: str) -> Optional[dict]:
        """Get a specific capture."""
        # Check active
        capture = self._captures.get(capture_id)
        if capture:
            return capture.to_dict()

        # Check completed
        for c in self._completed_captures:
            if c.capture_id == capture_id:
                return c.to_dict()

        return None

    def get_active_captures(self) -> list[dict]:
        """Get all active captures."""
        return [c.to_dict() for c in self._captures.values()]

    def get_completed_captures(self, limit: int = 50) -> list[dict]:
        """Get recent completed captures."""
        return [c.to_dict() for c in self._completed_captures[-limit:]]

    def get_attacker_profile(self, attacker_ip: str) -> dict:
        """Get aggregated profile for an attacker IP."""
        capture_ids = self._attacker_profiles.get(attacker_ip, [])

        captures = []
        for cid in capture_ids:
            # Check active
            if cid in self._captures:
                captures.append(self._captures[cid])
            # Check completed
            for c in self._completed_captures:
                if c.capture_id == cid:
                    captures.append(c)

        if not captures:
            return {"attacker_ip": attacker_ip, "sessions": 0}

        total_duration = sum(c.duration_s for c in captures)
        all_tools = set()
        all_techniques = set()
        total_commands = 0
        total_credentials = 0

        for c in captures:
            all_tools.update(c.tools_detected)
            all_techniques.update(t.technique_id for t in c.techniques_observed)
            total_commands += c.total_commands
            total_credentials += len(c.credential_attempts)

        # Average sophistication
        sophistication_scores = [
            c.sophistication_score for c in captures
            if c.sophistication_score > 0
        ]
        avg_sophistication = (
            np.mean(sophistication_scores) if sophistication_scores else 0.0
        )

        return {
            "attacker_ip": attacker_ip,
            "sessions": len(captures),
            "total_duration_s": round(total_duration, 1),
            "total_commands": total_commands,
            "total_credential_attempts": total_credentials,
            "tools_observed": sorted(all_tools),
            "techniques_observed": sorted(all_techniques),
            "avg_sophistication": round(float(avg_sophistication), 3),
            "threat_levels": [c.threat_level for c in captures],
            "first_seen": min(c.started_at for c in captures),
            "last_seen": max(c.ended_at or c.started_at for c in captures),
        }

    def get_all_attacker_ips(self) -> list[str]:
        """Get all known attacker IPs."""
        return list(self._attacker_profiles.keys())

    def get_technique_frequency(self) -> dict[str, int]:
        """Get frequency of observed MITRE ATT&CK techniques."""
        freq: dict[str, int] = {}
        for capture in self._completed_captures:
            for technique in capture.techniques_observed:
                tid = technique.technique_id
                freq[tid] = freq.get(tid, 0) + 1

        return dict(sorted(freq.items(), key=lambda x: x[1], reverse=True))

    def get_behavioural_vectors(self) -> list[tuple[str, list[float]]]:
        """Get all behavioural vectors for clustering."""
        vectors = []
        for capture in self._completed_captures:
            if capture.behavioural_vector:
                vectors.append((capture.capture_id, capture.behavioural_vector))
        return vectors

    def get_stats(self) -> dict:
        """Return capture engine statistics."""
        return {
            "total_captures": self._total_captures,
            "active_captures": len(self._captures),
            "completed_captures": len(self._completed_captures),
            "unique_attackers": len(self._attacker_profiles),
            "total_commands_captured": self._total_commands_captured,
            "total_credentials_captured": self._total_credentials_captured,
            "total_payloads_captured": self._total_payloads_captured,
            "total_techniques_observed": self._total_techniques_observed,
            "technique_frequency": self.get_technique_frequency(),
        }


# Module-level singleton
_engine: Optional[CaptureEngine] = None


def get_capture_engine() -> CaptureEngine:
    """Get or create the singleton CaptureEngine instance."""
    global _engine
    if _engine is None:
        _engine = CaptureEngine()
    return _engine
