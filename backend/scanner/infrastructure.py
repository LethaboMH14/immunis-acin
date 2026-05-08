"""
IMMUNIS ACIN — Infrastructure Security Scanner
System-level CIS benchmark auditing and security posture assessment.

Examines the host operating system, network configuration, running services,
file permissions, user accounts, and system resources against CIS Benchmarks
(Center for Internet Security) and IMMUNIS-specific hardening requirements.

This is the internal immune system's self-examination — checking that the
body itself is healthy, not just watching for external pathogens.

Mathematical foundation:
- Compliance score: C = (Σ weighted_pass) / (Σ weighted_total) × 100
- Risk exposure: E = Σ(severity_weight × (1 - compliance_per_control))
- Hardening index: H = 1 - (E / max_possible_exposure)
"""

import asyncio
import hashlib
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("immunis.scanner.infrastructure")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class InfraCheckSeverity(str, Enum):
    """Severity of an infrastructure finding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class InfraCheckCategory(str, Enum):
    """Categories aligned with CIS Controls v8."""
    INVENTORY = "inventory_and_control"           # CIS Control 1-2
    DATA_PROTECTION = "data_protection"           # CIS Control 3
    SECURE_CONFIG = "secure_configuration"        # CIS Control 4
    ACCOUNT_MGMT = "account_management"           # CIS Control 5-6
    AUDIT_LOG = "audit_and_log_management"        # CIS Control 8
    NETWORK_SECURITY = "network_security"         # CIS Control 9, 12, 13
    MALWARE_DEFENSE = "malware_defense"           # CIS Control 10
    SERVICE_MGMT = "service_management"           # CIS Control 4, 7
    PATCH_MGMT = "patch_management"               # CIS Control 7
    RESOURCE_HEALTH = "resource_health"           # Operational
    FILE_INTEGRITY = "file_integrity"             # CIS Control 3
    CRYPTO_CONFIG = "cryptographic_configuration" # CIS Control 3


class InfraCheckStatus(str, Enum):
    """Result status of an infrastructure check."""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    ERROR = "error"
    SKIP = "skip"


class InfraScanStatus(str, Enum):
    """Overall scan lifecycle."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class InfraFinding:
    """A single infrastructure audit finding."""
    check_id: str
    title: str
    category: InfraCheckCategory
    severity: InfraCheckSeverity
    status: InfraCheckStatus
    description: str
    impact: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    cis_control: str = ""
    cis_benchmark: str = ""
    weight: float = 1.0

    @property
    def is_pass(self) -> bool:
        return self.status == InfraCheckStatus.PASS

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "cis_control": self.cis_control,
            "cis_benchmark": self.cis_benchmark,
            "weight": self.weight,
        }


@dataclass
class InfraScanResult:
    """Complete result of an infrastructure scan."""
    scan_id: str
    status: InfraScanStatus
    started_at: float
    completed_at: float = 0.0
    hostname: str = ""
    os_info: str = ""
    findings: list[InfraFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    @property
    def total_checks(self) -> int:
        return len([f for f in self.findings if f.status != InfraCheckStatus.SKIP])

    @property
    def passed_checks(self) -> int:
        return len([f for f in self.findings if f.status == InfraCheckStatus.PASS])

    @property
    def failed_checks(self) -> int:
        return len([f for f in self.findings if f.status == InfraCheckStatus.FAIL])

    @property
    def compliance_score(self) -> float:
        """Weighted compliance percentage."""
        applicable = [f for f in self.findings if f.status not in (InfraCheckStatus.SKIP, InfraCheckStatus.ERROR)]
        if not applicable:
            return 0.0
        total_weight = sum(f.weight for f in applicable)
        passed_weight = sum(f.weight for f in applicable if f.is_pass)
        return (passed_weight / total_weight) * 100.0 if total_weight > 0 else 0.0

    @property
    def risk_exposure(self) -> float:
        """Aggregate risk exposure from failed checks."""
        severity_weights = {
            InfraCheckSeverity.CRITICAL: 10.0,
            InfraCheckSeverity.HIGH: 5.0,
            InfraCheckSeverity.MEDIUM: 2.0,
            InfraCheckSeverity.LOW: 0.5,
            InfraCheckSeverity.INFO: 0.1,
        }
        failed = [f for f in self.findings if f.status == InfraCheckStatus.FAIL]
        return sum(severity_weights.get(f.severity, 1.0) * f.weight for f in failed)

    @property
    def hardening_index(self) -> float:
        """0.0 (unhardened) to 1.0 (fully hardened)."""
        severity_weights = {
            InfraCheckSeverity.CRITICAL: 10.0,
            InfraCheckSeverity.HIGH: 5.0,
            InfraCheckSeverity.MEDIUM: 2.0,
            InfraCheckSeverity.LOW: 0.5,
            InfraCheckSeverity.INFO: 0.1,
        }
        applicable = [f for f in self.findings if f.status not in (InfraCheckStatus.SKIP, InfraCheckStatus.ERROR)]
        if not applicable:
            return 0.0
        max_exposure = sum(severity_weights.get(f.severity, 1.0) * f.weight for f in applicable)
        if max_exposure == 0:
            return 1.0
        return 1.0 - (self.risk_exposure / max_exposure)

    @property
    def category_scores(self) -> dict[str, dict[str, Any]]:
        """Compliance score per category."""
        categories: dict[str, dict[str, Any]] = {}
        for f in self.findings:
            if f.status in (InfraCheckStatus.SKIP, InfraCheckStatus.ERROR):
                continue
            cat = f.category.value
            if cat not in categories:
                categories[cat] = {"total_weight": 0.0, "passed_weight": 0.0, "count": 0, "passed": 0}
            categories[cat]["total_weight"] += f.weight
            categories[cat]["count"] += 1
            if f.is_pass:
                categories[cat]["passed_weight"] += f.weight
                categories[cat]["passed"] += 1

        result = {}
        for cat, data in categories.items():
            score = (data["passed_weight"] / data["total_weight"] * 100.0) if data["total_weight"] > 0 else 0.0
            result[cat] = {
                "score": round(score, 1),
                "passed": data["passed"],
                "total": data["count"],
            }
        return result

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "failed_checks": self.failed_checks,
            "compliance_score": round(self.compliance_score, 1),
            "risk_exposure": round(self.risk_exposure, 2),
            "hardening_index": round(self.hardening_index, 3),
            "category_scores": self.category_scores,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "scan_duration_seconds": self.scan_duration_seconds,
        }


# ---------------------------------------------------------------------------
# Helper: safe command execution
# ---------------------------------------------------------------------------

def _run_cmd(cmd: list[str], timeout: int = 10) -> tuple[str, str, int]:
    """
    Run a system command safely with timeout.
    Returns (stdout, stderr, returncode).
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C"},
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -2
    except Exception as e:
        return "", str(e), -3


def _is_linux() -> bool:
    return platform.system().lower() == "linux"


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _is_macos() -> bool:
    return platform.system().lower() == "darwin"


# ---------------------------------------------------------------------------
# Infrastructure check implementations
# ---------------------------------------------------------------------------

class NetworkSecurityChecks:
    """Network-level security audits."""

    def check_open_ports(self) -> list[InfraFinding]:
        """Check for unnecessarily open ports."""
        findings: list[InfraFinding] = []

        # Well-known dangerous ports
        dangerous_ports = {
            21: ("FTP", "Unencrypted file transfer"),
            23: ("Telnet", "Unencrypted remote access"),
            25: ("SMTP", "Mail relay — potential spam source"),
            69: ("TFTP", "Trivial file transfer — no authentication"),
            111: ("RPCBind", "RPC service mapper — information disclosure"),
            135: ("MSRPC", "Windows RPC — common attack vector"),
            139: ("NetBIOS", "Windows file sharing — lateral movement"),
            445: ("SMB", "Windows file sharing — EternalBlue, WannaCry"),
            512: ("rexec", "Remote execution — no encryption"),
            513: ("rlogin", "Remote login — no encryption"),
            514: ("rsh", "Remote shell — no encryption"),
            1433: ("MSSQL", "Database — should not be internet-facing"),
            1521: ("Oracle", "Database — should not be internet-facing"),
            2049: ("NFS", "Network file system — data exposure"),
            3306: ("MySQL", "Database — should not be internet-facing"),
            3389: ("RDP", "Remote desktop — brute force target"),
            5432: ("PostgreSQL", "Database — should not be internet-facing"),
            5900: ("VNC", "Remote desktop — often unencrypted"),
            6379: ("Redis", "Cache — often no authentication"),
            8080: ("HTTP-Alt", "Alternative HTTP — may be unprotected"),
            11211: ("Memcached", "Cache — amplification attacks"),
            27017: ("MongoDB", "Database — often no authentication"),
        }

        open_dangerous: list[dict[str, Any]] = []
        open_other: list[int] = []

        for port, (service, risk) in dangerous_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()
                if result == 0:
                    open_dangerous.append({"port": port, "service": service, "risk": risk})
            except (socket.error, OSError):
                pass

        if open_dangerous:
            # Group by severity
            critical_ports = [p for p in open_dangerous if p["port"] in (21, 23, 69, 512, 513, 514)]
            high_ports = [p for p in open_dangerous if p["port"] in (445, 3389, 6379, 27017, 11211)]
            medium_ports = [p for p in open_dangerous if p not in critical_ports and p not in high_ports]

            if critical_ports:
                findings.append(InfraFinding(
                    check_id="INFRA-NET-001",
                    title="Critical Insecure Services Running",
                    category=InfraCheckCategory.NETWORK_SECURITY,
                    severity=InfraCheckSeverity.CRITICAL,
                    status=InfraCheckStatus.FAIL,
                    description=f"Critical insecure services detected on {len(critical_ports)} ports.",
                    impact="Unencrypted protocols allow credential theft and data interception.",
                    remediation="Disable or replace with encrypted alternatives: FTP→SFTP, Telnet→SSH, rsh→SSH.",
                    evidence={"critical_ports": critical_ports},
                    cis_control="CIS Control 4.4",
                    cis_benchmark="CIS Benchmark 2.2.1",
                    weight=3.0,
                ))

            if high_ports:
                findings.append(InfraFinding(
                    check_id="INFRA-NET-002",
                    title="High-Risk Services Exposed",
                    category=InfraCheckCategory.NETWORK_SECURITY,
                    severity=InfraCheckSeverity.HIGH,
                    status=InfraCheckStatus.FAIL,
                    description=f"High-risk services detected on {len(high_ports)} ports.",
                    impact="Database and cache services exposed. Lateral movement and data theft possible.",
                    remediation="Bind services to localhost only. Use firewall rules to restrict access. Enable authentication.",
                    evidence={"high_risk_ports": high_ports},
                    cis_control="CIS Control 4.4",
                    cis_benchmark="CIS Benchmark 2.2.2",
                    weight=2.0,
                ))

            if medium_ports:
                findings.append(InfraFinding(
                    check_id="INFRA-NET-003",
                    title="Potentially Unnecessary Services Running",
                    category=InfraCheckCategory.NETWORK_SECURITY,
                    severity=InfraCheckSeverity.MEDIUM,
                    status=InfraCheckStatus.WARN,
                    description=f"Services detected on {len(medium_ports)} ports that may not be required.",
                    impact="Increased attack surface. Each open port is a potential entry point.",
                    remediation="Review and disable unnecessary services. Apply principle of least functionality.",
                    evidence={"medium_risk_ports": medium_ports},
                    cis_control="CIS Control 4.8",
                    weight=1.0,
                ))
        else:
            findings.append(InfraFinding(
                check_id="INFRA-NET-001",
                title="No Dangerous Ports Open",
                category=InfraCheckCategory.NETWORK_SECURITY,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.PASS,
                description="No commonly dangerous ports detected as open on localhost.",
                impact="N/A",
                remediation="N/A",
                evidence={"scanned_ports": len(dangerous_ports)},
                cis_control="CIS Control 4.4",
                weight=3.0,
            ))

        return findings

    def check_dns_config(self) -> InfraFinding:
        """Check DNS resolver configuration."""
        try:
            hostname = socket.gethostname()
            fqdn = socket.getfqdn()

            # Check if hostname resolves
            try:
                socket.gethostbyname(hostname)
                resolves = True
            except socket.gaierror:
                resolves = False

            if resolves:
                return InfraFinding(
                    check_id="INFRA-NET-010",
                    title="DNS Resolution Working",
                    category=InfraCheckCategory.NETWORK_SECURITY,
                    severity=InfraCheckSeverity.INFO,
                    status=InfraCheckStatus.PASS,
                    description="Hostname resolves correctly.",
                    impact="N/A",
                    remediation="N/A",
                    evidence={"hostname": hostname, "fqdn": fqdn},
                    cis_control="CIS Control 9.2",
                    weight=1.0,
                )
            else:
                return InfraFinding(
                    check_id="INFRA-NET-010",
                    title="DNS Resolution Failure",
                    category=InfraCheckCategory.NETWORK_SECURITY,
                    severity=InfraCheckSeverity.MEDIUM,
                    status=InfraCheckStatus.WARN,
                    description="Hostname does not resolve via DNS.",
                    impact="Service discovery and certificate validation may fail.",
                    remediation="Configure DNS properly. Ensure /etc/hosts or DNS server has correct entries.",
                    evidence={"hostname": hostname, "fqdn": fqdn},
                    cis_control="CIS Control 9.2",
                    weight=1.0,
                )
        except Exception as e:
            return InfraFinding(
                check_id="INFRA-NET-010",
                title="DNS Check Error",
                category=InfraCheckCategory.NETWORK_SECURITY,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.ERROR,
                description=f"Could not check DNS: {e}",
                impact="Unknown",
                remediation="Investigate DNS configuration manually.",
                evidence={"error": str(e)},
                weight=1.0,
            )


class FileSystemChecks:
    """File system security audits."""

    def check_sensitive_file_permissions(self) -> list[InfraFinding]:
        """Check permissions on sensitive files."""
        findings: list[InfraFinding] = []

        sensitive_files = [
            {"path": ".env", "max_mode": 0o600, "description": "Environment secrets file"},
            {"path": "backend/config.py", "max_mode": 0o644, "description": "Configuration module"},
            {"path": ".git/config", "max_mode": 0o644, "description": "Git configuration"},
        ]

        # Also check for common sensitive files in project root
        project_root = Path(".")
        for pattern in ["*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "*.env.*"]:
            for match in project_root.glob(pattern):
                sensitive_files.append({
                    "path": str(match),
                    "max_mode": 0o600,
                    "description": f"Sensitive file: {match.name}",
                })

        for spec in sensitive_files:
            path = Path(spec["path"])
            if not path.exists():
                continue

            try:
                if _is_windows():
                    # Windows doesn't use Unix permissions — check if file is readable by everyone
                    findings.append(InfraFinding(
                        check_id=f"INFRA-FS-{hashlib.sha256(spec['path'].encode()).hexdigest()[:8]}",
                        title=f"Sensitive File Exists: {spec['path']}",
                        category=InfraCheckCategory.FILE_INTEGRITY,
                        severity=InfraCheckSeverity.INFO,
                        status=InfraCheckStatus.PASS,
                        description=f"{spec['description']} exists. Windows ACLs not checked.",
                        impact="N/A",
                        remediation="Verify Windows ACLs restrict access to authorised users only.",
                        evidence={"path": spec["path"], "platform": "windows"},
                        cis_control="CIS Control 3.3",
                        weight=1.5,
                    ))
                else:
                    mode = path.stat().st_mode & 0o777
                    max_mode = spec["max_mode"]

                    if mode > max_mode:
                        findings.append(InfraFinding(
                            check_id=f"INFRA-FS-{hashlib.sha256(spec['path'].encode()).hexdigest()[:8]}",
                            title=f"Overly Permissive: {spec['path']}",
                            category=InfraCheckCategory.FILE_INTEGRITY,
                            severity=InfraCheckSeverity.HIGH if max_mode <= 0o600 else InfraCheckSeverity.MEDIUM,
                            status=InfraCheckStatus.FAIL,
                            description=f"{spec['description']} has permissions {oct(mode)} (max allowed: {oct(max_mode)}).",
                            impact="Unauthorised users may read sensitive data.",
                            remediation=f"Run: chmod {oct(max_mode)} {spec['path']}",
                            evidence={"path": spec["path"], "current_mode": oct(mode), "max_mode": oct(max_mode)},
                            cis_control="CIS Control 3.3",
                            cis_benchmark="CIS Benchmark 1.4.2",
                            weight=2.0,
                        ))
                    else:
                        findings.append(InfraFinding(
                            check_id=f"INFRA-FS-{hashlib.sha256(spec['path'].encode()).hexdigest()[:8]}",
                            title=f"Correct Permissions: {spec['path']}",
                            category=InfraCheckCategory.FILE_INTEGRITY,
                            severity=InfraCheckSeverity.INFO,
                            status=InfraCheckStatus.PASS,
                            description=f"{spec['description']} has correct permissions {oct(mode)}.",
                            impact="N/A",
                            remediation="N/A",
                            evidence={"path": spec["path"], "mode": oct(mode)},
                            cis_control="CIS Control 3.3",
                            weight=2.0,
                        ))
            except OSError as e:
                findings.append(InfraFinding(
                    check_id=f"INFRA-FS-{hashlib.sha256(spec['path'].encode()).hexdigest()[:8]}",
                    title=f"Cannot Check: {spec['path']}",
                    category=InfraCheckCategory.FILE_INTEGRITY,
                    severity=InfraCheckSeverity.INFO,
                    status=InfraCheckStatus.ERROR,
                    description=f"Could not check permissions: {e}",
                    impact="Unknown",
                    remediation="Verify file permissions manually.",
                    evidence={"path": spec["path"], "error": str(e)},
                    weight=1.0,
                ))

        return findings

    def check_disk_space(self) -> InfraFinding:
        """Check available disk space."""
        try:
            usage = shutil.disk_usage(".")
            percent_used = (usage.used / usage.total) * 100
            free_gb = usage.free / (1024 ** 3)

            if percent_used > 95:
                return InfraFinding(
                    check_id="INFRA-FS-DISK-001",
                    title="Critical Disk Space",
                    category=InfraCheckCategory.RESOURCE_HEALTH,
                    severity=InfraCheckSeverity.CRITICAL,
                    status=InfraCheckStatus.FAIL,
                    description=f"Disk is {percent_used:.1f}% full. Only {free_gb:.1f}GB free.",
                    impact="System may crash. Logs cannot be written. Database corruption possible.",
                    remediation="Free disk space immediately. Remove old logs, temp files, and unused data.",
                    evidence={"percent_used": percent_used, "free_gb": round(free_gb, 2), "total_gb": round(usage.total / (1024**3), 2)},
                    cis_control="CIS Control 8.3",
                    weight=3.0,
                )
            elif percent_used > 85:
                return InfraFinding(
                    check_id="INFRA-FS-DISK-001",
                    title="Low Disk Space Warning",
                    category=InfraCheckCategory.RESOURCE_HEALTH,
                    severity=InfraCheckSeverity.MEDIUM,
                    status=InfraCheckStatus.WARN,
                    description=f"Disk is {percent_used:.1f}% full. {free_gb:.1f}GB free.",
                    impact="May run out of space soon. Log rotation and cleanup needed.",
                    remediation="Implement log rotation. Schedule regular cleanup. Monitor disk usage.",
                    evidence={"percent_used": percent_used, "free_gb": round(free_gb, 2)},
                    cis_control="CIS Control 8.3",
                    weight=1.5,
                )
            else:
                return InfraFinding(
                    check_id="INFRA-FS-DISK-001",
                    title="Disk Space Adequate",
                    category=InfraCheckCategory.RESOURCE_HEALTH,
                    severity=InfraCheckSeverity.INFO,
                    status=InfraCheckStatus.PASS,
                    description=f"Disk is {percent_used:.1f}% full. {free_gb:.1f}GB free.",
                    impact="N/A",
                    remediation="N/A",
                    evidence={"percent_used": percent_used, "free_gb": round(free_gb, 2)},
                    cis_control="CIS Control 8.3",
                    weight=1.5,
                )
        except Exception as e:
            return InfraFinding(
                check_id="INFRA-FS-DISK-001",
                title="Disk Space Check Error",
                category=InfraCheckCategory.RESOURCE_HEALTH,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.ERROR,
                description=f"Could not check disk space: {e}",
                impact="Unknown",
                remediation="Check disk space manually.",
                evidence={"error": str(e)},
                weight=1.0,
            )

    def check_temp_directory(self) -> InfraFinding:
        """Check temp directory security."""
        import tempfile
        temp_dir = Path(tempfile.gettempdir())

        try:
            if _is_linux():
                # Check if /tmp is a separate partition with noexec
                stdout, _, rc = _run_cmd(["mount"])
                if rc == 0 and "/tmp" in stdout:
                    if "noexec" not in stdout.split("/tmp")[1].split("\n")[0]:
                        return InfraFinding(
                            check_id="INFRA-FS-TMP-001",
                            title="/tmp Not Mounted with noexec",
                            category=InfraCheckCategory.SECURE_CONFIG,
                            severity=InfraCheckSeverity.MEDIUM,
                            status=InfraCheckStatus.FAIL,
                            description="/tmp partition does not have noexec mount option.",
                            impact="Attackers can execute uploaded malware from /tmp.",
                            remediation="Add noexec,nosuid,nodev to /tmp mount options in /etc/fstab.",
                            evidence={"temp_dir": str(temp_dir)},
                            cis_control="CIS Control 4.1",
                            cis_benchmark="CIS Benchmark 1.1.2",
                            weight=1.5,
                        )

            return InfraFinding(
                check_id="INFRA-FS-TMP-001",
                title="Temp Directory Check",
                category=InfraCheckCategory.SECURE_CONFIG,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.PASS,
                description=f"Temp directory: {temp_dir}",
                impact="N/A",
                remediation="N/A",
                evidence={"temp_dir": str(temp_dir), "exists": temp_dir.exists()},
                cis_control="CIS Control 4.1",
                weight=1.0,
            )
        except Exception as e:
            return InfraFinding(
                check_id="INFRA-FS-TMP-001",
                title="Temp Directory Check Error",
                category=InfraCheckCategory.SECURE_CONFIG,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.ERROR,
                description=f"Could not check temp directory: {e}",
                impact="Unknown",
                remediation="Check manually.",
                evidence={"error": str(e)},
                weight=1.0,
            )


class AccountSecurityChecks:
    """User account and authentication audits."""

    def check_password_policy(self) -> InfraFinding:
        """Check system password policy (Linux)."""
        if not _is_linux():
            return InfraFinding(
                check_id="INFRA-ACC-001",
                title="Password Policy Check",
                category=InfraCheckCategory.ACCOUNT_MGMT,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.SKIP,
                description="Password policy check only available on Linux.",
                impact="N/A",
                remediation="N/A",
                evidence={"platform": platform.system()},
                weight=2.0,
            )

        # Check /etc/login.defs
        login_defs = Path("/etc/login.defs")
        if not login_defs.exists():
            return InfraFinding(
                check_id="INFRA-ACC-001",
                title="Password Policy File Missing",
                category=InfraCheckCategory.ACCOUNT_MGMT,
                severity=InfraCheckSeverity.HIGH,
                status=InfraCheckStatus.FAIL,
                description="/etc/login.defs not found.",
                impact="No system-wide password policy enforced.",
                remediation="Create /etc/login.defs with appropriate password aging settings.",
                evidence={"file": "/etc/login.defs", "exists": False},
                cis_control="CIS Control 5.2",
                cis_benchmark="CIS Benchmark 5.4.1",
                weight=2.0,
            )

        try:
            content = login_defs.read_text()
            settings: dict[str, str] = {}
            for line in content.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2:
                        settings[parts[0]] = parts[1]

            issues: list[str] = []
            pass_max_days = int(settings.get("PASS_MAX_DAYS", "99999"))
            pass_min_days = int(settings.get("PASS_MIN_DAYS", "0"))
            pass_min_len = int(settings.get("PASS_MIN_LEN", "5"))

            if pass_max_days > 90:
                issues.append(f"PASS_MAX_DAYS={pass_max_days} (should be ≤90)")
            if pass_min_days < 1:
                issues.append(f"PASS_MIN_DAYS={pass_min_days} (should be ≥1)")
            if pass_min_len < 12:
                issues.append(f"PASS_MIN_LEN={pass_min_len} (should be ≥12)")

            if issues:
                return InfraFinding(
                    check_id="INFRA-ACC-001",
                    title="Weak Password Policy",
                    category=InfraCheckCategory.ACCOUNT_MGMT,
                    severity=InfraCheckSeverity.MEDIUM,
                    status=InfraCheckStatus.FAIL,
                    description=f"Password policy issues: {'; '.join(issues)}",
                    impact="Weak passwords may persist. Compromised accounts not forced to rotate.",
                    remediation="Set PASS_MAX_DAYS=90, PASS_MIN_DAYS=1, PASS_MIN_LEN=12 in /etc/login.defs.",
                    evidence={"settings": settings, "issues": issues},
                    cis_control="CIS Control 5.2",
                    cis_benchmark="CIS Benchmark 5.4.1",
                    weight=2.0,
                )
            else:
                return InfraFinding(
                    check_id="INFRA-ACC-001",
                    title="Password Policy Adequate",
                    category=InfraCheckCategory.ACCOUNT_MGMT,
                    severity=InfraCheckSeverity.INFO,
                    status=InfraCheckStatus.PASS,
                    description="Password policy meets minimum requirements.",
                    impact="N/A",
                    remediation="N/A",
                    evidence={"settings": settings},
                    cis_control="CIS Control 5.2",
                    weight=2.0,
                )
        except Exception as e:
            return InfraFinding(
                check_id="INFRA-ACC-001",
                title="Password Policy Check Error",
                category=InfraCheckCategory.ACCOUNT_MGMT,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.ERROR,
                description=f"Error reading password policy: {e}",
                impact="Unknown",
                remediation="Check /etc/login.defs manually.",
                evidence={"error": str(e)},
                weight=2.0,
            )

    def check_root_login(self) -> InfraFinding:
        """Check if direct root login is disabled."""
        if not _is_linux():
            return InfraFinding(
                check_id="INFRA-ACC-002",
                title="Root Login Check",
                category=InfraCheckCategory.ACCOUNT_MGMT,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.SKIP,
                description="Root login check only available on Linux.",
                impact="N/A",
                remediation="N/A",
                evidence={"platform": platform.system()},
                weight=2.5,
            )

        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            return InfraFinding(
                check_id="INFRA-ACC-002",
                title="SSH Configuration Not Found",
                category=InfraCheckCategory.ACCOUNT_MGMT,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.SKIP,
                description="SSH server configuration not found (SSH may not be installed).",
                impact="N/A",
                remediation="N/A",
                evidence={"file": "/etc/ssh/sshd_config", "exists": False},
                weight=2.5,
            )

        try:
            content = sshd_config.read_text()
            permit_root = re.search(r"^\s*PermitRootLogin\s+(\S+)", content, re.MULTILINE)

            if permit_root:
                value = permit_root.group(1).lower()
                if value in ("no", "prohibit-password", "forced-commands-only"):
                    return InfraFinding(
                        check_id="INFRA-ACC-002",
                        title="Root Login Restricted",
                        category=InfraCheckCategory.ACCOUNT_MGMT,
                        severity=InfraCheckSeverity.INFO,
                        status=InfraCheckStatus.PASS,
                        description=f"PermitRootLogin set to '{value}'.",
                        impact="N/A",
                        remediation="N/A",
                        evidence={"permit_root_login": value},
                        cis_control="CIS Control 5.4",
                        cis_benchmark="CIS Benchmark 5.2.10",
                        weight=2.5,
                    )
                else:
                    return InfraFinding(
                        check_id="INFRA-ACC-002",
                        title="Root Login Permitted via SSH",
                        category=InfraCheckCategory.ACCOUNT_MGMT,
                        severity=InfraCheckSeverity.HIGH,
                        status=InfraCheckStatus.FAIL,
                        description=f"PermitRootLogin set to '{value}'. Direct root SSH access is allowed.",
                        impact="Brute force attacks target root directly. No audit trail for who used root.",
                        remediation="Set PermitRootLogin to 'no' in /etc/ssh/sshd_config. Use sudo for privilege escalation.",
                        evidence={"permit_root_login": value},
                        cis_control="CIS Control 5.4",
                        cis_benchmark="CIS Benchmark 5.2.10",
                        weight=2.5,
                    )
            else:
                # Default is usually 'yes' if not specified
                return InfraFinding(
                    check_id="INFRA-ACC-002",
                    title="Root Login Not Explicitly Disabled",
                    category=InfraCheckCategory.ACCOUNT_MGMT,
                    severity=InfraCheckSeverity.MEDIUM,
                    status=InfraCheckStatus.WARN,
                    description="PermitRootLogin not explicitly set in sshd_config (default may allow root).",
                    impact="Root login may be permitted depending on system defaults.",
                    remediation="Explicitly set PermitRootLogin no in /etc/ssh/sshd_config.",
                    evidence={"permit_root_login": "not_set"},
                    cis_control="CIS Control 5.4",
                    weight=2.5,
                )
        except Exception as e:
            return InfraFinding(
                check_id="INFRA-ACC-002",
                title="Root Login Check Error",
                category=InfraCheckCategory.ACCOUNT_MGMT,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.ERROR,
                description=f"Error checking root login: {e}",
                impact="Unknown",
                remediation="Check /etc/ssh/sshd_config manually.",
                evidence={"error": str(e)},
                weight=2.5,
            )


class ServiceSecurityChecks:
    """Running service security audits."""

    def check_python_version(self) -> InfraFinding:
        """Check Python version for known vulnerabilities."""
        import sys
        version = sys.version_info
        version_str = f"{version.major}.{version.minor}.{version.micro}"

        # Python versions with known security issues
        if version.major < 3 or (version.major == 3 and version.minor < 9):
            return InfraFinding(
                check_id="INFRA-SVC-001",
                title=f"Outdated Python Version: {version_str}",
                category=InfraCheckCategory.PATCH_MGMT,
                severity=InfraCheckSeverity.HIGH,
                status=InfraCheckStatus.FAIL,
                description=f"Python {version_str} is end-of-life or has known vulnerabilities.",
                impact="Known security vulnerabilities in standard library. No security patches.",
                remediation="Upgrade to Python 3.11+ for security fixes and performance improvements.",
                evidence={"version": version_str, "major": version.major, "minor": version.minor},
                cis_control="CIS Control 7.4",
                weight=2.0,
            )
        elif version.major == 3 and version.minor < 11:
            return InfraFinding(
                check_id="INFRA-SVC-001",
                title=f"Python Version: {version_str} (Acceptable)",
                category=InfraCheckCategory.PATCH_MGMT,
                severity=InfraCheckSeverity.LOW,
                status=InfraCheckStatus.WARN,
                description=f"Python {version_str} is supported but not latest.",
                impact="May miss recent security fixes.",
                remediation="Consider upgrading to Python 3.12+ for latest security patches.",
                evidence={"version": version_str},
                cis_control="CIS Control 7.4",
                weight=1.0,
            )
        else:
            return InfraFinding(
                check_id="INFRA-SVC-001",
                title=f"Python Version: {version_str} (Current)",
                category=InfraCheckCategory.PATCH_MGMT,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.PASS,
                description=f"Python {version_str} is current and supported.",
                impact="N/A",
                remediation="N/A",
                evidence={"version": version_str},
                cis_control="CIS Control 7.4",
                weight=1.0,
            )

    def check_debug_mode(self) -> InfraFinding:
        """Check if application is running in debug mode."""
        # Check common environment variables
        debug_indicators = {
            "DEBUG": os.environ.get("DEBUG", ""),
            "FLASK_DEBUG": os.environ.get("FLASK_DEBUG", ""),
            "DJANGO_DEBUG": os.environ.get("DJANGO_DEBUG", ""),
            "FASTAPI_DEBUG": os.environ.get("FASTAPI_DEBUG", ""),
            "ENVIRONMENT": os.environ.get("ENVIRONMENT", ""),
            "ENV": os.environ.get("ENV", ""),
        }

        debug_active = False
        active_flags: list[str] = []

        for key, value in debug_indicators.items():
            if value.lower() in ("true", "1", "yes", "on", "development", "dev"):
                debug_active = True
                active_flags.append(f"{key}={value}")

        if debug_active:
            return InfraFinding(
                check_id="INFRA-SVC-002",
                title="Debug Mode Active",
                category=InfraCheckCategory.SECURE_CONFIG,
                severity=InfraCheckSeverity.HIGH,
                status=InfraCheckStatus.FAIL,
                description=f"Application running in debug mode: {', '.join(active_flags)}",
                impact="Detailed error messages, stack traces, and internal state exposed to attackers.",
                remediation="Set DEBUG=false and ENVIRONMENT=production for production deployments.",
                evidence={"debug_flags": active_flags},
                cis_control="CIS Control 4.1",
                cis_benchmark="CIS Benchmark 2.2",
                weight=2.5,
            )
        else:
            return InfraFinding(
                check_id="INFRA-SVC-002",
                title="Debug Mode Disabled",
                category=InfraCheckCategory.SECURE_CONFIG,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.PASS,
                description="No debug mode indicators detected.",
                impact="N/A",
                remediation="N/A",
                evidence={"checked_vars": list(debug_indicators.keys())},
                cis_control="CIS Control 4.1",
                weight=2.5,
            )

    def check_environment_secrets(self) -> InfraFinding:
        """Check that required secrets are set and not defaults."""
        required_secrets = [
            "AISA_API_KEY",
            "GROQ_API_KEY",
            "SECRET_KEY",
        ]

        missing: list[str] = []
        default_values: list[str] = []
        present: list[str] = []

        default_patterns = [
            "changeme", "default", "password", "secret", "xxx",
            "your-key-here", "sk-xxx", "placeholder", "todo",
        ]

        for secret in required_secrets:
            value = os.environ.get(secret, "")
            if not value:
                missing.append(secret)
            elif any(dp in value.lower() for dp in default_patterns):
                default_values.append(secret)
            else:
                present.append(secret)

        if missing or default_values:
            severity = InfraCheckSeverity.CRITICAL if missing else InfraCheckSeverity.HIGH
            return InfraFinding(
                check_id="INFRA-SVC-003",
                title="Missing or Default Secrets",
                category=InfraCheckCategory.DATA_PROTECTION,
                severity=severity,
                status=InfraCheckStatus.FAIL,
                description=f"Missing: {missing}. Default values: {default_values}.",
                impact="Application may fail or use insecure defaults. API access compromised.",
                remediation="Set all required secrets in .env file with strong, unique values.",
                evidence={"missing": missing, "default_values": default_values, "present": len(present)},
                cis_control="CIS Control 3.11",
                weight=3.0,
            )
        else:
            return InfraFinding(
                check_id="INFRA-SVC-003",
                title="All Required Secrets Set",
                category=InfraCheckCategory.DATA_PROTECTION,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.PASS,
                description=f"All {len(required_secrets)} required secrets are set with non-default values.",
                impact="N/A",
                remediation="N/A",
                evidence={"secrets_checked": len(required_secrets), "all_present": True},
                cis_control="CIS Control 3.11",
                weight=3.0,
            )


class ResourceHealthChecks:
    """System resource health monitoring."""

    def check_memory(self) -> InfraFinding:
        """Check system memory usage."""
        try:
            if _is_linux():
                stdout, _, rc = _run_cmd(["free", "-m"])
                if rc == 0:
                    lines = stdout.split("\n")
                    for line in lines:
                        if line.startswith("Mem:"):
                            parts = line.split()
                            total_mb = int(parts[1])
                            used_mb = int(parts[2])
                            percent = (used_mb / total_mb) * 100 if total_mb > 0 else 0

                            if percent > 95:
                                severity = InfraCheckSeverity.CRITICAL
                                status = InfraCheckStatus.FAIL
                            elif percent > 85:
                                severity = InfraCheckSeverity.MEDIUM
                                status = InfraCheckStatus.WARN
                            else:
                                severity = InfraCheckSeverity.INFO
                                status = InfraCheckStatus.PASS

                            return InfraFinding(
                                check_id="INFRA-RES-001",
                                title=f"Memory Usage: {percent:.1f}%",
                                category=InfraCheckCategory.RESOURCE_HEALTH,
                                severity=severity,
                                status=status,
                                description=f"Memory: {used_mb}MB used of {total_mb}MB ({percent:.1f}%).",
                                impact="High memory may cause OOM kills, swap thrashing, or service crashes." if percent > 85 else "N/A",
                                remediation="Investigate memory-hungry processes. Consider scaling or optimising." if percent > 85 else "N/A",
                                evidence={"total_mb": total_mb, "used_mb": used_mb, "percent": round(percent, 1)},
                                cis_control="CIS Control 8.3",
                                weight=1.5,
                            )

            # Fallback: use psutil if available
            try:
                import psutil
                mem = psutil.virtual_memory()
                percent = mem.percent

                if percent > 95:
                    severity = InfraCheckSeverity.CRITICAL
                    status = InfraCheckStatus.FAIL
                elif percent > 85:
                    severity = InfraCheckSeverity.MEDIUM
                    status = InfraCheckStatus.WARN
                else:
                    severity = InfraCheckSeverity.INFO
                    status = InfraCheckStatus.PASS

                return InfraFinding(
                    check_id="INFRA-RES-001",
                    title=f"Memory Usage: {percent:.1f}%",
                    category=InfraCheckCategory.RESOURCE_HEALTH,
                    severity=severity,
                    status=status,
                    description=f"Memory: {percent:.1f}% used ({mem.used // (1024**2)}MB of {mem.total // (1024**2)}MB).",
                    impact="High memory may cause OOM kills or service crashes." if percent > 85 else "N/A",
                    remediation="Investigate memory usage. Scale or optimise." if percent > 85 else "N/A",
                    evidence={"percent": percent, "total_mb": mem.total // (1024**2), "used_mb": mem.used // (1024**2)},
                    cis_control="CIS Control 8.3",
                    weight=1.5,
                )
            except ImportError:
                pass

            return InfraFinding(
                check_id="INFRA-RES-001",
                title="Memory Check Unavailable",
                category=InfraCheckCategory.RESOURCE_HEALTH,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.SKIP,
                description="Cannot determine memory usage (psutil not installed, not Linux).",
                impact="N/A",
                remediation="Install psutil for memory monitoring: pip install psutil",
                evidence={"platform": platform.system()},
                weight=1.0,
            )
        except Exception as e:
            return InfraFinding(
                check_id="INFRA-RES-001",
                title="Memory Check Error",
                category=InfraCheckCategory.RESOURCE_HEALTH,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.ERROR,
                description=f"Error checking memory: {e}",
                impact="Unknown",
                remediation="Check memory manually.",
                evidence={"error": str(e)},
                weight=1.0,
            )

    def check_uptime(self) -> InfraFinding:
        """Check system uptime (long uptime may indicate missing patches)."""
        try:
            if _is_linux():
                stdout, _, rc = _run_cmd(["uptime", "-s"])
                if rc == 0:
                    # Parse uptime start time
                    import datetime
                    start = datetime.datetime.strptime(stdout.strip(), "%Y-%m-%d %H:%M:%S")
                    uptime_days = (datetime.datetime.now() - start).days

                    if uptime_days > 90:
                        return InfraFinding(
                            check_id="INFRA-RES-002",
                            title=f"System Uptime: {uptime_days} Days",
                            category=InfraCheckCategory.PATCH_MGMT,
                            severity=InfraCheckSeverity.MEDIUM,
                            status=InfraCheckStatus.WARN,
                            description=f"System has been running for {uptime_days} days without reboot.",
                            impact="Kernel patches and system updates may not be applied (require reboot).",
                            remediation="Schedule maintenance window for reboot to apply pending kernel updates.",
                            evidence={"uptime_days": uptime_days, "boot_time": stdout.strip()},
                            cis_control="CIS Control 7.3",
                            weight=1.0,
                        )
                    else:
                        return InfraFinding(
                            check_id="INFRA-RES-002",
                            title=f"System Uptime: {uptime_days} Days",
                            category=InfraCheckCategory.PATCH_MGMT,
                            severity=InfraCheckSeverity.INFO,
                            status=InfraCheckStatus.PASS,
                            description=f"System uptime is {uptime_days} days (within acceptable range).",
                            impact="N/A",
                            remediation="N/A",
                            evidence={"uptime_days": uptime_days, "boot_time": stdout.strip()},
                            cis_control="CIS Control 7.3",
                            weight=1.0,
                        )

            return InfraFinding(
                check_id="INFRA-RES-002",
                title="Uptime Check",
                category=InfraCheckCategory.PATCH_MGMT,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.SKIP,
                description="Uptime check not available on this platform.",
                impact="N/A",
                remediation="N/A",
                evidence={"platform": platform.system()},
                weight=1.0,
            )
        except Exception as e:
            return InfraFinding(
                check_id="INFRA-RES-002",
                title="Uptime Check Error",
                category=InfraCheckCategory.RESOURCE_HEALTH,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.ERROR,
                description=f"Error checking uptime: {e}",
                impact="Unknown",
                remediation="Check uptime manually: uptime -s",
                evidence={"error": str(e)},
                weight=1.0,
            )


class CryptoConfigChecks:
    """Cryptographic configuration audits."""

    def check_ssh_config(self) -> list[InfraFinding]:
        """Check SSH server cryptographic configuration."""
        findings: list[InfraFinding] = []

        if not _is_linux():
            findings.append(InfraFinding(
                check_id="INFRA-CRY-001",
                title="SSH Crypto Check",
                category=InfraCheckCategory.CRYPTO_CONFIG,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.SKIP,
                description="SSH crypto check only available on Linux.",
                impact="N/A",
                remediation="N/A",
                evidence={"platform": platform.system()},
                weight=2.0,
            ))
            return findings

        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            findings.append(InfraFinding(
                check_id="INFRA-CRY-001",
                title="SSH Configuration Not Found",
                category=InfraCheckCategory.CRYPTO_CONFIG,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.SKIP,
                description="SSH server configuration not found.",
                impact="N/A",
                remediation="N/A",
                evidence={"file": "/etc/ssh/sshd_config"},
                weight=2.0,
            ))
            return findings

        try:
            content = sshd_config.read_text()

            # Check for weak ciphers
            weak_ciphers = ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
                            "blowfish-cbc", "cast128-cbc", "arcfour"]
            cipher_match = re.search(r"^\s*Ciphers\s+(.+)$", content, re.MULTILINE)

            if cipher_match:
                configured_ciphers = [c.strip().lower() for c in cipher_match.group(1).split(",")]
                weak_found = [c for c in configured_ciphers if c in weak_ciphers]

                if weak_found:
                    findings.append(InfraFinding(
                        check_id="INFRA-CRY-002",
                        title="Weak SSH Ciphers Enabled",
                        category=InfraCheckCategory.CRYPTO_CONFIG,
                        severity=InfraCheckSeverity.HIGH,
                        status=InfraCheckStatus.FAIL,
                        description=f"Weak SSH ciphers enabled: {', '.join(weak_found)}",
                        impact="CBC mode ciphers vulnerable to BEAST and padding oracle attacks.",
                        remediation="Set Ciphers to: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
                        evidence={"weak_ciphers": weak_found, "all_ciphers": configured_ciphers},
                        cis_control="CIS Control 3.10",
                        cis_benchmark="CIS Benchmark 5.2.13",
                        weight=2.0,
                    ))
                else:
                    findings.append(InfraFinding(
                        check_id="INFRA-CRY-002",
                        title="SSH Ciphers Adequate",
                        category=InfraCheckCategory.CRYPTO_CONFIG,
                        severity=InfraCheckSeverity.INFO,
                        status=InfraCheckStatus.PASS,
                        description="No weak SSH ciphers detected.",
                        impact="N/A",
                        remediation="N/A",
                        evidence={"ciphers": configured_ciphers},
                        cis_control="CIS Control 3.10",
                        weight=2.0,
                    ))

            # Check for weak MACs
            weak_macs = ["hmac-md5", "hmac-sha1", "hmac-md5-96", "hmac-sha1-96"]
            mac_match = re.search(r"^\s*MACs\s+(.+)$", content, re.MULTILINE)

            if mac_match:
                configured_macs = [m.strip().lower() for m in mac_match.group(1).split(",")]
                weak_mac_found = [m for m in configured_macs if m in weak_macs]

                if weak_mac_found:
                    findings.append(InfraFinding(
                        check_id="INFRA-CRY-003",
                        title="Weak SSH MACs Enabled",
                        category=InfraCheckCategory.CRYPTO_CONFIG,
                        severity=InfraCheckSeverity.MEDIUM,
                        status=InfraCheckStatus.FAIL,
                        description=f"Weak SSH MACs enabled: {', '.join(weak_mac_found)}",
                        impact="MD5 and SHA1 MACs have known weaknesses.",
                        remediation="Set MACs to: hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
                        evidence={"weak_macs": weak_mac_found, "all_macs": configured_macs},
                        cis_control="CIS Control 3.10",
                        cis_benchmark="CIS Benchmark 5.2.14",
                        weight=1.5,
                    ))
                else:
                    findings.append(InfraFinding(
                        check_id="INFRA-CRY-003",
                        title="SSH MACs Adequate",
                        category=InfraCheckCategory.CRYPTO_CONFIG,
                        severity=InfraCheckSeverity.INFO,
                        status=InfraCheckStatus.PASS,
                        description="No weak SSH MACs detected.",
                        impact="N/A",
                        remediation="N/A",
                        evidence={"macs": configured_macs},
                        cis_control="CIS Control 3.10",
                        weight=1.5,
                    ))

            # Check Protocol version
            protocol_match = re.search(r"^\s*Protocol\s+(\d+)", content, re.MULTILINE)
            if protocol_match:
                protocol = int(protocol_match.group(1))
                if protocol == 1:
                    findings.append(InfraFinding(
                        check_id="INFRA-CRY-004",
                        title="SSH Protocol 1 Enabled",
                        category=InfraCheckCategory.CRYPTO_CONFIG,
                        severity=InfraCheckSeverity.CRITICAL,
                        status=InfraCheckStatus.FAIL,
                        description="SSH Protocol 1 is enabled. This protocol has fundamental cryptographic weaknesses.",
                        impact="Session hijacking, key recovery attacks.",
                        remediation="Set Protocol 2 in /etc/ssh/sshd_config. Remove Protocol 1.",
                        evidence={"protocol": protocol},
                        cis_control="CIS Control 3.10",
                        cis_benchmark="CIS Benchmark 5.2.4",
                        weight=3.0,
                    ))

        except Exception as e:
            findings.append(InfraFinding(
                check_id="INFRA-CRY-001",
                title="SSH Crypto Check Error",
                category=InfraCheckCategory.CRYPTO_CONFIG,
                severity=InfraCheckSeverity.INFO,
                status=InfraCheckStatus.ERROR,
                description=f"Error checking SSH crypto: {e}",
                impact="Unknown",
                remediation="Check SSH configuration manually.",
                evidence={"error": str(e)},
                weight=2.0,
            ))

        return findings


class FirewallChecks:
    """Firewall configuration audits."""

    def check_firewall_status(self) -> InfraFinding:
        """Check if a firewall is active."""
        if _is_linux():
            # Check iptables
            stdout, stderr, rc = _run_cmd(["iptables", "-L", "-n", "--line-numbers"])
            if rc == 0:
                rules = [l for l in stdout.split("\n") if l.strip() and not l.startswith("Chain") and not l.startswith("num")]
                if len(rules) > 0:
                    return InfraFinding(
                        check_id="INFRA-FW-001",
                        title="Firewall Active (iptables)",
                        category=InfraCheckCategory.NETWORK_SECURITY,
                        severity=InfraCheckSeverity.INFO,
                        status=InfraCheckStatus.PASS,
                        description=f"iptables firewall active with {len(rules)} rules.",
                        impact="N/A",
                        remediation="N/A",
                        evidence={"rule_count": len(rules), "tool": "iptables"},
                        cis_control="CIS Control 4.4",
                        cis_benchmark="CIS Benchmark 3.5.1",
                        weight=3.0,
                    )

            # Check ufw
            stdout, stderr, rc = _run_cmd(["ufw", "status"])
            if rc == 0 and "active" in stdout.lower():
                return InfraFinding(
                    check_id="INFRA-FW-001",
                    title="Firewall Active (ufw)",
                    category=InfraCheckCategory.NETWORK_SECURITY,
                    severity=InfraCheckSeverity.INFO,
                    status=InfraCheckStatus.PASS,
                    description="UFW firewall is active.",
                    impact="N/A",
                    remediation="N/A",
                    evidence={"status": stdout[:200], "tool": "ufw"},
                    cis_control="CIS Control 4.4",
                    cis_benchmark="CIS Benchmark 3.5.1",
                    weight=3.0,
                )

            # Check firewalld
            stdout, stderr, rc = _run_cmd(["firewall-cmd", "--state"])
            if rc == 0 and "running" in stdout.lower():
                return InfraFinding(
                    check_id="INFRA-FW-001",
                    title="Firewall Active (firewalld)",
                    category=InfraCheckCategory.NETWORK_SECURITY,
                    severity=InfraCheckSeverity.INFO,
                    status=InfraCheckStatus.PASS,
                    description="firewalld is active.",
                    impact="N/A",
                    remediation="N/A",
                    evidence={"status": stdout, "tool": "firewalld"},
                    cis_control="CIS Control 4.4",
                    weight=3.0,
                )

            # No firewall detected
            return InfraFinding(
                check_id="INFRA-FW-001",
                title="No Firewall Detected",
                category=InfraCheckCategory.NETWORK_SECURITY,
                severity=InfraCheckSeverity.HIGH,
                status=InfraCheckStatus.FAIL,
                description="No active firewall detected (checked iptables, ufw, firewalld).",
                impact="All ports accessible. No network-level access control.",
                remediation="Enable a firewall: sudo ufw enable (Ubuntu) or sudo systemctl start firewalld (RHEL/CentOS).",
                evidence={"checked": ["iptables", "ufw", "firewalld"]},
                cis_control="CIS Control 4.4",
                cis_benchmark="CIS Benchmark 3.5.1",
                weight=3.0,
            )

        elif _is_windows():
            stdout, stderr, rc = _run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])
            if rc == 0:
                if "ON" in stdout.upper():
                    return InfraFinding(
                        check_id="INFRA-FW-001",
                        title="Windows Firewall Active",
                        category=InfraCheckCategory.NETWORK_SECURITY,
                        severity=InfraCheckSeverity.INFO,
                        status=InfraCheckStatus.PASS,
                        description="Windows Firewall is enabled.",
                        impact="N/A",
                        remediation="N/A",
                        evidence={"status": stdout[:300]},
                        cis_control="CIS Control 4.4",
                        weight=3.0,
                    )
                else:
                    return InfraFinding(
                        check_id="INFRA-FW-001",
                        title="Windows Firewall Disabled",
                        category=InfraCheckCategory.NETWORK_SECURITY,
                        severity=InfraCheckSeverity.HIGH,
                        status=InfraCheckStatus.FAIL,
                        description="Windows Firewall is disabled on one or more profiles.",
                        impact="All ports accessible. No network-level access control.",
                        remediation="Enable Windows Firewall: netsh advfirewall set allprofiles state on",
                        evidence={"status": stdout[:300]},
                        cis_control="CIS Control 4.4",
                        weight=3.0,
                    )

        return InfraFinding(
            check_id="INFRA-FW-001",
            title="Firewall Check Unavailable",
            category=InfraCheckCategory.NETWORK_SECURITY,
            severity=InfraCheckSeverity.INFO,
            status=InfraCheckStatus.SKIP,
            description=f"Firewall check not implemented for {platform.system()}.",
            impact="N/A",
            remediation="Check firewall status manually.",
            evidence={"platform": platform.system()},
            weight=3.0,
        )


# ---------------------------------------------------------------------------
# Main infrastructure scanner orchestrator
# ---------------------------------------------------------------------------

class InfrastructureScanner:
    """
    Orchestrates the full infrastructure security audit:
    1. System information gathering
    2. Network security checks (ports, DNS, firewall)
    3. File system checks (permissions, disk, temp)
    4. Account security checks (password policy, root login)
    5. Service checks (Python version, debug mode, secrets)
    6. Resource health checks (memory, uptime)
    7. Cryptographic configuration checks (SSH)
    8. Result aggregation with CIS Control mapping

    Design principle: Non-destructive, read-only checks. Never modifies
    system state. Safe to run in production. Cross-platform where possible
    with graceful degradation on unsupported platforms.
    """

    def __init__(self):
        self.network_checks = NetworkSecurityChecks()
        self.filesystem_checks = FileSystemChecks()
        self.account_checks = AccountSecurityChecks()
        self.service_checks = ServiceSecurityChecks()
        self.resource_checks = ResourceHealthChecks()
        self.crypto_checks = CryptoConfigChecks()
        self.firewall_checks = FirewallChecks()
        self._scan_history: list[InfraScanResult] = []

    async def scan(self) -> InfraScanResult:
        """
        Run a full infrastructure security audit.

        Returns:
            InfraScanResult with all findings and compliance scores
        """
        scan_id = hashlib.sha256(f"infra:{time.time()}".encode()).hexdigest()[:16]
        result = InfraScanResult(
            scan_id=scan_id,
            status=InfraScanStatus.RUNNING,
            started_at=time.time(),
            hostname=socket.gethostname(),
            os_info=f"{platform.system()} {platform.release()} ({platform.machine()})",
        )

        try:
            all_findings: list[InfraFinding] = []

            # Run all check categories
            logger.info(f"Infrastructure scan {scan_id}: Starting on {result.hostname}")

            # Network security
            logger.info(f"Infrastructure scan {scan_id}: Network checks")
            all_findings.extend(self.network_checks.check_open_ports())
            all_findings.append(self.network_checks.check_dns_config())

            # Firewall
            logger.info(f"Infrastructure scan {scan_id}: Firewall checks")
            all_findings.append(self.firewall_checks.check_firewall_status())

            # File system
            logger.info(f"Infrastructure scan {scan_id}: File system checks")
            all_findings.extend(self.filesystem_checks.check_sensitive_file_permissions())
            all_findings.append(self.filesystem_checks.check_disk_space())
            all_findings.append(self.filesystem_checks.check_temp_directory())

            # Account security
            logger.info(f"Infrastructure scan {scan_id}: Account checks")
            all_findings.append(self.account_checks.check_password_policy())
            all_findings.append(self.account_checks.check_root_login())

            # Service security
            logger.info(f"Infrastructure scan {scan_id}: Service checks")
            all_findings.append(self.service_checks.check_python_version())
            all_findings.append(self.service_checks.check_debug_mode())
            all_findings.append(self.service_checks.check_environment_secrets())

            # Resource health
            logger.info(f"Infrastructure scan {scan_id}: Resource health checks")
            all_findings.append(self.resource_checks.check_memory())
            all_findings.append(self.resource_checks.check_uptime())

            # Cryptographic configuration
            logger.info(f"Infrastructure scan {scan_id}: Crypto checks")
            all_findings.extend(self.crypto_checks.check_ssh_config())

            result.findings = all_findings
            result.status = InfraScanStatus.COMPLETED
            result.completed_at = time.time()
            result.scan_duration_seconds = result.completed_at - result.started_at

            logger.info(
                f"Infrastructure scan {scan_id} completed: "
                f"{result.passed_checks}/{result.total_checks} passed, "
                f"compliance: {result.compliance_score:.1f}%, "
                f"hardening: {result.hardening_index:.3f} "
                f"({result.scan_duration_seconds:.1f}s)"
            )

        except Exception as e:
            result.status = InfraScanStatus.FAILED
            result.errors.append(f"Scan failed: {e}")
            result.completed_at = time.time()
            result.scan_duration_seconds = result.completed_at - result.started_at
            logger.error(f"Infrastructure scan {scan_id} failed: {e}")

        self._scan_history.append(result)
        return result

    def get_scan_history(self) -> list[dict]:
        """Return summary of all past scans."""
        return [
            {
                "scan_id": s.scan_id,
                "status": s.status.value,
                "started_at": s.started_at,
                "hostname": s.hostname,
                "compliance_score": round(s.compliance_score, 1),
                "hardening_index": round(s.hardening_index, 3),
                "total_checks": s.total_checks,
                "passed_checks": s.passed_checks,
                "duration": s.scan_duration_seconds,
            }
            for s in self._scan_history
        ]

    def get_latest_scan(self) -> Optional[InfraScanResult]:
        """Return the most recent scan result."""
        return self._scan_history[-1] if self._scan_history else None


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

infra_scanner = InfrastructureScanner()
