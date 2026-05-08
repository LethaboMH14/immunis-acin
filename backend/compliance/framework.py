"""
IMMUNIS ACIN — Compliance Framework Engine
Maps security findings to regulatory and industry frameworks,
computes compliance posture scores, and identifies control gaps.

Supported frameworks:
- POPIA (Protection of Personal Information Act, South Africa)
- NIST CSF 2.0 (Cybersecurity Framework)
- MITRE ATT&CK v14 (Adversary Tactics, Techniques, and Procedures)
- CIS Controls v8 (Center for Internet Security)
- OWASP Top 10 2021 (Web Application Security)
- OWASP LLM Top 10 2025 (AI/LLM Security)
- Cybercrimes Act 19 of 2020 (South Africa)
- GDPR (EU General Data Protection Regulation)

Mathematical foundation:
- Per-framework compliance: C_f = (Σ controls_met × weight) / (Σ total_controls × weight)
- Overall posture: P = Σ(C_f × framework_weight) / Σ(framework_weight)
- Gap severity: G = (1 - C_f) × framework_criticality × regulatory_penalty_factor
- Trend: ΔC = C_f(t) - C_f(t-1), positive = improving
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("immunis.compliance.framework")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class FrameworkID(str, Enum):
    """Supported compliance frameworks."""
    POPIA = "popia"
    NIST_CSF = "nist_csf"
    MITRE_ATTACK = "mitre_attack"
    CIS_CONTROLS = "cis_controls"
    OWASP_TOP10 = "owasp_top10"
    OWASP_LLM = "owasp_llm"
    CYBERCRIMES_ACT = "cybercrimes_act"
    GDPR = "gdpr"


class ControlStatus(str, Enum):
    """Status of a compliance control."""
    MET = "met"
    PARTIALLY_MET = "partially_met"
    NOT_MET = "not_met"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class ComplianceLevel(str, Enum):
    """Overall compliance level."""
    COMPLIANT = "compliant"           # >= 90%
    SUBSTANTIALLY = "substantially"   # >= 75%
    PARTIALLY = "partially"           # >= 50%
    NON_COMPLIANT = "non_compliant"   # < 50%

    @staticmethod
    def from_score(score: float) -> "ComplianceLevel":
        if score >= 90.0:
            return ComplianceLevel.COMPLIANT
        elif score >= 75.0:
            return ComplianceLevel.SUBSTANTIALLY
        elif score >= 50.0:
            return ComplianceLevel.PARTIALLY
        return ComplianceLevel.NON_COMPLIANT


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ControlDefinition:
    """Definition of a single compliance control."""
    control_id: str
    framework: FrameworkID
    title: str
    description: str
    category: str
    weight: float = 1.0
    is_critical: bool = False
    related_vuln_categories: list[str] = field(default_factory=list)
    related_cwe: list[str] = field(default_factory=list)
    related_owasp: list[str] = field(default_factory=list)
    remediation_guidance: str = ""
    regulatory_reference: str = ""
    penalty_description: str = ""

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "framework": self.framework.value,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "weight": self.weight,
            "is_critical": self.is_critical,
            "related_vuln_categories": self.related_vuln_categories,
            "regulatory_reference": self.regulatory_reference,
            "penalty_description": self.penalty_description,
        }


@dataclass
class ControlAssessment:
    """Assessment result for a single control."""
    control: ControlDefinition
    status: ControlStatus
    score: float  # 0.0 to 1.0
    evidence: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)  # Finding IDs that affect this control
    notes: str = ""
    assessed_at: float = field(default_factory=time.time)

    @property
    def weighted_score(self) -> float:
        return self.score * self.control.weight

    def to_dict(self) -> dict:
        return {
            "control_id": self.control.control_id,
            "title": self.control.title,
            "category": self.control.category,
            "status": self.status.value,
            "score": self.score,
            "weight": self.control.weight,
            "weighted_score": self.weighted_score,
            "is_critical": self.control.is_critical,
            "evidence": self.evidence,
            "findings": self.findings,
            "notes": self.notes,
            "regulatory_reference": self.control.regulatory_reference,
        }


@dataclass
class FrameworkAssessment:
    """Complete assessment for a single framework."""
    framework: FrameworkID
    framework_name: str
    controls: list[ControlAssessment] = field(default_factory=list)
    assessed_at: float = field(default_factory=time.time)

    @property
    def total_controls(self) -> int:
        return len([c for c in self.controls if c.status != ControlStatus.NOT_APPLICABLE])

    @property
    def met_controls(self) -> int:
        return len([c for c in self.controls if c.status == ControlStatus.MET])

    @property
    def partially_met_controls(self) -> int:
        return len([c for c in self.controls if c.status == ControlStatus.PARTIALLY_MET])

    @property
    def not_met_controls(self) -> int:
        return len([c for c in self.controls if c.status == ControlStatus.NOT_MET])

    @property
    def compliance_score(self) -> float:
        """Weighted compliance score (0-100)."""
        applicable = [c for c in self.controls if c.status not in (ControlStatus.NOT_APPLICABLE, ControlStatus.NOT_ASSESSED)]
        if not applicable:
            return 0.0
        total_weight = sum(c.control.weight for c in applicable)
        achieved_weight = sum(c.weighted_score for c in applicable)
        return (achieved_weight / total_weight) * 100.0 if total_weight > 0 else 0.0

    @property
    def compliance_level(self) -> ComplianceLevel:
        return ComplianceLevel.from_score(self.compliance_score)

    @property
    def critical_gaps(self) -> list[ControlAssessment]:
        """Controls that are critical AND not met."""
        return [
            c for c in self.controls
            if c.control.is_critical and c.status in (ControlStatus.NOT_MET, ControlStatus.PARTIALLY_MET)
        ]

    def to_dict(self) -> dict:
        return {
            "framework": self.framework.value,
            "framework_name": self.framework_name,
            "compliance_score": round(self.compliance_score, 1),
            "compliance_level": self.compliance_level.value,
            "total_controls": self.total_controls,
            "met": self.met_controls,
            "partially_met": self.partially_met_controls,
            "not_met": self.not_met_controls,
            "critical_gaps": len(self.critical_gaps),
            "controls": [c.to_dict() for c in self.controls],
            "assessed_at": self.assessed_at,
        }


@dataclass
class CompliancePosture:
    """Overall compliance posture across all frameworks."""
    assessments: dict[str, FrameworkAssessment] = field(default_factory=dict)
    assessed_at: float = field(default_factory=time.time)

    @property
    def overall_score(self) -> float:
        """Weighted average across all frameworks."""
        framework_weights = {
            FrameworkID.POPIA: 3.0,        # Legal requirement in SA
            FrameworkID.NIST_CSF: 2.0,     # Industry standard
            FrameworkID.MITRE_ATTACK: 1.5, # Threat coverage
            FrameworkID.CIS_CONTROLS: 2.0, # Operational baseline
            FrameworkID.OWASP_TOP10: 2.0,  # Application security
            FrameworkID.OWASP_LLM: 1.5,   # AI-specific
            FrameworkID.CYBERCRIMES_ACT: 2.5, # Legal requirement in SA
            FrameworkID.GDPR: 2.0,         # International requirement
        }

        total_weight = 0.0
        weighted_score = 0.0

        for fw_id, assessment in self.assessments.items():
            try:
                fw_enum = FrameworkID(fw_id)
                weight = framework_weights.get(fw_enum, 1.0)
            except ValueError:
                weight = 1.0
            total_weight += weight
            weighted_score += assessment.compliance_score * weight

        return (weighted_score / total_weight) if total_weight > 0 else 0.0

    @property
    def overall_level(self) -> ComplianceLevel:
        return ComplianceLevel.from_score(self.overall_score)

    @property
    def total_critical_gaps(self) -> int:
        return sum(len(a.critical_gaps) for a in self.assessments.values())

    def to_dict(self) -> dict:
        return {
            "overall_score": round(self.overall_score, 1),
            "overall_level": self.overall_level.value,
            "total_critical_gaps": self.total_critical_gaps,
            "frameworks": {k: v.to_dict() for k, v in self.assessments.items()},
            "assessed_at": self.assessed_at,
        }


# ---------------------------------------------------------------------------
# Framework control definitions
# ---------------------------------------------------------------------------

def _build_popia_controls() -> list[ControlDefinition]:
    """POPIA (Protection of Personal Information Act) controls."""
    return [
        ControlDefinition(
            control_id="POPIA-S19-1",
            framework=FrameworkID.POPIA,
            title="Security Safeguards",
            description="Appropriate technical and organisational measures to secure personal information.",
            category="Security Measures",
            weight=3.0,
            is_critical=True,
            related_vuln_categories=["injection", "broken_access_control", "security_misconfiguration", "cryptographic_weakness"],
            regulatory_reference="Section 19(1)",
            penalty_description="Fine up to R10 million or imprisonment up to 10 years",
        ),
        ControlDefinition(
            control_id="POPIA-S19-1a",
            framework=FrameworkID.POPIA,
            title="Prevent Unauthorised Access",
            description="Identify reasonably foreseeable risks and establish safeguards against them.",
            category="Access Control",
            weight=3.0,
            is_critical=True,
            related_vuln_categories=["broken_authentication", "broken_access_control", "hardcoded_secrets"],
            related_cwe=["CWE-287", "CWE-284", "CWE-798"],
            regulatory_reference="Section 19(1)(a)",
            penalty_description="Fine up to R10 million",
        ),
        ControlDefinition(
            control_id="POPIA-S19-1b",
            framework=FrameworkID.POPIA,
            title="Prevent Loss or Damage",
            description="Establish and maintain safeguards against loss, damage, or destruction of personal information.",
            category="Data Protection",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["sensitive_data_exposure", "insecure_deserialization"],
            regulatory_reference="Section 19(1)(b)",
            penalty_description="Fine up to R10 million",
        ),
        ControlDefinition(
            control_id="POPIA-S19-1c",
            framework=FrameworkID.POPIA,
            title="Prevent Unlawful Processing",
            description="Establish safeguards against unlawful access to or processing of personal information.",
            category="Processing Controls",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["broken_access_control", "excessive_agency", "prompt_injection"],
            regulatory_reference="Section 19(1)(c)",
            penalty_description="Fine up to R10 million",
        ),
        ControlDefinition(
            control_id="POPIA-S19-2",
            framework=FrameworkID.POPIA,
            title="Accepted Security Practices",
            description="Measures must be in accordance with generally accepted information security practices.",
            category="Standards Compliance",
            weight=2.0,
            related_vuln_categories=["security_misconfiguration", "cryptographic_weakness"],
            regulatory_reference="Section 19(2)",
        ),
        ControlDefinition(
            control_id="POPIA-S22",
            framework=FrameworkID.POPIA,
            title="Breach Notification",
            description="Notify the Information Regulator and data subjects of security compromises.",
            category="Incident Response",
            weight=3.0,
            is_critical=True,
            related_vuln_categories=["sensitive_data_exposure", "insufficient_logging"],
            regulatory_reference="Section 22",
            penalty_description="Fine up to R10 million or imprisonment",
        ),
        ControlDefinition(
            control_id="POPIA-S22-4",
            framework=FrameworkID.POPIA,
            title="Breach Notification Content",
            description="Notification must include nature of compromise, identity of unauthorised person, "
                        "steps taken, and recommendation to data subjects.",
            category="Incident Response",
            weight=2.0,
            related_vuln_categories=["insufficient_logging"],
            regulatory_reference="Section 22(4)",
        ),
    ]


def _build_nist_csf_controls() -> list[ControlDefinition]:
    """NIST Cybersecurity Framework 2.0 controls."""
    return [
        # IDENTIFY
        ControlDefinition(
            control_id="NIST-ID.AM-1",
            framework=FrameworkID.NIST_CSF,
            title="Asset Inventory",
            description="Physical devices and systems are inventoried.",
            category="Identify",
            weight=1.5,
            related_vuln_categories=["security_misconfiguration"],
            regulatory_reference="NIST CSF ID.AM-1",
        ),
        ControlDefinition(
            control_id="NIST-ID.RA-1",
            framework=FrameworkID.NIST_CSF,
            title="Risk Assessment",
            description="Asset vulnerabilities are identified and documented.",
            category="Identify",
            weight=2.0,
            related_vuln_categories=["security_misconfiguration", "vulnerable_dependencies"],
            regulatory_reference="NIST CSF ID.RA-1",
        ),
        ControlDefinition(
            control_id="NIST-ID.SC-2",
            framework=FrameworkID.NIST_CSF,
            title="Supply Chain Risk",
            description="Suppliers and third-party partners are assessed for risk.",
            category="Identify",
            weight=1.5,
            related_vuln_categories=["vulnerable_dependencies"],
            regulatory_reference="NIST CSF ID.SC-2",
        ),
        # PROTECT
        ControlDefinition(
            control_id="NIST-PR.AC-1",
            framework=FrameworkID.NIST_CSF,
            title="Identity & Credential Management",
            description="Identities and credentials are issued, managed, verified, revoked, and audited.",
            category="Protect",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["broken_authentication", "hardcoded_secrets"],
            related_cwe=["CWE-287", "CWE-798"],
            regulatory_reference="NIST CSF PR.AC-1",
        ),
        ControlDefinition(
            control_id="NIST-PR.AC-4",
            framework=FrameworkID.NIST_CSF,
            title="Access Control",
            description="Access permissions and authorisations are managed with least privilege.",
            category="Protect",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["broken_access_control", "excessive_agency"],
            related_cwe=["CWE-284", "CWE-250"],
            regulatory_reference="NIST CSF PR.AC-4",
        ),
        ControlDefinition(
            control_id="NIST-PR.DS-1",
            framework=FrameworkID.NIST_CSF,
            title="Data-at-Rest Protection",
            description="Data-at-rest is protected.",
            category="Protect",
            weight=2.0,
            is_critical=True,
            related_vuln_categories=["sensitive_data_exposure", "cryptographic_weakness"],
            regulatory_reference="NIST CSF PR.DS-1",
        ),
        ControlDefinition(
            control_id="NIST-PR.DS-2",
            framework=FrameworkID.NIST_CSF,
            title="Data-in-Transit Protection",
            description="Data-in-transit is protected.",
            category="Protect",
            weight=2.0,
            is_critical=True,
            related_vuln_categories=["cryptographic_weakness"],
            related_cwe=["CWE-319", "CWE-326"],
            regulatory_reference="NIST CSF PR.DS-2",
        ),
        ControlDefinition(
            control_id="NIST-PR.DS-5",
            framework=FrameworkID.NIST_CSF,
            title="Data Leak Protection",
            description="Protections against data leaks are implemented.",
            category="Protect",
            weight=2.0,
            related_vuln_categories=["injection", "sensitive_data_exposure", "prompt_injection"],
            regulatory_reference="NIST CSF PR.DS-5",
        ),
        ControlDefinition(
            control_id="NIST-PR.IP-1",
            framework=FrameworkID.NIST_CSF,
            title="Baseline Configuration",
            description="A baseline configuration of systems is created and maintained.",
            category="Protect",
            weight=1.5,
            related_vuln_categories=["security_misconfiguration"],
            regulatory_reference="NIST CSF PR.IP-1",
        ),
        # DETECT
        ControlDefinition(
            control_id="NIST-DE.CM-1",
            framework=FrameworkID.NIST_CSF,
            title="Network Monitoring",
            description="The network is monitored to detect potential cybersecurity events.",
            category="Detect",
            weight=2.0,
            related_vuln_categories=["insufficient_logging"],
            regulatory_reference="NIST CSF DE.CM-1",
        ),
        ControlDefinition(
            control_id="NIST-DE.CM-4",
            framework=FrameworkID.NIST_CSF,
            title="Malicious Code Detection",
            description="Malicious code is detected.",
            category="Detect",
            weight=2.0,
            related_vuln_categories=["injection", "insecure_deserialization"],
            regulatory_reference="NIST CSF DE.CM-4",
        ),
        # RESPOND
        ControlDefinition(
            control_id="NIST-RS.RP-1",
            framework=FrameworkID.NIST_CSF,
            title="Incident Response Plan",
            description="Response plan is executed during or after an incident.",
            category="Respond",
            weight=2.0,
            is_critical=True,
            related_vuln_categories=["insufficient_logging"],
            regulatory_reference="NIST CSF RS.RP-1",
        ),
    ]


def _build_cis_controls() -> list[ControlDefinition]:
    """CIS Controls v8."""
    return [
        ControlDefinition(
            control_id="CIS-1.1",
            framework=FrameworkID.CIS_CONTROLS,
            title="Enterprise Asset Inventory",
            description="Establish and maintain an accurate enterprise asset inventory.",
            category="Inventory and Control of Enterprise Assets",
            weight=1.5,
            regulatory_reference="CIS Control 1.1 (IG1)",
        ),
        ControlDefinition(
            control_id="CIS-2.1",
            framework=FrameworkID.CIS_CONTROLS,
            title="Software Inventory",
            description="Establish and maintain a software inventory.",
            category="Inventory and Control of Software Assets",
            weight=1.5,
            related_vuln_categories=["vulnerable_dependencies"],
            regulatory_reference="CIS Control 2.1 (IG1)",
        ),
        ControlDefinition(
            control_id="CIS-3.10",
            framework=FrameworkID.CIS_CONTROLS,
            title="Encrypt Data in Transit",
            description="Encrypt sensitive data in transit.",
            category="Data Protection",
            weight=2.0,
            is_critical=True,
            related_vuln_categories=["cryptographic_weakness"],
            related_cwe=["CWE-319"],
            regulatory_reference="CIS Control 3.10 (IG1)",
        ),
        ControlDefinition(
            control_id="CIS-3.11",
            framework=FrameworkID.CIS_CONTROLS,
            title="Encrypt Data at Rest",
            description="Encrypt sensitive data at rest.",
            category="Data Protection",
            weight=2.0,
            is_critical=True,
            related_vuln_categories=["sensitive_data_exposure", "hardcoded_secrets"],
            regulatory_reference="CIS Control 3.11 (IG1)",
        ),
        ControlDefinition(
            control_id="CIS-4.1",
            framework=FrameworkID.CIS_CONTROLS,
            title="Secure Configuration",
            description="Establish and maintain a secure configuration process.",
            category="Secure Configuration",
            weight=2.0,
            related_vuln_categories=["security_misconfiguration"],
            regulatory_reference="CIS Control 4.1 (IG1)",
        ),
        ControlDefinition(
            control_id="CIS-5.2",
            framework=FrameworkID.CIS_CONTROLS,
            title="Use Unique Passwords",
            description="Use unique passwords for all enterprise assets.",
            category="Account Management",
            weight=2.0,
            is_critical=True,
            related_vuln_categories=["broken_authentication", "hardcoded_secrets"],
            regulatory_reference="CIS Control 5.2 (IG1)",
        ),
        ControlDefinition(
            control_id="CIS-6.3",
            framework=FrameworkID.CIS_CONTROLS,
            title="Require MFA",
            description="Require MFA for externally-exposed enterprise or third-party applications.",
            category="Access Control Management",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["broken_authentication"],
            regulatory_reference="CIS Control 6.3 (IG1)",
        ),
        ControlDefinition(
            control_id="CIS-6.8",
            framework=FrameworkID.CIS_CONTROLS,
            title="Role-Based Access Control",
            description="Define and maintain role-based access control.",
            category="Access Control Management",
            weight=2.0,
            related_vuln_categories=["broken_access_control"],
            regulatory_reference="CIS Control 6.8 (IG2)",
        ),
        ControlDefinition(
            control_id="CIS-7.4",
            framework=FrameworkID.CIS_CONTROLS,
            title="Patch Management",
            description="Perform automated patch management for operating systems.",
            category="Continuous Vulnerability Management",
            weight=2.0,
            is_critical=True,
            related_vuln_categories=["vulnerable_dependencies"],
            regulatory_reference="CIS Control 7.4 (IG1)",
        ),
        ControlDefinition(
            control_id="CIS-8.2",
            framework=FrameworkID.CIS_CONTROLS,
            title="Audit Log Collection",
            description="Collect audit logs.",
            category="Audit Log Management",
            weight=2.0,
            related_vuln_categories=["insufficient_logging"],
            regulatory_reference="CIS Control 8.2 (IG1)",
        ),
        ControlDefinition(
            control_id="CIS-16.2",
            framework=FrameworkID.CIS_CONTROLS,
            title="Application Security",
            description="Establish and maintain a process to accept and address software vulnerabilities.",
            category="Application Software Security",
            weight=2.0,
            related_vuln_categories=["injection", "cross_site_scripting", "insecure_deserialization"],
            regulatory_reference="CIS Control 16.2 (IG2)",
        ),
    ]


def _build_owasp_top10_controls() -> list[ControlDefinition]:
    """OWASP Top 10 2021."""
    return [
        ControlDefinition(
            control_id="OWASP-A01",
            framework=FrameworkID.OWASP_TOP10,
            title="A01: Broken Access Control",
            description="Restrictions on authenticated users are not properly enforced.",
            category="Access Control",
            weight=3.0,
            is_critical=True,
            related_vuln_categories=["broken_access_control", "path_traversal"],
            related_cwe=["CWE-284", "CWE-22"],
            related_owasp=["A01:2021"],
        ),
        ControlDefinition(
            control_id="OWASP-A02",
            framework=FrameworkID.OWASP_TOP10,
            title="A02: Cryptographic Failures",
            description="Failures related to cryptography which lead to sensitive data exposure.",
            category="Cryptography",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["cryptographic_weakness", "sensitive_data_exposure"],
            related_cwe=["CWE-327", "CWE-328", "CWE-319"],
            related_owasp=["A02:2021"],
        ),
        ControlDefinition(
            control_id="OWASP-A03",
            framework=FrameworkID.OWASP_TOP10,
            title="A03: Injection",
            description="User-supplied data is not validated, filtered, or sanitised.",
            category="Input Validation",
            weight=3.0,
            is_critical=True,
            related_vuln_categories=["injection", "cross_site_scripting"],
            related_cwe=["CWE-89", "CWE-78", "CWE-79"],
            related_owasp=["A03:2021"],
        ),
        ControlDefinition(
            control_id="OWASP-A04",
            framework=FrameworkID.OWASP_TOP10,
            title="A04: Insecure Design",
            description="Missing or ineffective control design.",
            category="Design",
            weight=2.0,
            related_vuln_categories=["security_misconfiguration"],
            related_owasp=["A04:2021"],
        ),
        ControlDefinition(
            control_id="OWASP-A05",
            framework=FrameworkID.OWASP_TOP10,
            title="A05: Security Misconfiguration",
            description="Missing security hardening or improperly configured permissions.",
            category="Configuration",
            weight=2.0,
            related_vuln_categories=["security_misconfiguration", "cors_misconfiguration"],
            related_owasp=["A05:2021"],
        ),
        ControlDefinition(
            control_id="OWASP-A06",
            framework=FrameworkID.OWASP_TOP10,
            title="A06: Vulnerable and Outdated Components",
            description="Using components with known vulnerabilities.",
            category="Dependencies",
            weight=2.0,
            is_critical=True,
            related_vuln_categories=["vulnerable_dependencies"],
            related_cwe=["CWE-1035"],
            related_owasp=["A06:2021"],
        ),
        ControlDefinition(
            control_id="OWASP-A07",
            framework=FrameworkID.OWASP_TOP10,
            title="A07: Identification and Authentication Failures",
            description="Confirmation of user identity, authentication, and session management.",
            category="Authentication",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["broken_authentication"],
            related_cwe=["CWE-287", "CWE-306"],
            related_owasp=["A07:2021"],
        ),
        ControlDefinition(
            control_id="OWASP-A08",
            framework=FrameworkID.OWASP_TOP10,
            title="A08: Software and Data Integrity Failures",
            description="Code and infrastructure that does not protect against integrity violations.",
            category="Integrity",
            weight=2.0,
            related_vuln_categories=["insecure_deserialization"],
            related_cwe=["CWE-502"],
            related_owasp=["A08:2021"],
        ),
        ControlDefinition(
            control_id="OWASP-A09",
            framework=FrameworkID.OWASP_TOP10,
            title="A09: Security Logging and Monitoring Failures",
            description="Insufficient logging, detection, monitoring, and active response.",
            category="Monitoring",
            weight=2.0,
            related_vuln_categories=["insufficient_logging"],
            related_cwe=["CWE-778"],
            related_owasp=["A09:2021"],
        ),
        ControlDefinition(
            control_id="OWASP-A10",
            framework=FrameworkID.OWASP_TOP10,
            title="A10: Server-Side Request Forgery",
            description="SSRF flaws occur when a web application fetches a remote resource without validating URL.",
            category="Input Validation",
            weight=2.0,
            related_vuln_categories=["server_side_request_forgery"],
            related_cwe=["CWE-918"],
            related_owasp=["A10:2021"],
        ),
    ]


def _build_owasp_llm_controls() -> list[ControlDefinition]:
    """OWASP LLM Top 10 2025."""
    return [
        ControlDefinition(
            control_id="LLM-01",
            framework=FrameworkID.OWASP_LLM,
            title="LLM01: Prompt Injection",
            description="Crafted inputs manipulate LLM behaviour, bypassing safeguards.",
            category="Input Security",
            weight=3.0,
            is_critical=True,
            related_vuln_categories=["prompt_injection"],
            related_cwe=["CWE-74"],
        ),
        ControlDefinition(
            control_id="LLM-02",
            framework=FrameworkID.OWASP_LLM,
            title="LLM02: Sensitive Information Disclosure",
            description="LLM reveals confidential data in responses.",
            category="Data Protection",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["sensitive_info_llm", "sensitive_data_exposure"],
        ),
        ControlDefinition(
            control_id="LLM-03",
            framework=FrameworkID.OWASP_LLM,
            title="LLM03: Supply Chain Vulnerabilities",
            description="Compromised components, training data, or plugins affect LLM integrity.",
            category="Supply Chain",
            weight=2.0,
            related_vuln_categories=["vulnerable_dependencies"],
        ),
        ControlDefinition(
            control_id="LLM-04",
            framework=FrameworkID.OWASP_LLM,
            title="LLM04: Data and Model Poisoning",
            description="Training data manipulation leads to compromised model outputs.",
            category="Model Integrity",
            weight=2.0,
            related_vuln_categories=["insecure_deserialization"],
        ),
        ControlDefinition(
            control_id="LLM-05",
            framework=FrameworkID.OWASP_LLM,
            title="LLM05: Improper Output Handling",
            description="LLM output used without validation in downstream systems.",
            category="Output Security",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["injection", "cross_site_scripting"],
        ),
        ControlDefinition(
            control_id="LLM-06",
            framework=FrameworkID.OWASP_LLM,
            title="LLM06: Excessive Agency",
            description="LLM granted excessive functionality, permissions, or autonomy.",
            category="Access Control",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["excessive_agency"],
            related_cwe=["CWE-250"],
        ),
        ControlDefinition(
            control_id="LLM-07",
            framework=FrameworkID.OWASP_LLM,
            title="LLM07: System Prompt Leakage",
            description="System prompts containing sensitive information are extractable.",
            category="Confidentiality",
            weight=2.0,
            related_vuln_categories=["prompt_injection", "sensitive_info_llm"],
        ),
        ControlDefinition(
            control_id="LLM-08",
            framework=FrameworkID.OWASP_LLM,
            title="LLM08: Vector and Embedding Weaknesses",
            description="Vulnerabilities in RAG vector stores and embeddings.",
            category="Data Integrity",
            weight=1.5,
            related_vuln_categories=["injection"],
        ),
        ControlDefinition(
            control_id="LLM-09",
            framework=FrameworkID.OWASP_LLM,
            title="LLM09: Misinformation",
            description="LLM generates false or misleading information.",
            category="Output Quality",
            weight=1.5,
            related_vuln_categories=[],
        ),
        ControlDefinition(
            control_id="LLM-10",
            framework=FrameworkID.OWASP_LLM,
            title="LLM10: Unbounded Consumption",
            description="LLM operations consume excessive resources without limits.",
            category="Resource Management",
            weight=2.0,
            related_vuln_categories=["rate_limiting"],
        ),
    ]


def _build_cybercrimes_controls() -> list[ControlDefinition]:
    """South African Cybercrimes Act 19 of 2020."""
    return [
        ControlDefinition(
            control_id="CCA-S2",
            framework=FrameworkID.CYBERCRIMES_ACT,
            title="Unlawful Access Prevention",
            description="Prevent unlawful access to computer systems.",
            category="Access Control",
            weight=3.0,
            is_critical=True,
            related_vuln_categories=["broken_authentication", "broken_access_control", "hardcoded_secrets"],
            regulatory_reference="Section 2",
            penalty_description="Fine or imprisonment up to 5 years",
        ),
        ControlDefinition(
            control_id="CCA-S3",
            framework=FrameworkID.CYBERCRIMES_ACT,
            title="Unlawful Interception Prevention",
            description="Prevent unlawful interception of data.",
            category="Data Protection",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["cryptographic_weakness", "sensitive_data_exposure"],
            regulatory_reference="Section 3",
            penalty_description="Fine or imprisonment up to 5 years",
        ),
        ControlDefinition(
            control_id="CCA-S5",
            framework=FrameworkID.CYBERCRIMES_ACT,
            title="Unlawful Data Acquisition Prevention",
            description="Prevent unlawful acquisition of data.",
            category="Data Protection",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["injection", "path_traversal", "server_side_request_forgery"],
            regulatory_reference="Section 5",
            penalty_description="Fine or imprisonment up to 5 years",
        ),
        ControlDefinition(
            control_id="CCA-S54",
            framework=FrameworkID.CYBERCRIMES_ACT,
            title="Reporting Obligation",
            description="Electronic communications service providers must report offences to SAPS within 72 hours.",
            category="Incident Response",
            weight=3.0,
            is_critical=True,
            related_vuln_categories=["insufficient_logging"],
            regulatory_reference="Section 54",
            penalty_description="Fine up to R50,000 per day of non-compliance",
        ),
        ControlDefinition(
            control_id="CCA-S16",
            framework=FrameworkID.CYBERCRIMES_ACT,
            title="Cyber Fraud Prevention",
            description="Prevent use of computer systems for fraud.",
            category="Fraud Prevention",
            weight=2.0,
            related_vuln_categories=["injection", "broken_authentication"],
            regulatory_reference="Section 16",
            penalty_description="Fine or imprisonment up to 15 years",
        ),
    ]


def _build_gdpr_controls() -> list[ControlDefinition]:
    """EU General Data Protection Regulation."""
    return [
        ControlDefinition(
            control_id="GDPR-A25",
            framework=FrameworkID.GDPR,
            title="Data Protection by Design",
            description="Implement appropriate technical and organisational measures for data protection by design and default.",
            category="Design",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["broken_access_control", "sensitive_data_exposure"],
            regulatory_reference="Article 25",
            penalty_description="Up to €20 million or 4% of global annual turnover",
        ),
        ControlDefinition(
            control_id="GDPR-A32",
            framework=FrameworkID.GDPR,
            title="Security of Processing",
            description="Implement appropriate technical and organisational measures to ensure security.",
            category="Security",
            weight=3.0,
            is_critical=True,
            related_vuln_categories=["injection", "cryptographic_weakness", "security_misconfiguration", "broken_authentication"],
            regulatory_reference="Article 32",
            penalty_description="Up to €20 million or 4% of global annual turnover",
        ),
        ControlDefinition(
            control_id="GDPR-A32-1a",
            framework=FrameworkID.GDPR,
            title="Pseudonymisation and Encryption",
            description="Pseudonymisation and encryption of personal data.",
            category="Data Protection",
            weight=2.0,
            related_vuln_categories=["cryptographic_weakness", "sensitive_data_exposure"],
            regulatory_reference="Article 32(1)(a)",
        ),
        ControlDefinition(
            control_id="GDPR-A32-1b",
            framework=FrameworkID.GDPR,
            title="Confidentiality and Integrity",
            description="Ensure ongoing confidentiality, integrity, availability and resilience of systems.",
            category="Security",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["broken_authentication", "broken_access_control", "injection"],
            regulatory_reference="Article 32(1)(b)",
        ),
        ControlDefinition(
            control_id="GDPR-A33",
            framework=FrameworkID.GDPR,
            title="Breach Notification to Authority",
            description="Notify supervisory authority within 72 hours of becoming aware of a personal data breach.",
            category="Incident Response",
            weight=3.0,
            is_critical=True,
            related_vuln_categories=["insufficient_logging", "sensitive_data_exposure"],
            regulatory_reference="Article 33",
            penalty_description="Up to €20 million or 4% of global annual turnover",
        ),
        ControlDefinition(
            control_id="GDPR-A34",
            framework=FrameworkID.GDPR,
            title="Breach Notification to Data Subjects",
            description="Communicate personal data breach to data subjects when high risk.",
            category="Incident Response",
            weight=2.5,
            related_vuln_categories=["sensitive_data_exposure"],
            regulatory_reference="Article 34",
        ),
        ControlDefinition(
            control_id="GDPR-A35",
            framework=FrameworkID.GDPR,
            title="Data Protection Impact Assessment",
            description="Carry out DPIA where processing is likely to result in high risk.",
            category="Risk Assessment",
            weight=2.0,
            related_vuln_categories=[],
            regulatory_reference="Article 35",
        ),
    ]


def _build_mitre_attack_controls() -> list[ControlDefinition]:
    """MITRE ATT&CK coverage controls."""
    return [
        ControlDefinition(
            control_id="MITRE-TA0001",
            framework=FrameworkID.MITRE_ATTACK,
            title="Initial Access Detection",
            description="Detect techniques used to gain initial foothold.",
            category="Initial Access",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["injection", "broken_authentication"],
            regulatory_reference="TA0001",
        ),
        ControlDefinition(
            control_id="MITRE-TA0002",
            framework=FrameworkID.MITRE_ATTACK,
            title="Execution Detection",
            description="Detect techniques for running malicious code.",
            category="Execution",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["injection", "insecure_deserialization"],
            regulatory_reference="TA0002",
        ),
        ControlDefinition(
            control_id="MITRE-TA0003",
            framework=FrameworkID.MITRE_ATTACK,
            title="Persistence Detection",
            description="Detect techniques for maintaining access.",
            category="Persistence",
            weight=2.0,
            related_vuln_categories=["broken_access_control"],
            regulatory_reference="TA0003",
        ),
        ControlDefinition(
            control_id="MITRE-TA0004",
            framework=FrameworkID.MITRE_ATTACK,
            title="Privilege Escalation Detection",
            description="Detect techniques for gaining higher-level permissions.",
            category="Privilege Escalation",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["broken_access_control", "security_misconfiguration"],
            regulatory_reference="TA0004",
        ),
        ControlDefinition(
            control_id="MITRE-TA0005",
            framework=FrameworkID.MITRE_ATTACK,
            title="Defense Evasion Detection",
            description="Detect techniques for avoiding detection.",
            category="Defense Evasion",
            weight=2.0,
            related_vuln_categories=["insufficient_logging"],
            regulatory_reference="TA0005",
        ),
        ControlDefinition(
            control_id="MITRE-TA0006",
            framework=FrameworkID.MITRE_ATTACK,
            title="Credential Access Detection",
            description="Detect techniques for stealing credentials.",
            category="Credential Access",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["broken_authentication", "hardcoded_secrets"],
            regulatory_reference="TA0006",
        ),
        ControlDefinition(
            control_id="MITRE-TA0009",
            framework=FrameworkID.MITRE_ATTACK,
            title="Collection Detection",
            description="Detect techniques for gathering data of interest.",
            category="Collection",
            weight=2.0,
            related_vuln_categories=["sensitive_data_exposure", "path_traversal"],
            regulatory_reference="TA0009",
        ),
        ControlDefinition(
            control_id="MITRE-TA0010",
            framework=FrameworkID.MITRE_ATTACK,
            title="Exfiltration Detection",
            description="Detect techniques for stealing data.",
            category="Exfiltration",
            weight=2.5,
            is_critical=True,
            related_vuln_categories=["sensitive_data_exposure", "server_side_request_forgery"],
            regulatory_reference="TA0010",
        ),
    ]


# ---------------------------------------------------------------------------
# Master control registry
# ---------------------------------------------------------------------------

def build_all_controls() -> dict[FrameworkID, list[ControlDefinition]]:
    """Build the complete control registry for all frameworks."""
    return {
        FrameworkID.POPIA: _build_popia_controls(),
        FrameworkID.NIST_CSF: _build_nist_csf_controls(),
        FrameworkID.CIS_CONTROLS: _build_cis_controls(),
        FrameworkID.OWASP_TOP10: _build_owasp_top10_controls(),
        FrameworkID.OWASP_LLM: _build_owasp_llm_controls(),
        FrameworkID.CYBERCRIMES_ACT: _build_cybercrimes_controls(),
        FrameworkID.GDPR: _build_gdpr_controls(),
        FrameworkID.MITRE_ATTACK: _build_mitre_attack_controls(),
    }


FRAMEWORK_NAMES: dict[FrameworkID, str] = {
    FrameworkID.POPIA: "Protection of Personal Information Act (POPIA)",
    FrameworkID.NIST_CSF: "NIST Cybersecurity Framework 2.0",
    FrameworkID.CIS_CONTROLS: "CIS Controls v8",
    FrameworkID.OWASP_TOP10: "OWASP Top 10 (2021)",
    FrameworkID.OWASP_LLM: "OWASP LLM Top 10 (2025)",
    FrameworkID.CYBERCRIMES_ACT: "Cybercrimes Act 19 of 2020 (South Africa)",
    FrameworkID.GDPR: "EU General Data Protection Regulation (GDPR)",
    FrameworkID.MITRE_ATTACK: "MITRE ATT&CK v14",
}


# ---------------------------------------------------------------------------
# Compliance assessment engine
# ---------------------------------------------------------------------------

class ComplianceFrameworkEngine:
    """
    Maps security findings to compliance frameworks and computes
    posture scores.

    Assessment logic:
    1. Load all control definitions for all frameworks
    2. For each control, check if any findings violate it
    3. Score each control: 1.0 (met), 0.5 (partially met), 0.0 (not met)
    4. Compute weighted framework scores
    5. Compute overall posture score
    6. Identify critical gaps
    7. Track compliance over time

    A control is considered:
    - MET: No findings match its related vulnerability categories
    - PARTIALLY_MET: Only low/medium findings match
    - NOT_MET: High/critical findings match
    """

    def __init__(self):
        self._controls = build_all_controls()
        self._posture_history: list[CompliancePosture] = []

    def assess(
        self,
        findings: list[dict[str, Any]],
        frameworks: Optional[list[FrameworkID]] = None,
    ) -> CompliancePosture:
        """
        Assess compliance posture against findings.

        Args:
            findings: List of vulnerability/finding dicts from any scanner
            frameworks: Specific frameworks to assess (None = all)

        Returns:
            CompliancePosture with per-framework and overall scores
        """
        if frameworks is None:
            frameworks = list(FrameworkID)

        # Index findings by category for fast lookup
        findings_by_category: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            cat = f.get("category", "unknown")
            if cat not in findings_by_category:
                findings_by_category[cat] = []
            findings_by_category[cat].append(f)

        # Also index by CWE
        findings_by_cwe: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            for cwe in f.get("cwe_ids", []):
                if cwe not in findings_by_cwe:
                    findings_by_cwe[cwe] = []
                findings_by_cwe[cwe].append(f)

        posture = CompliancePosture(assessed_at=time.time())

        for fw_id in frameworks:
            controls = self._controls.get(fw_id, [])
            if not controls:
                continue

            assessments: list[ControlAssessment] = []

            for control in controls:
                assessment = self._assess_control(control, findings_by_category, findings_by_cwe)
                assessments.append(assessment)

            fw_assessment = FrameworkAssessment(
                framework=fw_id,
                framework_name=FRAMEWORK_NAMES.get(fw_id, fw_id.value),
                controls=assessments,
                assessed_at=time.time(),
            )

            posture.assessments[fw_id.value] = fw_assessment

        self._posture_history.append(posture)

        logger.info(
            f"Compliance assessment completed: overall {posture.overall_score:.1f}% "
            f"({posture.overall_level.value}), "
            f"{posture.total_critical_gaps} critical gaps"
        )

        return posture

    def _assess_control(
        self,
        control: ControlDefinition,
        findings_by_category: dict[str, list[dict[str, Any]]],
        findings_by_cwe: dict[str, list[dict[str, Any]]],
    ) -> ControlAssessment:
        """Assess a single control against findings."""
        related_findings: list[dict[str, Any]] = []
        finding_ids: list[str] = []

        # Find related findings by category
        for cat in control.related_vuln_categories:
            for f in findings_by_category.get(cat, []):
                fid = f.get("vuln_id", f.get("finding_id", f.get("check_id", "")))
                if fid not in finding_ids:
                    related_findings.append(f)
                    finding_ids.append(fid)

        # Find related findings by CWE
        for cwe in control.related_cwe:
            for f in findings_by_cwe.get(cwe, []):
                fid = f.get("vuln_id", f.get("finding_id", f.get("check_id", "")))
                if fid not in finding_ids:
                    related_findings.append(f)
                    finding_ids.append(fid)

        if not related_findings:
            # No findings = control is met
            return ControlAssessment(
                control=control,
                status=ControlStatus.MET,
                score=1.0,
                evidence=["No related vulnerabilities detected by scanner."],
                findings=[],
                notes="Control satisfied — no violations found.",
            )

        # Determine severity of related findings
        severities = [f.get("severity", "info") for f in related_findings]
        has_critical = "critical" in severities
        has_high = "high" in severities
        has_medium = "medium" in severities

        if has_critical or has_high:
            status = ControlStatus.NOT_MET
            score = 0.0
            if has_critical:
                notes = f"CRITICAL: {len([s for s in severities if s == 'critical'])} critical findings violate this control."
            else:
                notes = f"HIGH: {len([s for s in severities if s == 'high'])} high-severity findings violate this control."
        elif has_medium:
            status = ControlStatus.PARTIALLY_MET
            score = 0.5
            notes = f"PARTIAL: {len([s for s in severities if s == 'medium'])} medium-severity findings partially violate this control."
        else:
            # Only low/info findings
            status = ControlStatus.PARTIALLY_MET
            score = 0.75
            notes = f"MINOR: Only low-severity findings ({len(related_findings)}) related to this control."

        evidence = [
            f"{f.get('title', 'Unknown')} [{f.get('severity', 'unknown').upper()}]"
            for f in related_findings[:10]
        ]

        return ControlAssessment(
            control=control,
            status=status,
            score=score,
            evidence=evidence,
            findings=finding_ids,
            notes=notes,
        )

    def get_control_gaps(
        self,
        posture: CompliancePosture,
        framework: Optional[FrameworkID] = None,
        critical_only: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Get list of control gaps from a posture assessment.

        Args:
            posture: CompliancePosture to analyse
            framework: Filter to specific framework (None = all)
            critical_only: Only return critical control gaps

        Returns:
            List of gap dicts sorted by severity
        """
        gaps: list[dict[str, Any]] = []

        for fw_id, assessment in posture.assessments.items():
            if framework and fw_id != framework.value:
                continue

            for ctrl in assessment.controls:
                if ctrl.status in (ControlStatus.NOT_MET, ControlStatus.PARTIALLY_MET):
                    if critical_only and not ctrl.control.is_critical:
                        continue

                    gaps.append({
                        "framework": fw_id,
                        "framework_name": assessment.framework_name,
                        "control_id": ctrl.control.control_id,
                        "title": ctrl.control.title,
                        "status": ctrl.status.value,
                        "score": ctrl.score,
                        "is_critical": ctrl.control.is_critical,
                        "weight": ctrl.control.weight,
                        "gap_severity": ctrl.control.weight * (1 - ctrl.score),
                        "findings": ctrl.findings,
                        "evidence": ctrl.evidence,
                        "remediation": ctrl.control.remediation_guidance,
                        "regulatory_reference": ctrl.control.regulatory_reference,
                        "penalty": ctrl.control.penalty_description,
                        "notes": ctrl.notes,
                    })

        # Sort by gap severity (highest first)
        gaps.sort(key=lambda g: g["gap_severity"], reverse=True)
        return gaps

    def get_framework_summary(self, posture: CompliancePosture) -> dict[str, Any]:
        """Get a summary of compliance across all frameworks."""
        summary: dict[str, Any] = {
            "overall_score": round(posture.overall_score, 1),
            "overall_level": posture.overall_level.value,
            "total_critical_gaps": posture.total_critical_gaps,
            "frameworks": {},
        }

        for fw_id, assessment in posture.assessments.items():
            summary["frameworks"][fw_id] = {
                "name": assessment.framework_name,
                "score": round(assessment.compliance_score, 1),
                "level": assessment.compliance_level.value,
                "met": assessment.met_controls,
                "partially_met": assessment.partially_met_controls,
                "not_met": assessment.not_met_controls,
                "total": assessment.total_controls,
                "critical_gaps": len(assessment.critical_gaps),
            }

        return summary

    def get_trend(self) -> list[dict[str, Any]]:
        """Get compliance score trend over time."""
        return [
            {
                "timestamp": p.assessed_at,
                "overall_score": round(p.overall_score, 1),
                "overall_level": p.overall_level.value,
                "critical_gaps": p.total_critical_gaps,
                "frameworks": {
                    fw_id: round(a.compliance_score, 1)
                    for fw_id, a in p.assessments.items()
                },
            }
            for p in self._posture_history
        ]

    def get_latest_posture(self) -> Optional[CompliancePosture]:
        """Return most recent posture assessment."""
        return self._posture_history[-1] if self._posture_history else None

    def get_all_controls(self, framework: Optional[FrameworkID] = None) -> list[dict]:
        """List all control definitions."""
        controls: list[dict] = []
        for fw_id, fw_controls in self._controls.items():
            if framework and fw_id != framework:
                continue
            for ctrl in fw_controls:
                controls.append(ctrl.to_dict())
        return controls


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

compliance_engine = ComplianceFrameworkEngine()
