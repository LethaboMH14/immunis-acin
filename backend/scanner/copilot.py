"""
IMMUNIS ACIN — AI Security Copilot
Conversational security assistant for vulnerability explanation,
remediation guidance, and compliance mapping.

The Copilot bridges the gap between raw scanner output and actionable
intelligence. It speaks six languages — not human languages (that's Lingua's
job) — but audience languages: SOC Analyst, IR Lead, CISO, IT Director,
Finance, and Auditor. Each audience gets the same truth at different
abstraction levels with different action items.

Design philosophy:
- Never hallucinate severity — always ground in scanner evidence
- Never suggest fixes without explaining WHY they work
- Always provide copy-pasteable remediation commands
- Compliance mapping is automatic, not optional
- Cost awareness: batch similar questions, cache explanations
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("immunis.scanner.copilot")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AudienceLevel(str, Enum):
    """Six audience levels for vulnerability communication."""
    SOC_ANALYST = "soc_analyst"
    IR_LEAD = "ir_lead"
    CISO = "ciso"
    IT_DIRECTOR = "it_director"
    FINANCE = "finance"
    AUDITOR = "auditor"


class CopilotAction(str, Enum):
    """Types of copilot interactions."""
    EXPLAIN_VULN = "explain_vulnerability"
    SUGGEST_FIX = "suggest_fix"
    GENERATE_PLAN = "generate_remediation_plan"
    COMPLIANCE_MAP = "compliance_mapping"
    RISK_ASSESS = "risk_assessment"
    COMPARE_SCANS = "compare_scans"
    PRIORITISE = "prioritise_findings"
    CHAT = "general_chat"


class RemediationPriority(str, Enum):
    """Remediation priority levels."""
    IMMEDIATE = "immediate"      # Fix within 24 hours
    URGENT = "urgent"            # Fix within 1 week
    PLANNED = "planned"          # Fix within 1 month
    BACKLOG = "backlog"          # Fix within 1 quarter
    ACCEPTED = "accepted_risk"   # Documented risk acceptance


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AudienceProfile:
    """Defines communication style for each audience."""
    level: AudienceLevel
    title: str
    technical_depth: str  # "deep", "moderate", "overview", "minimal"
    focus: str
    tone: str
    include_code: bool
    include_financial: bool
    include_compliance: bool
    max_length: int  # approximate word count

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "title": self.title,
            "technical_depth": self.technical_depth,
            "focus": self.focus,
        }


# Audience profiles — how to speak to each stakeholder
AUDIENCE_PROFILES: dict[AudienceLevel, AudienceProfile] = {
    AudienceLevel.SOC_ANALYST: AudienceProfile(
        level=AudienceLevel.SOC_ANALYST,
        title="SOC Analyst",
        technical_depth="deep",
        focus="Detection signatures, IOCs, log queries, immediate containment steps",
        tone="Direct, technical, actionable. Use exact commands and paths.",
        include_code=True,
        include_financial=False,
        include_compliance=False,
        max_length=500,
    ),
    AudienceLevel.IR_LEAD: AudienceProfile(
        level=AudienceLevel.IR_LEAD,
        title="Incident Response Lead",
        technical_depth="deep",
        focus="Attack chain analysis, containment strategy, evidence preservation, timeline",
        tone="Structured, methodical. NIST IR framework language.",
        include_code=True,
        include_financial=False,
        include_compliance=True,
        max_length=600,
    ),
    AudienceLevel.CISO: AudienceProfile(
        level=AudienceLevel.CISO,
        title="Chief Information Security Officer",
        technical_depth="moderate",
        focus="Risk posture impact, strategic implications, resource requirements, board talking points",
        tone="Executive, risk-focused. Quantify impact. Reference frameworks.",
        include_code=False,
        include_financial=True,
        include_compliance=True,
        max_length=400,
    ),
    AudienceLevel.IT_DIRECTOR: AudienceProfile(
        level=AudienceLevel.IT_DIRECTOR,
        title="IT Director",
        technical_depth="moderate",
        focus="Infrastructure impact, patching requirements, downtime estimates, team assignments",
        tone="Operational, practical. Focus on what needs to happen and when.",
        include_code=False,
        include_financial=False,
        include_compliance=False,
        max_length=400,
    ),
    AudienceLevel.FINANCE: AudienceProfile(
        level=AudienceLevel.FINANCE,
        title="Finance / CFO",
        technical_depth="minimal",
        focus="Financial exposure, insurance implications, regulatory fines, ROI of remediation",
        tone="Business language. Rand/Dollar amounts. Risk vs cost of fix.",
        include_code=False,
        include_financial=True,
        include_compliance=True,
        max_length=300,
    ),
    AudienceLevel.AUDITOR: AudienceProfile(
        level=AudienceLevel.AUDITOR,
        title="Compliance Auditor",
        technical_depth="moderate",
        focus="Control gaps, framework mapping, evidence of compliance/non-compliance, remediation timeline",
        tone="Formal, evidence-based. Reference specific controls and benchmarks.",
        include_code=False,
        include_financial=False,
        include_compliance=True,
        max_length=500,
    ),
}


@dataclass
class CopilotMessage:
    """A single message in a copilot conversation."""
    role: str  # "user", "assistant", "system"
    content: str
    timestamp: float = field(default_factory=time.time)
    audience: Optional[AudienceLevel] = None
    action: Optional[CopilotAction] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp,
            "audience": self.audience.value if self.audience else None,
            "action": self.action.value if self.action else None,
            "metadata": self.metadata,
        }


@dataclass
class RemediationStep:
    """A single step in a remediation plan."""
    step_number: int
    title: str
    description: str
    commands: list[str] = field(default_factory=list)
    estimated_hours: float = 1.0
    priority: RemediationPriority = RemediationPriority.PLANNED
    requires_downtime: bool = False
    verification: str = ""
    rollback: str = ""

    def to_dict(self) -> dict:
        return {
            "step_number": self.step_number,
            "title": self.title,
            "description": self.description,
            "commands": self.commands,
            "estimated_hours": self.estimated_hours,
            "priority": self.priority.value,
            "requires_downtime": self.requires_downtime,
            "verification": self.verification,
            "rollback": self.rollback,
        }


@dataclass
class RemediationPlan:
    """Complete remediation plan for a set of findings."""
    plan_id: str
    title: str
    created_at: float
    total_findings: int
    steps: list[RemediationStep] = field(default_factory=list)
    total_estimated_hours: float = 0.0
    estimated_cost: float = 0.0
    risk_reduction_percent: float = 0.0

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id,
            "title": self.title,
            "created_at": self.created_at,
            "total_findings": self.total_findings,
            "steps": [s.to_dict() for s in self.steps],
            "total_estimated_hours": self.total_estimated_hours,
            "estimated_cost": self.estimated_cost,
            "risk_reduction_percent": self.risk_reduction_percent,
        }


@dataclass
class ComplianceMapping:
    """Maps a finding to compliance frameworks."""
    finding_id: str
    finding_title: str
    frameworks: dict[str, list[dict[str, str]]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "finding_title": self.finding_title,
            "frameworks": self.frameworks,
        }


# ---------------------------------------------------------------------------
# Compliance framework mappings
# ---------------------------------------------------------------------------

COMPLIANCE_FRAMEWORKS: dict[str, dict[str, dict[str, str]]] = {
    "POPIA": {
        "injection": {"section": "Section 19", "requirement": "Security safeguards for personal information", "penalty": "Up to R10 million fine or imprisonment"},
        "broken_authentication": {"section": "Section 19(1)(a)", "requirement": "Prevent unauthorised access", "penalty": "Up to R10 million fine"},
        "sensitive_data_exposure": {"section": "Section 22", "requirement": "Notification of security compromises", "penalty": "Up to R10 million fine"},
        "broken_access_control": {"section": "Section 19(1)(b)", "requirement": "Prevent unlawful processing", "penalty": "Up to R10 million fine"},
        "security_misconfiguration": {"section": "Section 19(1)", "requirement": "Appropriate technical measures", "penalty": "Up to R10 million fine"},
        "hardcoded_secrets": {"section": "Section 19(1)(a)", "requirement": "Prevent unauthorised access to credentials", "penalty": "Up to R10 million fine"},
    },
    "NIST_CSF": {
        "injection": {"control": "PR.DS-5", "requirement": "Protections against data leaks", "category": "Protect"},
        "broken_authentication": {"control": "PR.AC-7", "requirement": "Authentication and identity proofing", "category": "Protect"},
        "sensitive_data_exposure": {"control": "PR.DS-1", "requirement": "Data-at-rest is protected", "category": "Protect"},
        "broken_access_control": {"control": "PR.AC-4", "requirement": "Access permissions managed", "category": "Protect"},
        "security_misconfiguration": {"control": "PR.IP-1", "requirement": "Baseline configuration", "category": "Protect"},
        "cryptographic_weakness": {"control": "PR.DS-2", "requirement": "Data-in-transit is protected", "category": "Protect"},
        "vulnerable_dependencies": {"control": "ID.SC-2", "requirement": "Supply chain risk management", "category": "Identify"},
        "hardcoded_secrets": {"control": "PR.AC-1", "requirement": "Identities and credentials managed", "category": "Protect"},
        "prompt_injection": {"control": "PR.DS-5", "requirement": "Protections against data leaks via AI", "category": "Protect"},
    },
    "MITRE_ATTACK": {
        "injection": {"technique": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
        "broken_authentication": {"technique": "T1078", "tactic": "Persistence", "name": "Valid Accounts"},
        "sensitive_data_exposure": {"technique": "T1005", "tactic": "Collection", "name": "Data from Local System"},
        "broken_access_control": {"technique": "T1548", "tactic": "Privilege Escalation", "name": "Abuse Elevation Control"},
        "security_misconfiguration": {"technique": "T1574", "tactic": "Persistence", "name": "Hijack Execution Flow"},
        "hardcoded_secrets": {"technique": "T1552.001", "tactic": "Credential Access", "name": "Credentials In Files"},
        "path_traversal": {"technique": "T1083", "tactic": "Discovery", "name": "File and Directory Discovery"},
        "prompt_injection": {"technique": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"},
    },
    "CIS_CONTROLS": {
        "injection": {"control": "16.2", "requirement": "Application software security", "ig": "IG2"},
        "broken_authentication": {"control": "6.3", "requirement": "Require MFA for externally-exposed applications", "ig": "IG1"},
        "sensitive_data_exposure": {"control": "3.11", "requirement": "Encrypt sensitive data at rest", "ig": "IG1"},
        "broken_access_control": {"control": "6.8", "requirement": "Define and maintain role-based access control", "ig": "IG2"},
        "security_misconfiguration": {"control": "4.1", "requirement": "Establish and maintain secure configuration", "ig": "IG1"},
        "vulnerable_dependencies": {"control": "16.4", "requirement": "Use up-to-date third-party components", "ig": "IG2"},
        "cryptographic_weakness": {"control": "3.10", "requirement": "Encrypt sensitive data in transit", "ig": "IG1"},
        "hardcoded_secrets": {"control": "3.11", "requirement": "Encrypt sensitive data at rest", "ig": "IG1"},
    },
    "CYBERCRIMES_ACT": {
        "injection": {"section": "Section 3", "offence": "Unlawful interception of data", "penalty": "Fine or imprisonment up to 5 years"},
        "broken_authentication": {"section": "Section 2", "offence": "Unlawful access to computer system", "penalty": "Fine or imprisonment up to 5 years"},
        "sensitive_data_exposure": {"section": "Section 5", "offence": "Unlawful acquisition of data", "penalty": "Fine or imprisonment up to 5 years"},
        "hardcoded_secrets": {"section": "Section 2(2)", "offence": "Possession of credentials for unlawful access", "penalty": "Fine or imprisonment up to 5 years"},
    },
    "GDPR": {
        "injection": {"article": "Article 32", "requirement": "Security of processing", "penalty": "Up to €20M or 4% global turnover"},
        "sensitive_data_exposure": {"article": "Article 33", "requirement": "Notification of breach to supervisory authority", "penalty": "Up to €20M or 4% global turnover"},
        "broken_access_control": {"article": "Article 25", "requirement": "Data protection by design and default", "penalty": "Up to €20M or 4% global turnover"},
        "broken_authentication": {"article": "Article 32(1)(b)", "requirement": "Ensure ongoing confidentiality of systems", "penalty": "Up to €20M or 4% global turnover"},
    },
}

# Financial impact estimates per vulnerability category (ZAR)
FINANCIAL_IMPACT_ESTIMATES: dict[str, dict[str, Any]] = {
    "injection": {"min_loss": 500_000, "max_loss": 50_000_000, "avg_loss": 5_000_000, "remediation_cost": 50_000},
    "broken_authentication": {"min_loss": 200_000, "max_loss": 20_000_000, "avg_loss": 2_000_000, "remediation_cost": 30_000},
    "sensitive_data_exposure": {"min_loss": 1_000_000, "max_loss": 100_000_000, "avg_loss": 10_000_000, "remediation_cost": 100_000},
    "broken_access_control": {"min_loss": 300_000, "max_loss": 30_000_000, "avg_loss": 3_000_000, "remediation_cost": 40_000},
    "security_misconfiguration": {"min_loss": 100_000, "max_loss": 10_000_000, "avg_loss": 1_000_000, "remediation_cost": 20_000},
    "cryptographic_weakness": {"min_loss": 500_000, "max_loss": 50_000_000, "avg_loss": 5_000_000, "remediation_cost": 60_000},
    "vulnerable_dependencies": {"min_loss": 200_000, "max_loss": 20_000_000, "avg_loss": 2_000_000, "remediation_cost": 10_000},
    "hardcoded_secrets": {"min_loss": 500_000, "max_loss": 50_000_000, "avg_loss": 5_000_000, "remediation_cost": 5_000},
    "prompt_injection": {"min_loss": 100_000, "max_loss": 10_000_000, "avg_loss": 1_000_000, "remediation_cost": 30_000},
    "path_traversal": {"min_loss": 200_000, "max_loss": 20_000_000, "avg_loss": 2_000_000, "remediation_cost": 15_000},
    "cross_site_scripting": {"min_loss": 100_000, "max_loss": 5_000_000, "avg_loss": 500_000, "remediation_cost": 15_000},
}


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

EXPLAIN_PROMPT = """You are the IMMUNIS ACIN Security Copilot explaining a vulnerability finding.

AUDIENCE: {audience_title}
TECHNICAL DEPTH: {technical_depth}
FOCUS: {focus}
TONE: {tone}
MAX LENGTH: ~{max_length} words

VULNERABILITY:
- Title: {title}
- Category: {category}
- Severity: {severity} (CVSS: {cvss})
- Confidence: {confidence}
- Location: {location}
- Description: {description}
- Impact: {impact}
- Evidence: {evidence}

{code_section}
{financial_section}
{compliance_section}

Explain this vulnerability for the {audience_title}. Be specific to THIS finding, not generic.
Include:
1. What happened (in audience-appropriate language)
2. Why it matters (specific to their role)
3. What to do next (actionable, specific)
{extra_instructions}
"""

FIX_PROMPT = """You are the IMMUNIS ACIN Security Copilot suggesting a fix.

VULNERABILITY:
- Title: {title}
- Category: {category}
- Severity: {severity}
- Location: {location}
- Code: {code_snippet}
- Current remediation suggestion: {current_remediation}

Provide a SPECIFIC fix for this exact vulnerability:
1. The exact code change needed (before/after)
2. WHY this fix works (the security principle)
3. How to verify the fix worked
4. Any side effects or considerations
5. A rollback plan if the fix causes issues

Be precise. Use the actual file path and line numbers. Provide copy-pasteable code.
"""

PLAN_PROMPT = """You are the IMMUNIS ACIN Security Copilot generating a remediation plan.

FINDINGS SUMMARY:
{findings_summary}

TOTAL FINDINGS: {total_findings}
CRITICAL: {critical_count}
HIGH: {high_count}
MEDIUM: {medium_count}
LOW: {low_count}

Generate a prioritised remediation plan:
1. Group related findings that can be fixed together
2. Order by: critical first, then by effort (quick wins before large projects)
3. For each step: title, description, commands, estimated hours, priority, downtime needed
4. Include verification steps for each fix
5. Include rollback procedures
6. Estimate total effort and cost

Format as structured JSON matching this schema:
{{
    "steps": [
        {{
            "step_number": 1,
            "title": "...",
            "description": "...",
            "commands": ["..."],
            "estimated_hours": N,
            "priority": "immediate|urgent|planned|backlog",
            "requires_downtime": true/false,
            "verification": "...",
            "rollback": "..."
        }}
    ],
    "total_hours": N,
    "estimated_cost_zar": N,
    "risk_reduction_percent": N
}}
"""

CHAT_PROMPT = """You are the IMMUNIS ACIN Security Copilot — an expert AI security assistant.

You have access to the following scan results:
{scan_context}

CONVERSATION HISTORY:
{conversation_history}

USER QUESTION: {question}

AUDIENCE: {audience_title}

Rules:
- Ground all answers in the actual scan data provided
- Never invent vulnerabilities that weren't found
- If asked about something not in the scan data, say so clearly
- Provide specific, actionable advice
- Reference specific findings by ID when relevant
- Be honest about uncertainty
- For technical audiences: include commands and code
- For executive audiences: include business impact and cost
"""


# ---------------------------------------------------------------------------
# Security Copilot engine
# ---------------------------------------------------------------------------

class SecurityCopilot:
    """
    AI-powered security assistant that translates scanner findings
    into audience-appropriate intelligence and actionable guidance.

    Core capabilities:
    1. Explain any vulnerability to any of 6 audiences
    2. Suggest specific, verified fixes with code
    3. Generate prioritised remediation plans
    4. Map findings to compliance frameworks
    5. Compare scan results over time
    6. Interactive chat grounded in scan evidence
    """

    def __init__(self):
        self._model_router = None
        self._conversations: dict[str, list[CopilotMessage]] = {}
        self._explanation_cache: dict[str, str] = {}
        self._scan_context: dict[str, Any] = {}

    async def _get_router(self):
        """Lazy-load model router to avoid circular imports."""
        if self._model_router is None:
            try:
                from backend.services.model_router import model_router
                self._model_router = model_router
            except ImportError:
                logger.warning("Model router unavailable — copilot in offline mode")
        return self._model_router

    def load_scan_results(
        self,
        static_results: Optional[dict] = None,
        dynamic_results: Optional[dict] = None,
        infra_results: Optional[dict] = None,
    ) -> None:
        """Load scan results for the copilot to reference."""
        self._scan_context = {
            "static": static_results,
            "dynamic": dynamic_results,
            "infrastructure": infra_results,
            "loaded_at": time.time(),
        }
        logger.info(
            f"Copilot loaded scan context: "
            f"static={bool(static_results)}, "
            f"dynamic={bool(dynamic_results)}, "
            f"infra={bool(infra_results)}"
        )

    async def explain_vulnerability(
        self,
        finding: dict[str, Any],
        audience: AudienceLevel = AudienceLevel.SOC_ANALYST,
    ) -> str:
        """
        Explain a vulnerability finding for a specific audience.

        Args:
            finding: Vulnerability finding dict (from any scanner)
            audience: Target audience level

        Returns:
            Audience-appropriate explanation string
        """
        # Check cache
        cache_key = f"{finding.get('vuln_id', finding.get('finding_id', finding.get('check_id', '')))}:{audience.value}"
        if cache_key in self._explanation_cache:
            return self._explanation_cache[cache_key]

        profile = AUDIENCE_PROFILES[audience]

        # Build audience-specific sections
        code_section = ""
        if profile.include_code and finding.get("location", {}).get("snippet"):
            code_section = f"\nCODE SNIPPET:\n```\n{finding['location']['snippet']}\n```"

        financial_section = ""
        if profile.include_financial:
            category = finding.get("category", "security_misconfiguration")
            fin_data = FINANCIAL_IMPACT_ESTIMATES.get(category, {})
            if fin_data:
                financial_section = (
                    f"\nFINANCIAL IMPACT (ZAR):\n"
                    f"- Minimum loss: R{fin_data.get('min_loss', 0):,.0f}\n"
                    f"- Average loss: R{fin_data.get('avg_loss', 0):,.0f}\n"
                    f"- Maximum loss: R{fin_data.get('max_loss', 0):,.0f}\n"
                    f"- Remediation cost: R{fin_data.get('remediation_cost', 0):,.0f}\n"
                    f"- ROI of fix: {fin_data.get('avg_loss', 0) / max(fin_data.get('remediation_cost', 1), 1):.0f}x"
                )

        compliance_section = ""
        if profile.include_compliance:
            category = finding.get("category", "")
            mappings = []
            for framework, controls in COMPLIANCE_FRAMEWORKS.items():
                if category in controls:
                    ctrl = controls[category]
                    mappings.append(f"- {framework}: {json.dumps(ctrl)}")
            if mappings:
                compliance_section = f"\nCOMPLIANCE MAPPINGS:\n" + "\n".join(mappings)

        extra_instructions = ""
        if audience == AudienceLevel.SOC_ANALYST:
            extra_instructions = "Include detection signatures, log queries, and immediate containment commands."
        elif audience == AudienceLevel.IR_LEAD:
            extra_instructions = "Structure as: Identification → Containment → Eradication → Recovery → Lessons Learned."
        elif audience == AudienceLevel.CISO:
            extra_instructions = "Include board-ready talking points and strategic risk implications."
        elif audience == AudienceLevel.FINANCE:
            extra_instructions = "Express everything in Rand amounts. Include insurance and regulatory fine implications."
        elif audience == AudienceLevel.AUDITOR:
            extra_instructions = "Reference specific control IDs. Note evidence of compliance or non-compliance."

        # Build location string
        location = finding.get("location", {})
        if isinstance(location, dict):
            location_str = f"{location.get('file_path', 'N/A')}:{location.get('line_start', 'N/A')}"
        else:
            location_str = str(finding.get("url", "N/A"))

        prompt = EXPLAIN_PROMPT.format(
            audience_title=profile.title,
            technical_depth=profile.technical_depth,
            focus=profile.focus,
            tone=profile.tone,
            max_length=profile.max_length,
            title=finding.get("title", "Unknown"),
            category=finding.get("category", "Unknown"),
            severity=finding.get("severity", "Unknown"),
            cvss=finding.get("cvss_score", "N/A"),
            confidence=finding.get("confidence", "N/A"),
            location=location_str,
            description=finding.get("description", ""),
            impact=finding.get("impact", ""),
            evidence=json.dumps(finding.get("evidence", {}), indent=2)[:500],
            code_section=code_section,
            financial_section=financial_section,
            compliance_section=compliance_section,
            extra_instructions=extra_instructions,
        )

        router = await self._get_router()
        if router is None:
            explanation = self._offline_explain(finding, profile)
        else:
            try:
                explanation = await router.generate(
                    prompt=prompt,
                    system_prompt="You are the IMMUNIS ACIN Security Copilot. Be precise, grounded, and actionable.",
                    temperature=0.4,
                    max_tokens=1500,
                    agent_id="copilot_explain",
                )
            except Exception as e:
                logger.warning(f"LLM explanation failed: {e}")
                explanation = self._offline_explain(finding, profile)

        # Cache the explanation
        self._explanation_cache[cache_key] = explanation
        return explanation

    async def suggest_fix(self, finding: dict[str, Any]) -> str:
        """
        Generate a specific fix suggestion for a vulnerability.

        Returns detailed remediation with before/after code,
        verification steps, and rollback procedure.
        """
        location = finding.get("location", {})
        code_snippet = ""
        if isinstance(location, dict):
            code_snippet = location.get("snippet", "")

        prompt = FIX_PROMPT.format(
            title=finding.get("title", "Unknown"),
            category=finding.get("category", "Unknown"),
            severity=finding.get("severity", "Unknown"),
            location=f"{location.get('file_path', 'N/A')}:{location.get('line_start', 'N/A')}" if isinstance(location, dict) else str(finding.get("url", "N/A")),
            code_snippet=code_snippet or "N/A",
            current_remediation=finding.get("remediation", "N/A"),
        )

        router = await self._get_router()
        if router is None:
            return self._offline_fix(finding)

        try:
            fix = await router.generate(
                prompt=prompt,
                system_prompt="You are a senior security engineer. Provide precise, tested fixes only.",
                temperature=0.3,
                max_tokens=2000,
                agent_id="copilot_fix",
            )
            return fix
        except Exception as e:
            logger.warning(f"LLM fix suggestion failed: {e}")
            return self._offline_fix(finding)

    async def generate_remediation_plan(
        self, findings: list[dict[str, Any]]
    ) -> RemediationPlan:
        """
        Generate a prioritised remediation plan from a list of findings.

        Groups related findings, orders by priority, estimates effort
        and cost, and provides verification + rollback for each step.
        """
        plan_id = hashlib.sha256(f"plan:{time.time()}:{len(findings)}".encode()).hexdigest()[:16]

        # Build findings summary for LLM
        summary_lines = []
        critical_count = high_count = medium_count = low_count = 0

        for f in findings:
            severity = f.get("severity", "info")
            if severity == "critical":
                critical_count += 1
            elif severity == "high":
                high_count += 1
            elif severity == "medium":
                medium_count += 1
            else:
                low_count += 1

            summary_lines.append(
                f"- [{severity.upper()}] {f.get('title', 'Unknown')} "
                f"(Category: {f.get('category', 'N/A')}, "
                f"CVSS: {f.get('cvss_score', 'N/A')})"
            )

        findings_summary = "\n".join(summary_lines[:30])  # Cap for token limits

        router = await self._get_router()
        if router is None:
            return self._offline_plan(plan_id, findings, critical_count, high_count, medium_count, low_count)

        prompt = PLAN_PROMPT.format(
            findings_summary=findings_summary,
            total_findings=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
        )

        try:
            response = await router.generate(
                prompt=prompt,
                system_prompt="You are a security remediation planner. Respond only in valid JSON.",
                temperature=0.3,
                max_tokens=3000,
                agent_id="copilot_plan",
            )

            plan_data = json.loads(response)

            steps = []
            for step_data in plan_data.get("steps", []):
                try:
                    priority_str = step_data.get("priority", "planned")
                    try:
                        priority = RemediationPriority(priority_str)
                    except ValueError:
                        priority = RemediationPriority.PLANNED

                    steps.append(RemediationStep(
                        step_number=int(step_data.get("step_number", len(steps) + 1)),
                        title=step_data.get("title", ""),
                        description=step_data.get("description", ""),
                        commands=step_data.get("commands", []),
                        estimated_hours=float(step_data.get("estimated_hours", 1.0)),
                        priority=priority,
                        requires_downtime=bool(step_data.get("requires_downtime", False)),
                        verification=step_data.get("verification", ""),
                        rollback=step_data.get("rollback", ""),
                    ))
                except (ValueError, TypeError, KeyError) as e:
                    logger.warning(f"Failed to parse plan step: {e}")

            plan = RemediationPlan(
                plan_id=plan_id,
                title=f"Remediation Plan — {len(findings)} Findings",
                created_at=time.time(),
                total_findings=len(findings),
                steps=steps,
                total_estimated_hours=float(plan_data.get("total_hours", sum(s.estimated_hours for s in steps))),
                estimated_cost=float(plan_data.get("estimated_cost_zar", 0)),
                risk_reduction_percent=float(plan_data.get("risk_reduction_percent", 0)),
            )

            return plan

        except Exception as e:
            logger.warning(f"LLM plan generation failed: {e}")
            return self._offline_plan(plan_id, findings, critical_count, high_count, medium_count, low_count)

    def map_compliance(self, finding: dict[str, Any]) -> ComplianceMapping:
        """
        Map a finding to all applicable compliance frameworks.

        This is deterministic — no LLM needed. Direct lookup from
        the compliance framework mappings.
        """
        category = finding.get("category", "")
        finding_id = finding.get("vuln_id", finding.get("finding_id", finding.get("check_id", "unknown")))

        mapping = ComplianceMapping(
            finding_id=finding_id,
            finding_title=finding.get("title", "Unknown"),
        )

        for framework, controls in COMPLIANCE_FRAMEWORKS.items():
            if category in controls:
                ctrl = controls[category]
                if framework not in mapping.frameworks:
                    mapping.frameworks[framework] = []
                mapping.frameworks[framework].append(ctrl)

        # Also map by CWE IDs if available
        cwe_ids = finding.get("cwe_ids", [])
        for cwe in cwe_ids:
            # Add CWE reference
            if "CWE" not in mapping.frameworks:
                mapping.frameworks["CWE"] = []
            mapping.frameworks["CWE"].append({
                "id": cwe,
                "url": f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html",
            })

        # Map OWASP IDs
        owasp_ids = finding.get("owasp_ids", [])
        for owasp in owasp_ids:
            if "OWASP" not in mapping.frameworks:
                mapping.frameworks["OWASP"] = []
            mapping.frameworks["OWASP"].append({
                "id": owasp,
                "url": f"https://owasp.org/Top10/",
            })

        return mapping

    async def chat(
        self,
        session_id: str,
        message: str,
        audience: AudienceLevel = AudienceLevel.SOC_ANALYST,
    ) -> str:
        """
        Interactive chat grounded in scan results.

        Maintains conversation history per session.
        All responses are grounded in actual scan data.
        """
        # Initialise conversation if new
        if session_id not in self._conversations:
            self._conversations[session_id] = []

        # Add user message
        self._conversations[session_id].append(CopilotMessage(
            role="user",
            content=message,
            audience=audience,
            action=CopilotAction.CHAT,
        ))

        # Build conversation history
        history_lines = []
        for msg in self._conversations[session_id][-10:]:  # Last 10 messages
            history_lines.append(f"{msg.role.upper()}: {msg.content}")
        conversation_history = "\n".join(history_lines)

        # Build scan context summary
        scan_context = self._build_scan_context_summary()

        profile = AUDIENCE_PROFILES[audience]

        prompt = CHAT_PROMPT.format(
            scan_context=scan_context,
            conversation_history=conversation_history,
            question=message,
            audience_title=profile.title,
        )

        router = await self._get_router()
        if router is None:
            response = self._offline_chat(message)
        else:
            try:
                response = await router.generate(
                    prompt=prompt,
                    system_prompt=(
                        f"You are the IMMUNIS ACIN Security Copilot speaking to a {profile.title}. "
                        f"Tone: {profile.tone}. Focus: {profile.focus}. "
                        f"Technical depth: {profile.technical_depth}."
                    ),
                    temperature=0.6,
                    max_tokens=1500,
                    agent_id="copilot_chat",
                )
            except Exception as e:
                logger.warning(f"LLM chat failed: {e}")
                response = self._offline_chat(message)

        # Add assistant response to history
        self._conversations[session_id].append(CopilotMessage(
            role="assistant",
            content=response,
            audience=audience,
            action=CopilotAction.CHAT,
        ))

        return response

    def get_conversation(self, session_id: str) -> list[dict]:
        """Return conversation history for a session."""
        if session_id not in self._conversations:
            return []
        return [msg.to_dict() for msg in self._conversations[session_id]]

    def get_unified_assessment(self) -> dict[str, Any]:
        """
        Generate a unified security assessment from all loaded scan results.

        Aggregates static, dynamic, and infrastructure findings into
        a single posture score with category breakdowns.
        """
        all_findings: list[dict[str, Any]] = []

        # Collect findings from all scanners
        if self._scan_context.get("static"):
            static = self._scan_context["static"]
            all_findings.extend(static.get("vulnerabilities", []))

        if self._scan_context.get("dynamic"):
            dynamic = self._scan_context["dynamic"]
            all_findings.extend(dynamic.get("findings", []))

        if self._scan_context.get("infrastructure"):
            infra = self._scan_context["infrastructure"]
            for f in infra.get("findings", []):
                if f.get("status") == "fail":
                    all_findings.append(f)

        # Compute severity distribution
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Compute category distribution
        category_counts: dict[str, int] = {}
        for f in all_findings:
            cat = f.get("category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Compute overall risk score (0-100, lower is better)
        severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 0.5, "info": 0.1}
        raw_risk = sum(
            severity_weights.get(f.get("severity", "info"), 0) * f.get("confidence", 0.5)
            for f in all_findings
        )
        risk_score = min(100.0, raw_risk)

        # Compute posture score (0-100, higher is better)
        posture_score = max(0.0, 100.0 - risk_score)

        # Compliance posture from infrastructure scan
        infra_compliance = 0.0
        if self._scan_context.get("infrastructure"):
            infra_compliance = self._scan_context["infrastructure"].get("compliance_score", 0.0)

        # Financial exposure estimate
        total_min_loss = 0
        total_max_loss = 0
        total_avg_loss = 0
        total_remediation_cost = 0

        for f in all_findings:
            cat = f.get("category", "")
            fin = FINANCIAL_IMPACT_ESTIMATES.get(cat, {})
            if fin:
                total_min_loss += fin.get("min_loss", 0)
                total_max_loss += fin.get("max_loss", 0)
                total_avg_loss += fin.get("avg_loss", 0)
                total_remediation_cost += fin.get("remediation_cost", 0)

        return {
            "posture_score": round(posture_score, 1),
            "risk_score": round(risk_score, 1),
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "infrastructure_compliance": round(infra_compliance, 1),
            "financial_exposure": {
                "min_loss_zar": total_min_loss,
                "avg_loss_zar": total_avg_loss,
                "max_loss_zar": total_max_loss,
                "remediation_cost_zar": total_remediation_cost,
                "roi_of_remediation": round(total_avg_loss / max(total_remediation_cost, 1), 1),
            },
            "scan_sources": {
                "static": bool(self._scan_context.get("static")),
                "dynamic": bool(self._scan_context.get("dynamic")),
                "infrastructure": bool(self._scan_context.get("infrastructure")),
            },
            "generated_at": time.time(),
        }

    # -----------------------------------------------------------------------
    # Offline fallback methods (when LLM is unavailable)
    # -----------------------------------------------------------------------

    def _offline_explain(self, finding: dict[str, Any], profile: AudienceProfile) -> str:
        """Generate explanation without LLM — template-based fallback."""
        title = finding.get("title", "Unknown Vulnerability")
        severity = finding.get("severity", "unknown").upper()
        category = finding.get("category", "unknown")
        description = finding.get("description", "No description available.")
        impact = finding.get("impact", "No impact assessment available.")
        remediation = finding.get("remediation", "No remediation guidance available.")

        if profile.level == AudienceLevel.SOC_ANALYST:
            return (
                f"## {title}\n\n"
                f"**Severity:** {severity} | **Category:** {category}\n\n"
                f"**What:** {description}\n\n"
                f"**Impact:** {impact}\n\n"
                f"**Immediate Actions:**\n"
                f"1. Verify the finding at the reported location\n"
                f"2. Check logs for exploitation attempts\n"
                f"3. Apply fix: {remediation}\n"
                f"4. Monitor for recurrence\n"
            )
        elif profile.level == AudienceLevel.IR_LEAD:
            return (
                f"## Incident Assessment: {title}\n\n"
                f"**Severity:** {severity} | **Category:** {category}\n\n"
                f"### Identification\n{description}\n\n"
                f"### Impact Assessment\n{impact}\n\n"
                f"### Containment\n"
                f"- Isolate affected component if actively exploited\n"
                f"- Preserve evidence (logs, artifacts)\n\n"
                f"### Eradication\n{remediation}\n\n"
                f"### Recovery\n"
                f"- Verify fix in staging before production\n"
                f"- Monitor for 48 hours post-fix\n\n"
                f"### Lessons Learned\n"
                f"- Add detection rule for this vulnerability class\n"
                f"- Update security baseline\n"
            )
        elif profile.level == AudienceLevel.CISO:
            fin_data = FINANCIAL_IMPACT_ESTIMATES.get(category, {})
            avg_loss = fin_data.get("avg_loss", 0)
            rem_cost = fin_data.get("remediation_cost", 0)
            return (
                f"## Executive Summary: {title}\n\n"
                f"**Risk Level:** {severity}\n\n"
                f"**Business Impact:** {impact}\n\n"
                f"**Financial Exposure:** R{avg_loss:,.0f} average potential loss\n"
                f"**Remediation Cost:** R{rem_cost:,.0f}\n"
                f"**ROI of Fix:** {avg_loss / max(rem_cost, 1):.0f}x return\n\n"
                f"**Recommendation:** {remediation}\n\n"
                f"**Board Talking Point:** A {severity.lower()}-severity {category.replace('_', ' ')} "
                f"vulnerability has been identified. Remediation is recommended within "
                f"{'24 hours' if severity == 'CRITICAL' else '1 week' if severity == 'HIGH' else '1 month'}.\n"
            )
        elif profile.level == AudienceLevel.IT_DIRECTOR:
            return (
                f"## Action Required: {title}\n\n"
                f"**Priority:** {severity}\n\n"
                f"**What needs to happen:** {remediation}\n\n"
                f"**Impact if not fixed:** {impact}\n\n"
                f"**Estimated effort:** "
                f"{'2-4 hours' if severity in ('CRITICAL', 'HIGH') else '4-8 hours'}\n"
                f"**Downtime required:** Likely minimal (code change + restart)\n\n"
                f"**Team assignment:** Security engineering or DevOps\n"
            )
        elif profile.level == AudienceLevel.FINANCE:
            fin_data = FINANCIAL_IMPACT_ESTIMATES.get(category, {})
            min_loss = fin_data.get("min_loss", 0)
            avg_loss = fin_data.get("avg_loss", 0)
            max_loss = fin_data.get("max_loss", 0)
            rem_cost = fin_data.get("remediation_cost", 0)
            return (
                f"## Financial Risk Assessment: {title}\n\n"
                f"**Risk Level:** {severity}\n\n"
                f"**Potential Financial Impact:**\n"
                f"- Best case: R{min_loss:,.0f}\n"
                f"- Expected: R{avg_loss:,.0f}\n"
                f"- Worst case: R{max_loss:,.0f}\n\n"
                f"**Cost to Fix:** R{rem_cost:,.0f}\n"
                f"**Return on Investment:** {avg_loss / max(rem_cost, 1):.0f}x\n\n"
                f"**Regulatory Exposure:** Potential POPIA fines up to R10 million. "
                f"GDPR fines up to €20 million or 4% global turnover.\n\n"
                f"**Insurance Implications:** Unfixed known vulnerabilities may void "
                f"cyber insurance coverage.\n\n"
                f"**Recommendation:** Approve remediation budget of R{rem_cost:,.0f}.\n"
            )
        elif profile.level == AudienceLevel.AUDITOR:
            mapping = self.map_compliance(finding)
            framework_lines = []
            for fw, controls in mapping.frameworks.items():
                for ctrl in controls:
                    framework_lines.append(f"  - {fw}: {json.dumps(ctrl)}")
            frameworks_str = "\n".join(framework_lines) if framework_lines else "  No specific mappings found."

            return (
                f"## Audit Finding: {title}\n\n"
                f"**Severity:** {severity} | **Category:** {category}\n\n"
                f"**Finding Description:** {description}\n\n"
                f"**Control Gap:** {impact}\n\n"
                f"**Applicable Frameworks:**\n{frameworks_str}\n\n"
                f"**Evidence:** Finding detected by automated scanner with "
                f"confidence {finding.get('confidence', 'N/A')}.\n\n"
                f"**Recommended Remediation:** {remediation}\n\n"
                f"**Remediation Timeline:** "
                f"{'Immediate (24h)' if severity == 'CRITICAL' else 'Urgent (7 days)' if severity == 'HIGH' else 'Planned (30 days)'}\n"
            )

        # Default fallback
        return (
            f"## {title}\n\n"
            f"**Severity:** {severity}\n"
            f"**Description:** {description}\n"
            f"**Impact:** {impact}\n"
            f"**Remediation:** {remediation}\n"
        )

    def _offline_fix(self, finding: dict[str, Any]) -> str:
        """Generate fix suggestion without LLM — template-based fallback."""
        title = finding.get("title", "Unknown")
        remediation = finding.get("remediation", "No specific remediation available.")
        category = finding.get("category", "")
        location = finding.get("location", {})

        file_path = location.get("file_path", "N/A") if isinstance(location, dict) else "N/A"
        line_start = location.get("line_start", "N/A") if isinstance(location, dict) else "N/A"
        snippet = location.get("snippet", "") if isinstance(location, dict) else ""

        fix_text = f"## Fix: {title}\n\n"
        fix_text += f"**Location:** {file_path}:{line_start}\n\n"

        if snippet:
            fix_text += f"**Current Code:**\n```\n{snippet}\n```\n\n"

        fix_text += f"**Remediation:** {remediation}\n\n"

        # Category-specific fix templates
        fix_templates = {
            "injection": (
                "**Fix Pattern:**\n"
                "```python\n"
                "# BEFORE (vulnerable):\n"
                "# cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
                "# AFTER (safe):\n"
                "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n"
                "```\n\n"
                "**Why this works:** Parameterised queries separate code from data. "
                "The database engine treats the parameter as a literal value, not SQL code.\n"
            ),
            "hardcoded_secrets": (
                "**Fix Pattern:**\n"
                "```python\n"
                "# BEFORE (vulnerable):\n"
                "# API_KEY = \"sk-abc123...\"\n\n"
                "# AFTER (safe):\n"
                "import os\n"
                "API_KEY = os.environ.get(\"API_KEY\")\n"
                "if not API_KEY:\n"
                "    raise RuntimeError(\"API_KEY environment variable not set\")\n"
                "```\n\n"
                "**Why this works:** Secrets in environment variables are not committed to "
                "version control and can be rotated without code changes.\n"
            ),
            "cryptographic_weakness": (
                "**Fix Pattern:**\n"
                "```python\n"
                "# BEFORE (vulnerable):\n"
                "# hashlib.md5(data).hexdigest()\n\n"
                "# AFTER (safe):\n"
                "hashlib.sha256(data).hexdigest()\n"
                "```\n\n"
                "**Why this works:** SHA-256 has no known practical collision attacks. "
                "MD5 and SHA-1 have demonstrated collision vulnerabilities.\n"
            ),
            "insecure_deserialization": (
                "**Fix Pattern:**\n"
                "```python\n"
                "# BEFORE (vulnerable):\n"
                "# data = pickle.loads(untrusted_bytes)\n\n"
                "# AFTER (safe):\n"
                "import json\n"
                "data = json.loads(untrusted_string)\n"
                "```\n\n"
                "**Why this works:** JSON parsing cannot execute arbitrary code. "
                "Pickle can instantiate any Python object, enabling RCE.\n"
            ),
        }

        if category in fix_templates:
            fix_text += fix_templates[category]

        fix_text += (
            "\n**Verification:**\n"
            "1. Apply the fix\n"
            "2. Run the scanner again to confirm the finding is resolved\n"
            "3. Run unit tests to ensure no regression\n"
            "4. Deploy to staging and verify\n\n"
            "**Rollback:**\n"
            "If the fix causes issues, revert the code change via git:\n"
            "```bash\n"
            f"git checkout HEAD -- {file_path}\n"
            "```\n"
        )

        return fix_text

    def _offline_plan(
        self,
        plan_id: str,
        findings: list[dict[str, Any]],
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
    ) -> RemediationPlan:
        """Generate remediation plan without LLM — deterministic fallback."""
        steps: list[RemediationStep] = []
        step_num = 0

        # Step 1: Critical findings (immediate)
        if critical_count > 0:
            step_num += 1
            critical_findings = [f for f in findings if f.get("severity") == "critical"]
            steps.append(RemediationStep(
                step_number=step_num,
                title=f"Fix {critical_count} Critical Vulnerabilities",
                description="Critical vulnerabilities must be fixed within 24 hours. "
                            + "; ".join(f.get("title", "Unknown") for f in critical_findings[:5]),
                commands=["# Review and fix each critical finding", "# Run scanner to verify"],
                estimated_hours=critical_count * 4.0,
                priority=RemediationPriority.IMMEDIATE,
                requires_downtime=False,
                verification="Re-run scanner. Zero critical findings expected.",
                rollback="Git revert if fix causes regression. Restore from backup if data affected.",
            ))

        # Step 2: High findings (urgent)
        if high_count > 0:
            step_num += 1
            high_findings = [f for f in findings if f.get("severity") == "high"]
            steps.append(RemediationStep(
                step_number=step_num,
                title=f"Fix {high_count} High-Severity Vulnerabilities",
                description="High-severity vulnerabilities should be fixed within 1 week. "
                            + "; ".join(f.get("title", "Unknown") for f in high_findings[:5]),
                commands=["# Review and fix each high finding", "# Run scanner to verify"],
                estimated_hours=high_count * 2.0,
                priority=RemediationPriority.URGENT,
                requires_downtime=False,
                verification="Re-run scanner. Zero high findings expected.",
                rollback="Git revert affected files.",
            ))

        # Step 3: Medium findings (planned)
        if medium_count > 0:
            step_num += 1
            steps.append(RemediationStep(
                step_number=step_num,
                title=f"Fix {medium_count} Medium-Severity Vulnerabilities",
                description="Medium-severity vulnerabilities should be fixed within 1 month.",
                commands=["# Schedule fixes in sprint planning"],
                estimated_hours=medium_count * 1.0,
                priority=RemediationPriority.PLANNED,
                requires_downtime=False,
                verification="Re-run scanner after fixes.",
                rollback="Standard git revert.",
            ))

        # Step 4: Low findings (backlog)
        if low_count > 0:
            step_num += 1
            steps.append(RemediationStep(
                step_number=step_num,
                title=f"Address {low_count} Low-Severity Findings",
                description="Low-severity findings should be addressed within 1 quarter.",
                commands=["# Add to backlog"],
                estimated_hours=low_count * 0.5,
                priority=RemediationPriority.BACKLOG,
                requires_downtime=False,
                verification="Re-run scanner quarterly.",
                rollback="N/A — low risk.",
            ))

        # Step 5: Dependency updates
        dep_findings = [f for f in findings if f.get("category") == "vulnerable_dependencies"]
        if dep_findings:
            step_num += 1
            steps.append(RemediationStep(
                step_number=step_num,
                title=f"Update {len(dep_findings)} Vulnerable Dependencies",
                description="Upgrade packages with known CVEs to patched versions.",
                commands=[
                    "pip install --upgrade " + " ".join(
                        f.get("title", "").split(":")[1].strip().split(" ")[0]
                        for f in dep_findings
                        if ":" in f.get("title", "")
                    )[:200],
                    "pip freeze > requirements.txt",
                    "pytest  # Run tests after upgrade",
                ],
                estimated_hours=2.0,
                priority=RemediationPriority.URGENT,
                requires_downtime=False,
                verification="pip audit (if available) or re-run scanner.",
                rollback="pip install -r requirements.txt.bak",
            ))

        # Step 6: Security hardening
        step_num += 1
        steps.append(RemediationStep(
            step_number=step_num,
            title="Security Hardening Review",
            description="Review and implement security headers, TLS configuration, and access controls.",
            commands=[
                "# Add security headers to web server config",
                "# Review TLS configuration",
                "# Audit access controls",
            ],
            estimated_hours=4.0,
            priority=RemediationPriority.PLANNED,
            requires_downtime=False,
            verification="Run DAST scan to verify headers and TLS.",
            rollback="Revert web server configuration.",
        ))

        total_hours = sum(s.estimated_hours for s in steps)
        # Estimate cost at R500/hour for security engineering
        estimated_cost = total_hours * 500.0

        # Estimate risk reduction
        total_risk = critical_count * 10 + high_count * 5 + medium_count * 2 + low_count * 0.5
        fixable_risk = critical_count * 10 + high_count * 5 + medium_count * 1.5
        risk_reduction = (fixable_risk / max(total_risk, 1)) * 100

        return RemediationPlan(
            plan_id=plan_id,
            title=f"Remediation Plan — {len(findings)} Findings",
            created_at=time.time(),
            total_findings=len(findings),
            steps=steps,
            total_estimated_hours=total_hours,
            estimated_cost=estimated_cost,
            risk_reduction_percent=min(risk_reduction, 95.0),
        )

    def _offline_chat(self, message: str) -> str:
        """Handle chat without LLM — basic keyword matching."""
        message_lower = message.lower()

        if any(kw in message_lower for kw in ["summary", "overview", "status", "posture"]):
            assessment = self.get_unified_assessment()
            return (
                f"## Security Posture Summary\n\n"
                f"**Posture Score:** {assessment['posture_score']}/100\n"
                f"**Risk Score:** {assessment['risk_score']}/100\n"
                f"**Total Findings:** {assessment['total_findings']}\n\n"
                f"**Severity Breakdown:**\n"
                f"- Critical: {assessment['severity_counts']['critical']}\n"
                f"- High: {assessment['severity_counts']['high']}\n"
                f"- Medium: {assessment['severity_counts']['medium']}\n"
                f"- Low: {assessment['severity_counts']['low']}\n\n"
                f"**Financial Exposure:** R{assessment['financial_exposure']['avg_loss_zar']:,.0f} average\n"
                f"**Remediation Cost:** R{assessment['financial_exposure']['remediation_cost_zar']:,.0f}\n"
                f"**ROI of Remediation:** {assessment['financial_exposure']['roi_of_remediation']}x\n"
            )

        if any(kw in message_lower for kw in ["critical", "urgent", "worst", "top"]):
            return (
                "To see critical findings, use the vulnerability panel in the dashboard. "
                "Critical findings require immediate attention (within 24 hours). "
                "Use the 'Generate Plan' feature for a prioritised remediation roadmap."
            )

        if any(kw in message_lower for kw in ["compliance", "popia", "gdpr", "nist"]):
            return (
                "IMMUNIS maps all findings to compliance frameworks automatically:\n"
                "- **POPIA** (Protection of Personal Information Act)\n"
                "- **NIST CSF** (Cybersecurity Framework)\n"
                "- **MITRE ATT&CK** (Adversary Tactics & Techniques)\n"
                "- **CIS Controls** v8\n"
                "- **Cybercrimes Act** (South Africa)\n"
                "- **GDPR** (EU General Data Protection Regulation)\n\n"
                "Use the Compliance Panel to view framework-specific posture scores."
            )

        if any(kw in message_lower for kw in ["fix", "remediate", "patch", "resolve"]):
            return (
                "To get fix suggestions:\n"
                "1. Select a finding in the vulnerability panel\n"
                "2. Click 'Suggest Fix' for code-level remediation\n"
                "3. Click 'Generate Plan' for a full remediation roadmap\n\n"
                "All fixes include before/after code, verification steps, and rollback procedures."
            )

        return (
            "I'm the IMMUNIS ACIN Security Copilot. I can help with:\n\n"
            "- **Explain** any vulnerability for your audience level\n"
            "- **Suggest fixes** with copy-pasteable code\n"
            "- **Generate remediation plans** with priorities and cost estimates\n"
            "- **Map to compliance** frameworks (POPIA, NIST, MITRE, CIS, GDPR)\n"
            "- **Assess risk** with financial impact estimates\n"
            "- **Compare scans** to track improvement over time\n\n"
            "Try asking: 'What's our security posture?' or 'Show me critical findings.'\n\n"
            "*Note: LLM is currently offline. Responses are template-based. "
            "Connect an LLM provider for full conversational capability.*"
        )

    def _build_scan_context_summary(self) -> str:
        """Build a concise summary of loaded scan results for LLM context."""
        parts: list[str] = []

        if self._scan_context.get("static"):
            static = self._scan_context["static"]
            parts.append(
                f"STATIC ANALYSIS: {static.get('vulnerability_count', 0)} vulnerabilities found "
                f"in {static.get('files_scanned', 0)} files. "
                f"Risk score: {static.get('risk_score', 0):.1f}/100. "
                f"Severities: {json.dumps(static.get('severity_counts', {}))}"
            )

        if self._scan_context.get("dynamic"):
            dynamic = self._scan_context["dynamic"]
            parts.append(
                f"DYNAMIC ANALYSIS: {dynamic.get('finding_count', 0)} findings from "
                f"{dynamic.get('endpoints_discovered', 0)} endpoints. "
                f"Risk score: {dynamic.get('risk_score', 0):.1f}/100. "
                f"Severities: {json.dumps(dynamic.get('severity_counts', {}))}"
            )

        if self._scan_context.get("infrastructure"):
            infra = self._scan_context["infrastructure"]
            parts.append(
                f"INFRASTRUCTURE: {infra.get('passed_checks', 0)}/{infra.get('total_checks', 0)} checks passed. "
                f"Compliance: {infra.get('compliance_score', 0):.1f}%. "
                f"Hardening index: {infra.get('hardening_index', 0):.3f}. "
                f"Host: {infra.get('hostname', 'unknown')}"
            )

        if not parts:
            return "No scan results loaded. Run a scan first."

        return "\n".join(parts)

    def clear_cache(self) -> None:
        """Clear explanation cache."""
        self._explanation_cache.clear()
        logger.info("Copilot explanation cache cleared")

    def clear_conversations(self) -> None:
        """Clear all conversation histories."""
        self._conversations.clear()
        logger.info("Copilot conversations cleared")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

security_copilot = SecurityCopilot()
