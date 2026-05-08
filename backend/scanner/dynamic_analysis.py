"""
IMMUNIS ACIN — Dynamic Analysis Scanner (DAST)
Runtime vulnerability detection against live services.

Unlike static analysis which examines code, dynamic analysis probes running
applications to find vulnerabilities that only manifest at runtime:
misconfigured headers, exposed endpoints, authentication bypasses, injection
flaws in live request handling, and TLS/certificate weaknesses.

Mathematical foundation:
- Exploit probability: P(exploit) = P(reachable) × P(vulnerable) × P(no_mitigation)
- Risk scoring: DAST_risk = Σ(cvss_i × exploit_probability_i × asset_value_i)
- Coverage metric: tested_endpoints / total_endpoints
"""

import asyncio
import hashlib
import json
import logging
import re
import ssl
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, quote

logger = logging.getLogger("immunis.scanner.dynamic")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class DASTProbeSeverity(str, Enum):
    """Severity of a DAST finding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DASTProbeCategory(str, Enum):
    """Categories of DAST probes."""
    HEADER_SECURITY = "header_security"
    TLS_CONFIG = "tls_configuration"
    INJECTION = "injection"
    AUTH_BYPASS = "authentication_bypass"
    INFO_DISCLOSURE = "information_disclosure"
    CORS_MISCONFIG = "cors_misconfiguration"
    RATE_LIMITING = "rate_limiting"
    ERROR_HANDLING = "error_handling"
    SESSION_MANAGEMENT = "session_management"
    API_SECURITY = "api_security"
    REDIRECT = "open_redirect"
    CSRF = "csrf"


class DASTScanStatus(str, Enum):
    """DAST scan lifecycle."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DASTFinding:
    """A single DAST finding from probing a live endpoint."""
    finding_id: str
    title: str
    category: DASTProbeCategory
    severity: DASTProbeSeverity
    cvss_score: float
    confidence: float
    url: str
    method: str
    description: str
    impact: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    request_sent: str = ""
    response_received: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    owasp_ids: list[str] = field(default_factory=list)
    exploit_probability: float = 0.0

    @property
    def risk_score(self) -> float:
        return self.cvss_score * self.confidence * max(self.exploit_probability, 0.1)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence,
            "url": self.url,
            "method": self.method,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "cwe_ids": self.cwe_ids,
            "owasp_ids": self.owasp_ids,
            "exploit_probability": self.exploit_probability,
            "risk_score": self.risk_score,
        }


@dataclass
class EndpointInfo:
    """Information about a discovered endpoint."""
    url: str
    method: str
    status_code: int = 0
    content_type: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    requires_auth: bool = False
    parameters: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "requires_auth": self.requires_auth,
            "parameters": self.parameters,
        }


@dataclass
class DASTScanResult:
    """Complete result of a DAST scan."""
    scan_id: str
    target_url: str
    status: DASTScanStatus
    started_at: float
    completed_at: float = 0.0
    endpoints_discovered: list[EndpointInfo] = field(default_factory=list)
    findings: list[DASTFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    requests_sent: int = 0

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in DASTProbeSeverity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def risk_score(self) -> float:
        if not self.findings:
            return 0.0
        weights = {
            DASTProbeSeverity.CRITICAL: 10.0,
            DASTProbeSeverity.HIGH: 5.0,
            DASTProbeSeverity.MEDIUM: 2.0,
            DASTProbeSeverity.LOW: 0.5,
            DASTProbeSeverity.INFO: 0.1,
        }
        total = sum(weights[f.severity] * f.confidence for f in self.findings)
        return min(100.0, total)

    @property
    def coverage(self) -> float:
        if not self.endpoints_discovered:
            return 0.0
        tested = len({f.url for f in self.findings})
        return tested / len(self.endpoints_discovered)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "endpoints_discovered": len(self.endpoints_discovered),
            "finding_count": len(self.findings),
            "severity_counts": self.severity_counts,
            "risk_score": self.risk_score,
            "coverage": self.coverage,
            "findings": [f.to_dict() for f in self.findings],
            "endpoints": [e.to_dict() for e in self.endpoints_discovered],
            "errors": self.errors,
            "requests_sent": self.requests_sent,
            "scan_duration_seconds": self.scan_duration_seconds,
        }


# ---------------------------------------------------------------------------
# HTTP client wrapper (safe, instrumented)
# ---------------------------------------------------------------------------

class SafeHTTPClient:
    """
    HTTP client for DAST probing with safety controls.

    Safety measures:
    - Request rate limiting (max 10 req/s default)
    - Timeout enforcement (10s per request)
    - Response size limits (1MB)
    - Only targets explicitly allowed hosts
    - User-Agent identifies scanner
    - No automatic redirect following for redirect tests
    """

    USER_AGENT = "IMMUNIS-ACIN-DAST/1.0 (Security Scanner)"
    MAX_RESPONSE_SIZE = 1_048_576  # 1MB
    DEFAULT_TIMEOUT = 10.0
    DEFAULT_RATE_LIMIT = 10  # requests per second

    def __init__(self, allowed_hosts: Optional[list[str]] = None):
        self.allowed_hosts = set(allowed_hosts or [])
        self._request_count = 0
        self._last_request_time = 0.0
        self._rate_limit = self.DEFAULT_RATE_LIMIT

    def _is_allowed(self, url: str) -> bool:
        """Verify the target URL is in the allowed hosts list."""
        if not self.allowed_hosts:
            return True
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return host in self.allowed_hosts or host == "localhost" or host == "127.0.0.1"

    async def _rate_limit_wait(self) -> None:
        """Enforce rate limiting between requests."""
        now = time.time()
        min_interval = 1.0 / self._rate_limit
        elapsed = now - self._last_request_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_time = time.time()

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        body: Optional[str] = None,
        follow_redirects: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> dict[str, Any]:
        """
        Send an HTTP request and return structured response.

        Returns dict with: status_code, headers, body, elapsed, error
        """
        if not self._is_allowed(url):
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "elapsed": 0.0,
                "error": f"Host not in allowed list: {urlparse(url).hostname}",
            }

        await self._rate_limit_wait()
        self._request_count += 1

        req_headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "*/*",
        }
        if headers:
            req_headers.update(headers)

        start = time.time()

        try:
            try:
                import aiohttp

                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.request(
                        method=method.upper(),
                        url=url,
                        headers=req_headers,
                        data=body,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        allow_redirects=follow_redirects,
                        max_field_size=self.MAX_RESPONSE_SIZE,
                    ) as resp:
                        resp_body = await resp.text(errors="replace")
                        if len(resp_body) > self.MAX_RESPONSE_SIZE:
                            resp_body = resp_body[:self.MAX_RESPONSE_SIZE] + "\n[TRUNCATED]"

                        return {
                            "status_code": resp.status,
                            "headers": dict(resp.headers),
                            "body": resp_body,
                            "elapsed": time.time() - start,
                            "error": None,
                        }

            except ImportError:
                import urllib.request
                import urllib.error

                req = urllib.request.Request(
                    url,
                    method=method.upper(),
                    headers=req_headers,
                    data=body.encode() if body else None,
                )

                loop = asyncio.get_event_loop()
                try:
                    response = await asyncio.wait_for(
                        loop.run_in_executor(
                            None,
                            lambda: urllib.request.urlopen(req, timeout=timeout),
                        ),
                        timeout=timeout + 2,
                    )
                    resp_body = response.read(self.MAX_RESPONSE_SIZE).decode("utf-8", errors="replace")
                    return {
                        "status_code": response.status,
                        "headers": dict(response.headers),
                        "body": resp_body,
                        "elapsed": time.time() - start,
                        "error": None,
                    }
                except urllib.error.HTTPError as e:
                    return {
                        "status_code": e.code,
                        "headers": dict(e.headers) if e.headers else {},
                        "body": e.read(self.MAX_RESPONSE_SIZE).decode("utf-8", errors="replace") if e.fp else "",
                        "elapsed": time.time() - start,
                        "error": None,
                    }

        except asyncio.TimeoutError:
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "elapsed": time.time() - start,
                "error": "Request timed out",
            }
        except Exception as e:
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "elapsed": time.time() - start,
                "error": str(e),
            }


# ---------------------------------------------------------------------------
# Security header analysis
# ---------------------------------------------------------------------------

SECURITY_HEADERS: list[dict[str, Any]] = [
    {
        "header": "Strict-Transport-Security",
        "title": "Missing HSTS Header",
        "severity": DASTProbeSeverity.HIGH,
        "cvss": 7.4,
        "description": "HTTP Strict Transport Security header not set. Allows protocol downgrade attacks.",
        "impact": "MITM attacks via SSL stripping. Session hijacking on first visit.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cwe": ["CWE-319"],
        "owasp": ["A02:2021"],
        "validate": lambda v: "max-age=" in v.lower() and int(
            re.search(r"max-age=(\d+)", v.lower()).group(1)
            if re.search(r"max-age=(\d+)", v.lower()) else "0"
        ) >= 31536000,
    },
    {
        "header": "Content-Security-Policy",
        "title": "Missing or Weak Content Security Policy",
        "severity": DASTProbeSeverity.HIGH,
        "cvss": 7.1,
        "description": "Content-Security-Policy header missing or uses unsafe directives.",
        "impact": "XSS attacks, data injection, clickjacking via framing.",
        "remediation": "Add CSP: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;",
        "cwe": ["CWE-693"],
        "owasp": ["A05:2021"],
        "validate": lambda v: "unsafe-eval" not in v.lower() and "default-src" in v.lower(),
    },
    {
        "header": "X-Content-Type-Options",
        "title": "Missing X-Content-Type-Options Header",
        "severity": DASTProbeSeverity.MEDIUM,
        "cvss": 5.3,
        "description": "X-Content-Type-Options header not set to 'nosniff'.",
        "impact": "MIME type sniffing can lead to XSS via content type confusion.",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "cwe": ["CWE-693"],
        "owasp": ["A05:2021"],
        "validate": lambda v: v.lower().strip() == "nosniff",
    },
    {
        "header": "X-Frame-Options",
        "title": "Missing X-Frame-Options Header",
        "severity": DASTProbeSeverity.MEDIUM,
        "cvss": 5.4,
        "description": "X-Frame-Options header not set. Page can be framed by malicious sites.",
        "impact": "Clickjacking attacks. User tricked into clicking hidden elements.",
        "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing needed)",
        "cwe": ["CWE-1021"],
        "owasp": ["A05:2021"],
        "validate": lambda v: v.upper().strip() in ("DENY", "SAMEORIGIN"),
    },
    {
        "header": "X-XSS-Protection",
        "title": "Missing X-XSS-Protection Header",
        "severity": DASTProbeSeverity.LOW,
        "cvss": 3.1,
        "description": "X-XSS-Protection header not set. Legacy XSS filter not enabled.",
        "impact": "Reduced defense-in-depth against reflected XSS (legacy browsers).",
        "remediation": "Add header: X-XSS-Protection: 1; mode=block (or 0 if CSP is strong)",
        "cwe": ["CWE-79"],
        "owasp": ["A03:2021"],
        "validate": lambda v: v.strip().startswith("1") or v.strip() == "0",
    },
    {
        "header": "Referrer-Policy",
        "title": "Missing Referrer-Policy Header",
        "severity": DASTProbeSeverity.LOW,
        "cvss": 3.1,
        "description": "Referrer-Policy not set. Full URL may leak to third parties.",
        "impact": "Sensitive URL parameters (tokens, IDs) leaked via Referer header.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": ["CWE-200"],
        "owasp": ["A01:2021"],
        "validate": lambda v: v.lower().strip() in (
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "same-origin", "no-referrer-when-downgrade",
        ),
    },
    {
        "header": "Permissions-Policy",
        "title": "Missing Permissions-Policy Header",
        "severity": DASTProbeSeverity.LOW,
        "cvss": 2.6,
        "description": "Permissions-Policy (formerly Feature-Policy) not set.",
        "impact": "Browser features (camera, microphone, geolocation) not restricted.",
        "remediation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "cwe": ["CWE-693"],
        "owasp": ["A05:2021"],
        "validate": lambda v: len(v) > 0,
    },
]

DANGEROUS_HEADERS: list[dict[str, Any]] = [
    {
        "header": "Server",
        "title": "Server Version Disclosure",
        "severity": DASTProbeSeverity.LOW,
        "cvss": 2.6,
        "description": "Server header reveals software and version information.",
        "impact": "Attacker can target known vulnerabilities for the specific server version.",
        "remediation": "Remove or genericise the Server header. In nginx: server_tokens off;",
        "cwe": ["CWE-200"],
        "check": lambda v: bool(re.search(r"\d+\.\d+", v)),
    },
    {
        "header": "X-Powered-By",
        "title": "Technology Stack Disclosure",
        "severity": DASTProbeSeverity.LOW,
        "cvss": 2.6,
        "description": "X-Powered-By header reveals backend technology.",
        "impact": "Attacker can target framework-specific vulnerabilities.",
        "remediation": "Remove X-Powered-By header entirely.",
        "cwe": ["CWE-200"],
        "check": lambda v: True,
    },
    {
        "header": "X-AspNet-Version",
        "title": "ASP.NET Version Disclosure",
        "severity": DASTProbeSeverity.LOW,
        "cvss": 2.6,
        "description": "X-AspNet-Version header reveals .NET framework version.",
        "impact": "Attacker can target .NET-specific vulnerabilities.",
        "remediation": "Remove header via web.config: <httpRuntime enableVersionHeader='false' />",
        "cwe": ["CWE-200"],
        "check": lambda v: True,
    },
]


# ---------------------------------------------------------------------------
# Injection probe payloads
# ---------------------------------------------------------------------------

INJECTION_PAYLOADS: list[dict[str, Any]] = [
    # SQL Injection
    {
        "name": "SQL Injection (single quote)",
        "payload": "' OR '1'='1",
        "category": DASTProbeCategory.INJECTION,
        "severity": DASTProbeSeverity.CRITICAL,
        "cvss": 9.8,
        "detection_patterns": [
            r"sql.*syntax",
            r"mysql.*error",
            r"ORA-\d{5}",
            r"PostgreSQL.*ERROR",
            r"sqlite3\.OperationalError",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
        ],
        "cwe": ["CWE-89"],
        "owasp": ["A03:2021"],
    },
    {
        "name": "SQL Injection (UNION)",
        "payload": "' UNION SELECT NULL,NULL,NULL--",
        "category": DASTProbeCategory.INJECTION,
        "severity": DASTProbeSeverity.CRITICAL,
        "cvss": 9.8,
        "detection_patterns": [
            r"UNION.*SELECT", r"column.*mismatch", r"different number of columns",
        ],
        "cwe": ["CWE-89"],
        "owasp": ["A03:2021"],
    },
    # XSS
    {
        "name": "Reflected XSS (script tag)",
        "payload": "<script>alert('IMMUNIS-XSS-TEST')</script>",
        "category": DASTProbeCategory.INJECTION,
        "severity": DASTProbeSeverity.HIGH,
        "cvss": 7.1,
        "detection_patterns": [r"<script>alert$'IMMUNIS-XSS-TEST'$</script>"],
        "cwe": ["CWE-79"],
        "owasp": ["A03:2021"],
    },
    {
        "name": "Reflected XSS (event handler)",
        "payload": '"><img src=x onerror=alert("IMMUNIS")>',
        "category": DASTProbeCategory.INJECTION,
        "severity": DASTProbeSeverity.HIGH,
        "cvss": 7.1,
        "detection_patterns": [r'onerror=alert$"IMMUNIS"$'],
        "cwe": ["CWE-79"],
        "owasp": ["A03:2021"],
    },
    # Command Injection
    {
        "name": "OS Command Injection (semicolon)",
        "payload": "; echo IMMUNIS_CMD_TEST",
        "category": DASTProbeCategory.INJECTION,
        "severity": DASTProbeSeverity.CRITICAL,
        "cvss": 9.8,
        "detection_patterns": [r"IMMUNIS_CMD_TEST"],
        "cwe": ["CWE-78"],
        "owasp": ["A03:2021"],
    },
    # Path Traversal
    {
        "name": "Path Traversal (etc/passwd)",
        "payload": "../../../../etc/passwd",
        "category": DASTProbeCategory.INJECTION,
        "severity": DASTProbeSeverity.HIGH,
        "cvss": 7.5,
        "detection_patterns": [r"root:.*:0:0:", r"/bin/bash", r"/bin/sh"],
        "cwe": ["CWE-22"],
        "owasp": ["A01:2021"],
    },
    # SSTI
    {
        "name": "Server-Side Template Injection",
        "payload": "{{7*7}}",
        "category": DASTProbeCategory.INJECTION,
        "severity": DASTProbeSeverity.CRITICAL,
        "cvss": 9.8,
        "detection_patterns": [r"\b49\b"],
        "cwe": ["CWE-94"],
        "owasp": ["A03:2021"],
    },
    # Open Redirect
    {
        "name": "Open Redirect",
        "payload": "https://evil.example.com",
        "category": DASTProbeCategory.REDIRECT,
        "severity": DASTProbeSeverity.MEDIUM,
        "cvss": 5.4,
        "detection_patterns": [],
        "cwe": ["CWE-601"],
        "owasp": ["A01:2021"],
    },
]


# ---------------------------------------------------------------------------
# DAST probe implementations
# ---------------------------------------------------------------------------

class SecurityHeaderProbe:
    """Checks security headers on HTTP responses."""

    async def probe(self, client: SafeHTTPClient, url: str) -> list[DASTFinding]:
        findings: list[DASTFinding] = []

        response = await client.request("GET", url)
        if response.get("error"):
            return findings

        resp_headers = {k.lower(): v for k, v in response.get("headers", {}).items()}

        # Check required headers
        for spec in SECURITY_HEADERS:
            header_lower = spec["header"].lower()
            value = resp_headers.get(header_lower)

            if value is None:
                findings.append(DASTFinding(
                    finding_id=self._make_id(url, spec["header"], "missing"),
                    title=spec["title"],
                    category=DASTProbeCategory.HEADER_SECURITY,
                    severity=spec["severity"],
                    cvss_score=spec["cvss"],
                    confidence=0.95,
                    url=url,
                    method="GET",
                    description=spec["description"],
                    impact=spec["impact"],
                    remediation=spec["remediation"],
                    evidence={"header": spec["header"], "status": "missing"},
                    cwe_ids=spec.get("cwe", []),
                    owasp_ids=spec.get("owasp", []),
                    exploit_probability=0.5,
                ))
            elif not spec["validate"](value):
                findings.append(DASTFinding(
                    finding_id=self._make_id(url, spec["header"], "weak"),
                    title=f"Weak {spec['header']} Configuration",
                    category=DASTProbeCategory.HEADER_SECURITY,
                    severity=DASTProbeSeverity.MEDIUM,
                    cvss_score=max(spec["cvss"] - 2.0, 2.0),
                    confidence=0.85,
                    url=url,
                    method="GET",
                    description=f"{spec['header']} is set but misconfigured: {value}",
                    impact=spec["impact"],
                    remediation=spec["remediation"],
                    evidence={"header": spec["header"], "value": value, "status": "weak"},
                    cwe_ids=spec.get("cwe", []),
                    owasp_ids=spec.get("owasp", []),
                    exploit_probability=0.3,
                ))

        # Check dangerous headers
        for spec in DANGEROUS_HEADERS:
            header_lower = spec["header"].lower()
            value = resp_headers.get(header_lower)
            if value and spec["check"](value):
                findings.append(DASTFinding(
                    finding_id=self._make_id(url, spec["header"], "disclosure"),
                    title=spec["title"],
                    category=DASTProbeCategory.INFO_DISCLOSURE,
                    severity=spec["severity"],
                    cvss_score=spec["cvss"],
                    confidence=0.90,
                    url=url,
                    method="GET",
                    description=spec["description"],
                    impact=spec["impact"],
                    remediation=spec["remediation"],
                    evidence={"header": spec["header"], "value": value},
                    cwe_ids=spec.get("cwe", []),
                    exploit_probability=0.2,
                ))

        return findings

    @staticmethod
    def _make_id(url: str, header: str, status: str) -> str:
        raw = f"{url}:{header}:{status}"
        return f"DAST-HDR-{hashlib.sha256(raw.encode()).hexdigest()[:12]}"


class InjectionProbe:
    """Tests endpoints for injection vulnerabilities."""

    async def probe(
        self,
        client: SafeHTTPClient,
        url: str,
        parameters: list[str],
    ) -> list[DASTFinding]:
        findings: list[DASTFinding] = []

        for param in parameters:
            for payload_spec in INJECTION_PAYLOADS:
                test_url = self._inject_param(url, param, payload_spec["payload"])
                response = await client.request("GET", test_url)

                if response.get("error"):
                    continue

                body = response.get("body", "")

                # Check detection patterns
                for pattern in payload_spec["detection_patterns"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(DASTFinding(
                            finding_id=self._make_id(url, param, payload_spec["name"]),
                            title=payload_spec["name"],
                            category=payload_spec["category"],
                            severity=payload_spec["severity"],
                            cvss_score=payload_spec["cvss"],
                            confidence=0.85,
                            url=url,
                            method="GET",
                            description=f"Injection vulnerability detected in parameter '{param}'.",
                            impact=f"Parameter '{param}' is vulnerable to {payload_spec['name']}.",
                            remediation=f"Sanitise and validate parameter '{param}'. Use parameterised queries for SQL, output encoding for XSS.",
                            evidence={
                                "parameter": param,
                                "payload": payload_spec["payload"],
                                "matched_pattern": pattern,
                                "response_snippet": body[:500],
                            },
                            request_sent=f"GET {test_url}",
                            response_received=f"HTTP {response.get('status_code', 0)}\n{body[:200]}",
                            cwe_ids=payload_spec.get("cwe", []),
                            owasp_ids=payload_spec.get("owasp", []),
                            exploit_probability=0.7,
                        ))
                        break

                # Special handling for open redirect
                if payload_spec["category"] == DASTProbeCategory.REDIRECT:
                    status = response.get("status_code", 0)
                    location = response.get("headers", {}).get("Location", "")
                    if status in (301, 302, 303, 307, 308) and "evil.example.com" in location:
                        findings.append(DASTFinding(
                            finding_id=self._make_id(url, param, "open_redirect"),
                            title="Open Redirect",
                            category=DASTProbeCategory.REDIRECT,
                            severity=DASTProbeSeverity.MEDIUM,
                            cvss_score=5.4,
                            confidence=0.90,
                            url=url,
                            method="GET",
                            description=f"Open redirect via parameter '{param}'.",
                            impact="Phishing attacks using trusted domain as redirect source.",
                            remediation="Validate redirect URLs against an allowlist. Never redirect to user-supplied URLs.",
                            evidence={"parameter": param, "redirect_to": location},
                            cwe_ids=["CWE-601"],
                            owasp_ids=["A01:2021"],
                            exploit_probability=0.6,
                        ))

        return findings

    @staticmethod
    def _inject_param(url: str, param: str, payload: str) -> str:
        """Inject payload into a URL parameter."""
        parsed = urlparse(url)
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{quote(param)}={quote(payload)}"

    @staticmethod
    def _make_id(url: str, param: str, name: str) -> str:
        raw = f"{url}:{param}:{name}"
        return f"DAST-INJ-{hashlib.sha256(raw.encode()).hexdigest()[:12]}"


class CORSProbe:
    """Tests for CORS misconfiguration."""

    async def probe(self, client: SafeHTTPClient, url: str) -> list[DASTFinding]:
        findings: list[DASTFinding] = []

        # Test 1: Arbitrary origin reflection
        evil_origin = "https://evil.example.com"
        response = await client.request(
            "OPTIONS", url,
            headers={
                "Origin": evil_origin,
                "Access-Control-Request-Method": "GET",
            },
        )

        if not response.get("error"):
            resp_headers = {k.lower(): v for k, v in response.get("headers", {}).items()}
            acao = resp_headers.get("access-control-allow-origin", "")

            if acao == evil_origin or acao == "*":
                acac = resp_headers.get("access-control-allow-credentials", "").lower()
                if acao == "*" and acac == "true":
                    # Critical: wildcard + credentials
                    findings.append(DASTFinding(
                        finding_id=f"DAST-CORS-{hashlib.sha256(url.encode()).hexdigest()[:12]}",
                        title="CORS Wildcard with Credentials",
                        category=DASTProbeCategory.CORS_MISCONFIG,
                        severity=DASTProbeSeverity.CRITICAL,
                        cvss_score=9.1,
                        confidence=0.95,
                        url=url,
                        method="OPTIONS",
                        description="CORS allows any origin with credentials. Any website can make authenticated requests.",
                        impact="Full account takeover. Any malicious site can read authenticated responses.",
                        remediation="Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Use explicit origin allowlist.",
                        evidence={"acao": acao, "acac": acac},
                        cwe_ids=["CWE-942"],
                        owasp_ids=["A05:2021"],
                        exploit_probability=0.9,
                    ))
                elif acao == evil_origin:
                    # High: reflects arbitrary origin
                    findings.append(DASTFinding(
                        finding_id=f"DAST-CORS-REFLECT-{hashlib.sha256(url.encode()).hexdigest()[:12]}",
                        title="CORS Origin Reflection",
                        category=DASTProbeCategory.CORS_MISCONFIG,
                        severity=DASTProbeSeverity.HIGH,
                        cvss_score=7.5,
                        confidence=0.90,
                        url=url,
                        method="OPTIONS",
                        description="CORS reflects arbitrary Origin header. Attacker-controlled sites can make cross-origin requests.",
                        impact="Cross-origin data theft if credentials are included.",
                        remediation="Validate Origin against an explicit allowlist. Do not reflect the Origin header directly.",
                        evidence={"sent_origin": evil_origin, "reflected_acao": acao, "acac": acac},
                        cwe_ids=["CWE-942"],
                        owasp_ids=["A05:2021"],
                        exploit_probability=0.7,
                    ))

        # Test 2: Null origin
        response_null = await client.request(
            "OPTIONS", url,
            headers={
                "Origin": "null",
                "Access-Control-Request-Method": "GET",
            },
        )

        if not response_null.get("error"):
            resp_headers = {k.lower(): v for k, v in response_null.get("headers", {}).items()}
            acao = resp_headers.get("access-control-allow-origin", "")
            if acao == "null":
                findings.append(DASTFinding(
                    finding_id=f"DAST-CORS-NULL-{hashlib.sha256(url.encode()).hexdigest()[:12]}",
                    title="CORS Allows Null Origin",
                    category=DASTProbeCategory.CORS_MISCONFIG,
                    severity=DASTProbeSeverity.HIGH,
                    cvss_score=7.5,
                    confidence=0.90,
                    url=url,
                    method="OPTIONS",
                    description="CORS allows 'null' origin. Sandboxed iframes and data: URIs send null origin.",
                    impact="Attacker can craft requests from sandboxed context to bypass CORS.",
                    remediation="Never allow 'null' as a valid origin. Remove it from the allowlist.",
                    evidence={"sent_origin": "null", "reflected_acao": acao},
                    cwe_ids=["CWE-942"],
                    owasp_ids=["A05:2021"],
                    exploit_probability=0.6,
                ))

        return findings


class AuthenticationProbe:
    """Tests for authentication bypass vulnerabilities."""

    async def probe(
        self, client: SafeHTTPClient, endpoints: list[EndpointInfo]
    ) -> list[DASTFinding]:
        findings: list[DASTFinding] = []

        for endpoint in endpoints:
            if not endpoint.requires_auth:
                continue

            # Test 1: Access without credentials
            response = await client.request(endpoint.method, endpoint.url)
            if not response.get("error"):
                status = response.get("status_code", 0)
                if status == 200:
                    findings.append(DASTFinding(
                        finding_id=f"DAST-AUTH-BYPASS-{hashlib.sha256(endpoint.url.encode()).hexdigest()[:12]}",
                        title="Authentication Bypass",
                        category=DASTProbeCategory.AUTH_BYPASS,
                        severity=DASTProbeSeverity.CRITICAL,
                        cvss_score=9.8,
                        confidence=0.85,
                        url=endpoint.url,
                        method=endpoint.method,
                        description="Endpoint expected to require authentication returned 200 without credentials.",
                        impact="Unauthorised access to protected resources.",
                        remediation="Enforce authentication middleware on all protected endpoints. Return 401/403 for unauthenticated requests.",
                        evidence={"expected_status": "401/403", "actual_status": status},
                        cwe_ids=["CWE-306"],
                        owasp_ids=["A01:2021"],
                        exploit_probability=0.9,
                    ))

            # Test 2: Method override (POST endpoint accessible via GET)
            if endpoint.method.upper() in ("POST", "PUT", "DELETE"):
                response_get = await client.request("GET", endpoint.url)
                if not response_get.get("error"):
                    status = response_get.get("status_code", 0)
                    if status == 200:
                        findings.append(DASTFinding(
                            finding_id=f"DAST-AUTH-METHOD-{hashlib.sha256(endpoint.url.encode()).hexdigest()[:12]}",
                            title="HTTP Method Override Bypass",
                            category=DASTProbeCategory.AUTH_BYPASS,
                            severity=DASTProbeSeverity.HIGH,
                            cvss_score=7.5,
                            confidence=0.75,
                            url=endpoint.url,
                            method="GET",
                            description=f"Endpoint registered as {endpoint.method} also responds to GET.",
                            impact="Authentication or CSRF protections may be bypassed via method switching.",
                            remediation="Explicitly reject unexpected HTTP methods. Use @app.post() not @app.api_route().",
                            evidence={"registered_method": endpoint.method, "tested_method": "GET", "status": status},
                            cwe_ids=["CWE-287"],
                            owasp_ids=["A01:2021"],
                            exploit_probability=0.5,
                        ))

        return findings


class RateLimitProbe:
    """Tests for missing rate limiting on sensitive endpoints."""

    BURST_COUNT = 20
    BURST_WINDOW = 2.0  # seconds

    async def probe(
        self, client: SafeHTTPClient, url: str
    ) -> list[DASTFinding]:
        findings: list[DASTFinding] = []

        # Send burst of requests
        statuses: list[int] = []
        start = time.time()

        for _ in range(self.BURST_COUNT):
            response = await client.request("GET", url)
            if not response.get("error"):
                statuses.append(response.get("status_code", 0))

            elapsed = time.time() - start
            if elapsed > self.BURST_WINDOW:
                break

        if not statuses:
            return findings

        # Check if any request was rate-limited (429)
        rate_limited = sum(1 for s in statuses if s == 429)
        success = sum(1 for s in statuses if s == 200)

        if rate_limited == 0 and success >= 15:
            findings.append(DASTFinding(
                finding_id=f"DAST-RATE-{hashlib.sha256(url.encode()).hexdigest()[:12]}",
                title="Missing Rate Limiting",
                category=DASTProbeCategory.RATE_LIMITING,
                severity=DASTProbeSeverity.MEDIUM,
                cvss_score=5.3,
                confidence=0.80,
                url=url,
                method="GET",
                description=f"Sent {len(statuses)} requests in {time.time() - start:.1f}s — none were rate-limited.",
                impact="Brute force attacks, credential stuffing, and DoS attacks are not mitigated.",
                remediation="Implement rate limiting: 100 req/min for API, 10 req/min for auth endpoints. Use 429 status code.",
                evidence={
                    "requests_sent": len(statuses),
                    "successful": success,
                    "rate_limited": rate_limited,
                    "window_seconds": time.time() - start,
                },
                cwe_ids=["CWE-770"],
                owasp_ids=["A04:2021"],
                exploit_probability=0.4,
            ))

        return findings


class ErrorHandlingProbe:
    """Tests for information disclosure via error responses."""

    ERROR_TRIGGERS: list[dict[str, Any]] = [
        {"path": "/nonexistent_path_immunis_test", "method": "GET"},
        {"path": "/api/..%2f..%2f..%2fetc%2fpasswd", "method": "GET"},
        {"path": "/api/test", "method": "PATCH", "body": "{invalid json"},
        {"path": "/api/test?id=abc", "method": "GET"},
    ]

    DISCLOSURE_PATTERNS: list[dict[str, str]] = [
        {"pattern": r"Traceback $most recent call last$", "type": "Python traceback"},
        {"pattern": r"at [\w.]+$[\w.]+:\d+$", "type": "Java/C# stack trace"},
        {"pattern": r"File \"[^\"]+\", line \d+", "type": "Python file path"},
        {"pattern": r"(?:\/[\w.-]+){3,}\.py", "type": "Server file path"},
        {"pattern": r"(?:mysql|postgresql|sqlite|oracle).*(?:error|exception)", "type": "Database error"},
        {"pattern": r"(?:DEBUG|DEVELOPMENT|STAGING)\s*(?:=|:)\s*(?:true|True|1)", "type": "Debug mode indicator"},
        {"pattern": r"(?:secret|password|token|key)\s*(?:=|:)\s*['\"][^'\"]+['\"]", "type": "Credential in error"},
        {"pattern": r"<pre>.*(?:Error|Exception|Traceback)", "type": "Formatted error page"},
    ]

    async def probe(
        self, client: SafeHTTPClient, base_url: str
    ) -> list[DASTFinding]:
        findings: list[DASTFinding] = []

        for trigger in self.ERROR_TRIGGERS:
            url = urljoin(base_url, trigger["path"])
            response = await client.request(
                trigger["method"],
                url,
                body=trigger.get("body"),
            )

            if response.get("error"):
                continue

            body = response.get("body", "")
            status = response.get("status_code", 0)

            # Only check error responses
            if status < 400:
                continue

            for disc in self.DISCLOSURE_PATTERNS:
                if re.search(disc["pattern"], body, re.IGNORECASE | re.DOTALL):
                    findings.append(DASTFinding(
                        finding_id=f"DAST-ERR-{hashlib.sha256(f'{url}:{disc["type"]}'.encode()).hexdigest()[:12]}",
                        title=f"Information Disclosure via Error: {disc['type']}",
                        category=DASTProbeCategory.ERROR_HANDLING,
                        severity=DASTProbeSeverity.MEDIUM,
                        cvss_score=5.3,
                        confidence=0.85,
                        url=url,
                        method=trigger["method"],
                        description=f"Error response contains {disc['type']} information.",
                        impact="Internal paths, technology stack, and potentially credentials exposed to attackers.",
                        remediation="Use generic error pages in production. Log detailed errors server-side only. Set DEBUG=False.",
                        evidence={
                            "trigger": trigger,
                            "disclosure_type": disc["type"],
                            "status_code": status,
                            "response_snippet": body[:300],
                        },
                        cwe_ids=["CWE-209"],
                        owasp_ids=["A05:2021"],
                        exploit_probability=0.3,
                    ))
                    break  # One disclosure type per trigger is enough

        return findings


class TLSProbe:
    """Tests TLS configuration of the target."""

    async def probe(self, url: str) -> list[DASTFinding]:
        findings: list[DASTFinding] = []

        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            findings.append(DASTFinding(
                finding_id=f"DAST-TLS-NOSSL-{hashlib.sha256(url.encode()).hexdigest()[:12]}",
                title="Service Not Using HTTPS",
                category=DASTProbeCategory.TLS_CONFIG,
                severity=DASTProbeSeverity.HIGH,
                cvss_score=7.4,
                confidence=0.95,
                url=url,
                method="N/A",
                description="Service is accessible over unencrypted HTTP.",
                impact="All traffic including credentials transmitted in cleartext. MITM attacks trivial.",
                remediation="Enable TLS. Redirect all HTTP to HTTPS. Use HSTS header.",
                evidence={"scheme": parsed.scheme},
                cwe_ids=["CWE-319"],
                owasp_ids=["A02:2021"],
                exploit_probability=0.8,
            ))
            return findings

        # Check TLS version and certificate
        try:
            context = ssl.create_default_context()
            loop = asyncio.get_event_loop()

            def _check_tls():
                import socket
                conn = context.wrap_socket(
                    socket.socket(socket.AF_INET),
                    server_hostname=host,
                )
                conn.settimeout(10)
                try:
                    conn.connect((host, port))
                    cert = conn.getpeercert()
                    protocol = conn.version()
                    cipher = conn.cipher()
                    return {
                        "cert": cert,
                        "protocol": protocol,
                        "cipher": cipher,
                        "error": None,
                    }
                except Exception as e:
                    return {"cert": None, "protocol": None, "cipher": None, "error": str(e)}
                finally:
                    conn.close()

            result = await loop.run_in_executor(None, _check_tls)

            if result["error"]:
                if "certificate" in result["error"].lower():
                    findings.append(DASTFinding(
                        finding_id=f"DAST-TLS-CERT-{hashlib.sha256(url.encode()).hexdigest()[:12]}",
                        title="TLS Certificate Error",
                        category=DASTProbeCategory.TLS_CONFIG,
                        severity=DASTProbeSeverity.HIGH,
                        cvss_score=7.4,
                        confidence=0.90,
                        url=url,
                        method="N/A",
                        description=f"TLS certificate validation failed: {result['error']}",
                        impact="MITM attacks possible. Users may be trained to ignore certificate warnings.",
                        remediation="Install a valid certificate from a trusted CA. Use Let's Encrypt for free certificates.",
                        evidence={"error": result["error"]},
                        cwe_ids=["CWE-295"],
                        owasp_ids=["A02:2021"],
                        exploit_probability=0.6,
                    ))
            else:
                # Check protocol version
                protocol = result.get("protocol", "")
                weak_protocols = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}
                if protocol in weak_protocols:
                    findings.append(DASTFinding(
                        finding_id=f"DAST-TLS-PROTO-{hashlib.sha256(url.encode()).hexdigest()[:12]}",
                        title=f"Weak TLS Protocol: {protocol}",
                        category=DASTProbeCategory.TLS_CONFIG,
                        severity=DASTProbeSeverity.HIGH,
                        cvss_score=7.4,
                        confidence=0.95,
                        url=url,
                        method="N/A",
                        description=f"Server supports deprecated TLS protocol: {protocol}",
                        impact="Known attacks against older TLS versions (POODLE, BEAST, etc.).",
                        remediation="Disable TLS 1.0 and 1.1. Require TLS 1.2+ (preferably TLS 1.3).",
                        evidence={"protocol": protocol},
                        cwe_ids=["CWE-326"],
                        owasp_ids=["A02:2021"],
                        exploit_probability=0.5,
                    ))

                # Check cipher strength
                cipher_info = result.get("cipher")
                if cipher_info:
                    cipher_name = cipher_info[0] if isinstance(cipher_info, tuple) else str(cipher_info)
                    weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
                    if any(wc in cipher_name.upper() for wc in weak_ciphers):
                        findings.append(DASTFinding(
                            finding_id=f"DAST-TLS-CIPHER-{hashlib.sha256(url.encode()).hexdigest()[:12]}",
                            title=f"Weak TLS Cipher: {cipher_name}",
                            category=DASTProbeCategory.TLS_CONFIG,
                            severity=DASTProbeSeverity.HIGH,
                            cvss_score=7.4,
                            confidence=0.90,
                            url=url,
                            method="N/A",
                            description=f"Server uses weak cipher suite: {cipher_name}",
                            impact="Encrypted traffic may be decryptable by attacker.",
                            remediation="Configure strong cipher suites only. Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
                            evidence={"cipher": cipher_name},
                            cwe_ids=["CWE-327"],
                            owasp_ids=["A02:2021"],
                            exploit_probability=0.4,
                        ))

        except Exception as e:
            logger.warning(f"TLS probe failed for {url}: {e}")

        return findings


# ---------------------------------------------------------------------------
# Endpoint discovery
# ---------------------------------------------------------------------------

class EndpointDiscoverer:
    """
    Discovers API endpoints through multiple strategies:
    1. OpenAPI/Swagger spec parsing
    2. Common path brute-forcing
    3. Response link extraction
    """

    COMMON_PATHS: list[dict[str, Any]] = [
        {"path": "/", "method": "GET"},
        {"path": "/api", "method": "GET"},
        {"path": "/api/health", "method": "GET"},
        {"path": "/api/docs", "method": "GET"},
        {"path": "/api/openapi.json", "method": "GET"},
        {"path": "/docs", "method": "GET"},
        {"path": "/redoc", "method": "GET"},
        {"path": "/openapi.json", "method": "GET"},
        {"path": "/swagger.json", "method": "GET"},
        {"path": "/api/v1", "method": "GET"},
        {"path": "/api/v2", "method": "GET"},
        {"path": "/admin", "method": "GET", "auth": True},
        {"path": "/login", "method": "POST"},
        {"path": "/api/users", "method": "GET", "auth": True},
        {"path": "/api/config", "method": "GET", "auth": True},
        {"path": "/metrics", "method": "GET"},
        {"path": "/health", "method": "GET"},
        {"path": "/status", "method": "GET"},
        {"path": "/.env", "method": "GET"},
        {"path": "/.git/config", "method": "GET"},
        {"path": "/robots.txt", "method": "GET"},
        {"path": "/sitemap.xml", "method": "GET"},
        {"path": "/.well-known/security.txt", "method": "GET"},
    ]

    async def discover(
        self, client: SafeHTTPClient, base_url: str
    ) -> list[EndpointInfo]:
        endpoints: list[EndpointInfo] = []

        # Strategy 1: Try OpenAPI spec
        openapi_endpoints = await self._parse_openapi(client, base_url)
        endpoints.extend(openapi_endpoints)

        # Strategy 2: Common path probing
        for path_spec in self.COMMON_PATHS:
            url = urljoin(base_url.rstrip("/") + "/", path_spec["path"].lstrip("/"))
            response = await client.request(path_spec["method"], url)

            if response.get("error"):
                continue

            status = response.get("status_code", 0)
            if status < 500 and status != 404:
                resp_headers = response.get("headers", {})
                content_type = resp_headers.get("Content-Type", resp_headers.get("content-type", ""))

                endpoints.append(EndpointInfo(
                    url=url,
                    method=path_spec["method"],
                    status_code=status,
                    content_type=content_type,
                    headers=resp_headers,
                    requires_auth=path_spec.get("auth", False) or status in (401, 403),
                ))

        # Deduplicate
        seen: set[str] = set()
        unique: list[EndpointInfo] = []
        for ep in endpoints:
            key = f"{ep.method}:{ep.url}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)

        return unique

    async def _parse_openapi(
        self, client: SafeHTTPClient, base_url: str
    ) -> list[EndpointInfo]:
        """Try to parse OpenAPI/Swagger spec for endpoint discovery."""
        endpoints: list[EndpointInfo] = []

        spec_paths = ["/openapi.json", "/api/openapi.json", "/swagger.json", "/api/swagger.json"]

        for spec_path in spec_paths:
            url = urljoin(base_url.rstrip("/") + "/", spec_path.lstrip("/"))
            response = await client.request("GET", url)

            if response.get("error") or response.get("status_code", 0) != 200:
                continue

            try:
                spec = json.loads(response.get("body", ""))
                paths = spec.get("paths", {})

                for path, methods in paths.items():
                    for method, details in methods.items():
                        if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                            full_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

                            # Extract parameters
                            params = []
                            for param in details.get("parameters", []):
                                if param.get("in") == "query":
                                    params.append(param.get("name", ""))

                            requires_auth = bool(details.get("security", spec.get("security")))

                            endpoints.append(EndpointInfo(
                                url=full_url,
                                method=method.upper(),
                                requires_auth=requires_auth,
                                parameters=params,
                            ))

                logger.info(f"Parsed OpenAPI spec: {len(endpoints)} endpoints from {url}")
                break  # Found a valid spec

            except (json.JSONDecodeError, KeyError, TypeError):
                continue

        return endpoints


# ---------------------------------------------------------------------------
# Main DAST scanner orchestrator
# ---------------------------------------------------------------------------

class DynamicAnalysisScanner:
    """
    Orchestrates the full DAST scanning pipeline:
    1. Endpoint discovery (OpenAPI + common paths)
    2. Security header analysis
    3. TLS configuration check
    4. CORS misconfiguration testing
    5. Injection probe testing
    6. Authentication bypass testing
    7. Rate limiting verification
    8. Error handling information disclosure
    9. Result aggregation and prioritisation

    Design principle: Non-destructive probing only. No data modification,
    no brute-force attacks, no denial-of-service. All probes are safe for
    production environments when rate limiting is respected.
    """

    def __init__(self):
        self.header_probe = SecurityHeaderProbe()
        self.injection_probe = InjectionProbe()
        self.cors_probe = CORSProbe()
        self.auth_probe = AuthenticationProbe()
        self.rate_probe = RateLimitProbe()
        self.error_probe = ErrorHandlingProbe()
        self.tls_probe = TLSProbe()
        self.discoverer = EndpointDiscoverer()
        self._scan_history: list[DASTScanResult] = []

    async def scan(
        self,
        target_url: str,
        allowed_hosts: Optional[list[str]] = None,
        skip_tls: bool = False,
        skip_injection: bool = False,
        max_endpoints: int = 50,
    ) -> DASTScanResult:
        """
        Run a full DAST scan against a target URL.

        Args:
            target_url: Base URL to scan
            allowed_hosts: Hosts allowed for probing (safety control)
            skip_tls: Skip TLS checks (for HTTP-only targets)
            skip_injection: Skip injection probes (faster, less intrusive)
            max_endpoints: Maximum endpoints to probe

        Returns:
            DASTScanResult with all findings
        """
        scan_id = hashlib.sha256(f"{target_url}:{time.time()}".encode()).hexdigest()[:16]
        result = DASTScanResult(
            scan_id=scan_id,
            target_url=target_url,
            status=DASTScanStatus.RUNNING,
            started_at=time.time(),
        )

        # Determine allowed hosts
        if allowed_hosts is None:
            parsed = urlparse(target_url)
            allowed_hosts = [parsed.hostname or "localhost"]

        client = SafeHTTPClient(allowed_hosts=allowed_hosts)

        try:
            # Phase 1: Endpoint discovery
            logger.info(f"DAST scan {scan_id}: Discovering endpoints at {target_url}")
            endpoints = await self.discoverer.discover(client, target_url)
            result.endpoints_discovered = endpoints[:max_endpoints]
            logger.info(f"DAST scan {scan_id}: Discovered {len(result.endpoints_discovered)} endpoints")

            all_findings: list[DASTFinding] = []

            # Phase 2: Security headers (on base URL)
            logger.info(f"DAST scan {scan_id}: Checking security headers")
            header_findings = await self.header_probe.probe(client, target_url)
            all_findings.extend(header_findings)

            # Phase 3: TLS configuration
            if not skip_tls:
                logger.info(f"DAST scan {scan_id}: Checking TLS configuration")
                tls_findings = await self.tls_probe.probe(target_url)
                all_findings.extend(tls_findings)

            # Phase 4: CORS
            logger.info(f"DAST scan {scan_id}: Testing CORS configuration")
            cors_findings = await self.cors_probe.probe(client, target_url)
            all_findings.extend(cors_findings)

            # Also test CORS on discovered API endpoints
            api_endpoints = [ep for ep in result.endpoints_discovered if "/api" in ep.url]
            for ep in api_endpoints[:5]:
                cors_ep_findings = await self.cors_probe.probe(client, ep.url)
                all_findings.extend(cors_ep_findings)

            # Phase 5: Injection testing
            if not skip_injection:
                logger.info(f"DAST scan {scan_id}: Testing for injection vulnerabilities")
                for ep in result.endpoints_discovered:
                    if ep.parameters:
                        inj_findings = await self.injection_probe.probe(
                            client, ep.url, ep.parameters,
                        )
                        all_findings.extend(inj_findings)

            # Phase 6: Authentication bypass
            logger.info(f"DAST scan {scan_id}: Testing authentication bypass")
            auth_endpoints = [ep for ep in result.endpoints_discovered if ep.requires_auth]
            if auth_endpoints:
                auth_findings = await self.auth_probe.probe(client, auth_endpoints)
                all_findings.extend(auth_findings)

            # Phase 7: Rate limiting
            logger.info(f"DAST scan {scan_id}: Testing rate limiting")
            rate_findings = await self.rate_probe.probe(client, target_url)
            all_findings.extend(rate_findings)

            # Phase 8: Error handling
            logger.info(f"DAST scan {scan_id}: Testing error handling")
            error_findings = await self.error_probe.probe(client, target_url)
            all_findings.extend(error_findings)

            # Phase 9: Sensitive file exposure
            logger.info(f"DAST scan {scan_id}: Checking for sensitive file exposure")
            sensitive_findings = await self._check_sensitive_files(client, target_url)
            all_findings.extend(sensitive_findings)

            # Deduplicate and prioritise
            all_findings = self._deduplicate(all_findings)
            all_findings.sort(key=lambda f: f.risk_score, reverse=True)

            result.findings = all_findings
            result.requests_sent = client._request_count
            result.status = DASTScanStatus.COMPLETED
            result.completed_at = time.time()
            result.scan_duration_seconds = result.completed_at - result.started_at

            logger.info(
                f"DAST scan {scan_id} completed: {len(all_findings)} findings, "
                f"{result.requests_sent} requests in {result.scan_duration_seconds:.1f}s"
            )

        except Exception as e:
            result.status = DASTScanStatus.FAILED
            result.errors.append(f"Scan failed: {e}")
            result.completed_at = time.time()
            result.scan_duration_seconds = result.completed_at - result.started_at
            logger.error(f"DAST scan {scan_id} failed: {e}")

        self._scan_history.append(result)
        return result

    async def _check_sensitive_files(
        self, client: SafeHTTPClient, base_url: str
    ) -> list[DASTFinding]:
        """Check for exposed sensitive files and directories."""
        findings: list[DASTFinding] = []

        sensitive_paths = [
            {
                "path": "/.env",
                "title": "Exposed Environment File",
                "severity": DASTProbeSeverity.CRITICAL,
                "cvss": 9.8,
                "description": "Environment file containing secrets is publicly accessible.",
                "impact": "Database credentials, API keys, and secrets exposed.",
                "patterns": [r"(?:DB_|DATABASE_|SECRET|API_KEY|PASSWORD|TOKEN)\s*="],
            },
            {
                "path": "/.git/config",
                "title": "Exposed Git Repository",
                "severity": DASTProbeSeverity.HIGH,
                "cvss": 7.5,
                "description": "Git repository metadata is publicly accessible.",
                "impact": "Full source code recovery. May contain hardcoded secrets in history.",
                "patterns": [r"\[core\]", r"\[remote", r"repositoryformatversion"],
            },
            {
                "path": "/.git/HEAD",
                "title": "Exposed Git HEAD",
                "severity": DASTProbeSeverity.HIGH,
                "cvss": 7.5,
                "description": "Git HEAD file is publicly accessible.",
                "impact": "Confirms git repository exposure. Enables full repo reconstruction.",
                "patterns": [r"ref: refs/"],
            },
            {
                "path": "/wp-config.php",
                "title": "Exposed WordPress Configuration",
                "severity": DASTProbeSeverity.CRITICAL,
                "cvss": 9.8,
                "description": "WordPress configuration file is publicly accessible.",
                "impact": "Database credentials and authentication keys exposed.",
                "patterns": [r"DB_NAME", r"DB_PASSWORD", r"AUTH_KEY"],
            },
            {
                "path": "/phpinfo.php",
                "title": "Exposed PHP Info Page",
                "severity": DASTProbeSeverity.MEDIUM,
                "cvss": 5.3,
                "description": "PHP information page is publicly accessible.",
                "impact": "Server configuration, installed modules, and environment variables exposed.",
                "patterns": [r"phpinfo\(\)", r"PHP Version", r"Configuration"],
            },
            {
                "path": "/server-status",
                "title": "Exposed Server Status",
                "severity": DASTProbeSeverity.MEDIUM,
                "cvss": 5.3,
                "description": "Apache server-status page is publicly accessible.",
                "impact": "Active connections, request details, and server load exposed.",
                "patterns": [r"Apache Server Status", r"Server uptime"],
            },
            {
                "path": "/debug",
                "title": "Exposed Debug Endpoint",
                "severity": DASTProbeSeverity.HIGH,
                "cvss": 7.5,
                "description": "Debug endpoint is publicly accessible.",
                "impact": "Internal application state, configuration, and potentially code execution.",
                "patterns": [r"debug", r"traceback", r"stack trace"],
            },
            {
                "path": "/backup.sql",
                "title": "Exposed Database Backup",
                "severity": DASTProbeSeverity.CRITICAL,
                "cvss": 9.8,
                "description": "Database backup file is publicly accessible.",
                "impact": "Complete database contents including user data and credentials.",
                "patterns": [r"CREATE TABLE", r"INSERT INTO", r"DROP TABLE"],
            },
            {
                "path": "/api/graphql",
                "title": "GraphQL Introspection Enabled",
                "severity": DASTProbeSeverity.MEDIUM,
                "cvss": 5.3,
                "description": "GraphQL endpoint with introspection enabled.",
                "impact": "Full API schema exposed. Enables targeted attacks on all fields and mutations.",
                "patterns": [r"__schema", r"__type", r"queryType"],
            },
        ]

        for spec in sensitive_paths:
            url = urljoin(base_url.rstrip("/") + "/", spec["path"].lstrip("/"))
            response = await client.request("GET", url)

            if response.get("error"):
                continue

            status = response.get("status_code", 0)
            body = response.get("body", "")

            if status == 200:
                # Verify content matches expected patterns
                matched = False
                for pattern in spec["patterns"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        matched = True
                        break

                if matched:
                    findings.append(DASTFinding(
                        finding_id=f"DAST-FILE-{hashlib.sha256(url.encode()).hexdigest()[:12]}",
                        title=spec["title"],
                        category=DASTProbeCategory.INFO_DISCLOSURE,
                        severity=spec["severity"],
                        cvss_score=spec["cvss"],
                        confidence=0.90,
                        url=url,
                        method="GET",
                        description=spec["description"],
                        impact=spec["impact"],
                        remediation=f"Block access to {spec['path']} in web server configuration. Add to .gitignore and deny rules.",
                        evidence={
                            "path": spec["path"],
                            "status_code": status,
                            "content_preview": body[:200],
                        },
                        cwe_ids=["CWE-538"],
                        owasp_ids=["A05:2021"],
                        exploit_probability=0.8,
                    ))

        return findings

    def _deduplicate(self, findings: list[DASTFinding]) -> list[DASTFinding]:
        """Remove duplicate findings."""
        seen: set[str] = set()
        unique: list[DASTFinding] = []

        for finding in findings:
            dedup_key = f"{finding.url}:{finding.category.value}:{finding.title}"
            if dedup_key not in seen:
                seen.add(dedup_key)
                unique.append(finding)

        return unique

    def get_scan_history(self) -> list[dict]:
        """Return summary of all past scans."""
        return [
            {
                "scan_id": s.scan_id,
                "target_url": s.target_url,
                "status": s.status.value,
                "started_at": s.started_at,
                "endpoints_discovered": len(s.endpoints_discovered),
                "finding_count": len(s.findings),
                "risk_score": s.risk_score,
                "duration": s.scan_duration_seconds,
            }
            for s in self._scan_history
        ]

    def get_latest_scan(self) -> Optional[DASTScanResult]:
        """Return the most recent scan result."""
        return self._scan_history[-1] if self._scan_history else None


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

dynamic_scanner = DynamicAnalysisScanner()
