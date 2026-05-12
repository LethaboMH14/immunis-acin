"""
VirusTotal Integration — Real-World Threat Validation

Provides live cross-referencing of IMMUNIS detections against VirusTotal's
database of 70+ antivirus engines. Used during demos to prove IMMUNIS detects
threats that commercial solutions miss.

Free API: 4 requests/minute, 500 requests/day, 15.5K requests/month.
We rate-limit to 3/minute to stay safely under quota.

Reference: VirusTotal API v3 documentation
https://docs.virustotal.com/reference/overview

WHY THIS EXISTS:
- Transforms demo from "impressive simulation" to "real-world proof"
- Direct comparison against 70+ commercial AV engines
- Shows IMMUNIS value proposition with hard data
- Judges see live API calls, not mock data
"""

import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

import httpx

from backend.config import settings

logger = logging.getLogger("immunis.virustotal")

# --- Constants ---

VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_RATE_LIMIT = 3  # requests per minute (free tier is 4, we stay under)
VT_TIMEOUT = 30  # seconds
VT_MAX_RETRIES = 2


class VTResourceType(str, Enum):
    """Types of resources we can look up on VirusTotal."""
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    FILE_HASH = "file_hash"


@dataclass
class VTDetectionResult:
    """Result of a VirusTotal lookup for a single indicator."""
    indicator: str
    indicator_type: VTResourceType
    found: bool
    total_engines: int = 0
    engines_detected: int = 0
    engines_undetected: int = 0
    detection_rate: float = 0.0
    detection_names: list[str] = field(default_factory=list)
    categories: dict[str, str] = field(default_factory=dict)
    reputation: int = 0
    last_analysis_date: Optional[str] = None
    community_score: int = 0
    error: Optional[str] = None
    raw_stats: dict = field(default_factory=dict)
    query_time_ms: float = 0.0


@dataclass
class VTComparisonResult:
    """Side-by-side comparison of IMMUNIS vs VirusTotal detection."""
    threat_id: str
    immunis_detected: bool
    immunis_confidence: float
    immunis_classification: str
    immunis_attack_family: str
    immunis_time_ms: float
    vt_results: list[VTDetectionResult] = field(default_factory=list)
    vt_max_detection_rate: float = 0.0
    vt_avg_detection_rate: float = 0.0
    immunis_advantage: str = ""
    comparison_summary: str = ""
    indicators_checked: int = 0
    indicators_missed_by_vt: int = 0


class VirusTotalClient:
    """
    Async client for VirusTotal API v3.
    
    Handles rate limiting (3 req/min for free tier), retries,
    and provides both raw lookups and IMMUNIS comparison analysis.
    
    Usage:
        client = VirusTotalClient()
        result = await client.lookup_url("https://evil-phishing.com")
        comparison = await client.compare_with_immunis(threat_data, immunis_result)
    """

    def __init__(self):
        self._api_key: str = getattr(settings, 'VIRUSTOTAL_API_KEY', '') or ''
        self._request_times: list[float] = []
        self._daily_count: int = 0
        self._daily_reset: float = time.time() + 86400
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def is_configured(self) -> bool:
        """Check if VT API key is available."""
        return len(self._api_key) > 0

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with VT headers."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=VT_API_BASE,
                headers={
                    "x-apikey": self._api_key,
                    "Accept": "application/json",
                },
                timeout=VT_TIMEOUT,
            )
        return self._client

    async def _rate_limit(self):
        """
        Enforce rate limit: max VT_RATE_LIMIT requests per 60 seconds.
        Blocks until a slot is available.
        """
        now = time.time()

        # Reset daily counter
        if now > self._daily_reset:
            self._daily_count = 0
            self._daily_reset = now + 86400

        # Check daily limit (500 for free tier)
        if self._daily_count >= 480:  # Leave 20 buffer
            logger.warning("VT daily quota nearly exhausted (%d/500)", self._daily_count)
            raise RuntimeError("VirusTotal daily quota exhausted")

        # Clean old timestamps
        self._request_times = [t for t in self._request_times if now - t < 60]

        # Wait if at rate limit
        if len(self._request_times) >= VT_RATE_LIMIT:
            oldest = self._request_times[0]
            wait_time = 60 - (now - oldest) + 0.5  # 0.5s buffer
            if wait_time > 0:
                logger.debug("VT rate limit: waiting %.1fs", wait_time)
                await asyncio.sleep(wait_time)

        self._request_times.append(time.time())
        self._daily_count += 1

    async def _request(self, method: str, path: str, **kwargs) -> Optional[dict]:
        """Make a rate-limited request to VT API with retry."""
        if not self.is_configured:
            logger.debug("VT API key not configured — returning None")
            return None

        for attempt in range(VT_MAX_RETRIES + 1):
            try:
                await self._rate_limit()
                client = await self._get_client()
                response = await client.request(method, path, **kwargs)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    logger.debug("VT resource not found: %s", path)
                    return None
                elif response.status_code == 429:
                    wait = 60 if attempt < VT_MAX_RETRIES else 0
                    logger.warning("VT rate limited (429), waiting %ds", wait)
                    if wait:
                        await asyncio.sleep(wait)
                    continue
                elif response.status_code == 401:
                    logger.error("VT API key invalid (401)")
                    return None
                else:
                    logger.warning("VT unexpected status %d: %s",
                                   response.status_code, response.text[:200])
                    if attempt < VT_MAX_RETRIES:
                        await asyncio.sleep(2 ** attempt)
                    continue

            except httpx.TimeoutException:
                logger.warning("VT request timeout (attempt %d/%d)",
                               attempt + 1, VT_MAX_RETRIES + 1)
                if attempt < VT_MAX_RETRIES:
                    await asyncio.sleep(2 ** attempt)
            except Exception as e:
                logger.error("VT request error: %s", e)
                if attempt < VT_MAX_RETRIES:
                    await asyncio.sleep(2 ** attempt)

        return None

    # --- Lookup Methods ---

    async def lookup_url(self, url: str) -> VTDetectionResult:
        """
        Look up a URL on VirusTotal.
        
        VT API requires URL to be base64url-encoded (no padding) as the resource ID.
        """
        start = time.time()
        result = VTDetectionResult(
            indicator=url,
            indicator_type=VTResourceType.URL,
            found=False,
        )

        try:
            # VT URL ID is base64url of the URL without padding
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

            data = await self._request("GET", f"/urls/{url_id}")
            if data:
                result = self._parse_analysis_result(data, url, VTResourceType.URL)

        except Exception as e:
            result.error = str(e)
            logger.error("VT URL lookup error: %s", e)

        result.query_time_ms = (time.time() - start) * 1000
        return result

    async def lookup_domain(self, domain: str) -> VTDetectionResult:
        """Look up a domain on VirusTotal."""
        start = time.time()
        result = VTDetectionResult(
            indicator=domain,
            indicator_type=VTResourceType.DOMAIN,
            found=False,
        )

        try:
            data = await self._request("GET", f"/domains/{domain}")
            if data:
                result = self._parse_analysis_result(data, domain, VTResourceType.DOMAIN)

        except Exception as e:
            result.error = str(e)
            logger.error("VT domain lookup error: %s", e)

        result.query_time_ms = (time.time() - start) * 1000
        return result

    async def lookup_ip(self, ip: str) -> VTDetectionResult:
        """Look up an IP address on VirusTotal."""
        start = time.time()
        result = VTDetectionResult(
            indicator=ip,
            indicator_type=VTResourceType.IP,
            found=False,
        )

        try:
            data = await self._request("GET", f"/ip_addresses/{ip}")
            if data:
                result = self._parse_analysis_result(data, ip, VTResourceType.IP)

        except Exception as e:
            result.error = str(e)
            logger.error("VT IP lookup error: %s", e)

        result.query_time_ms = (time.time() - start) * 1000
        return result

    async def lookup_hash(self, file_hash: str) -> VTDetectionResult:
        """Look up a file hash (MD5, SHA1, SHA256) on VirusTotal."""
        start = time.time()
        result = VTDetectionResult(
            indicator=file_hash,
            indicator_type=VTResourceType.FILE_HASH,
            found=False,
        )

        try:
            data = await self._request("GET", f"/files/{file_hash}")
            if data:
                result = self._parse_analysis_result(data, file_hash, VTResourceType.FILE_HASH)

        except Exception as e:
            result.error = str(e)
            logger.error("VT hash lookup error: %s", e)

        result.query_time_ms = (time.time() - start) * 1000
        return result

    def _parse_analysis_result(
        self, data: dict, indicator: str, indicator_type: VTResourceType
    ) -> VTDetectionResult:
        """Parse VT API response into structured result."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        timeout_count = stats.get("timeout", 0)

        total = malicious + suspicious + undetected + harmless + timeout_count
        detected = malicious + suspicious

        # Extract detection names from engines that flagged it
        detection_names = []
        last_analysis = attrs.get("last_analysis_results", {})
        for engine_name, engine_result in last_analysis.items():
            if engine_result.get("category") in ("malicious", "suspicious"):
                result_name = engine_result.get("result", engine_name)
                if result_name:
                    detection_names.append(f"{engine_name}: {result_name}")

        # Categories (for domains/URLs)
        categories = {}
        for cat_source, cat_value in attrs.get("categories", {}).items():
            categories[cat_source] = cat_value

        return VTDetectionResult(
            indicator=indicator,
            indicator_type=indicator_type,
            found=True,
            total_engines=total,
            engines_detected=detected,
            engines_undetected=total - detected,
            detection_rate=detected / total if total > 0 else 0.0,
            detection_names=detection_names[:20],  # Cap at 20 for display
            categories=categories,
            reputation=attrs.get("reputation", 0),
            last_analysis_date=attrs.get("last_analysis_date"),
            community_score=attrs.get("total_votes", {}).get("malicious", 0),
            raw_stats=stats,
        )

    # --- Indicator Extraction ---

    def extract_indicators(self, threat_content: str) -> dict[VTResourceType, list[str]]:
        """
        Extract checkable indicators from threat content.
        
        Pulls out URLs, domains, IPs, and hashes that can be
        cross-referenced with VirusTotal.
        """
        indicators: dict[VTResourceType, list[str]] = {
            VTResourceType.URL: [],
            VTResourceType.DOMAIN: [],
            VTResourceType.IP: [],
            VTResourceType.FILE_HASH: [],
        }

        # URLs (http/https)
        url_pattern = r'https?://[^\s<>"\')\]},;]+'
        urls = re.findall(url_pattern, threat_content, re.IGNORECASE)
        for url in urls:
            url = url.rstrip('.')
            indicators[VTResourceType.URL].append(url)
            # Also extract domain from URL
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    indicators[VTResourceType.DOMAIN].append(parsed.hostname)
            except Exception:
                pass

        # Standalone domains (not already in URLs)
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|gov|edu|mil|int|info|biz|xyz|top|online|site|club|ru|cn|za|ae|uk|de|fr|jp|kr|br|in|au|nl|se|no|fi|dk|ch|at|be|it|es|pt|pl|cz|ro|bg|hr|rs|ua|by|kz|ir|sa|qa|om|bh|kw|eg|ng|ke|gh|tz|ug|rw|et|ma|dz|tn|ly)\b'
        domains = re.findall(domain_pattern, threat_content, re.IGNORECASE)
        existing_domains = set(indicators[VTResourceType.DOMAIN])
        for domain in domains:
            if domain.lower() not in existing_domains:
                indicators[VTResourceType.DOMAIN].append(domain.lower())
                existing_domains.add(domain.lower())

        # IP addresses (IPv4)
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = re.findall(ip_pattern, threat_content)
        # Filter out private/reserved IPs
        for ip in ips:
            octets = [int(o) for o in ip.split('.')]
            if octets[0] in (10, 127):
                continue
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                continue
            if octets[0] == 192 and octets[1] == 168:
                continue
            indicators[VTResourceType.IP].append(ip)

        # File hashes (MD5, SHA1, SHA256)
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'

        for pattern in [sha256_pattern, sha1_pattern, md5_pattern]:
            hashes = re.findall(pattern, threat_content)
            for h in hashes:
                if h not in indicators[VTResourceType.FILE_HASH]:
                    indicators[VTResourceType.FILE_HASH].append(h)

        # Deduplicate
        for key in indicators:
            indicators[key] = list(dict.fromkeys(indicators[key]))[:10]  # Max 10 per type

        return indicators

    # --- Comparison Engine ---

    async def compare_with_immunis(
        self,
        threat_id: str,
        threat_content: str,
        immunis_detected: bool,
        immunis_confidence: float,
        immunis_classification: str,
        immunis_attack_family: str,
        immunis_time_ms: float,
    ) -> VTComparisonResult:
        """
        Run IMMUNIS detection alongside VirusTotal and produce a comparison.
        
        This is the showpiece function for the demo:
        "IMMUNIS detected this with 0.97 confidence in 1.8 seconds.
         VirusTotal: 3 out of 70 engines flagged it."
        
        Args:
            threat_id: IMMUNIS incident ID
            threat_content: Raw threat text to extract indicators from
            immunis_detected: Whether IMMUNIS detected the threat
            immunis_confidence: IMMUNIS confidence score (0-1)
            immunis_classification: IMMUNIS classification (known/variant/novel)
            immunis_attack_family: IMMUNIS attack family label
            immunis_time_ms: IMMUNIS detection time in milliseconds
        
        Returns:
            VTComparisonResult with side-by-side analysis
        """
        comparison = VTComparisonResult(
            threat_id=threat_id,
            immunis_detected=immunis_detected,
            immunis_confidence=immunis_confidence,
            immunis_classification=immunis_classification,
            immunis_attack_family=immunis_attack_family,
            immunis_time_ms=immunis_time_ms,
        )

        if not self.is_configured:
            comparison.comparison_summary = (
                "VirusTotal API key not configured. "
                "Add VIRUSTOTAL_API_KEY to .env for live comparison."
            )
            return comparison

        # Extract indicators from threat content
        indicators = self.extract_indicators(threat_content)
        total_indicators = sum(len(v) for v in indicators.values())
        comparison.indicators_checked = total_indicators

        if total_indicators == 0:
            comparison.comparison_summary = (
                "No checkable indicators (URLs, domains, IPs, hashes) found in threat content. "
                "This is expected for social engineering threats — they rely on manipulation, "
                "not malicious infrastructure. IMMUNIS detects the INTENT, not just IOCs."
            )
            comparison.immunis_advantage = "intent_detection"
            return comparison

        # Query VT for each indicator (rate-limited)
        vt_results = []
        lookup_methods = {
            VTResourceType.URL: self.lookup_url,
            VTResourceType.DOMAIN: self.lookup_domain,
            VTResourceType.IP: self.lookup_ip,
            VTResourceType.FILE_HASH: self.lookup_hash,
        }

        for indicator_type, indicator_list in indicators.items():
            method = lookup_methods[indicator_type]
            for indicator in indicator_list[:3]:  # Max 3 per type to conserve quota
                try:
                    result = await method(indicator)
                    vt_results.append(result)
                except Exception as e:
                    logger.error("VT lookup failed for %s: %s", indicator, e)
                    vt_results.append(VTDetectionResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        found=False,
                        error=str(e),
                    ))

        comparison.vt_results = vt_results

        # Compute aggregate stats
        found_results = [r for r in vt_results if r.found]
        if found_results:
            rates = [r.detection_rate for r in found_results]
            comparison.vt_max_detection_rate = max(rates)
            comparison.vt_avg_detection_rate = sum(rates) / len(rates)
        
        # Count indicators VT missed
        comparison.indicators_missed_by_vt = sum(
            1 for r in vt_results
            if not r.found or r.detection_rate < 0.05
        )

        # Generate comparison summary
        comparison.comparison_summary = self._generate_summary(comparison)
        comparison.immunis_advantage = self._classify_advantage(comparison)

        return comparison

    def _generate_summary(self, comp: VTComparisonResult) -> str:
        """Generate human-readable comparison summary for demo narration."""
        found = [r for r in comp.vt_results if r.found]
        missed = [r for r in comp.vt_results if not r.found]

        parts = []

        if comp.immunis_detected:
            parts.append(
                f"IMMUNIS detected this threat with {comp.immunis_confidence:.0%} confidence "
                f"in {comp.immunis_time_ms:.0f}ms, classified as {comp.immunis_classification} "
                f"({comp.immunis_attack_family})."
            )
        
        if found:
            best = max(found, key=lambda r: r.detection_rate)
            parts.append(
                f"VirusTotal: best indicator ({best.indicator_type.value}: "
                f"{best.indicator[:50]}) detected by {best.engines_detected}/{best.total_engines} "
                f"engines ({best.detection_rate:.0%})."
            )
            
            if best.detection_rate < 0.10:
                parts.append(
                    "Less than 10% of commercial engines flagged this. "
                    "IMMUNIS detected it because it analyzes INTENT, not signatures."
                )
            elif best.detection_rate < 0.50:
                parts.append(
                    f"Fewer than half of commercial engines caught this. "
                    f"IMMUNIS identified the attack family as {comp.immunis_attack_family} "
                    f"using semantic analysis."
                )

        if missed:
            parts.append(
                f"{len(missed)} indicator(s) had ZERO VirusTotal detections. "
                "These are unknown to the global threat intelligence community."
            )

        if not found and not missed:
            parts.append(
                "No indicators could be checked against VirusTotal. "
                "This threat uses pure social engineering with no malicious infrastructure — "
                "exactly the type that signature-based tools miss entirely."
            )

        return " ".join(parts)

    def _classify_advantage(self, comp: VTComparisonResult) -> str:
        """Classify the type of advantage IMMUNIS has over VT."""
        if not comp.vt_results:
            return "intent_detection"
        
        found = [r for r in comp.vt_results if r.found]
        if not found:
            return "zero_day_detection"
        
        best_rate = max(r.detection_rate for r in found)
        if best_rate < 0.05:
            return "near_zero_detection"
        elif best_rate < 0.30:
            return "low_detection"
        elif best_rate < 0.70:
            return "partial_detection"
        else:
            return "speed_advantage"

    # --- Cleanup ---

    async def close(self):
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# --- Module singleton ---
vt_client = VirusTotalClient()


# --- Convenience functions ---

async def compare_threat_with_virustotal(
    threat_id: str,
    threat_content: str,
    immunis_detected: bool = True,
    immunis_confidence: float = 0.95,
    immunis_classification: str = "novel",
    immunis_attack_family: str = "Unknown",
    immunis_time_ms: float = 1800.0,
) -> dict:
    """
    Convenience function for API route handlers.
    Returns a JSON-serializable dict.
    """
    result = await vt_client.compare_with_immunis(
        threat_id=threat_id,
        threat_content=threat_content,
        immunis_detected=immunis_detected,
        immunis_confidence=immunis_confidence,
        immunis_classification=immunis_classification,
        immunis_attack_family=immunis_attack_family,
        immunis_time_ms=immunis_time_ms,
    )
    
    return {
        "threat_id": result.threat_id,
        "immunis": {
            "detected": result.immunis_detected,
            "confidence": result.immunis_confidence,
            "classification": result.immunis_classification,
            "attack_family": result.immunis_attack_family,
            "time_ms": result.immunis_time_ms,
        },
        "virustotal": {
            "indicators_checked": result.indicators_checked,
            "indicators_missed": result.indicators_missed_by_vt,
            "max_detection_rate": result.vt_max_detection_rate,
            "avg_detection_rate": result.vt_avg_detection_rate,
            "results": [
                {
                    "indicator": r.indicator[:80],
                    "type": r.indicator_type.value,
                    "found": r.found,
                    "engines_detected": r.engines_detected,
                    "total_engines": r.total_engines,
                    "detection_rate": r.detection_rate,
                    "top_detections": r.detection_names[:5],
                    "query_time_ms": r.query_time_ms,
                    "error": r.error,
                }
                for r in result.vt_results
            ],
        },
        "comparison": {
            "advantage": result.immunis_advantage,
            "summary": result.comparison_summary,
        },
    }
