"""
PhishTank + OpenPhish Integration — Live Threat Feed

Pulls REAL, currently-active phishing URLs from two independent sources:
1. PhishTank (community-verified phishing database, ~75K active URLs)
2. OpenPhish (automated phishing intelligence, updated every 5 minutes)

Used during demos to feed IMMUNIS with real threats that are active
on the internet RIGHT NOW. Proves the system works on real-world data,
not just synthetic samples.

References:
- PhishTank Developer API: https://phishtank.org/developer_info.php
- OpenPhish Community Feed: https://openphish.com/feed.txt
- APWG Phishing Trends Report Q4 2024

WHY THIS EXISTS:
- Every other hackathon team uses synthetic data only
- We feed REAL active phishing URLs into IMMUNIS during the demo
- Judges hear: "This URL is live right now, targeting real people"
- Proves IMMUNIS works on threats the internet hasn't caught yet
"""

import asyncio
import csv
import io
import json
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx

from backend.config import settings

logger = logging.getLogger("immunis.phishtank")

# --- Constants ---

PHISHTANK_API_URL = "http://data.phishtank.com/data/online-valid.json"
PHISHTANK_CHECK_URL = "https://checkurl.phishtank.com/checkurl/"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

FEED_CACHE_TTL = 300  # 5 minutes — matches OpenPhish update interval
MAX_CACHED_URLS = 500  # Keep last 500 for random sampling
REQUEST_TIMEOUT = 30


@dataclass
class LivePhish:
    """A real, currently-active phishing URL from public threat feeds."""
    url: str
    source: str  # "phishtank", "openphish", "urlhaus"
    target_brand: Optional[str] = None
    discovered_at: Optional[str] = None
    verified: bool = False
    phish_id: Optional[str] = None
    country: Optional[str] = None
    ip_address: Optional[str] = None
    asn: Optional[str] = None
    threat_type: Optional[str] = None  # "phishing", "malware", "defacement"
    tags: list[str] = field(default_factory=list)

    def to_immunis_threat(self) -> dict:
        """
        Convert to IMMUNIS threat submission format.
        
        This formats the live phishing URL as a threat that can be
        submitted to POST /api/threats for real-time analysis.
        """
        brand_info = f" targeting {self.target_brand}" if self.target_brand else ""
        source_info = f"[Verified by {self.source}]" if self.verified else f"[Source: {self.source}]"
        
        return {
            "content": (
                f"LIVE PHISHING THREAT {source_info}\n\n"
                f"Active phishing URL detected{brand_info}:\n"
                f"{self.url}\n\n"
                f"This URL is currently LIVE on the internet and actively "
                f"targeting victims. Discovered: {self.discovered_at or 'within last 5 minutes'}.\n\n"
                f"Source: {self.source} threat intelligence feed\n"
                f"Verified: {'Yes — community verified' if self.verified else 'Automated detection'}\n"
                f"{'Country: ' + self.country if self.country else ''}\n"
                f"{'IP: ' + self.ip_address if self.ip_address else ''}\n"
                f"{'ASN: ' + self.asn if self.asn else ''}\n"
                f"{'Tags: ' + ', '.join(self.tags) if self.tags else ''}"
            ),
            "source": "threat_feed",
            "metadata": {
                "feed_source": self.source,
                "live_url": self.url,
                "target_brand": self.target_brand,
                "verified": self.verified,
                "phish_id": self.phish_id,
                "discovered_at": self.discovered_at,
                "is_real_threat": True,
                "demo_note": "This is a REAL active phishing URL, not synthetic data",
            },
        }


class LivePhishFeed:
    """
    Aggregates phishing URLs from multiple free threat intelligence feeds.
    
    Caches results to avoid hammering feeds during demo.
    Provides random sampling for variety across demo runs.
    
    Usage:
        feed = LivePhishFeed()
        threats = await feed.get_live_threats(count=5)
        for threat in threats:
            # Submit to IMMUNIS pipeline
            response = await client.post("/api/threats", json=threat.to_immunis_threat())
    """

    def __init__(self):
        self._cache: list[LivePhish] = []
        self._cache_time: float = 0
        self._client: Optional[httpx.AsyncClient] = None
        self._fetch_lock = asyncio.Lock()

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT,
                follow_redirects=True,
                headers={
                    "User-Agent": "IMMUNIS-ACIN/1.0 (Security Research; https://github.com/immunis-acin)",
                },
            )
        return self._client

    async def _fetch_openphish(self) -> list[LivePhish]:
        """
        Fetch from OpenPhish community feed.
        
        Free, no API key, updated every 5 minutes.
        Returns plain text list of active phishing URLs.
        """
        results = []
        try:
            client = await self._get_client()
            response = await client.get(OPENPHISH_FEED_URL)

            if response.status_code == 200:
                urls = response.text.strip().split("\n")
                now = datetime.now(timezone.utc).isoformat()
                
                for url in urls:
                    url = url.strip()
                    if url and url.startswith("http"):
                        # Try to guess target brand from URL
                        brand = self._guess_brand(url)
                        results.append(LivePhish(
                            url=url,
                            source="openphish",
                            target_brand=brand,
                            discovered_at=now,
                            verified=False,
                            threat_type="phishing",
                        ))

                logger.info("OpenPhish: fetched %d active URLs", len(results))
            else:
                logger.warning("OpenPhish returned status %d", response.status_code)

        except Exception as e:
            logger.error("OpenPhish fetch error: %s", e)

        return results

    async def _fetch_phishtank_sample(self) -> list[LivePhish]:
        """
        Fetch from PhishTank verified phishing database.
        
        The full database is large (~30MB JSON). We fetch it only if
        a PhishTank API key is configured. Otherwise we use the
        check URL endpoint for individual lookups.
        
        PhishTank API key is optional and free to register.
        """
        results = []
        api_key = getattr(settings, 'PHISHTANK_API_KEY', '') or ''

        if not api_key:
            logger.debug("PhishTank API key not configured — skipping bulk fetch")
            return results

        try:
            client = await self._get_client()
            # PhishTank requires app_key parameter
            url = f"{PHISHTANK_API_URL}?app_key={api_key}"
            response = await client.get(url)

            if response.status_code == 200:
                data = response.json()
                # PhishTank returns array of verified phishing entries
                for entry in data[:MAX_CACHED_URLS]:
                    results.append(LivePhish(
                        url=entry.get("url", ""),
                        source="phishtank",
                        target_brand=entry.get("target", ""),
                        discovered_at=entry.get("submission_time", ""),
                        verified=entry.get("verified") == "yes",
                        phish_id=str(entry.get("phish_id", "")),
                        threat_type="phishing",
                    ))

                logger.info("PhishTank: fetched %d verified URLs", len(results))
            else:
                logger.warning("PhishTank returned status %d", response.status_code)

        except Exception as e:
            logger.error("PhishTank fetch error: %s", e)

        return results

    async def _fetch_urlhaus_recent(self) -> list[LivePhish]:
        """
        Fetch from URLhaus recent additions.
        
        Free, no API key. Includes malware distribution URLs.
        Broader than just phishing — shows IMMUNIS handles malware URLs too.
        
        Reference: https://urlhaus-api.abuse.ch/
        """
        results = []
        try:
            client = await self._get_client()
            response = await client.get(URLHAUS_RECENT_URL)

            if response.status_code == 200:
                data = response.json()
                urls = data.get("urls", [])

                for entry in urls[:200]:
                    if entry.get("url_status") != "online":
                        continue

                    tags = entry.get("tags", []) or []
                    if tags is None:
                        tags = []

                    results.append(LivePhish(
                        url=entry.get("url", ""),
                        source="urlhaus",
                        target_brand=None,
                        discovered_at=entry.get("date_added", ""),
                        verified=True,
                        phish_id=str(entry.get("id", "")),
                        country=entry.get("country", ""),
                        threat_type=entry.get("threat", "malware"),
                        tags=tags if isinstance(tags, list) else [tags],
                    ))

                logger.info("URLhaus: fetched %d active URLs", len(results))
            else:
                logger.warning("URLhaus returned status %d", response.status_code)

        except Exception as e:
            logger.error("URLhaus fetch error: %s", e)

        return results

    def _guess_brand(self, url: str) -> Optional[str]:
        """
        Guess the target brand from a phishing URL.
        
        Simple heuristic based on domain keywords.
        Not perfect, but useful for demo narration.
        """
        url_lower = url.lower()
        brands = {
            "paypal": "PayPal",
            "apple": "Apple",
            "microsoft": "Microsoft",
            "google": "Google",
            "amazon": "Amazon",
            "facebook": "Facebook",
            "instagram": "Instagram",
            "whatsapp": "WhatsApp",
            "netflix": "Netflix",
            "linkedin": "LinkedIn",
            "dropbox": "Dropbox",
            "chase": "Chase Bank",
            "wellsfargo": "Wells Fargo",
            "bankofamerica": "Bank of America",
            "citibank": "Citibank",
            "hsbc": "HSBC",
            "barclays": "Barclays",
            "standardbank": "Standard Bank",
            "fnb": "First National Bank",
            "absa": "ABSA",
            "nedbank": "Nedbank",
            "capitec": "Capitec",
            "sars": "SARS (Revenue Service)",
            "dhl": "DHL",
            "fedex": "FedEx",
            "usps": "USPS",
            "office365": "Microsoft 365",
            "outlook": "Microsoft Outlook",
            "icloud": "Apple iCloud",
            "coinbase": "Coinbase",
            "binance": "Binance",
            "crypto": "Cryptocurrency Exchange",
            "steam": "Steam",
            "ebay": "eBay",
            "alibaba": "Alibaba",
            "rakuten": "Rakuten",
            "docusign": "DocuSign",
            "adobe": "Adobe",
            "zoom": "Zoom",
            "slack": "Slack",
        }

        for keyword, brand in brands.items():
            if keyword in url_lower:
                return brand

        return None

    async def refresh_cache(self):
        """Fetch fresh data from all feeds."""
        async with self._fetch_lock:
            now = time.time()
            if now - self._cache_time < FEED_CACHE_TTL and self._cache:
                return  # Cache still fresh

            logger.info("Refreshing live phishing feeds...")

            # Fetch from all sources in parallel
            openphish_task = self._fetch_openphish()
            urlhaus_task = self._fetch_urlhaus_recent()
            phishtank_task = self._fetch_phishtank_sample()

            results = await asyncio.gather(
                openphish_task, urlhaus_task, phishtank_task,
                return_exceptions=True,
            )

            all_urls = []
            for result in results:
                if isinstance(result, list):
                    all_urls.extend(result)
                elif isinstance(result, Exception):
                    logger.error("Feed fetch failed: %s", result)

            # Deduplicate by URL
            seen = set()
            unique = []
            for phish in all_urls:
                if phish.url not in seen:
                    seen.add(phish.url)
                    unique.append(phish)

            # Keep most recent, cap at MAX_CACHED_URLS
            self._cache = unique[:MAX_CACHED_URLS]
            self._cache_time = now
            logger.info("Live feed cache: %d unique active threats", len(self._cache))

    async def get_live_threats(
        self,
        count: int = 5,
        source_filter: Optional[str] = None,
        brand_filter: Optional[str] = None,
        randomize: bool = True,
    ) -> list[LivePhish]:
        """
        Get live phishing threats for demo use.
        
        Args:
            count: Number of threats to return
            source_filter: Filter by source ("openphish", "phishtank", "urlhaus")
            brand_filter: Filter by target brand keyword
            randomize: Shuffle results for variety across demo runs
        
        Returns:
            List of LivePhish objects ready for submission
        """
        await self.refresh_cache()

        pool = self._cache.copy()

        if source_filter:
            pool = [p for p in pool if p.source == source_filter]
        
        if brand_filter:
            brand_lower = brand_filter.lower()
            pool = [p for p in pool if p.target_brand and brand_lower in p.target_brand.lower()]

        if not pool:
            logger.warning("No live threats match filters (source=%s, brand=%s)",
                           source_filter, brand_filter)
            return []

        if randomize:
            random.shuffle(pool)

        return pool[:count]

    async def get_demo_selection(self) -> list[LivePhish]:
        """
        Get a curated selection for the 10-minute demo.
        
        Returns ~5 diverse threats: different sources, different brands,
        different threat types. Optimised for demo narration impact.
        """
        await self.refresh_cache()

        selection = []
        used_sources = set()
        used_brands = set()

        # Priority 1: A verified PhishTank URL targeting a well-known brand
        for p in self._cache:
            if p.source == "phishtank" and p.verified and p.target_brand:
                selection.append(p)
                used_sources.add(p.source)
                used_brands.add(p.target_brand)
                break

        # Priority 2: An OpenPhish URL targeting a different brand
        for p in self._cache:
            if (p.source == "openphish" and p.target_brand 
                    and p.target_brand not in used_brands):
                selection.append(p)
                used_sources.add(p.source)
                used_brands.add(p.target_brand)
                break

        # Priority 3: A URLhaus malware URL
        for p in self._cache:
            if p.source == "urlhaus" and p.threat_type != "phishing":
                selection.append(p)
                used_sources.add(p.source)
                break

        # Priority 4: A financial brand phish (banking)
        bank_keywords = {"bank", "fnb", "absa", "capitec", "standardbank", "chase", "wells", "citi", "hsbc"}
        for p in self._cache:
            if p.target_brand and any(k in p.target_brand.lower() for k in bank_keywords):
                if p.url not in {s.url for s in selection}:
                    selection.append(p)
                    break

        # Priority 5: Fill remaining with random diverse URLs
        remaining = [p for p in self._cache if p.url not in {s.url for s in selection}]
        random.shuffle(remaining)
        while len(selection) < 5 and remaining:
            selection.append(remaining.pop())

        return selection

    async def get_feed_stats(self) -> dict:
        """Get statistics about the current feed cache."""
        await self.refresh_cache()

        sources = {}
        brands = {}
        threat_types = {}

        for p in self._cache:
            sources[p.source] = sources.get(p.source, 0) + 1
            if p.target_brand:
                brands[p.target_brand] = brands.get(p.target_brand, 0) + 1
            if p.threat_type:
                threat_types[p.threat_type] = threat_types.get(p.threat_type, 0) + 1

        # Sort brands by frequency
        top_brands = sorted(brands.items(), key=lambda x: -x[1])[:15]

        return {
            "total_active_threats": len(self._cache),
            "sources": sources,
            "top_targeted_brands": dict(top_brands),
            "threat_types": threat_types,
            "cache_age_seconds": time.time() - self._cache_time if self._cache_time else None,
            "last_refresh": datetime.fromtimestamp(self._cache_time, tz=timezone.utc).isoformat() if self._cache_time else None,
        }

    async def close(self):
        """Close HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# --- Module singleton ---
live_feed = LivePhishFeed()


# --- Convenience functions ---

async def get_live_threats_for_demo(count: int = 5) -> list[dict]:
    """Get live threats formatted for IMMUNIS submission."""
    threats = await live_feed.get_live_threats(count=count)
    return [t.to_immunis_threat() for t in threats]


async def get_demo_selection() -> list[dict]:
    """Get curated demo selection formatted for IMMUNIS submission."""
    threats = await live_feed.get_demo_selection()
    return [
        {
            "phish": {
                "url": t.url,
                "source": t.source,
                "brand": t.target_brand,
                "verified": t.verified,
                "threat_type": t.threat_type,
                "discovered": t.discovered_at,
            },
            "immunis_submission": t.to_immunis_threat(),
        }
        for t in threats
    ]
