"""
IMMUNIS ACIN — Token Bucket Rate Limiter

Prevents any single source from overwhelming the pipeline.

Algorithm: Token Bucket
    - Each source gets a bucket with max_tokens capacity
    - Tokens are added at refill_rate per second
    - Each request consumes one token
    - If bucket is empty, request is rejected

Why token bucket over sliding window:
    - Allows bursts (a legitimate SOC analyst might submit 5 threats quickly)
    - Smooth rate limiting (no cliff edges at window boundaries)
    - O(1) per check (no need to store timestamps of all recent requests)
    - Memory efficient (one bucket per source, not one timestamp per request)

Temperature: 0.3 (infrastructure code)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("immunis.rate_limiter")


@dataclass
class TokenBucket:
    """
    Token bucket for a single source.
    
    Tokens accumulate at refill_rate per second, up to max_tokens.
    Each request consumes one token. Empty bucket = rate limited.
    """
    source_id: str
    max_tokens: float = 10.0        # Maximum burst capacity
    refill_rate: float = 0.5         # Tokens per second (0.5 = 1 token every 2 seconds)
    tokens: float = field(default=10.0)
    last_refill: float = field(default_factory=time.monotonic)
    total_allowed: int = field(default=0)
    total_rejected: int = field(default=0)

    def _refill(self) -> None:
        """Add tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def allow(self) -> bool:
        """
        Check if a request should be allowed.
        Consumes one token if allowed.
        """
        self._refill()

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            self.total_allowed += 1
            return True
        else:
            self.total_rejected += 1
            logger.warning(
                f"Rate limited: {self.source_id}",
                extra={
                    "source": self.source_id,
                    "tokens_remaining": round(self.tokens, 2),
                    "total_rejected": self.total_rejected,
                },
            )
            return False

    def get_status(self) -> dict:
        """Current bucket status for monitoring."""
        self._refill()
        return {
            "source_id": self.source_id,
            "tokens_remaining": round(self.tokens, 2),
            "max_tokens": self.max_tokens,
            "refill_rate": self.refill_rate,
            "total_allowed": self.total_allowed,
            "total_rejected": self.total_rejected,
            "rejection_rate": round(
                self.total_rejected / max(1, self.total_allowed + self.total_rejected), 4
            ),
        }


class RateLimiter:
    """
    Rate limiter managing multiple token buckets.
    
    Each unique source (IP address, node ID, API key) gets its own bucket.
    Buckets are created on first request and cleaned up periodically.
    
    Usage:
        limiter = get_rate_limiter()
        
        if not limiter.allow("192.168.1.1"):
            raise RateLimitError("Too many requests")
    """

    def __init__(
        self,
        default_max_tokens: float = 10.0,
        default_refill_rate: float = 0.5,
        max_buckets: int = 10_000,
        cleanup_interval_seconds: float = 300.0,
    ):
        """
        Args:
            default_max_tokens: Default burst capacity per source
            default_refill_rate: Default tokens per second per source
            max_buckets: Maximum number of tracked sources (memory limit)
            cleanup_interval_seconds: How often to remove stale buckets
        """
        self.default_max_tokens = default_max_tokens
        self.default_refill_rate = default_refill_rate
        self.max_buckets = max_buckets
        self.cleanup_interval = cleanup_interval_seconds

        self._buckets: dict[str, TokenBucket] = {}
        self._last_cleanup: float = time.monotonic()

    def allow(
        self,
        source_id: str,
        max_tokens: Optional[float] = None,
        refill_rate: Optional[float] = None,
    ) -> bool:
        """
        Check if a request from this source should be allowed.
        
        Args:
            source_id: Unique identifier for the source (IP, node ID, API key)
            max_tokens: Override default burst capacity for this source
            refill_rate: Override default refill rate for this source
        
        Returns:
            True if allowed, False if rate limited
        """
        # Periodic cleanup of stale buckets
        self._maybe_cleanup()

        # Get or create bucket
        if source_id not in self._buckets:
            if len(self._buckets) >= self.max_buckets:
                # Evict oldest bucket to prevent memory exhaustion
                self._evict_oldest()

            self._buckets[source_id] = TokenBucket(
                source_id=source_id,
                max_tokens=max_tokens or self.default_max_tokens,
                refill_rate=refill_rate or self.default_refill_rate,
            )

        return self._buckets[source_id].allow()

    def _maybe_cleanup(self) -> None:
        """Remove stale buckets that haven't been used recently."""
        now = time.monotonic()
        if now - self._last_cleanup < self.cleanup_interval:
            return

        self._last_cleanup = now
        stale_threshold = now - self.cleanup_interval * 2

        stale_keys = [
            key for key, bucket in self._buckets.items()
            if bucket.last_refill < stale_threshold
        ]

        for key in stale_keys:
            del self._buckets[key]

        if stale_keys:
            logger.debug(f"Cleaned up {len(stale_keys)} stale rate limit buckets")

    def _evict_oldest(self) -> None:
        """Evict the least recently used bucket."""
        if not self._buckets:
            return

        oldest_key = min(
            self._buckets.keys(),
            key=lambda k: self._buckets[k].last_refill,
        )
        del self._buckets[oldest_key]

    def get_status(self, source_id: str) -> Optional[dict]:
        """Get rate limit status for a specific source."""
        bucket = self._buckets.get(source_id)
        if bucket:
            return bucket.get_status()
        return None

    def get_all_status(self) -> list[dict]:
        """Get status of all active buckets."""
        return [bucket.get_status() for bucket in self._buckets.values()]

    def get_limited_sources(self) -> list[str]:
        """Get source IDs that are currently rate limited (empty buckets)."""
        limited = []
        for source_id, bucket in self._buckets.items():
            bucket._refill()
            if bucket.tokens < 1.0:
                limited.append(source_id)
        return limited

    def reset(self, source_id: str) -> bool:
        """Reset rate limit for a specific source. Returns True if source existed."""
        if source_id in self._buckets:
            self._buckets[source_id].tokens = self._buckets[source_id].max_tokens
            self._buckets[source_id].total_rejected = 0
            return True
        return False

    def reset_all(self) -> None:
        """Reset all rate limits."""
        self._buckets.clear()

    @property
    def active_sources(self) -> int:
        """Number of currently tracked sources."""
        return len(self._buckets)

    @property
    def total_rejections(self) -> int:
        """Total rejections across all sources."""
        return sum(b.total_rejected for b in self._buckets.values())


# ============================================================================
# PRESET CONFIGURATIONS
# ============================================================================

# Different rate limits for different contexts
RATE_LIMIT_PRESETS = {
    "api_threat_submission": {
        "max_tokens": 10.0,      # Allow burst of 10 threats
        "refill_rate": 0.5,      # Then 1 every 2 seconds (30/minute sustained)
    },
    "api_general": {
        "max_tokens": 30.0,      # Higher burst for general API calls
        "refill_rate": 2.0,      # 120/minute sustained
    },
    "mesh_broadcast": {
        "max_tokens": 5.0,       # Lower burst for mesh broadcasts
        "refill_rate": 0.2,      # 12/minute sustained (antibodies don't arrive that fast)
    },
    "red_agent": {
        "max_tokens": 20.0,      # Red Agent generates variants in bursts
        "refill_rate": 1.0,      # 60/minute sustained
    },
    "copilot_chat": {
        "max_tokens": 5.0,       # Prevent chat abuse
        "refill_rate": 0.33,     # ~20/minute sustained
    },
    "vulnerability_scan": {
        "max_tokens": 3.0,       # Scans are expensive
        "refill_rate": 0.05,     # 3/minute sustained
    },
}


# ============================================================================
# GLOBAL SINGLETON
# ============================================================================

_limiters: dict[str, RateLimiter] = {}


def get_rate_limiter(context: str = "api_general") -> RateLimiter:
    """
    Get or create a rate limiter for a specific context.
    
    Usage:
        from backend.security.rate_limiter import get_rate_limiter
        
        limiter = get_rate_limiter("api_threat_submission")
        if not limiter.allow(request.client.host):
            raise HTTPException(429, "Rate limited")
    """
    if context not in _limiters:
        preset = RATE_LIMIT_PRESETS.get(context, RATE_LIMIT_PRESETS["api_general"])
        _limiters[context] = RateLimiter(
            default_max_tokens=preset["max_tokens"],
            default_refill_rate=preset["refill_rate"],
        )
    return _limiters[context]


class RateLimitError(Exception):
    """Raised when a request is rate limited."""
    def __init__(self, source_id: str, context: str = ""):
        self.source_id = source_id
        self.context = context
        super().__init__(f"Rate limited: {source_id} ({context})")
