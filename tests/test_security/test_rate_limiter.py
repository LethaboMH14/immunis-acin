"""
IMMUNIS ACIN — Rate Limiter Tests
Tests token bucket rate limiting.
"""
import pytest
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.security.rate_limiter import RateLimiter


class TestRateLimiter:
    """Tests for token bucket rate limiting."""

    def setup_method(self):
        self.limiter = RateLimiter(
            default_max_tokens=10,
            default_refill_rate=2.0  # 2 tokens per second
        )

    def test_init_full_bucket(self):
        """Bucket starts full."""
        assert self.limiter.allow("test_source") is True

    def test_consume_tokens(self):
        """Consuming tokens reduces availability."""
        for _ in range(10):
            assert self.limiter.allow("test_source") is True
        # Bucket should be empty now
        assert self.limiter.allow("test_source") is False

    def test_refill_over_time(self):
        """Tokens refill over time."""
        # Drain bucket
        for _ in range(10):
            self.limiter.allow("test_source")
        # Wait for refill
        time.sleep(1.1)
        # Should have ~2 tokens now
        assert self.limiter.allow("test_source") is True

    def test_burst_capacity(self):
        """Full bucket allows burst up to max_tokens."""
        count = 0
        for _ in range(20):
            if self.limiter.allow("test_source"):
                count += 1
        assert count == 10, f"Burst should be max_tokens=10, got {count}"

    def test_steady_state_rate(self):
        """Sustained rate should match refill_rate."""
        # Drain bucket
        for _ in range(10):
            self.limiter.allow("test_source")

        # Now measure sustained rate over 2 seconds
        time.sleep(2.0)
        count = 0
        for _ in range(10):
            if self.limiter.allow("test_source"):
                count += 1
        # Should have ~4 tokens (2/sec × 2 sec)
        assert 3 <= count <= 5, f"Expected ~4 tokens after 2s, got {count}"

    def test_never_exceeds_max(self):
        """Bucket never holds more than max_tokens even after long wait."""
        time.sleep(10)  # Way more than needed to fill
        count = 0
        for _ in range(20):
            if self.limiter.allow("test_source"):
                count += 1
        assert count == 10, f"Should cap at max_tokens=10, got {count}"

    def test_multiple_limiters_independent(self):
        """Different limiter instances are independent."""
        self.limiter = RateLimiter(default_max_tokens=10.0, default_refill_rate=0.5)
        # Drain first
        for _ in range(10):
            self.limiter.allow("test_source1")
        # Second should still be full
        limiter2 = RateLimiter(default_max_tokens=5, default_refill_rate=1.0)
        assert limiter2.allow("test_source2") is True

    def test_zero_tokens_denied(self):
        """Empty bucket denies immediately."""
        # Drain
        for _ in range(10):
            self.limiter.allow("test_source")
        assert self.limiter.allow("test_source") is False
        assert self.limiter.allow("test_source") is False
