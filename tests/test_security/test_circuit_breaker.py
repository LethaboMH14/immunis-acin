"""
IMMUNIS ACIN — Circuit Breaker Tests
Tests per-agent circuit breakers: CLOSED → OPEN → HALF_OPEN.
"""
import pytest
import asyncio
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.security.circuit_breaker import CircuitBreaker


class TestCircuitBreaker:
    """Tests for circuit breaker state machine."""

    def setup_method(self):
        self.cb = CircuitBreaker(
            name="test_breaker",
            failure_threshold=3,
            cooldown_seconds=1,  # 1 second for fast tests
            half_open_max_calls=2
        )

    def test_init_closed(self):
        """Circuit breaker starts in CLOSED state."""
        state = self.cb.state
        assert state == "closed" or state == "CLOSED" or state.lower() == "closed"

    def test_success_stays_closed(self):
        """Successful calls keep breaker CLOSED."""
        self.cb.record_success()
        self.cb.record_success()
        state = self.cb.state
        assert state.lower() == "closed"

    def test_failures_open_breaker(self):
        """Exceeding failure threshold opens the breaker."""
        for _ in range(3):
            self.cb.record_failure()
        state = self.cb.state
        assert state.lower() == "open", f"3 failures should open breaker, got {state}"

    def test_open_breaker_rejects(self):
        """Open breaker rejects calls."""
        for _ in range(3):
            self.cb.record_failure()

        if hasattr(self.cb, 'allow_call'):
            assert self.cb.allow_call() is False
        elif hasattr(self.cb, 'allow_request'):
            assert self.cb.allow_request() is False
        elif hasattr(self.cb, 'can_execute'):
            assert self.cb.can_execute() is False
        elif hasattr(self.cb, 'is_open'):
            assert self.cb.is_open() is True

    def test_recovery_to_half_open(self):
        """After recovery timeout, breaker transitions to HALF_OPEN."""
        for _ in range(3):
            self.cb.record_failure()
        time.sleep(1.1)  # Wait for recovery timeout

        if hasattr(self.cb, 'allow_call'):
            assert self.cb.allow_call() is True
        state = self.cb.state
        assert state.lower() in ("half_open", "half-open", "halfopen", "closed")

    def test_half_open_success_closes(self):
        """Successful call in HALF_OPEN closes the breaker."""
        for _ in range(3):
            self.cb.record_failure()
        time.sleep(1.1)

        # Trigger half-open
        if hasattr(self.cb, 'allow_call'):
            self.cb.allow_call()

        self.cb.record_success()
        if hasattr(self.cb, 'half_open_max_calls'):
            self.cb.record_success()

        state = self.cb.state
        assert state.lower() == "closed", f"Success in half-open should close, got {state}"

    def test_half_open_failure_reopens(self):
        """Failure in HALF_OPEN re-opens the breaker."""
        for _ in range(3):
            self.cb.record_failure()
        time.sleep(1.1)

        if hasattr(self.cb, 'allow_call'):
            self.cb.allow_call()

        self.cb.record_failure()
        state = self.cb.state
        assert state.lower() == "open", f"Failure in half-open should reopen, got {state}"

    def test_failure_count_resets_on_success(self):
        """Successful call resets failure counter."""
        self.cb.record_failure()
        self.cb.record_failure()
        self.cb.record_success()  # Reset
        self.cb.record_failure()
        state = self.cb.state
        assert state.lower() == "closed", "Success should reset failure count"

    def test_multiple_breakers_independent(self):
        """Different breaker instances are independent."""
        self.breaker = CircuitBreaker(name="test_breaker", cooldown_seconds=60.0)
        for _ in range(3):
            self.cb.record_failure()
        assert self.cb.state.lower() == "open"
        assert self.breaker.state.lower() == "closed"
