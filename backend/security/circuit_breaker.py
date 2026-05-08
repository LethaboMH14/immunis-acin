"""
IMMUNIS ACIN — Circuit Breaker

Per-agent circuit breaker that prevents cascading failures.

When an agent (or the AI provider it calls) starts failing repeatedly,
the circuit breaker OPENS — all subsequent calls fail immediately without
attempting the call. After a cooldown period, the circuit enters HALF-OPEN
state and allows one test call. If it succeeds, the circuit CLOSES (normal).
If it fails, the circuit OPENS again.

This prevents:
1. A failing LLM API from consuming all retry budget across the pipeline
2. Timeout accumulation (7 agents × 30s timeout = 3.5 minutes of waiting)
3. Cascading failures where one agent's failure corrupts downstream agents

State machine:
    CLOSED → (failure_count >= threshold) → OPEN
    OPEN → (cooldown_elapsed) → HALF_OPEN
    HALF_OPEN → (test_call_succeeds) → CLOSED
    HALF_OPEN → (test_call_fails) → OPEN

Research basis:
    - Nygard (2007), "Release It!" — Circuit Breaker pattern
    - Netflix Hystrix (2012) — Production circuit breaker implementation

Temperature: 0.3 (infrastructure code, must be precise)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("immunis.circuit_breaker")


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"       # Normal operation — calls pass through
    OPEN = "open"           # Failing — calls rejected immediately
    HALF_OPEN = "half_open" # Testing — one call allowed through


@dataclass
class CircuitBreaker:
    """
    Circuit breaker for a single agent or service.
    
    Usage:
        breaker = CircuitBreaker(name="incident_analyst")
        
        if not breaker.allow_call():
            return fallback_result()
        
        try:
            result = await agent_call()
            breaker.record_success()
            return result
        except Exception as e:
            breaker.record_failure()
            raise
    """
    name: str
    failure_threshold: int = 3          # Failures before opening
    cooldown_seconds: float = 60.0      # How long to stay open
    half_open_max_calls: int = 1        # Calls allowed in half-open state

    # Internal state
    state: CircuitState = field(default=CircuitState.CLOSED)
    failure_count: int = field(default=0)
    success_count: int = field(default=0)
    last_failure_time: float = field(default=0.0)
    last_state_change: float = field(default_factory=time.monotonic)
    total_calls: int = field(default=0)
    total_failures: int = field(default=0)
    total_rejections: int = field(default=0)
    half_open_calls: int = field(default=0)

    def allow_call(self) -> bool:
        """
        Check if a call should be allowed through.
        
        Returns True if the call should proceed.
        Returns False if the circuit is open (call should be rejected).
        """
        self.total_calls += 1

        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            # Check if cooldown has elapsed
            elapsed = time.monotonic() - self.last_failure_time
            if elapsed >= self.cooldown_seconds:
                # Transition to half-open
                self._transition(CircuitState.HALF_OPEN)
                self.half_open_calls = 0
                return True
            else:
                # Still in cooldown — reject
                self.total_rejections += 1
                remaining = self.cooldown_seconds - elapsed
                logger.debug(
                    f"Circuit OPEN for {self.name} — rejecting call "
                    f"({remaining:.1f}s remaining in cooldown)"
                )
                return False

        if self.state == CircuitState.HALF_OPEN:
            if self.half_open_calls < self.half_open_max_calls:
                self.half_open_calls += 1
                return True
            else:
                # Already used our test call — reject until it resolves
                self.total_rejections += 1
                return False

        return False  # Should never reach here

    def record_success(self) -> None:
        """Record a successful call. May close the circuit."""
        self.success_count += 1

        if self.state == CircuitState.HALF_OPEN:
            # Test call succeeded — close the circuit
            self._transition(CircuitState.CLOSED)
            self.failure_count = 0
            logger.info(f"Circuit CLOSED for {self.name} — recovered from failures")

        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success (consecutive failures model)
            self.failure_count = 0

    def record_failure(self) -> None:
        """Record a failed call. May open the circuit."""
        self.failure_count += 1
        self.total_failures += 1
        self.last_failure_time = time.monotonic()

        if self.state == CircuitState.HALF_OPEN:
            # Test call failed — back to open
            self._transition(CircuitState.OPEN)
            logger.warning(
                f"Circuit OPEN for {self.name} — half-open test failed "
                f"(cooldown: {self.cooldown_seconds}s)"
            )

        elif self.state == CircuitState.CLOSED:
            if self.failure_count >= self.failure_threshold:
                self._transition(CircuitState.OPEN)
                logger.warning(
                    f"Circuit OPEN for {self.name} — "
                    f"{self.failure_count} consecutive failures "
                    f"(threshold: {self.failure_threshold}, cooldown: {self.cooldown_seconds}s)"
                )

    def _transition(self, new_state: CircuitState) -> None:
        """Transition to a new state with logging."""
        old_state = self.state
        self.state = new_state
        self.last_state_change = time.monotonic()

        logger.info(
            f"Circuit breaker {self.name}: {old_state.value} → {new_state.value}",
            extra={
                "breaker": self.name,
                "old_state": old_state.value,
                "new_state": new_state.value,
                "failure_count": self.failure_count,
                "total_failures": self.total_failures,
                "total_rejections": self.total_rejections,
            },
        )

    def reset(self) -> None:
        """Manually reset the circuit breaker to closed state."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.half_open_calls = 0
        self.last_state_change = time.monotonic()
        logger.info(f"Circuit breaker {self.name} manually reset to CLOSED")

    def get_status(self) -> dict:
        """Get current status for dashboard display."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "failure_threshold": self.failure_threshold,
            "total_calls": self.total_calls,
            "total_failures": self.total_failures,
            "total_rejections": self.total_rejections,
            "cooldown_seconds": self.cooldown_seconds,
            "time_in_current_state": round(
                time.monotonic() - self.last_state_change, 1
            ),
        }


# ============================================================================
# CIRCUIT BREAKER REGISTRY — One breaker per agent/service
# ============================================================================

class CircuitBreakerRegistry:
    """
    Registry of all circuit breakers in the system.
    
    Each agent and external service gets its own breaker.
    The registry provides a single point of monitoring for
    the dashboard and health checks.
    """

    def __init__(self):
        self._breakers: dict[str, CircuitBreaker] = {}

    def get_or_create(
        self,
        name: str,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
    ) -> CircuitBreaker:
        """Get existing breaker or create a new one."""
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(
                name=name,
                failure_threshold=failure_threshold,
                cooldown_seconds=cooldown_seconds,
            )
        return self._breakers[name]

    def get_all_status(self) -> list[dict]:
        """Get status of all breakers for dashboard display."""
        return [b.get_status() for b in self._breakers.values()]

    def get_open_breakers(self) -> list[str]:
        """Get names of all currently open breakers."""
        return [
            name for name, breaker in self._breakers.items()
            if breaker.state == CircuitState.OPEN
        ]

    def reset_all(self) -> None:
        """Reset all breakers to closed state."""
        for breaker in self._breakers.values():
            breaker.reset()

    @property
    def any_open(self) -> bool:
        """Whether any circuit breaker is currently open."""
        return any(
            b.state == CircuitState.OPEN
            for b in self._breakers.values()
        )


# ============================================================================
# GLOBAL REGISTRY SINGLETON
# ============================================================================

_registry: Optional[CircuitBreakerRegistry] = None


def get_circuit_registry() -> CircuitBreakerRegistry:
    """Get or create the global circuit breaker registry."""
    global _registry
    if _registry is None:
        _registry = CircuitBreakerRegistry()
    return _registry


def get_breaker(
    name: str,
    failure_threshold: int = 3,
    cooldown_seconds: float = 60.0,
) -> CircuitBreaker:
    """
    Convenience function to get a circuit breaker by name.
    
    Usage:
        from backend.security.circuit_breaker import get_breaker
        
        breaker = get_breaker("incident_analyst")
        if not breaker.allow_call():
            return fallback_result()
    """
    return get_circuit_registry().get_or_create(
        name=name,
        failure_threshold=failure_threshold,
        cooldown_seconds=cooldown_seconds,
    )
