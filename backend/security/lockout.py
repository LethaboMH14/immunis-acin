"""
IMMUNIS ACIN — Emergency Lockout System

WHY: A compromised AI system is more dangerous than a disabled one.
If IMMUNIS itself is compromised — adversarial model poisoning,
prompt injection that bypasses sanitisation, or a rogue agent —
the system must be killable in under 5 seconds via a deterministic
5-step sequence that cannot be bypassed by software.

Operational Security mandate from IMMUNIS_ACIN.md Section 7:
- Emergency lockout: 5-step sequence in <5 seconds
- Two-person rule: hardware key + peer approval for autonomous operations
- Dead man's switch: auto-lockout after 24h without check-in

Lockout levels:
  LEVEL 1 — PAUSE: Stop processing new threats, finish in-flight
  LEVEL 2 — ISOLATE: Disconnect mesh, stop all agents
  LEVEL 3 — QUARANTINE: Freeze antibody library, revoke mesh keys
  LEVEL 4 — SHUTDOWN: Stop all services, seal audit trail
  LEVEL 5 — SCORCHED EARTH: Wipe runtime state, preserve only audit trail

The 5-step sequence:
  1. Operator initiates lockout (API call or hardware button)
  2. System validates operator identity (JWT + optional hardware key)
  3. Peer confirms (second operator approval within 30s)
  4. System executes lockout at specified level
  5. Audit trail sealed with Merkle root and timestamp

Dead man's switch:
  If no check-in received within 24 hours, system auto-escalates
  to LEVEL 2 (ISOLATE). This prevents a compromised system from
  running indefinitely without human oversight.
"""

import logging
import time
import hashlib
import hmac
import secrets
import asyncio
from typing import Optional, Callable, Awaitable
from datetime import datetime, timezone, timedelta
from enum import IntEnum

from backend.models.enums import SystemStatus

logger = logging.getLogger("immunis.security.lockout")


class LockoutLevel(IntEnum):
    """Lockout severity levels — higher is more severe."""
    NORMAL = 0
    PAUSE = 1
    ISOLATE = 2
    QUARANTINE = 3
    SHUTDOWN = 4
    SCORCHED_EARTH = 5


class LockoutEvent:
    """Record of a lockout state change."""

    def __init__(
        self,
        level: LockoutLevel,
        initiated_by: str,
        confirmed_by: Optional[str],
        reason: str,
        timestamp: Optional[datetime] = None,
    ):
        self.level = level
        self.initiated_by = initiated_by
        self.confirmed_by = confirmed_by
        self.reason = reason
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.event_id = hashlib.sha256(
            f"{self.timestamp.isoformat()}:{level}:{initiated_by}:{reason}".encode()
        ).hexdigest()[:16]


class EmergencyLockout:
    """
    Emergency lockout system with 5-level severity,
    two-person rule, and dead man's switch.

    Usage:
        lockout = EmergencyLockout()

        # Register shutdown hooks
        lockout.register_hook(LockoutLevel.PAUSE, pause_pipeline)
        lockout.register_hook(LockoutLevel.ISOLATE, disconnect_mesh)

        # Initiate lockout
        token = lockout.initiate(operator_id="op-001", level=LockoutLevel.ISOLATE, reason="Anomaly detected")

        # Peer confirms (within 30s)
        lockout.confirm(token, confirmer_id="op-002")

        # Check-in (dead man's switch)
        lockout.check_in(operator_id="op-001")
    """

    # Two-person rule timeout
    CONFIRMATION_TIMEOUT_S = 30

    # Dead man's switch interval
    DEAD_MAN_INTERVAL_H = 24

    # Levels that require two-person confirmation
    REQUIRES_CONFIRMATION = {
        LockoutLevel.QUARANTINE,
        LockoutLevel.SHUTDOWN,
        LockoutLevel.SCORCHED_EARTH,
    }

    def __init__(self):
        self._current_level: LockoutLevel = LockoutLevel.NORMAL
        self._hooks: dict[LockoutLevel, list[Callable[[], Awaitable[None]]]] = {
            level: [] for level in LockoutLevel
        }
        self._pending_initiations: dict[str, dict] = {}
        self._event_history: list[LockoutEvent] = []
        self._last_check_in: datetime = datetime.now(timezone.utc)
        self._check_in_operator: Optional[str] = None
        self._dead_man_task: Optional[asyncio.Task] = None
        self._sealed: bool = False

        logger.info("Emergency lockout system initialised at NORMAL")

    @property
    def current_level(self) -> LockoutLevel:
        """Current lockout level."""
        return self._current_level

    @property
    def is_locked(self) -> bool:
        """Whether system is in any lockout state."""
        return self._current_level > LockoutLevel.NORMAL

    @property
    def is_sealed(self) -> bool:
        """Whether audit trail has been sealed (SHUTDOWN or higher)."""
        return self._sealed

    @property
    def accepts_threats(self) -> bool:
        """Whether system is accepting new threats for processing."""
        return self._current_level <= LockoutLevel.NORMAL

    @property
    def accepts_mesh(self) -> bool:
        """Whether mesh network is active."""
        return self._current_level < LockoutLevel.ISOLATE

    @property
    def accepts_antibody_writes(self) -> bool:
        """Whether antibody library accepts new entries."""
        return self._current_level < LockoutLevel.QUARANTINE

    def register_hook(
        self,
        level: LockoutLevel,
        hook: Callable[[], Awaitable[None]],
    ) -> None:
        """
        Register an async callback to execute when a lockout level is reached.

        Hooks for a given level also fire for all higher levels.
        Example: a PAUSE hook fires for PAUSE, ISOLATE, QUARANTINE, etc.
        """
        if level not in self._hooks:
            self._hooks[level] = []
        self._hooks[level].append(hook)
        logger.debug(f"Registered lockout hook for level {level.name}")

    def initiate(
        self,
        operator_id: str,
        level: LockoutLevel,
        reason: str,
        hardware_key_hash: Optional[str] = None,
    ) -> str:
        """
        Step 1: Initiate a lockout request.

        For levels QUARANTINE and above, returns a confirmation token
        that must be confirmed by a second operator within 30 seconds.

        For levels PAUSE and ISOLATE, executes immediately (single-person).

        Args:
            operator_id: Identifier of initiating operator.
            level: Desired lockout level.
            reason: Human-readable reason for lockout.
            hardware_key_hash: Optional HMAC of hardware security key.

        Returns:
            Confirmation token (for two-person levels) or event_id (for immediate).
        """
        if self._sealed:
            raise LockoutError("System is sealed — no further lockout changes permitted")

        if level <= self._current_level:
            raise LockoutError(
                f"Cannot lockout to level {level.name} — "
                f"already at {self._current_level.name}"
            )

        logger.warning(
            f"Lockout initiated: {level.name} by {operator_id} — {reason}"
        )

        if level in self.REQUIRES_CONFIRMATION:
            # Two-person rule: generate confirmation token
            token = secrets.token_hex(16)
            self._pending_initiations[token] = {
                "operator_id": operator_id,
                "level": level,
                "reason": reason,
                "hardware_key_hash": hardware_key_hash,
                "initiated_at": time.time(),
            }
            logger.warning(
                f"Lockout {level.name} requires peer confirmation within "
                f"{self.CONFIRMATION_TIMEOUT_S}s — token: {token[:8]}..."
            )
            return token
        else:
            # Single-person: execute immediately
            event = LockoutEvent(
                level=level,
                initiated_by=operator_id,
                confirmed_by=None,
                reason=reason,
            )
            asyncio.create_task(self._execute_lockout(event))
            return event.event_id

    def confirm(
        self,
        token: str,
        confirmer_id: str,
        hardware_key_hash: Optional[str] = None,
    ) -> str:
        """
        Step 3: Peer confirms a pending lockout request.

        Must be called within CONFIRMATION_TIMEOUT_S seconds of initiation.
        Confirmer must be different from initiator.

        Args:
            token: Confirmation token from initiate().
            confirmer_id: Identifier of confirming operator.
            hardware_key_hash: Optional HMAC of hardware security key.

        Returns:
            Event ID of the executed lockout.

        Raises:
            LockoutError: If token invalid, expired, or same operator.
        """
        if token not in self._pending_initiations:
            raise LockoutError("Invalid or expired confirmation token")

        pending = self._pending_initiations[token]

        # Check timeout
        elapsed = time.time() - pending["initiated_at"]
        if elapsed > self.CONFIRMATION_TIMEOUT_S:
            del self._pending_initiations[token]
            raise LockoutError(
                f"Confirmation token expired ({elapsed:.1f}s > "
                f"{self.CONFIRMATION_TIMEOUT_S}s)"
            )

        # Two-person rule: confirmer must be different
        if confirmer_id == pending["operator_id"]:
            raise LockoutError(
                "Two-person rule violation: confirmer must be different from initiator"
            )

        # Execute
        del self._pending_initiations[token]

        event = LockoutEvent(
            level=pending["level"],
            initiated_by=pending["operator_id"],
            confirmed_by=confirmer_id,
            reason=pending["reason"],
        )

        asyncio.create_task(self._execute_lockout(event))

        logger.warning(
            f"Lockout {event.level.name} confirmed by {confirmer_id} — executing"
        )

        return event.event_id

    async def _execute_lockout(self, event: LockoutEvent) -> None:
        """
        Steps 4-5: Execute lockout and seal audit trail.

        Fires all hooks for target level and all levels below it.
        """
        previous_level = self._current_level
        self._current_level = event.level
        self._event_history.append(event)

        logger.critical(
            f"LOCKOUT EXECUTED: {previous_level.name} → {event.level.name} "
            f"by {event.initiated_by}"
            f"{' + ' + event.confirmed_by if event.confirmed_by else ''} "
            f"— {event.reason}"
        )

        # Fire hooks for all levels up to and including target
        for level in LockoutLevel:
            if level == LockoutLevel.NORMAL:
                continue
            if level <= event.level:
                for hook in self._hooks.get(level, []):
                    try:
                        await hook()
                    except Exception as e:
                        logger.error(
                            f"Lockout hook failed at level {level.name}: {e}"
                        )

        # Seal audit trail for SHUTDOWN and above
        if event.level >= LockoutLevel.SHUTDOWN:
            self._sealed = True
            logger.critical("Audit trail SEALED — no further modifications permitted")

        # Scorched earth: clear runtime state
        if event.level >= LockoutLevel.SCORCHED_EARTH:
            await self._scorched_earth()

    async def _scorched_earth(self) -> None:
        """
        SCORCHED EARTH: Wipe all runtime state.

        Preserves ONLY:
        - Audit trail (sealed, immutable)
        - Lockout event history
        - Configuration (for forensic analysis)

        Destroys:
        - In-memory antibody cache
        - Active pipeline state
        - Mesh connections and keys
        - Model inference state
        - WebSocket connections
        """
        logger.critical(
            "SCORCHED EARTH: Wiping all runtime state. "
            "Only audit trail preserved."
        )
        # Hooks registered at SCORCHED_EARTH level handle the actual cleanup.
        # This method is a marker — hooks do the work.

    def check_in(self, operator_id: str) -> None:
        """
        Dead man's switch check-in.

        Must be called at least once every DEAD_MAN_INTERVAL_H hours.
        If not called, system auto-escalates to LEVEL 2 (ISOLATE).
        """
        self._last_check_in = datetime.now(timezone.utc)
        self._check_in_operator = operator_id
        logger.info(
            f"Dead man's switch check-in by {operator_id} at "
            f"{self._last_check_in.isoformat()}"
        )

    def start_dead_man_switch(self) -> None:
        """Start dead man's switch background task."""
        if self._dead_man_task is not None:
            self._dead_man_task.cancel()

        self._dead_man_task = asyncio.create_task(self._dead_man_loop())
        logger.info(
            f"Dead man's switch started — check-in required every "
            f"{self.DEAD_MAN_INTERVAL_H}h"
        )

    def stop_dead_man_switch(self) -> None:
        """Stop dead man's switch background task."""
        if self._dead_man_task is not None:
            self._dead_man_task.cancel()
            self._dead_man_task = None
            logger.info("Dead man's switch stopped")

    async def _dead_man_loop(self) -> None:
        """Background loop that checks for dead man's switch expiry."""
        check_interval_s = 300  # Check every 5 minutes
        try:
            while True:
                await asyncio.sleep(check_interval_s)

                if self._current_level >= LockoutLevel.ISOLATE:
                    # Already locked out — no need to check
                    continue

                elapsed = datetime.now(timezone.utc) - self._last_check_in
                deadline = timedelta(hours=self.DEAD_MAN_INTERVAL_H)

                if elapsed > deadline:
                    logger.critical(
                        f"DEAD MAN'S SWITCH TRIGGERED: No check-in for "
                        f"{elapsed.total_seconds() / 3600:.1f}h "
                        f"(limit: {self.DEAD_MAN_INTERVAL_H}h). "
                        f"Auto-escalating to ISOLATE."
                    )
                    event = LockoutEvent(
                        level=LockoutLevel.ISOLATE,
                        initiated_by="DEAD_MAN_SWITCH",
                        confirmed_by=None,
                        reason=(
                            f"No operator check-in for "
                            f"{elapsed.total_seconds() / 3600:.1f} hours"
                        ),
                    )
                    await self._execute_lockout(event)

                elif elapsed > deadline * 0.75:
                    remaining = deadline - elapsed
                    logger.warning(
                        f"Dead man's switch warning: {remaining.total_seconds() / 60:.0f} "
                        f"minutes until auto-lockout"
                    )

        except asyncio.CancelledError:
            logger.info("Dead man's switch loop cancelled")

    def reset(self, operator_id: str, reason: str) -> str:
        """
        Reset lockout to NORMAL level.

        Only permitted from levels PAUSE and ISOLATE.
        QUARANTINE and above require manual intervention
        (system restart with fresh configuration).

        Args:
            operator_id: Identifier of operator performing reset.
            reason: Reason for reset.

        Returns:
            Event ID of the reset event.
        """
        if self._sealed:
            raise LockoutError(
                "System is sealed — cannot reset. "
                "Manual restart with fresh configuration required."
            )

        if self._current_level >= LockoutLevel.QUARANTINE:
            raise LockoutError(
                f"Cannot reset from {self._current_level.name} — "
                f"manual restart required for levels QUARANTINE and above"
            )

        previous = self._current_level
        self._current_level = LockoutLevel.NORMAL

        event = LockoutEvent(
            level=LockoutLevel.NORMAL,
            initiated_by=operator_id,
            confirmed_by=None,
            reason=f"Reset from {previous.name}: {reason}",
        )
        self._event_history.append(event)

        # Reset dead man's switch
        self._last_check_in = datetime.now(timezone.utc)

        # Clean up expired pending initiations
        self._pending_initiations.clear()

        logger.warning(
            f"Lockout RESET: {previous.name} → NORMAL by {operator_id} — {reason}"
        )

        return event.event_id

    def get_status(self) -> dict:
        """Return current lockout status for API/dashboard."""
        now = datetime.now(timezone.utc)
        elapsed_since_checkin = now - self._last_check_in
        deadline = timedelta(hours=self.DEAD_MAN_INTERVAL_H)
        remaining = max(deadline - elapsed_since_checkin, timedelta(0))

        return {
            "current_level": self._current_level.name,
            "current_level_value": int(self._current_level),
            "is_locked": self.is_locked,
            "is_sealed": self.is_sealed,
            "accepts_threats": self.accepts_threats,
            "accepts_mesh": self.accepts_mesh,
            "accepts_antibody_writes": self.accepts_antibody_writes,
            "last_check_in": self._last_check_in.isoformat(),
            "last_check_in_operator": self._check_in_operator,
            "dead_man_remaining_minutes": round(
                remaining.total_seconds() / 60, 1
            ),
            "pending_confirmations": len(self._pending_initiations),
            "total_events": len(self._event_history),
            "recent_events": [
                {
                    "event_id": e.event_id,
                    "level": e.level.name,
                    "initiated_by": e.initiated_by,
                    "confirmed_by": e.confirmed_by,
                    "reason": e.reason,
                    "timestamp": e.timestamp.isoformat(),
                }
                for e in self._event_history[-10:]
            ],
        }

    def get_history(self) -> list[dict]:
        """Return full lockout event history for audit."""
        return [
            {
                "event_id": e.event_id,
                "level": e.level.name,
                "level_value": int(e.level),
                "initiated_by": e.initiated_by,
                "confirmed_by": e.confirmed_by,
                "reason": e.reason,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in self._event_history
        ]


class LockoutError(Exception):
    """Raised when a lockout operation fails."""
    pass


# Module-level singleton
_lockout: Optional[EmergencyLockout] = None


def get_lockout() -> EmergencyLockout:
    """Get or create the singleton EmergencyLockout instance."""
    global _lockout
    if _lockout is None:
        _lockout = EmergencyLockout()
    return _lockout
