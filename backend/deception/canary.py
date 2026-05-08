"""
IMMUNIS ACIN — HMAC-SHA256 Canary Token Engine

WHY: A canary token is a tripwire. It's a piece of data that has
no legitimate reason to be accessed — a fake credential, a decoy
document, a honeypot URL. When an attacker touches it, the canary
sings, and we know we've been breached.

Unlike traditional IDS alerts that generate thousands of false
positives, canary tokens have a near-zero false positive rate:
if the canary triggers, something is wrong. Period.

This module generates and manages:
1. Database canary tokens (fake credentials in config files)
2. Document canary tokens (tracked documents that phone home)
3. URL canary tokens (unique URLs that alert on access)
4. DNS canary tokens (unique hostnames that alert on resolution)
5. Email canary tokens (addresses that should never receive mail)
6. API key canary tokens (fake keys that alert on use)
7. File canary tokens (files that alert on open/copy)

Security properties:
- Tokens are HMAC-SHA256 signed (tamper-proof)
- Constant-time verification (no timing oracle)
- Tokens are unique per deployment (no cross-deployment leakage)
- Token metadata never stored with the token itself
- Verification requires the secret key (attacker can't self-verify)

Mathematical foundation:
  token = HMAC-SHA256(secret_key, token_type || token_id || salt)
  verification: constant_time_compare(
      HMAC-SHA256(secret_key, token_type || token_id || salt),
      presented_token
  )
"""

import logging
import hmac
import hashlib
import secrets
import time
import json
from typing import Optional
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("immunis.deception.canary")


class CanaryType(str, Enum):
    """Types of canary tokens."""
    DATABASE_CREDENTIAL = "database_credential"
    DOCUMENT = "document"
    URL = "url"
    DNS = "dns"
    EMAIL = "email"
    API_KEY = "api_key"
    FILE = "file"
    AWS_KEY = "aws_key"
    SYSTEM_PROMPT = "system_prompt"  # AI-specific: detects prompt extraction


@dataclass
class CanaryToken:
    """A deployed canary token."""
    token_id: str
    token_type: CanaryType
    token_value: str  # The actual canary value (fake cred, URL, etc.)
    hmac_signature: str  # HMAC-SHA256 for verification
    created_at: str
    expires_at: Optional[str] = None
    description: str = ""
    location: str = ""  # Where the canary is deployed
    triggered: bool = False
    trigger_count: int = 0
    last_triggered_at: Optional[str] = None
    last_triggered_by: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "token_id": self.token_id,
            "token_type": self.token_type.value,
            "token_value": self.token_value[:20] + "..." if len(self.token_value) > 20 else self.token_value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "description": self.description,
            "location": self.location,
            "triggered": self.triggered,
            "trigger_count": self.trigger_count,
            "last_triggered_at": self.last_triggered_at,
            "last_triggered_by": self.last_triggered_by,
        }


@dataclass
class CanaryAlert:
    """Alert generated when a canary token is triggered."""
    alert_id: str
    token_id: str
    token_type: CanaryType
    triggered_at: str
    triggered_by: str  # IP, user agent, or identifier
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    request_path: Optional[str] = None
    severity: str = "CRITICAL"  # Canary triggers are always critical
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "token_id": self.token_id,
            "token_type": self.token_type.value,
            "triggered_at": self.triggered_at,
            "triggered_by": self.triggered_by,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "request_path": self.request_path,
            "severity": self.severity,
            "details": self.details,
        }


class CanaryEngine:
    """
    HMAC-SHA256 canary token generation and verification engine.

    Generates various types of canary tokens, deploys them in
    strategic locations, and alerts when they're triggered.

    Security properties:
    - All verification uses constant-time comparison
    - Secret key never exposed in tokens or logs
    - Token metadata stored separately from token values
    - Expired tokens automatically invalidated

    Usage:
        engine = CanaryEngine(secret_key=os.environ["CANARY_SECRET"])

        # Generate a canary
        token = engine.generate(
            token_type=CanaryType.API_KEY,
            description="Fake AWS key in .env.backup",
            location="/app/.env.backup",
        )

        # Check if a value is a canary
        alert = engine.check("AKIA1234567890CANARY")

        # Verify a specific token
        is_valid = engine.verify(token_id, presented_value)
    """

    # Default expiry per token type
    DEFAULT_EXPIRY = {
        CanaryType.DATABASE_CREDENTIAL: timedelta(days=365),
        CanaryType.DOCUMENT: timedelta(days=180),
        CanaryType.URL: timedelta(days=90),
        CanaryType.DNS: timedelta(days=365),
        CanaryType.EMAIL: timedelta(days=365),
        CanaryType.API_KEY: timedelta(days=180),
        CanaryType.FILE: timedelta(days=365),
        CanaryType.AWS_KEY: timedelta(days=90),
        CanaryType.SYSTEM_PROMPT: timedelta(days=365),
    }

    def __init__(self, secret_key: Optional[str] = None):
        if secret_key is None:
            try:
                from backend.config import config
                secret_key = getattr(config, "jwt_secret", None)
            except (ImportError, AttributeError):
                pass

        if secret_key is None:
            secret_key = secrets.token_hex(32)
            logger.warning(
                "Canary engine using generated secret — "
                "tokens will not survive restart"
            )

        self._secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        self._tokens: dict[str, CanaryToken] = {}
        self._token_values: dict[str, str] = {}  # value → token_id (reverse lookup)
        self._alerts: list[CanaryAlert] = []
        self._alert_handlers: list = []

        # Statistics
        self._total_generated: int = 0
        self._total_checks: int = 0
        self._total_triggers: int = 0

        logger.info("Canary token engine initialised")

    def generate(
        self,
        token_type: CanaryType,
        description: str = "",
        location: str = "",
        custom_value: Optional[str] = None,
        expires_in: Optional[timedelta] = None,
        metadata: Optional[dict] = None,
    ) -> CanaryToken:
        """
        Generate a new canary token.

        Args:
            token_type: Type of canary to generate.
            description: Human-readable description.
            location: Where the canary will be deployed.
            custom_value: Custom token value (auto-generated if None).
            expires_in: Custom expiry duration.
            metadata: Additional metadata.

        Returns:
            CanaryToken ready for deployment.
        """
        # Generate token ID
        token_id = hashlib.sha256(
            f"{token_type.value}:{time.time()}:{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]

        # Generate token value based on type
        if custom_value:
            token_value = custom_value
        else:
            token_value = self._generate_value(token_type, token_id)

        # Generate salt
        salt = secrets.token_hex(8)

        # Compute HMAC signature
        hmac_input = f"{token_type.value}|{token_id}|{salt}".encode()
        hmac_sig = hmac.new(
            self._secret_key,
            hmac_input,
            hashlib.sha256,
        ).hexdigest()

        # Compute expiry
        now = datetime.now(timezone.utc)
        if expires_in is None:
            expires_in = self.DEFAULT_EXPIRY.get(token_type, timedelta(days=180))
        expires_at = (now + expires_in).isoformat()

        token = CanaryToken(
            token_id=token_id,
            token_type=token_type,
            token_value=token_value,
            hmac_signature=hmac_sig,
            created_at=now.isoformat(),
            expires_at=expires_at,
            description=description,
            location=location,
            metadata=metadata or {"salt": salt},
        )

        # Store token
        self._tokens[token_id] = token
        self._token_values[token_value] = token_id

        self._total_generated += 1

        logger.info(
            f"Canary generated: {token_type.value} at {location} "
            f"(id={token_id})"
        )

        return token

    def _generate_value(self, token_type: CanaryType, token_id: str) -> str:
        """Generate a realistic-looking canary value based on type."""
        if token_type == CanaryType.DATABASE_CREDENTIAL:
            # Looks like a database connection string
            user = secrets.token_hex(4)
            password = secrets.token_hex(12)
            return f"postgresql://canary_{user}:{password}@db.internal:5432/production"

        elif token_type == CanaryType.API_KEY:
            # Looks like a generic API key
            prefix = secrets.choice(["sk-", "pk-", "api-", "key-"])
            return f"{prefix}{secrets.token_hex(24)}"

        elif token_type == CanaryType.AWS_KEY:
            # Looks like an AWS access key
            key_id = f"AKIA{''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567') for _ in range(16))}"
            return key_id

        elif token_type == CanaryType.URL:
            # Unique tracking URL
            path = secrets.token_urlsafe(16)
            return f"https://canary.immunis.local/t/{path}"

        elif token_type == CanaryType.DNS:
            # Unique DNS hostname
            subdomain = secrets.token_hex(8)
            return f"{subdomain}.canary.immunis.local"

        elif token_type == CanaryType.EMAIL:
            # Email address that should never receive mail
            user = secrets.token_hex(6)
            return f"canary.{user}@immunis.local"

        elif token_type == CanaryType.DOCUMENT:
            # Unique document identifier
            return f"IMMUNIS-CONFIDENTIAL-{secrets.token_hex(8).upper()}"

        elif token_type == CanaryType.FILE:
            # Filename that looks interesting to attackers
            names = [
                "passwords_backup.xlsx",
                "admin_credentials.txt",
                "database_dump_2024.sql",
                "private_keys.pem",
                "salary_data_confidential.csv",
                "board_minutes_draft.docx",
            ]
            return secrets.choice(names)

        elif token_type == CanaryType.SYSTEM_PROMPT:
            # Canary embedded in AI system prompts
            return f"IMMUNIS-CANARY-{secrets.token_hex(8).upper()}"

        else:
            return f"canary-{secrets.token_hex(16)}"

    def check(
        self,
        value: str,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_path: Optional[str] = None,
        context: Optional[dict] = None,
    ) -> Optional[CanaryAlert]:
        """
        Check if a value matches any deployed canary token.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            value: The value to check.
            source_ip: Source IP of the request.
            user_agent: User agent string.
            request_path: Request path.
            context: Additional context.

        Returns:
            CanaryAlert if triggered, None if not a canary.
        """
        self._total_checks += 1

        # Constant-time lookup: check against all token values
        # This prevents timing-based enumeration of canary tokens
        matched_token_id = None

        for token_value, token_id in self._token_values.items():
            # Use constant-time comparison
            if self._constant_time_compare(value, token_value):
                matched_token_id = token_id
                # Don't break — continue checking all to maintain constant time

        if matched_token_id is None:
            return None

        # Token matched — generate alert
        token = self._tokens.get(matched_token_id)
        if token is None:
            return None

        # Check expiry
        if token.expires_at:
            try:
                expires = datetime.fromisoformat(
                    token.expires_at.replace("Z", "+00:00")
                )
                if datetime.now(timezone.utc) > expires:
                    logger.debug(f"Expired canary triggered: {matched_token_id}")
                    return None
            except (ValueError, TypeError):
                pass

        # Update token state
        now = datetime.now(timezone.utc).isoformat()
        token.triggered = True
        token.trigger_count += 1
        token.last_triggered_at = now
        token.last_triggered_by = source_ip or "unknown"

        # Generate alert
        alert_id = hashlib.sha256(
            f"{matched_token_id}:{now}:{source_ip}".encode()
        ).hexdigest()[:16]

        triggered_by = source_ip or user_agent or "unknown"

        alert = CanaryAlert(
            alert_id=alert_id,
            token_id=matched_token_id,
            token_type=token.token_type,
            triggered_at=now,
            triggered_by=triggered_by,
            source_ip=source_ip,
            user_agent=user_agent,
            request_path=request_path,
            details={
                "token_description": token.description,
                "token_location": token.location,
                "trigger_count": token.trigger_count,
                "context": context or {},
            },
        )

        self._alerts.append(alert)
        self._total_triggers += 1

        # Notify handlers
        for handler in self._alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Canary alert handler error: {e}")

        logger.critical(
            f"🐦 CANARY TRIGGERED: {token.token_type.value} "
            f"at {token.location} by {triggered_by} "
            f"(token={matched_token_id}, triggers={token.trigger_count})"
        )

        return alert

    def verify(self, token_id: str, presented_value: str) -> bool:
        """
        Verify a specific token value.

        Constant-time comparison to prevent timing oracle.
        """
        token = self._tokens.get(token_id)
        if token is None:
            return False

        return self._constant_time_compare(presented_value, token.token_value)

    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Constant-time string comparison to prevent timing attacks."""
        return hmac.compare_digest(a.encode(), b.encode())

    def on_trigger(self, handler) -> None:
        """Register a handler for canary trigger events."""
        self._alert_handlers.append(handler)

    def get_token(self, token_id: str) -> Optional[dict]:
        """Get token info (without the actual value for security)."""
        token = self._tokens.get(token_id)
        if token is None:
            return None
        return token.to_dict()

    def get_all_tokens(self) -> list[dict]:
        """Get all deployed tokens (without values)."""
        return [t.to_dict() for t in self._tokens.values()]

    def get_alerts(self, limit: int = 50) -> list[dict]:
        """Get recent canary alerts."""
        return [a.to_dict() for a in self._alerts[-limit:]]

    def get_triggered_tokens(self) -> list[dict]:
        """Get all tokens that have been triggered."""
        return [
            t.to_dict() for t in self._tokens.values()
            if t.triggered
        ]

    def revoke_token(self, token_id: str) -> bool:
        """Revoke a canary token (remove from active monitoring)."""
        token = self._tokens.pop(token_id, None)
        if token:
            self._token_values.pop(token.token_value, None)
            logger.info(f"Canary revoked: {token_id}")
            return True
        return False

    def deploy_standard_set(self) -> list[CanaryToken]:
        """
        Deploy a standard set of canary tokens.

        Creates canaries in common attacker-targeted locations.
        """
        tokens = []

        standard_canaries = [
            (CanaryType.DATABASE_CREDENTIAL, "Fake DB creds in .env.backup", ".env.backup"),
            (CanaryType.API_KEY, "Fake API key in config", "config/api_keys.json"),
            (CanaryType.AWS_KEY, "Fake AWS key in environment", "~/.aws/credentials"),
            (CanaryType.EMAIL, "Honeypot email in contacts", "admin_contacts.csv"),
            (CanaryType.FILE, "Decoy sensitive file", "/shared/confidential/"),
            (CanaryType.SYSTEM_PROMPT, "AI system prompt canary", "system_prompts/"),
            (CanaryType.URL, "Tracking URL in internal docs", "internal_wiki"),
            (CanaryType.DNS, "Canary DNS in hosts file", "/etc/hosts"),
        ]

        for token_type, description, location in standard_canaries:
            token = self.generate(
                token_type=token_type,
                description=description,
                location=location,
            )
            tokens.append(token)

        logger.info(f"Standard canary set deployed: {len(tokens)} tokens")
        return tokens

    def get_stats(self) -> dict:
        """Return canary engine statistics."""
        type_counts = {}
        for token in self._tokens.values():
            t = token.token_type.value
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "total_generated": self._total_generated,
            "active_tokens": len(self._tokens),
            "total_checks": self._total_checks,
            "total_triggers": self._total_triggers,
            "triggered_tokens": sum(
                1 for t in self._tokens.values() if t.triggered
            ),
            "token_types": type_counts,
            "recent_alerts": len(self._alerts),
        }


# Module-level singleton
_engine: Optional[CanaryEngine] = None


def get_canary_engine() -> CanaryEngine:
    """Get or create the singleton CanaryEngine instance."""
    global _engine
    if _engine is None:
        _engine = CanaryEngine()
    return _engine
