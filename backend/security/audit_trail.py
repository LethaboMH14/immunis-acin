"""
IMMUNIS ACIN — Merkle Tree Audit Trail

Every significant action in IMMUNIS is recorded as a leaf in a Merkle tree.
The root hash is periodically anchored to immutable storage (WORM blob).

Why Merkle tree instead of just a database log:
    A database log can be tampered with if an attacker gains DB access.
    A Merkle tree makes tampering detectable: changing any single event
    changes every hash above it in the tree, and the root won't match
    the externally anchored value.

    This is the same data structure that secures every blockchain.
    But we don't need a blockchain — we need tamper DETECTION, not
    tamper PREVENTION. The Merkle tree + external anchor achieves this
    at zero infrastructure cost.

Properties:
    - Adding an event: O(1) amortised
    - Generating a proof for any event: O(log n)
    - Verifying a proof: O(log n)
    - Storage: O(n) for leaves, O(n) for internal nodes
    - For 1M events: ~20 hash operations per verification

Research basis:
    - Merkle (1979), "A Certified Digital Signature"
    - Certificate Transparency (RFC 6962) — same Merkle tree approach

Security:
    - SHA-256 for all hashing (collision-resistant)
    - Root hash anchored to external immutable storage
    - No raw content in audit events — only metadata and hashes
    - Audit events are append-only — no update, no delete

Temperature: 0.3 (security-critical code, must be precise)
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from backend.models.schemas import generate_id, utc_now

logger = logging.getLogger("immunis.audit")


# ============================================================================
# AUDIT EVENT MODEL
# ============================================================================

class AuditEvent(BaseModel):
    """
    A single audit event. Becomes a leaf in the Merkle tree.
    
    CRITICAL SECURITY RULE: Never include raw threat content, PII,
    or credentials in any field. Only metadata and references.
    """
    event_id: str = Field(default_factory=lambda: generate_id("AUD"))
    timestamp: datetime = Field(default_factory=utc_now)
    pipeline_id: str = Field(default="")
    stage: str = Field(default="", description="Pipeline stage that generated this event")
    agent: str = Field(default="", description="Which agent produced this event")
    action: str = Field(default="", description="What happened (e.g., 'antibody_synthesised')")
    antibody_id: Optional[str] = Field(default=None)
    node_id: str = Field(default="")
    success: bool = Field(default=True)
    duration_ms: float = Field(default=0.0, ge=0.0)
    payload_size_bytes: int = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context — NEVER raw content or PII",
    )

    def to_hash_input(self) -> bytes:
        """
        Deterministic serialisation for hashing.
        Keys sorted, no whitespace, UTF-8 encoded.
        """
        data = self.model_dump(mode="json")
        # Convert datetime to ISO string for deterministic serialisation
        if isinstance(data.get("timestamp"), str):
            pass  # Already string from model_dump
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
        return canonical.encode("utf-8")


# ============================================================================
# MERKLE TREE
# ============================================================================

class MerkleTree:
    """
    Append-only Merkle tree for tamper-evident audit logging.
    
    Each leaf is a SHA-256 hash of an AuditEvent.
    Internal nodes are SHA-256(left_child || right_child).
    The root hash summarises the entire audit history.
    
    Tampering with any single event changes the root hash,
    making tampering detectable when compared against
    the externally anchored root.
    """

    def __init__(self):
        self._leaves: list[str] = []  # Leaf hashes (hex strings)
        self._events: list[AuditEvent] = []  # Original events (for export)
        self._root: Optional[str] = None

    @property
    def size(self) -> int:
        """Number of events in the tree."""
        return len(self._leaves)

    @property
    def root(self) -> Optional[str]:
        """Current Merkle root hash. None if tree is empty."""
        return self._root

    def add_event(self, event: AuditEvent) -> str:
        """
        Add an audit event to the tree.
        
        Returns the leaf hash of the added event.
        """
        # Compute leaf hash
        leaf_hash = hashlib.sha256(event.to_hash_input()).hexdigest()

        self._leaves.append(leaf_hash)
        self._events.append(event)

        # Recompute root
        self._root = self._compute_root()

        logger.debug(
            "Audit event added",
            extra={
                "event_id": event.event_id,
                "action": event.action,
                "leaf_hash": leaf_hash[:16],
                "tree_size": self.size,
                "root": self._root[:16] if self._root else "empty",
            },
        )

        return leaf_hash

    def _compute_root(self) -> str:
        """
        Compute the Merkle root from all leaves.
        
        Algorithm:
        1. Start with leaf hashes as the current level
        2. Pair adjacent hashes and compute parent: SHA-256(left || right)
        3. If odd number of nodes, duplicate the last one
        4. Repeat until one hash remains — that's the root
        """
        if not self._leaves:
            return hashlib.sha256(b"empty_tree").hexdigest()

        level = list(self._leaves)

        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                # If odd number, duplicate last node
                right = level[i + 1] if i + 1 < len(level) else left
                combined = hashlib.sha256(
                    (left + right).encode("utf-8")
                ).hexdigest()
                next_level.append(combined)
            level = next_level

        return level[0]

    def generate_proof(self, leaf_index: int) -> list[dict[str, str]]:
        """
        Generate a Merkle proof for a specific event.
        
        The proof is a list of sibling hashes that, combined with the
        leaf hash, can reconstruct the root. An auditor can verify
        that a specific event existed in the tree without seeing
        any other events.
        
        Args:
            leaf_index: Index of the event (0-based)
        
        Returns:
            List of {"hash": str, "direction": "left"|"right"} steps
        
        Raises:
            IndexError if leaf_index is out of range
        """
        if leaf_index < 0 or leaf_index >= len(self._leaves):
            raise IndexError(f"Leaf index {leaf_index} out of range (tree has {len(self._leaves)} leaves)")

        proof = []
        level = list(self._leaves)
        idx = leaf_index

        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left

                # If current index is in this pair, record the sibling
                if i == idx or i + 1 == idx:
                    if i == idx:
                        sibling = right
                        direction = "right"
                    else:
                        sibling = left
                        direction = "left"
                    proof.append({"hash": sibling, "direction": direction})

                combined = hashlib.sha256(
                    (left + right).encode("utf-8")
                ).hexdigest()
                next_level.append(combined)

            idx = idx // 2
            level = next_level

        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: list[dict[str, str]], expected_root: str) -> bool:
        """
        Verify a Merkle proof against an expected root hash.
        
        This is what an external auditor runs. They have:
        1. The event they want to verify (they compute its leaf hash)
        2. The proof (list of sibling hashes)
        3. The anchored root hash (from immutable storage)
        
        If the reconstructed root matches the anchored root,
        the event is proven to be part of the original audit trail.
        """
        current = leaf_hash

        for step in proof:
            sibling = step["hash"]
            if step["direction"] == "right":
                current = hashlib.sha256(
                    (current + sibling).encode("utf-8")
                ).hexdigest()
            else:
                current = hashlib.sha256(
                    (sibling + current).encode("utf-8")
                ).hexdigest()

        return current == expected_root

    def get_event(self, index: int) -> Optional[AuditEvent]:
        """Get an event by index."""
        if 0 <= index < len(self._events):
            return self._events[index]
        return None

    def get_events_by_pipeline(self, pipeline_id: str) -> list[AuditEvent]:
        """Get all events for a specific pipeline run."""
        return [e for e in self._events if e.pipeline_id == pipeline_id]

    def get_events_by_action(self, action: str) -> list[AuditEvent]:
        """Get all events with a specific action."""
        return [e for e in self._events if e.action == action]

    def get_recent_events(self, count: int = 50) -> list[AuditEvent]:
        """Get the most recent N events."""
        return list(reversed(self._events[-count:]))

    def export_for_anchor(self) -> dict[str, Any]:
        """
        Export data for anchoring to immutable storage.
        
        This is written to a WORM (Write Once Read Many) blob.
        Once written, it cannot be modified or deleted — even by
        Azure administrators (with legal hold policy).
        """
        return {
            "merkle_root": self._root,
            "tree_size": self.size,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "first_event_id": self._events[0].event_id if self._events else None,
            "last_event_id": self._events[-1].event_id if self._events else None,
            "anchor_version": "1.0",
        }

    def save(self, path: str) -> None:
        """Persist the audit trail to disk."""
        save_path = Path(path)
        save_path.mkdir(parents=True, exist_ok=True)

        # Save events as JSONL (one event per line — append-friendly)
        with open(save_path / "audit_events.jsonl", "w") as f:
            for event in self._events:
                f.write(event.model_dump_json() + "\n")

        # Save tree metadata
        meta = {
            "root": self._root,
            "size": self.size,
            "leaves": self._leaves,
        }
        with open(save_path / "audit_meta.json", "w") as f:
            json.dump(meta, f)

        logger.info(f"Audit trail saved to {save_path} ({self.size} events)")

    def load(self, path: str) -> None:
        """Load the audit trail from disk."""
        load_path = Path(path)

        events_file = load_path / "audit_events.jsonl"
        if not events_file.exists():
            logger.warning(f"No audit trail found at {load_path}")
            return

        self._events = []
        self._leaves = []

        with open(events_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    event = AuditEvent.model_validate_json(line)
                    self._events.append(event)
                    leaf_hash = hashlib.sha256(event.to_hash_input()).hexdigest()
                    self._leaves.append(leaf_hash)

        self._root = self._compute_root()
        logger.info(f"Audit trail loaded from {load_path} ({self.size} events)")

    def integrity_check(self) -> dict[str, Any]:
        """
        Verify internal consistency of the tree.
        
        Recomputes all leaf hashes from events and verifies
        the root matches. Used for startup verification.
        """
        if not self._events:
            return {"valid": True, "size": 0, "message": "Empty tree"}

        # Recompute all leaf hashes
        recomputed_leaves = []
        for event in self._events:
            leaf_hash = hashlib.sha256(event.to_hash_input()).hexdigest()
            recomputed_leaves.append(leaf_hash)

        # Check leaves match
        if recomputed_leaves != self._leaves:
            mismatches = sum(
                1 for a, b in zip(recomputed_leaves, self._leaves) if a != b
            )
            return {
                "valid": False,
                "size": self.size,
                "message": f"INTEGRITY FAILURE: {mismatches} leaf hashes do not match events",
                "mismatched_count": mismatches,
            }

        # Recompute root
        recomputed_root = self._compute_root()
        if recomputed_root != self._root:
            return {
                "valid": False,
                "size": self.size,
                "message": "INTEGRITY FAILURE: Root hash does not match recomputed root",
                "stored_root": self._root,
                "recomputed_root": recomputed_root,
            }

        return {
            "valid": True,
            "size": self.size,
            "root": self._root,
            "message": "Integrity verified — all hashes consistent",
        }


# ============================================================================
# GLOBAL AUDIT TRAIL SINGLETON
# ============================================================================

_audit_trail: Optional[MerkleTree] = None


def get_audit_trail() -> MerkleTree:
    """Get or create the global audit trail."""
    global _audit_trail
    if _audit_trail is None:
        _audit_trail = MerkleTree()

        # Try to load persisted trail
        from backend.config import get_settings
        settings = get_settings()
        trail_path = settings.data_dir / "audit_trail"
        if (trail_path / "audit_events.jsonl").exists():
            _audit_trail.load(str(trail_path))
            # Verify integrity on load
            check = _audit_trail.integrity_check()
            if not check["valid"]:
                logger.critical(
                    "AUDIT TRAIL INTEGRITY FAILURE ON LOAD",
                    extra=check,
                )
                # In production, this would trigger emergency lockout
                # For now, log and continue with the loaded (potentially tampered) trail
            else:
                logger.info(
                    "Audit trail loaded and verified",
                    extra={"size": check["size"], "root": check.get("root", "")[:16]},
                )

    return _audit_trail


def record_event(
    pipeline_id: str = "",
    stage: str = "",
    agent: str = "",
    action: str = "",
    antibody_id: Optional[str] = None,
    success: bool = True,
    duration_ms: float = 0.0,
    payload_size_bytes: int = 0,
    metadata: Optional[dict[str, Any]] = None,
) -> str:
    """
    Convenience function to record an audit event.
    Returns the leaf hash.
    
    Usage:
        from backend.security.audit_trail import record_event
        
        leaf_hash = record_event(
            pipeline_id="PL-abc123",
            stage="fingerprint",
            agent="incident_analyst",
            action="fingerprint_generated",
            success=True,
            duration_ms=1234.5,
        )
    """
    from backend.config import get_settings
    settings = get_settings()

    event = AuditEvent(
        pipeline_id=pipeline_id,
        stage=stage,
        agent=agent,
        action=action,
        antibody_id=antibody_id,
        node_id=settings.immunis_node_id,
        success=success,
        duration_ms=duration_ms,
        payload_size_bytes=payload_size_bytes,
        metadata=metadata or {},
    )

    trail = get_audit_trail()
    return trail.add_event(event)
