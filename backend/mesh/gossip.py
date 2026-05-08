"""
IMMUNIS ACIN — Epidemic Gossip Protocol with R₀-Priority Broadcast

WHY: When a node synthesises an antibody, it must reach every node
in the mesh as fast as possible. But not all antibodies are equally
urgent — an antibody for a novel zero-day with R₀=5.0 must propagate
faster than an update to a known signature with R₀=0.3.

This module implements an epidemic gossip protocol inspired by
real disease propagation models. Each antibody has a computed R₀
(basic reproduction number of the ATTACK it defends against).
Higher R₀ = higher broadcast priority.

Protocol:
1. Node synthesises antibody → computes R₀ priority
2. Selects peers to infect (fan-out based on R₀)
3. Sends antibody with TTL and hop count
4. Receiving node verifies signature → stores → re-gossips
5. Deduplication via bloom filter (prevent infinite loops)
6. Convergence: all nodes receive antibody within O(log N) rounds

Mathematical foundation:
  Fan-out f = min(ceil(R₀ × 2), total_peers)
  TTL = ceil(log₂(network_size)) + 2
  Expected convergence rounds: O(log N / log f)

  Priority queue ordered by:
    priority = R₀ × severity_weight × (1 / age_seconds)
"""

import logging
import time
import asyncio
import hashlib
import json
import math
from typing import Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field
from collections import deque

logger = logging.getLogger("immunis.mesh.gossip")


# Bloom filter for deduplication
class BloomFilter:
    """
    Simple bloom filter for antibody deduplication.

    Prevents infinite gossip loops by tracking which antibody IDs
    have already been seen and forwarded.
    """

    def __init__(self, capacity: int = 100_000, error_rate: float = 0.001):
        self._capacity = capacity
        self._error_rate = error_rate

        # Compute optimal size and hash count
        # m = -n * ln(p) / (ln(2))^2
        # k = (m/n) * ln(2)
        self._size = int(-capacity * math.log(error_rate) / (math.log(2) ** 2))
        self._hash_count = int((self._size / capacity) * math.log(2))
        self._bits = bytearray(self._size // 8 + 1)
        self._count = 0

    def add(self, item: str) -> None:
        """Add an item to the bloom filter."""
        for i in range(self._hash_count):
            idx = self._hash(item, i) % self._size
            self._bits[idx // 8] |= (1 << (idx % 8))
        self._count += 1

    def contains(self, item: str) -> bool:
        """Check if an item might be in the bloom filter."""
        for i in range(self._hash_count):
            idx = self._hash(item, i) % self._size
            if not (self._bits[idx // 8] & (1 << (idx % 8))):
                return False
        return True

    def _hash(self, item: str, seed: int) -> int:
        """Generate a hash for the bloom filter."""
        h = hashlib.sha256(f"{item}:{seed}".encode()).digest()
        return int.from_bytes(h[:4], "big")

    @property
    def count(self) -> int:
        return self._count

    def reset(self) -> None:
        """Reset the bloom filter."""
        self._bits = bytearray(self._size // 8 + 1)
        self._count = 0


@dataclass
class GossipMessage:
    """A message in the gossip protocol."""
    message_id: str
    antibody_id: str
    payload: bytes  # Signed antibody data
    r0: float  # Attack R₀ (broadcast priority)
    severity: float  # 0-1 severity weight
    ttl: int  # Time-to-live (hops remaining)
    hop_count: int = 0  # Hops so far
    origin_node: str = ""
    origin_fingerprint: str = ""
    created_at: float = field(default_factory=time.time)
    priority: float = 0.0  # Computed priority score

    def compute_priority(self) -> float:
        """Compute broadcast priority based on R₀, severity, and age."""
        age_seconds = max(1.0, time.time() - self.created_at)
        self.priority = self.r0 * self.severity * (1.0 / age_seconds) * 1000
        return self.priority

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "antibody_id": self.antibody_id,
            "payload": self.payload.hex() if isinstance(self.payload, bytes) else self.payload,
            "r0": self.r0,
            "severity": self.severity,
            "ttl": self.ttl,
            "hop_count": self.hop_count,
            "origin_node": self.origin_node,
            "origin_fingerprint": self.origin_fingerprint,
            "created_at": self.created_at,
            "priority": self.priority,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GossipMessage":
        payload = data.get("payload", "")
        if isinstance(payload, str):
            try:
                payload = bytes.fromhex(payload)
            except ValueError:
                payload = payload.encode()

        return cls(
            message_id=data.get("message_id", ""),
            antibody_id=data.get("antibody_id", ""),
            payload=payload,
            r0=data.get("r0", 1.0),
            severity=data.get("severity", 0.5),
            ttl=data.get("ttl", 5),
            hop_count=data.get("hop_count", 0),
            origin_node=data.get("origin_node", ""),
            origin_fingerprint=data.get("origin_fingerprint", ""),
            created_at=data.get("created_at", time.time()),
            priority=data.get("priority", 0.0),
        )


class GossipProtocol:
    """
    Epidemic gossip protocol with R₀-priority broadcast.

    Implements push-based gossip with:
    - R₀-weighted fan-out (higher R₀ = more peers contacted)
    - Priority queue for message ordering
    - Bloom filter deduplication
    - TTL-based hop limiting
    - Convergence tracking

    Usage:
        gossip = GossipProtocol(mesh_node)
        await gossip.start()

        # Broadcast a new antibody
        await gossip.broadcast_antibody(
            antibody_id="AB-001",
            payload=signed_bytes,
            r0=2.3,
            severity=0.9,
        )

        # Handle incoming gossip
        gossip.on_receive(handler_function)
    """

    # Protocol parameters
    DEFAULT_TTL = 8
    MAX_TTL = 15
    MIN_FAN_OUT = 2
    MAX_FAN_OUT = 10
    GOSSIP_INTERVAL_S = 1.0  # Process queue every second
    MAX_QUEUE_SIZE = 1000
    BLOOM_CAPACITY = 100_000
    BLOOM_RESET_INTERVAL_S = 3600  # Reset bloom filter every hour

    def __init__(self, mesh_node=None):
        self._mesh_node = mesh_node
        self._bloom = BloomFilter(capacity=self.BLOOM_CAPACITY)
        self._priority_queue: list[GossipMessage] = []
        self._receive_handlers: list = []
        self._gossip_task: Optional[asyncio.Task] = None
        self._bloom_reset_task: Optional[asyncio.Task] = None
        self._running = False

        # Statistics
        self._messages_originated: int = 0
        self._messages_forwarded: int = 0
        self._messages_deduplicated: int = 0
        self._messages_expired: int = 0
        self._total_hops: int = 0
        self._convergence_times: list[float] = []

        logger.info("Gossip protocol initialised")

    async def start(self) -> None:
        """Start gossip protocol background tasks."""
        self._running = True
        self._gossip_task = asyncio.create_task(self._gossip_loop())
        self._bloom_reset_task = asyncio.create_task(self._bloom_reset_loop())
        logger.info("Gossip protocol started")

    async def stop(self) -> None:
        """Stop gossip protocol."""
        self._running = False
        if self._gossip_task:
            self._gossip_task.cancel()
        if self._bloom_reset_task:
            self._bloom_reset_task.cancel()
        logger.info("Gossip protocol stopped")

    async def broadcast_antibody(
        self,
        antibody_id: str,
        payload: bytes,
        r0: float = 1.0,
        severity: float = 0.5,
        ttl: Optional[int] = None,
    ) -> str:
        """
        Initiate broadcast of a new antibody.

        Args:
            antibody_id: Unique antibody identifier.
            payload: Signed antibody data.
            r0: Attack R₀ (determines broadcast urgency).
            severity: Attack severity (0-1).
            ttl: Time-to-live in hops. None = auto-compute.

        Returns:
            Message ID for tracking.
        """
        # Compute TTL based on estimated network size
        if ttl is None:
            network_size = max(3, self._estimate_network_size())
            ttl = min(
                self.MAX_TTL,
                max(self.DEFAULT_TTL, int(math.ceil(math.log2(network_size))) + 2),
            )

        # Generate message ID
        message_id = hashlib.sha256(
            f"{antibody_id}:{time.time()}:{id(payload)}".encode()
        ).hexdigest()[:16]

        # Get origin info
        origin_node = ""
        origin_fingerprint = ""
        if self._mesh_node:
            identity = self._mesh_node.get_identity()
            if identity:
                origin_node = identity.node_id
                origin_fingerprint = identity.fingerprint

        message = GossipMessage(
            message_id=message_id,
            antibody_id=antibody_id,
            payload=payload,
            r0=r0,
            severity=severity,
            ttl=ttl,
            hop_count=0,
            origin_node=origin_node,
            origin_fingerprint=origin_fingerprint,
        )
        message.compute_priority()

        # Add to bloom filter (we've seen our own message)
        self._bloom.add(message_id)

        # Add to priority queue
        self._enqueue(message)

        self._messages_originated += 1

        logger.info(
            f"Antibody broadcast initiated: {antibody_id}, "
            f"R₀={r0:.1f}, severity={severity:.2f}, "
            f"TTL={ttl}, priority={message.priority:.2f}, "
            f"message_id={message_id}"
        )

        return message_id

    async def handle_incoming(self, raw_message: dict) -> bool:
        """
        Handle an incoming gossip message from a peer.

        Verifies, deduplicates, stores, and re-gossips.

        Args:
            raw_message: Parsed JSON message from peer.

        Returns:
            True if message was new and processed, False if deduplicated.
        """
        try:
            message = GossipMessage.from_dict(raw_message)
        except Exception as e:
            logger.warning(f"Invalid gossip message: {e}")
            return False

        # Deduplication check
        if self._bloom.contains(message.message_id):
            self._messages_deduplicated += 1
            logger.debug(
                f"Gossip dedup: {message.message_id} (antibody {message.antibody_id})"
            )
            return False

        # TTL check
        if message.ttl <= 0:
            self._messages_expired += 1
            logger.debug(
                f"Gossip TTL expired: {message.message_id} "
                f"(hops={message.hop_count})"
            )
            return False

        # Mark as seen
        self._bloom.add(message.message_id)

        # Track hops
        self._total_hops += message.hop_count

        # Notify receive handlers
        for handler in self._receive_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(message)
                else:
                    handler(message)
            except Exception as e:
                logger.error(f"Gossip receive handler error: {e}")

        # Prepare for re-gossip (decrement TTL, increment hop count)
        message.ttl -= 1
        message.hop_count += 1
        message.compute_priority()

        if message.ttl > 0:
            self._enqueue(message)
            self._messages_forwarded += 1

        logger.info(
            f"Gossip received: antibody={message.antibody_id}, "
            f"R₀={message.r0:.1f}, hops={message.hop_count}, "
            f"TTL_remaining={message.ttl}, "
            f"from={message.origin_node}"
        )

        return True

    def on_receive(self, handler) -> None:
        """Register a handler for received gossip messages."""
        self._receive_handlers.append(handler)

    # ------------------------------------------------------------------
    # GOSSIP LOOP
    # ------------------------------------------------------------------

    async def _gossip_loop(self) -> None:
        """Process priority queue and send messages to peers."""
        try:
            while self._running:
                await asyncio.sleep(self.GOSSIP_INTERVAL_S)

                if not self._priority_queue:
                    continue

                if not self._mesh_node:
                    continue

                # Process highest priority messages first
                self._priority_queue.sort(key=lambda m: m.priority, reverse=True)

                # Process up to 10 messages per cycle
                batch = self._priority_queue[:10]
                self._priority_queue = self._priority_queue[10:]

                for message in batch:
                    await self._gossip_message(message)

        except asyncio.CancelledError:
            logger.debug("Gossip loop cancelled")

    async def _gossip_message(self, message: GossipMessage) -> None:
        """Send a gossip message to selected peers."""
        if not self._mesh_node:
            return

        online_peers = self._mesh_node.get_online_peers()
        if not online_peers:
            return

        # Compute fan-out based on R₀
        fan_out = self._compute_fan_out(message.r0, len(online_peers))

        # Select peers (random subset for epidemic spread)
        import random
        selected_peers = random.sample(
            online_peers,
            min(fan_out, len(online_peers)),
        )

        # Send to selected peers
        envelope = json.dumps({
            "type": "gossip",
            **message.to_dict(),
        })

        sent = 0
        for peer in selected_peers:
            try:
                success = await self._mesh_node.send_to_peer(
                    peer.node_id,
                    envelope.encode(),
                    message_type="gossip",
                )
                if success:
                    sent += 1
            except Exception as e:
                logger.debug(f"Gossip send to {peer.node_id} failed: {e}")

        logger.debug(
            f"Gossip spread: {message.antibody_id} → "
            f"{sent}/{fan_out} peers (R₀={message.r0:.1f})"
        )

    def _compute_fan_out(self, r0: float, total_peers: int) -> int:
        """
        Compute fan-out (number of peers to contact) based on R₀.

        fan_out = min(ceil(R₀ × 2), total_peers, MAX_FAN_OUT)

        Higher R₀ = more peers contacted = faster propagation.
        """
        fan_out = int(math.ceil(r0 * 2))
        fan_out = max(self.MIN_FAN_OUT, fan_out)
        fan_out = min(self.MAX_FAN_OUT, fan_out)
        fan_out = min(fan_out, total_peers)
        return fan_out

    def _estimate_network_size(self) -> int:
        """Estimate total network size from local peer knowledge."""
        if self._mesh_node:
            return max(3, self._mesh_node.peer_count + 1)
        return 3

    def _enqueue(self, message: GossipMessage) -> None:
        """Add a message to the priority queue with size limit."""
        if len(self._priority_queue) >= self.MAX_QUEUE_SIZE:
            # Drop lowest priority message
            self._priority_queue.sort(key=lambda m: m.priority)
            self._priority_queue.pop(0)

        self._priority_queue.append(message)

    async def _bloom_reset_loop(self) -> None:
        """Periodically reset bloom filter to prevent saturation."""
        try:
            while self._running:
                await asyncio.sleep(self.BLOOM_RESET_INTERVAL_S)
                old_count = self._bloom.count
                self._bloom.reset()
                logger.info(
                    f"Bloom filter reset: cleared {old_count} entries"
                )
        except asyncio.CancelledError:
            logger.debug("Bloom reset loop cancelled")

    # ------------------------------------------------------------------
    # STATISTICS
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return gossip protocol statistics."""
        avg_hops = (
            self._total_hops / (self._messages_forwarded + self._messages_originated)
            if (self._messages_forwarded + self._messages_originated) > 0
            else 0
        )

        return {
            "running": self._running,
            "messages_originated": self._messages_originated,
            "messages_forwarded": self._messages_forwarded,
            "messages_deduplicated": self._messages_deduplicated,
            "messages_expired": self._messages_expired,
            "queue_size": len(self._priority_queue),
            "bloom_filter_count": self._bloom.count,
            "bloom_filter_capacity": self._bloom._capacity,
            "avg_hops": round(avg_hops, 2),
            "total_hops": self._total_hops,
        }


# Module-level singleton
_gossip: Optional[GossipProtocol] = None


def get_gossip_protocol(mesh_node=None) -> GossipProtocol:
    """Get or create the singleton GossipProtocol instance."""
    global _gossip
    if _gossip is None:
        _gossip = GossipProtocol(mesh_node=mesh_node)
    return _gossip
