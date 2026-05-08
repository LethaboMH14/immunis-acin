"""
IMMUNIS ACIN — P2P Mesh Node Identity & Connection Management

WHY: Each IMMUNIS deployment is a node in a peer-to-peer mesh.
Nodes must discover each other, establish authenticated connections,
exchange public keys, maintain heartbeats, and track peer health.
When a node synthesises an antibody, it broadcasts to all connected
peers. When a node receives an antibody, it verifies the signature
and adds it to its local immune memory.

This module manages:
1. Node identity (unique ID, key pair, metadata)
2. Peer discovery and registration
3. Connection lifecycle (connect, heartbeat, disconnect)
4. Peer health monitoring (latency, uptime, reliability)
5. Connection pool management

Architecture:
  Node A ←→ Node B: WebSocket connections
  Each node maintains a connection pool to all known peers.
  Heartbeats every 30 seconds. Dead peers pruned after 3 missed beats.
  New peers discovered via gossip (existing peers share their peer lists).
"""

import logging
import time
import asyncio
import json
import hashlib
from typing import Optional
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("immunis.mesh.node")


class PeerStatus(str, Enum):
    """Status of a peer node."""
    UNKNOWN = "unknown"
    CONNECTING = "connecting"
    ONLINE = "online"
    DEGRADED = "degraded"  # High latency or packet loss
    OFFLINE = "offline"
    BANNED = "banned"


@dataclass
class PeerInfo:
    """Information about a peer node."""
    node_id: str
    endpoint: str  # ws://host:port
    display_name: Optional[str] = None
    public_keys: dict = field(default_factory=dict)
    fingerprint: Optional[str] = None
    status: PeerStatus = PeerStatus.UNKNOWN
    connected_at: Optional[str] = None
    last_heartbeat: Optional[str] = None
    last_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    heartbeats_sent: int = 0
    heartbeats_received: int = 0
    heartbeats_missed: int = 0
    antibodies_received: int = 0
    antibodies_sent: int = 0
    immunity_score: float = 0.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "endpoint": self.endpoint,
            "display_name": self.display_name,
            "fingerprint": self.fingerprint,
            "status": self.status.value,
            "connected_at": self.connected_at,
            "last_heartbeat": self.last_heartbeat,
            "last_latency_ms": round(self.last_latency_ms, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "heartbeats_sent": self.heartbeats_sent,
            "heartbeats_received": self.heartbeats_received,
            "heartbeats_missed": self.heartbeats_missed,
            "antibodies_received": self.antibodies_received,
            "antibodies_sent": self.antibodies_sent,
            "immunity_score": round(self.immunity_score, 2),
            "metadata": self.metadata,
        }


@dataclass
class NodeIdentity:
    """This node's identity."""
    node_id: str
    display_name: str
    endpoint: str
    fingerprint: str
    created_at: str
    metadata: dict = field(default_factory=dict)


class MeshNode:
    """
    P2P mesh node for IMMUNIS antibody distribution.

    Manages:
    - This node's identity and key pair
    - Peer connections (WebSocket)
    - Heartbeat monitoring
    - Peer discovery via gossip
    - Connection health tracking

    Usage:
        node = MeshNode(node_id="node-001", port=8765)
        await node.start()
        await node.connect_to_peer("ws://peer:8765")
        await node.broadcast(antibody_bytes)
        await node.stop()
    """

    HEARTBEAT_INTERVAL_S = 30
    HEARTBEAT_TIMEOUT_S = 10
    MAX_MISSED_HEARTBEATS = 3
    PEER_PRUNE_INTERVAL_S = 60
    MAX_PEERS = 50
    RECONNECT_DELAY_S = 5
    MAX_RECONNECT_ATTEMPTS = 5

    def __init__(
        self,
        node_id: Optional[str] = None,
        display_name: Optional[str] = None,
        port: int = 8765,
        host: str = "0.0.0.0",
    ):
        if node_id is None:
            try:
                from backend.config import config
                node_id = config.immunis_node_id
                port = config.immunis_mesh_port
            except (ImportError, AttributeError):
                node_id = f"node-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"

        self._node_id = node_id
        self._display_name = display_name or node_id
        self._host = host
        self._port = port
        self._endpoint = f"ws://{host}:{port}"

        # Peer management
        self._peers: dict[str, PeerInfo] = {}
        self._connections: dict[str, object] = {}  # node_id → websocket
        self._reconnect_attempts: dict[str, int] = {}

        # Identity
        self._identity: Optional[NodeIdentity] = None
        self._fingerprint: Optional[str] = None

        # Background tasks
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._prune_task: Optional[asyncio.Task] = None
        self._server = None
        self._running = False

        # Message handlers
        self._message_handlers: dict[str, list] = {}

        # Statistics
        self._messages_sent: int = 0
        self._messages_received: int = 0
        self._bytes_sent: int = 0
        self._bytes_received: int = 0
        self._started_at: Optional[str] = None

        logger.info(
            f"Mesh node created: {node_id} on {host}:{port}"
        )

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def peer_count(self) -> int:
        return len(self._peers)

    @property
    def online_peer_count(self) -> int:
        return sum(
            1 for p in self._peers.values()
            if p.status == PeerStatus.ONLINE
        )

    async def start(self, crypto=None) -> None:
        """
        Start the mesh node.

        Initialises identity, starts WebSocket server,
        begins heartbeat and peer pruning loops.
        """
        if self._running:
            logger.warning("Mesh node already running")
            return

        # Initialise identity
        if crypto:
            keypair = crypto.get_keypair()
            if keypair is None:
                keypair = crypto.generate_keypair(self._node_id)
            self._fingerprint = keypair.fingerprint
        else:
            self._fingerprint = hashlib.sha256(
                self._node_id.encode()
            ).hexdigest()[:16]

        self._identity = NodeIdentity(
            node_id=self._node_id,
            display_name=self._display_name,
            endpoint=self._endpoint,
            fingerprint=self._fingerprint,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        self._running = True
        self._started_at = datetime.now(timezone.utc).isoformat()

        # Start background tasks
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._prune_task = asyncio.create_task(self._prune_loop())

        # Connect to initial peers
        try:
            from backend.config import config
            initial_peers = config.immunis_mesh_peers
            if initial_peers:
                peers = [p.strip() for p in initial_peers.split(",") if p.strip()]
                for peer_endpoint in peers:
                    asyncio.create_task(self.connect_to_peer(peer_endpoint))
        except (ImportError, AttributeError):
            pass

        logger.info(
            f"Mesh node started: {self._node_id} "
            f"(fingerprint={self._fingerprint})"
        )

    async def stop(self) -> None:
        """Stop the mesh node and close all connections."""
        self._running = False

        # Cancel background tasks
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None

        if self._prune_task:
            self._prune_task.cancel()
            self._prune_task = None

        # Close all peer connections
        for node_id, ws in list(self._connections.items()):
            try:
                if hasattr(ws, 'close'):
                    await ws.close()
            except Exception as e:
                logger.debug(f"Error closing connection to {node_id}: {e}")

        self._connections.clear()

        # Update all peers to offline
        for peer in self._peers.values():
            peer.status = PeerStatus.OFFLINE

        logger.info(f"Mesh node stopped: {self._node_id}")

    async def connect_to_peer(
        self,
        endpoint: str,
        node_id: Optional[str] = None,
        display_name: Optional[str] = None,
    ) -> bool:
        """
        Connect to a peer node.

        Args:
            endpoint: WebSocket endpoint (ws://host:port).
            node_id: Known node ID (discovered during handshake if not provided).
            display_name: Human-readable name.

        Returns:
            True if connection established, False otherwise.
        """
        if not self._running:
            return False

        # Prevent self-connection
        if endpoint == self._endpoint:
            return False

        # Check if already connected
        if node_id and node_id in self._connections:
            logger.debug(f"Already connected to {node_id}")
            return True

        # Check peer limit
        if len(self._peers) >= self.MAX_PEERS:
            logger.warning(f"Max peers ({self.MAX_PEERS}) reached — rejecting {endpoint}")
            return False

        try:
            import websockets

            ws = await asyncio.wait_for(
                websockets.connect(endpoint),
                timeout=10.0,
            )

            # Perform handshake
            handshake = {
                "type": "handshake",
                "node_id": self._node_id,
                "display_name": self._display_name,
                "fingerprint": self._fingerprint,
                "endpoint": self._endpoint,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            await ws.send(json.dumps(handshake))

            # Wait for handshake response
            response_raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
            response = json.loads(response_raw)

            peer_node_id = response.get("node_id", node_id or endpoint)
            peer_fingerprint = response.get("fingerprint", "")
            peer_display_name = response.get("display_name", display_name or peer_node_id)

            # Register peer
            peer = PeerInfo(
                node_id=peer_node_id,
                endpoint=endpoint,
                display_name=peer_display_name,
                fingerprint=peer_fingerprint,
                status=PeerStatus.ONLINE,
                connected_at=datetime.now(timezone.utc).isoformat(),
                last_heartbeat=datetime.now(timezone.utc).isoformat(),
                public_keys=response.get("public_keys", {}),
            )

            self._peers[peer_node_id] = peer
            self._connections[peer_node_id] = ws
            self._reconnect_attempts[peer_node_id] = 0

            # Start receiving messages from this peer
            asyncio.create_task(self._receive_loop(peer_node_id, ws))

            logger.info(
                f"Connected to peer: {peer_node_id} ({endpoint}) "
                f"fingerprint={peer_fingerprint}"
            )

            return True

        except asyncio.TimeoutError:
            logger.warning(f"Connection to {endpoint} timed out")
            return False
        except ImportError:
            logger.warning(
                "websockets library not available — mesh connections disabled. "
                "Install with: pip install websockets"
            )
            return False
        except Exception as e:
            logger.warning(f"Failed to connect to {endpoint}: {e}")
            return False

    async def disconnect_peer(self, node_id: str) -> bool:
        """Disconnect from a specific peer."""
        ws = self._connections.pop(node_id, None)
        if ws:
            try:
                if hasattr(ws, 'close'):
                    await ws.close()
            except Exception:
                pass

        peer = self._peers.get(node_id)
        if peer:
            peer.status = PeerStatus.OFFLINE
            logger.info(f"Disconnected from peer: {node_id}")
            return True

        return False

    def register_peer(self, peer_info: PeerInfo) -> None:
        """Register a peer without connecting (for gossip discovery)."""
        if peer_info.node_id == self._node_id:
            return
        if peer_info.node_id not in self._peers:
            peer_info.status = PeerStatus.UNKNOWN
            self._peers[peer_info.node_id] = peer_info
            logger.debug(f"Peer registered via gossip: {peer_info.node_id}")

    async def broadcast(
        self,
        message: bytes,
        message_type: str = "antibody",
        exclude_node: Optional[str] = None,
    ) -> int:
        """
        Broadcast a message to all connected peers.

        Args:
            message: Raw message bytes.
            message_type: Type identifier for routing.
            exclude_node: Node ID to exclude (prevent echo).

        Returns:
            Number of peers the message was sent to.
        """
        if not self._running:
            return 0

        envelope = json.dumps({
            "type": message_type,
            "sender": self._node_id,
            "fingerprint": self._fingerprint,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": message.hex() if isinstance(message, bytes) else message,
            "size": len(message),
        })

        sent_count = 0
        failed_peers = []

        for node_id, ws in list(self._connections.items()):
            if node_id == exclude_node:
                continue

            try:
                await asyncio.wait_for(ws.send(envelope), timeout=5.0)
                sent_count += 1
                self._messages_sent += 1
                self._bytes_sent += len(envelope)

                # Update peer stats
                peer = self._peers.get(node_id)
                if peer:
                    peer.antibodies_sent += 1

            except Exception as e:
                logger.warning(f"Failed to send to {node_id}: {e}")
                failed_peers.append(node_id)

        # Handle failed peers
        for node_id in failed_peers:
            peer = self._peers.get(node_id)
            if peer:
                peer.status = PeerStatus.DEGRADED

        logger.info(
            f"Broadcast {message_type}: sent to {sent_count}/{len(self._connections)} peers"
        )

        return sent_count

    async def send_to_peer(
        self,
        node_id: str,
        message: bytes,
        message_type: str = "direct",
    ) -> bool:
        """Send a message to a specific peer."""
        ws = self._connections.get(node_id)
        if ws is None:
            logger.warning(f"No connection to peer {node_id}")
            return False

        try:
            envelope = json.dumps({
                "type": message_type,
                "sender": self._node_id,
                "fingerprint": self._fingerprint,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": message.hex() if isinstance(message, bytes) else message,
            })

            await asyncio.wait_for(ws.send(envelope), timeout=5.0)
            self._messages_sent += 1
            self._bytes_sent += len(envelope)
            return True

        except Exception as e:
            logger.warning(f"Failed to send to {node_id}: {e}")
            return False

    def on_message(self, message_type: str, handler) -> None:
        """Register a handler for a specific message type."""
        if message_type not in self._message_handlers:
            self._message_handlers[message_type] = []
        self._message_handlers[message_type].append(handler)

    # ------------------------------------------------------------------
    # BACKGROUND LOOPS
    # ------------------------------------------------------------------

    async def _receive_loop(self, node_id: str, ws) -> None:
        """Receive messages from a peer."""
        try:
            async for raw_message in ws:
                self._messages_received += 1
                self._bytes_received += len(raw_message)

                try:
                    message = json.loads(raw_message)
                    msg_type = message.get("type", "unknown")

                    # Handle heartbeat
                    if msg_type == "heartbeat":
                        await self._handle_heartbeat(node_id, message)
                        continue

                    # Handle heartbeat response
                    if msg_type == "heartbeat_ack":
                        self._handle_heartbeat_ack(node_id, message)
                        continue

                    # Handle peer list (gossip)
                    if msg_type == "peer_list":
                        await self._handle_peer_list(message)
                        continue

                    # Handle handshake (incoming connection)
                    if msg_type == "handshake":
                        await self._handle_incoming_handshake(node_id, ws, message)
                        continue

                    # Dispatch to registered handlers
                    handlers = self._message_handlers.get(msg_type, [])
                    for handler in handlers:
                        try:
                            if asyncio.iscoroutinefunction(handler):
                                await handler(message)
                            else:
                                handler(message)
                        except Exception as e:
                            logger.error(
                                f"Message handler error for {msg_type}: {e}"
                            )

                    # Update peer stats
                    peer = self._peers.get(node_id)
                    if peer and msg_type == "antibody":
                        peer.antibodies_received += 1

                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON from {node_id}")
                except Exception as e:
                    logger.error(f"Error processing message from {node_id}: {e}")

        except Exception as e:
            logger.info(f"Connection to {node_id} closed: {e}")

        # Connection closed — update status
        self._connections.pop(node_id, None)
        peer = self._peers.get(node_id)
        if peer:
            peer.status = PeerStatus.OFFLINE

        # Attempt reconnection
        if self._running and node_id in self._peers:
            asyncio.create_task(self._attempt_reconnect(node_id))

    async def _heartbeat_loop(self) -> None:
        """Send heartbeats to all connected peers."""
        try:
            while self._running:
                await asyncio.sleep(self.HEARTBEAT_INTERVAL_S)

                for node_id, ws in list(self._connections.items()):
                    try:
                        heartbeat = json.dumps({
                            "type": "heartbeat",
                            "sender": self._node_id,
                            "timestamp": time.time(),
                            "immunity_score": self._get_local_immunity_score(),
                        })
                        await asyncio.wait_for(ws.send(heartbeat), timeout=self.HEARTBEAT_TIMEOUT_S)

                        peer = self._peers.get(node_id)
                        if peer:
                            peer.heartbeats_sent += 1

                    except Exception as e:
                        logger.debug(f"Heartbeat to {node_id} failed: {e}")
                        peer = self._peers.get(node_id)
                        if peer:
                            peer.heartbeats_missed += 1

        except asyncio.CancelledError:
            logger.debug("Heartbeat loop cancelled")

    async def _prune_loop(self) -> None:
        """Prune dead peers and attempt reconnection."""
        try:
            while self._running:
                await asyncio.sleep(self.PEER_PRUNE_INTERVAL_S)

                now = datetime.now(timezone.utc)

                for node_id, peer in list(self._peers.items()):
                    if peer.status == PeerStatus.BANNED:
                        continue

                    if peer.heartbeats_missed >= self.MAX_MISSED_HEARTBEATS:
                        if node_id in self._connections:
                            await self.disconnect_peer(node_id)
                        peer.status = PeerStatus.OFFLINE
                        logger.info(
                            f"Peer {node_id} pruned: "
                            f"{peer.heartbeats_missed} missed heartbeats"
                        )

                # Share peer list with connected peers (gossip)
                await self._gossip_peer_list()

        except asyncio.CancelledError:
            logger.debug("Prune loop cancelled")

    async def _handle_heartbeat(self, node_id: str, message: dict) -> None:
        """Handle incoming heartbeat from a peer."""
        peer = self._peers.get(node_id)
        if peer:
            peer.last_heartbeat = datetime.now(timezone.utc).isoformat()
            peer.heartbeats_received += 1
            peer.heartbeats_missed = 0
            peer.status = PeerStatus.ONLINE

            # Update peer's immunity score
            peer.immunity_score = message.get("immunity_score", 0.0)

        # Send ack
        ws = self._connections.get(node_id)
        if ws:
            try:
                ack = json.dumps({
                    "type": "heartbeat_ack",
                    "sender": self._node_id,
                    "timestamp": time.time(),
                    "original_timestamp": message.get("timestamp", 0),
                })
                await ws.send(ack)
            except Exception:
                pass

    def _handle_heartbeat_ack(self, node_id: str, message: dict) -> None:
        """Handle heartbeat acknowledgement — compute latency."""
        peer = self._peers.get(node_id)
        if peer:
            original_ts = message.get("original_timestamp", 0)
            if original_ts > 0:
                latency_ms = (time.time() - original_ts) * 1000
                peer.last_latency_ms = latency_ms

                # Exponential moving average
                alpha = 0.3
                if peer.avg_latency_ms == 0:
                    peer.avg_latency_ms = latency_ms
                else:
                    peer.avg_latency_ms = (
                        alpha * latency_ms + (1 - alpha) * peer.avg_latency_ms
                    )

    async def _handle_peer_list(self, message: dict) -> None:
        """Handle peer list from gossip — discover new peers."""
        peers = message.get("peers", [])
        for peer_data in peers:
            peer_id = peer_data.get("node_id")
            endpoint = peer_data.get("endpoint")

            if not peer_id or not endpoint:
                continue
            if peer_id == self._node_id:
                continue
            if peer_id in self._peers:
                continue

            # Register discovered peer
            peer = PeerInfo(
                node_id=peer_id,
                endpoint=endpoint,
                display_name=peer_data.get("display_name"),
                fingerprint=peer_data.get("fingerprint"),
                status=PeerStatus.UNKNOWN,
            )
            self.register_peer(peer)

            # Attempt connection
            if len(self._connections) < self.MAX_PEERS:
                asyncio.create_task(self.connect_to_peer(endpoint, peer_id))

    async def _handle_incoming_handshake(
        self,
        node_id: str,
        ws,
        message: dict,
    ) -> None:
        """Handle incoming handshake from a connecting peer."""
        peer_id = message.get("node_id", node_id)

        # Send handshake response
        response = {
            "type": "handshake_ack",
            "node_id": self._node_id,
            "display_name": self._display_name,
            "fingerprint": self._fingerprint,
            "endpoint": self._endpoint,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            await ws.send(json.dumps(response))
        except Exception:
            pass

    async def _gossip_peer_list(self) -> None:
        """Share peer list with connected peers."""
        peer_list = []
        for peer in self._peers.values():
            if peer.status in (PeerStatus.ONLINE, PeerStatus.DEGRADED):
                peer_list.append({
                    "node_id": peer.node_id,
                    "endpoint": peer.endpoint,
                    "display_name": peer.display_name,
                    "fingerprint": peer.fingerprint,
                })

        if not peer_list:
            return

        message = json.dumps({
            "type": "peer_list",
            "sender": self._node_id,
            "peers": peer_list,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        for ws in self._connections.values():
            try:
                await asyncio.wait_for(ws.send(message), timeout=5.0)
            except Exception:
                pass

    async def _attempt_reconnect(self, node_id: str) -> None:
        """Attempt to reconnect to a disconnected peer."""
        peer = self._peers.get(node_id)
        if not peer:
            return

        attempts = self._reconnect_attempts.get(node_id, 0)
        if attempts >= self.MAX_RECONNECT_ATTEMPTS:
            logger.info(f"Max reconnect attempts reached for {node_id}")
            return

        delay = self.RECONNECT_DELAY_S * (2 ** attempts)  # Exponential backoff
        await asyncio.sleep(delay)

        if not self._running:
            return

        self._reconnect_attempts[node_id] = attempts + 1
        logger.info(
            f"Reconnecting to {node_id} (attempt {attempts + 1}/"
            f"{self.MAX_RECONNECT_ATTEMPTS})"
        )

        success = await self.connect_to_peer(peer.endpoint, node_id)
        if success:
            self._reconnect_attempts[node_id] = 0

    def _get_local_immunity_score(self) -> float:
        """Get the local node's immunity score."""
        try:
            from backend.agents.evolution_tracker import get_evolution_tracker
            tracker = get_evolution_tracker()
            return tracker.get_current_score()
        except Exception:
            return 0.0

    # ------------------------------------------------------------------
    # QUERY METHODS
    # ------------------------------------------------------------------

    def get_peer(self, node_id: str) -> Optional[PeerInfo]:
        """Get info about a specific peer."""
        return self._peers.get(node_id)

    def get_peers(
        self,
        status: Optional[PeerStatus] = None,
    ) -> list[PeerInfo]:
        """Get all peers, optionally filtered by status."""
        if status:
            return [p for p in self._peers.values() if p.status == status]
        return list(self._peers.values())

    def get_online_peers(self) -> list[PeerInfo]:
        """Get all online peers."""
        return self.get_peers(PeerStatus.ONLINE)

    def get_identity(self) -> Optional[NodeIdentity]:
        """Get this node's identity."""
        return self._identity

    def ban_peer(self, node_id: str, reason: str = "") -> bool:
        """Ban a peer (e.g., for sending invalid signatures)."""
        peer = self._peers.get(node_id)
        if peer:
            peer.status = PeerStatus.BANNED
            peer.metadata["ban_reason"] = reason
            peer.metadata["banned_at"] = datetime.now(timezone.utc).isoformat()

            # Disconnect if connected
            if node_id in self._connections:
                asyncio.create_task(self.disconnect_peer(node_id))

            logger.warning(f"Peer BANNED: {node_id} — {reason}")
            return True
        return False

    def get_status(self) -> dict:
        """Return mesh node status for API/dashboard."""
        return {
            "node_id": self._node_id,
            "display_name": self._display_name,
            "endpoint": self._endpoint,
            "fingerprint": self._fingerprint,
            "running": self._running,
            "started_at": self._started_at,
            "total_peers": len(self._peers),
            "online_peers": self.online_peer_count,
            "connected_peers": len(self._connections),
            "messages_sent": self._messages_sent,
            "messages_received": self._messages_received,
            "bytes_sent": self._bytes_sent,
            "bytes_received": self._bytes_received,
            "peers": [p.to_dict() for p in self._peers.values()],
        }


# Module-level singleton
_node: Optional[MeshNode] = None


def get_mesh_node() -> MeshNode:
    """Get or create the singleton MeshNode instance."""
    global _node
    if _node is None:
        _node = MeshNode()
    return _node
