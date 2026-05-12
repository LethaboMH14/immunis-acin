"""
IMMUNIS ACIN — Simulated Mesh Node: Tshwane Metropolitan Municipality

Simulates a remote IMMUNIS deployment at the City of Tshwane (Pretoria).
Connects to the main IMMUNIS backend via WebSocket, receives antibody broadcasts,
and simulates detection of incoming threats using received antibodies.

This node:
1. Connects to the main IMMUNIS backend via WebSocket
2. Announces itself with node identity (name, location, capabilities)
3. Receives antibody broadcasts from the mesh
4. Simulates "installing" antibodies with a short delay
5. Periodically reports health status
6. When the demo script sends the "same attack hits Tshwane" moment,
   this node reports an instant block using the received antibody

Usage:
    python demo/mesh_nodes/node_tshwane.py

    # Or with custom backend URL:
    python demo/mesh_nodes/node_tshwane.py --url ws://localhost:8000/ws

    # With verbose logging:
    python demo/mesh_nodes/node_tshwane.py --verbose
"""

import asyncio
import json
import logging
import os
import sys
import time
import random
import hashlib
from datetime import datetime, timezone
from typing import Optional

# --- Configuration ---

WS_URL = os.environ.get("IMMUNIS_WS_URL", "ws://localhost:8000/ws")
NODE_ID = "node-tshwane-001"
NODE_NAME = "Tshwane Metropolitan Municipality"
NODE_LOCATION = "Pretoria, Gauteng, South Africa"
NODE_LAT = -25.7479
NODE_LON = 28.2293
NODE_REGION = "za-gp"
NODE_POPULATION = 3_275_152  # Metro population
NODE_SECTOR = "government"
NODE_COLOR = "#00E5A0"  # Green — primary demo node

VERBOSE = "--verbose" in sys.argv or "-v" in sys.argv

# Parse custom URL
for i, arg in enumerate(sys.argv):
    if arg == "--url" and i + 1 < len(sys.argv):
        WS_URL = sys.argv[i + 1]

# --- Logging ---

logging.basicConfig(
    level=logging.DEBUG if VERBOSE else logging.INFO,
    format="%(asctime)s [TSHWANE] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("tshwane")

# --- Node State ---

class MeshNodeSimulator:
    """
    Simulates an IMMUNIS mesh node.
    
    Maintains local state:
    - Received antibodies (immune memory)
    - Health metrics
    - Detection statistics
    """

    def __init__(self, node_id: str, node_name: str):
        self.node_id = node_id
        self.node_name = node_name
        self.antibodies: dict[str, dict] = {}  # antibody_id → antibody data
        self.threats_blocked: int = 0
        self.threats_received: int = 0
        self.connected: bool = False
        self.connect_time: Optional[float] = None
        self.last_heartbeat: float = 0
        self.immunity_score: float = 65.0  # Starting immunity
        self.status: str = "initializing"

    @property
    def uptime_seconds(self) -> float:
        if not self.connect_time:
            return 0
        return time.time() - self.connect_time

    def receive_antibody(self, antibody: dict) -> dict:
        """
        Process a received antibody broadcast.
        
        Simulates:
        1. Signature verification (instant)
        2. Compatibility check (instant)
        3. Installation into local immune memory (short delay)
        4. Immunity score update
        """
        ab_id = antibody.get("antibody_id", antibody.get("id", "unknown"))
        
        if ab_id in self.antibodies:
            logger.debug("Antibody %s already installed — skipping", ab_id)
            return {"status": "duplicate", "antibody_id": ab_id}

        # Simulate verification
        logger.info("Verifying antibody %s...", ab_id)
        
        # Install
        self.antibodies[ab_id] = {
            "antibody_id": ab_id,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "attack_family": antibody.get("attack_family", "Unknown"),
            "strength": antibody.get("strength", 0.85),
            "source_node": antibody.get("source_node", "origin"),
            "language": antibody.get("language", "en"),
            "verified": True,
        }

        # Update immunity
        boost = min(antibody.get("strength", 0.85) * 5, 8)
        self.immunity_score = min(self.immunity_score + boost, 99)

        logger.info(
            "✓ Antibody %s installed | Family: %s | Strength: %.2f | Immunity: %.1f",
            ab_id,
            antibody.get("attack_family", "?"),
            antibody.get("strength", 0),
            self.immunity_score,
        )

        return {
            "status": "installed",
            "antibody_id": ab_id,
            "node_id": self.node_id,
            "immunity_score": self.immunity_score,
            "total_antibodies": len(self.antibodies),
        }

    def check_threat(self, threat_content: str) -> dict:
        """
        Check an incoming threat against installed antibodies.
        
        If a matching antibody exists, return instant block.
        This is the "same attack hits Tshwane" demo moment.
        """
        self.threats_received += 1

        # Simple matching: check if any antibody's attack family
        # is mentioned or if content similarity is high
        for ab_id, ab in self.antibodies.items():
            family = ab.get("attack_family", "").lower()
            content_lower = threat_content.lower()
            
            # Check for family keywords in content
            family_keywords = family.replace("_", " ").split()
            matches = sum(1 for kw in family_keywords if kw in content_lower)
            
            if matches >= 2 or family in content_lower:
                self.threats_blocked += 1
                block_time_ms = random.uniform(50, 180)  # Fast — from memory

                logger.info(
                    "🛡️ THREAT BLOCKED in %.0fms | Antibody: %s | Family: %s",
                    block_time_ms, ab_id, ab.get("attack_family", "?"),
                )

                return {
                    "status": "blocked",
                    "node_id": self.node_id,
                    "antibody_id": ab_id,
                    "attack_family": ab.get("attack_family", "Unknown"),
                    "block_time_ms": round(block_time_ms, 1),
                    "from_mesh": True,
                    "note": "Blocked using antibody received from mesh — this node was never directly attacked",
                }

        # No match — would need full pipeline
        logger.warning("⚠ No matching antibody — threat requires full pipeline analysis")
        return {
            "status": "no_match",
            "node_id": self.node_id,
            "note": "No matching antibody in local memory. Would require full 7-stage AIR pipeline.",
        }

    def get_health(self) -> dict:
        """Generate health report for the main node."""
        return {
            "node_id": self.node_id,
            "node_name": self.node_name,
            "status": self.status,
            "location": NODE_LOCATION,
            "coordinates": {"lat": NODE_LAT, "lon": NODE_LON},
            "region": NODE_REGION,
            "sector": NODE_SECTOR,
            "immunity_score": round(self.immunity_score, 1),
            "antibodies_installed": len(self.antibodies),
            "threats_blocked": self.threats_blocked,
            "threats_received": self.threats_received,
            "uptime_seconds": round(self.uptime_seconds, 1),
            "connected": self.connected,
            "last_heartbeat": datetime.now(timezone.utc).isoformat(),
            "population_protected": NODE_POPULATION,
            "color": NODE_COLOR,
        }


async def run_node():
    """Main node loop — connect via WebSocket and process messages."""
    
    try:
        import websockets
    except ImportError:
        # Fallback to httpx WebSocket or basic implementation
        logger.error("websockets package not installed. Install with: pip install websockets")
        logger.info("Falling back to HTTP polling mode...")
        await run_node_polling()
        return

    node = MeshNodeSimulator(NODE_ID, NODE_NAME)

    while True:
        try:
            logger.info("Connecting to %s...", WS_URL)
            
            async with websockets.connect(WS_URL) as ws:
                node.connected = True
                node.connect_time = time.time()
                node.status = "online"

                # Send handshake
                handshake = {
                    "type": "mesh_node_connect",
                    "node": node.get_health(),
                }
                await ws.send(json.dumps(handshake))
                logger.info("✓ Connected to mesh network as %s", NODE_NAME)

                # Start heartbeat task
                heartbeat_task = asyncio.create_task(
                    heartbeat_loop(ws, node)
                )

                try:
                    # Message loop
                    async for message in ws:
                        try:
                            data = json.loads(message)
                            await handle_message(ws, node, data)
                        except json.JSONDecodeError:
                            logger.warning("Invalid JSON received: %s", message[:100])
                        except Exception as e:
                            logger.error("Error handling message: %s", e)

                except websockets.ConnectionClosed as e:
                    logger.warning("Connection closed: %s", e)
                finally:
                    heartbeat_task.cancel()
                    node.connected = False
                    node.status = "disconnected"

        except ConnectionRefusedError:
            logger.warning("Connection refused — backend not running? Retrying in 5s...")
        except Exception as e:
            logger.error("Connection error: %s. Retrying in 5s...", e)

        node.connected = False
        node.status = "reconnecting"
        await asyncio.sleep(5)


async def run_node_polling():
    """Fallback: HTTP polling mode if websockets not available."""
    import httpx
    
    node = MeshNodeSimulator(NODE_ID, NODE_NAME)
    http_base = WS_URL.replace("ws://", "http://").replace("/ws", "")
    
    logger.info("Running in HTTP polling mode (fallback)")
    node.connected = True
    node.connect_time = time.time()
    node.status = "online"

    async with httpx.AsyncClient() as client:
        while True:
            try:
                # Report health
                health = node.get_health()
                try:
                    await client.post(
                        f"{http_base}/api/mesh/node-report",
                        json=health,
                        timeout=10,
                    )
                    logger.debug("Health reported")
                except Exception:
                    pass

                await asyncio.sleep(10)

            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error("Polling error: %s", e)
                await asyncio.sleep(5)


async def heartbeat_loop(ws, node: MeshNodeSimulator):
    """Send periodic heartbeat to main node."""
    while True:
        try:
            await asyncio.sleep(15)  # Every 15 seconds
            heartbeat = {
                "type": "mesh_heartbeat",
                "node": node.get_health(),
            }
            await ws.send(json.dumps(heartbeat))
            node.last_heartbeat = time.time()
            logger.debug("Heartbeat sent | Immunity: %.1f | Antibodies: %d",
                         node.immunity_score, len(node.antibodies))
        except Exception as e:
            logger.debug("Heartbeat failed: %s", e)
            break


async def handle_message(ws, node: MeshNodeSimulator, data: dict):
    """Handle an incoming WebSocket message from the main node."""
    msg_type = data.get("type", data.get("event", ""))

    if msg_type in ("antibody_broadcast", "mesh_broadcast", "antibody_promoted"):
        # Receive antibody from mesh
        antibody = data.get("antibody", data.get("data", data))
        
        # Simulate network delay
        delay = random.uniform(0.1, 0.5)
        await asyncio.sleep(delay)
        
        result = node.receive_antibody(antibody)
        
        # Report back
        response = {
            "type": "antibody_received",
            "node_id": node.node_id,
            "result": result,
            "network_delay_ms": round(delay * 1000, 1),
        }
        await ws.send(json.dumps(response))

    elif msg_type in ("threat_check", "test_threat"):
        # Check a threat against local antibodies
        content = data.get("content", data.get("threat_content", ""))
        result = node.check_threat(content)
        
        response = {
            "type": "threat_check_result",
            "node_id": node.node_id,
            "result": result,
        }
        await ws.send(json.dumps(response))

    elif msg_type in ("ping", "heartbeat_request"):
        # Respond to ping
        await ws.send(json.dumps({
            "type": "pong",
            "node": node.get_health(),
        }))

    elif msg_type == "status_request":
        # Full status report
        await ws.send(json.dumps({
            "type": "status_response",
            "node": node.get_health(),
            "antibodies": list(node.antibodies.keys()),
        }))

    elif msg_type in ("threat_detected", "pipeline_complete", "new_incident"):
        # Informational broadcast — log it
        logger.info("📡 Received: %s from mesh", msg_type)

    else:
        logger.debug("Unhandled message type: %s", msg_type)


def main():
    """Entry point."""
    print(f"\n{'='*60}")
    print(f"  IMMUNIS ACIN — Mesh Node: {NODE_NAME}")
    print(f"  Location: {NODE_LOCATION}")
    print(f"  Node ID: {NODE_ID}")
    print(f"  Connecting to: {WS_URL}")
    print(f"{'='*60}\n")

    try:
        asyncio.run(run_node())
    except KeyboardInterrupt:
        print(f"\n{'='*60}")
        print(f"  Node {NODE_NAME} shutting down gracefully")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
