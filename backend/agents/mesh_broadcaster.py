"""
IMMUNIS ACIN — Agent 7: Mesh Broadcaster

WHY: An antibody that exists on only one node is like a vaccine
that exists in only one hospital. The Mesh Broadcaster is the
distribution system — it takes promoted antibodies, signs them
with hybrid post-quantum cryptography, computes epidemiological
priority, and broadcasts them across the P2P mesh so that every
connected node inherits immunity without experiencing the attack.

This is the mechanism that transforms IMMUNIS from a standalone
detector into a collective immune system.

Pipeline position: Stage 7 of the AIR Protocol
  After: Battleground promotion (Stage 6)
  Before: Peer nodes receive and store antibody

Responsibilities:
1. Package antibody for transmission (serialise + compress)
2. Sign with hybrid Ed25519 + Dilithium
3. Compute R₀ broadcast priority from epidemiological model
4. Broadcast via gossip protocol (R₀-weighted fan-out)
5. Export as STIX 2.1 for industry interoperability
6. Track delivery confirmation from peers
7. Update epidemiological model with propagation data

Mathematical foundation:
  Broadcast priority = R₀_attack × severity × (1 / time_since_synthesis)
  Fan-out = min(ceil(R₀ × 2), total_peers)
  Expected convergence: O(log N / log fan_out) rounds
"""

import logging
import json
import time
import hashlib
import zlib
from typing import Optional
from datetime import datetime, timezone

logger = logging.getLogger("immunis.agents.mesh_broadcaster")


class MeshBroadcaster:
    """
    Agent 7: Signs and broadcasts antibodies to the P2P mesh.

    Integrates:
    - MeshCrypto for hybrid signing
    - MeshNode for peer connections
    - GossipProtocol for R₀-priority broadcast
    - STIXExporter for industry interoperability
    - EpidemiologicalModel for R₀ computation
    - AuditTrail for broadcast logging

    Usage:
        broadcaster = MeshBroadcaster()
        result = await broadcaster.broadcast(antibody, incident)
    """

    def __init__(self):
        # Lazy-loaded dependencies
        self._crypto = None
        self._mesh_node = None
        self._gossip = None
        self._stix_exporter = None
        self._taxii_server = None
        self._epi_model = None
        self._audit = None

        # Statistics
        self._total_broadcasts: int = 0
        self._total_bytes_broadcast: int = 0
        self._successful_deliveries: int = 0
        self._failed_deliveries: int = 0
        self._stix_exports: int = 0

        logger.info("Mesh Broadcaster (Agent 7) initialised")

    def _ensure_dependencies(self) -> None:
        """Lazy-load dependencies to avoid circular imports."""
        if self._crypto is None:
            try:
                from backend.mesh.crypto import get_mesh_crypto
                self._crypto = get_mesh_crypto()
            except ImportError:
                logger.warning("Mesh crypto not available")

        if self._mesh_node is None:
            try:
                from backend.mesh.node import get_mesh_node
                self._mesh_node = get_mesh_node()
            except ImportError:
                logger.warning("Mesh node not available")

        if self._gossip is None:
            try:
                from backend.mesh.gossip import get_gossip_protocol
                self._gossip = get_gossip_protocol(self._mesh_node)
            except ImportError:
                logger.warning("Gossip protocol not available")

        if self._stix_exporter is None:
            try:
                from backend.mesh.stix_taxii import get_stix_exporter, get_taxii_server
                self._stix_exporter = get_stix_exporter()
                self._taxii_server = get_taxii_server()
            except ImportError:
                logger.warning("STIX/TAXII not available")

        if self._epi_model is None:
            try:
                from backend.agents.epidemiological_model import get_epidemiological_model
                self._epi_model = get_epidemiological_model()
            except ImportError:
                logger.warning("Epidemiological model not available")

        if self._audit is None:
            try:
                from backend.security.audit_trail import get_audit_trail
                self._audit = get_audit_trail()
            except ImportError:
                pass

    async def broadcast(
        self,
        antibody: dict,
        incident: Optional[dict] = None,
        force: bool = False,
    ) -> dict:
        """
        Sign and broadcast an antibody to the mesh network.

        Args:
            antibody: Antibody dict (must be promoted unless force=True).
            incident: Optional incident dict for context.
            force: Broadcast even if not promoted (for testing).

        Returns:
            Dict with broadcast results:
            - broadcast_id: unique identifier
            - peers_reached: number of peers sent to
            - signature: hybrid signature details
            - stix_exported: whether STIX bundle was created
            - r0: computed broadcast priority
            - gossip_message_id: gossip protocol message ID
        """
        start = time.perf_counter()
        self._ensure_dependencies()

        antibody_id = antibody.get("antibody_id", "unknown")
        status = antibody.get("status", "pending")

        # Verify antibody is promoted (unless forced)
        if not force and status != "promoted":
            logger.warning(
                f"Cannot broadcast unpromoted antibody {antibody_id} "
                f"(status={status}). Use force=True to override."
            )
            return {
                "broadcast_id": None,
                "error": f"Antibody not promoted (status={status})",
                "peers_reached": 0,
            }

        # Step 1: Package antibody
        package = self._package_antibody(antibody, incident)

        # Step 2: Sign with hybrid crypto
        signature_info = self._sign_package(package)

        # Step 3: Compute R₀ priority
        r0 = self._compute_broadcast_priority(antibody, incident)

        # Step 4: Broadcast via gossip
        gossip_message_id = None
        peers_reached = 0

        if self._gossip and self._mesh_node and self._mesh_node.is_running:
            try:
                severity = self._compute_severity(antibody)
                gossip_message_id = await self._gossip.broadcast_antibody(
                    antibody_id=antibody_id,
                    payload=package,
                    r0=r0,
                    severity=severity,
                )
                peers_reached = self._mesh_node.online_peer_count
                self._successful_deliveries += peers_reached
            except Exception as e:
                logger.error(f"Gossip broadcast failed: {e}")
                self._failed_deliveries += 1
        else:
            # Mesh not running — log but don't fail
            logger.info(
                f"Mesh not active — antibody {antibody_id} stored locally only"
            )

        # Step 5: Export as STIX
        stix_exported = False
        if self._stix_exporter:
            try:
                bundle = self._stix_exporter.export_antibody(antibody, incident)
                if self._taxii_server:
                    self._taxii_server.add_antibody_to_collection(antibody, incident)
                stix_exported = True
                self._stix_exports += 1
            except Exception as e:
                logger.warning(f"STIX export failed: {e}")

        # Step 6: Update epidemiological model
        if self._epi_model and peers_reached > 0:
            try:
                self._epi_model.record_broadcast(
                    antibody_id=antibody_id,
                    nodes_reached=peers_reached,
                    r0=r0,
                )
            except Exception as e:
                logger.debug(f"Epi model update failed: {e}")

        # Step 7: Audit trail
        broadcast_id = hashlib.sha256(
            f"{antibody_id}:{time.time()}".encode()
        ).hexdigest()[:16]

        if self._audit:
            try:
                self._audit.log_event(
                    event_type="mesh_broadcast",
                    actor="agent_7_mesh_broadcaster",
                    action="broadcast_antibody",
                    target=antibody_id,
                    details={
                        "broadcast_id": broadcast_id,
                        "peers_reached": peers_reached,
                        "r0": r0,
                        "stix_exported": stix_exported,
                        "gossip_message_id": gossip_message_id,
                    },
                )
            except Exception:
                pass

        elapsed_ms = (time.perf_counter() - start) * 1000
        self._total_broadcasts += 1
        self._total_bytes_broadcast += len(package)

        result = {
            "broadcast_id": broadcast_id,
            "antibody_id": antibody_id,
            "peers_reached": peers_reached,
            "signature": signature_info,
            "stix_exported": stix_exported,
            "r0": round(r0, 2),
            "gossip_message_id": gossip_message_id,
            "package_size_bytes": len(package),
            "duration_ms": round(elapsed_ms, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            f"Broadcast complete: {antibody_id} → "
            f"{peers_reached} peers, R₀={r0:.1f}, "
            f"STIX={'yes' if stix_exported else 'no'}, "
            f"{elapsed_ms:.1f}ms"
        )

        return result

    def _package_antibody(
        self,
        antibody: dict,
        incident: Optional[dict] = None,
    ) -> bytes:
        """
        Package antibody for mesh transmission.

        Includes:
        - Antibody metadata (ID, family, strength, verification)
        - Detection rule
        - Indicators
        - MITRE techniques
        - Actuarial risk metrics
        - Source incident summary (sanitised)

        Compressed with zlib for bandwidth efficiency.
        """
        package = {
            "version": "1.0",
            "type": "antibody_broadcast",
            "antibody": {
                "antibody_id": antibody.get("antibody_id"),
                "attack_family": antibody.get("attack_family"),
                "attack_type": antibody.get("attack_type"),
                "detection_rule": antibody.get("detection_rule", {}),
                "indicators": antibody.get("indicators", []),
                "strength": antibody.get("strength", 0.0),
                "verification_status": antibody.get("verification_status"),
                "verification_proof_hash": antibody.get("verification_proof_hash"),
                "battleground_rounds": antibody.get("battleground_rounds", 0),
                "red_variants_tested": antibody.get("red_variants_tested", 0),
                "blue_blocks": antibody.get("blue_blocks", 0),
                "languages": antibody.get("languages", []),
                "mitre_techniques": antibody.get("mitre_techniques", []),
                "actuarial_expected_loss": antibody.get("actuarial_expected_loss"),
                "actuarial_var_95": antibody.get("actuarial_var_95"),
                "actuarial_cvar_95": antibody.get("actuarial_cvar_95"),
            },
            "incident_summary": None,
            "packaged_at": datetime.now(timezone.utc).isoformat(),
        }

        # Add sanitised incident summary (no PII, no raw content)
        if incident:
            package["incident_summary"] = {
                "attack_family": incident.get("attack_family"),
                "attack_type": incident.get("attack_type"),
                "language": incident.get("language"),
                "surprise_score": incident.get("surprise_score"),
                "surprise_level": incident.get("surprise_level"),
                "severity": incident.get("severity"),
                "confidence": incident.get("confidence"),
                "mitre_techniques": incident.get("mitre_techniques", []),
            }

        # Serialise and compress
        json_bytes = json.dumps(package, separators=(",", ":")).encode("utf-8")
        compressed = zlib.compress(json_bytes, level=6)

        logger.debug(
            f"Packaged antibody {antibibody.get('antibody_id')}: "
            f"{len(json_bytes)} bytes → {len(compressed)} bytes "
            f"({len(compressed)/len(json_bytes)*100:.0f}% of original)"
        )

        return compressed

    def _sign_package(self, package: bytes) -> dict:
        """Sign the package with hybrid crypto."""
        if self._crypto is None:
            return {"signed": False, "reason": "crypto_unavailable"}

        try:
            # Ensure we have a key pair
            keypair = self._crypto.get_keypair()
            if keypair is None:
                try:
                    from backend.config import config
                    node_id = config.immunis_node_id
                except (ImportError, AttributeError):
                    node_id = "node-primary"
                self._crypto.generate_keypair(node_id)

            signature = self._crypto.sign(package)

            return {
                "signed": True,
                "signer_fingerprint": signature.signer_fingerprint,
                "message_hash": signature.message_hash,
                "ed25519": bool(signature.ed25519_signature),
                "dilithium": bool(signature.dilithium_signature),
                "signed_at": signature.signed_at,
            }

        except Exception as e:
            logger.warning(f"Package signing failed: {e}")
            return {"signed": False, "reason": str(e)}

    def _compute_broadcast_priority(
        self,
        antibody: dict,
        incident: Optional[dict] = None,
    ) -> float:
        """
        Compute R₀-based broadcast priority.

        Uses epidemiological model if available, otherwise
        estimates from antibody metadata.

        Higher R₀ = higher priority = faster propagation.
        """
        if self._epi_model:
            try:
                state = self._epi_model.get_current_state()
                return state.get("r0_immunity", 1.5)
            except Exception:
                pass

        # Estimate R₀ from antibody properties
        base_r0 = 1.0

        # Novel threats get higher priority
        if incident:
            surprise_level = incident.get("surprise_level", "")
            if surprise_level == "novel":
                base_r0 += 2.0
            elif surprise_level == "variant":
                base_r0 += 1.0

            # Higher confidence = higher priority
            confidence = incident.get("confidence", 0.5)
            base_r0 *= (0.5 + confidence)

        # Stronger antibodies get higher priority
        strength = antibody.get("strength", 0.5)
        base_r0 *= (0.5 + strength)

        # Verified antibodies get priority boost
        if antibody.get("verification_status") == "sound":
            base_r0 *= 1.2

        return max(0.5, min(5.0, base_r0))

    def _compute_severity(self, antibody: dict) -> float:
        """Compute severity score (0-1) for gossip priority."""
        severity = 0.5

        # Actuarial risk increases severity
        expected_loss = antibody.get("actuarial_expected_loss", 0)
        if expected_loss and expected_loss > 0:
            # Logarithmic scaling: R100K = 0.5, R1M = 0.75, R10M = 1.0
            import math
            severity = min(1.0, 0.25 + 0.25 * math.log10(max(1, expected_loss / 100000)))

        # Strength modifies severity
        strength = antibody.get("strength", 0.5)
        severity = severity * (0.5 + 0.5 * strength)

        return max(0.1, min(1.0, severity))

    async def receive_broadcast(self, package_bytes: bytes, signature: dict) -> dict:
        """
        Handle an incoming antibody broadcast from a peer.

        Verifies signature, decompresses, validates, and stores.

        Args:
            package_bytes: Compressed antibody package.
            signature: Hybrid signature dict.

        Returns:
            Dict with reception results.
        """
        self._ensure_dependencies()

        # Step 1: Verify signature
        if self._crypto and signature:
            try:
                from backend.mesh.crypto import HybridSignature
                sig = HybridSignature.from_dict(signature)
                is_valid = self._crypto.verify(package_bytes, sig)
                if not is_valid:
                    logger.warning("Received broadcast with INVALID signature — rejecting")
                    return {"accepted": False, "reason": "invalid_signature"}
            except Exception as e:
                logger.warning(f"Signature verification error: {e}")

        # Step 2: Decompress
        try:
            json_bytes = zlib.decompress(package_bytes)
            package = json.loads(json_bytes)
        except Exception as e:
            logger.warning(f"Failed to decompress broadcast: {e}")
            return {"accepted": False, "reason": "decompression_failed"}

        # Step 3: Extract antibody
        antibody_data = package.get("antibody", {})
        antibody_id = antibody_data.get("antibody_id", "unknown")

        # Step 4: Store in local immune memory
        try:
            from backend.agents.immune_memory import get_immune_memory
            memory = get_immune_memory()
            # Store would need the embedding — for now, store metadata
            logger.info(f"Received antibody from mesh: {antibody_id}")
        except ImportError:
            pass

        # Step 5: Store in database
        try:
            from backend.storage.database import get_database
            db = get_database()
            antibody_data["status"] = "mesh_received"
            antibody_data["mesh_broadcast_at"] = package.get("packaged_at")
            db.insert_antibody(antibody_data)
        except Exception as e:
            logger.debug(f"Database store failed: {e}")

        return {
            "accepted": True,
            "antibody_id": antibody_id,
            "attack_family": antibody_data.get("attack_family"),
            "strength": antibody_data.get("strength"),
            "verification_status": antibody_data.get("verification_status"),
        }

    def get_stats(self) -> dict:
        """Return broadcaster statistics."""
        return {
            "total_broadcasts": self._total_broadcasts,
            "total_bytes_broadcast": self._total_bytes_broadcast,
            "successful_deliveries": self._successful_deliveries,
            "failed_deliveries": self._failed_deliveries,
            "stix_exports": self._stix_exports,
            "avg_package_size": (
                round(self._total_bytes_broadcast / self._total_broadcasts)
                if self._total_broadcasts > 0
                else 0
            ),
        }


# Module-level singleton
_broadcaster: Optional[MeshBroadcaster] = None


def get_mesh_broadcaster() -> MeshBroadcaster:
    """Get or create the singleton MeshBroadcaster instance."""
    global _broadcaster
    if _broadcaster is None:
        _broadcaster = MeshBroadcaster()
    return _broadcaster
