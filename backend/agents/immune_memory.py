"""
IMMUNIS ACIN — Agent 3: Immune Memory

Manages the antibody library — the system's permanent immune knowledge.

Responsibilities:
    1. STORE new antibodies with their LaBSE semantic vectors
    2. SEARCH for matching antibodies when a new threat arrives
    3. DEDUPLICATE near-identical antibodies (cosine similarity > 0.92)
    4. CLUSTER antibodies by attack family
    5. PROVIDE bridge antibodies for novel threats (nearest family centroid)
    6. HEBBIAN LEARNING: strengthen connections between co-activated antibodies

The memory is backed by:
    - FAISS vector index for fast similarity search (~5ms for 100K antibodies)
    - In-memory antibody registry for structured data
    - Persistence to disk for durability

This agent does NOT use an LLM. It is purely mathematical:
    - LaBSE vectors for semantic representation
    - Cosine similarity for matching
    - FAISS for approximate nearest neighbor search
    - Hebbian weight updates for self-organizing clusters

Temperature: N/A (no LLM calls — deterministic math only)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

import numpy as np

from backend.config import get_settings
from backend.math_engines.surprise import get_surprise_detector
from backend.models.enums import AntibodyStatus, ThreatVerdict
from backend.models.schemas import (
    Antibody,
    MemorySearchResult,
    MemoryStoreResult,
    SemanticFingerprint,
    generate_id,
)
from backend.security.audit_trail import record_event

logger = logging.getLogger("immunis.agent.immune_memory")


# ============================================================================
# SIMILARITY THRESHOLDS
# ============================================================================

DUPLICATE_THRESHOLD = 0.92    # Above this = same antibody (deduplicate)
VARIANT_THRESHOLD = 0.65      # Above this = variant of known (bridge defense)
NOVEL_THRESHOLD = 0.65        # Below this = genuinely novel


# ============================================================================
# IMMUNE MEMORY CLASS
# ============================================================================

class ImmuneMemory:
    """
    The antibody library — IMMUNIS's permanent immune knowledge.

    Backed by FAISS for fast vector search and an in-memory registry
    for structured antibody data.
    """

    def __init__(self):
        self._antibodies: dict[str, Antibody] = {}  # antibody_id → Antibody
        self._vectors: dict[str, np.ndarray] = {}    # antibody_id → LaBSE vector
        self._families: dict[str, list[str]] = {}    # family_name → [antibody_ids]
        self._family_centroids: dict[str, np.ndarray] = {}  # family_name → centroid vector

        # Hebbian connection weights between antibodies
        # w[i][j] = strength of connection between antibody i and j
        # Strengthened when both fire on the same threat (co-activation)
        self._hebbian_weights: dict[str, dict[str, float]] = {}

        # FAISS index
        self._faiss_index = None
        self._faiss_id_map: list[str] = []  # FAISS index position → antibody_id
        self._index_dirty = True

        logger.info("Immune Memory initialised")

    @property
    def library_size(self) -> int:
        return len(self._antibodies)

    @property
    def family_count(self) -> int:
        return len(self._families)

    # ====================================================================
    # STORE — Add new antibody to library
    # ====================================================================

    def store_antibody(
        self,
        antibody: Antibody,
        vector: Optional[np.ndarray] = None,
    ) -> MemoryStoreResult:
        """
        Store a new antibody in the library.

        Process:
        1. Generate semantic vector if not provided
        2. Check for duplicates (cosine > 0.92)
        3. If duplicate: merge, increment frequency
        4. If variant: link to parent, add to family
        5. If novel: create new family
        6. Update FAISS index
        7. Update surprise detector library
        """
        start_time = time.monotonic()

        # Generate a random vector if none provided (will be replaced by LaBSE in production)
        if vector is None:
            vector = self._generate_placeholder_vector(antibody)

        # Normalise vector
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm
        vector = vector.astype(np.float32)

        # Check for duplicates
        if self.library_size > 0:
            nearest_id, similarity = self._find_nearest(vector)

            if similarity > DUPLICATE_THRESHOLD:
                # DUPLICATE — merge with existing
                logger.info(
                    f"Duplicate detected (similarity={similarity:.4f}), merging with {nearest_id}"
                )
                return MemoryStoreResult(
                    action="deduplicated",
                    antibody_id=nearest_id,
                    family_id=self._get_family_for_antibody(nearest_id),
                    family_name=self._get_family_name_for_antibody(nearest_id),
                    family_size=self._get_family_size(nearest_id),
                    is_variant_of=nearest_id,
                    library_size=self.library_size,
                )

            if similarity > VARIANT_THRESHOLD:
                # VARIANT — add to existing family
                family_name = self._get_family_name_for_antibody(nearest_id)
                self._add_to_library(antibody, vector, family_name)

                logger.info(
                    f"Variant detected (similarity={similarity:.4f}), "
                    f"added to family '{family_name}'"
                )

                return MemoryStoreResult(
                    action="clustered",
                    antibody_id=antibody.antibody_id,
                    family_id=self._get_family_for_antibody(antibody.antibody_id),
                    family_name=family_name,
                    family_size=self._get_family_size_by_name(family_name),
                    is_variant_of=nearest_id,
                    library_size=self.library_size,
                )

        # NOVEL — create new family
        family_name = antibody.attack_family or f"family_{generate_id('FAM')}"
        self._add_to_library(antibody, vector, family_name)

        logger.info(
            f"Novel antibody stored, new family '{family_name}'"
        )

        record_event(
            stage="memory_store",
            agent="immune_memory",
            action="antibody_stored",
            antibody_id=antibody.antibody_id,
            success=True,
            duration_ms=(time.monotonic() - start_time) * 1000,
            metadata={
                "family": family_name,
                "library_size": self.library_size,
            },
        )

        return MemoryStoreResult(
            action="stored",
            antibody_id=antibody.antibody_id,
            family_id=family_name,
            family_name=family_name,
            family_size=1,
            is_variant_of=None,
            library_size=self.library_size,
        )

    # ====================================================================
    # SEARCH — Find matching antibodies for a threat
    # ====================================================================

    def search(
        self,
        vector: np.ndarray,
        top_k: int = 5,
    ) -> MemorySearchResult:
        """
        Search the antibody library for matches to a threat vector.

        Returns the top-K most similar antibodies and a verdict:
        - KNOWN: exact match (similarity > 0.92) → instant block
        - VARIANT: related match (0.65-0.92) → bridge + synthesise
        - NOVEL: no match (< 0.65) → full AIR protocol
        """
        start_time = time.monotonic()

        if self.library_size == 0:
            return MemorySearchResult(
                verdict=ThreatVerdict.NOVEL,
                library_size=0,
                search_ms=(time.monotonic() - start_time) * 1000,
            )

        # Normalise query vector
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm
        vector = vector.astype(np.float32)

        # Find top-K nearest antibodies
        matches = self._find_top_k(vector, top_k)

        if not matches:
            return MemorySearchResult(
                verdict=ThreatVerdict.NOVEL,
                library_size=self.library_size,
                search_ms=(time.monotonic() - start_time) * 1000,
            )

        best_id, best_sim = matches[0]

        # Determine verdict
        if best_sim > DUPLICATE_THRESHOLD:
            verdict = ThreatVerdict.KNOWN
        elif best_sim > VARIANT_THRESHOLD:
            verdict = ThreatVerdict.VARIANT
        else:
            verdict = ThreatVerdict.NOVEL

        # Get bridge antibodies for novel/variant threats
        bridge_ids = []
        if verdict in (ThreatVerdict.VARIANT, ThreatVerdict.NOVEL):
            bridge_ids = self._get_bridge_antibodies(vector, top_k=3)

        search_ms = (time.monotonic() - start_time) * 1000

        return MemorySearchResult(
            query_vector_hash=str(hash(vector.tobytes()))[:16],
            matches=[
                {
                    "antibody_id": aid,
                    "similarity": round(sim, 4),
                    "attack_family": self._antibodies[aid].attack_family if aid in self._antibodies else "",
                }
                for aid, sim in matches
            ],
            best_match_id=best_id,
            best_match_similarity=round(best_sim, 4),
            verdict=verdict,
            bridge_antibody_ids=bridge_ids,
            library_size=self.library_size,
            search_ms=round(search_ms, 2),
        )

    # ====================================================================
    # HEBBIAN LEARNING — Co-activation strengthens connections
    # ====================================================================

    def record_co_activation(self, antibody_ids: list[str], learning_rate: float = 0.1) -> None:
        """
        Record that multiple antibodies fired on the same threat.

        Hebbian rule: Δw_ij = η · a_i · a_j
        Where η is the learning rate and a_i, a_j are activation values (1.0 for fired).

        Over time, this creates self-organizing clusters where antibodies
        that detect similar threats are strongly connected.
        """
        for i, id_i in enumerate(antibody_ids):
            if id_i not in self._hebbian_weights:
                self._hebbian_weights[id_i] = {}

            for j, id_j in enumerate(antibody_ids):
                if i != j:
                    current = self._hebbian_weights[id_i].get(id_j, 0.0)
                    # Hebbian update with decay
                    new_weight = current + learning_rate * 1.0 * 1.0  # Both activated = 1.0
                    # Apply decay to prevent unbounded growth
                    new_weight *= 0.99
                    self._hebbian_weights[id_i][id_j] = min(new_weight, 1.0)

    def get_connected_antibodies(self, antibody_id: str, threshold: float = 0.3) -> list[str]:
        """Get antibodies strongly connected via Hebbian learning."""
        weights = self._hebbian_weights.get(antibody_id, {})
        return [
            aid for aid, weight in weights.items()
            if weight >= threshold
        ]

    # ====================================================================
    # RETRIEVAL
    # ====================================================================

    def get_antibody(self, antibody_id: str) -> Optional[Antibody]:
        """Get a specific antibody by ID."""
        return self._antibodies.get(antibody_id)

    def get_all_antibodies(self) -> list[Antibody]:
        """Get all antibodies in the library."""
        return list(self._antibodies.values())

    def get_family(self, family_name: str) -> list[Antibody]:
        """Get all antibodies in a family."""
        ids = self._families.get(family_name, [])
        return [self._antibodies[aid] for aid in ids if aid in self._antibodies]

    def get_families_summary(self) -> list[dict[str, Any]]:
        """Get summary of all antibody families for dashboard display."""
        summaries = []
        for family_name, antibody_ids in self._families.items():
            antibodies = [self._antibodies[aid] for aid in antibody_ids if aid in self._antibodies]
            if not antibodies:
                continue

            severities = [ab.severity.value for ab in antibodies]
            strengths = [ab.strength_score for ab in antibodies]

            summaries.append({
                "family_name": family_name,
                "antibody_count": len(antibodies),
                "highest_severity": max(severities) if severities else "Medium",
                "average_strength": round(sum(strengths) / len(strengths), 4) if strengths else 0.0,
                "languages_covered": list(set(
                    lang.value for ab in antibodies for lang in ab.language_variants
                )),
                "newest_antibody": max(ab.synthesised_at for ab in antibodies).isoformat(),
            })

        return sorted(summaries, key=lambda x: x["antibody_count"], reverse=True)

    def update_antibody_status(self, antibody_id: str, status: AntibodyStatus) -> bool:
        """Update the status of an antibody. Returns True if found."""
        if antibody_id in self._antibodies:
            self._antibodies[antibody_id].status = status
            return True
        return False

    def update_antibody_strength(
        self,
        antibody_id: str,
        strength: float,
        tests: int = 0,
        evasions: int = 0,
    ) -> bool:
        """Update antibody strength after Red Agent stress testing."""
        if antibody_id in self._antibodies:
            ab = self._antibodies[antibody_id]
            ab.strength_score = max(0.0, min(1.0, strength))
            ab.red_agent_tests += tests
            ab.red_agent_evasions += evasions
            return True
        return False

    # ====================================================================
    # INTERNAL METHODS
    # ====================================================================

    def _add_to_library(
        self,
        antibody: Antibody,
        vector: np.ndarray,
        family_name: str,
    ) -> None:
        """Add an antibody to all internal data structures."""
        aid = antibody.antibody_id

        self._antibodies[aid] = antibody
        self._vectors[aid] = vector

        # Add to family
        if family_name not in self._families:
            self._families[family_name] = []
        self._families[family_name].append(aid)

        # Update family centroid
        self._update_family_centroid(family_name)

        # Update FAISS index
        self._index_dirty = True
        self._rebuild_faiss_index()

        # Update surprise detector
        surprise = get_surprise_detector()
        surprise.add_antibody(aid, vector)

    def _update_family_centroid(self, family_name: str) -> None:
        """Recompute the centroid vector for a family."""
        ids = self._families.get(family_name, [])
        vectors = [self._vectors[aid] for aid in ids if aid in self._vectors]

        if vectors:
            centroid = np.mean(np.stack(vectors), axis=0)
            norm = np.linalg.norm(centroid)
            if norm > 0:
                centroid = centroid / norm
            self._family_centroids[family_name] = centroid.astype(np.float32)

    def _find_nearest(self, vector: np.ndarray) -> tuple[Optional[str], float]:
        """Find the nearest antibody to a vector."""
        if not self._vectors:
            return None, 0.0

        best_id = None
        best_sim = -1.0

        # Use FAISS if available and index is built
        if self._faiss_index is not None and not self._index_dirty:
            query = vector.reshape(1, -1)
            similarities, indices = self._faiss_index.search(query, 1)
            idx = indices[0][0]
            sim = float(similarities[0][0])

            if 0 <= idx < len(self._faiss_id_map):
                return self._faiss_id_map[idx], max(0.0, min(1.0, sim))

        # Numpy fallback
        for aid, v in self._vectors.items():
            sim = float(np.dot(vector, v))
            if sim > best_sim:
                best_sim = sim
                best_id = aid

        return best_id, max(0.0, min(1.0, best_sim))

    def _find_top_k(self, vector: np.ndarray, k: int = 5) -> list[tuple[str, float]]:
        """Find the top-K nearest antibodies."""
        if not self._vectors:
            return []

        # Use FAISS if available
        if self._faiss_index is not None and not self._index_dirty:
            actual_k = min(k, len(self._faiss_id_map))
            query = vector.reshape(1, -1)
            similarities, indices = self._faiss_index.search(query, actual_k)

            results = []
            for i in range(actual_k):
                idx = indices[0][i]
                sim = float(similarities[0][i])
                if 0 <= idx < len(self._faiss_id_map):
                    results.append((self._faiss_id_map[idx], max(0.0, min(1.0, sim))))
            return results

        # Numpy fallback
        all_sims = []
        for aid, v in self._vectors.items():
            sim = float(np.dot(vector, v))
            all_sims.append((aid, sim))

        all_sims.sort(key=lambda x: x[1], reverse=True)
        return [(aid, max(0.0, min(1.0, sim))) for aid, sim in all_sims[:k]]

    def _get_bridge_antibodies(self, vector: np.ndarray, top_k: int = 3) -> list[str]:
        """
        Get bridge antibodies for a novel threat.

        Bridge antibodies are the nearest antibodies from different families.
        They provide partial, broad-spectrum coverage while the specific
        antibody is being synthesised.

        This is the innate immune response equivalent.
        """
        if not self._family_centroids:
            return []

        # Find nearest family centroids
        family_sims = []
        for family_name, centroid in self._family_centroids.items():
            sim = float(np.dot(vector, centroid))
            family_sims.append((family_name, sim))

        family_sims.sort(key=lambda x: x[1], reverse=True)

        # Get the strongest antibody from each of the top-K families
        bridge_ids = []
        for family_name, _ in family_sims[:top_k]:
            family_antibodies = self._families.get(family_name, [])
            if family_antibodies:
                # Pick the antibody with highest strength score
                best_ab = max(
                    family_antibodies,
                    key=lambda aid: self._antibodies[aid].strength_score
                    if aid in self._antibodies
                    else 0.0,
                )
                bridge_ids.append(best_ab)

        return bridge_ids

    def _get_family_for_antibody(self, antibody_id: str) -> str:
        """Get the family ID for an antibody."""
        for family_name, ids in self._families.items():
            if antibody_id in ids:
                return family_name
        return ""

    def _get_family_name_for_antibody(self, antibody_id: str) -> str:
        """Get the family name for an antibody."""
        return self._get_family_for_antibody(antibody_id)

    def _get_family_size(self, antibody_id: str) -> int:
        """Get the size of the family an antibody belongs to."""
        family = self._get_family_for_antibody(antibody_id)
        return len(self._families.get(family, []))

    def _get_family_size_by_name(self, family_name: str) -> int:
        """Get the size of a family by name."""
        return len(self._families.get(family_name, []))

    def _generate_placeholder_vector(self, antibody: Antibody) -> np.ndarray:
        """
        Generate a placeholder vector from antibody text content.

        In production, this is replaced by LaBSE encoding of the
        cross_lingual_pattern. For development without sentence-transformers,
        we generate a deterministic pseudo-random vector from the text hash.
        """
        import hashlib

        text = f"{antibody.attack_family} {antibody.cross_lingual_pattern}"
        hash_bytes = hashlib.sha256(text.encode()).digest()

        # Expand hash to 768 dimensions using repeated hashing
        vector_parts = []
        current = hash_bytes
        while len(vector_parts) < 768:
            current = hashlib.sha256(current).digest()
            for byte in current:
                if len(vector_parts) < 768:
                    vector_parts.append((byte - 128) / 128.0)

        vector = np.array(vector_parts, dtype=np.float32)
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm

        return vector

    def _rebuild_faiss_index(self) -> None:
        """Rebuild the FAISS index from current vectors."""
        try:
            import faiss

            if not self._vectors:
                self._faiss_index = None
                self._faiss_id_map = []
                self._index_dirty = False
                return

            # Build matrix
            ids = list(self._vectors.keys())
            matrix = np.stack([self._vectors[aid] for aid in ids], axis=0)
            d = matrix.shape[1]

            # Create index (inner product = cosine for normalised vectors)
            if len(matrix) < 10_000:
                index = faiss.IndexFlatIP(d)
            else:
                nlist = min(int(np.sqrt(len(matrix))), 256)
                quantiser = faiss.IndexFlatIP(d)
                index = faiss.IndexIVFFlat(quantiser, d, nlist, faiss.METRIC_INNER_PRODUCT)
                index.train(matrix)
                index.nprobe = min(nlist // 4, 16)

            index.add(matrix)
            self._faiss_index = index
            self._faiss_id_map = ids
            self._index_dirty = False

        except ImportError:
            self._faiss_index = None
            self._faiss_id_map = []
            self._index_dirty = False

    # ====================================================================
    # PERSISTENCE
    # ====================================================================

    def save(self, path: str) -> None:
        """Save the entire memory to disk."""
        import json
        from pathlib import Path

        save_path = Path(path)
        save_path.mkdir(parents=True, exist_ok=True)

        # Save antibodies as JSONL
        with open(save_path / "antibodies.jsonl", "w") as f:
            for ab in self._antibodies.values():
                f.write(ab.model_dump_json() + "\n")

        # Save vectors
        if self._vectors:
            ids = list(self._vectors.keys())
            matrix = np.stack([self._vectors[aid] for aid in ids], axis=0)
            np.save(save_path / "vectors.npy", matrix)

            with open(save_path / "vector_ids.json", "w") as f:
                json.dump(ids, f)

        # Save families
        with open(save_path / "families.json", "w") as f:
            json.dump(self._families, f)

        # Save Hebbian weights
        with open(save_path / "hebbian.json", "w") as f:
            json.dump(self._hebbian_weights, f)

        logger.info(f"Immune Memory saved to {save_path} ({self.library_size} antibodies)")

    def load(self, path: str) -> None:
        """Load the entire memory from disk."""
        import json
        from pathlib import Path

        load_path = Path(path)

        # Load antibodies
        ab_file = load_path / "antibodies.jsonl"
        if ab_file.exists():
            with open(ab_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        ab = Antibody.model_validate_json(line)
                        self._antibodies[ab.antibody_id] = ab

        # Load vectors
        vectors_file = load_path / "vectors.npy"
        ids_file = load_path / "vector_ids.json"
        if vectors_file.exists() and ids_file.exists():
            matrix = np.load(vectors_file)
            with open(ids_file) as f:
                ids = json.load(f)

            for i, aid in enumerate(ids):
                if i < len(matrix):
                    self._vectors[aid] = matrix[i]

        # Load families
        families_file = load_path / "families.json"
        if families_file.exists():
            with open(families_file) as f:
                self._families = json.load(f)

            # Rebuild centroids
            for family_name in self._families:
                self._update_family_centroid(family_name)

        # Load Hebbian weights
        hebbian_file = load_path / "hebbian.json"
        if hebbian_file.exists():
            with open(hebbian_file) as f:
                self._hebbian_weights = json.load(f)

        # Rebuild FAISS index
        self._index_dirty = True
        self._rebuild_faiss_index()

        # Populate surprise detector
        surprise = get_surprise_detector()
        for aid, vector in self._vectors.items():
            surprise.add_antibody(aid, vector)

        logger.info(
            f"Immune Memory loaded from {load_path} "
            f"({self.library_size} antibodies, {self.family_count} families)"
        )

    def get_statistics(self) -> dict[str, Any]:
        """Get library statistics for dashboard display."""
        strengths = [ab.strength_score for ab in self._antibodies.values()]
        statuses = [ab.status.value for ab in self._antibodies.values()]

        return {
            "total_antibodies": self.library_size,
            "total_families": self.family_count,
            "average_strength": round(sum(strengths) / len(strengths), 4) if strengths else 0.0,
            "status_distribution": {
                status: statuses.count(status) for status in set(statuses)
            } if statuses else {},
            "families": self.get_families_summary()[:10],  # Top 10 families
            "hebbian_connections": sum(
                len(weights) for weights in self._hebbian_weights.values()
            ),
        }


# ============================================================================
# MODULE-LEVEL SINGLETON
# ============================================================================

_memory: Optional[ImmuneMemory] = None


def get_immune_memory() -> ImmuneMemory:
    """Get or create the global Immune Memory instance."""
    global _memory
    if _memory is None:
        _memory = ImmuneMemory()

        # Try to load persisted library
        settings = get_settings()
        memory_path = settings.data_dir / "immune_memory"
        if (memory_path / "antibodies.jsonl").exists():
            _memory.load(str(memory_path))

    return _memory
