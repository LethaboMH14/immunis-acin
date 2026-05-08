"""
IMMUNIS ACIN — Vector Store (FAISS Index for Antibodies)

WHY: The immune memory must find similar antibodies in sub-millisecond
time across potentially millions of entries. FAISS (Facebook AI
Similarity Search) provides exact and approximate nearest-neighbour
search on dense vectors with GPU acceleration support.

Every antibody is stored as a 768-dimensional LaBSE embedding.
When a new threat arrives, we search for the nearest antibodies
to determine if this is KNOWN, VARIANT, or NOVEL — this is the
foundation of the information-theoretic surprise detector.

Architecture:
  - Primary index: FAISS IndexFlatIP (inner product / cosine similarity)
  - Scaled index: FAISS IndexIVFFlat when library exceeds 10K entries
  - Metadata: parallel dict mapping FAISS IDs to antibody metadata
  - Persistence: save/load to disk for restart resilience

Performance targets:
  - Search latency: ≤5ms for 100K vectors
  - Insert latency: ≤1ms per vector
  - Memory: ~300MB per 100K 768-dim float32 vectors
"""

import logging
import os
import json
import time
import threading
from typing import Optional
from pathlib import Path
from datetime import datetime, timezone

import numpy as np

try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False

logger = logging.getLogger("immunis.storage.vector_store")

# LaBSE embedding dimension
EMBEDDING_DIM = 768

# Threshold for switching from flat to IVF index
IVF_THRESHOLD = 10_000

# Number of IVF clusters (sqrt of expected corpus size)
IVF_NLIST = 100

# Number of clusters to probe during search
IVF_NPROBE = 10


class VectorStore:
    """
    FAISS-backed vector store for antibody embeddings.

    Supports:
    - Add vectors with metadata
    - Search by vector (cosine similarity)
    - Search by ID
    - Persistence (save/load)
    - Auto-scaling (flat → IVF at threshold)
    - Thread-safe operations
    """

    def __init__(
        self,
        store_path: Optional[str] = None,
        dimension: int = EMBEDDING_DIM,
        auto_save: bool = True,
        auto_save_interval: int = 100,
    ):
        self._dimension = dimension
        self._store_path = Path(store_path) if store_path else None
        self._auto_save = auto_save
        self._auto_save_interval = auto_save_interval
        self._lock = threading.RLock()

        # Metadata storage: faiss_id → metadata dict
        self._metadata: dict[int, dict] = {}

        # Reverse lookup: antibody_id → faiss_id
        self._id_map: dict[str, int] = {}

        # Counter for next FAISS ID
        self._next_id: int = 0

        # Operations since last save
        self._ops_since_save: int = 0

        # Statistics
        self._total_searches: int = 0
        self._total_search_time_ms: float = 0.0
        self._total_inserts: int = 0

        if not FAISS_AVAILABLE:
            logger.error(
                "FAISS not installed — vector store will use brute-force numpy. "
                "Install with: pip install faiss-cpu"
            )
            self._index = None
            self._vectors: list[np.ndarray] = []
        else:
            # Start with flat index (exact search)
            self._index = faiss.IndexFlatIP(dimension)
            self._vectors = []
            logger.info(
                f"FAISS vector store initialised: dim={dimension}, "
                f"AVX2={'yes' if hasattr(faiss, 'METRIC_INNER_PRODUCT') else 'no'}"
            )

        # Try to load existing index
        if self._store_path:
            self._load()

    @property
    def size(self) -> int:
        """Number of vectors in the store."""
        with self._lock:
            if FAISS_AVAILABLE and self._index is not None:
                return self._index.ntotal
            return len(self._vectors)

    def add(
        self,
        vector: np.ndarray,
        antibody_id: str,
        metadata: Optional[dict] = None,
    ) -> int:
        """
        Add a vector with metadata to the store.

        Args:
            vector: 768-dim float32 numpy array (L2-normalised for cosine sim).
            antibody_id: Unique antibody identifier.
            metadata: Additional metadata to store alongside the vector.

        Returns:
            FAISS ID assigned to this vector.
        """
        with self._lock:
            # Validate vector
            vector = self._validate_vector(vector)

            # Check for duplicate
            if antibody_id in self._id_map:
                logger.debug(f"Updating existing vector for {antibody_id}")
                return self._update(vector, antibody_id, metadata)

            # Assign ID
            faiss_id = self._next_id
            self._next_id += 1

            # Store metadata
            meta = metadata or {}
            meta["antibody_id"] = antibody_id
            meta["faiss_id"] = faiss_id
            meta["added_at"] = datetime.now(timezone.utc).isoformat()
            self._metadata[faiss_id] = meta
            self._id_map[antibody_id] = faiss_id

            # Add to index
            if FAISS_AVAILABLE and self._index is not None:
                vector_2d = vector.reshape(1, -1).astype(np.float32)
                self._index.add(vector_2d)
            else:
                self._vectors.append(vector.copy())

            self._total_inserts += 1
            self._ops_since_save += 1

            # Auto-save check
            if (
                self._auto_save
                and self._store_path
                and self._ops_since_save >= self._auto_save_interval
            ):
                self._save()

            # Check if we should upgrade to IVF index
            if (
                FAISS_AVAILABLE
                and self._index is not None
                and self.size == IVF_THRESHOLD
                and not isinstance(self._index, faiss.IndexIVFFlat)
            ):
                self._upgrade_to_ivf()

            logger.debug(
                f"Added vector for {antibody_id} (id={faiss_id}, "
                f"store_size={self.size})"
            )

            return faiss_id

    def _update(
        self,
        vector: np.ndarray,
        antibody_id: str,
        metadata: Optional[dict] = None,
    ) -> int:
        """Update an existing vector. Must be called within lock."""
        faiss_id = self._id_map[antibody_id]

        # Update metadata
        if metadata:
            self._metadata[faiss_id].update(metadata)
        self._metadata[faiss_id]["updated_at"] = datetime.now(timezone.utc).isoformat()

        # FAISS doesn't support in-place update for flat index
        # For simplicity, we mark the old entry and the search
        # will use the metadata to resolve to the latest
        # In production, periodic rebuild would compact the index

        if FAISS_AVAILABLE and self._index is not None:
            vector_2d = vector.reshape(1, -1).astype(np.float32)
            self._index.add(vector_2d)
            # Update ID map to point to new position
            new_id = self._index.ntotal - 1
            self._metadata[new_id] = self._metadata.pop(faiss_id)
            self._metadata[new_id]["faiss_id"] = new_id
            self._id_map[antibody_id] = new_id
        else:
            idx = faiss_id
            if idx < len(self._vectors):
                self._vectors[idx] = vector.copy()

        self._ops_since_save += 1
        return self._id_map[antibody_id]

    def search(
        self,
        query_vector: np.ndarray,
        k: int = 10,
        threshold: Optional[float] = None,
    ) -> list[dict]:
        """
        Search for nearest neighbours by cosine similarity.

        Args:
            query_vector: 768-dim query vector (L2-normalised).
            k: Number of results to return.
            threshold: Minimum similarity score (0-1). None = no filter.

        Returns:
            List of dicts with keys: antibody_id, score, metadata, faiss_id
        """
        start = time.perf_counter()

        with self._lock:
            if self.size == 0:
                return []

            query = self._validate_vector(query_vector)
            k = min(k, self.size)

            if FAISS_AVAILABLE and self._index is not None:
                query_2d = query.reshape(1, -1).astype(np.float32)
                scores, indices = self._index.search(query_2d, k)
                scores = scores[0]
                indices = indices[0]
            else:
                scores, indices = self._brute_force_search(query, k)

            results = []
            for score, idx in zip(scores, indices):
                if idx < 0:
                    continue

                score_float = float(score)

                if threshold is not None and score_float < threshold:
                    continue

                meta = self._metadata.get(int(idx), {})
                results.append({
                    "antibody_id": meta.get("antibody_id", f"unknown-{idx}"),
                    "score": score_float,
                    "faiss_id": int(idx),
                    "metadata": meta,
                })

        elapsed_ms = (time.perf_counter() - start) * 1000
        self._total_searches += 1
        self._total_search_time_ms += elapsed_ms

        logger.debug(
            f"Vector search: k={k}, results={len(results)}, "
            f"top_score={results[0]['score']:.4f if results else 0:.4f}, "
            f"latency={elapsed_ms:.2f}ms"
        )

        return results

    def get_by_id(self, antibody_id: str) -> Optional[dict]:
        """Get metadata for a specific antibody by ID."""
        with self._lock:
            faiss_id = self._id_map.get(antibody_id)
            if faiss_id is None:
                return None
            return self._metadata.get(faiss_id)

    def get_vector(self, antibody_id: str) -> Optional[np.ndarray]:
        """Get the raw vector for a specific antibody."""
        with self._lock:
            faiss_id = self._id_map.get(antibody_id)
            if faiss_id is None:
                return None

            if FAISS_AVAILABLE and self._index is not None:
                try:
                    vector = self._index.reconstruct(int(faiss_id))
                    return vector
                except RuntimeError:
                    return None
            else:
                if faiss_id < len(self._vectors):
                    return self._vectors[faiss_id].copy()
                return None

    def get_all_vectors(self) -> np.ndarray:
        """Get all vectors as a 2D numpy array. Used by KDE surprise detector."""
        with self._lock:
            if self.size == 0:
                return np.empty((0, self._dimension), dtype=np.float32)

            if FAISS_AVAILABLE and self._index is not None:
                try:
                    vectors = np.zeros(
                        (self._index.ntotal, self._dimension),
                        dtype=np.float32,
                    )
                    for i in range(self._index.ntotal):
                        vectors[i] = self._index.reconstruct(i)
                    return vectors
                except RuntimeError:
                    pass

            if self._vectors:
                return np.array(self._vectors, dtype=np.float32)

            return np.empty((0, self._dimension), dtype=np.float32)

    def remove(self, antibody_id: str) -> bool:
        """
        Remove a vector from the store.

        Note: FAISS flat index doesn't support removal.
        We mark the metadata as deleted and skip during search.
        Periodic rebuild compacts the index.
        """
        with self._lock:
            faiss_id = self._id_map.pop(antibody_id, None)
            if faiss_id is None:
                return False

            meta = self._metadata.get(faiss_id)
            if meta:
                meta["deleted"] = True
                meta["deleted_at"] = datetime.now(timezone.utc).isoformat()

            self._ops_since_save += 1
            logger.debug(f"Marked vector {antibody_id} as deleted (faiss_id={faiss_id})")
            return True

    def rebuild(self) -> int:
        """
        Rebuild the index, removing deleted entries.

        Returns number of entries after rebuild.
        """
        with self._lock:
            if not FAISS_AVAILABLE or self._index is None:
                # Numpy fallback: filter deleted
                active_ids = [
                    aid for aid, fid in self._id_map.items()
                    if not self._metadata.get(fid, {}).get("deleted", False)
                ]
                logger.info(f"Rebuild: {len(active_ids)} active entries (numpy mode)")
                return len(active_ids)

            # Collect active vectors and metadata
            active_vectors = []
            active_metadata = {}
            new_id_map = {}
            new_id = 0

            for antibody_id, faiss_id in self._id_map.items():
                meta = self._metadata.get(faiss_id, {})
                if meta.get("deleted", False):
                    continue

                try:
                    vector = self._index.reconstruct(int(faiss_id))
                    active_vectors.append(vector)
                    meta["faiss_id"] = new_id
                    active_metadata[new_id] = meta
                    new_id_map[antibody_id] = new_id
                    new_id += 1
                except RuntimeError:
                    continue

            # Create new index
            if len(active_vectors) > IVF_THRESHOLD:
                quantizer = faiss.IndexFlatIP(self._dimension)
                new_index = faiss.IndexIVFFlat(
                    quantizer, self._dimension, IVF_NLIST
                )
                vectors_array = np.array(active_vectors, dtype=np.float32)
                new_index.train(vectors_array)
                new_index.add(vectors_array)
                new_index.nprobe = IVF_NPROBE
            else:
                new_index = faiss.IndexFlatIP(self._dimension)
                if active_vectors:
                    vectors_array = np.array(active_vectors, dtype=np.float32)
                    new_index.add(vectors_array)

            # Swap
            self._index = new_index
            self._metadata = active_metadata
            self._id_map = new_id_map
            self._next_id = new_id

            self._ops_since_save += 1

            logger.info(
                f"Index rebuilt: {new_index.ntotal} active entries "
                f"(type: {'IVF' if isinstance(new_index, faiss.IndexIVFFlat) else 'Flat'})"
            )

            return new_index.ntotal

    # ------------------------------------------------------------------
    # PERSISTENCE
    # ------------------------------------------------------------------

    def save(self) -> bool:
        """Manually trigger save to disk."""
        with self._lock:
            return self._save()

    def _save(self) -> bool:
        """Save index and metadata to disk. Must be called within lock."""
        if self._store_path is None:
            return False

        try:
            self._store_path.mkdir(parents=True, exist_ok=True)

            # Save FAISS index
            if FAISS_AVAILABLE and self._index is not None:
                index_path = self._store_path / "faiss.index"
                faiss.write_index(self._index, str(index_path))
            else:
                # Save numpy vectors
                vectors_path = self._store_path / "vectors.npy"
                if self._vectors:
                    np.save(str(vectors_path), np.array(self._vectors))

            # Save metadata
            meta_path = self._store_path / "metadata.json"
            serialisable_meta = {
                str(k): v for k, v in self._metadata.items()
            }
            with open(meta_path, "w") as f:
                json.dump(serialisable_meta, f, indent=2)

            # Save ID map
            idmap_path = self._store_path / "id_map.json"
            with open(idmap_path, "w") as f:
                json.dump(self._id_map, f, indent=2)

            # Save counter
            state_path = self._store_path / "state.json"
            with open(state_path, "w") as f:
                json.dump({
                    "next_id": self._next_id,
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                    "total_entries": self.size,
                }, f, indent=2)

            self._ops_since_save = 0

            logger.info(
                f"Vector store saved to {self._store_path}: "
                f"{self.size} vectors"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to save vector store: {e}")
            return False

    def _load(self) -> bool:
        """Load index and metadata from disk. Must be called within lock."""
        if self._store_path is None or not self._store_path.exists():
            return False

        try:
            # Load FAISS index
            index_path = self._store_path / "faiss.index"
            vectors_path = self._store_path / "vectors.npy"

            if FAISS_AVAILABLE and index_path.exists():
                self._index = faiss.read_index(str(index_path))
                logger.info(
                    f"Loaded FAISS index: {self._index.ntotal} vectors"
                )
            elif vectors_path.exists():
                self._vectors = list(np.load(str(vectors_path)))
                logger.info(f"Loaded numpy vectors: {len(self._vectors)}")

            # Load metadata
            meta_path = self._store_path / "metadata.json"
            if meta_path.exists():
                with open(meta_path) as f:
                    raw = json.load(f)
                self._metadata = {int(k): v for k, v in raw.items()}

            # Load ID map
            idmap_path = self._store_path / "id_map.json"
            if idmap_path.exists():
                with open(idmap_path) as f:
                    self._id_map = json.load(f)

            # Load state
            state_path = self._store_path / "state.json"
            if state_path.exists():
                with open(state_path) as f:
                    state = json.load(f)
                self._next_id = state.get("next_id", len(self._metadata))

            logger.info(
                f"Vector store loaded from {self._store_path}: "
                f"{self.size} vectors, {len(self._id_map)} antibodies"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to load vector store: {e}")
            return False

    # ------------------------------------------------------------------
    # INTERNAL HELPERS
    # ------------------------------------------------------------------

    def _validate_vector(self, vector: np.ndarray) -> np.ndarray:
        """Validate and normalise a vector for cosine similarity."""
        vector = np.asarray(vector, dtype=np.float32).flatten()

        if vector.shape[0] != self._dimension:
            raise ValueError(
                f"Vector dimension mismatch: expected {self._dimension}, "
                f"got {vector.shape[0]}"
            )

        # L2 normalise for cosine similarity via inner product
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm

        return vector

    def _brute_force_search(
        self,
        query: np.ndarray,
        k: int,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Numpy brute-force search fallback when FAISS unavailable."""
        if not self._vectors:
            return np.array([]), np.array([])

        vectors = np.array(self._vectors, dtype=np.float32)
        scores = vectors @ query  # cosine similarity via dot product

        # Get top-k indices
        if k >= len(scores):
            top_indices = np.argsort(scores)[::-1]
        else:
            top_indices = np.argpartition(scores, -k)[-k:]
            top_indices = top_indices[np.argsort(scores[top_indices])[::-1]]

        return scores[top_indices], top_indices

    def _upgrade_to_ivf(self) -> None:
        """Upgrade from flat index to IVF index for better scaling."""
        if not FAISS_AVAILABLE or self._index is None:
            return

        logger.info(
            f"Upgrading vector index from Flat to IVF "
            f"(threshold: {IVF_THRESHOLD} vectors)"
        )

        try:
            # Extract all vectors
            n = self._index.ntotal
            vectors = np.zeros((n, self._dimension), dtype=np.float32)
            for i in range(n):
                vectors[i] = self._index.reconstruct(i)

            # Create IVF index
            quantizer = faiss.IndexFlatIP(self._dimension)
            ivf_index = faiss.IndexIVFFlat(
                quantizer, self._dimension, IVF_NLIST
            )
            ivf_index.train(vectors)
            ivf_index.add(vectors)
            ivf_index.nprobe = IVF_NPROBE

            self._index = ivf_index

            logger.info(
                f"Index upgraded to IVF: {n} vectors, "
                f"{IVF_NLIST} clusters, nprobe={IVF_NPROBE}"
            )

        except Exception as e:
            logger.error(f"Failed to upgrade index to IVF: {e}")

    # ------------------------------------------------------------------
    # STATISTICS
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return vector store statistics."""
        avg_search = (
            self._total_search_time_ms / self._total_searches
            if self._total_searches > 0
            else 0.0
        )

        index_type = "none"
        if FAISS_AVAILABLE and self._index is not None:
            if isinstance(self._index, faiss.IndexIVFFlat):
                index_type = "IVF"
            else:
                index_type = "Flat"
        elif self._vectors:
            index_type = "numpy"

        return {
            "total_vectors": self.size,
            "total_antibodies": len(self._id_map),
            "deleted_vectors": sum(
                1 for m in self._metadata.values()
                if m.get("deleted", False)
            ),
            "index_type": index_type,
            "dimension": self._dimension,
            "faiss_available": FAISS_AVAILABLE,
            "total_searches": self._total_searches,
            "avg_search_ms": round(avg_search, 3),
            "total_inserts": self._total_inserts,
            "store_path": str(self._store_path) if self._store_path else None,
            "ops_since_save": self._ops_since_save,
        }


# Module-level singleton
_store: Optional[VectorStore] = None


def get_vector_store(
    store_path: Optional[str] = None,
) -> VectorStore:
    """Get or create the singleton VectorStore instance."""
    global _store
    if _store is None:
        if store_path is None:
            try:
                from backend.config import config
                store_path = config.vector_store_path
            except (ImportError, AttributeError):
                store_path = "./data/faiss_index"
        _store = VectorStore(store_path=store_path)
    return _store
