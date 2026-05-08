"""
IMMUNIS ACIN — Threat Actor Clustering (DBSCAN)

WHY: Individual attacker sessions are data points. Clustering
reveals GROUPS — coordinated campaigns, recurring threat actors,
and attack patterns that span multiple sessions and targets.

DBSCAN (Density-Based Spatial Clustering of Applications with Noise)
is ideal because:
1. It doesn't require specifying the number of clusters in advance
2. It handles noise (one-off attackers) naturally
3. It finds arbitrarily-shaped clusters (attack campaigns aren't spherical)
4. It works well with cosine distance on behavioural vectors

Mathematical foundation:
  DBSCAN(D, ε, MinPts):
    Core point: |N_ε(p)| ≥ MinPts
    Border point: in N_ε of a core point but not core itself
    Noise: neither core nor border

  Parameters:
    ε = 0.3 (cosine distance threshold — 0.7 similarity)
    MinPts = 3 (minimum sessions to form a cluster)

  Cluster = connected component of core points + their borders
  Each cluster represents a threat actor or campaign
"""

import logging
import time
import hashlib
from typing import Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field
from collections import defaultdict

import numpy as np

logger = logging.getLogger("immunis.taf.clusterer")


@dataclass
class ThreatActorCluster:
    """A cluster of related attacker sessions."""
    cluster_id: str
    label: str  # Human-readable label
    fingerprint_ids: list[str] = field(default_factory=list)
    attacker_ips: list[str] = field(default_factory=list)
    centroid: Optional[np.ndarray] = None
    size: int = 0

    # Aggregate profile
    avg_sophistication: float = 0.0
    avg_automation: float = 0.0
    avg_stealth: float = 0.0
    primary_tactics: list[str] = field(default_factory=list)
    primary_tools: list[str] = field(default_factory=list)
    threat_level: str = "unknown"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    total_sessions: int = 0

    # Campaign indicators
    is_coordinated: bool = False
    coordination_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "label": self.label,
            "size": self.size,
            "attacker_ips": self.attacker_ips,
            "avg_sophistication": round(self.avg_sophistication, 3),
            "avg_automation": round(self.avg_automation, 3),
            "avg_stealth": round(self.avg_stealth, 3),
            "primary_tactics": self.primary_tactics,
            "primary_tools": self.primary_tools,
            "threat_level": self.threat_level,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "total_sessions": self.total_sessions,
            "is_coordinated": self.is_coordinated,
            "coordination_score": round(self.coordination_score, 3),
        }


class ThreatActorClusterer:
    """
    DBSCAN-based threat actor clustering engine.

    Clusters behavioural fingerprints to identify:
    1. Recurring threat actors (same person, different sessions)
    2. Coordinated campaigns (different people, same playbook)
    3. Tool-sharing groups (same tools, different objectives)
    4. Noise (one-off opportunistic attackers)

    Usage:
        clusterer = ThreatActorClusterer()

        # Add fingerprints
        clusterer.add_fingerprint(fp1)
        clusterer.add_fingerprint(fp2)

        # Run clustering
        clusters = clusterer.cluster()

        # Find cluster for a new fingerprint
        cluster = clusterer.assign(new_fp)
    """

    DEFAULT_EPSILON = 0.3  # Cosine distance threshold
    DEFAULT_MIN_SAMPLES = 3  # Minimum cluster size

    def __init__(
        self,
        epsilon: float = DEFAULT_EPSILON,
        min_samples: int = DEFAULT_MIN_SAMPLES,
    ):
        self._epsilon = epsilon
        self._min_samples = min_samples
        self._fingerprints: list = []  # BehaviouralFingerprint objects
        self._clusters: dict[str, ThreatActorCluster] = {}
        self._labels: Optional[np.ndarray] = None
        self._noise_indices: list[int] = []

        # Statistics
        self._total_clusterings: int = 0
        self._last_clustering_time_ms: float = 0.0

        logger.info(
            f"Threat actor clusterer initialised: "
            f"ε={epsilon}, MinPts={min_samples}"
        )

    def add_fingerprint(self, fingerprint) -> None:
        """Add a fingerprint to the clustering pool."""
        self._fingerprints.append(fingerprint)

    def add_fingerprints(self, fingerprints: list) -> None:
        """Add multiple fingerprints."""
        self._fingerprints.extend(fingerprints)

    def cluster(self) -> list[ThreatActorCluster]:
        """
        Run DBSCAN clustering on all fingerprints.

        Returns list of discovered clusters.
        """
        start = time.perf_counter()

        if len(self._fingerprints) < self._min_samples:
            logger.info(
                f"Not enough fingerprints for clustering: "
                f"{len(self._fingerprints)} < {self._min_samples}"
            )
            return []

        # Build distance matrix (cosine distance)
        n = len(self._fingerprints)
        vectors = np.array([fp.vector for fp in self._fingerprints])

        # Cosine similarity matrix
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        normalised = vectors / norms
        similarity_matrix = normalised @ normalised.T

        # Cosine distance matrix
        distance_matrix = 1.0 - similarity_matrix
        np.fill_diagonal(distance_matrix, 0.0)

        # Run DBSCAN
        labels = self._dbscan(distance_matrix)
        self._labels = labels

        # Build clusters
        self._clusters.clear()
        self._noise_indices = []

        cluster_map: dict[int, list[int]] = defaultdict(list)
        for i, label in enumerate(labels):
            if label == -1:
                self._noise_indices.append(i)
            else:
                cluster_map[label].append(i)

        clusters = []
        for cluster_label, indices in cluster_map.items():
            cluster = self._build_cluster(cluster_label, indices)
            self._clusters[cluster.cluster_id] = cluster
            clusters.append(cluster)

        elapsed_ms = (time.perf_counter() - start) * 1000
        self._total_clusterings += 1
        self._last_clustering_time_ms = elapsed_ms

        logger.info(
            f"Clustering complete: {len(clusters)} clusters, "
            f"{len(self._noise_indices)} noise points, "
            f"{n} total fingerprints, latency={elapsed_ms:.1f}ms"
        )

        return clusters

    def _dbscan(self, distance_matrix: np.ndarray) -> np.ndarray:
        """
        DBSCAN implementation using precomputed distance matrix.

        Returns array of cluster labels (-1 = noise).
        """
        n = distance_matrix.shape[0]
        labels = np.full(n, -1, dtype=int)
        visited = np.zeros(n, dtype=bool)
        cluster_id = 0

        for i in range(n):
            if visited[i]:
                continue

            visited[i] = True

            # Find neighbours within epsilon
            neighbours = self._region_query(distance_matrix, i)

            if len(neighbours) < self._min_samples:
                # Noise point (may be reassigned later as border)
                labels[i] = -1
            else:
                # Core point — start new cluster
                self._expand_cluster(
                    distance_matrix, labels, visited,
                    i, neighbours, cluster_id,
                )
                cluster_id += 1

        return labels

    def _region_query(
        self,
        distance_matrix: np.ndarray,
        point_idx: int,
    ) -> list[int]:
        """Find all points within epsilon distance of point_idx."""
        distances = distance_matrix[point_idx]
        return [
            j for j, d in enumerate(distances)
            if d <= self._epsilon and j != point_idx
        ]

    def _expand_cluster(
        self,
        distance_matrix: np.ndarray,
        labels: np.ndarray,
        visited: np.ndarray,
        point_idx: int,
        neighbours: list[int],
        cluster_id: int,
    ) -> None:
        """Expand a cluster from a core point."""
        labels[point_idx] = cluster_id

        # Use a queue for BFS expansion
        queue = list(neighbours)
        idx = 0

        while idx < len(queue):
            neighbour = queue[idx]
            idx += 1

            if not visited[neighbour]:
                visited[neighbour] = True

                # Find this neighbour's neighbours
                new_neighbours = self._region_query(distance_matrix, neighbour)

                if len(new_neighbours) >= self._min_samples:
                    # This neighbour is also a core point — expand
                    for nn in new_neighbours:
                        if nn not in queue:
                            queue.append(nn)

            # Assign to cluster if not already assigned
            if labels[neighbour] == -1:
                labels[neighbour] = cluster_id

    def _build_cluster(
        self,
        cluster_label: int,
        indices: list[int],
    ) -> ThreatActorCluster:
        """Build a ThreatActorCluster from fingerprint indices."""
        fingerprints = [self._fingerprints[i] for i in indices]

        # Compute centroid
        vectors = np.array([fp.vector for fp in fingerprints])
        centroid = np.mean(vectors, axis=0)
        norm = np.linalg.norm(centroid)
        if norm > 0:
            centroid = centroid / norm

        # Aggregate features
        ips = list(set(fp.attacker_ip for fp in fingerprints if fp.attacker_ip))
        all_tools = set()
        all_tactics = []
        sophistication_scores = []
        automation_scores = []
        stealth_scores = []
        timestamps = []

        for fp in fingerprints:
            all_tools.update(fp.primary_tools)
            if fp.primary_tactic:
                all_tactics.append(fp.primary_tactic)
            sophistication_scores.append(fp.sophistication)
            automation_scores.append(fp.automation)
            stealth_scores.append(fp.stealth)
            if fp.computed_at:
                timestamps.append(fp.computed_at)

        # Primary tactics (most common)
        tactic_counts: dict[str, int] = {}
        for t in all_tactics:
            tactic_counts[t] = tactic_counts.get(t, 0) + 1
        primary_tactics = sorted(
            tactic_counts.keys(),
            key=lambda t: tactic_counts[t],
            reverse=True,
        )[:3]

        # Threat level from average sophistication
        avg_soph = float(np.mean(sophistication_scores)) if sophistication_scores else 0
        if avg_soph >= 0.7:
            threat_level = "critical"
        elif avg_soph >= 0.5:
            threat_level = "high"
        elif avg_soph >= 0.3:
            threat_level = "medium"
        else:
            threat_level = "low"

        # Coordination score
        coordination = self._compute_coordination_score(fingerprints)

        # Cluster ID
        cluster_id = hashlib.sha256(
            f"cluster-{cluster_label}-{len(indices)}".encode()
        ).hexdigest()[:12]

        # Generate label
        label = self._generate_cluster_label(
            primary_tactics, sorted(all_tools)[:3], threat_level, len(ips)
        )

        # Timestamps
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None

        return ThreatActorCluster(
            cluster_id=cluster_id,
            label=label,
            fingerprint_ids=[fp.fingerprint_id for fp in fingerprints],
            attacker_ips=ips,
            centroid=centroid,
            size=len(indices),
            avg_sophistication=avg_soph,
            avg_automation=float(np.mean(automation_scores)) if automation_scores else 0,
            avg_stealth=float(np.mean(stealth_scores)) if stealth_scores else 0,
            primary_tactics=primary_tactics,
            primary_tools=sorted(all_tools)[:5],
            threat_level=threat_level,
            first_seen=first_seen,
            last_seen=last_seen,
            total_sessions=len(indices),
            is_coordinated=coordination > 0.6,
            coordination_score=coordination,
        )

    def _compute_coordination_score(self, fingerprints: list) -> float:
        """
        Compute coordination score for a cluster.

        High coordination = multiple IPs using very similar techniques
        in a short time window (suggests organised campaign).
        """
        if len(fingerprints) < 2:
            return 0.0

        # Multiple IPs = potential coordination
        unique_ips = len(set(fp.attacker_ip for fp in fingerprints if fp.attacker_ip))
        ip_diversity = min(1.0, unique_ips / 5)

        # Technique similarity within cluster
        vectors = np.array([fp.vector for fp in fingerprints])
        if len(vectors) > 1:
            # Average pairwise similarity
            norms = np.linalg.norm(vectors, axis=1, keepdims=True)
            norms[norms == 0] = 1.0
            normalised = vectors / norms
            sim_matrix = normalised @ normalised.T
            np.fill_diagonal(sim_matrix, 0)
            n = len(vectors)
            avg_similarity = sim_matrix.sum() / (n * (n - 1)) if n > 1 else 0
        else:
            avg_similarity = 0.0

        # Temporal clustering (sessions close in time)
        temporal_score = 0.5  # Default

        # Coordination = diverse IPs × high similarity × temporal clustering
        coordination = (
            ip_diversity * 0.3
            + float(avg_similarity) * 0.5
            + temporal_score * 0.2
        )

        return min(1.0, coordination)

    def _generate_cluster_label(
        self,
        tactics: list[str],
        tools: list[str],
        threat_level: str,
        num_ips: int,
    ) -> str:
        """Generate a human-readable label for a cluster."""
        parts = []

        if threat_level in ("critical", "high"):
            parts.append("Advanced")
        elif threat_level == "medium":
            parts.append("Intermediate")
        else:
            parts.append("Basic")

        if tactics:
            tactic_names = {
                "discovery": "Recon",
                "credential_access": "Credential",
                "execution": "Execution",
                "persistence": "Persistence",
                "exfiltration": "Exfiltration",
                "impact": "Destructive",
                "lateral_movement": "Lateral",
                "privilege_escalation": "PrivEsc",
            }
            primary = tactic_names.get(tactics[0], tactics[0].title())
            parts.append(primary)

        if num_ips > 1:
            parts.append(f"Campaign ({num_ips} IPs)")
        else:
            parts.append("Actor")

        return " ".join(parts)

    def assign(self, fingerprint) -> Optional[ThreatActorCluster]:
        """
        Assign a new fingerprint to the nearest existing cluster.

        Returns the cluster if within epsilon, None if noise.
        """
        if not self._clusters:
            return None

        best_cluster = None
        best_distance = float("inf")

        for cluster in self._clusters.values():
            if cluster.centroid is not None:
                # Cosine distance to centroid
                dot = np.dot(fingerprint.vector, cluster.centroid)
                norm_a = np.linalg.norm(fingerprint.vector)
                norm_b = np.linalg.norm(cluster.centroid)
                if norm_a > 0 and norm_b > 0:
                    similarity = dot / (norm_a * norm_b)
                    distance = 1.0 - similarity
                else:
                    distance = 1.0

                if distance < best_distance:
                    best_distance = distance
                    best_cluster = cluster

        if best_distance <= self._epsilon and best_cluster is not None:
            return best_cluster

        return None

    def get_cluster(self, cluster_id: str) -> Optional[dict]:
        """Get a specific cluster."""
        cluster = self._clusters.get(cluster_id)
        return cluster.to_dict() if cluster else None

    def get_all_clusters(self) -> list[dict]:
        """Get all clusters."""
        return [c.to_dict() for c in self._clusters.values()]

    def get_noise_count(self) -> int:
        """Get number of noise (unclustered) fingerprints."""
        return len(self._noise_indices)

    def get_stats(self) -> dict:
        """Return clustering statistics."""
        return {
            "total_fingerprints": len(self._fingerprints),
            "total_clusters": len(self._clusters),
            "noise_points": len(self._noise_indices),
            "total_clusterings": self._total_clusterings,
            "last_clustering_time_ms": round(self._last_clustering_time_ms, 2),
            "epsilon": self._epsilon,
            "min_samples": self._min_samples,
            "cluster_sizes": {
                c.cluster_id: c.size for c in self._clusters.values()
            },
        }


# Module-level singleton
_clusterer: Optional[ThreatActorClusterer] = None


def get_threat_clusterer() -> ThreatActorClusterer:
    """Get or create the singleton ThreatActorClusterer instance."""
    global _clusterer
    if _clusterer is None:
        _clusterer = ThreatActorClusterer()
    return _clusterer
