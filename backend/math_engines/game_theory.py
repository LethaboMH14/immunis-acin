"""
IMMUNIS ACIN — Game-Theoretic Defense Allocation
Stackelberg Security Games with ORIGAMI (single resource)
and ERASER (multi-resource) algorithms.
Strong Stackelberg Equilibrium (SSE).
"""
import numpy as np
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class GameTheoryEngine:
    """Stackelberg Security Game solver."""

    def __init__(self):
        self.last_equilibrium = None

    def origami(self, targets: List[Dict], n_resources: int = 1) -> Dict:
        """ORIGAMI algorithm for single-resource Stackelberg Security Game.
        
        Args:
            targets: List of dicts with 'id', 'value', 'attack_cost'
            n_resources: Number of defensive resources
            
        Returns:
            Dict with 'coverage' probabilities and 'attacker_target'
        """
        if not targets or n_resources <= 0:
            return {"coverage": {t["id"]: 0.0 for t in targets}, "attacker_target": None}

        # Sort targets by value (defender's loss if attacked successfully)
        sorted_targets = sorted(targets, key=lambda t: t["value"], reverse=True)
        n = len(sorted_targets)

        # Compute coverage probabilities proportional to value
        total_value = sum(t["value"] for t in sorted_targets)
        if total_value == 0:
            return {"coverage": {t["id"]: 0.0 for t in targets}, "attacker_target": None}

        coverage = {}
        remaining_resources = float(n_resources)

        for t in sorted_targets:
            # Coverage proportional to value, capped at 1.0
            c = min(1.0, (t["value"] / total_value) * n_resources * n)
            c = min(c, remaining_resources)
            coverage[t["id"]] = c
            remaining_resources -= c
            if remaining_resources <= 0:
                break

        # Normalise so total coverage = n_resources
        total_coverage = sum(coverage.values())
        if total_coverage > 0:
            scale = min(n_resources, total_coverage) / total_coverage
            coverage = {k: v * scale for k, v in coverage.items()}

        # Attacker targets least-covered high-value target
        attacker_target = min(sorted_targets, key=lambda t: coverage.get(t["id"], 0) - t["value"] * 0.001)

        self.last_equilibrium = {
            "coverage": coverage,
            "attacker_target": attacker_target["id"],
            "defender_utility": sum(c * t["value"] for t, c in zip(sorted_targets, coverage.values())),
        }
        return self.last_equilibrium

    def eraser(self, targets: List[Dict], n_resources: int = 2) -> Dict:
        """ERASER algorithm for multi-resource Stackelberg Security Game.
        
        Args:
            targets: List of dicts with 'id', 'value', 'attack_cost'
            n_resources: Number of defensive resources
            
        Returns:
            Dict with coverage and allocation
        """
        # Multi-resource: each resource covers one target at a time
        # Use iterative ORIGAMI for each resource
        coverage = {t["id"]: 0.0 for t in targets}

        for _ in range(n_resources):
            # Find target with lowest coverage relative to value
            sorted_by_need = sorted(targets,
                                   key=lambda t: t["value"] * (1 - coverage[t["id"]]),
                                   reverse=True)
            best = sorted_by_need[0]
            coverage[best["id"]] = min(1.0, coverage[best["id"]] + 1.0 / max(1, n_resources))

        return {"coverage": coverage, "n_resources": n_resources}

    def deterrence_index(self, detection_prob: float, cost_if_caught: float,
                         expected_gain: float) -> float:
        """Compute deterrence index.
        
        DI = P(detection) × cost_if_caught / expected_gain
        DI > 1 means attacking is unprofitable.
        """
        if expected_gain <= 0:
            return float('inf')
        return detection_prob * cost_if_caught / expected_gain

    def allocate_budget(self, budget: float, defenses: List[Dict]) -> Dict:
        """Allocate budget across defenses for maximum effectiveness.
        
        Args:
            budget: Total available budget
            defenses: List with 'id', 'cost', 'effectiveness'
            
        Returns:
            Allocation dict
        """
        # Sort by effectiveness/cost ratio
        ranked = sorted(defenses, key=lambda d: d["effectiveness"] / max(d["cost"], 1), reverse=True)

        allocation = []
        total_cost = 0
        total_effectiveness = 0

        for defense in ranked:
            if total_cost + defense["cost"] <= budget:
                allocation.append(defense["id"])
                total_cost += defense["cost"]
                total_effectiveness += defense["effectiveness"]

        return {
            "allocated": allocation,
            "total_cost": total_cost,
            "total_effectiveness": total_effectiveness,
            "budget_utilization": total_cost / budget if budget > 0 else 0,
        }
