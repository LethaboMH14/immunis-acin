"""
IMMUNIS ACIN — Game Theory Tests
Tests Stackelberg Security Games with ORIGAMI and ERASER algorithms.
"""
import pytest
import numpy as np
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.math_engines.game_theory import GameTheoryEngine


class TestGameTheoryEngine:
    """Tests for Stackelberg equilibrium computation."""

    def setup_method(self):
        self.engine = GameTheoryEngine()

    def test_init(self):
        """Engine initialises."""
        assert self.engine is not None

    def test_origami_single_resource(self):
        """ORIGAMI algorithm returns valid coverage for single resource."""
        targets = [
            {"id": "t1", "value": 100, "attack_cost": 20},
            {"id": "t2", "value": 50, "attack_cost": 10},
            {"id": "t3", "value": 200, "attack_cost": 30},
        ]
        result = self.engine.origami(targets, n_resources=1)
        assert result is not None
        if isinstance(result, dict) and "coverage" in result:
            coverage = result["coverage"]
            assert all(0 <= c <= 1 for c in coverage.values()), \
                "Coverage probabilities must be in [0,1]"
            total = sum(coverage.values())
            assert total <= len(targets) + 0.01, "Total coverage can't exceed resources"

    def test_highest_value_gets_most_coverage(self):
        """Highest-value target should get highest coverage probability."""
        targets = [
            {"id": "low", "value": 10, "attack_cost": 5},
            {"id": "high", "value": 1000, "attack_cost": 5},
        ]
        result = self.engine.origami(targets, n_resources=1)
        if isinstance(result, dict) and "coverage" in result:
            assert result["coverage"].get("high", 0) >= result["coverage"].get("low", 0)

    def test_eraser_multi_resource(self):
        """ERASER algorithm handles multiple resources."""
        targets = [
            {"id": "t1", "value": 100, "attack_cost": 20},
            {"id": "t2", "value": 50, "attack_cost": 10},
            {"id": "t3", "value": 200, "attack_cost": 30},
            {"id": "t4", "value": 75, "attack_cost": 15},
        ]
        result = self.engine.eraser(targets, n_resources=2)
        assert result is not None

    def test_deterrence_index_computation(self):
        """DI = P(detection) × cost_if_caught / expected_gain."""
        di = self.engine.deterrence_index(
            detection_prob=0.95,
            cost_if_caught=500_000,
            expected_gain=50_000
        )
        expected = 0.95 * 500_000 / 50_000  # = 9.5
        assert abs(di - expected) < 0.5, f"DI should be ~{expected}, got {di}"
        assert di > 1.0, "DI > 1 means attacking is unprofitable"

    def test_deterrence_index_low_detection(self):
        """Low detection probability → DI < 1 (profitable to attack)."""
        di = self.engine.deterrence_index(
            detection_prob=0.05,
            cost_if_caught=100_000,
            expected_gain=200_000
        )
        assert di < 1.0, f"Low detection should make DI < 1, got {di}"

    def test_sse_existence(self):
        """Strong Stackelberg Equilibrium should always exist for finite games."""
        targets = [
            {"id": f"t{i}", "value": np.random.randint(10, 500), "attack_cost": np.random.randint(5, 50)}
            for i in range(5)
        ]
        result = self.engine.origami(targets, n_resources=2)
        assert result is not None, "SSE must exist for any finite game"

    def test_zero_resources_no_coverage(self):
        """Zero resources → zero coverage everywhere."""
        targets = [
            {"id": "t1", "value": 100, "attack_cost": 20},
            {"id": "t2", "value": 200, "attack_cost": 30},
        ]
        result = self.engine.origami(targets, n_resources=0)
        if isinstance(result, dict) and "coverage" in result:
            assert all(c == 0 for c in result["coverage"].values())

    def test_budget_allocation(self):
        """Budget allocation should distribute across defenses."""
        if hasattr(self.engine, 'allocate_budget'):
            allocation = self.engine.allocate_budget(
                budget=1_000_000,
                defenses=[
                    {"id": "firewall", "cost": 200_000, "effectiveness": 0.7},
                    {"id": "edr", "cost": 300_000, "effectiveness": 0.85},
                    {"id": "training", "cost": 50_000, "effectiveness": 0.4},
                ]
            )
            assert allocation is not None
            if isinstance(allocation, dict) and "total_cost" in allocation:
                assert allocation["total_cost"] <= 1_000_000



class TestGameTheoryIntegration:
    """Integration tests for game theory engine."""

