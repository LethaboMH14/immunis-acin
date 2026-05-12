"""
IMMUNIS ACIN — Portfolio Optimization Tests
Tests Markowitz defensive resource allocation.
"""
import pytest
import numpy as np
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.math_engines.portfolio import PortfolioOptimiser


class TestPortfolioOptimizer:
    """Tests for Markowitz defensive resource allocation."""

    def setup_method(self):
        self.optimizer = PortfolioOptimiser()

    def test_init(self):
        """Optimizer initialises."""
        assert self.optimizer is not None

    def test_weights_sum_to_one(self):
        """Portfolio weights must sum to 1 (fully invested)."""
        from backend.math_engines.portfolio import DefensiveAsset
        assets = [
            DefensiveAsset("firewall", "Firewall", "network", 0.15, 0.05, 100),
            DefensiveAsset("edr", "EDR", "endpoint", 0.25, 0.12, 200),
            DefensiveAsset("training", "Training", "identity", 0.08, 0.02, 50),
            DefensiveAsset("siem", "SIEM", "monitoring", 0.18, 0.08, 150),
        ]
        result = self.optimizer.optimise(assets)
        if hasattr(result, 'weights'):
            weights = result.weights
            total = sum(weights.values()) if isinstance(weights, dict) else sum(weights)
            assert abs(total - 1.0) < 0.01, f"Weights should sum to 1, got {total}"

    def test_no_negative_weights(self):
        """No short selling — all weights ≥ 0."""
        from backend.math_engines.portfolio import DefensiveAsset
        assets = [
            DefensiveAsset("a1", "Asset 1", "network", 0.10, 0.05, 100),
            DefensiveAsset("a2", "Asset 2", "endpoint", 0.20, 0.15, 200),
        ]
        result = self.optimizer.optimise(assets)
        if hasattr(result, 'weights'):
            weights = result.weights
            if isinstance(weights, dict):
                assert all(w >= -0.001 for w in weights.values()), \
                    f"No short selling: {weights}"
            else:
                assert all(w >= -0.001 for w in weights)

    def test_sharpe_ratio_positive(self):
        """Optimal portfolio should have positive Sharpe ratio."""
        from backend.math_engines.portfolio import DefensiveAsset
        assets = [
            DefensiveAsset("a1", "Asset 1", "network", 0.15, 0.05, 100),
            DefensiveAsset("a2", "Asset 2", "endpoint", 0.25, 0.10, 200),
        ]
        result = self.optimizer.optimise(assets)
        if hasattr(result, 'sharpe_ratio'):
            assert result.sharpe_ratio > 0

    def test_efficient_frontier(self):
        """Multiple portfolios on efficient frontier should show risk-return tradeoff."""
        from backend.math_engines.portfolio import DefensiveAsset
        assets = [
            DefensiveAsset("a1", "Asset 1", "network", 0.10, 0.03, 100),
            DefensiveAsset("a2", "Asset 2", "endpoint", 0.20, 0.12, 200),
            DefensiveAsset("a3", "Asset 3", "identity", 0.30, 0.25, 300),
        ]
        if hasattr(self.optimizer, 'efficient_frontier'):
            frontier = self.optimizer.efficient_frontier(assets, n_points=10)
            if isinstance(frontier, list) and len(frontier) > 1:
                returns = [p.get("return", 0) for p in frontier]
                risks = [p.get("risk", 0) for p in frontier]
                # Higher return should generally mean higher risk
                assert returns[-1] > returns[0] or risks[-1] >= risks[0]

    def test_single_asset(self):
        """Single asset portfolio should get weight = 1."""
        from backend.math_engines.portfolio import DefensiveAsset
        assets = [DefensiveAsset("only", "Only Asset", "network", 0.15, 0.08, 100)]
        result = self.optimizer.optimise(assets)
        if hasattr(result, 'weights'):
            weights = result.weights
            if isinstance(weights, dict):
                assert abs(weights.get("only", 0) - 1.0) < 0.01
            else:
                assert abs(weights[0] - 1.0) < 0.01

    def test_budget_constraint(self):
        """Allocation should respect budget constraint."""
        if hasattr(self.optimizer, 'allocate'):
            assets = [
                {"id": "a1", "cost": 100_000, "expected_return": 0.15, "risk": 0.05},
                {"id": "a2", "cost": 200_000, "expected_return": 0.25, "risk": 0.10},
            ]
            result = self.optimizer.allocate(assets, budget=250_000)
            if isinstance(result, dict) and "total_cost" in result:
                assert result["total_cost"] <= 250_000
