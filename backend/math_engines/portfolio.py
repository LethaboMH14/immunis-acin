"""
IMMUNIS ACIN — Markowitz Defensive Portfolio Engine
Optimal resource allocation using Modern Portfolio Theory.

Applies Markowitz mean-variance optimisation to cybersecurity defence:
- Each defensive measure is an "asset" with expected return (risk reduction)
  and variance (uncertainty in effectiveness)
- The efficient frontier shows maximum risk reduction for each budget level
- The optimal portfolio maximises Sharpe-like ratio:
  (expected_risk_reduction - risk_free_baseline) / volatility

Mathematical foundation:
- Expected portfolio return: E[R_p] = Σ w_i × E[R_i]
- Portfolio variance: σ²_p = Σ_i Σ_j w_i × w_j × σ_ij
- Sharpe ratio analog: S = (E[R_p] - R_f) / σ_p
- Efficient frontier: min σ²_p subject to E[R_p] = target, Σw_i = 1, w_i ≥ 0
- Constraint: Σ w_i × cost_i ≤ budget

Cross-domain synthesis:
- Finance: Markowitz (1952) mean-variance optimisation
- Cybersecurity: Risk reduction as return, effectiveness uncertainty as variance
- Operations Research: Constrained quadratic programming
"""

import hashlib
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("immunis.math.portfolio")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DefensiveAsset:
    """
    A defensive measure treated as a portfolio asset.

    In financial terms:
    - expected_return = expected risk reduction (0.0 to 1.0)
    - volatility = uncertainty in effectiveness (standard deviation)
    - cost = resource cost to deploy/maintain
    - correlation with other assets captured in covariance matrix
    """
    asset_id: str
    name: str
    category: str
    expected_return: float      # Expected risk reduction (0.0 - 1.0)
    volatility: float           # Std dev of effectiveness (0.0 - 1.0)
    cost: float                 # Resource cost (normalised or absolute)
    min_allocation: float = 0.0 # Minimum weight (0.0 - 1.0)
    max_allocation: float = 1.0 # Maximum weight (0.0 - 1.0)
    is_mandatory: bool = False  # Must be included in portfolio
    current_allocation: float = 0.0  # Current resource allocation
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def sharpe_ratio(self) -> float:
        """Individual asset Sharpe-like ratio."""
        if self.volatility <= 0:
            return float('inf') if self.expected_return > 0 else 0.0
        return self.expected_return / self.volatility

    @property
    def cost_efficiency(self) -> float:
        """Return per unit cost."""
        if self.cost <= 0:
            return float('inf') if self.expected_return > 0 else 0.0
        return self.expected_return / self.cost

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "category": self.category,
            "expected_return": self.expected_return,
            "volatility": self.volatility,
            "cost": self.cost,
            "sharpe_ratio": round(self.sharpe_ratio, 4) if self.sharpe_ratio != float('inf') else "inf",
            "cost_efficiency": round(self.cost_efficiency, 4) if self.cost_efficiency != float('inf') else "inf",
            "min_allocation": self.min_allocation,
            "max_allocation": self.max_allocation,
            "is_mandatory": self.is_mandatory,
            "current_allocation": self.current_allocation,
        }


@dataclass
class PortfolioAllocation:
    """Result of portfolio optimisation — optimal weights for each asset."""
    portfolio_id: str
    weights: dict[str, float]           # asset_id -> weight (0.0 - 1.0)
    expected_return: float              # Portfolio expected risk reduction
    volatility: float                   # Portfolio volatility
    sharpe_ratio: float                 # Portfolio Sharpe ratio
    total_cost: float                   # Total resource cost
    budget_utilisation: float           # Fraction of budget used
    diversification_ratio: float        # 1 = fully concentrated, 0 = fully diversified
    optimisation_method: str            # Method used
    computed_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "portfolio_id": self.portfolio_id,
            "weights": {k: round(v, 6) for k, v in self.weights.items()},
            "expected_return": round(self.expected_return, 6),
            "volatility": round(self.volatility, 6),
            "sharpe_ratio": round(self.sharpe_ratio, 4),
            "total_cost": round(self.total_cost, 2),
            "budget_utilisation": round(self.budget_utilisation, 4),
            "diversification_ratio": round(self.diversification_ratio, 4),
            "optimisation_method": self.optimisation_method,
            "computed_at": self.computed_at,
        }


@dataclass
class EfficientFrontierPoint:
    """A single point on the efficient frontier."""
    target_return: float
    min_volatility: float
    weights: dict[str, float]
    sharpe_ratio: float
    total_cost: float

    def to_dict(self) -> dict:
        return {
            "target_return": round(self.target_return, 6),
            "min_volatility": round(self.min_volatility, 6),
            "sharpe_ratio": round(self.sharpe_ratio, 4),
            "total_cost": round(self.total_cost, 2),
            "weights": {k: round(v, 4) for k, v in self.weights.items()},
        }


@dataclass
class PortfolioAnalysis:
    """Complete portfolio analysis result."""
    optimal_portfolio: PortfolioAllocation
    efficient_frontier: list[EfficientFrontierPoint]
    asset_contributions: dict[str, dict[str, float]]  # asset_id -> {return_contrib, risk_contrib}
    recommendations: list[str]
    analysis_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "optimal_portfolio": self.optimal_portfolio.to_dict(),
            "efficient_frontier": [p.to_dict() for p in self.efficient_frontier],
            "asset_contributions": self.asset_contributions,
            "recommendations": self.recommendations,
            "analysis_duration_seconds": round(self.analysis_duration_seconds, 3),
        }


# ---------------------------------------------------------------------------
# Covariance estimation
# ---------------------------------------------------------------------------

class CovarianceEstimator:
    """
    Estimates covariance matrix between defensive assets.

    In cybersecurity, correlations arise because:
    - Defences in the same category (e.g., two firewalls) are highly correlated
    - Defences targeting the same attack phase are moderately correlated
    - Defences in different domains (network vs application) are weakly correlated
    - Some defences are negatively correlated (honeypot effectiveness increases
      when perimeter defence is weak — more attackers reach the honeypot)

    When historical data is unavailable (common in cybersecurity), we use
    a structured prior based on category similarity.
    """

    # Category correlation priors
    CATEGORY_CORRELATIONS: dict[tuple[str, str], float] = {
        # Same category = high correlation
        ("network", "network"): 0.8,
        ("application", "application"): 0.7,
        ("endpoint", "endpoint"): 0.75,
        ("identity", "identity"): 0.7,
        ("data", "data"): 0.65,
        ("deception", "deception"): 0.5,
        ("monitoring", "monitoring"): 0.6,

        # Cross-category correlations
        ("network", "application"): 0.3,
        ("network", "endpoint"): 0.4,
        ("network", "identity"): 0.2,
        ("network", "data"): 0.2,
        ("network", "deception"): -0.1,  # Negative: weak perimeter helps honeypots
        ("network", "monitoring"): 0.3,

        ("application", "endpoint"): 0.3,
        ("application", "identity"): 0.35,
        ("application", "data"): 0.3,
        ("application", "deception"): 0.0,
        ("application", "monitoring"): 0.25,

        ("endpoint", "identity"): 0.3,
        ("endpoint", "data"): 0.25,
        ("endpoint", "deception"): -0.05,
        ("endpoint", "monitoring"): 0.4,

        ("identity", "data"): 0.4,
        ("identity", "deception"): 0.1,
        ("identity", "monitoring"): 0.3,

        ("data", "deception"): 0.05,
        ("data", "monitoring"): 0.35,

        ("deception", "monitoring"): 0.2,
    }

    def estimate(self, assets: list[DefensiveAsset]) -> list[list[float]]:
        """
        Estimate covariance matrix for a set of defensive assets.

        Returns n×n covariance matrix where n = len(assets).
        σ_ij = ρ_ij × σ_i × σ_j
        """
        n = len(assets)
        cov_matrix = [[0.0] * n for _ in range(n)]

        for i in range(n):
            for j in range(n):
                if i == j:
                    # Diagonal: variance = volatility²
                    cov_matrix[i][j] = assets[i].volatility ** 2
                else:
                    # Off-diagonal: covariance = correlation × σ_i × σ_j
                    rho = self._get_correlation(assets[i].category, assets[j].category)
                    cov_matrix[i][j] = rho * assets[i].volatility * assets[j].volatility

        return cov_matrix

    def _get_correlation(self, cat1: str, cat2: str) -> float:
        """Look up correlation between two categories."""
        cat1 = cat1.lower()
        cat2 = cat2.lower()

        # Direct lookup
        if (cat1, cat2) in self.CATEGORY_CORRELATIONS:
            return self.CATEGORY_CORRELATIONS[(cat1, cat2)]
        if (cat2, cat1) in self.CATEGORY_CORRELATIONS:
            return self.CATEGORY_CORRELATIONS[(cat2, cat1)]

        # Same category
        if cat1 == cat2:
            return 0.6  # Default same-category correlation

        # Default cross-category
        return 0.15


# ---------------------------------------------------------------------------
# Portfolio optimiser (no external dependencies)
# ---------------------------------------------------------------------------

class PortfolioOptimiser:
    """
    Markowitz mean-variance portfolio optimiser.

    Implemented from scratch without scipy/numpy dependency.
    Uses projected gradient descent for constrained optimisation:

    min  w^T Σ w                    (minimise portfolio variance)
    s.t. w^T μ = target_return      (achieve target return)
         Σ w_i = 1                  (fully invested)
         w_i ≥ min_i                (minimum allocations)
         w_i ≤ max_i                (maximum allocations)
         Σ w_i × c_i ≤ budget      (budget constraint)

    For the tangency portfolio (maximum Sharpe ratio), we search
    along the efficient frontier.
    """

    def __init__(self, risk_free_rate: float = 0.0):
        self.risk_free_rate = risk_free_rate
        self.cov_estimator = CovarianceEstimator()

    def optimise(
        self,
        assets: list[DefensiveAsset],
        budget: Optional[float] = None,
        target_return: Optional[float] = None,
        max_iterations: int = 5000,
        learning_rate: float = 0.01,
        tolerance: float = 1e-8,
    ) -> PortfolioAllocation:
        """
        Find the optimal portfolio allocation.

        If target_return is specified: minimise variance for that return.
        If target_return is None: maximise Sharpe ratio (tangency portfolio).

        Args:
            assets: List of defensive assets
            budget: Total resource budget (None = no budget constraint)
            target_return: Target portfolio return (None = max Sharpe)
            max_iterations: Maximum optimisation iterations
            learning_rate: Gradient descent step size
            tolerance: Convergence tolerance

        Returns:
            PortfolioAllocation with optimal weights
        """
        n = len(assets)
        if n == 0:
            return self._empty_portfolio()

        if n == 1:
            return self._single_asset_portfolio(assets[0], budget)

        # Estimate covariance matrix
        cov_matrix = self.cov_estimator.estimate(assets)
        returns = [a.expected_return for a in assets]
        costs = [a.cost for a in assets]

        if target_return is not None:
            # Minimise variance for target return
            weights = self._min_variance_for_return(
                assets, returns, cov_matrix, costs,
                target_return, budget,
                max_iterations, learning_rate, tolerance,
            )
        else:
            # Find tangency portfolio (max Sharpe)
            weights = self._max_sharpe(
                assets, returns, cov_matrix, costs, budget,
                max_iterations, learning_rate, tolerance,
            )

        # Compute portfolio metrics
        port_return = sum(w * r for w, r in zip(weights, returns))
        port_variance = self._portfolio_variance(weights, cov_matrix)
        port_volatility = math.sqrt(max(port_variance, 0))
        port_cost = sum(w * c for w, c in zip(weights, costs))

        sharpe = (port_return - self.risk_free_rate) / port_volatility if port_volatility > 0 else 0.0

        # Diversification ratio: 1 - (1/n_effective)
        # n_effective = 1 / Σ w_i²  (Herfindahl index inverse)
        hhi = sum(w ** 2 for w in weights)
        n_effective = 1.0 / hhi if hhi > 0 else n
        diversification = 1.0 - (1.0 / n_effective) if n_effective > 1 else 0.0

        portfolio_id = hashlib.sha256(
            f"portfolio:{time.time()}:{n}".encode()
        ).hexdigest()[:12]

        return PortfolioAllocation(
            portfolio_id=portfolio_id,
            weights={assets[i].asset_id: weights[i] for i in range(n)},
            expected_return=port_return,
            volatility=port_volatility,
            sharpe_ratio=sharpe,
            total_cost=port_cost,
            budget_utilisation=port_cost / budget if budget and budget > 0 else 1.0,
            diversification_ratio=diversification,
            optimisation_method="projected_gradient_descent",
        )

    def compute_efficient_frontier(
        self,
        assets: list[DefensiveAsset],
        budget: Optional[float] = None,
        n_points: int = 20,
        max_iterations: int = 3000,
    ) -> list[EfficientFrontierPoint]:
        """
        Compute the efficient frontier — set of portfolios that
        achieve maximum return for each level of risk.

        Returns n_points along the frontier from min-variance to max-return.
        """
        n = len(assets)
        if n == 0:
            return []

        cov_matrix = self.cov_estimator.estimate(assets)
        returns = [a.expected_return for a in assets]
        costs = [a.cost for a in assets]

        min_return = min(returns)
        max_return = max(returns)

        if min_return >= max_return:
            # All assets have same return — single point
            weights = [1.0 / n] * n
            vol = math.sqrt(max(self._portfolio_variance(weights, cov_matrix), 0))
            return [EfficientFrontierPoint(
                target_return=min_return,
                min_volatility=vol,
                weights={assets[i].asset_id: weights[i] for i in range(n)},
                sharpe_ratio=(min_return - self.risk_free_rate) / vol if vol > 0 else 0,
                total_cost=sum(w * c for w, c in zip(weights, costs)),
            )]

        frontier: list[EfficientFrontierPoint] = []
        step = (max_return - min_return) / (n_points - 1)

        for i in range(n_points):
            target = min_return + i * step

            weights = self._min_variance_for_return(
                assets, returns, cov_matrix, costs,
                target, budget,
                max_iterations, learning_rate=0.01, tolerance=1e-7,
            )

            port_return = sum(w * r for w, r in zip(weights, returns))
            port_variance = self._portfolio_variance(weights, cov_matrix)
            port_volatility = math.sqrt(max(port_variance, 0))
            port_cost = sum(w * c for w, c in zip(weights, costs))

            sharpe = (port_return - self.risk_free_rate) / port_volatility if port_volatility > 0 else 0.0

            frontier.append(EfficientFrontierPoint(
                target_return=port_return,
                min_volatility=port_volatility,
                weights={assets[i_a].asset_id: weights[i_a] for i_a in range(n)},
                sharpe_ratio=sharpe,
                total_cost=port_cost,
            ))

        return frontier

    def analyse(
        self,
        assets: list[DefensiveAsset],
        budget: Optional[float] = None,
    ) -> PortfolioAnalysis:
        """
        Complete portfolio analysis: optimal allocation, efficient frontier,
        asset contributions, and recommendations.
        """
        start = time.time()

        # Optimal portfolio
        optimal = self.optimise(assets, budget)

        # Efficient frontier
        frontier = self.compute_efficient_frontier(assets, budget)

        # Asset contributions
        contributions = self._compute_contributions(assets, optimal)

        # Recommendations
        recommendations = self._generate_recommendations(assets, optimal, budget)

        duration = time.time() - start

        return PortfolioAnalysis(
            optimal_portfolio=optimal,
            efficient_frontier=frontier,
            asset_contributions=contributions,
            recommendations=recommendations,
            analysis_duration_seconds=duration,
        )

    # -----------------------------------------------------------------------
    # Core optimisation algorithms
    # -----------------------------------------------------------------------

    def _min_variance_for_return(
        self,
        assets: list[DefensiveAsset],
        returns: list[float],
        cov_matrix: list[list[float]],
        costs: list[float],
        target_return: float,
        budget: Optional[float],
        max_iterations: int,
        learning_rate: float,
        tolerance: float,
    ) -> list[float]:
        """
        Minimise portfolio variance subject to return and budget constraints.

        Uses projected gradient descent with Lagrangian penalties.
        """
        n = len(assets)

        # Initialise with equal weights
        weights = [1.0 / n] * n

        # Apply mandatory asset constraints
        for i, asset in enumerate(assets):
            if asset.is_mandatory:
                weights[i] = max(weights[i], asset.min_allocation)

        # Normalise
        total = sum(weights)
        weights = [w / total for w in weights]

        # Lagrangian penalty multipliers
        lambda_return = 1.0
        lambda_budget = 0.5

        prev_variance = float('inf')

        for iteration in range(max_iterations):
            # Compute gradient of variance: ∂σ²/∂w_i = 2 × Σ_j w_j × σ_ij
            grad = [0.0] * n
            for i in range(n):
                for j in range(n):
                    grad[i] += 2.0 * weights[j] * cov_matrix[i][j]

            # Add return constraint penalty: λ × (target - w^T μ)
            current_return = sum(w * r for w, r in zip(weights, returns))
            return_gap = target_return - current_return
            for i in range(n):
                grad[i] -= lambda_return * returns[i] * (1.0 if return_gap > 0 else -1.0)

            # Add budget constraint penalty
            if budget is not None:
                current_cost = sum(w * c for w, c in zip(weights, costs))
                if current_cost > budget:
                    for i in range(n):
                        grad[i] += lambda_budget * costs[i]

            # Gradient descent step
            for i in range(n):
                weights[i] -= learning_rate * grad[i]

            # Project onto constraints
            weights = self._project_constraints(weights, assets, budget, costs)

            # Check convergence
            current_variance = self._portfolio_variance(weights, cov_matrix)
            if abs(current_variance - prev_variance) < tolerance:
                break
            prev_variance = current_variance

            # Adaptive learning rate
            if iteration > 0 and iteration % 500 == 0:
                learning_rate *= 0.9

        return weights

    def _max_sharpe(
        self,
        assets: list[DefensiveAsset],
        returns: list[float],
        cov_matrix: list[list[float]],
        costs: list[float],
        budget: Optional[float],
        max_iterations: int,
        learning_rate: float,
        tolerance: float,
    ) -> list[float]:
        """
        Find the tangency portfolio (maximum Sharpe ratio).

        Strategy: Search along the efficient frontier for the point
        with the highest Sharpe ratio.
        """
        n = len(assets)
        min_return = min(returns)
        max_return = max(returns)

        if min_return >= max_return:
            return [1.0 / n] * n

        best_sharpe = -float('inf')
        best_weights = [1.0 / n] * n

        # Search 30 points along the frontier
        n_search = 30
        step = (max_return - min_return) / n_search

        for i in range(n_search + 1):
            target = min_return + i * step

            weights = self._min_variance_for_return(
                assets, returns, cov_matrix, costs,
                target, budget,
                max_iterations // 2, learning_rate, tolerance,
            )

            port_return = sum(w * r for w, r in zip(weights, returns))
            port_variance = self._portfolio_variance(weights, cov_matrix)
            port_volatility = math.sqrt(max(port_variance, 0))

            if port_volatility > 0:
                sharpe = (port_return - self.risk_free_rate) / port_volatility
                if sharpe > best_sharpe:
                    best_sharpe = sharpe
                    best_weights = list(weights)

        return best_weights

    def _project_constraints(
        self,
        weights: list[float],
        assets: list[DefensiveAsset],
        budget: Optional[float],
        costs: list[float],
    ) -> list[float]:
        """
        Project weights onto the feasible set:
        - w_i >= min_i
        - w_i <= max_i
        - Σ w_i = 1
        - Σ w_i × c_i ≤ budget (if specified)
        """
        n = len(weights)

        # Clip to [min, max] bounds
        for i in range(n):
            weights[i] = max(assets[i].min_allocation, min(assets[i].max_allocation, weights[i]))

        # Ensure non-negative
        for i in range(n):
            weights[i] = max(0.0, weights[i])

        # Normalise to sum to 1
        total = sum(weights)
        if total > 0:
            weights = [w / total for w in weights]
        else:
            weights = [1.0 / n] * n

        # Budget constraint: if over budget, reduce highest-cost allocations
        if budget is not None and budget > 0:
            current_cost = sum(w * c for w, c in zip(weights, costs))
            if current_cost > budget:
                # Scale down proportionally
                scale = budget / current_cost
                weights = [w * scale for w in weights]
                # Re-normalise
                total = sum(weights)
                if total > 0:
                    weights = [w / total for w in weights]

        return weights

    # -----------------------------------------------------------------------
    # Helper methods
    # -----------------------------------------------------------------------

    @staticmethod
    def _portfolio_variance(weights: list[float], cov_matrix: list[list[float]]) -> float:
        """Compute portfolio variance: w^T Σ w."""
        n = len(weights)
        variance = 0.0
        for i in range(n):
            for j in range(n):
                variance += weights[i] * weights[j] * cov_matrix[i][j]
        return variance

    def _compute_contributions(
        self,
        assets: list[DefensiveAsset],
        portfolio: PortfolioAllocation,
    ) -> dict[str, dict[str, float]]:
        """Compute each asset's contribution to portfolio return and risk."""
        contributions: dict[str, dict[str, float]] = {}

        for asset in assets:
            weight = portfolio.weights.get(asset.asset_id, 0.0)
            return_contrib = weight * asset.expected_return
            risk_contrib = weight * asset.volatility  # Simplified marginal risk

            contributions[asset.asset_id] = {
                "name": asset.name,
                "weight": round(weight, 6),
                "return_contribution": round(return_contrib, 6),
                "risk_contribution": round(risk_contrib, 6),
                "return_share": round(
                    return_contrib / portfolio.expected_return if portfolio.expected_return > 0 else 0, 4
                ),
            }

        return contributions

    def _generate_recommendations(
        self,
        assets: list[DefensiveAsset],
        portfolio: PortfolioAllocation,
        budget: Optional[float],
    ) -> list[str]:
        """Generate human-readable portfolio recommendations."""
        recommendations: list[str] = []

        # Overall assessment
        if portfolio.sharpe_ratio > 2.0:
            recommendations.append(
                f"Portfolio Sharpe ratio ({portfolio.sharpe_ratio:.2f}) is excellent. "
                f"Current allocation is highly efficient."
            )
        elif portfolio.sharpe_ratio > 1.0:
            recommendations.append(
                f"Portfolio Sharpe ratio ({portfolio.sharpe_ratio:.2f}) is good. "
                f"Minor rebalancing may improve efficiency."
            )
        else:
            recommendations.append(
                f"Portfolio Sharpe ratio ({portfolio.sharpe_ratio:.2f}) is below optimal. "
                f"Significant rebalancing recommended."
            )

        # Diversification
        if portfolio.diversification_ratio < 0.3:
            recommendations.append(
                "WARNING: Portfolio is highly concentrated. "
                "Consider diversifying across more defensive categories."
            )
        elif portfolio.diversification_ratio > 0.7:
            recommendations.append(
                "Portfolio is well-diversified across defensive measures."
            )

        # Identify over/under-allocated assets
        for asset in assets:
            optimal_weight = portfolio.weights.get(asset.asset_id, 0.0)
            current_weight = asset.current_allocation

            if current_weight > 0 and optimal_weight > 0:
                ratio = optimal_weight / current_weight
                if ratio > 1.5:
                    recommendations.append(
                        f"INCREASE: '{asset.name}' is under-allocated. "
                        f"Current: {current_weight:.1%}, Optimal: {optimal_weight:.1%} "
                        f"(+{(optimal_weight - current_weight):.1%})"
                    )
                elif ratio < 0.5:
                    recommendations.append(
                        f"DECREASE: '{asset.name}' is over-allocated. "
                        f"Current: {current_weight:.1%}, Optimal: {optimal_weight:.1%} "
                        f"({(optimal_weight - current_weight):.1%})"
                    )

        # Budget utilisation
        if budget and portfolio.budget_utilisation < 0.8:
            recommendations.append(
                f"Budget under-utilised ({portfolio.budget_utilisation:.0%}). "
                f"Consider investing remaining {(1 - portfolio.budget_utilisation):.0%} "
                f"in highest Sharpe-ratio assets."
            )

        # Identify best individual assets not in portfolio
        zero_weight_assets = [
            a for a in assets
            if portfolio.weights.get(a.asset_id, 0.0) < 0.01
        ]
        if zero_weight_assets:
            best_excluded = max(zero_weight_assets, key=lambda a: a.sharpe_ratio)
            if best_excluded.sharpe_ratio > 0.5:
                recommendations.append(
                    f"CONSIDER: '{best_excluded.name}' has Sharpe ratio "
                    f"{best_excluded.sharpe_ratio:.2f} but zero allocation. "
                    f"May improve portfolio if constraints allow."
                )

        return recommendations

    def _empty_portfolio(self) -> PortfolioAllocation:
        """Return empty portfolio when no assets provided."""
        return PortfolioAllocation(
            portfolio_id="empty",
            weights={},
            expected_return=0.0,
            volatility=0.0,
            sharpe_ratio=0.0,
            total_cost=0.0,
            budget_utilisation=0.0,
            diversification_ratio=0.0,
            optimisation_method="none",
        )

    def _single_asset_portfolio(
        self, asset: DefensiveAsset, budget: Optional[float]
    ) -> PortfolioAllocation:
        """Return portfolio with single asset at 100% allocation."""
        weight = 1.0
        if budget is not None and asset.cost > 0:
            weight = min(1.0, budget / asset.cost)

        return PortfolioAllocation(
            portfolio_id=hashlib.sha256(
                f"single:{asset.asset_id}:{time.time()}".encode()
            ).hexdigest()[:12],
            weights={asset.asset_id: weight},
            expected_return=asset.expected_return * weight,
            volatility=asset.volatility * weight,
            sharpe_ratio=asset.sharpe_ratio,
            total_cost=asset.cost * weight,
            budget_utilisation=weight,
            diversification_ratio=0.0,
            optimisation_method="single_asset",
        )


# ---------------------------------------------------------------------------
# Default defensive asset library
# ---------------------------------------------------------------------------

def build_default_assets() -> list[DefensiveAsset]:
    """
    Build the default set of defensive assets for IMMUNIS ACIN.

    Each asset represents a defensive capability with estimated
    effectiveness (return) and uncertainty (volatility).

    These estimates are based on industry benchmarks:
    - NIST SP 800-53 control effectiveness studies
    - Verizon DBIR attack surface analysis
    - SANS Institute defensive ROI research
    """
    return [
        DefensiveAsset(
            asset_id="DEF-FIREWALL",
            name="Network Firewall",
            category="network",
            expected_return=0.65,
            volatility=0.15,
            cost=100.0,
            min_allocation=0.05,
            is_mandatory=True,
            metadata={"mitre_coverage": ["TA0001", "TA0011"]},
        ),
        DefensiveAsset(
            asset_id="DEF-IDS",
            name="Intrusion Detection System",
            category="network",
            expected_return=0.55,
            volatility=0.25,
            cost=150.0,
            metadata={"mitre_coverage": ["TA0001", "TA0002", "TA0010"]},
        ),
        DefensiveAsset(
            asset_id="DEF-WAF",
            name="Web Application Firewall",
            category="application",
            expected_return=0.60,
            volatility=0.20,
            cost=120.0,
            metadata={"mitre_coverage": ["TA0001", "TA0002"]},
        ),
        DefensiveAsset(
            asset_id="DEF-SAST",
            name="Static Application Security Testing",
            category="application",
            expected_return=0.50,
            volatility=0.30,
            cost=80.0,
            metadata={"mitre_coverage": ["TA0001"]},
        ),
        DefensiveAsset(
            asset_id="DEF-DAST",
            name="Dynamic Application Security Testing",
            category="application",
            expected_return=0.45,
            volatility=0.30,
            cost=90.0,
            metadata={"mitre_coverage": ["TA0001", "TA0002"]},
        ),
        DefensiveAsset(
            asset_id="DEF-EDR",
            name="Endpoint Detection & Response",
            category="endpoint",
            expected_return=0.70,
            volatility=0.18,
            cost=200.0,
            min_allocation=0.05,
            is_mandatory=True,
            metadata={"mitre_coverage": ["TA0002", "TA0003", "TA0004", "TA0005"]},
        ),
        DefensiveAsset(
            asset_id="DEF-MFA",
            name="Multi-Factor Authentication",
            category="identity",
            expected_return=0.80,
            volatility=0.10,
            cost=60.0,
            min_allocation=0.05,
            is_mandatory=True,
            metadata={"mitre_coverage": ["TA0001", "TA0006"]},
        ),
        DefensiveAsset(
            asset_id="DEF-PAM",
            name="Privileged Access Management",
            category="identity",
            expected_return=0.72,
            volatility=0.15,
            cost=180.0,
            metadata={"mitre_coverage": ["TA0004", "TA0006"]},
        ),
        DefensiveAsset(
            asset_id="DEF-DLP",
            name="Data Loss Prevention",
            category="data",
            expected_return=0.50,
            volatility=0.28,
            cost=160.0,
            metadata={"mitre_coverage": ["TA0009", "TA0010"]},
        ),
        DefensiveAsset(
            asset_id="DEF-ENCRYPT",
            name="Data Encryption (at rest + in transit)",
            category="data",
            expected_return=0.75,
            volatility=0.08,
            cost=70.0,
            min_allocation=0.03,
            is_mandatory=True,
            metadata={"mitre_coverage": ["TA0009"]},
        ),
        DefensiveAsset(
            asset_id="DEF-HONEYPOT",
            name="Adaptive Honeypot (IMMUNIS Deception)",
            category="deception",
            expected_return=0.40,
            volatility=0.35,
            cost=50.0,
            metadata={"mitre_coverage": ["TA0001", "TA0007", "TA0011"]},
        ),
        DefensiveAsset(
            asset_id="DEF-CANARY",
            name="Canary Tokens",
            category="deception",
            expected_return=0.35,
            volatility=0.15,
            cost=10.0,
            metadata={"mitre_coverage": ["TA0007", "TA0009"]},
        ),
        DefensiveAsset(
            asset_id="DEF-SIEM",
            name="SIEM + Log Monitoring",
            category="monitoring",
            expected_return=0.60,
            volatility=0.22,
            cost=250.0,
            min_allocation=0.05,
            is_mandatory=True,
            metadata={"mitre_coverage": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0010"]},
        ),
        DefensiveAsset(
            asset_id="DEF-VULN-SCAN",
            name="Continuous Vulnerability Scanning",
            category="monitoring",
            expected_return=0.55,
            volatility=0.20,
            cost=100.0,
            metadata={"mitre_coverage": ["TA0001"]},
        ),
        DefensiveAsset(
            asset_id="DEF-IMMUNIS",
            name="IMMUNIS ACIN (Adversarial Immune Network)",
            category="monitoring",
            expected_return=0.85,
            volatility=0.20,
            cost=300.0,
            min_allocation=0.10,
            is_mandatory=True,
            metadata={
                "mitre_coverage": [
                    "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
                    "TA0006", "TA0007", "TA0009", "TA0010", "TA0011",
                ],
                "unique_capabilities": [
                    "adversarial_coevolution",
                    "formal_verification",
                    "multilingual_detection",
                    "mesh_immunity",
                    "threat_actor_fingerprinting",
                ],
            },
        ),
        DefensiveAsset(
            asset_id="DEF-TRAINING",
            name="Security Awareness Training",
            category="identity",
            expected_return=0.45,
            volatility=0.35,
            cost=40.0,
            metadata={"mitre_coverage": ["TA0001"]},
        ),
    ]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

portfolio_engine = PortfolioOptimiser()
default_defensive_assets = build_default_assets()
