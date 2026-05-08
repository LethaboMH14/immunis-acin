"""
IMMUNIS ACIN — Agent 11: Game Theorist

WHY: Cyber defence is a strategic game. Attackers choose targets
to maximise damage. Defenders allocate limited resources to
minimise loss. The optimal strategy is NOT to defend everything
equally — it's to compute the Stackelberg equilibrium where the
defender commits first and the attacker best-responds.

Agent 11 wraps the Stackelberg math engine into an agent that:
1. Models the attacker-defender game for the current threat landscape
2. Computes optimal defence allocation across mesh nodes
3. Prioritises antibody distribution based on game-theoretic value
4. Estimates attacker economics (cost to attack vs expected gain)
5. Computes deterrence index (when attacking becomes unprofitable)

Mathematical foundation:
  Stackelberg Security Game (SSG):
    Leader (defender): commits to mixed strategy x ∈ Δ(T)
    Follower (attacker): best-responds with a ∈ BR(x)

    max_x min_a Σ_t x_t · U_d(t, a_t)
    s.t. Σ_t x_t = 1, x_t ≥ 0

  Strong Stackelberg Equilibrium (SSE):
    When attacker is indifferent between targets, they choose
    the one most favourable to the defender (tie-breaking rule).

  Defender utility: U_d(t, covered) = reward if defended
                    U_d(t, uncovered) = penalty if breached
  Attacker utility: U_a(t, covered) = penalty if caught
                    U_a(t, uncovered) = reward if successful

  Deterrence Index:
    DI = P(detection) × cost_of_detection / expected_gain
    When DI > 1: attacking is unprofitable → deterrence achieved

Pipeline position: Intelligence layer (parallel to Agents 9-10)
  Feeds into: Agent 7 (Mesh Broadcaster) for priority allocation
              Dashboard (deterrence index display)
              Response Layer (executive risk framing)
"""

import logging
import time
import math
from typing import Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger("immunis.agents.game_theorist")


@dataclass
class Target:
    """A potential attack target in the security game."""
    target_id: str
    name: str
    defender_reward_covered: float  # U_d when defended and attacked
    defender_penalty_uncovered: float  # U_d when undefended and attacked (negative)
    attacker_reward_uncovered: float  # U_a when undefended (attacker gains)
    attacker_penalty_covered: float  # U_a when defended (attacker loses, negative)
    current_coverage: float = 0.0  # Current defence allocation (0-1)
    asset_value: float = 0.0  # Monetary value of the asset
    attack_probability: float = 0.0  # Historical attack frequency
    vulnerability_score: float = 0.5  # 0=hardened, 1=vulnerable


@dataclass
class StackelbergEquilibrium:
    """Result of Stackelberg equilibrium computation."""
    defender_strategy: dict[str, float]  # target_id → coverage probability
    attacker_best_response: str  # target_id of attacker's best target
    defender_expected_utility: float
    attacker_expected_utility: float
    is_pure_strategy: bool  # True if defender uses pure strategy
    computation_time_ms: float = 0.0


@dataclass
class DeterrenceProfile:
    """Deterrence analysis for the current threat landscape."""
    deterrence_index: float  # >1 = deterrence achieved
    deterrence_level: str  # LOW, MEDIUM, HIGH, MAXIMUM
    attacker_expected_profit: float  # Expected profit per attack
    attacker_cost_per_attack: float  # Estimated cost to mount attack
    defender_detection_probability: float  # P(detection)
    defender_response_cost: float  # Cost of responding to attack
    break_even_detection_rate: float  # Detection rate where attack becomes unprofitable
    economic_summary: str  # Human-readable summary
    recommendations: list[str] = field(default_factory=list)


@dataclass
class DefenceAllocation:
    """Recommended defence resource allocation."""
    allocations: dict[str, float]  # target_id → allocation weight
    total_budget: float
    expected_loss_before: float
    expected_loss_after: float
    loss_reduction: float
    loss_reduction_pct: float
    roi: float  # Return on investment
    equilibrium: Optional[StackelbergEquilibrium] = None
    deterrence: Optional[DeterrenceProfile] = None
    computed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class GameTheorist:
    """
    Agent 11: Game-theoretic defence allocation engine.

    Computes optimal defence strategies using Stackelberg Security
    Games, estimates attacker economics, and produces deterrence
    indices that quantify whether attacking is profitable.

    Usage:
        theorist = GameTheorist()

        # Define targets
        targets = [
            Target("email", "Email Gateway", 10, -50, 40, -20, asset_value=500000),
            Target("web", "Web Application", 5, -30, 25, -15, asset_value=200000),
            Target("vpn", "VPN Endpoint", 8, -80, 60, -25, asset_value=1000000),
        ]

        # Compute equilibrium
        eq = theorist.compute_equilibrium(targets)

        # Get defence allocation
        allocation = theorist.compute_allocation(targets, budget=100000)

        # Get deterrence profile
        deterrence = theorist.compute_deterrence(targets, eq)
    """

    def __init__(self):
        self._computations: int = 0
        self._total_computation_time_ms: float = 0.0
        self._last_equilibrium: Optional[StackelbergEquilibrium] = None
        self._last_allocation: Optional[DefenceAllocation] = None
        self._targets: list[Target] = []

        logger.info("Game Theorist (Agent 11) initialised")

    def compute_equilibrium(
        self,
        targets: list[Target],
        num_resources: int = 1,
    ) -> StackelbergEquilibrium:
        """
        Compute the Strong Stackelberg Equilibrium (SSE).

        For a single defender resource, the SSE can be computed
        in O(n log n) time using the ORIGAMI algorithm.

        For multiple resources, we use the ERASER algorithm
        (Efficient Randomized Allocation of Security Resources).

        Args:
            targets: List of potential attack targets.
            num_resources: Number of defence resources to allocate.

        Returns:
            StackelbergEquilibrium with optimal mixed strategy.
        """
        start = time.perf_counter()

        if not targets:
            return StackelbergEquilibrium(
                defender_strategy={},
                attacker_best_response="",
                defender_expected_utility=0.0,
                attacker_expected_utility=0.0,
                is_pure_strategy=True,
            )

        n = len(targets)

        if num_resources >= n:
            # Can cover everything — pure strategy
            strategy = {t.target_id: 1.0 for t in targets}
            # Attacker picks least defended (all equal, pick first)
            best_response = targets[0].target_id

            defender_util = sum(
                t.defender_reward_covered for t in targets
            ) / n

            attacker_util = min(
                t.attacker_penalty_covered for t in targets
            )

            elapsed = (time.perf_counter() - start) * 1000

            eq = StackelbergEquilibrium(
                defender_strategy=strategy,
                attacker_best_response=best_response,
                defender_expected_utility=defender_util,
                attacker_expected_utility=attacker_util,
                is_pure_strategy=True,
                computation_time_ms=round(elapsed, 2),
            )

            self._last_equilibrium = eq
            self._computations += 1
            self._total_computation_time_ms += elapsed

            return eq

        # ORIGAMI algorithm for single resource
        if num_resources == 1:
            eq = self._origami(targets)
        else:
            eq = self._eraser(targets, num_resources)

        elapsed = (time.perf_counter() - start) * 1000
        eq.computation_time_ms = round(elapsed, 2)

        self._last_equilibrium = eq
        self._computations += 1
        self._total_computation_time_ms += elapsed

        logger.info(
            f"Stackelberg equilibrium computed: "
            f"attacker targets {eq.attacker_best_response}, "
            f"defender utility={eq.defender_expected_utility:.2f}, "
            f"attacker utility={eq.attacker_expected_utility:.2f}, "
            f"latency={elapsed:.1f}ms"
        )

        return eq

    def _origami(self, targets: list[Target]) -> StackelbergEquilibrium:
        """
        ORIGAMI algorithm for single-resource SSG.

        Optimal Resource Allocation for Game-theoretic
        Analysis of Multi-target Interactions.

        Key insight: In SSE, the attacker is indifferent between
        all targets in the support of the defender's strategy.
        We find the strategy that maximises defender utility
        subject to this indifference constraint.
        """
        n = len(targets)

        # Sort targets by attacker's uncovered reward (descending)
        # Attacker prefers targets with highest reward when uncovered
        sorted_targets = sorted(
            targets,
            key=lambda t: t.attacker_reward_uncovered,
            reverse=True,
        )

        best_defender_utility = float("-inf")
        best_strategy = {}
        best_attacker_target = ""
        best_attacker_utility = float("inf")

        # Try each target as the attacker's best response
        for k in range(n):
            attacker_target = sorted_targets[k]

            # Compute coverage needed to make attacker indifferent
            # between target k and all higher-value targets
            strategy = {}
            feasible = True
            total_coverage = 0.0

            for i in range(k):
                t = sorted_targets[i]
                # Coverage needed to make attacker indifferent between t and k
                # U_a(t, x_t) = U_a(k, x_k)
                # x_t * U_a_covered(t) + (1-x_t) * U_a_uncovered(t) =
                # x_k * U_a_covered(k) + (1-x_k) * U_a_uncovered(k)

                numerator = (
                    attacker_target.attacker_reward_uncovered
                    - t.attacker_reward_uncovered
                )
                denominator = (
                    t.attacker_penalty_covered
                    - t.attacker_reward_uncovered
                )

                if abs(denominator) < 1e-10:
                    coverage = 0.0
                else:
                    coverage = numerator / denominator

                coverage = max(0.0, min(1.0, coverage))
                strategy[t.target_id] = coverage
                total_coverage += coverage

            # Remaining coverage goes to target k
            remaining = 1.0 - total_coverage
            if remaining < -0.01:
                feasible = False
            else:
                remaining = max(0.0, remaining)
                strategy[attacker_target.target_id] = remaining

            # Add zero coverage for remaining targets
            for i in range(k + 1, n):
                strategy[sorted_targets[i].target_id] = 0.0

            if not feasible:
                continue

            # Compute defender utility
            defender_util = 0.0
            for t in targets:
                x = strategy.get(t.target_id, 0.0)
                util = (
                    x * t.defender_reward_covered
                    + (1 - x) * t.defender_penalty_uncovered
                )
                defender_util += util / n  # Average over targets

            # Compute attacker utility at target k
            x_k = strategy.get(attacker_target.target_id, 0.0)
            attacker_util = (
                x_k * attacker_target.attacker_penalty_covered
                + (1 - x_k) * attacker_target.attacker_reward_uncovered
            )

            if defender_util > best_defender_utility:
                best_defender_utility = defender_util
                best_strategy = strategy.copy()
                best_attacker_target = attacker_target.target_id
                best_attacker_utility = attacker_util

        is_pure = all(
            v == 0.0 or v == 1.0
            for v in best_strategy.values()
        )

        return StackelbergEquilibrium(
            defender_strategy=best_strategy,
            attacker_best_response=best_attacker_target,
            defender_expected_utility=best_defender_utility,
            attacker_expected_utility=best_attacker_utility,
            is_pure_strategy=is_pure,
        )

    def _eraser(
        self,
        targets: list[Target],
        num_resources: int,
    ) -> StackelbergEquilibrium:
        """
        ERASER algorithm for multi-resource SSG.

        Simplified version: distribute resources proportionally
        to target value, then refine using iterative best response.
        """
        n = len(targets)

        # Initial allocation: proportional to asset value
        total_value = sum(t.asset_value for t in targets) or 1.0
        strategy = {}

        for t in targets:
            coverage = min(
                1.0,
                (t.asset_value / total_value) * num_resources,
            )
            strategy[t.target_id] = coverage

        # Normalise so total coverage = num_resources
        total_coverage = sum(strategy.values())
        if total_coverage > 0:
            scale = num_resources / total_coverage
            for tid in strategy:
                strategy[tid] = min(1.0, strategy[tid] * scale)

        # Find attacker's best response
        best_target = None
        best_attacker_util = float("-inf")

        for t in targets:
            x = strategy.get(t.target_id, 0.0)
            attacker_util = (
                x * t.attacker_penalty_covered
                + (1 - x) * t.attacker_reward_uncovered
            )
            if attacker_util > best_attacker_util:
                best_attacker_util = attacker_util
                best_target = t

        # Compute defender utility
        defender_util = 0.0
        for t in targets:
            x = strategy.get(t.target_id, 0.0)
            util = (
                x * t.defender_reward_covered
                + (1 - x) * t.defender_penalty_uncovered
            )
            defender_util += util / n

        return StackelbergEquilibrium(
            defender_strategy=strategy,
            attacker_best_response=best_target.target_id if best_target else "",
            defender_expected_utility=defender_util,
            attacker_expected_utility=best_attacker_util,
            is_pure_strategy=False,
        )

    def compute_deterrence(
        self,
        targets: list[Target],
        equilibrium: Optional[StackelbergEquilibrium] = None,
    ) -> DeterrenceProfile:
        """
        Compute the deterrence profile for the current landscape.

        Deterrence is achieved when the expected cost of attacking
        exceeds the expected gain. The deterrence index quantifies
        this ratio.

        DI = (P(detection) × cost_if_caught + opportunity_cost) / expected_gain
        When DI > 1: attacking is unprofitable
        """
        if equilibrium is None:
            equilibrium = self.compute_equilibrium(targets)

        if not targets:
            return DeterrenceProfile(
                deterrence_index=1.0,
                deterrence_level="UNKNOWN",
                attacker_expected_profit=0.0,
                attacker_cost_per_attack=0.0,
                defender_detection_probability=0.0,
                defender_response_cost=0.0,
                break_even_detection_rate=0.0,
                economic_summary="No targets defined",
            )

        # Compute average detection probability from coverage
        avg_coverage = np.mean([
            equilibrium.defender_strategy.get(t.target_id, 0.0)
            for t in targets
        ])

        # Estimate attacker economics
        avg_reward = np.mean([t.attacker_reward_uncovered for t in targets])
        avg_penalty = np.mean([abs(t.attacker_penalty_covered) for t in targets])

        # Attacker expected profit
        expected_gain = (1 - avg_coverage) * avg_reward
        expected_cost = avg_coverage * avg_penalty

        # Estimated cost to mount attack (infrastructure, time, risk)
        # Heuristic: 20% of average asset value
        avg_asset = np.mean([t.asset_value for t in targets]) if targets else 0
        attack_cost = avg_asset * 0.2

        attacker_profit = expected_gain - expected_cost - attack_cost

        # Deterrence index
        if expected_gain > 0:
            deterrence_index = (expected_cost + attack_cost) / expected_gain
        else:
            deterrence_index = float("inf")

        # Break-even detection rate
        if avg_reward > 0 and avg_penalty > 0:
            break_even = (avg_reward - attack_cost) / (avg_reward + avg_penalty)
            break_even = max(0.0, min(1.0, break_even))
        else:
            break_even = 0.5

        # Deterrence level
        if deterrence_index >= 3.0:
            level = "MAXIMUM"
        elif deterrence_index >= 2.0:
            level = "HIGH"
        elif deterrence_index >= 1.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        # Defender response cost
        avg_defender_penalty = np.mean([
            abs(t.defender_penalty_uncovered) for t in targets
        ])

        # Recommendations
        recommendations = []
        if level == "LOW":
            recommendations.append(
                "Increase detection coverage — current coverage "
                f"({avg_coverage:.0%}) is below break-even ({break_even:.0%})"
            )
            recommendations.append(
                "Deploy additional antibodies to high-value targets"
            )
            recommendations.append(
                "Consider active deception (honeypots) to increase attacker cost"
            )
        elif level == "MEDIUM":
            recommendations.append(
                "Maintain current coverage and focus on reducing response time"
            )
            recommendations.append(
                "Prioritise antibody distribution to weakest nodes"
            )
        elif level in ("HIGH", "MAXIMUM"):
            recommendations.append(
                "Deterrence achieved — maintain current posture"
            )
            recommendations.append(
                "Monitor for attacker strategy shifts to novel vectors"
            )

        # Economic summary
        summary = (
            f"Attacker expected profit per attack: R{attacker_profit:,.0f}. "
            f"Detection probability: {avg_coverage:.0%}. "
            f"Deterrence index: {deterrence_index:.2f} ({level}). "
        )
        if deterrence_index >= 1.0:
            summary += "Attacking is currently UNPROFITABLE."
        else:
            summary += (
                f"Attacking is still profitable. Need to increase "
                f"detection rate from {avg_coverage:.0%} to {break_even:.0%} "
                f"to achieve deterrence."
            )

        profile = DeterrenceProfile(
            deterrence_index=round(deterrence_index, 3),
            deterrence_level=level,
            attacker_expected_profit=round(attacker_profit, 2),
            attacker_cost_per_attack=round(attack_cost, 2),
            defender_detection_probability=round(avg_coverage, 3),
            defender_response_cost=round(avg_defender_penalty, 2),
            break_even_detection_rate=round(break_even, 3),
            economic_summary=summary,
            recommendations=recommendations,
        )

        logger.info(
            f"Deterrence profile: DI={deterrence_index:.2f} ({level}), "
            f"attacker profit=R{attacker_profit:,.0f}, "
            f"detection={avg_coverage:.0%}"
        )

        return profile

    def compute_allocation(
        self,
        targets: list[Target],
        budget: float = 100000.0,
        num_resources: int = 1,
    ) -> DefenceAllocation:
        """
        Compute optimal defence resource allocation.

        Combines Stackelberg equilibrium with budget constraints
        to produce actionable allocation recommendations.

        Args:
            targets: List of targets to defend.
            budget: Total defence budget (monetary).
            num_resources: Number of discrete defence resources.

        Returns:
            DefenceAllocation with recommendations and ROI.
        """
        start = time.perf_counter()

        # Compute equilibrium
        equilibrium = self.compute_equilibrium(targets, num_resources)

        # Compute deterrence
        deterrence = self.compute_deterrence(targets, equilibrium)

        # Translate strategy to budget allocation
        allocations = {}
        for t in targets:
            coverage = equilibrium.defender_strategy.get(t.target_id, 0.0)
            allocations[t.target_id] = round(coverage * budget, 2)

        # Compute expected loss before and after
        expected_loss_before = sum(
            t.attack_probability * abs(t.defender_penalty_uncovered)
            for t in targets
        )

        expected_loss_after = sum(
            t.attack_probability * (
                equilibrium.defender_strategy.get(t.target_id, 0.0)
                * abs(t.defender_reward_covered)
                + (1 - equilibrium.defender_strategy.get(t.target_id, 0.0))
                * abs(t.defender_penalty_uncovered)
            )
            for t in targets
        )

        loss_reduction = max(0, expected_loss_before - expected_loss_after)
        loss_reduction_pct = (
            (loss_reduction / expected_loss_before * 100)
            if expected_loss_before > 0
            else 0.0
        )

        roi = (loss_reduction / budget) if budget > 0 else 0.0

        elapsed = (time.perf_counter() - start) * 1000

        allocation = DefenceAllocation(
            allocations=allocations,
            total_budget=budget,
            expected_loss_before=round(expected_loss_before, 2),
            expected_loss_after=round(expected_loss_after, 2),
            loss_reduction=round(loss_reduction, 2),
            loss_reduction_pct=round(loss_reduction_pct, 1),
            roi=round(roi, 3),
            equilibrium=equilibrium,
            deterrence=deterrence,
        )

        self._last_allocation = allocation

        logger.info(
            f"Defence allocation computed: budget=R{budget:,.0f}, "
            f"loss reduction={loss_reduction_pct:.1f}%, "
            f"ROI={roi:.2f}x, latency={elapsed:.1f}ms"
        )

        return allocation

    def build_targets_from_landscape(self) -> list[Target]:
        """
        Build target list from current threat landscape.

        Pulls data from the database and epidemiological model
        to construct game-theoretic targets.
        """
        targets = []

        try:
            from backend.storage.database import get_database
            db = get_database()
            stats = db.get_dashboard_stats()

            # Build targets from attack family distribution
            families = stats.get("attack_families", {})
            total_incidents = stats.get("incidents", {}).get("total", 1) or 1

            for family, count in families.items():
                attack_prob = count / total_incidents

                # Estimate values based on family
                value_estimates = {
                    "BEC": 500000,
                    "Phishing": 200000,
                    "Ransomware": 1000000,
                    "Malware": 300000,
                    "VendorImpersonation": 400000,
                    "InvoiceFraud": 600000,
                }

                asset_value = value_estimates.get(
                    family.split("_")[0], 250000
                )

                targets.append(Target(
                    target_id=family,
                    name=family,
                    defender_reward_covered=asset_value * 0.02,
                    defender_penalty_uncovered=-asset_value * 0.1,
                    attacker_reward_uncovered=asset_value * 0.08,
                    attacker_penalty_covered=-asset_value * 0.04,
                    asset_value=asset_value,
                    attack_probability=attack_prob,
                    vulnerability_score=0.5,
                ))

        except Exception as e:
            logger.debug(f"Failed to build targets from landscape: {e}")

        # Default targets if none from database
        if not targets:
            targets = [
                Target("email", "Email Gateway", 10, -50, 40, -20,
                       asset_value=500000, attack_probability=0.4),
                Target("web", "Web Application", 5, -30, 25, -15,
                       asset_value=200000, attack_probability=0.3),
                Target("vpn", "VPN/Remote Access", 8, -80, 60, -25,
                       asset_value=1000000, attack_probability=0.15),
                Target("endpoint", "Endpoints", 3, -20, 15, -10,
                       asset_value=100000, attack_probability=0.1),
                Target("cloud", "Cloud Services", 7, -60, 45, -20,
                       asset_value=800000, attack_probability=0.05),
            ]

        self._targets = targets
        return targets

    def get_current_allocation(self) -> Optional[dict]:
        """Get the most recent allocation for the dashboard."""
        if self._last_allocation is None:
            return None

        return {
            "allocations": self._last_allocation.allocations,
            "total_budget": self._last_allocation.total_budget,
            "loss_reduction_pct": self._last_allocation.loss_reduction_pct,
            "roi": self._last_allocation.roi,
            "deterrence_index": (
                self._last_allocation.deterrence.deterrence_index
                if self._last_allocation.deterrence
                else 0.0
            ),
            "deterrence_level": (
                self._last_allocation.deterrence.deterrence_level
                if self._last_allocation.deterrence
                else "UNKNOWN"
            ),
            "computed_at": self._last_allocation.computed_at,
        }

    def get_stats(self) -> dict:
        """Return game theorist statistics."""
        avg_time = (
            self._total_computation_time_ms / self._computations
            if self._computations > 0
            else 0.0
        )

        return {
            "total_computations": self._computations,
            "avg_computation_time_ms": round(avg_time, 2),
            "targets_modelled": len(self._targets),
            "last_deterrence_index": (
                self._last_allocation.deterrence.deterrence_index
                if self._last_allocation and self._last_allocation.deterrence
                else None
            ),
            "last_deterrence_level": (
                self._last_allocation.deterrence.deterrence_level
                if self._last_allocation and self._last_allocation.deterrence
                else None
            ),
        }


# Module-level singleton
_theorist: Optional[GameTheorist] = None


def get_game_theorist() -> GameTheorist:
    """Get or create the singleton GameTheorist instance."""
    global _theorist
    if _theorist is None:
        _theorist = GameTheorist()
    return _theorist
