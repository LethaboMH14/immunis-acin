"""
IMMUNIS ACIN — Epidemiological Immunity Propagation Model

Models how immunity spreads across the mesh network using
compartmental epidemiology (SIR model).

The key insight: IMMUNIS INVERTS THE SIR MODEL.
In disease epidemiology, infections spread and recovery is individual.
In IMMUNIS, IMMUNITY SPREADS — a node that synthesises an antibody
broadcasts it to the mesh, and susceptible nodes become immune
without ever being attacked.

Mathematical foundation:
    dS/dt = -β·S·I/N                    [susceptible nodes get attacked]
    dI/dt = β·S·I/N - γ·I               [attacked nodes synthesise antibody]
    dR/dt = γ·I + μ·S·R/N               [immune = recovered + mesh-immunised]

    The critical new term: μ·S·R/N
    This is the mesh broadcast term. In biology, recovered humans can't
    transmit immunity. In IMMUNIS, they can.

    R₀_immunity = μ·S₀/γ
    When R₀_immunity > 1: immunity spreads faster than attacks.
    This is HERD IMMUNITY for cybersecurity.

Research basis:
    - Kermack & McKendrick (1927), "A Contribution to the Mathematical Theory of Epidemics"
    - Keeling & Eames (2005), "Networks and epidemic models"
    - Cohen et al. (2000), "Resilience of the Internet to Random Breakdowns"

Temperature: N/A (pure math)
"""

from __future__ import annotations

import logging
import math
from typing import Any, Optional

from backend.models.schemas import EpidemiologicalState

logger = logging.getLogger("immunis.math.epidemiological")


class SIRImmunityModel:
    """
    SIR compartmental model adapted for cyber immunity propagation.
    
    S = Susceptible (nodes without antibody for a specific threat)
    I = Infected (nodes currently under attack)
    R = Recovered/Immune (nodes with antibody)
    
    The mesh broadcast adds a unique term: susceptible nodes can
    become immune directly from immune nodes (antibody sharing).
    """

    def __init__(
        self,
        total_nodes: int = 278,  # SA municipalities
        beta: float = 0.3,       # Attack transmission rate
        gamma: float = 0.1,      # Recovery rate (antibody synthesis speed)
        mu: float = 0.8,         # Mesh broadcast rate (immunity transmission)
    ):
        """
        Args:
            total_nodes: Total nodes in the mesh network
            beta: Rate at which attacks spread between nodes
            gamma: Rate at which attacked nodes synthesise antibodies
            mu: Rate at which immune nodes share immunity via mesh
        """
        self.N = total_nodes
        self.beta = beta
        self.gamma = gamma
        self.mu = mu

        # Initial state
        self.S = total_nodes - 1  # All susceptible except first immune node
        self.I = 0                 # No active attacks initially
        self.R = 1                 # One node has an antibody

        logger.info(
            "SIR Immunity Model initialised",
            extra={
                "total_nodes": total_nodes,
                "beta": beta,
                "gamma": gamma,
                "mu": mu,
            },
        )

    @property
    def r0_immunity(self) -> float:
        """
        Basic reproduction number of IMMUNITY.
        
        R₀ = μ · S₀ / γ
        
        When R₀ > 1: each immune node makes more than one other node immune.
        Immunity spreads exponentially. This is herd immunity for cyber.
        
        When R₀ < 1: immunity spreads slower than it decays.
        The mesh is not providing enough protection.
        """
        if self.gamma == 0:
            return float('inf')
        return self.mu * self.S / (self.gamma * self.N)

    @property
    def herd_immunity_threshold(self) -> float:
        """
        Fraction of nodes that must be immune for herd immunity.
        
        p_c = 1 - 1/R₀
        
        When this fraction is reached, attacks can no longer spread
        because there aren't enough susceptible nodes to sustain transmission.
        """
        r0 = self.r0_immunity
        if r0 <= 1:
            return 0.0  # Already at herd immunity (or immunity isn't spreading)
        return 1.0 - (1.0 / r0)

    @property
    def immune_fraction(self) -> float:
        """Current fraction of nodes that are immune."""
        return self.R / max(1, self.N)

    @property
    def has_herd_immunity(self) -> bool:
        """Whether the network has achieved herd immunity."""
        return self.immune_fraction >= self.herd_immunity_threshold

    def update(
        self,
        new_immune_nodes: int = 0,
        new_attacked_nodes: int = 0,
        recovered_nodes: int = 0,
    ) -> EpidemiologicalState:
        """
        Update the model with new events.
        
        Called by the orchestrator when:
        - A new antibody is broadcast (new_immune_nodes)
        - A node is attacked (new_attacked_nodes)
        - An attacked node synthesises its own antibody (recovered_nodes)
        """
        # Apply changes
        self.R += new_immune_nodes + recovered_nodes
        self.I += new_attacked_nodes - recovered_nodes
        self.S = max(0, self.N - self.R - self.I)

        # Clamp values
        self.S = max(0, self.S)
        self.I = max(0, self.I)
        self.R = max(0, min(self.N, self.R))

        return self.get_state()

    def simulate_broadcast(self, antibody_count: int = 1) -> EpidemiologicalState:
        """
        Simulate the effect of broadcasting antibodies to the mesh.
        
        Each broadcast makes susceptible nodes immune based on
        mesh broadcast rate (mu) and network connectivity.
        """
        # Number of newly immunised nodes from this broadcast
        # Proportional to: mu × (S/N) × number of immune nodes
        newly_immune = min(
            self.S,
            int(self.mu * (self.S / max(1, self.N)) * self.R * antibody_count)
        )
        # At minimum, broadcast reaches at least 1 node if there are susceptible nodes
        if self.S > 0 and newly_immune == 0:
            newly_immune = 1

        return self.update(new_immune_nodes=newly_immune)

    def time_to_herd_immunity(self) -> Optional[float]:
        """
        Estimate hours until herd immunity is reached.
        
        Based on current R₀ and broadcast rate.
        Returns None if herd immunity is not achievable with current parameters.
        """
        if self.has_herd_immunity:
            return 0.0

        r0 = self.r0_immunity
        if r0 <= 1:
            return None  # Immunity isn't spreading fast enough

        # Exponential growth model: R(t) = R₀ · e^(μt)
        # Solve for t when R(t) = herd_threshold × N
        target = self.herd_immunity_threshold * self.N
        if self.R >= target:
            return 0.0

        if self.R <= 0 or self.mu <= 0:
            return None

        # t = ln(target/R_current) / μ
        try:
            hours = math.log(target / self.R) / self.mu
            return round(hours, 2)
        except (ValueError, ZeroDivisionError):
            return None

    def get_state(self) -> EpidemiologicalState:
        """Get the current epidemiological state."""
        return EpidemiologicalState(
            susceptible=self.S,
            infected=self.I,
            recovered=self.R,
            total_nodes=self.N,
            r0_immunity=round(self.r0_immunity, 4),
            herd_immunity_threshold=round(self.herd_immunity_threshold, 4),
            time_to_herd_immunity_hours=self.time_to_herd_immunity(),
        )

    def get_dashboard_data(self) -> dict[str, Any]:
        """Get data formatted for dashboard."""
        state = self.get_state()
        return {
            "susceptible": state.susceptible,
            "infected": state.infected,
            "recovered": state.recovered,
            "total_nodes": state.total_nodes,
            "r0_immunity": state.r0_immunity,
            "herd_immunity_threshold": state.herd_immunity_threshold,
            "herd_immunity_reached": self.has_herd_immunity,
            "immune_fraction": round(self.immune_fraction, 4),
            "time_to_herd_immunity_hours": state.time_to_herd_immunity_hours,
            "mesh_effectiveness": round(
                min(1.0, self.r0_immunity / 3.0), 4  # Normalised to 0-1
            ),
        }


# ============================================================================
# MODULE-LEVEL SINGLETON
# ============================================================================

_model: Optional[SIRImmunityModel] = None


def get_sir_model() -> SIRImmunityModel:
    """Get or create the global SIR model."""
    global _model
    if _model is None:
        _model = SIRImmunityModel()
    return _model
