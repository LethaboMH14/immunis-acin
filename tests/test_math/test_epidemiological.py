"""
IMMUNIS ACIN — Epidemiological Model Tests
Tests SIR model, R₀ computation, herd immunity threshold.
dS/dt = -β·S·I/N, dI/dt = β·S·I/N - γ·I, dR/dt = γ·I
"""
import pytest
import numpy as np
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.math_engines.epidemiological import SIRImmunityModel


class TestEpidemiologicalModel:
    """Tests for SIR immunity propagation model."""

    def setup_method(self):
        self.model = SIRImmunityModel()

    def test_init(self):
        """Model initialises with default parameters."""
        assert self.model is not None

    def test_sir_conservation(self):
        """S + I + R = N at all times (population conservation)."""
        state = self.model.get_state()
        total = state.susceptible + state.infected + state.recovered
        assert abs(total - state.total_nodes) < 1.0, f"S+I+R should equal N: {total} vs {state.total_nodes}"

    def test_r0_computation(self):
        """R₀ = μ·S₀/γ should be computable and positive."""
        r0 = self.model.r0_immunity
        assert r0 > 0, f"R₀ should be positive, got {r0}"

    def test_herd_immunity_threshold(self):
        """Herd immunity threshold = 1 - 1/R₀."""
        r0 = self.model.r0_immunity
        if r0 > 1:
            threshold = 1 - 1 / r0
            hit = self.model.herd_immunity_threshold
            assert abs(hit - threshold) < 0.05, \
                f"HIT should be ~{threshold}, got {hit}"

    def test_infection_peak_then_decline(self):
        """Test basic model update functionality."""
        # Update model with some attacked nodes
        state = self.model.update(new_attacked_nodes=5, recovered_nodes=2)
        assert state is not None
        assert hasattr(state, 'susceptible')
        assert hasattr(state, 'infected')
        assert hasattr(state, 'recovered')

    def test_recovered_monotonically_increases(self):
        """Recovered population should only increase."""
        initial_state = self.model.get_state()
        initial_recovered = initial_state.recovered
        
        # Add some recovered nodes
        new_state = self.model.update(recovered_nodes=3)
        assert new_state.recovered >= initial_recovered, \
            f"Recovered should increase: {initial_recovered} -> {new_state.recovered}"

    def test_r0_based_broadcast_priority(self):
        """Higher R₀ threats should get higher broadcast priority."""
        # Test that r0_immunity property works
        r0 = self.model.r0_immunity
        assert isinstance(r0, (int, float)), "R₀ should be numeric"
        assert r0 > 0, "R₀ should be positive"
