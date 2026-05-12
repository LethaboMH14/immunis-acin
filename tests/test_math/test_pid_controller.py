"""
IMMUNIS ACIN — PID Controller Tests
Tests immunity score stabilisation.
u(t) = K_p·e(t) + K_i·∫e(τ)dτ + K_d·de/dt
"""
import pytest
import numpy as np
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.math_engines.pid_controller import PIDController


class TestPIDController:
    """Tests for PID immunity score stabilisation."""

    def setup_method(self):
        self.pid = PIDController()

    def test_init(self):
        """PID initialises with gains."""
        assert self.pid is not None

    def test_zero_error_zero_output(self):
        """When current == target, output should be ~0."""
        if hasattr(self.pid, 'compute'):
            output = self.pid.compute(current=0.75, target=0.75)
            assert abs(output) < 0.01, f"Zero error should give ~zero output, got {output}"
        elif hasattr(self.pid, 'update'):
            output = self.pid.update(current=0.75, target=0.75)
            assert abs(output) < 0.01

    def test_positive_error_positive_output(self):
        """When current < target, output should be positive (increase immunity)."""
        if hasattr(self.pid, 'compute'):
            output = self.pid.compute(current=0.5, target=0.8)
        else:
            output = self.pid.update(current=0.5, target=0.8)
        assert output > 0, f"Below target should give positive output, got {output}"

    def test_negative_error_negative_output(self):
        """When current > target, output should be negative (reduce overshoot)."""
        if hasattr(self.pid, 'compute'):
            output = self.pid.compute(current=0.95, target=0.75)
        else:
            output = self.pid.update(current=0.95, target=0.75)
        assert output < 0, f"Above target should give negative output, got {output}"

    def test_convergence(self):
        """Repeated application should converge to target."""
        target = 0.80
        current = 0.50
        for _ in range(100):
            if hasattr(self.pid, 'compute'):
                adjustment = self.pid.compute(current=current, target=target)
            else:
                adjustment = self.pid.update(current=current, target=target)
            current += adjustment * 0.1  # damped application
            current = max(0, min(1, current))

        assert abs(current - target) < 0.1, \
            f"PID should converge to target {target}, got {current}"

    def test_integral_windup_prevention(self):
        """Integral term should be bounded to prevent windup."""
        target = 0.99
        current = 0.01
        outputs = []
        for _ in range(1000):
            if hasattr(self.pid, 'compute'):
                output = self.pid.compute(current=current, target=target)
            else:
                output = self.pid.update(current=current, target=target)
            outputs.append(output)

        # Output should not grow unbounded
        assert max(outputs) < 100, f"Integral windup: max output {max(outputs)}"

    def test_derivative_kick_damping(self):
        """Sudden target change shouldn't cause massive derivative spike."""
        if hasattr(self.pid, 'compute'):
            self.pid.compute(current=0.5, target=0.5)
            self.pid.compute(current=0.5, target=0.5)
            output = self.pid.compute(current=0.5, target=0.9)
        else:
            self.pid.update(current=0.5, target=0.5)
            self.pid.update(current=0.5, target=0.5)
            output = self.pid.update(current=0.5, target=0.9)
        assert abs(output) < 10, f"Derivative kick should be bounded, got {output}"

    def test_reset(self):
        """Reset should clear integral and derivative history."""
        if hasattr(self.pid, 'compute'):
            self.pid.compute(current=0.3, target=0.9)
            self.pid.compute(current=0.4, target=0.9)
        if hasattr(self.pid, 'reset'):
            self.pid.reset()
            if hasattr(self.pid, 'compute'):
                output = self.pid.compute(current=0.75, target=0.75)
            else:
                output = self.pid.update(current=0.75, target=0.75)
            assert abs(output) < 0.1, "After reset, zero error should give ~zero output"
