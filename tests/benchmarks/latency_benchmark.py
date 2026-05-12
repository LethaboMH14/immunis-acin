"""
IMMUNIS ACIN — Latency Benchmarks
Measures pipeline stage timing against SLA requirements.
"""
import pytest
import time
import asyncio
import numpy as np
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


class TestLatencyBenchmarks:
    """Benchmark tests for pipeline timing SLAs."""

    def test_surprise_detection_under_200ms(self):
        """Stage 1: Surprise detection must complete in <200ms."""
        from backend.math_engines.surprise import SurpriseDetector

        detector = SurpriseDetector()
        # Pre-populate with samples
        rng = np.random.RandomState(42)
        for _ in range(100):
            detector.add_sample(rng.randn(768).astype(np.float32))

        test_vector = rng.randn(768).astype(np.float32)

        start = time.perf_counter()
        for _ in range(10):
            detector.compute_surprise(test_vector)
        elapsed = (time.perf_counter() - start) / 10

        assert elapsed < 0.200, f"Surprise detection took {elapsed*1000:.1f}ms (SLA: <200ms)"

    def test_kde_scales_with_library_size(self):
        """KDE computation time should scale sub-linearly with library size."""
        from backend.math_engines.surprise import SurpriseDetector

        rng = np.random.RandomState(42)
        test_vector = rng.randn(768).astype(np.float32)

        times = []
        for n_samples in [10, 50, 100, 500]:
            detector = SurpriseDetector()
            for _ in range(n_samples):
                detector.add_sample(rng.randn(768).astype(np.float32))

            start = time.perf_counter()
            for _ in range(5):
                detector.compute_surprise(test_vector)
            elapsed = (time.perf_counter() - start) / 5
            times.append(elapsed)

        # 50x more samples shouldn't take 50x longer (sub-linear)
        ratio = times[-1] / times[0] if times[0] > 0 else 1
        assert ratio < 50, f"KDE should scale sub-linearly: {times}"

    def test_pid_controller_under_1ms(self):
        """PID computation must be <1ms (called every update cycle)."""
        from backend.math_engines.pid_controller import PIDController

        pid = PIDController()

        start = time.perf_counter()
        for i in range(1000):
            if hasattr(pid, 'compute'):
                pid.compute(current=0.5 + i * 0.0001, target=0.8)
            else:
                pid.update(current=0.5 + i * 0.0001, target=0.8)
        elapsed = (time.perf_counter() - start) / 1000

        assert elapsed < 0.001, f"PID took {elapsed*1000:.3f}ms (SLA: <1ms)"

    def test_actuarial_var_under_50ms(self):
        """Actuarial VaR computation should be <50ms."""
        from backend.math_engines.actuarial import ActuarialEngine

        engine = ActuarialEngine()
        rng = np.random.RandomState(42)
        losses = rng.pareto(1.5, size=500) * 50000 + 10000
        engine.fit(losses)

        start = time.perf_counter()
        for _ in range(10):
            engine.var(0.95)
        elapsed = (time.perf_counter() - start) / 10

        assert elapsed < 0.050, f"VaR took {elapsed*1000:.1f}ms (SLA: <50ms)"

    def test_game_theory_under_100ms(self):
        """Stackelberg equilibrium computation should be <100ms for 10 targets."""
        from backend.math_engines.game_theory import GameTheoryEngine

        engine = GameTheoryEngine()
        targets = [
            {"id": f"t{i}", "value": np.random.randint(10, 500), "attack_cost": np.random.randint(5, 50)}
            for i in range(10)
        ]

        start = time.perf_counter()
        for _ in range(5):
            engine.origami(targets, n_resources=3)
        elapsed = (time.perf_counter() - start) / 5

        assert elapsed < 0.100, f"ORIGAMI took {elapsed*1000:.1f}ms (SLA: <100ms)"

    def test_epidemiological_sir_under_10ms(self):
        """SIR model simulation should be <10ms for 200 steps."""
        from backend.math_engines.epidemiological import EpidemiologicalModel

        model = EpidemiologicalModel()

        start = time.perf_counter()
        for _ in range(10):
            model.simulate(S0=990, I0=10, R0=0, N=1000, steps=200)
        elapsed = (time.perf_counter() - start) / 10

        assert elapsed < 0.010, f"SIR took {elapsed*1000:.1f}ms (SLA: <10ms)"

    def test_input_sanitisation_under_5ms(self):
        """Input sanitisation must be <5ms for typical threat text."""
        from backend.security.input_sanitiser import InputSanitiser

        sanitiser = InputSanitiser()
        text = "Dumela Mofumahadi Molefe, re hloka hore o fetise R2,450,000 ho account e ncha. Sena se potlakileng."

        start = time.perf_counter()
        for _ in range(100):
            sanitiser.sanitise(text)
        elapsed = (time.perf_counter() - start) / 100

        assert elapsed < 0.005, f"Sanitisation took {elapsed*1000:.1f}ms (SLA: <5ms)"
