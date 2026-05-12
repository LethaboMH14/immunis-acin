"""
IMMUNIS ACIN — PID Immunity Controller
u(t) = K_p·e(t) + K_i·∫e(τ)dτ + K_d·de/dt
Stabilises immunity score to prevent oscillation.
"""
import time
import logging

logger = logging.getLogger(__name__)


class PIDController:
    """PID controller for immunity score stabilisation."""

    def __init__(self, kp: float = 1.0, ki: float = 0.1, kd: float = 0.05,
                 integral_limit: float = 10.0):
        self.kp = kp
        self.ki = ki
        self.kd = kd
        self.integral_limit = integral_limit
        self.reset()

    def reset(self):
        """Reset controller state."""
        self.integral = 0.0
        self.previous_error = 0.0
        self.last_time = time.time()

    def compute(self, current: float, target: float) -> float:
        """Compute PID output.
        
        Args:
            current: Current immunity score [0,1]
            target: Target immunity score [0,1]
            
        Returns:
            Control output (adjustment to apply)
        """
        now = time.time()
        dt = now - self.last_time
        if dt <= 0:
            dt = 0.01

        error = target - current

        # Proportional
        p_term = self.kp * error

        # Integral with anti-windup
        self.integral += error * dt
        self.integral = max(-self.integral_limit, min(self.integral_limit, self.integral))
        i_term = self.ki * self.integral

        # Derivative (on error, not setpoint)
        derivative = (error - self.previous_error) / dt
        d_term = self.kd * derivative

        # Update state
        self.previous_error = error
        self.last_time = now

        output = p_term + i_term + d_term
        logger.debug(f"PID: e={error:.4f} P={p_term:.4f} I={i_term:.4f} D={d_term:.4f} u={output:.4f}")
        return output

    def update(self, current: float, target: float) -> float:
        """Alias for compute()."""
        return self.compute(current, target)
