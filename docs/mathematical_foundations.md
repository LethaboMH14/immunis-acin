# IMMUNIS ACIN - Mathematical Foundations

## Overview

IMMUNIS ACIN employs seven sophisticated mathematical engines to power its adaptive cybersecurity defense system. Each engine provides unique analytical capabilities that, when combined, create a robust, intelligent threat detection and response framework.

## 1. KDE Surprise Detection Engine

### Mathematical Foundation

The Kernel Density Estimation (KDE) Surprise Detection engine identifies novel threats by measuring how "surprising" a new threat vector is compared to the existing threat library.

#### Core Formula

The surprise score S(x) for a new threat vector x is computed as:

```
S(x) = -log(f_KDE(x))

where f_KDE(x) = (1/nh) * Σ(i=1 to n) K((x - xi)/h)
```

- **n**: Number of threat vectors in library
- **h**: Bandwidth parameter (computed via Scott's rule)
- **K**: Gaussian kernel function: K(u) = (1/√(2π)) * exp(-u²/2)
- **xi**: i-th threat vector in library

#### Scott's Rule for Bandwidth

The optimal bandwidth h is computed using Scott's rule:

```
h = n^(-1/(d+4))

where:
- n: sample size
- d: dimensionality (768 for LaBSE embeddings)
```

#### Threshold Classification

Surprise scores are classified into three categories:

```
Known threat:     S(x) < 3.0
Variant threat:    3.0 ≤ S(x) < 8.0  
Novel threat:      S(x) ≥ 8.0
```

### Intuition

- **Low surprise** indicates the threat is similar to known patterns
- **Medium surprise** suggests a variation of known threats
- **High surprise** signals a completely novel attack pattern

### Implementation Reference

```python
def compute_kde_surprise(new_vector, library_vectors):
    n = len(library_vectors)
    if n == 0:
        return float('inf')
    
    # Scott's rule for bandwidth
    h = n ** (-1.0 / (library_vectors.shape[1] + 4))
    
    # KDE computation
    distances = np.linalg.norm(library_vectors - new_vector, axis=1)
    kde_values = np.exp(-0.5 * (distances / h) ** 2) / (h * np.sqrt(2 * np.pi))
    f_kde = np.mean(kde_values)
    
    return -np.log(f_kde + 1e-10)  # Avoid log(0)
```

### Academic Citation

Based on: Silverman, B. W. (1986). "Density Estimation for Statistics and Data Analysis." Chapman & Hall.

---

## 2. GPD Actuarial Risk Engine

### Mathematical Foundation

The Generalized Pareto Distribution (GPD) engine models extreme financial losses using Extreme Value Theory (EVT), providing robust risk metrics for tail events.

#### Core Formula

The GPD cumulative distribution function:

```
G(x; ξ, σ) = 1 - (1 + ξ * (x - μ)/σ)^(-1/ξ) for ξ ≠ 0
G(x; 0, σ) = 1 - exp(-(x - μ)/σ) for ξ = 0

where:
- ξ: Shape parameter (tail index)
- σ: Scale parameter (> 0)
- μ: Location parameter (threshold)
- x: Loss amount (x ≥ μ)
```

#### Value at Risk (VaR)

VaR at confidence level α:

```
VaR_α = μ + (σ/ξ) * ((1/(1-α))^(-ξ) - 1) for ξ ≠ 0
VaR_α = μ - σ * log(1-α) for ξ = 0
```

#### Conditional Value at Risk (CVaR)

CVaR (Expected Shortfall) at confidence level α:

```
CVaR_α = VaR_α/(1-ξ) + (σ - ξ*μ)/(1-ξ) for ξ ≠ 0
CVaR_α = VaR_α + σ for ξ = 0
```

### Intuition

- **Shape parameter ξ** indicates tail heaviness (ξ > 0: heavy tail, ξ < 0: bounded tail)
- **VaR** provides the maximum expected loss at given confidence
- **CVaR** gives expected loss beyond VaR (more conservative)

### Implementation Reference

```python
def fit_gpd(excesses):
    """Fit GPD parameters using Method of Moments."""
    mean_excess = np.mean(excesses)
    var_excess = np.var(excesses)
    
    # Method of moments estimators
    xi_hat = 0.5 * ((mean_excess**2 / var_excess) - 1)
    sigma_hat = mean_excess * (1 - xi_hat)
    
    return xi_hat, sigma_hat

def compute_var_cvar(losses, confidence=0.95):
    """Compute VaR and CVaR for given confidence level."""
    threshold = np.percentile(losses, 90)  # 90th percentile
    excesses = losses[losses > threshold] - threshold
    
    xi, sigma = fit_gpd(excesses)
    
    var = threshold + (sigma/xi) * ((1/(1-confidence))**(-xi) - 1)
    cvar = var/(1-xi) + (sigma - xi*threshold)/(1-xi)
    
    return var, cvar
```

### Academic Citation

Based on: Embrechts, P., Klüppelberg, C., & Mikosch, T. (1997). "Modelling Extremal Events." Springer.

---

## 3. SIR Epidemiological Model

### Mathematical Foundation

The SIR (Susceptible-Infected-Recovered) model simulates threat propagation through networks, modeling how malware or attack patterns spread across systems.

#### Core Differential Equations

```
dS/dt = -β * S * I / N
dI/dt = β * S * I / N - γ * I
dR/dt = γ * I

where:
- S(t): Susceptible systems at time t
- I(t): Infected systems at time t  
- R(t): Recovered/patched systems at time t
- N: Total systems (S + I + R)
- β: Transmission rate
- γ: Recovery rate
```

#### Basic Reproduction Number (R₀)

```
R₀ = β/γ

Interpretation:
- R₀ < 1: Outbreak dies out
- R₀ = 1: Outbreak stable
- R₀ > 1: Outbreak grows
```

#### Solution for Early Stage

For early outbreak (I << N):

```
I(t) ≈ I₀ * exp((β - γ) * t)
```

### Intuition

- **Transmission rate β** represents how easily threats spread
- **Recovery rate γ** represents patching/remediation speed
- **R₀** indicates outbreak potential and required response intensity

### Implementation Reference

```python
def sir_model(t, y, beta, gamma):
    """SIR differential equations."""
    S, I, R = y
    N = S + I + R
    
    dSdt = -beta * S * I / N
    dIdt = beta * S * I / N - gamma * I
    dRdt = gamma * I
    
    return [dSdt, dIdt, dRdt]

def simulate_outbreak(beta, gamma, I0, days):
    """Simulate threat outbreak."""
    from scipy.integrate import odeint
    
    # Initial conditions
    S0 = 10000 - I0  # Total population minus initial infected
    y0 = [S0, I0, 0]
    
    # Time points
    t = np.linspace(0, days, days*24)
    
    # Solve ODE
    solution = odeint(sir_model, y0, t, args=(beta, gamma))
    
    return solution.T  # Return S, I, R arrays
```

### Academic Citation

Based on: Kermack, W. O., & McKendrick, A. G. (1927). "A Contribution to the Mathematical Theory of Epidemics." Proceedings of the Royal Society.

---

## 4. Stackelberg Game Theory Engine

### Mathematical Foundation

The Stackelberg game models the strategic interaction between defenders (leaders) and attackers (followers), where defenders commit to a strategy first, and attackers respond optimally.

#### Core Optimization Problem

Defender's problem (leader):

```
max_{x∈X} min_{y∈Y(x)} U_D(x, y)

subject to:
- x: Defender's strategy (resource allocation)
- y(x): Attacker's best response to x
- U_D: Defender's utility function
- X: Defender's feasible strategy set
- Y(x): Attacker's feasible response set given x
```

#### Attacker's Best Response

Given defender strategy x, attacker solves:

```
max_{y∈Y(x)} U_A(x, y)

where U_A is attacker's utility function
```

#### Stackelberg Equilibrium (SSE)

Strategy pair (x*, y*) is SSE if:
1. y* ∈ argmax_{y∈Y(x*)} U_A(x*, y) (Attacker optimality)
2. x* ∈ argmax_{x∈X} U_D(x, argmax_{y∈Y(x)} U_A(x, y)) (Defender optimality)

### ORIGAMI Algorithm

The Optimal Resource Allocation for Multiple Incidents (ORIGAMI) algorithm solves the defender's optimization:

```
max_{x} Σ(i=1 to n) p_i(x) * V_i - C(x)

subject to:
- Σ(i=1 to n) x_i ≤ B (budget constraint)
- 0 ≤ x_i ≤ 1 (allocation bounds)
- p_i(x): Coverage probability of target i
- V_i: Value of protecting target i
- C(x): Total cost of allocation x
- B: Available budget
```

### Deterrence Index

The Deterrence Index (DI) measures attack profitability:

```
DI = (U_A + Cost_Attack) / (-U_D)

Interpretation:
- DI > 1: Attack is unprofitable (strong deterrence)
- DI = 1: Break-even point
- DI < 1: Attack is profitable (weak deterrence)
```

### Intuition

- **First-mover advantage**: Defender commits to visible defenses
- **Optimal response**: Attacker exploits weakest defended targets
- **Equilibrium**: No incentive to deviate for either player

### Implementation Reference

```python
def compute_stackelberg_equilibrium(defender_payoffs, attacker_payoffs):
    """Compute Stackelberg equilibrium using backward induction."""
    n_targets = defender_payoffs.shape[0]
    
    # For each defender strategy, find attacker's best response
    best_responses = []
    for def_strategy in range(n_targets):
        attacker_utilities = attacker_payoffs[:, def_strategy]
        best_attacker = np.argmax(attacker_utilities)
        best_responses.append(best_attacker)
    
    # Find defender strategy that maximizes utility given best responses
    defender_utilities_given_response = [
        defender_payoffs[i, best_responses[i]] 
        for i in range(n_targets)
    ]
    optimal_defender = np.argmax(defender_utilities_given_response)
    
    return {
        'defender_strategy': optimal_defender,
        'attacker_strategy': best_responses[optimal_defender],
        'defender_utility': defender_utilities_given_response[optimal_defender],
        'attacker_utility': attacker_payoffs[best_responses[optimal_defender], optimal_defender]
    }
```

### Academic Citation

Based on: Von Stackelberg, H. (1934). "Marktform und Gleichgewicht." Springer. And: Tambe, M. (2011). "Security and Game Theory." Cambridge University Press.

---

## 5. PID Controller Engine

### Mathematical Foundation

The Proportional-Integral-Derivative (PID) controller maintains system stability by adjusting defense parameters based on error signals between desired and actual system states.

#### Core Control Law

```
u(t) = K_p * e(t) + K_i * ∫₀ᵗ e(τ)dτ + K_d * de(t)/dt

where:
- u(t): Control output (defense adjustment)
- e(t): Error = setpoint - measurement
- K_p: Proportional gain
- K_i: Integral gain  
- K_d: Derivative gain
```

#### Transfer Function

In Laplace domain:

```
G(s) = U(s)/E(s) = K_p + K_i/s + K_d*s

or equivalently:
G(s) = (K_d*s² + K_p*s + K_i)/s
```

#### Discrete Implementation

For digital control with sampling time T:

```
u[k] = K_p*e[k] + K_i*T*Σ(i=0 to k) e[i] + K_d*(e[k] - e[k-1])/T
```

#### Tuning Parameters

- **Proportional term**: Reduces rise time, eliminates steady-state error
- **Integral term**: Eliminates steady-state error, improves disturbance rejection
- **Derivative term**: Reduces overshoot, improves stability

### Intuition

- **P term**: Responds to current error magnitude
- **I term**: Accumulates past errors for correction
- **D term**: Predicts future error based on rate of change

### Implementation Reference

```python
class PIDController:
    def __init__(self, Kp, Ki, Kd, setpoint, dt=1.0):
        self.Kp = Kp
        self.Ki = Ki
        self.Kd = Kd
        self.setpoint = setpoint
        self.dt = dt
        
        self.integral = 0
        self.previous_error = 0
    
    def update(self, measurement):
        """Compute control output."""
        error = self.setpoint - measurement
        
        # Proportional term
        P = self.Kp * error
        
        # Integral term
        self.integral += error * self.dt
        I = self.Ki * self.integral
        
        # Derivative term
        derivative = (error - self.previous_error) / self.dt
        D = self.Kd * derivative
        
        # Control output
        output = P + I + D
        
        self.previous_error = error
        return output
```

### Academic Citation

Based on: Åström, K. J., & Hägglund, T. (2006). "Advanced PID Control." ISA.

---

## 6. Lotka-Volterra Coevolution Engine

### Mathematical Foundation

The Lotka-Volterra equations model the coevolutionary dynamics between attackers (predators) and defenders (prey), capturing the arms race in cybersecurity.

#### Core Differential Equations

```
dA/dt = r_A * A * (1 - A/K_A) - α * A * D
dD/dt = r_D * D * (1 - D/K_D) + β * A * D

where:
- A(t): Attacker capability/innovation level
- D(t): Defender capability/innovation level
- r_A, r_D: Intrinsic growth rates
- K_A, K_D: Carrying capacities
- α: Attack success rate (predation)
- β: Defense learning rate (benefit from attacks)
```

#### Equilibrium Analysis

Coexistence equilibrium (both populations stable):

```
A* = (r_D/α) * (1 - D*/K_D)
D* = (r_A/β) * (1 - A*/K_A)

Solving simultaneously:
A* = K_A * (1 - r_D/(α*K_D))
D* = K_D * (1 - r_A/(β*K_A))
```

#### Stability Conditions

Jacobian matrix at equilibrium:

```
J = [[r_A(1 - 2A*/K_A) - α*D*, -α*A*],
     [β*D*, r_D(1 - 2D*/K_D) + β*A*]]

Stability requires: eigenvalues of J have negative real parts
```

### Intuition

- **Predation term α**: Attacks consume defender resources
- **Benefit term β**: Attacks accelerate defender innovation
- **Carrying capacity**: Maximum innovation level given resources
- **Coevolution**: Each side drives innovation in the other

### Implementation Reference

```python
def lotka_volterra_dynamics(t, state, params):
    """Lotka-Volterra differential equations."""
    A, D = state
    
    r_A, r_D, K_A, K_D, alpha, beta = params
    
    dAdt = r_A * A * (1 - A/K_A) - alpha * A * D
    dDdt = r_D * D * (1 - D/K_D) + beta * A * D
    
    return [dAdt, dDdt]

def simulate_coevolution(params, initial_state, days):
    """Simulate attacker-defender coevolution."""
    from scipy.integrate import odeint
    
    t = np.linspace(0, days, days*24)
    solution = odeint(lotka_volterra_dynamics, initial_state, t, args=(params,))
    
    return solution.T  # Return A(t), D(t)
```

### Academic Citation

Based on: Lotka, A. J. (1925). "Elements of Physical Biology." Williams & Wilkins. And: Hofbauer, J., & Sigmund, K. (1998). "Evolutionary Games and Population Dynamics." Cambridge University Press.

---

## 7. Markowitz Portfolio Optimization Engine

### Mathematical Foundation

Markowitz portfolio theory optimizes the allocation of defensive resources across multiple controls to maximize expected risk reduction for a given level of resource cost.

#### Core Optimization Problem

```
minimize: σ²_p = Σ(i=1 to n) Σ(j=1 to n) w_i * w_j * σ_ij
subject to: Σ(i=1 to n) w_i * μ_i = μ_p (target return)
           Σ(i=1 to n) w_i = 1 (full allocation)
           w_i ≥ 0 (no short selling)

where:
- w_i: Weight allocated to control i
- μ_i: Expected risk reduction from control i
- σ_ij: Covariance between controls i and j
- μ_p: Target portfolio risk reduction
- σ²_p: Portfolio variance (risk)
```

#### Efficient Frontier

The efficient frontier represents optimal portfolios:

```
E[R_p] = f(σ_p)

where each point on the frontier represents the maximum expected return
for a given level of risk (minimum variance for that return).
```

#### Sharpe Ratio

Risk-adjusted performance measure:

```
SR = (E[R_p] - R_f) / σ_p

where:
- R_f: Risk-free rate (baseline security)
- E[R_p]: Expected portfolio return
- σ_p: Portfolio standard deviation
```

### Intuition

- **Diversification**: Spreading resources reduces overall risk
- **Efficient frontier**: Best possible risk-return combinations
- **Optimal allocation**: Maximizes risk reduction per unit cost

### Implementation Reference

```python
def markowitz_optimization(returns, cov_matrix, target_return=None):
    """Solve Markowitz portfolio optimization."""
    n_assets = len(returns)
    
    if target_return is None:
        # Maximum Sharpe ratio portfolio
        def objective(weights):
            portfolio_return = np.sum(returns * weights)
            portfolio_risk = np.sqrt(weights.T @ cov_matrix @ weights)
            return -(portfolio_return - 0.02) / portfolio_risk  # Negative for minimization
    else:
        # Minimum variance for target return
        def objective(weights):
            portfolio_return = np.sum(returns * weights)
            portfolio_variance = weights.T @ cov_matrix @ weights
            return portfolio_variance
    
    # Constraints
    constraints = [
        {'type': 'eq', 'fun': lambda w: np.sum(w) - 1},  # Full allocation
    ]
    
    if target_return is not None:
        constraints.append({
            'type': 'eq', 
            'fun': lambda w: np.sum(returns * w) - target_return
        })
    
    # Bounds and initial guess
    bounds = [(0, 1) for _ in range(n_assets)]
    x0 = np.array([1/n_assets] * n_assets)
    
    from scipy.optimize import minimize
    result = minimize(objective, x0, method='SLSQP', 
                   bounds=bounds, constraints=constraints)
    
    return result.x, -result.fun  # Weights and optimal value
```

### Academic Citation

Based on: Markowitz, H. (1952). "Portfolio Selection." Journal of Finance. And: Elton, E. J., et al. (2014). "Modern Portfolio Theory and Investment Analysis." Wiley.

---

## Integration of Mathematical Engines

The seven mathematical engines work in concert to provide comprehensive threat analysis:

1. **KDE Surprise** identifies novel threats
2. **GPD Actuarial** quantifies financial risk
3. **SIR Epidemiology** models threat propagation
4. **Stackelberg Games** optimizes defense allocation
5. **PID Control** maintains system stability
6. **Lotka-Volterra** predicts coevolution dynamics
7. **Markowitz Portfolio** optimizes resource allocation

### Cross-Engine Synergies

- **Surprise + Epidemiology**: Novel threats may have different propagation patterns
- **Actuarial + Portfolio**: Risk metrics inform optimal resource allocation
- **Game Theory + Coevolution**: Strategic interactions drive innovation dynamics
- **PID Control + All Engines**: Maintains optimal system parameters

This integrated mathematical foundation enables IMMUNIS ACIN to provide intelligent, adaptive, and quantifiable cybersecurity defense capabilities.
