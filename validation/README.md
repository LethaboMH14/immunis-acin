# IMMUNIS ACIN — Validation Harness

> Industry-grade validation framework that runs IMMUNIS against real-world
> threat intelligence and produces a scored report.

## Quick Start

```bash
# Safe offline validation (default — no API calls)
python -m validation.full_validation

# Live validation (hits real VirusTotal, NVD, PhishTank APIs)
python -m validation.full_validation --live

# Quick validation (skips slow checks)
python -m validation.full_validation --fast

# Save report to specific file
python -m validation.full_validation --output reports/my_validation.json
```

## Validation Sections

### 1. Internal Test Suite
- Runs pytest and captures pass/fail rates
- Weight: 15%
- Target: >95% pass rate

### 2. Multilingual Detection  
- Tests threat detection across Sesotho, isiZulu, Arabic, Mandarin, Russian, English
- Weight: 15%
- Target: >90% language detection accuracy

### 3. Adversarial Robustness
- Tests evasion techniques: homoglyphs, Unicode bypass, case manipulation, etc.
- Weight: 20%
- Target: >80% robustness score

### 4. MITRE ATT&CK Coverage
- Validates technique mapping, layer generation, gap analysis
- Weight: 15%
- Target: >40 techniques mapped

### 5. Real-World Threat Feeds
- Live API integration: VirusTotal, PhishTank, NVD
- Weight: 15%
- Target: API connectivity and data retrieval

### 6. Performance SLAs
- Benchmarks core components against performance targets
- Weight: 10%
- Target: <200ms surprise, <1ms PID, <50ms VaR, <10ms SIR

### 7. Compliance Frameworks
- Validates POPIA, NIST CSF, MITRE ATT&CK, OWASP, GDPR
- Weight: 10%
- Target: Framework integration coverage

## Scoring & Grades

- **A (90-100)**: PRODUCTION-READY
- **B (80-89)**: HACKATHON-READY  
- **C (70-79)**: DEMO-READY
- **D (60-69)**: NEEDS POLISH
- **F (0-59)**: NEEDS WORK

## Output Formats

- **Terminal**: Color-coded real-time output
- **JSON**: Structured report for integration
- **Exit Codes**: 0 (A), 1 (B), 2 (C/D), 3 (F)

## Architecture

```
validation/
├── __init__.py          # Package init
├── full_validation.py    # Main orchestrator
├── reports/             # JSON output directory
│   └── .gitkeep       # Git tracking
└── README.md            # This documentation
```

## Usage Examples

```bash
# Full validation (production readiness check)
python -m validation.full_validation

# Quick demo validation (skip slow checks)
python -m validation.full_validation --fast

# Live threat intelligence validation
python -m validation.full_validation --live --verbose

# Save detailed report
python -m validation.full_validation --output validation_report_$(date +%Y%m%d_%H%M%S).json
```

## Integration Points

The harness validates integration with:
- **Backend Services**: VirusTotal, NVD, PhishTank clients
- **Math Engines**: Surprise detection, PID control, VaR, SIR models
- **Lingua Engine**: Multi-language threat ingestion
- **Compliance**: POPIA, NIST, MITRE frameworks
- **Security**: Input sanitisation and formal verification

## Performance Targets

| Component                | Target     | Measurement Method |
|-------------------------|-------------|-------------------|
| Surprise Detection       | <200ms      | 100 iterations    |
| PID Controller          | <1ms        | 1000 iterations   |
| Actuarial VaR          | <50ms       | 10 iterations      |
| SIR Model              | <10ms       | 200 steps          |
| Input Sanitisation     | <5ms        | 100 iterations     |

## Exit Codes

- `0`: Production-ready (Grade A)
- `1`: Hackathon-ready (Grade B) 
- `2`: Needs polish (Grade C/D)
- `3`: Failed validation (Grade F)
