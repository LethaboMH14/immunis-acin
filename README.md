# IMMUNIS ACIN — Adversarial Coevolutionary Immune Network

> **The breach that teaches. The system that remembers.**

IMMUNIS ACIN is the world's first Adversarial Coevolutionary Immune Network — a living, self-evolving, multilingual cyber immune system that detects threats in 40+ languages, synthesises its own defences through adversarial AI battle, formally verifies their correctness, and broadcasts immunity across an encrypted peer-to-peer mesh so that every connected organisation inherits protection without ever experiencing the attack.

## 🎯 Hackathon Entry

**AMD Developer Hackathon (lablab.ai)**
- **Track 1: AI Agents** — 12 autonomous agents orchestrated via 7-stage pipeline
- **Track 2: Fine-Tuning on AMD GPUs** — 3 fine-tuned models (Sentinel, Adversary, Vision)
- **Track 3: Vision & Multimodal** — QR phishing, deepfake, document forgery, steganography detection
- **Additional:** HuggingFace Space Prize, Qwen Integration, Ship It + Build in Public

## 🏗️ Architecture Overview

┌──────────────────────────────────────────────────────────────────────┐
│ LAYER 1 — LINGUA (Sensory Layer) │
│ 40+ languages · Email · Voice · Network · Endpoint · Visual │
└──────────────────────────────┬───────────────────────────────────────┘
│
┌──────────────────────────────▼───────────────────────────────────────┐
│ LAYER 2 — IMMUNE CORE │
│ 12 Agents · Battleground (WGAN-GP) · Arbiter │
│ Deception · TAF · Scanner · Compliance │
└──────────────────────────────┬───────────────────────────────────────┘
│
┌──────────────────────────────▼───────────────────────────────────────┐
│ LAYER 3 — ANTIBODY MESH (P2P Network) │
│ Hybrid Ed25519 + CRYSTALS-Dilithium · R₀-priority gossip │
└──────────────────────────────┬───────────────────────────────────────┘
│
┌──────────────────────────────▼───────────────────────────────────────┐
│ LAYER 4 — RESPONSE (Six Audiences) │
│ SOC · IR · CISO · IT · Finance · Auditor │
└──────────────────────────────┬───────────────────────────────────────┘
│
┌──────────────────────────────▼───────────────────────────────────────┐
│ LAYER 5 — OBSERVABILITY │
│ Security Posture · MITRE ATT&CK · OWASP · Benchmarks │
└──────────────────────────────────────────────────────────────────────┘


## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ (for frontend)
- AMD GPU (optional, for fine-tuned models)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/immunis-acin.git
cd immunis-acin

# Install backend dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
# Edit .env with your API keys

# Run the backend
uvicorn backend.main:app --reload --port 8000

# Run the frontend (new terminal)
cd frontend
npm install
npm run dev

# Open browser
open http://localhost:3000
🧬 The 7-Stage AIR Protocol
Stage	Name	Time	Description
1	Surprise Detection	<200ms	Information-theoretic novelty via KDE on LaBSE space
2	Polymorphic Containment	<500ms	MILP-generated unique containment per incident
3	Adaptive Deception	Simultaneous	RL-optimised honeypot + canary token deployment
4	Analogical Bridge Defense	<2s	Attention-weighted antibody fusion from nearest family
5	Deep Synthesis + Verification	30-60s	Agent 2 generates antibody, Z3 proves correctness
6	Adversarial Stress Test	30s-5min	WGAN-GP Red vs Blue in Battleground digital twin
7	Mesh Broadcast	<300ms	R₀-prioritised distribution with hybrid signatures
🤖 The 12 Agents
#	Agent	Role	Key Technology
1	Incident Analyst	Semantic fingerprinting	LaBSE + LLM classification
2	Antibody Synthesiser	Detection rule compilation	LLM + Z3 theorem prover
3	Immune Memory	Antibody storage & clustering	FAISS + Hebbian learning
4	Red Agent	Adversarial variant generation	LLM with T=0.8 creativity
5	Variant Recogniser	Known/variant/novel classification	KDE surprise detection
6	Evolution Tracker	Arms race history + PID control	PID controller + Lotka-Volterra
7	Mesh Broadcaster	Sign & broadcast antibodies	Ed25519 + Dilithium + gossip
8	Visual Threat Analyst	Image/QR/document analysis	FFT + ELA + chi-squared + LLM vision
9	Epidemiological Modeler	SIR model, R₀ computation	Differential equations
10	Actuarial Risk Engine	GPD, CVaR, expected loss	Extreme value theory
11	Game Theorist	Stackelberg equilibrium	ORIGAMI + ERASER algorithms
12	Arbiter	Battleground judge, promotion	Multi-criteria decision
📊 Mathematical Engines
Engine	Math	Purpose
Surprise Detector	S(x) = -log₂ p̂(x), Gaussian KDE	Novelty detection without black-box confidence
Actuarial Risk	GPD, VaR(95%), CVaR(95%)	Financial risk per antibody
Epidemiological	SIR: dS/dt = -βSI/N	Immunity propagation modelling
Game Theory	Stackelberg SSE, ORIGAMI	Optimal defence allocation
PID Controller	u(t) = Kp·e + Ki·∫e + Kd·de/dt	Immunity score stabilisation
Coevolution	Lotka-Volterra	Red-Blue arms race dynamics
Portfolio	Markowitz mean-variance, Sharpe ratio	Optimal resource allocation under budget constraints
🖥️ Frontend Dashboard
Design Philosophy: "Calm Vigilance"
Serene until action needed, then precise and decisive. Inspired by Wiz, Darktrace, Linear, Bloomberg.

3 Theme Modes
Midnight — Deep dark (#0A0E1A) for SOC analysts in dim rooms
Twilight — Medium dark (#1A1F2E) for extended 8+ hour shifts
Overcast — Warm white (#F8FAFC) for executives in bright offices
10 Pages
Page	Purpose
Overview	Landing page — immunity gauge, metrics, feed, pipeline, evolution
Threats	Submit threats, live feed, statistics, language breakdown
Immunity	Antibody library with search, filter, strength bars, Z3 verification
Battleground	Red vs Blue arena, arms race chart, battle history
Mesh Network	P2P topology visualization, node list, R₀, herd immunity
Scanner	4-layer vulnerability scanning (SAST/DAST/Infra/Results)
Compliance	8 frameworks, posture scoring, 6 auto-generated report types
Copilot	AI chat with 6 audience levels, quick actions
Analytics	7 math engines visualized — actuarial, game theory, SIR, portfolio
Settings	Theme, density, role, notifications, about
Key UI Features
Command Palette (Cmd+K) — Power user quick access to any page or action
Real-time WebSocket — Live updates for threats, antibodies, pipeline, mesh
Framer Motion animations — 30+ reusable variants, respects prefers-reduced-motion
Responsive design — Desktop, tablet, mobile breakpoints
Keyboard shortcuts — Navigate, toggle theme, submit threats without mouse
Demo mode — Auto-authenticated for hackathon judges

### Cinematic Visualizations (Canvas-based, 60fps)
- **Mesh Network** — Force-directed physics with flowing antibody broadcast particles, pulsing nodes, organic drift, hover tooltips
- **Battleground Arena** — Red projectiles vs Blue shield wall, impact explosions with particle shockwaves, zone glow, score counters
- **Immunity Ring** — Multi-ring gauge with orbiting particles, conic gradient arcs, breathing center score, color transitions
- **Honeypot Sandbox** — Terminal aesthetic with scripted attacker session, MITRE ATT&CK annotations, tool detection callouts, auto-looping

🔍 Vulnerability Scanner

IMMUNIS doesn't just detect external threats — it examines its own infrastructure:

Static Analysis (SAST)
12 detection rules covering OWASP Top 10 + LLM Top 10
AST-based analysis with LLM semantic verification
Dependency checking against known CVE database
Dynamic Analysis (DAST)
Security headers, TLS configuration, CORS misconfiguration
Injection testing (SQL, XSS, command, path traversal, SSTI)
Authentication bypass and sensitive file exposure
Infrastructure Audit (CIS Benchmarks)
Network security, file system permissions, account security
Cryptographic configuration, compliance scoring
AI Security Copilot
6 audience levels with appropriate language
Explain, fix, plan, and interactive chat modes
🛡️ Deception Layer
Canary Tokens — 9 types with HMAC-SHA256 constant-time verification
RL-Adaptive Honeypot — Q-learning agent that evolves deception strategies
Capture Engine — Full session transcripts, MITRE ATT&CK mapping, 128-dim fingerprints
� Compliance Engine
8 Regulatory Frameworks
Framework	Controls	Focus
POPIA	7	South African data protection (mandatory)
NIST CSF 2.0	12	Cybersecurity framework
MITRE ATT&CK v14	8	Adversary technique coverage
CIS Controls v8	11	Operational security baseline
OWASP Top 10	10	Web application security
OWASP LLM Top 10	10	AI/LLM-specific security
Cybercrimes Act	5	South African cybercrime law (mandatory)
GDPR	7	EU data protection
6 Auto-Generated Report Types
POPIA Section 22, Cybercrimes Act S54, GDPR Article 33
Executive Summary, Audit Package, Incident Report
🌐 Mesh Network
Hybrid Signing — Ed25519 + CRYSTALS-Dilithium (post-quantum ready)
Epidemic Gossip — R₀-weighted fan-out with bloom filter deduplication
STIX/TAXII 2.1 — Industry interoperability with SIEMs, TIPs, SOARs
🔐 Security Features
5-layer input sanitisation with prompt injection detection
Per-agent circuit breakers and rate limiting
Merkle tree audit trail with WORM anchor
5-level emergency lockout (PAUSE → SCORCHED_EARTH)
Behavioural biometric continuous authentication
Z3 formal verification of detection rules
🌍 Multilingual Support
40+ languages including all 11 South African official languages, with:

Script-based detection, Bantu noun-class analysis
Code-switch detection via sliding window entropy
Context-preserving translation with social engineering annotation
Cultural context notes (Ubuntu philosophy, lobola, sangoma references)
📊 Demo Scenario (3 Minutes)
T+0:00  Dashboard open. ImmunityGauge at 72. Three mesh nodes green.
T+0:10  BEC email arrives in Sesotho. ThreatFeed shows ST badge.
T+0:15  Surprise score: 9.2 bits (NOVEL). Purple flash.
T+0:20  Polymorphic containment deploys. Honeypot activates.
T+0:30  Agent 1 fingerprint appears. Agent 8 scans attached invoice.
T+0:45  Multimodal fusion: text 0.87 + visual 0.91 = combined 0.97.
T+0:55  Agent 2 synthesises antibody. Z3 verification: SOUND ✓
T+1:10  Red Agent attacks. ArmsRaceTimeline activates.
T+1:30  Blue blocks 5/6 variants. New antibody for the evasion.
T+1:45  Arbiter: strength 0.89. PROMOTED.
T+1:50  Mesh broadcast. R₀ = 2.3. Tshwane → green. Joburg → green.
T+2:00  Same attack hits Tshwane. BLOCKED. Antibody matched.
T+2:10  ResponseLayer: SOC tab → Architect tab → Executive tab.
T+2:20  Actuarial: R500K loss prevented. Deterrence index: HIGH.
T+2:30  Compliance: POPIA 94%, NIST 88%. Auto-generated S22 draft.
T+2:40  "IMMUNIS went from vulnerable to immune in 90 seconds."
T+2:50  "Two municipalities are now immune without being attacked."
T+2:55  "The breach that teaches. The system that remembers."

🏆 Technical Highlights
Backend (55+ files, ~20,000+ LOC)
12 autonomous AI agents orchestrated via 7-stage pipeline
7 mathematical engines (KDE, GPD, SIR, Stackelberg, PID, Lotka-Volterra, Markowitz)
Formal verification via Z3 theorem prover
Post-quantum cryptography (Ed25519 + CRYSTALS-Dilithium hybrid)
RL-adaptive honeypots with Q-learning
128-dimensional threat actor fingerprinting with DBSCAN clustering
5 psychographic attacker profiles with tailored deterrence
Epidemic gossip protocol with R₀-priority broadcast
STIX/TAXII 2.1 for industry interoperability
40+ language support including all 11 SA official languages
4-layer vulnerability scanning (SAST + DAST + Infrastructure + AI Copilot)
8 compliance frameworks with 70+ controls
6 auto-generated regulatory report types
Frontend (~83 files, ~11,000+ LOC)
10 full page components with responsive grid layouts
19 common UI components (design-system compliant)
3-mode theme system (Midnight/Twilight/Overcast) with 80+ CSS properties each
"Calm Vigilance" design philosophy — Wiz, Darktrace, Linear, Bloomberg inspired
Framer Motion animation system with 30+ reusable variants
Command palette (Cmd+K) for power user navigation
Real-time WebSocket state management via provider pattern
Typed API client with retry, timeout, and interceptors
Complete TypeScript type system mirroring all backend Pydantic models
South African locale-first formatting (en-ZA dates, ZAR currency)
SVG data visualizations (immunity gauge, evolution sparkline, arms race chart, network topology)
Lazy-loaded pages via React.lazy + Suspense
Keyboard shortcuts for all primary actions
Demo mode with auto-authentication and sample threats
Accessibility: focus traps, ARIA labels, prefers-reduced-motion support
Combined
~138 files across backend + frontend
~31,000+ lines of code
End-to-end tested with real multilingual threats
23-second threat-to-immunity pipeline via Groq
📱 API Endpoints
# Threats
POST /api/threats                    # Analyze a threat
GET  /api/health                     # Health check

# Evolution & Battleground
GET  /api/evolution/timeline         # Evolution timeline
GET  /api/battleground/history       # Battleground history

# Risk & Epidemiology
GET  /api/risk/portfolio             # Risk portfolio
GET  /api/risk/allocation            # Portfolio allocation
GET  /api/epidemiological            # Epidemiological state

# Scanner
POST /api/scanner/static             # Run SAST scan
POST /api/scanner/dynamic            # Run DAST scan
POST /api/scanner/infra              # Run infrastructure audit
GET  /api/scanner/results            # Get scan results

# Compliance
GET  /api/compliance/posture         # Compliance posture
POST /api/compliance/assess          # Run assessment
POST /api/compliance/report          # Generate report

# Copilot
POST /api/copilot/chat               # Interactive chat
POST /api/copilot/explain            # Explain vulnerability
POST /api/copilot/fix                # Suggest fix
POST /api/copilot/plan               # Remediation plan

# TAXII
GET  /taxii2/                        # TAXII discovery
GET  /taxii2/collections/            # TAXII collections
🧪 Testing
pytest                               # Run all tests
pytest tests/test_agents/            # Agent tests
pytest --cov=backend --cov-report=html  # Coverage
python tests/benchmarks/mitre_evaluation.py  # MITRE eval
📄 License
This project is licensed under the MIT License.

🤝 Acknowledgments
AMD Developer Hackathon for GPU resources
AIsa.one for multi-model API access
Hugging Face for model hosting and community
The open-source security community
The breach that teaches. The system that remembers.


"The breach that teaches. The system that remembers."
