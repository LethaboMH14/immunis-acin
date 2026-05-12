# IMMUNIS ACIN - System Architecture

## Overview

IMMUNIS ACIN (AI-powered Cybersecurity Intelligence Network) is a sophisticated defense system that combines multiple AI agents, mathematical engines, and distributed mesh networking to provide comprehensive threat detection and response capabilities.

## 5-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    LAYER 5: PRESENTATION & ANALYTICS                │
├─────────────────────────────────────────────────────────────────────────┤
│  • Web Dashboard (React/TypeScript)                               │
│  • Real-time Analytics & Visualization                              │
│  • Threat Intelligence Display                                        │
│  • API Gateway (FastAPI)                                           │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      LAYER 4: AI AGENTS                             │
├─────────────────────────────────────────────────────────────────────────┤
│  • Sentinel Agent (Threat Detection)                               │
│  • Adversary Agent (Red Team Simulation)                            │
│  • Vision Agent (Visual Threat Analysis)                             │
│  • Antibody Synthesiser (Pattern Generation)                         │
│  • Evolution Tracker (Co-evolution Monitoring)                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   LAYER 3: MATHEMATICAL ENGINES                        │
├─────────────────────────────────────────────────────────────────────────┤
│  • KDE Surprise Detection (Novelty Detection)                        │
│  • GPD Actuarial Risk (Extreme Value Theory)                         │
│  • SIR Epidemiological Model (Threat Propagation)                     │
│  • Stackelberg Game Theory (Optimal Defense)                          │
│  • PID Controller (System Stability)                                   │
│  • Lotka-Volterra Coevolution (Arms Race Dynamics)                   │
│  • Markowitz Portfolio (Resource Optimization)                           │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    LAYER 2: DATA & STORAGE                             │
├─────────────────────────────────────────────────────────────────────────┤
│  • Vector Database (FAISS)                                         │
│  • Relational Database (SQLite/PostgreSQL)                           │
│  • Cache Layer (Redis)                                              │
│  • Knowledge Graph (Neo4j)                                          │
│  • Log Storage (Elasticsearch)                                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     LAYER 1: INFRASTRUCTURE                             │
├─────────────────────────────────────────────────────────────────────────┤
│  • Mesh Network (P2P Communication)                                │
│  • Load Balancer (NGINX)                                          │
│  • Message Queue (RabbitMQ)                                        │
│  • Monitoring (Prometheus/Grafana)                                  │
│  • Security (OAuth 2.0 + Cryptographic Controls)                   │
└─────────────────────────────────────────────────────────────────────────┘
```

## 7-Stage AIR Protocol (Adaptive Immune Response)

The AIR protocol defines how threats flow through the system:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    STAGE 1: INGESTION                              │
├─────────────────────────────────────────────────────────────────────────┤
│  • Input Sanitisation & Validation                                    │
│  • Language Detection (15 languages)                                  │
│  • Encoding Normalisation (NFC)                                       │
│  • Homoglyph Attack Detection                                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   STAGE 2: FEATURE EXTRACTION                         │
├─────────────────────────────────────────────────────────────────────────┤
│  • LaBSE Embeddings (768-dim vectors)                             │
│  • Linguistic Feature Extraction                                      │
│  • Semantic Analysis                                                │
│  • Pattern Recognition                                               │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    STAGE 3: SURPRISE DETECTION                        │
├─────────────────────────────────────────────────────────────────────────┤
│  • KDE Density Estimation                                            │
│  • Novelty Scoring (Known/Variant/Novel)                            │
│  • Threshold Classification (3/8 boundary)                           │
│  • Library Updating                                                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     STAGE 4: THREAT CLASSIFICATION                      │
├─────────────────────────────────────────────────────────────────────────┤
│  • Multi-family Detection (11 attack families)                         │
│  • Severity Assessment (Low/Medium/High)                             │
│  • Confidence Scoring                                               │
│  • Geographic & Temporal Analysis                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     STAGE 5: RISK ASSESSMENT                           │
├─────────────────────────────────────────────────────────────────────────┤
│  • GPD Extreme Value Analysis                                        │
│  • VaR/CVaR Computation (95%/99%)                                  │
│  • Expected Loss Calculation                                         │
│  • ROI Analysis for Controls                                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    STAGE 6: RESPONSE GENERATION                        │
├─────────────────────────────────────────────────────────────────────────┤
│  • Antibody Pattern Synthesis                                       │
│  • Adaptive Defense Strategies                                        │
│  • Game-Theoretic Optimization                                       │
│  • Resource Allocation                                              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    STAGE 7: COEVOLUTION                              │
├─────────────────────────────────────────────────────────────────────────┤
│  • Red Team Simulation (Adversary Agent)                             │
│  • Blue Team Adaptation (Sentinel Updates)                            │
│  • Lotka-Volterra Dynamics                                         │
│  • Arms Race Monitoring                                             │
└─────────────────────────────────────────────────────────────────────────┘
```

## Agent Interaction Diagram

```
                    ┌─────────────────┐
                    │   FRONTEND     │
                    │  (Dashboard)    │
                    └─────────┬───────┘
                              │ API
                              ▼
                    ┌─────────────────┐
                    │  API GATEWAY   │
                    │   (FastAPI)    │
                    └─────────┬───────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    MESSAGE QUEUE (RabbitMQ)                      │
├─────────────────────────────────────────────────────────────────────┤
│  • Threat Ingestion Queue                                        │
│  • Agent Communication Queue                                       │
│  • Response Generation Queue                                        │
│  • Analytics Queue                                                │
└─────────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                    ▼                   ▼
        ┌─────────────────┐   ┌─────────────────┐
        │   SENTINEL     │   │  ADVERSARY     │
        │   AGENT        │   │    AGENT       │
        │ (Blue Team)    │   │ (Red Team)     │
        └─────────┬─────┘   └─────────┬─────┘
                  │                     │
                  ▼                     ▼
        ┌─────────────────┐   ┌─────────────────┐
        │   VISION       │   │  ANTIBODY      │
        │   AGENT        │   │ SYNTHESER     │
        └─────────┬─────┘   └─────────┬─────┘
                  │                     │
                  └─────────┬───────────┘
                            │
                            ▼
        ┌─────────────────────────────────────┐
        │     MATHEMATICAL ENGINES          │
        │  (KDE, GPD, Game Theory, etc.)  │
        └─────────────────┬─────────────────┘
                          │
                          ▼
        ┌─────────────────────────────────────┐
        │        DATA LAYER                │
        │  (Vector DB, SQL, Cache)        │
        └─────────────────────────────────────┘
```

## Mesh Network Topology

```
                    ┌─────────────────────────────────────────┐
                    │           MESH NETWORK             │
                    │     (Decentralized P2P)              │
                    └─────────────────────────────────────────┘
                              
                              │
                    ┌─────────┴─────────┐
                    │                   │
                    ▼                   ▼
        ┌─────────────────┐   ┌─────────────────┐
        │   NODE A        │   │   NODE B        │
        │ (Primary Hub)   │   │ (Edge Node)    │
        │ • Sentinel      │   │ • Sentinel      │
        │ • Adversary    │   │ • Vision        │
        │ • Math Engines  │   │ • Cache        │
        └─────────┬─────┘   └─────────┬─────┘
                  │                     │
                  │     P2P Links        │
                  │                     │
        ┌─────────┴─────────┐   ┌─────────┴─────────┐
        │   NODE C        │   │   NODE D        │
        │ (Analytics)     │   │ (Storage)      │
        │ • Dashboard    │   │ • Vector DB     │
        │ • Monitoring    │   │ • SQL DB       │
        │ • API Gateway   │   │ • Backup        │
        └───────────────────┘   └───────────────────┘
                  │                     │
                  └─────────┬───────────┘
                            │
                            ▼
        ┌─────────────────────────────┐
        │   LOAD BALANCER          │
        │    (NGINX)              │
        │   • Round Robin          │
        │   • Health Checks        │
        │   • SSL Termination      │
        └─────────────────────────────┘
```

## Technology Stack Summary

| Component | Technology | Purpose | Key Features |
|-----------|-------------|---------|---------------|
| **Frontend** | React + TypeScript | User Interface | Real-time updates, responsive design |
| **Backend API** | FastAPI + Pydantic | REST API | Auto-docs, validation, async support |
| **AI/ML** | PyTorch + Transformers | Model Inference | ROCm support, distributed training |
| **Vector DB** | FAISS | Similarity Search | High-performance ANN search |
| **Relational DB** | SQLite/PostgreSQL | Structured Data | ACID compliance, indexing |
| **Cache** | Redis | Fast Access | In-memory storage, pub/sub |
| **Message Queue** | RabbitMQ | Async Communication | Reliable delivery, routing |
| **Load Balancer** | NGINX | Traffic Distribution | SSL termination, health checks |
| **Monitoring** | Prometheus + Grafana | Observability | Metrics, alerts, visualization |
| **Security** | OAuth 2.0 + Ed25519 | Authentication | Cryptographic signing, token-based auth |
| **Deployment** | Docker + Kubernetes | Container Orchestration | Scalability, rolling updates |

## Data Flow Architecture

```
External Threat Sources
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                 INGESTION LAYER                              │
│  • Email APIs (IMAP/Exchange)                                │
│  • Network Logs (Syslog/CEF)                                 │
│  • Threat Feeds (STIX/TAXII)                                │
│  • Webhooks (Custom Integrations)                               │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                PROCESSING PIPELINE                              │
│  1. Input Sanitisation                                           │
│  2. Language Detection & Translation                                 │
│  3. Feature Extraction (LaBSE)                                    │
│  4. Vector Embedding                                               │
│  5. Metadata Enrichment                                          │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│               ANALYSIS ENGINES                                 │
│  • KDE Surprise Detection (Novelty)                               │
│  • Threat Classification (11 Families)                               │
│  • Risk Assessment (GPD/VaR/CVaR)                              │
│  • Game Theory Optimization                                        │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│              RESPONSE GENERATION                                   │
│  • Antibody Pattern Synthesis                                    │
│  • Adaptive Defense Strategies                                    │
│  • Resource Allocation                                            │
│  • Coevolution Monitoring                                       │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│               STORAGE & INDEXING                                  │
│  • Vector Database (FAISS)                                      │
│  • Time Series Database (InfluxDB)                                │
│  • Knowledge Graph (Neo4j)                                      │
│  • Log Storage (Elasticsearch)                                     │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│              PRESENTATION LAYER                                │
│  • Real-time Dashboard                                          │
│  • API Endpoints                                                │
│  • Alerting System                                             │
│  • Reporting Engine                                             │
└─────────────────────────────────────────────────────────────────┘
```

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   SECURITY BOUNDARY                             │
├─────────────────────────────────────────────────────────────────┤
│  • Network Firewall (iptables/nftables)                        │
│  • Web Application Firewall (ModSecurity)                        │
│  • DDoS Protection (Cloudflare)                               │
│  • SSL/TLS Encryption (TLS 1.3)                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                AUTHENTICATION & AUTHORIZATION                     │
├─────────────────────────────────────────────────────────────────┤
│  • OAuth 2.0 + OpenID Connect                                 │
│  • JWT Tokens (Ed25519 signed)                                   │
│  • Role-Based Access Control (RBAC)                                 │
│  • Multi-Factor Authentication (MFA)                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  DATA PROTECTION                                   │
├─────────────────────────────────────────────────────────────────┤
│  • Encryption at Rest (AES-256)                                  │
│  • Encryption in Transit (TLS 1.3)                                │
│  • Key Management (HSM)                                          │
│  • Data Masking & Anonymization                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 AUDIT & COMPLIANCE                                │
├─────────────────────────────────────────────────────────────────┤
│  • Comprehensive Logging (Audit Trail)                               │
│  • Immutable Logs (WORM Storage)                                  │
│  • Compliance Reporting (GDPR/SOC2)                               │
│  • Security Monitoring (SIEM Integration)                           │
└─────────────────────────────────────────────────────────────────┘
```

## Scalability & Performance Considerations

### Horizontal Scaling
- **Stateless Services**: All API endpoints designed for horizontal scaling
- **Load Balancing**: NGINX with round-robin and health checks
- **Database Sharding**: Vector DB and relational DB can be sharded
- **Caching Strategy**: Multi-layer caching (Redis + CDN)

### Performance Optimizations
- **Vector Search**: FAISS with GPU acceleration for similarity queries
- **Batch Processing**: Bulk operations for data ingestion
- **Async Operations**: Non-blocking I/O throughout the pipeline
- **Connection Pooling**: Database and external API connection reuse

### Fault Tolerance
- **Circuit Breakers**: Prevent cascading failures
- **Retry Logic**: Exponential backoff for external calls
- **Health Checks**: Comprehensive service monitoring
- **Graceful Degradation**: Fallback mechanisms for critical failures

## Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    KUBERNETES CLUSTER                          │
├─────────────────────────────────────────────────────────────────┤
│  • API Pods (3+ replicas)                                     │
│  • Agent Pods (1+ per agent type)                             │
│  • Database Pods (Primary + Replica)                           │
│  • Monitoring Stack (Prometheus + Grafana)                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  PERSISTENT STORAGE                               │
├─────────────────────────────────────────────────────────────────┤
│  • Persistent Volumes (SSD)                                      │
│  • Object Storage (S3/MinIO)                                   │
│  • Backup Storage (Cross-region)                                   │
│  • Log Aggregation (ELK Stack)                                    │
└─────────────────────────────────────────────────────────────────┘
```

This architecture provides a robust, scalable, and secure foundation for the IMMUNIS ACIN system, enabling real-time threat detection and adaptive response capabilities while maintaining high availability and performance.
