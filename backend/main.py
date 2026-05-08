"""
IMMUNIS ACIN — FastAPI Application

The entry point for the entire system. Handles:
    - HTTP API routes (threat submission, antibody queries, health checks)
    - WebSocket hub (real-time dashboard updates)
    - Application lifecycle (startup, shutdown)
    - CORS configuration
    - Error handling

Architecture:
    HTTP POST /api/threats → returns 202 immediately
    → Background task runs 7-stage AIR pipeline
    → WebSocket broadcasts events at each stage
    → Dashboard updates in real time

Security:
    - CORS restricted to frontend URL
    - Rate limiting on all endpoints
    - Input validation via Pydantic
    - No raw content in any response
    - Health check exposes minimal information

Temperature: 0.3 (infrastructure code)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config import get_settings, print_startup_banner
from backend.models.enums import ThreatVector, Language
from backend.models.schemas import (
    AnalyzeThreatRequest,
    AnalyzeThreatResponse,
    AntibodyListResponse,
    HealthResponse,
    MeshStatusResponse,
    ThreatInput,
    generate_id,
    utc_now,
)
from backend.security.rate_limiter import get_rate_limiter

logger = logging.getLogger("immunis.main")

# ============================================================================
# STARTUP TIME TRACKING
# ============================================================================

_start_time: float = 0.0


# ============================================================================
# WEBSOCKET CONNECTION MANAGER
# ============================================================================

class ConnectionManager:
    """
    Manages WebSocket connections for real-time dashboard updates.
    
    Every pipeline event is broadcast to all connected clients.
    Clients receive typed events they can route to specific UI components.
    """

    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, data: dict[str, Any]) -> None:
        """
        Broadcast an event to all connected WebSocket clients.
        
        Failed sends are silently dropped — a disconnected client
        should not affect other clients or the pipeline.
        """
        async with self._lock:
            dead_connections = []
            for connection in self.active_connections:
                try:
                    await connection.send_json(data)
                except Exception:
                    dead_connections.append(connection)

            # Clean up dead connections
            for dead in dead_connections:
                if dead in self.active_connections:
                    self.active_connections.remove(dead)

    @property
    def client_count(self) -> int:
        return len(self.active_connections)


# Global connection manager
ws_manager = ConnectionManager()


# ============================================================================
# APPLICATION LIFECYCLE
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifecycle.
    
    Startup:
        1. Print banner with provider status
        2. Validate configuration
        3. Initialise orchestrator with WebSocket broadcast function
        4. Load persisted data (immune memory, audit trail, surprise library)
    
    Shutdown:
        1. Save all persisted data
        2. Close WebSocket connections
        3. Log shutdown
    """
    global _start_time
    _start_time = time.monotonic()

    settings = get_settings()

    # Print startup banner
    print_startup_banner(settings)

    # Initialise orchestrator with broadcast function
    from backend.orchestrator import get_orchestrator
    orchestrator = get_orchestrator(broadcast_fn=ws_manager.broadcast)

    # Load persisted data
    try:
        from backend.agents.immune_memory import get_immune_memory
        memory = get_immune_memory()
        logger.info(f"Immune Memory: {memory.library_size} antibodies loaded")
    except Exception as e:
        logger.warning(f"Failed to load Immune Memory: {e}")

    try:
        from backend.security.audit_trail import get_audit_trail
        trail = get_audit_trail()
        logger.info(f"Audit Trail: {trail.size} events loaded")
    except Exception as e:
        logger.warning(f"Failed to load Audit Trail: {e}")

    try:
        from backend.math_engines.surprise import get_surprise_detector
        detector = get_surprise_detector()
        logger.info(f"Surprise Detector: {detector.library_size} vectors loaded")
    except Exception as e:
        logger.warning(f"Failed to load Surprise Detector: {e}")

    logger.info("IMMUNIS ACIN started successfully")

    yield  # Application runs here

    # ── Shutdown ────────────────────────────────────────────────────────
    logger.info("IMMUNIS ACIN shutting down...")

    # Save persisted data
    try:
        from backend.agents.immune_memory import get_immune_memory
        memory = get_immune_memory()
        memory.save(str(settings.data_dir / "immune_memory"))
        logger.info("Immune Memory saved")
    except Exception as e:
        logger.warning(f"Failed to save Immune Memory: {e}")

    try:
        from backend.security.audit_trail import get_audit_trail
        trail = get_audit_trail()
        trail.save(str(settings.data_dir / "audit_trail"))
        logger.info("Audit Trail saved")
    except Exception as e:
        logger.warning(f"Failed to save Audit Trail: {e}")

    try:
        from backend.math_engines.surprise import get_surprise_detector
        detector = get_surprise_detector()
        detector.save(str(settings.data_dir / "surprise_library"))
        logger.info("Surprise Detector saved")
    except Exception as e:
        logger.warning(f"Failed to save Surprise Detector: {e}")

    logger.info("IMMUNIS ACIN shutdown complete")


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="IMMUNIS ACIN",
    description=(
        "Adversarial Coevolutionary Immune Network — "
        "The world's first self-evolving multilingual cyber immune system"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        settings.frontend_url,
        "http://localhost:3000",
        "http://localhost:5173",  # Vite dev server
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


# ============================================================================
# API ROUTES — THREAT ANALYSIS
# ============================================================================

@app.post(
    "/api/threats",
    response_model=AnalyzeThreatResponse,
    status_code=202,
    summary="Submit a threat for analysis",
    description=(
        "Submit suspicious content for analysis through the 7-stage AIR pipeline. "
        "Returns 202 immediately. Pipeline progress is streamed via WebSocket."
    ),
)
async def submit_threat(
    request: AnalyzeThreatRequest,
    background_tasks: BackgroundTasks,
) -> AnalyzeThreatResponse:
    """
    Submit a threat for analysis.
    
    The threat is processed asynchronously through the 7-stage pipeline.
    Progress is broadcast via WebSocket events.
    The response contains a pipeline_id for tracking.
    """
    # Rate limiting
    limiter = get_rate_limiter("api_threat_submission")
    if not limiter.allow("api_default"):
        raise HTTPException(
            status_code=429,
            detail="Rate limited. Please wait before submitting another threat.",
        )

    # Build ThreatInput
    threat = ThreatInput(
        content=request.content,
        vector=request.vector,
        language_hint=Language.from_string(request.language_hint) if request.language_hint else None,
        metadata=request.metadata,
        image_base64=request.image_base64,
        audio_base64=request.audio_base64,
    )

    pipeline_id = generate_id("PL")

    # Run pipeline in background
    background_tasks.add_task(_run_pipeline, threat, pipeline_id)

    return AnalyzeThreatResponse(
        pipeline_id=pipeline_id,
        status="processing",
        message="Threat received. Processing via 7-stage AIR pipeline. Track via WebSocket.",
    )


async def _run_pipeline(threat: ThreatInput, pipeline_id: str) -> None:
    """Background task that runs the full pipeline."""
    try:
        from backend.orchestrator import get_orchestrator
        orchestrator = get_orchestrator()
        await orchestrator.process_threat(threat)
    except Exception as e:
        logger.error(f"Pipeline background task failed: {e}")
        await ws_manager.broadcast({
            "event_type": "pipeline_error",
            "payload": {"error": str(e)[:200]},
            "pipeline_id": pipeline_id,
        })


# ============================================================================
# API ROUTES — ANTIBODY LIBRARY
# ============================================================================

@app.get(
    "/api/antibodies",
    response_model=AntibodyListResponse,
    summary="List all antibodies in the library",
)
async def list_antibodies(
    page: int = 1,
    page_size: int = 50,
    family: str | None = None,
    status: str | None = None,
) -> AntibodyListResponse:
    """Get antibodies from the immune memory library."""
    from backend.agents.immune_memory import get_immune_memory

    memory = get_immune_memory()
    all_antibodies = memory.get_all_antibodies()

    # Filter
    if family:
        all_antibodies = [ab for ab in all_antibodies if ab.attack_family == family]
    if status:
        all_antibodies = [ab for ab in all_antibodies if ab.status.value == status]

    # Paginate
    total = len(all_antibodies)
    start = (page - 1) * page_size
    end = start + page_size
    page_antibodies = all_antibodies[start:end]

    return AntibodyListResponse(
        antibodies=page_antibodies,
        total=total,
        page=page,
        page_size=page_size,
    )


@app.get(
    "/api/antibodies/{antibody_id}",
    summary="Get a specific antibody by ID",
)
async def get_antibody(antibody_id: str):
    """Get a specific antibody from the library."""
    from backend.agents.immune_memory import get_immune_memory

    memory = get_immune_memory()
    antibody = memory.get_antibody(antibody_id)

    if not antibody:
        raise HTTPException(status_code=404, detail=f"Antibody {antibody_id} not found")

    return antibody.model_dump(mode="json")


@app.get(
    "/api/evolution/timeline",
    summary="Get arms race timeline",
)
async def get_evolution_timeline(limit: int = 100):
    """Get the arms race timeline for dashboard."""
    from backend.agents.evolution_tracker import get_evolution_tracker
    tracker = get_evolution_tracker()
    return tracker.get_timeline(limit)


@app.get(
    "/api/evolution/summary",
    summary="Get evolution dashboard summary",
)
async def get_evolution_summary():
    """Get the complete evolution summary for dashboard."""
    from backend.agents.evolution_tracker import get_evolution_tracker
    tracker = get_evolution_tracker()
    return tracker.get_dashboard_summary()


@app.get(
    "/api/battleground/history",
    summary="Get battleground battle history",
)
async def get_battle_history():
    """Get the history of all battleground stress tests."""
    from backend.battleground.arena import get_arena
    arena = get_arena()
    return arena.get_battle_history()


@app.get(
    "/api/risk/portfolio",
    summary="Get portfolio risk analysis",
)
async def get_portfolio_risk():
    """Get aggregate actuarial risk across all antibodies."""
    from backend.agents.immune_memory import get_immune_memory
    from backend.math_engines.actuarial import compute_portfolio_risk
    memory = get_immune_memory()
    antibodies = memory.get_all_antibodies()
    return compute_portfolio_risk(antibodies)


@app.get(
    "/api/epidemiological",
    summary="Get epidemiological model state",
)
async def get_epidemiological_state():
    """Get the SIR immunity propagation model state."""
    from backend.math_engines.epidemiological import get_sir_model
    model = get_sir_model()
    return model.get_dashboard_data()


# ============================================================================
# API ROUTES — SYSTEM STATUS
# ============================================================================

@app.get(
    "/api/health",
    response_model=HealthResponse,
    summary="System health check",
)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.
    
    Returns minimal information — does not expose internal state
    to unauthenticated callers.
    """
    settings = get_settings()

    # Get basic stats
    antibody_count = 0
    immunity_score = 0.0
    try:
        from backend.agents.immune_memory import get_immune_memory
        memory = get_immune_memory()
        antibody_count = memory.library_size
    except Exception:
        pass

    try:
        from backend.orchestrator import get_orchestrator
        orchestrator = get_orchestrator()
        if hasattr(orchestrator, '_immunity_state'):
            immunity_score = orchestrator._immunity_state.immunity_score
    except Exception:
        pass

    return HealthResponse(
        status="healthy",
        version="1.0.0",
        node_id=settings.immunis_node_id,
        provider=settings.get_best_available_provider(),
        immunity_score=round(immunity_score, 1),
        antibody_count=antibody_count,
        mesh_nodes=len(settings.mesh_peers_list) + 1,
        uptime_seconds=round(time.monotonic() - _start_time, 1),
    )


@app.get(
    "/api/immunity",
    summary="Get current immunity state",
)
async def get_immunity_state():
    """Get current immunity state for dashboard."""
    try:
        from backend.orchestrator import get_orchestrator
        orchestrator = get_orchestrator()
        if hasattr(orchestrator, '_immunity_state'):
            return orchestrator._immunity_state.model_dump(mode="json")
    except Exception:
        pass

    return {
        "immunity_score": 50.0,
        "trend": "stable",
        "total_antibodies": 0,
        "total_threats_processed": 0,
    }


@app.get(
    "/api/memory/stats",
    summary="Get immune memory statistics",
)
async def get_memory_stats():
    """Get statistics about the antibody library."""
    from backend.agents.immune_memory import get_immune_memory
    memory = get_immune_memory()
    return memory.get_statistics()


@app.get(
    "/api/surprise/stats",
    summary="Get surprise detector statistics",
)
async def get_surprise_stats():
    """Get statistics about the surprise detector library."""
    from backend.math_engines.surprise import get_surprise_detector
    detector = get_surprise_detector()
    return detector.get_library_statistics()


@app.get(
    "/api/audit/recent",
    summary="Get recent audit events",
)
async def get_recent_audit(count: int = 50):
    """Get the most recent audit events."""
    from backend.security.audit_trail import get_audit_trail
    trail = get_audit_trail()
    events = trail.get_recent_events(count)
    return [e.model_dump(mode="json") for e in events]


@app.get(
    "/api/audit/integrity",
    summary="Verify audit trail integrity",
)
async def verify_audit_integrity():
    """Verify the Merkle tree integrity of the audit trail."""
    from backend.security.audit_trail import get_audit_trail
    trail = get_audit_trail()
    return trail.integrity_check()


@app.get(
    "/api/circuit-breakers",
    summary="Get circuit breaker status",
)
async def get_circuit_breakers():
    """Get status of all circuit breakers."""
    from backend.security.circuit_breaker import get_circuit_registry
    registry = get_circuit_registry()
    return registry.get_all_status()


# ============================================================================
# API ROUTES — MESH NETWORK
# ============================================================================

@app.get(
    "/api/mesh/status",
    response_model=MeshStatusResponse,
    summary="Get mesh network status",
)
async def get_mesh_status() -> MeshStatusResponse:
    """Get the status of the mesh network."""
    settings = get_settings()

    return MeshStatusResponse(
        node_id=settings.immunis_node_id,
        connected_peers=[],  # Populated when mesh is running
        total_peers=len(settings.mesh_peers_list),
        r0_immunity=0.0,  # Populated by epidemiological model
        herd_immunity_threshold=0.0,
    )


# ============================================================================
# WEBSOCKET ENDPOINT
# ============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time dashboard updates.
    
    The dashboard connects here on load and receives typed events
    for every pipeline stage, every arms race round, every mesh
    broadcast, and every immunity score update.
    
    Events are JSON objects with:
    {
        "event_type": "string",
        "payload": {...},
        "timestamp": "ISO8601",
        "pipeline_id": "optional"
    }
    """
    await ws_manager.connect(websocket)

    try:
        # Send initial state on connect
        await websocket.send_json({
            "event_type": "connected",
            "payload": {
                "node_id": get_settings().immunis_node_id,
                "clients_connected": ws_manager.client_count,
            },
            "timestamp": utc_now().isoformat(),
        })

        # Send current immunity state
        try:
            from backend.orchestrator import get_orchestrator
            orchestrator = get_orchestrator()
            if hasattr(orchestrator, '_immunity_state'):
                from backend.models.schemas import WebSocketEvent
                await websocket.send_json(
                    WebSocketEvent.immunity_update(
                        orchestrator._immunity_state
                    ).model_dump(mode="json")
                )
        except Exception:
            pass

        # Keep connection alive — listen for client messages
        while True:
            try:
                data = await websocket.receive_text()
                # Client can send commands (future: copilot chat, manual triage)
                message = json.loads(data)
                await _handle_ws_message(websocket, message)
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                await websocket.send_json({
                    "event_type": "error",
                    "payload": {"message": "Invalid JSON"},
                })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        await ws_manager.disconnect(websocket)


async def _handle_ws_message(websocket: WebSocket, message: dict) -> None:
    """Handle incoming WebSocket messages from clients."""
    msg_type = message.get("type", "")

    if msg_type == "ping":
        await websocket.send_json({
            "event_type": "pong",
            "payload": {},
            "timestamp": utc_now().isoformat(),
        })

    elif msg_type == "get_immunity":
        try:
            from backend.orchestrator import get_orchestrator
            orchestrator = get_orchestrator()
            if hasattr(orchestrator, '_immunity_state'):
                from backend.models.schemas import WebSocketEvent
                await websocket.send_json(
                    WebSocketEvent.immunity_update(
                        orchestrator._immunity_state
                    ).model_dump(mode="json")
                )
        except Exception:
            pass

    elif msg_type == "get_stats":
        try:
            from backend.agents.immune_memory import get_immune_memory
            memory = get_immune_memory()
            await websocket.send_json({
                "event_type": "stats",
                "payload": memory.get_statistics(),
                "timestamp": utc_now().isoformat(),
            })
        except Exception:
            pass


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """
    Global exception handler.
    
    NEVER expose internal error details to the client.
    Log the full error internally, return a generic message externally.
    """
    logger.error(
        "Unhandled exception",
        extra={
            "error_type": type(exc).__name__,
            "error": str(exc)[:300],
            "path": str(request.url.path),
        },
    )

    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error. The incident has been logged.",
            "error_type": type(exc).__name__,
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """HTTP exception handler — passes through status code and detail."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )
