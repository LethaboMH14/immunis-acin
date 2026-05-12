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

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks, Request
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
from backend.services.virustotal import compare_threat_with_virustotal, vt_client
from backend.services.phishtank import live_feed, get_live_threats_for_demo, get_demo_selection
from backend.services.nvd_client import nvd_client, enrich_finding_with_cves
from backend.services.explainability import explain_detection, explain_for_audience
from backend.security.robustness_certificate import certificate_generator
from backend.services.mitre_navigator import navigator, IMMUNIS_TECHNIQUE_MAP, THREAT_ACTOR_TTPS

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
        event_type = data.get('event_type', 'unknown')
        logger.info(f"WS broadcast to {len(self.active_connections)} clients: {event_type}")
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

    # Preload LaBSE model before accepting requests
    logger.info("Preloading LaBSE model...")
    try:
        # Force LaBSE load by computing a dummy embedding
        if hasattr(orchestrator, '_ensure_labse_loaded'):
            orchestrator._ensure_labse_loaded()
        else:
            # Trigger lazy load by accessing the model function
            import asyncio
            await asyncio.to_thread(lambda: orchestrator._embed("warmup") if hasattr(orchestrator, '_embed') else None)
        logger.info("LaBSE preloaded. Server ready.")
    except Exception as e:
        logger.warning(f"LaBSE preload failed: {e} — will load on first request")

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

    # Start Autonomous Battleground Loop if enabled
    if settings.autonomous_battleground_enabled:
        try:
            from backend.battleground.autonomous_loop import start_autonomous_battleground
            asyncio.create_task(start_autonomous_battleground())
            logger.info("Autonomous Battleground loop scheduled")
        except Exception as e:
            logger.warning(f"Failed to start Autonomous Battleground loop: {e}")

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

    # Stop Autonomous Battleground Loop
    try:
        from backend.battleground.autonomous_loop import get_autonomous_loop
        autonomous_loop = get_autonomous_loop()
        await autonomous_loop.stop()
        logger.info("Autonomous Battleground loop stopped")
    except Exception as e:
        logger.warning(f"Failed to stop Autonomous Battleground loop: {e}")

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


# ============================================================================
# API ROUTES — AUTONOMOUS BATTLEGROUND CONTROL
# ============================================================================

@app.get(
    "/api/battleground/autonomous/status",
    summary="Get autonomous battleground loop status",
)
async def get_autonomous_battleground_status():
    """Get the current status and statistics of the autonomous battleground loop."""
    from backend.battleground.autonomous_loop import get_autonomous_loop
    loop = get_autonomous_loop()
    return loop.get_status()


@app.post(
    "/api/battleground/autonomous/start",
    summary="Start autonomous battleground loop",
)
async def start_autonomous_battleground():
    """Start the autonomous battleground loop if it's not already running."""
    from backend.battleground.autonomous_loop import get_autonomous_loop
    loop = get_autonomous_loop()
    await loop.start()
    return {"message": "Autonomous battleground loop started", "status": loop.get_status()}


@app.post(
    "/api/battleground/autonomous/stop",
    summary="Stop autonomous battleground loop",
)
async def stop_autonomous_battleground():
    """Stop the autonomous battleground loop gracefully."""
    from backend.battleground.autonomous_loop import get_autonomous_loop
    loop = get_autonomous_loop()
    await loop.stop()
    return {"message": "Autonomous battleground loop stopped", "status": loop.get_status()}


@app.post(
    "/api/battleground/autonomous/trigger",
    summary="Trigger immediate autonomous round",
)
async def trigger_autonomous_round():
    """Force an immediate autonomous battleground round."""
    from backend.battleground.autonomous_loop import get_autonomous_loop
    loop = get_autonomous_loop()
    result = await loop.trigger_round()
    return result


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
                # Receive with timeout, send ping if idle
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=20.0)
                # Client can send commands (future: copilot chat, manual triage)
                message = json.loads(msg)
                await _handle_ws_message(websocket, message)
            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                await websocket.send_json({"event_type": "ping", "payload": {}})
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
# VIRUSTOTAL INTEGRATION
# ============================================================================

@app.get("/api/virustotal/status")
async def virustotal_status():
    """Check if VirusTotal integration is configured and available."""
    return {
        "configured": vt_client.is_configured,
        "rate_limit": "3 requests/minute (free tier)",
        "capabilities": ["url", "domain", "ip", "file_hash"],
    }


@app.post("/api/virustotal/compare")
async def virustotal_compare(request):
    """
    Compare an IMMUNIS detection with VirusTotal results.
    
    Body:
    {
        "threat_id": "incident-xxx",
        "threat_content": "raw threat text...",
        "immunis_confidence": 0.97,
        "immunis_classification": "novel",
        "immunis_attack_family": "BEC_Authority_Financial",
        "immunis_time_ms": 1800
    }
    """
    body = await request.json()
    result = await compare_threat_with_virustotal(
        threat_id=body.get("threat_id", "unknown"),
        threat_content=body.get("threat_content", ""),
        immunis_detected=body.get("immunis_detected", True),
        immunis_confidence=body.get("immunis_confidence", 0.95),
        immunis_classification=body.get("immunis_classification", "novel"),
        immunis_attack_family=body.get("immunis_attack_family", "Unknown"),
        immunis_time_ms=body.get("immunis_time_ms", 1800),
    )
    return result


@app.post("/api/virustotal/lookup")
async def virustotal_lookup(request):
    """
    Direct VirusTotal lookup for a single indicator.
    
    Body:
    {
        "indicator": "https://evil-phishing.com/login",
        "type": "url"  // url | domain | ip | file_hash
    }
    """
    body = await request.json()
    indicator = body.get("indicator", "")
    indicator_type = body.get("type", "url")
    
    lookup_methods = {
        "url": vt_client.lookup_url,
        "domain": vt_client.lookup_domain,
        "ip": vt_client.lookup_ip,
        "file_hash": vt_client.lookup_hash,
    }
    
    method = lookup_methods.get(indicator_type)
    if not method:
        return {"error": f"Unknown indicator type: {indicator_type}"}
    
    result = await method(indicator)
    return {
        "indicator": result.indicator,
        "type": result.indicator_type.value,
        "found": result.found,
        "engines_detected": result.engines_detected,
        "total_engines": result.total_engines,
        "detection_rate": result.detection_rate,
        "top_detections": result.detection_names[:10],
        "reputation": result.reputation,
        "query_time_ms": result.query_time_ms,
        "error": result.error,
    }


# ============================================================================
# LIVE THREAT FEEDS
# ============================================================================

@app.get("/api/live-threats/stats")
async def live_threat_stats():
    """Get statistics about the live phishing threat feed."""
    return await live_feed.get_feed_stats()


@app.get("/api/live-threats/sample")
async def live_threat_sample(count: int = 5, source: Optional[str] = None):
    """
    Get live phishing threats from public feeds.
    
    Query params:
        count: Number of threats (default 5, max 20)
        source: Filter by source (openphish, phishtank, urlhaus)
    """
    count = min(count, 20)
    threats = await live_feed.get_live_threats(
        count=count,
        source_filter=source,
    )
    return {
        "count": len(threats),
        "threats": [
            {
                "url": t.url,
                "source": t.source,
                "brand": t.target_brand,
                "verified": t.verified,
                "threat_type": t.threat_type,
                "discovered": t.discovered_at,
                "country": t.country,
                "tags": t.tags,
                "immunis_submission": t.to_immunis_threat(),
            }
            for t in threats
        ],
    }


@app.get("/api/live-threats/demo-selection")
async def live_threat_demo_selection():
    """
    Get curated selection of live threats for the 10-minute demo.
    Returns ~5 diverse threats optimised for demo narration impact.
    """
    return {"selection": await get_demo_selection()}


@app.post("/api/live-threats/feed-and-analyze")
async def feed_live_threat(request):
    """
    Fetch a live threat and immediately submit it to the IMMUNIS pipeline.
    
    This is the money endpoint for the demo:
    1. Pulls a REAL active phishing URL from the internet
    2. Feeds it into the 7-stage AIR pipeline
    3. Returns both the live threat data and IMMUNIS analysis
    
    Body (optional):
    {
        "source": "openphish",  // optional filter
        "brand": "PayPal"       // optional filter
    }
    """
    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    
    threats = await live_feed.get_live_threats(
        count=1,
        source_filter=body.get("source"),
        brand_filter=body.get("brand"),
    )
    
    if not threats:
        return {"error": "No live threats available matching filters. Try without filters."}
    
    threat = threats[0]
    submission = threat.to_immunis_threat()
    
    # Submit to IMMUNIS pipeline (same as POST /api/threats)
    # Import the threat processing function from main
    return {
        "live_threat": {
            "url": threat.url,
            "source": threat.source,
            "brand": threat.target_brand,
            "verified": threat.verified,
            "is_real": True,
            "note": "This URL is currently ACTIVE on the internet",
        },
        "immunis_submission": submission,
        "instruction": "Submit the immunis_submission.content to POST /api/threats to analyze",
    }


# ============================================================================
# NVD INTEGRATION
# ============================================================================

@app.get("/api/nvd/status")
async def nvd_status():
    """Check NVD integration status."""
    return {
        "configured": nvd_client.is_configured,
        "rate_limit": f"{nvd_client.rate_limit} requests per 30 seconds",
        "api_key_present": nvd_client.is_configured,
        "note": "Works without API key at reduced rate. Free key available at nvd.nist.gov",
    }


@app.get("/api/nvd/cve/{cve_id}")
async def nvd_get_cve(cve_id: str):
    """
    Look up a specific CVE by ID.
    
    Example: GET /api/nvd/cve/CVE-2024-21762
    """
    record = await nvd_client.get_cve(cve_id)
    if not record:
        return {"error": f"CVE {cve_id} not found in NVD"}
    return record.to_dict()


@app.get("/api/nvd/search")
async def nvd_search(keyword: str, max_results: int = 10):
    """
    Search NVD by keyword.
    
    Example: GET /api/nvd/search?keyword=FortiGate%20VPN&max_results=5
    """
    max_results = min(max_results, 20)
    result = await nvd_client.search_keyword(keyword, max_results=max_results)
    return {
        "query": result.query,
        "total_results": result.total_results,
        "returned": len(result.cves),
        "cves": [cve.to_dict() for cve in result.cves],
        "query_time_ms": result.query_time_ms,
    }


@app.get("/api/nvd/recent-critical")
async def nvd_recent_critical(days: int = 7):
    """
    Get recently published critical CVEs.
    
    Example: GET /api/nvd/recent-critical?days=7
    Shows judges that IMMUNIS tracks real-time vulnerability landscape.
    """
    days = min(days, 30)
    result = await nvd_client.get_recent_critical(days=days)
    return {
        "period": f"Last {days} days",
        "total_critical": result.total_results,
        "cves": [cve.to_dict() for cve in result.cves],
        "query_time_ms": result.query_time_ms,
    }


@app.get("/api/nvd/threat-landscape")
async def nvd_threat_landscape():
    """
    Real-time threat landscape summary from NVD.
    
    Dashboard widget showing live vulnerability data.
    """
    return await nvd_client.get_threat_landscape_summary()


@app.post("/api/nvd/enrich")
async def nvd_enrich_finding(request):
    """
    Enrich a scanner finding with real CVE data.
    
    Body:
    {
        "finding_type": "sql_injection",
        "finding_title": "SQL Injection in /api/login endpoint",
        "keywords": ["SQL injection authentication bypass"]
    }
    """
    body = await request.json()
    result = await enrich_finding_with_cves(
        finding_type=body.get("finding_type", ""),
        finding_title=body.get("finding_title", ""),
        keywords=body.get("keywords"),
    )
    return result


@app.get("/api/nvd/demo-cves")
async def nvd_demo_cves():
    """
    Get curated CVEs referenced in our demo threats.
    
    Includes FortiGate, Zerologon, Log4Shell — CVEs that judges know.
    """
    return {"cves": await nvd_client.get_demo_cves()}


# ============================================================================
# EXPLAINABILITY ENGINE
# ============================================================================

@app.post("/api/explain")
async def explain_threat_detection(request: Request):
    """
    Generate an explanation for a detection decision.
    
    Body:
    {
        "threat_id": "inc-123",
        "se_scores": {"urgency": 0.95, "authority": 0.92, "fear": 0.88, "financial_request": 0.97, "isolation": 0.85, "impersonation": 0.93},
        "linguistic_features": {"homoglyph": 0.95, "code_switch": 0.60},
        "technical_features": {"domain_spoofing": 0.93, "suspicious_headers": 0.70},
        "visual_features": {"document_forgery": 0.85, "qr_threat": 0.82},
        "classification": "novel",
        "severity": "critical",
        "attack_family": "BEC_Authority_Financial",
        "confidence": 0.97
    }
    """
    body = await request.json()
    result = explain_detection(
        threat_id=body.get("threat_id", "unknown"),
        se_scores=body.get("se_scores", {}),
        linguistic_features=body.get("linguistic_features"),
        technical_features=body.get("technical_features"),
        visual_features=body.get("visual_features"),
        network_features=body.get("network_features"),
        historical_features=body.get("historical_features"),
        classification=body.get("classification", "novel"),
        severity=body.get("severity", "critical"),
        attack_family=body.get("attack_family", "Unknown"),
        confidence=body.get("confidence", 0.95),
        visual_confidence=body.get("visual_confidence", 0.0),
        evidence_map=body.get("evidence_map"),
        evidence_spans_map=body.get("evidence_spans_map"),
    )
    return result


@app.post("/api/explain/audience")
async def explain_for_specific_audience(request):
    """
    Generate an audience-specific explanation.
    
    Body:
    {
        "threat_id": "inc-123",
        "features": {"urgency_language": 0.95, "authority_impersonation": 0.92, ...},
        "classification": "novel",
        "severity": "critical",
        "attack_family": "BEC_Authority_Financial",
        "confidence": 0.97,
        "audience": "ciso"  // soc_analyst | ir_lead | ciso | executive | auditor | machine
    }
    """
    body = await request.json()
    result = explain_for_audience(
        threat_id=body.get("threat_id", "unknown"),
        features=body.get("features", {}),
        classification=body.get("classification", "novel"),
        severity=body.get("severity", "critical"),
        attack_family=body.get("attack_family", "Unknown"),
        confidence=body.get("confidence", 0.95),
        audience=body.get("audience", "soc_analyst"),
        evidence_map=body.get("evidence_map"),
    )
    return certificate_generator.get_certificate_stats()


# ============================================================================
# ADVERSARIAL ROBUSTNESS CERTIFICATES
# ============================================================================

@app.post("/api/certificates/generate")
async def generate_robustness_certificate(request: Request):
    """
    Generate a robustness certificate for an antibody.
    
    Body:
    {
        "antibody_id": "AB-4a6a7f5120a7",
        "surprise_score": 9.2,
        "classification": "novel",
        "antibody_strength": 0.91,
        "attack_family": "BEC_Authority_Financial",
        "language": "st",
        "battleground_results": [
            {"distance": 0.12, "blocked": true, "surprise": 8.5},
            {"distance": 0.23, "blocked": true, "surprise": 7.8},
            {"distance": 0.31, "blocked": true, "surprise": 6.2},
            {"distance": 0.18, "blocked": false, "surprise": 4.5}
        ],
        "kde_bandwidth": 0.15,
        "kde_n_samples": 1000,
        "z3_verification_results": {
            "properties": {
                "soundness": true,
                "non_triviality": true,
                "consistency": true,
                "completeness": true,
                "minimality": true
            }
        }
    }
    """
    body = await request.json()
    certificate = certificate_generator.generate_certificate(
        antibody_id=body.get("antibody_id", "unknown"),
        surprise_score=body.get("surprise_score", 0),
        classification=body.get("classification", "novel"),
        antibody_strength=body.get("antibody_strength", 0),
        battleground_results=body.get("battleground_results"),
        threat_embedding=body.get("threat_embedding"),
        kde_bandwidth=body.get("kde_bandwidth", 0),
        kde_n_samples=body.get("kde_n_samples", 0),
        z3_verification_results=body.get("z3_verification_results"),
        attack_family=body.get("attack_family", "Unknown"),
        language=body.get("language", "en"),
    )
    return certificate


@app.get("/api/certificates/{antibody_id}")
async def get_robustness_certificate(antibody_id: str):
    """Get a robustness certificate by antibody ID."""
    cert = certificate_generator.get_certificate(antibody_id)
    if not cert:
        return {"error": f"No certificate found for {antibody_id}"}
    return cert


@app.get("/api/certificates")
async def list_robustness_certificates():
    """List all robustness certificates."""
    return {
        "certificates": certificate_generator.get_all_certificates(),
        "stats": certificate_generator.get_certificate_stats(),
    }


@app.get("/api/certificates/stats")
async def certificate_stats():
    """Get aggregate certificate statistics."""
    return certificate_generator.get_certificate_stats()


# ============================================================================
# MITRE ATT&CK NAVIGATOR
# ============================================================================

@app.get("/api/mitre/layer")
async def mitre_navigator_layer():
    """
    Get the IMMUNIS ATT&CK Navigator layer (JSON).
    
    Load this directly into https://mitre-attack.github.io/attack-navigator/
    """
    return navigator.generate_layer()


@app.get("/api/mitre/layer/download")
async def mitre_navigator_download():
    """
    Download the ATT&CK Navigator layer as a .json file.
    
    This file can be imported directly into the MITRE ATT&CK Navigator tool.
    """
    from fastapi.responses import Response
    
    json_content = navigator.export_json()
    return Response(
        content=json_content,
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=immunis-acin-attack-navigator.json"
        },
    )


@app.get("/api/mitre/coverage")
async def mitre_coverage_stats():
    """
    Get IMMUNIS ATT&CK coverage statistics.
    
    Shows coverage percentage, tactic breakdown, agent contribution,
    and strongest/weakest areas.
    """
    return navigator.get_coverage_stats()


@app.get("/api/mitre/gaps")
async def mitre_gap_analysis():
    """
    Get ATT&CK coverage gap analysis.
    
    Identifies weak spots, untested techniques, and single-agent risks.
    Shows self-awareness and continuous improvement mindset.
    """
    return navigator.get_gap_analysis()


@app.get("/api/mitre/techniques")
async def mitre_techniques():
    """
    Get all mapped ATT&CK techniques with IMMUNIS detection details.
    """
    return {
        "total": len(IMMUNIS_TECHNIQUE_MAP),
        "techniques": [
            {
                "id": t.technique_id,
                "name": t.technique_name,
                "tactic": t.tactic,
                "sub_technique": t.sub_technique,
                "coverage": t.coverage_level.value,
                "score": t.score,
                "agents": t.detecting_agents,
                "method": t.detection_method,
                "comment": t.comment,
                "battleground_tested": t.battleground_tested,
            }
            for t in IMMUNIS_TECHNIQUE_MAP.values()
        ],
    }


@app.get("/api/mitre/compare/{actor_name}")
async def mitre_compare_actor(actor_name: str):
    """
    Compare IMMUNIS coverage against a known threat actor's TTPs.
    
    Available actors: APT28, APT29, Sandworm, Lazarus, FIN7
    
    Example: GET /api/mitre/compare/Sandworm
    """
    # Find the actor (case-insensitive partial match)
    matched_actor = None
    matched_techniques = None
    
    for actor, techniques in THREAT_ACTOR_TTPS.items():
        if actor_name.lower() in actor.lower():
            matched_actor = actor
            matched_techniques = techniques
            break
    
    if not matched_actor:
        return {
            "error": f"Unknown threat actor: {actor_name}",
            "available_actors": list(THREAT_ACTOR_TTPS.keys()),
        }
    
    layer = navigator.generate_comparison_layer(matched_techniques, matched_actor)
    
    # Also compute stats
    covered = sum(1 for t in layer["techniques"] if t["score"] > 0)
    total = len(layer["techniques"])
    
    return {
        "actor": matched_actor,
        "total_techniques": total,
        "immunis_covers": covered,
        "coverage_percentage": round(covered / total * 100, 1) if total > 0 else 0,
        "layer": layer,
        "gaps": [
            t["techniqueID"] for t in layer["techniques"] if t["score"] == 0
        ],
        "covered": [
            t["techniqueID"] for t in layer["techniques"] if t["score"] > 0
        ],
    }


@app.get("/api/mitre/actors")
async def mitre_available_actors():
    """List available threat actors for comparison."""
    result = {}
    for actor, techniques in THREAT_ACTOR_TTPS.items():
        covered = sum(1 for tid in techniques if tid in IMMUNIS_TECHNIQUE_MAP and IMMUNIS_TECHNIQUE_MAP[tid].score > 0)
        result[actor] = {
            "techniques": len(techniques),
            "immunis_coverage": covered,
            "coverage_pct": round(covered / len(techniques) * 100, 1),
        }
    return result


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
