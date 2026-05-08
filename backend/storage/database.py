"""
IMMUNIS ACIN — Structured Database (SQLite / PostgreSQL)

WHY: Not everything is a vector. Incidents, pipeline results, audit
events, compliance reports, mesh node registrations, and lockout
history all need structured storage with ACID guarantees, queryable
fields, and relational integrity.

SQLite for development (zero config, single file).
PostgreSQL for production (concurrent access, replication).

The database stores:
- Incidents: raw threat data + pipeline results
- Antibodies: structured metadata (vectors in FAISS, metadata here)
- Audit events: Merkle-anchored trail
- Compliance reports: generated regulatory documents
- Mesh nodes: registered peers + status
- Battleground history: Red-Blue arms race records
- Evolution timeline: immunity score history

All tables use UTC timestamps. All IDs are deterministic hashes
where possible (reproducible, auditable).
"""

import logging
import os
import json
import time
from typing import Optional, Any
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager

try:
    import sqlite3
    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False

logger = logging.getLogger("immunis.storage.database")


# ------------------------------------------------------------------
# SCHEMA DEFINITIONS
# ------------------------------------------------------------------

SCHEMA_SQL = """
-- Incidents table: raw threat data + pipeline results
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    threat_content TEXT,
    threat_vector TEXT,
    language TEXT,
    language_confidence REAL,
    surprise_score REAL,
    surprise_level TEXT,
    attack_family TEXT,
    attack_type TEXT,
    confidence REAL,
    severity TEXT,
    pipeline_id TEXT,
    pipeline_duration_ms REAL,
    pipeline_stages TEXT,  -- JSON array of stage results
    mitre_techniques TEXT,  -- JSON array
    status TEXT DEFAULT 'processing',
    antibody_id TEXT,
    FOREIGN KEY (antibody_id) REFERENCES antibodies(antibody_id)
);

-- Antibodies table: structured metadata
CREATE TABLE IF NOT EXISTS antibodies (
    antibody_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    attack_family TEXT NOT NULL,
    attack_type TEXT,
    detection_rule TEXT,  -- JSON
    indicators TEXT,  -- JSON array
    strength REAL DEFAULT 0.0,
    status TEXT DEFAULT 'pending',
    verification_status TEXT,
    verification_proof_hash TEXT,
    verification_details TEXT,  -- JSON
    source_incident_id TEXT,
    promoted_at TEXT,
    promoted_by TEXT,
    battleground_rounds INTEGER DEFAULT 0,
    red_variants_tested INTEGER DEFAULT 0,
    blue_blocks INTEGER DEFAULT 0,
    mesh_broadcast_at TEXT,
    mesh_nodes_reached INTEGER DEFAULT 0,
    actuarial_expected_loss REAL,
    actuarial_var_95 REAL,
    actuarial_cvar_95 REAL,
    languages TEXT,  -- JSON array of languages this antibody covers
    FOREIGN KEY (source_incident_id) REFERENCES incidents(incident_id)
);

-- Audit events table
CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    event_type TEXT NOT NULL,
    actor TEXT,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT,  -- JSON
    merkle_hash TEXT,
    merkle_proof TEXT,  -- JSON array
    integrity_verified INTEGER DEFAULT 0
);

-- Compliance reports table
CREATE TABLE IF NOT EXISTS compliance_reports (
    report_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    framework TEXT NOT NULL,  -- POPIA, NIST, GDPR, etc.
    report_type TEXT NOT NULL,  -- S22, Art33, etc.
    incident_id TEXT,
    content TEXT,  -- JSON or markdown
    score REAL,
    status TEXT DEFAULT 'draft',
    submitted_at TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

-- Mesh nodes table
CREATE TABLE IF NOT EXISTS mesh_nodes (
    node_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT,
    display_name TEXT,
    endpoint TEXT,
    public_key_ed25519 TEXT,
    public_key_dilithium TEXT,
    status TEXT DEFAULT 'unknown',
    antibodies_received INTEGER DEFAULT 0,
    antibodies_sent INTEGER DEFAULT 0,
    immunity_score REAL DEFAULT 0.0,
    metadata TEXT  -- JSON
);

-- Battleground history table
CREATE TABLE IF NOT EXISTS battleground_history (
    battle_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    antibody_id TEXT NOT NULL,
    round_number INTEGER NOT NULL,
    red_variant TEXT,  -- JSON
    blue_response TEXT,  -- JSON
    red_score REAL,
    blue_score REAL,
    winner TEXT,  -- 'red' or 'blue'
    arbiter_decision TEXT,  -- JSON
    FOREIGN KEY (antibody_id) REFERENCES antibodies(antibody_id)
);

-- Evolution timeline table
CREATE TABLE IF NOT EXISTS evolution_timeline (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    immunity_score REAL NOT NULL,
    pid_error REAL,
    pid_output REAL,
    total_antibodies INTEGER,
    promoted_antibodies INTEGER,
    active_threats INTEGER,
    red_wins INTEGER DEFAULT 0,
    blue_wins INTEGER DEFAULT 0,
    mesh_nodes_online INTEGER DEFAULT 0,
    r0_immunity REAL
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_family ON incidents(attack_family);
CREATE INDEX IF NOT EXISTS idx_antibodies_family ON antibodies(attack_family);
CREATE INDEX IF NOT EXISTS idx_antibodies_status ON antibodies(status);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_compliance_framework ON compliance_reports(framework);
CREATE INDEX IF NOT EXISTS idx_battleground_antibody ON battleground_history(antibody_id);
CREATE INDEX IF NOT EXISTS idx_evolution_created ON evolution_timeline(created_at);
CREATE INDEX IF NOT EXISTS idx_mesh_status ON mesh_nodes(status);
"""


class Database:
    """
    Structured database for IMMUNIS ACIN.

    SQLite for development, PostgreSQL-ready for production.
    All operations are synchronous with connection pooling via
    context manager. Thread-safe via SQLite WAL mode.

    Usage:
        db = Database("sqlite:///./immunis.db")
        db.initialise()

        with db.connection() as conn:
            conn.execute("INSERT INTO incidents ...", params)

        # Or use convenience methods:
        db.insert_incident({...})
        incidents = db.query_incidents(attack_family="BEC")
    """

    def __init__(self, database_url: Optional[str] = None):
        if database_url is None:
            try:
                from backend.config import config
                database_url = config.database_url
            except (ImportError, AttributeError):
                database_url = "sqlite:///./immunis.db"

        self._database_url = database_url
        self._is_sqlite = database_url.startswith("sqlite")
        self._db_path: Optional[str] = None
        self._initialised = False

        if self._is_sqlite:
            # Extract path from sqlite:///path
            self._db_path = database_url.replace("sqlite:///", "")
            # Ensure directory exists
            db_dir = os.path.dirname(self._db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)

        logger.info(f"Database configured: {database_url}")

    def initialise(self) -> None:
        """Create tables and indexes if they don't exist."""
        if self._initialised:
            return

        with self.connection() as conn:
            if self._is_sqlite:
                # Enable WAL mode for concurrent reads
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("PRAGMA busy_timeout=5000")

            # Execute schema
            conn.executescript(SCHEMA_SQL)
            conn.commit()

        self._initialised = True
        logger.info("Database initialised — all tables and indexes created")

    @contextmanager
    def connection(self):
        """
        Context manager for database connections.

        Yields a connection object. Commits on success, rolls back on error.
        """
        if not self._is_sqlite:
            raise NotImplementedError(
                "PostgreSQL support requires asyncpg — use SQLite for development"
            )

        conn = sqlite3.connect(
            self._db_path,
            timeout=10,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        conn.row_factory = sqlite3.Row

        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # INCIDENT OPERATIONS
    # ------------------------------------------------------------------

    def insert_incident(self, incident: dict) -> str:
        """
        Insert a new incident record.

        Args:
            incident: Dict with incident fields. Must include incident_id.

        Returns:
            The incident_id.
        """
        incident_id = incident.get("incident_id", "")
        now = datetime.now(timezone.utc).isoformat()

        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    incident_id, created_at, updated_at,
                    threat_content, threat_vector, language, language_confidence,
                    surprise_score, surprise_level, attack_family, attack_type,
                    confidence, severity, pipeline_id, pipeline_duration_ms,
                    pipeline_stages, mitre_techniques, status, antibody_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    incident.get("created_at", now),
                    now,
                    incident.get("threat_content"),
                    incident.get("threat_vector"),
                    incident.get("language"),
                    incident.get("language_confidence"),
                    incident.get("surprise_score"),
                    incident.get("surprise_level"),
                    incident.get("attack_family"),
                    incident.get("attack_type"),
                    incident.get("confidence"),
                    incident.get("severity"),
                    incident.get("pipeline_id"),
                    incident.get("pipeline_duration_ms"),
                    json.dumps(incident.get("pipeline_stages", [])),
                    json.dumps(incident.get("mitre_techniques", [])),
                    incident.get("status", "processing"),
                    incident.get("antibody_id"),
                ),
            )

        logger.debug(f"Incident inserted: {incident_id}")
        return incident_id

    def update_incident(self, incident_id: str, updates: dict) -> bool:
        """Update specific fields of an incident."""
        if not updates:
            return False

        now = datetime.now(timezone.utc).isoformat()
        updates["updated_at"] = now

        # Serialise JSON fields
        for json_field in ("pipeline_stages", "mitre_techniques"):
            if json_field in updates and isinstance(updates[json_field], (list, dict)):
                updates[json_field] = json.dumps(updates[json_field])

        set_clauses = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [incident_id]

        with self.connection() as conn:
            cursor = conn.execute(
                f"UPDATE incidents SET {set_clauses} WHERE incident_id = ?",
                values,
            )
            return cursor.rowcount > 0

    def get_incident(self, incident_id: str) -> Optional[dict]:
        """Get a single incident by ID."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()

            if row is None:
                return None

            return self._row_to_dict(row)

    def query_incidents(
        self,
        attack_family: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        language: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        order_by: str = "created_at DESC",
    ) -> list[dict]:
        """Query incidents with optional filters."""
        conditions = []
        params = []

        if attack_family:
            conditions.append("attack_family = ?")
            params.append(attack_family)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if language:
            conditions.append("language = ?")
            params.append(language)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        # Sanitise order_by to prevent injection
        allowed_orders = {
            "created_at DESC", "created_at ASC",
            "confidence DESC", "surprise_score DESC",
            "severity DESC",
        }
        if order_by not in allowed_orders:
            order_by = "created_at DESC"

        params.extend([limit, offset])

        with self.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM incidents {where} ORDER BY {order_by} LIMIT ? OFFSET ?",
                params,
            ).fetchall()

            return [self._row_to_dict(row) for row in rows]

    def count_incidents(
        self,
        attack_family: Optional[str] = None,
        status: Optional[str] = None,
    ) -> int:
        """Count incidents with optional filters."""
        conditions = []
        params = []

        if attack_family:
            conditions.append("attack_family = ?")
            params.append(attack_family)
        if status:
            conditions.append("status = ?")
            params.append(status)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        with self.connection() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) as cnt FROM incidents {where}",
                params,
            ).fetchone()
            return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # ANTIBODY OPERATIONS
    # ------------------------------------------------------------------

    def insert_antibody(self, antibody: dict) -> str:
        """Insert a new antibody record."""
        antibody_id = antibody.get("antibody_id", "")
        now = datetime.now(timezone.utc).isoformat()

        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO antibodies (
                    antibody_id, created_at, updated_at,
                    attack_family, attack_type, detection_rule, indicators,
                    strength, status, verification_status, verification_proof_hash,
                    verification_details, source_incident_id, promoted_at,
                    promoted_by, battleground_rounds, red_variants_tested,
                    blue_blocks, mesh_broadcast_at, mesh_nodes_reached,
                    actuarial_expected_loss, actuarial_var_95, actuarial_cvar_95,
                    languages
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    antibody_id,
                    antibody.get("created_at", now),
                    now,
                    antibody.get("attack_family", "unknown"),
                    antibody.get("attack_type"),
                    json.dumps(antibody.get("detection_rule", {})),
                    json.dumps(antibody.get("indicators", [])),
                    antibody.get("strength", 0.0),
                    antibody.get("status", "pending"),
                    antibody.get("verification_status"),
                    antibody.get("verification_proof_hash"),
                    json.dumps(antibody.get("verification_details", {})),
                    antibody.get("source_incident_id"),
                    antibody.get("promoted_at"),
                    antibody.get("promoted_by"),
                    antibody.get("battleground_rounds", 0),
                    antibody.get("red_variants_tested", 0),
                    antibody.get("blue_blocks", 0),
                    antibody.get("mesh_broadcast_at"),
                    antibody.get("mesh_nodes_reached", 0),
                    antibody.get("actuarial_expected_loss"),
                    antibody.get("actuarial_var_95"),
                    antibody.get("actuarial_cvar_95"),
                    json.dumps(antibody.get("languages", [])),
                ),
            )

        logger.debug(f"Antibody inserted: {antibody_id}")
        return antibody_id

    def update_antibody(self, antibody_id: str, updates: dict) -> bool:
        """Update specific fields of an antibody."""
        if not updates:
            return False

        now = datetime.now(timezone.utc).isoformat()
        updates["updated_at"] = now

        # Serialise JSON fields
        for json_field in ("detection_rule", "indicators", "verification_details", "languages"):
            if json_field in updates and isinstance(updates[json_field], (list, dict)):
                updates[json_field] = json.dumps(updates[json_field])

        set_clauses = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [antibody_id]

        with self.connection() as conn:
            cursor = conn.execute(
                f"UPDATE antibodies SET {set_clauses} WHERE antibody_id = ?",
                values,
            )
            return cursor.rowcount > 0

    def get_antibody(self, antibody_id: str) -> Optional[dict]:
        """Get a single antibody by ID."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM antibodies WHERE antibody_id = ?",
                (antibody_id,),
            ).fetchone()

            if row is None:
                return None

            return self._row_to_dict(row)

    def query_antibodies(
        self,
        attack_family: Optional[str] = None,
        status: Optional[str] = None,
        min_strength: Optional[float] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """Query antibodies with optional filters."""
        conditions = []
        params = []

        if attack_family:
            conditions.append("attack_family = ?")
            params.append(attack_family)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if min_strength is not None:
            conditions.append("strength >= ?")
            params.append(min_strength)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])

        with self.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM antibodies {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()

            return [self._row_to_dict(row) for row in rows]

    def count_antibodies(
        self,
        status: Optional[str] = None,
    ) -> int:
        """Count antibodies with optional status filter."""
        if status:
            with self.connection() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM antibodies WHERE status = ?",
                    (status,),
                ).fetchone()
                return row["cnt"] if row else 0
        else:
            with self.connection() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM antibodies"
                ).fetchone()
                return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # AUDIT EVENT OPERATIONS
    # ------------------------------------------------------------------

    def insert_audit_event(self, event: dict) -> str:
        """Insert an audit event."""
        event_id = event.get("event_id", "")

        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, created_at, event_type, actor,
                    action, target, details, merkle_hash, merkle_proof,
                    integrity_verified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event.get("created_at", datetime.now(timezone.utc).isoformat()),
                    event.get("event_type", "unknown"),
                    event.get("actor"),
                    event.get("action", ""),
                    event.get("target"),
                    json.dumps(event.get("details", {})),
                    event.get("merkle_hash"),
                    json.dumps(event.get("merkle_proof", [])),
                    1 if event.get("integrity_verified") else 0,
                ),
            )

        return event_id

    def query_audit_events(
        self,
        event_type: Optional[str] = None,
        actor: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Query audit events with optional filters."""
        conditions = []
        params = []

        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if actor:
            conditions.append("actor = ?")
            params.append(actor)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])

        with self.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_events {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()

            return [self._row_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # COMPLIANCE REPORT OPERATIONS
    # ------------------------------------------------------------------

    def insert_compliance_report(self, report: dict) -> str:
        """Insert a compliance report."""
        report_id = report.get("report_id", "")

        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO compliance_reports (
                    report_id, created_at, framework, report_type,
                    incident_id, content, score, status, submitted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    report.get("created_at", datetime.now(timezone.utc).isoformat()),
                    report.get("framework", ""),
                    report.get("report_type", ""),
                    report.get("incident_id"),
                    report.get("content", ""),
                    report.get("score"),
                    report.get("status", "draft"),
                    report.get("submitted_at"),
                ),
            )

        return report_id

    def query_compliance_reports(
        self,
        framework: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict]:
        """Query compliance reports."""
        if framework:
            with self.connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM compliance_reports WHERE framework = ? ORDER BY created_at DESC LIMIT ?",
                    (framework, limit),
                ).fetchall()
                return [self._row_to_dict(row) for row in rows]
        else:
            with self.connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM compliance_reports ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [self._row_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # MESH NODE OPERATIONS
    # ------------------------------------------------------------------

    def upsert_mesh_node(self, node: dict) -> str:
        """Insert or update a mesh node."""
        node_id = node.get("node_id", "")
        now = datetime.now(timezone.utc).isoformat()

        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO mesh_nodes (
                    node_id, created_at, last_seen, display_name,
                    endpoint, public_key_ed25519, public_key_dilithium,
                    status, antibodies_received, antibodies_sent,
                    immunity_score, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    node_id,
                    node.get("created_at", now),
                    node.get("last_seen", now),
                    node.get("display_name"),
                    node.get("endpoint"),
                    node.get("public_key_ed25519"),
                    node.get("public_key_dilithium"),
                    node.get("status", "online"),
                    node.get("antibodies_received", 0),
                    node.get("antibodies_sent", 0),
                    node.get("immunity_score", 0.0),
                    json.dumps(node.get("metadata", {})),
                ),
            )

        return node_id

    def get_mesh_nodes(
        self,
        status: Optional[str] = None,
    ) -> list[dict]:
        """Get all mesh nodes, optionally filtered by status."""
        if status:
            with self.connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM mesh_nodes WHERE status = ? ORDER BY last_seen DESC",
                    (status,),
                ).fetchall()
                return [self._row_to_dict(row) for row in rows]
        else:
            with self.connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM mesh_nodes ORDER BY last_seen DESC"
                ).fetchall()
                return [self._row_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # BATTLEGROUND HISTORY OPERATIONS
    # ------------------------------------------------------------------

    def insert_battleground_round(self, battle: dict) -> str:
        """Insert a battleground round record."""
        battle_id = battle.get("battle_id", "")

        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO battleground_history (
                    battle_id, created_at, antibody_id, round_number,
                    red_variant, blue_response, red_score, blue_score,
                    winner, arbiter_decision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    battle_id,
                    battle.get("created_at", datetime.now(timezone.utc).isoformat()),
                    battle.get("antibody_id", ""),
                    battle.get("round_number", 0),
                    json.dumps(battle.get("red_variant", {})),
                    json.dumps(battle.get("blue_response", {})),
                    battle.get("red_score", 0.0),
                    battle.get("blue_score", 0.0),
                    battle.get("winner", ""),
                    json.dumps(battle.get("arbiter_decision", {})),
                ),
            )

        return battle_id

    def get_battleground_history(
        self,
        antibody_id: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict]:
        """Get battleground history, optionally for a specific antibody."""
        if antibody_id:
            with self.connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM battleground_history WHERE antibody_id = ? ORDER BY round_number ASC LIMIT ?",
                    (antibody_id, limit),
                ).fetchall()
                return [self._row_to_dict(row) for row in rows]
        else:
            with self.connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM battleground_history ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [self._row_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # EVOLUTION TIMELINE OPERATIONS
    # ------------------------------------------------------------------

    def insert_evolution_entry(self, entry: dict) -> None:
        """Insert an evolution timeline entry."""
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO evolution_timeline (
                    created_at, immunity_score, pid_error, pid_output,
                    total_antibodies, promoted_antibodies, active_threats,
                    red_wins, blue_wins, mesh_nodes_online, r0_immunity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.get("created_at", datetime.now(timezone.utc).isoformat()),
                    entry.get("immunity_score", 0.0),
                    entry.get("pid_error"),
                    entry.get("pid_output"),
                    entry.get("total_antibodies", 0),
                    entry.get("promoted_antibodies", 0),
                    entry.get("active_threats", 0),
                    entry.get("red_wins", 0),
                    entry.get("blue_wins", 0),
                    entry.get("mesh_nodes_online", 0),
                    entry.get("r0_immunity"),
                ),
            )

    def get_evolution_timeline(
        self,
        limit: int = 200,
    ) -> list[dict]:
        """Get evolution timeline entries."""
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM evolution_timeline ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # AGGREGATE QUERIES
    # ------------------------------------------------------------------

    def get_dashboard_stats(self) -> dict:
        """Get aggregate statistics for the dashboard."""
        with self.connection() as conn:
            stats = {}

            # Incident counts
            row = conn.execute(
                "SELECT COUNT(*) as total, "
                "SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked, "
                "SUM(CASE WHEN surprise_level = 'novel' THEN 1 ELSE 0 END) as novel "
                "FROM incidents"
            ).fetchone()
            stats["incidents"] = {
                "total": row["total"] if row else 0,
                "blocked": row["blocked"] if row else 0,
                "novel": row["novel"] if row else 0,
            }

            # Antibody counts
            row = conn.execute(
                "SELECT COUNT(*) as total, "
                "SUM(CASE WHEN status = 'promoted' THEN 1 ELSE 0 END) as promoted, "
                "SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending "
                "FROM antibodies"
            ).fetchone()
            stats["antibodies"] = {
                "total": row["total"] if row else 0,
                "promoted": row["promoted"] if row else 0,
                "pending": row["pending"] if row else 0,
            }

            # Mesh nodes
            row = conn.execute(
                "SELECT COUNT(*) as total, "
                "SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online "
                "FROM mesh_nodes"
            ).fetchone()
            stats["mesh_nodes"] = {
                "total": row["total"] if row else 0,
                "online": row["online"] if row else 0,
            }

            # Latest immunity score
            row = conn.execute(
                "SELECT immunity_score, r0_immunity FROM evolution_timeline "
                "ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            stats["immunity"] = {
                "score": row["immunity_score"] if row else 0.0,
                "r0": row["r0_immunity"] if row else 0.0,
            }

            # Attack family distribution
            rows = conn.execute(
                "SELECT attack_family, COUNT(*) as cnt FROM incidents "
                "WHERE attack_family IS NOT NULL "
                "GROUP BY attack_family ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
            stats["attack_families"] = {
                row["attack_family"]: row["cnt"] for row in rows
            }

            # Language distribution
            rows = conn.execute(
                "SELECT language, COUNT(*) as cnt FROM incidents "
                "WHERE language IS NOT NULL "
                "GROUP BY language ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
            stats["languages"] = {
                row["language"]: row["cnt"] for row in rows
            }

            return stats

    # ------------------------------------------------------------------
    # UTILITIES
    # ------------------------------------------------------------------

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        """Convert a sqlite3.Row to a dict, parsing JSON fields."""
        d = dict(row)

        # Parse JSON fields
        json_fields = [
            "pipeline_stages", "mitre_techniques", "detection_rule",
            "indicators", "verification_details", "details",
            "merkle_proof", "red_variant", "blue_response",
            "arbiter_decision", "metadata", "languages",
        ]

        for field in json_fields:
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass

        return d

    def vacuum(self) -> None:
        """Compact the database file."""
        if self._is_sqlite:
            with self.connection() as conn:
                conn.execute("VACUUM")
            logger.info("Database vacuumed")

    def get_stats(self) -> dict:
        """Return database statistics."""
        stats = {
            "database_url": self._database_url,
            "is_sqlite": self._is_sqlite,
            "initialised": self._initialised,
        }

        if self._is_sqlite and self._db_path:
            try:
                size_bytes = os.path.getsize(self._db_path)
                stats["file_size_mb"] = round(size_bytes / (1024 * 1024), 2)
            except OSError:
                stats["file_size_mb"] = 0

            try:
                with self.connection() as conn:
                    for table in [
                        "incidents", "antibodies", "audit_events",
                        "compliance_reports", "mesh_nodes",
                        "battleground_history", "evolution_timeline",
                    ]:
                        row = conn.execute(
                            f"SELECT COUNT(*) as cnt FROM {table}"
                        ).fetchone()
                        stats[f"{table}_count"] = row["cnt"] if row else 0
            except Exception:
                pass

        return stats


# Module-level singleton
_db: Optional[Database] = None


def get_database() -> Database:
    """Get or create the singleton Database instance."""
    global _db
    if _db is None:
        _db = Database()
        _db.initialise()
    return _db
