"""SQLite schema and connection management for ReachPrioritizer."""
from __future__ import annotations

import logging
import sqlite3

from app.config import DB_PATH

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    project_id   TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    upload_path  TEXT NOT NULL,
    file_count   INTEGER DEFAULT 0,
    size_bytes   INTEGER DEFAULT 0,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id        TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL,
    project_name   TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'queued',
    stage          TEXT,
    progress       INTEGER DEFAULT 0,
    finding_count  INTEGER DEFAULT 0,
    error_message  TEXT,
    model_used     TEXT,
    analysis_mode  TEXT,
    summary_json   TEXT,
    duration_ms    INTEGER,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    completed_at   TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id                TEXT PRIMARY KEY,
    scan_id                   TEXT NOT NULL,
    function_id               TEXT,
    function_name             TEXT,
    file_path                 TEXT NOT NULL,
    start_line                INTEGER,
    end_line                  INTEGER,
    line                      INTEGER,
    related_lines             TEXT,
    snippet                   TEXT,
    source_code               TEXT,
    prediction                TEXT,
    vulnerability_probability REAL DEFAULT 0.0,
    model_used                TEXT,
    rule_id                   TEXT,
    title                     TEXT,
    rule_message              TEXT,
    severity                  TEXT,
    cwe                       TEXT,
    category                  TEXT,
    sink                      TEXT,
    taint                     TEXT DEFAULT 'none',
    reachability_status       TEXT DEFAULT 'unknown',
    entry_point               TEXT,
    call_path                 TEXT,
    taint_path                TEXT,
    risk_score                REAL DEFAULT 0.0,
    risk_category             TEXT,
    risk_breakdown            TEXT,
    finding_type              TEXT,
    detector                  TEXT,
    created_at                TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS call_graph_nodes (
    scan_id        TEXT NOT NULL,
    node_id        TEXT NOT NULL,
    name           TEXT NOT NULL,
    file_path      TEXT,
    line           INTEGER,
    end_line       INTEGER,
    node_type      TEXT,
    reachability   TEXT,
    entry_kind     TEXT,
    ai_probability REAL,
    finding_count  INTEGER DEFAULT 0,
    max_risk       REAL DEFAULT 0,
    PRIMARY KEY (scan_id, node_id),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS call_graph_edges (
    edge_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   TEXT NOT NULL,
    caller_id TEXT NOT NULL,
    callee_id TEXT NOT NULL,
    kind      TEXT,
    line      INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS entry_points (
    scan_id    TEXT NOT NULL,
    node_id    TEXT NOT NULL,
    kind       TEXT,
    label      TEXT,
    active     INTEGER DEFAULT 1,
    file_path  TEXT,
    line       INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(scan_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_cg_nodes_scan ON call_graph_nodes(scan_id);
CREATE INDEX IF NOT EXISTS idx_cg_edges_scan ON call_graph_edges(scan_id);
CREATE INDEX IF NOT EXISTS idx_entry_scan ON entry_points(scan_id);
"""

LEGACY_TABLES = ["findings", "call_graph_edges", "call_graph_nodes", "entry_points", "scans", "projects"]


def get_connection() -> sqlite3.Connection:
    """Return a SQLite connection (one per operation; safe across threads)."""
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _current_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_meta'"
    ).fetchone()
    if not row:
        has_any = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scans'"
        ).fetchone()
        return 1 if has_any else 0
    v = conn.execute("SELECT value FROM schema_meta WHERE key='version'").fetchone()
    return int(v["value"]) if v else 0


def initialize_db() -> None:
    """Create tables; migrate a v1 (prototype) database by recreating the schema."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        version = _current_version(conn)
        if 0 < version < SCHEMA_VERSION:
            logger.warning(
                "Database schema v%d is incompatible with v%d; recreating tables "
                "(old prototype scan data is discarded).",
                version, SCHEMA_VERSION,
            )
            conn.execute("PRAGMA foreign_keys=OFF")
            for t in LEGACY_TABLES:
                conn.execute(f"DROP TABLE IF EXISTS {t}")
            conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(SCHEMA_SQL)
        conn.execute(
            "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('version', ?)",
            (str(SCHEMA_VERSION),),
        )
        conn.commit()
        logger.info("Database ready at %s (schema v%d)", DB_PATH, SCHEMA_VERSION)
    finally:
        conn.close()
