"""
SQLite Database Module — Stores analysis history and simulated IP blocks.
=========================================================================

This module handles all database operations for the application:

1. CAPTURES TABLE: Stores the result of every PCAP analysis
   (risk score, flow counts, attack ratio, etc.)
2. SUSPICIOUS_FLOWS TABLE: Stores the top suspicious flows
   for each capture (source/dest IPs, ports, attack probability)
3. SIMULATED_BLOCKS TABLE: Stores simulated IP blocks
   (for demonstration only — no real network changes are made)

The database is a single SQLite file (cyber_attacks.db) in the project root.
SQLite was chosen because:
- No separate database server needed (good for a mini-project demo)
- Data persists between server restarts
- Supports concurrent reads with WAL mode

All SQL queries use parameterised statements (?) to prevent SQL injection.
"""

import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = PROJECT_ROOT / "cyber_attacks.db"
UPLOADS_DIR = PROJECT_ROOT / "uploads"

# ── Database Schema ────────────────────────────────────────────────────
# These CREATE TABLE statements run on first startup.
# IF NOT EXISTS ensures they don't fail if the tables already exist.
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS captures (
    id TEXT PRIMARY KEY,
    original_name TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    file_deleted_at TEXT,
    total_flows INTEGER DEFAULT 0,
    attack_flows INTEGER DEFAULT 0,
    normal_flows INTEGER DEFAULT 0,
    attack_ratio REAL DEFAULT 0,
    risk_score REAL DEFAULT 0,
    risk_level TEXT DEFAULT 'LOW',
    status TEXT DEFAULT 'NORMAL',
    model_version TEXT DEFAULT '',
    mean_attack_probability REAL DEFAULT 0,
    protocol_breakdown TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS suspicious_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER DEFAULT 0,
    dst_port INTEGER DEFAULT 0,
    protocol TEXT DEFAULT '',
    attack_probability REAL DEFAULT 0,
    label TEXT DEFAULT '',
    FOREIGN KEY (capture_id) REFERENCES captures(id)
);

CREATE TABLE IF NOT EXISTS simulated_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    capture_id TEXT,
    blocked_at TEXT NOT NULL,
    status TEXT DEFAULT 'BLOCKED (SIMULATED)',
    note TEXT DEFAULT '',
    FOREIGN KEY (capture_id) REFERENCES captures(id)
);
"""


def get_connection() -> sqlite3.Connection:
    """
    Get a database connection configured for safe operation.

    - row_factory=Row: allows accessing columns by name (row['column'])
    - WAL journal mode: allows concurrent reads while writing
    - foreign_keys=ON: enforces referential integrity
    """
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create the database tables if they don't exist yet."""
    conn = get_connection()
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


def store_capture(capture_id: str, original_name: str, result: dict,
                  model_version: str = ""):
    """
    Store a complete capture analysis result in the database.

    Called after the full pipeline runs:
    PCAP → extract features → predict → risk score → [store here]

    This stores both the capture summary (in captures table)
    and the individual suspicious flows (in suspicious_flows table).

    Args:
        capture_id: UUID assigned to this capture upload.
        original_name: Original filename (for display in history).
        result: Complete result dict from risk.score.compute_risk().
        model_version: Training date string from model_metadata.json.
    """
    import json as _json

    conn = get_connection()
    try:
        # Store the capture-level summary
        conn.execute(
            """INSERT OR REPLACE INTO captures
               (id, original_name, uploaded_at, total_flows, attack_flows,
                normal_flows, attack_ratio, risk_score, risk_level, status,
                model_version, mean_attack_probability, protocol_breakdown)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                capture_id,
                original_name,
                datetime.now().isoformat(),
                result.get("total_flows", 0),
                result.get("attack_flows", 0),
                result.get("normal_flows", 0),
                result.get("attack_ratio", 0),
                result.get("risk_score", 0),
                result.get("risk_level", "LOW"),
                result.get("status", "NORMAL"),
                model_version,
                result.get("mean_attack_probability", 0),
                _json.dumps(result.get("protocol_breakdown", {})),
            )
        )

        # Store individual suspicious flows for this capture
        # These are shown in the "Top Suspicious Flows" table on the dashboard
        for flow in result.get("top_suspicious_flows", []):
            conn.execute(
                """INSERT INTO suspicious_flows
                   (capture_id, src_ip, dst_ip, src_port, dst_port,
                    protocol, attack_probability, label)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    capture_id,
                    flow.get("src_ip", ""),
                    flow.get("dst_ip", ""),
                    flow.get("src_port", 0),
                    flow.get("dst_port", 0),
                    flow.get("protocol", ""),
                    flow.get("attack_probability", 0),
                    flow.get("label", ""),
                )
            )

        conn.commit()
    finally:
        conn.close()


def get_capture(capture_id: str) -> Optional[dict]:
    """
    Retrieve a single capture result by its UUID.

    Used when the user clicks "View Details" on a capture in the history page.
    Returns the capture summary plus its associated suspicious flows.
    """
    import json as _json

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM captures WHERE id = ?", (capture_id,)
        ).fetchone()

        if row is None:
            return None

        result = dict(row)

        # Parse protocol_breakdown from JSON string back to dict
        if result.get("protocol_breakdown"):
            try:
                result["protocol_breakdown"] = _json.loads(result["protocol_breakdown"])
            except (ValueError, TypeError):
                result["protocol_breakdown"] = {}

        # Fetch associated suspicious flows, ordered by attack probability
        flows = conn.execute(
            """SELECT src_ip, dst_ip, src_port, dst_port, protocol,
                      attack_probability, label
               FROM suspicious_flows
               WHERE capture_id = ?
               ORDER BY attack_probability DESC""",
            (capture_id,)
        ).fetchall()

        result["top_suspicious_flows"] = [dict(f) for f in flows]

        # Aggregate suspicious IPs from flow data
        ip_rows = conn.execute(
            """SELECT src_ip as ip, COUNT(*) as attack_flows
               FROM suspicious_flows
               WHERE capture_id = ? AND label = 'Attack'
               GROUP BY src_ip
               ORDER BY attack_flows DESC""",
            (capture_id,)
        ).fetchall()

        result["suspicious_ips"] = [dict(r) for r in ip_rows]
        result["capture_id"] = capture_id
        result["id"] = capture_id
        result["filename"] = result.get("original_name", "")

        return result
    finally:
        conn.close()


def get_captures_list() -> list:
    """
    Get all capture analyses, newest first (for the history page).

    Returns summary fields only — full details are fetched
    separately via get_capture() when the user clicks on one.
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT id, original_name, uploaded_at, total_flows,
                      attack_flows, normal_flows, risk_score, risk_level, status
               FROM captures
               ORDER BY uploaded_at DESC"""
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_simulated_block(ip: str, capture_id: str, note: str = "") -> int:
    """
    Add a simulated IP block to the database.

    IMPORTANT: This is a SIMULATION only. No real firewall rules are created.
    The IP is just recorded in the database and shown on the dashboard.
    In a real system, this would call iptables/Windows Firewall APIs.

    Returns the block ID (for later removal).
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            """INSERT INTO simulated_blocks (ip, capture_id, blocked_at, status, note)
               VALUES (?, ?, ?, 'BLOCKED (SIMULATED)', ?)""",
            (ip, capture_id, datetime.now().isoformat(), note)
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_simulated_blocks() -> list:
    """Get all simulated blocks (for the Blocked IPs page)."""
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT id, ip, capture_id, blocked_at, status, note
               FROM simulated_blocks
               ORDER BY blocked_at DESC"""
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def remove_simulated_block(block_id: int) -> bool:
    """Remove a simulated block by ID. Returns True if found and deleted."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            "DELETE FROM simulated_blocks WHERE id = ?", (block_id,)
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def cleanup_old_uploads(max_age_hours: int = 24):
    """
    Delete uploaded PCAP/PCAPNG files older than max_age_hours.

    This runs automatically in the background to prevent the uploads/
    directory from growing indefinitely. Only the files are deleted —
    the analysis history in the database is preserved.
    """
    if not UPLOADS_DIR.exists():
        return

    cutoff = time.time() - (max_age_hours * 3600)
    deleted = []

    for filepath in UPLOADS_DIR.iterdir():
        if filepath.is_file() and filepath.stat().st_mtime < cutoff:
            try:
                filepath.unlink()
                deleted.append(filepath.name)
            except OSError:
                pass

    if deleted:
        # Record deletion timestamp in the captures table
        conn = get_connection()
        try:
            now = datetime.now().isoformat()
            for fname in deleted:
                conn.execute(
                    """UPDATE captures SET file_deleted_at = ?
                       WHERE id = ? AND file_deleted_at IS NULL""",
                    (now, fname.replace(".pcapng", "").replace(".pcap", ""))
                )
            conn.commit()
        finally:
            conn.close()

    return deleted


def start_cleanup_task(interval_seconds: int = 3600):
    """
    Start a background thread that cleans up old uploads every hour.

    Uses a daemon thread so it stops automatically when the server stops.
    Cleanup errors are silently caught to prevent crashing the server.
    """
    def _cleanup_loop():
        while True:
            time.sleep(interval_seconds)
            try:
                cleanup_old_uploads()
            except Exception:
                pass  # Cleanup errors should never crash the server

    thread = threading.Thread(target=_cleanup_loop, daemon=True)
    thread.start()
    return thread
