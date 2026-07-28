import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from .models import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY,
    hostname TEXT,
    location TEXT,
    ip_address TEXT,
    status TEXT NOT NULL DEFAULT 'offline',
    last_seen TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    attacker_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    username TEXT,
    password TEXT,
    start_time TEXT NOT NULL,
    end_time TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    session_id TEXT,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    attacker_ip TEXT,
    protocol TEXT,
    details TEXT NOT NULL,
    received_at TEXT NOT NULL,
    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
);
CREATE INDEX IF NOT EXISTS idx_events_node_timestamp ON events(node_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_attacker_timestamp ON events(attacker_ip, timestamp);
"""

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def connect(database_path: str) -> sqlite3.Connection:
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def initialise(database_path: str) -> None:
    with connect(database_path) as conn:
        conn.executescript(SCHEMA)

def event_exists(conn: sqlite3.Connection, event_id: str) -> bool:
    return conn.execute("SELECT 1 FROM events WHERE event_id = ?", (event_id,)).fetchone() is not None

def upsert_node(conn: sqlite3.Connection, node_id: str, received_at: str) -> None:
    conn.execute("""
        INSERT INTO nodes (node_id, status, last_seen) VALUES (?, 'online', ?)
        ON CONFLICT(node_id) DO UPDATE SET status='online', last_seen=excluded.last_seen
    """, (node_id, received_at))

def upsert_session(conn: sqlite3.Connection, event: Event) -> None:
    if event.event_type == "heartbeat" or event.session_id is None:
        return
    details = event.details
    conn.execute("""
        INSERT INTO sessions (session_id, node_id, attacker_ip, protocol, username, password, start_time, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
        ON CONFLICT(session_id) DO UPDATE SET
          username=COALESCE(excluded.username, sessions.username),
          password=COALESCE(excluded.password, sessions.password)
    """, (event.session_id, event.node_id, event.attacker_ip, event.protocol,
          details.get("username"), details.get("password"), event.timestamp.isoformat()))
    if event.event_type == "session_end":
        conn.execute("UPDATE sessions SET end_time=?, status=? WHERE session_id=?", (
            event.timestamp.isoformat(), details["status"], event.session_id))

def store_event(conn: sqlite3.Connection, event: Event, received_at: str) -> None:
    conn.execute("""
        INSERT INTO events (event_id, node_id, session_id, event_type, timestamp, attacker_ip, protocol, details, received_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (str(event.event_id), event.node_id, event.session_id, event.event_type,
          event.timestamp.isoformat(), event.attacker_ip, event.protocol,
          json.dumps(event.details, separators=(",", ":")), received_at))
    upsert_session(conn, event)

def ingest(database_path: str, events: list[Event]) -> tuple[int, int]:
    accepted = duplicates = 0
    with connect(database_path) as conn:
        for event in events:
            received_at = utc_now()
            upsert_node(conn, event.node_id, received_at)
            if event_exists(conn, str(event.event_id)):
                duplicates += 1
                continue
            store_event(conn, event, received_at)
            accepted += 1
    return accepted, duplicates

def get_node(database_path: str, node_id: str):
    with connect(database_path) as conn:
        row = conn.execute("SELECT * FROM nodes WHERE node_id=?", (node_id,)).fetchone()
        return dict(row) if row else None
