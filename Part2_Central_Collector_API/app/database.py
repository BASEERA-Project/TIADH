"""
app/database.py — Part 2 storage adapter.

The `common` package owns the SQLite database. This module is a thin shim over
its Database class and delegates every write to it. Part 2 must never open its
own connection to the shared database file; all writes go through the shared
write path so that masking, validation, and idempotency are applied
consistently regardless of which part is writing.

The storage contract (common/db/database.py docstring) lists the exact methods
Part 2 is expected to call:
    apply_event()              — persist one event (used by apply_events)
    apply_events()             — batch ingest, returns accepted/duplicates/rejected
    upsert_node()              — create or update a node row
    mark_stale_nodes_offline() — flip nodes offline after missed heartbeats
    close_stale_sessions()     — force-close abandoned sessions

Where the database lives
------------------------
`common` is an installed package, so there is nothing to locate at runtime —
no PART4_PATH, no sys.path insertion. The database *file* is chosen by the
HONEYPOT_DB_PATH environment variable, which common.config reads directly;
setting it points the whole pipeline at one file.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from common.db.database import Database, get_db, init_db

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Public helpers — called by main.py
# --------------------------------------------------------------------------

def get_database() -> Database:
    """
    Return the shared Database instance (write handle).

    The instance is created once per process. The Database class manages
    per-thread connections internally, so this is safe to call from any thread.
    """
    return get_db(read_only=False)


def initialise() -> None:
    """
    Ensure the schema exists.

    Delegates to init_db(), which runs initialize_schema() and is safe to call
    on every startup even when the database already has data.
    """
    db = init_db()
    log.info("shared database initialised at %s", db.path)


def ingest(events: List[Any]) -> Tuple[int, int, int]:
    """
    Persist a batch of already-validated Event objects.

    Converts each Pydantic Event to the plain dict format the storage layer
    expects (the shared Baseline v1.3 JSON envelope), then calls apply_events().

    Returns (accepted, duplicates, rejected).
    """
    db = get_database()

    raw_events: List[Dict[str, Any]] = []
    for event in events:
        raw_events.append({
            "event_id":   str(event.event_id),
            "node_id":    event.node_id,
            "event_type": event.event_type,
            "timestamp":  event.timestamp.isoformat().replace("+00:00", "Z"),
            "session_id": event.session_id,
            "attacker_ip": event.attacker_ip,
            "protocol":   event.protocol,
            "details":    dict(event.details),
        })

    result = db.apply_events(raw_events)
    return result["accepted"], result["duplicates"], result["rejected"]


def get_node(node_id: str) -> Optional[Dict[str, Any]]:
    """Return a node row as a plain dict, or None if the node is unknown."""
    db = get_database()
    return db.query_one("SELECT * FROM nodes WHERE node_id = ?", (node_id,))


def run_maintenance() -> None:
    """
    Housekeeping pass: mark stale nodes offline and force-close abandoned sessions.

    The storage contract (common/db/database.py) lists both of these as Part 2's
    responsibility because Part 2 is the only always-running process.
    Schedule this in the collector's background loop (see main.py lifespan).
    """
    db = get_database()
    nodes_flipped = db.mark_stale_nodes_offline()
    sessions_closed = db.close_stale_sessions()
    if nodes_flipped:
        log.info("maintenance: marked %d node(s) offline", nodes_flipped)
    if sessions_closed:
        log.info("maintenance: force-closed %d stale session(s)", sessions_closed)
