"""
app/database.py — Part 2 storage adapter.

Part 4 owns the SQLite database. This module is a thin shim that imports
Part 4's Database class and delegates every write to it. Part 2 must never
open its own connection to the shared database file; all writes go through
Part 4's write path so that masking, validation, and idempotency are applied
consistently regardless of which part is writing.

Part 4's documented contract (db/database.py docstring) lists the exact
methods Part 2 is expected to call:
    apply_event()            — persist one event (used by apply_events)
    apply_events()           — batch ingest, returns accepted/duplicates/rejected
    upsert_node()            — create or update a node row
    mark_stale_nodes_offline() — flip nodes offline after missed heartbeats
    close_stale_sessions()   — force-close abandoned sessions

How Part 4 is located
---------------------
Set PART4_PATH to the absolute path of the `part4_storage_alerting` directory.
In the shared deployment this is a sibling folder:

    PART4_PATH=/opt/tiadh/part4_storage_alerting

If PART4_PATH is not set the code falls back to looking two directories up from
this file (works when the whole repo is checked out into one place).
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


def _locate_part4() -> Path:
    """
    Return the path to the `part4_storage_alerting` directory.

    Resolution order:
      1. PART4_PATH environment variable
      2. ../../part4_storage_alerting relative to this file
         (i.e. assumes the full repo is checked out together)
    """
    from_env = os.getenv("PART4_PATH", "").strip()
    if from_env:
        p = Path(from_env)
        if p.is_dir():
            return p
        log.warning("PART4_PATH=%s does not exist — falling back to auto-detect", from_env)

    # Part2_Central_Collector_API/app/database.py  →  go up 3 levels
    repo_root = Path(__file__).resolve().parents[2]
    candidate = repo_root / "part4_storage_alerting"
    if candidate.is_dir():
        return candidate

    raise RuntimeError(
        "Cannot locate part4_storage_alerting. "
        "Set the PART4_PATH environment variable to its absolute path."
    )


def _import_part4_database():
    """
    Dynamically import Part 4's db.database module.

    We add part4_storage_alerting to sys.path at runtime because the two parts
    live in separate directories and are not installed as packages. The import is
    cached in sys.modules so subsequent calls are free.
    """
    part4_path = str(_locate_part4())
    if part4_path not in sys.path:
        sys.path.insert(0, part4_path)
    # Importing `config` here ensures Part 4's own config module is resolved
    # before `db.database` tries to use it.
    import importlib
    importlib.import_module("config")          # part4_storage_alerting/config.py
    db_mod = importlib.import_module("db.database")
    return db_mod


# --------------------------------------------------------------------------
# Public helpers — called by main.py
# --------------------------------------------------------------------------

def get_database():
    """
    Return Part 4's Database instance (write handle).

    The instance is created once per process. Part 4's Database class manages
    per-thread connections internally, so this is safe to call from any thread.
    """
    mod = _import_part4_database()
    return mod.get_db(read_only=False)


def initialise() -> None:
    """
    Ensure the schema exists.

    Delegates to Part 4's init_db(), which runs initialize_schema() and is safe
    to call on every startup even when the database already has data.
    """
    mod = _import_part4_database()
    db = mod.init_db()
    log.info("Part 4 database initialised at %s", db.path)


def ingest(events: List[Any]) -> Tuple[int, int, int]:
    """
    Persist a batch of already-validated Event objects.

    Converts each Pydantic Event to the plain dict format Part 4 expects (the
    shared Baseline v1.3 JSON envelope), then calls Part 4's apply_events().

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

    Part 4's contract (db/database.py) lists both of these as Part 2's
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
