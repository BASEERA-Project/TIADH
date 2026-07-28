"""
app/db.py — Request-scoped access to the shared database.

Rules this module enforces so no view has to remember them:

* Every read goes through ``common.db.database.Database`` opened with
  ``read_only=True``. SQLite is opened with ``mode=ro``, so a bug in a view
  physically cannot take a write lock away from the collector.
* One handle per request, closed on teardown. ``Database`` caches connections in
  ``threading.local``; under a threaded WSGI server those would otherwise
  accumulate one connection per worker thread and never be released.
* The single write path — acknowledging or closing an alert — is separated into
  :func:`get_writable_db` so it is greppable and can be switched off entirely
  with ``DASHBOARD_ALLOW_ALERT_ACTIONS=0``.
"""

from __future__ import annotations

import sqlite3
from typing import Optional

from flask import current_app, g

from common.db.database import Database, StorageError


class DatabaseUnavailable(RuntimeError):
    """The configured database file is missing or unreadable."""


def _path():
    return current_app.config["DB_PATH"]


def get_db() -> Database:
    """The read-only handle for this request, opened on first use."""
    handle: Optional[Database] = getattr(g, "_db", None)
    if handle is None:
        path = _path()
        if not path.exists():
            raise DatabaseUnavailable(f"no database at {path}")
        handle = Database(path=path, read_only=True)
        g._db = handle
    return handle


def get_writable_db() -> Database:
    """
    A writable handle, used only by the alert acknowledge/close actions.

    Kept separate from :func:`get_db` on purpose: the read path can never
    accidentally inherit write capability.
    """
    if not current_app.config["ALLOW_ALERT_ACTIONS"]:
        raise StorageError("alert actions are disabled by configuration")

    handle: Optional[Database] = getattr(g, "_db_rw", None)
    if handle is None:
        handle = Database(path=_path())
        g._db_rw = handle
    return handle


def close_db(_exc=None) -> None:
    """Teardown hook — release both handles for the finished request."""
    for attr in ("_db", "_db_rw"):
        handle = getattr(g, attr, None)
        if handle is not None:
            try:
                handle.close()
            except sqlite3.Error:  # pragma: no cover - closing must never 500
                pass
            setattr(g, attr, None)


def health() -> dict:
    """
    Cheap readiness probe, rendered by the setup screen when something is wrong.

    Returns the facts a person needs to fix it: where the dashboard looked, what
    it found, and whether the schema is the version the code expects.
    """
    path = _path()
    info = {
        "path": str(path),
        "exists": path.exists(),
        "readable": False,
        "schema_version": None,
        "expected_schema_version": Database.schema_user_version(),
        "tables": [],
        "error": None,
    }
    if not info["exists"]:
        info["error"] = "database file not found"
        return info

    try:
        db = Database(path=path, read_only=True)
        info["schema_version"] = db.current_user_version()
        info["tables"] = [
            row["name"]
            for row in db.query(
                "SELECT name FROM sqlite_master "
                "WHERE type IN ('table','view') ORDER BY type, name"
            )
        ]
        info["readable"] = True
        db.close()
    except sqlite3.Error as exc:
        info["error"] = str(exc)
    return info
