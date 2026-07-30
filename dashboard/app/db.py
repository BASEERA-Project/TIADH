"""
app/db.py — Request-scoped access to the shared database.

The dashboard never opens a database itself and never imports ``sqlite3``. It
holds a ``common.db.database.Database`` handle and calls methods on it; that
class owns the connection, the schema and the SQL dialect.

Rules this module enforces so no view has to remember them:

* Every read goes through a handle opened ``read_only=True``. SQLite is opened
  with ``mode=ro``, so a bug in a view physically cannot take a write lock away
  from the collector.
* One handle per request, closed on teardown. ``Database`` caches connections in
  ``threading.local``; under a threaded WSGI server those would otherwise
  accumulate one connection per worker thread and never be released.
* The single write path — acknowledging or closing an alert — is separated into
  :func:`get_writable_db` so it is greppable and can be switched off entirely
  with ``DASHBOARD_ALLOW_ALERT_ACTIONS=0``.
"""

from __future__ import annotations

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
        handle = Database(path=_path(), read_only=True)
        if not handle.exists():
            raise DatabaseUnavailable(f"no database at {handle.path}")
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
            except Exception:  # noqa: BLE001 - closing must never turn into a 500
                pass
            setattr(g, attr, None)


def health() -> dict:
    """
    Readiness facts for the setup screen: where the dashboard looked, what it
    found, and whether the schema is the version the code expects.

    ``Database.describe()`` reports rather than raises, so this needs no
    exception handling and no knowledge of the driver.
    """
    return Database(path=_path(), read_only=True).describe()
