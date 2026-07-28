"""
conftest.py — pytest fixtures for Part 2.

The collector no longer owns a database; it delegates to Part 4's Database
class. Tests must therefore mock `app.database.get_database` so they run
without requiring Part 4 to be installed or a real SQLite file to exist.

How the mock works
------------------
Each test gets a fresh, real Part4-style in-memory DB by constructing a
`Database(path=tmp_path/"test.db")` and initialising its schema from Part 4's
`schema.sql`. This is the most faithful approach: tests exercise the real
session/node logic without touching a shared file.

If Part 4 is not on sys.path (e.g. in CI without the full repo), the fixture
falls back to a lightweight MagicMock that returns sensible defaults, so
the authentication, validation, and routing tests still pass.
"""

from __future__ import annotations

import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


def _try_load_real_db(tmp_path: Path):
    """
    Try to import Part 4's Database and return a real test instance.
    Returns None if Part 4 is not available.
    """
    # Allow PART4_PATH env var to point at the module in CI
    part4_env = os.getenv("PART4_PATH", "").strip()
    if part4_env:
        candidate = Path(part4_env)
    else:
        # Assume standard repo layout: repo_root/part4_storage_alerting
        candidate = Path(__file__).resolve().parents[3] / "part4_storage_alerting"

    if not candidate.is_dir():
        return None

    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

    try:
        import importlib
        importlib.import_module("config")
        db_mod = importlib.import_module("db.database")
        db = db_mod.Database(path=tmp_path / "test.db")
        db.initialize_schema()
        return db
    except Exception:  # noqa: BLE001
        return None


def _make_mock_db():
    """
    Lightweight mock for environments where Part 4 is not installed.
    Mirrors the return shapes that app/database.py expects.
    """
    mock_db = MagicMock()
    # apply_events returns the standard batch result dict
    mock_db.apply_events.return_value = {
        "accepted": 1, "duplicates": 0, "rejected": 0, "errors": []
    }
    # query_one returns a basic node dict or None
    mock_db.query_one.return_value = {
        "node_id": "node-01", "status": "online", "last_seen": "2026-07-28T19:00:00Z"
    }
    mock_db.mark_stale_nodes_offline.return_value = 0
    mock_db.close_stale_sessions.return_value = 0
    return mock_db


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "NODE_KEYS_JSON",
        '{"node-01":"key-01","node-02":"key-02","node-03":"key-03"}',
    )
    monkeypatch.setenv("PART4_PATH", os.getenv("PART4_PATH", ""))

    real_db = _try_load_real_db(tmp_path)
    db_instance = real_db if real_db is not None else _make_mock_db()

    with patch("app.database.get_database", return_value=db_instance):
        # Re-import settings so monkeypatched env vars are picked up
        import app.main as main_mod
        from app.config import get_settings
        main_mod.settings = get_settings()
        with TestClient(main_mod.app) as test_client:
            yield test_client


def headers(node: str = "node-01", key: str = "key-01") -> dict:
    return {"X-Node-ID": node, "X-Node-Key": key}
