"""
conftest.py — pytest fixtures for Part 2.

The collector no longer owns a database; it delegates to the shared Database
class in `common`. Each test therefore gets a fresh, real database in its own
tmp_path and patches `app.database.get_database` to return it.

Using the real storage layer rather than a mock is deliberate: dedupe,
Baseline v1.3 validation and session derivation are exactly what these tests
assert on, and a mock would only ever confirm that the mock was configured
correctly. `common` is a declared dependency, so it is always importable.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from common.db.database import Database


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "NODE_KEYS_JSON",
        '{"node-01":"key-01","node-02":"key-02","node-03":"key-03"}',
    )

    db = Database(path=tmp_path / "test.db")
    db.initialize_schema()

    # The fixture owns the schema, so the startup hook must not run: init_db()
    # would reach for the real shared database at HONEYPOT_DB_PATH, which a
    # test run has no business touching.
    with patch("app.database.get_database", return_value=db), \
            patch("app.database.initialise"):
        # Re-import settings so monkeypatched env vars are picked up
        import app.main as main_mod
        from app.config import get_settings
        main_mod.settings = get_settings()
        with TestClient(main_mod.app) as test_client:
            yield test_client

    db.close()


def headers(node: str = "node-01", key: str = "key-01") -> dict:
    return {"X-Node-ID": node, "X-Node-Key": key}
