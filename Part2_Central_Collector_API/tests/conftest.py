import os
import pytest
from fastapi.testclient import TestClient

@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_PATH", str(db_path))
    monkeypatch.setenv("NODE_KEYS_JSON", '{"node-01":"key-01","node-02":"key-02","node-03":"key-03"}')
    import app.main as main
    main.settings = main.get_settings()
    with TestClient(main.app) as test_client:
        yield test_client

def headers(node="node-01", key="key-01"):
    return {"X-Node-ID": node, "X-Node-Key": key}
