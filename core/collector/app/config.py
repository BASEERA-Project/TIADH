import json
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """
    Runtime configuration for the Part 2 collector.

    DATABASE_PATH has been removed. The `common` package owns the shared SQLite
    database; its path is controlled by the HONEYPOT_DB_PATH environment
    variable, which common.config reads directly. Setting HONEYPOT_DB_PATH is
    enough to point the whole pipeline at the same file.

    There is nothing here to locate the storage layer: `common` is an installed
    dependency, so `from common.db.database import Database` just works.

    `host` and `port` are read here rather than hardcoded in `main.py serve`
    for the same reason the dashboard reads DASHBOARD_HOST / DASHBOARD_PORT in
    its own settings module: moving the ingest API to another interface or port
    is a deployment decision, not a code change. `serve --host/--port` still
    overrides them for one run.
    """
    node_keys: dict[str, str]
    host: str                  # interface the ingest API binds
    port: int
    max_batch_size: int
    maintenance_interval: int  # seconds between housekeeping passes


def _int(name: str, default: int) -> int:
    """
    Read an integer setting, naming the variable when it is unreadable.

    An empty value counts as unset — commenting a line out by blanking it is a
    normal thing to do to an env file. Anything else non-numeric is a typo, and
    it says so instead of falling back to the default, because a port you set
    and the collector silently ignored is the worst of the three outcomes.
    """
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc


def get_settings() -> Settings:
    raw_keys = os.getenv(
        "NODE_KEYS_JSON",
        '{"node-01":"dev-node-01-key","node-02":"dev-node-02-key","node-03":"dev-node-03-key"}',
    )
    try:
        node_keys = json.loads(raw_keys)
    except json.JSONDecodeError as exc:
        raise RuntimeError("NODE_KEYS_JSON must be valid JSON") from exc
    if not isinstance(node_keys, dict):
        raise RuntimeError("NODE_KEYS_JSON must be a JSON object")

    return Settings(
        node_keys={str(k): str(v) for k, v in node_keys.items()},
        # 0.0.0.0 on purpose, and the opposite of the dashboard's default: the
        # sensors are on other machines, so a loopback bind makes the collector
        # unreachable to every one of them.
        host=os.getenv("COLLECTOR_HOST", "0.0.0.0").strip() or "0.0.0.0",
        port=_int("COLLECTOR_PORT", 8000),
        max_batch_size=_int("MAX_BATCH_SIZE", 20),
        maintenance_interval=_int("MAINTENANCE_INTERVAL_SECONDS", 60),
    )
