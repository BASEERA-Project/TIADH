import json
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """
    Runtime configuration for the Part 2 collector.

    DATABASE_PATH has been removed. Part 4 owns the shared SQLite database;
    its path is controlled by the HONEYPOT_DB_PATH environment variable, which
    Part 4's config.py reads directly. Setting HONEYPOT_DB_PATH is enough to
    point the whole pipeline at the same file.

    PART4_PATH tells Part 2 where to find the part4_storage_alerting directory
    so it can import Part 4's Database class at runtime.
    """
    node_keys: dict[str, str]
    max_batch_size: int
    part4_path: str          # path to part4_storage_alerting (may be empty string)
    maintenance_interval: int  # seconds between housekeeping passes


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
        max_batch_size=int(os.getenv("MAX_BATCH_SIZE", "20")),
        part4_path=os.getenv("PART4_PATH", "").strip(),
        maintenance_interval=int(os.getenv("MAINTENANCE_INTERVAL_SECONDS", "60")),
    )
