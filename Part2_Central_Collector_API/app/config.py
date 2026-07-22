import json
import os
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class Settings:
    database_path: str
    node_keys: dict[str, str]
    max_batch_size: int

def get_settings() -> Settings:
    raw_keys = os.getenv("NODE_KEYS_JSON", '{"node-01":"dev-node-01-key","node-02":"dev-node-02-key","node-03":"dev-node-03-key"}')
    try:
        node_keys = json.loads(raw_keys)
    except json.JSONDecodeError as exc:
        raise RuntimeError("NODE_KEYS_JSON must be valid JSON") from exc
    if not isinstance(node_keys, dict):
        raise RuntimeError("NODE_KEYS_JSON must be a JSON object")
    database_path = os.getenv("DATABASE_PATH", "./data/collector.db")
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    return Settings(
        database_path=database_path,
        node_keys={str(k): str(v) for k, v in node_keys.items()},
        max_batch_size=int(os.getenv("MAX_BATCH_SIZE", "20")),
    )
