"""
settings.py — the configuration every sensor has, whatever honeypot it watches.

A sensor host is a different machine from the aggregator. It does not share the
aggregator's `.env` and has no `common` package to load one, so each adapter
reads the `.env` sitting next to it and builds a Settings out of the result.

Only the values that have to agree with the aggregator are shared with it:
NODE_ID must appear in the collector's KNOWN_NODES, NODE_KEY must match that
node's entry in NODE_KEYS_JSON, and HEARTBEAT_INTERVAL_SECONDS is a Baseline
v1.3 contract value rather than a local preference — see below.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def load_env(adapter_file: str) -> Path:
    """Read the `.env` beside `adapter_file`, and return the path tried.

    Named explicitly rather than left to dotenv's default upward search. That
    search would walk out of the sensor's directory and, on a machine with the
    whole repository checked out, reach the aggregator's own root `.env` — a
    different host's configuration entirely. A sensor is configured by the file
    next to its adapter or not at all.

    override=False (the default) leaves a real environment variable outranking
    the file, which is how common/config.py treats the aggregator's `.env`, and
    is what makes `NODE_KEY=... uv run adapter.py` still work.
    """
    env_path = Path(adapter_file).with_name(".env")
    load_dotenv(env_path)
    return env_path


def env_seconds(name: str, default: float) -> float:
    """Read one of the timing knobs below from the environment.

    Anything that isn't a positive number is refused and the default kept:
    zero or less would turn the loop it paces into a busy-wait, and a typo
    would otherwise quietly change how often this sensor reports — the sort of
    thing nobody notices until a node looks dead on the dashboard.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default

    try:
        seconds = float(raw)
    except ValueError:
        print(f"{name}={raw!r} is not a number — keeping the default of {default}s")
        return default

    if seconds <= 0:
        print(f"{name}={raw!r} must be greater than zero — keeping the default of {default}s")
        return default

    return seconds


@dataclass(frozen=True)
class Settings:
    """Everything a sensor needs that is not about its honeypot."""

    node_id: str
    node_key: str
    collector_url: str
    log_path: str

    # How long the tailer waits before looking at the log again when it has
    # nothing new — and therefore how quickly a rotation, or a log that hasn't
    # been created yet, is noticed.
    poll_interval: float

    # How often a heartbeat is queued. This one is a Baseline v1.3 contract
    # value rather than a local preference: the aggregator marks a node offline
    # after three missed beats — NODE_OFFLINE_AFTER_SECONDS, derived from its
    # own copy of this same variable in common/config.py — and the dashboard
    # reports node health in missed heartbeats. Raise it here without raising
    # it there and this node flaps offline between beats.
    heartbeat_interval: float

    # How long a partly-filled batch waits before being sent anyway. A batch
    # that reaches BATCH_MAX_EVENTS is sent the moment it does, whatever this
    # says.
    batch_interval: float

    # How often events spooled to `pending_file` by a failed send are retried.
    retry_interval: float

    # How often the adapter prints what it has been skipping. Silence is the
    # one thing a sensor must never report as success.
    summary_interval: float

    pending_file: str


def load_settings(
    adapter_file: str,
    *,
    default_node_id: str,
    default_log_path: str,
) -> Settings:
    """Build a Settings from the `.env` beside `adapter_file` and the environment.

    The two defaults are the caller's because they are the only settings that
    differ per honeypot: which node this sensor usually is, and where that
    honeypot writes its JSON log.
    """
    load_env(adapter_file)

    return Settings(
        node_id=os.environ.get("NODE_ID", default_node_id),
        node_key=os.environ.get("NODE_KEY", "dev-test-key"),
        collector_url=os.environ.get("COLLECTOR_URL", "http://localhost:8000/api/events"),
        log_path=os.environ.get("LOG_PATH", default_log_path),
        poll_interval=env_seconds("POLL_INTERVAL_SECONDS", 1.0),
        heartbeat_interval=env_seconds("HEARTBEAT_INTERVAL_SECONDS", 60.0),
        batch_interval=env_seconds("BATCH_INTERVAL_SECONDS", 10.0),
        retry_interval=env_seconds("RETRY_INTERVAL_SECONDS", 30.0),
        summary_interval=env_seconds("SUMMARY_INTERVAL_SECONDS", 300.0),
        pending_file=os.environ.get("PENDING_FILE", "pending_events.jsonl"),
    )
