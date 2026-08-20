"""
shipper — the half of a honeypot sensor that is not about the honeypot.

Two sensors live in `nodes/`: one watching Cowrie, one watching dionaea. What
they have in common is everything except the log format — tailing a file across
rotation, batching to twenty, heartbeating on the contract's interval, spooling
a failed POST to disk and retrying it. That is this package, so there is one
copy of it and a fix lands once.

An adapter is then a Settings and a mapper:

    from shipper import load_settings, run_sensor

    SETTINGS = load_settings(__file__, default_node_id="node-02",
                             default_log_path="./cowrie-logs/cowrie.json")

    def build_envelopes(raw_event: dict) -> list[dict]:
        \"\"\"One parsed log line in, zero or more v1.3 envelopes out.\"\"\"

    run_sensor(SETTINGS, build_envelopes)

and its `backfill.py` hands `shipper.backfill.main()` the same two, so the live
path and the replay path cannot disagree about what an event is.
"""

from .run import Mapper, Summariser, run_sensor
from .settings import Settings, env_seconds, load_env, load_settings
from .ship import BATCH_MAX_EVENTS, Shipper, build_heartbeat
from .tail import tail_lines

__all__ = [
    "BATCH_MAX_EVENTS",
    "Mapper",
    "Settings",
    "Shipper",
    "Summariser",
    "build_heartbeat",
    "env_seconds",
    "load_env",
    "load_settings",
    "run_sensor",
    "tail_lines",
]
