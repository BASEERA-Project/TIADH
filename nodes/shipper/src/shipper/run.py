"""
run.py — wire a honeypot's log to the collector.

An adapter is then two things and nothing else: a Settings, and a function that
turns one parsed log line into zero or more Baseline v1.3 envelopes. Everything
between those and the collector — tailing, rotation, batching, heartbeats,
retry — is the same for every honeypot and lives in this package.

    from shipper import load_settings, run_sensor

    SETTINGS = load_settings(__file__, default_node_id="node-02",
                             default_log_path="./cowrie-logs/cowrie.json")

    def build_envelopes(raw_event: dict) -> list[dict]:
        ...

    run_sensor(SETTINGS, build_envelopes)
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Callable, Iterable

from .settings import Settings
from .ship import Shipper

#: An adapter's mapper: one parsed log line in, zero or more envelopes out.
#: The envelopes carry no `event_id` — see `mint_event_ids` for why.
Mapper = Callable[[dict], Iterable[dict]]

#: Optional: called on a timer, and whatever it returns is printed. Used to
#: report what the mapper has been skipping, so that a sensor which is dropping
#: most of its traffic says so instead of just looking quiet.
Summariser = Callable[[], str | None]


def mint_event_ids(envelopes: Iterable[dict]) -> list[dict]:
    """Stamp a fresh random `event_id` on each envelope.

    Mappers deliberately leave `event_id` off, because the live adapter and
    `backfill.py` mint it differently and for good reason. Live, a random UUID
    is right: every line is seen exactly once, and a random id cannot collide
    with anything. Backfilling, the id has to be derived from the event itself
    so that a second run produces the same ids and the collector answers
    `duplicates` instead of inserting a second copy of every session.
    """
    stamped = []
    for envelope in envelopes:
        envelope["event_id"] = str(uuid.uuid4())
        stamped.append(envelope)
    return stamped


def _summary_loop(summarise: Summariser, interval: float) -> None:
    while True:
        time.sleep(interval)
        try:
            line = summarise()
        except Exception as exc:  # noqa: BLE001 — a broken counter must not stop ingest
            print(f"summary failed: {exc}")
            continue
        if line:
            print(line)


def run_sensor(
    settings: Settings,
    build_envelopes: Mapper,
    summarise: Summariser = None,
) -> None:
    """Tail the log named by `settings` and ship what `build_envelopes` makes of it.

    Never returns. Malformed lines are skipped rather than fatal: a honeypot log
    is written by software an attacker is actively poking, and one unparseable
    line must not take this sensor's whole ingest down with it.
    """
    shipper = Shipper(settings)
    shipper.start()

    if summarise is not None:
        threading.Thread(
            target=_summary_loop,
            args=(summarise, settings.summary_interval),
            daemon=True,
        ).start()

    print(f"Node {settings.node_id} → {settings.collector_url}")

    from .tail import tail_lines

    for line in tail_lines(settings.log_path, settings.poll_interval):
        try:
            raw_event = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue  # skip malformed lines rather than kill the tailer

        if not isinstance(raw_event, dict):
            # Valid JSON, but not an event: a bare number or string has no
            # .get() to give the mapper, and the AttributeError would take the
            # tailer — and so this sensor's whole ingest — down with it.
            continue

        for envelope in mint_event_ids(build_envelopes(raw_event)):
            shipper.submit(envelope)
