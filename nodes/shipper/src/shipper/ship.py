"""
ship.py — batch events, POST them to the collector, and survive it being down.

Section 3 of Baseline v1.3 in one class: batch up to BATCH_MAX_EVENTS events
every `batch_interval` seconds, authenticate with X-Node-ID / X-Node-Key,
heartbeat every `heartbeat_interval`, and append anything that failed to send
to `pending_events.jsonl` for retry.

None of it depends on which honeypot produced the events, so both adapters
share this and differ only in how they turn a log line into an envelope.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import uuid
from datetime import datetime, timezone

import requests

from .settings import Settings

#: A batch this size is sent the moment it fills, whatever `batch_interval`
#: says. It is the collector's own default MAX_BATCH_SIZE, from the baseline's
#: shipping rules — send it more than this in one POST and it answers 422.
BATCH_MAX_EVENTS = 20


def build_heartbeat(node_id: str) -> dict:
    """Build a heartbeat envelope, per Section 2's rules: session_id,
    attacker_ip, and protocol are always null for heartbeats."""
    return {
        "event_id": str(uuid.uuid4()),
        "node_id": node_id,
        "event_type": "heartbeat",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "session_id": None,
        "attacker_ip": None,
        "protocol": None,
        "details": {"status": "online"},
    }


class Shipper:
    """Owns the outbound half of a sensor: the queue, the batching, the retry."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.queue: queue.Queue = queue.Queue()

    # -- the two things an adapter calls ----------------------------------

    def submit(self, envelope: dict) -> None:
        """Queue one event for the next batch."""
        self.queue.put(envelope)

    def start(self) -> None:
        """Launch the heartbeat and sender threads. Both are daemons, so the
        adapter's own tailing loop is what keeps the process alive."""
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=self.sender_loop, daemon=True).start()

    # -- the loops ---------------------------------------------------------

    def heartbeat_loop(self) -> None:
        """Queue a heartbeat every `heartbeat_interval`, forever."""
        while True:
            self.submit(build_heartbeat(self.settings.node_id))
            time.sleep(self.settings.heartbeat_interval)

    def sender_loop(self) -> None:
        batch: list[dict] = []
        last_send = time.time()
        last_retry_attempt = time.time()

        while True:
            try:
                # Capped at a second so the two deadlines below are still
                # checked promptly on a quiet node, and never longer than the
                # flush deadline itself, which a sub-second batch_interval
                # would otherwise overshoot on every pass.
                event = self.queue.get(timeout=min(1.0, self.settings.batch_interval))
                batch.append(event)
            except queue.Empty:
                pass

            time_to_flush = (time.time() - last_send) >= self.settings.batch_interval
            batch_full = len(batch) >= BATCH_MAX_EVENTS

            if batch and (time_to_flush or batch_full):
                self.send_batch(batch)
                batch = []
                last_send = time.time()

            # Separately from normal batching: every retry_interval, check if
            # there's a backlog of previously-failed events sitting on disk,
            # and retry them.
            if (time.time() - last_retry_attempt) >= self.settings.retry_interval:
                pending = self.load_and_clear_pending()
                if pending:
                    print(f"Retrying {len(pending)} pending event(s)")
                    self.send_batch(pending)
                last_retry_attempt = time.time()

    # -- the wire ----------------------------------------------------------

    def send_batch(self, batch: list[dict]) -> None:
        headers = {
            "Content-Type": "application/json",
            "X-Node-ID": self.settings.node_id,
            "X-Node-Key": self.settings.node_key,
        }
        payload = {"events": batch}

        try:
            response = requests.post(
                self.settings.collector_url, json=payload, headers=headers, timeout=5
            )
            print(
                f"Sent {len(batch)} event(s) — collector responded: "
                f"{response.status_code} {response.text}"
            )
        except requests.exceptions.RequestException as e:
            print(
                f"Failed to send batch of {len(batch)}: {e} "
                f"— saving to {self.settings.pending_file}"
            )
            self.save_pending(batch)

    # -- the spool ---------------------------------------------------------

    def save_pending(self, batch: list[dict]) -> None:
        """Append failed events to disk so they survive even if the script crashes."""
        with open(self.settings.pending_file, "a") as f:
            for event in batch:
                f.write(json.dumps(event) + "\n")

    def load_and_clear_pending(self) -> list[dict]:
        """Read any events saved from a previous failure, then clear the file."""
        path = self.settings.pending_file
        if not os.path.exists(path):
            return []

        with open(path, "r") as f:
            lines = f.readlines()

        events = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # skip corrupted lines rather than crash

        os.remove(path)
        return events
