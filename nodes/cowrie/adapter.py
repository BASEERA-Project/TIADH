import json
import uuid
import time
from datetime import datetime, timezone
import threading
import os
import requests
import queue
from pathlib import Path
from dotenv import load_dotenv

# Read nodes/cowrie/.env by explicit path, not dotenv's default upward search.
# The search would walk out of this directory and, on a machine that has the
# whole repository checked out, reach the aggregator's own root .env — a
# different host's configuration entirely. A sensor is configured by the file
# next to this script or not at all.
#
# override=False (the default) leaves a real environment variable outranking
# the file, which is how common/config.py treats the aggregator's .env, and is
# what makes `NODE_KEY=... uv run adapter.py` still work.
load_dotenv(Path(__file__).with_name(".env"))

# All four come from the environment (see .env.example) so the same file runs
# on every sensor. NODE_ID must appear in the collector's KNOWN_NODES, and
# NODE_KEY must match that node's entry in the collector's NODE_KEYS_JSON.
#
# This host is a different machine from the aggregator, so it does not share
# the aggregator's .env and has no `common` package to load one — which is why
# the loading above is done here rather than inherited from `common.config`.
NODE_ID = os.environ.get("NODE_ID", "node-02")
LOG_PATH = os.environ.get("LOG_PATH", "../cowrie-logs/cowrie.json")
PROTOCOL = os.environ.get("PROTOCOL", "ssh")

COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://localhost:8000/api/events")
NODE_KEY = os.environ.get("NODE_KEY", "dev-test-key")

event_queue = queue.Queue()

PENDING_FILE = "pending_events.jsonl"

# Maps Cowrie's own event names to the baseline's allowed event_type values.
# Anything not in this dict gets skipped (Cowrie emits some internal events
# we don't care about at all, e.g. cowrie.client.version).
EVENT_TYPE_MAP = {
    "cowrie.session.connect": "connection",
    "cowrie.login.failed": "login_attempt",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "file_download",
    "cowrie.session.closed": "session_end",
}

def build_envelope(raw_event: dict) -> dict | None:
    """Convert one raw Cowrie JSON line into our shared event envelope.
    Returns None if this event type isn't one we care about."""

    cowrie_type = raw_event.get("eventid")
    event_type = EVENT_TYPE_MAP.get(cowrie_type)
    if event_type is None:
        return None  # not an event type we track — silently skip it

    # Cowrie gives timestamps already in ISO 8601 — reuse it directly.
    timestamp = raw_event.get("timestamp")

    envelope = {
        "event_id": str(uuid.uuid4()),
        "node_id": NODE_ID,
        "event_type": event_type,
        "timestamp": timestamp,
        "session_id": raw_event.get("session"),
        "attacker_ip": raw_event.get("src_ip"),
        "protocol": PROTOCOL,
        "details": build_details(event_type, raw_event),
    }
    return envelope


def build_details(event_type: str, raw_event: dict) -> dict:
    """Build the `details` object, using ONLY the keys the baseline
    allows for this specific event_type."""

    if event_type == "login_attempt":
        return {
            "username": raw_event.get("username"),
            "password": raw_event.get("password"),
        }
    elif event_type == "login_success":
        return {
            "username": raw_event.get("username"),
        }
    elif event_type == "command":
        return {
            "command": raw_event.get("input"),
        }
    elif event_type == "file_download":
        return {
            "download_url": raw_event.get("url"),
            "file_hash": raw_event.get("shasum"),
            "file_name": raw_event.get("outfile"),
        }
    elif event_type == "session_end":
        return {
            "status": "closed",
            "duration_seconds": raw_event.get("duration"),
        }
    elif event_type == "connection":
        return {
            "destination_ip": raw_event.get("dst_ip"),
            "destination_port": raw_event.get("dst_port"),
            "source_port": raw_event.get("src_port"),
        }
    return {}


def tail_and_process(path: str):
    """Continuously watch the log file and process new lines as they arrive."""
    with open(path, "r") as f:
        f.seek(0, 2)  # jump to the END of the file — we only want NEW events,
                       # not to replay everything that already happened.

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)  # nothing new yet — wait a second, check again
                continue

            try:
                raw_event = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip malformed/partial lines

            envelope = build_envelope(raw_event)
            if envelope:
                event_queue.put(envelope)  # temporary — stage 1 just prints


def build_heartbeat() -> dict:
    """Build a heartbeat envelope, per Section 2's rules: session_id,
    attacker_ip, and protocol are always null for heartbeats."""
    return {
        "event_id": str(uuid.uuid4()),
        "node_id": NODE_ID,
        "event_type": "heartbeat",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "session_id": None,
        "attacker_ip": None,
        "protocol": None,
        "details": {"status": "online"},
    }


def heartbeat_loop():
    """Runs forever in its own thread, printing a heartbeat every 60 seconds."""
    while True:
        envelope = build_heartbeat()
        event_queue.put(envelope)
        time.sleep(60)


def sender_loop():
    batch = []
    last_send = time.time()
    last_retry_attempt = time.time()

    while True:
        try:
            event = event_queue.get(timeout=1)
            batch.append(event)
        except queue.Empty:
            pass

        time_to_flush = (time.time() - last_send) >= 10
        batch_full = len(batch) >= 20

        if batch and (time_to_flush or batch_full):
            send_batch(batch)
            batch = []
            last_send = time.time()

        # Separately from normal batching: every 30s, check if there's a
        # backlog of previously-failed events sitting on disk, and retry them.
        if (time.time() - last_retry_attempt) >= 30:
            pending = load_and_clear_pending()
            if pending:
                print(f"Retrying {len(pending)} pending event(s)")
                send_batch(pending)
            last_retry_attempt = time.time()


def send_batch(batch: list):
    headers = {
        "Content-Type": "application/json",
        "X-Node-ID": NODE_ID,
        "X-Node-Key": NODE_KEY,
    }
    payload = {"events": batch}

    try:
        response = requests.post(COLLECTOR_URL, json=payload, headers=headers, timeout=5)
        print(f"Sent {len(batch)} event(s) — collector responded: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send batch of {len(batch)}: {e} — saving to {PENDING_FILE}")
        save_pending(batch)


def save_pending(batch: list):
    """Append failed events to disk so they survive even if the script crashes."""
    with open(PENDING_FILE, "a") as f:
        for event in batch:
            f.write(json.dumps(event) + "\n")


def load_and_clear_pending() -> list:
    """Read any events saved from a previous failure, then clear the file."""
    if not os.path.exists(PENDING_FILE):
        return []

    with open(PENDING_FILE, "r") as f:
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

    os.remove(PENDING_FILE)
    return events

if __name__ == "__main__":
    heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
    heartbeat_thread.start()

    sender_thread = threading.Thread(target=sender_loop, daemon=True)
    sender_thread.start()

    tail_and_process(LOG_PATH)
