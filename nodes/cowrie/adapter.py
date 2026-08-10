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
LOG_PATH = os.environ.get("LOG_PATH", "./cowrie-logs/cowrie.json")
PROTOCOL = os.environ.get("PROTOCOL", "ssh")

COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://localhost:8000/api/events")
NODE_KEY = os.environ.get("NODE_KEY", "dev-test-key")

event_queue = queue.Queue()

PENDING_FILE = "pending_events.jsonl"


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


# Every interval this adapter runs on, in seconds, so a sensor can be retuned
# without editing code. The defaults are the values these loops were hardcoded
# to, so a node that sets none of them behaves exactly as it did before.

# How long the tailer waits before looking at the log again when it has nothing
# new — and therefore how quickly a rotation, or a log that hasn't been created
# yet, is noticed.
POLL_INTERVAL_SECONDS = env_seconds("POLL_INTERVAL_SECONDS", 1.0)

# How often a heartbeat is queued. This one is a Baseline v1.3 contract value
# rather than a local preference: the aggregator marks a node offline after
# three missed beats — NODE_OFFLINE_AFTER_SECONDS, derived from its own copy of
# this same variable in common/config.py — and the dashboard reports node health
# in missed heartbeats. Raise it here without raising it there and this node
# flaps offline between beats.
HEARTBEAT_INTERVAL_SECONDS = env_seconds("HEARTBEAT_INTERVAL_SECONDS", 60.0)

# How long a partly-filled batch waits before being sent anyway. A batch that
# reaches 20 events is sent the moment it does, whatever this says.
BATCH_INTERVAL_SECONDS = env_seconds("BATCH_INTERVAL_SECONDS", 10.0)

# How often events spooled to PENDING_FILE by a failed send are retried.
RETRY_INTERVAL_SECONDS = env_seconds("RETRY_INTERVAL_SECONDS", 30.0)

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


def open_log(path: str, from_start: bool):
    """Open Cowrie's log and position the cursor, or return None if the file
    isn't there right now.

    A missing log is a normal, temporary state — Cowrie creates cowrie.json
    when it starts, and again a moment after each rotation — so this waits for
    it instead of raising. Any other error (a wrong LOG_PATH, a directory this
    account can't read) is left to propagate: that is a misconfiguration, and
    a sensor that stops is easier to notice than one that silently tails
    nothing.
    """
    try:
        # Binary mode, so tell() is a true byte offset. On a text handle it is
        # an opaque cookie, and the truncation check below compares it against
        # the file's size.
        f = open(path, "rb")
    except FileNotFoundError:
        return None

    if from_start:
        # Every file opened after the first one was created while we were
        # watching, so all of it is new — including whatever landed between
        # the rotation and our noticing it.
        f.seek(0, os.SEEK_SET)
    else:
        # The first file we open may hold days of events that were shipped
        # long ago, by an earlier run of this adapter. Start at its end rather
        # than replaying that history at the collector.
        f.seek(0, os.SEEK_END)
    return f


def rotated_away(path: str, f) -> bool:
    """True when `path` no longer names the file `f` is holding open.

    Cowrie rotates its JSON log daily: it closes cowrie.json, renames it to
    cowrie.json.YYYY-MM-DD, and creates a new, empty cowrie.json. A rename
    disturbs nothing that already has the file open, so our handle quietly
    follows the log into its archived name — where not one more byte will ever
    be written — while every new event goes to the new file under the old
    name. Nothing fails and nothing errors; the adapter just goes deaf.

    Comparing (device, inode) is what separates the two: the archived file
    keeps its inode under its new name, and its replacement gets a new one.
    """
    try:
        st = os.stat(path)
    except FileNotFoundError:
        # Caught in the instant between the rename and the new file's
        # creation. Nothing is lost — our handle still holds every byte
        # written so far — so hold on to it until the replacement appears.
        return False

    ours = os.fstat(f.fileno())
    return (st.st_dev, st.st_ino) != (ours.st_dev, ours.st_ino)


def consume_lines(f, partial: bytes) -> bytes:
    """Queue every complete line the handle has for us right now, and return
    whatever is left of a line Cowrie hasn't finished writing.

    That trailing fragment is why this carries `partial` across calls: handing
    half a line to json.loads() would drop the event once as an unparseable
    fragment, and then a second time when its remainder arrives looking like
    an unparseable line of its own.
    """
    while True:
        chunk = f.readline()
        if not chunk:
            return partial

        partial += chunk
        if not partial.endswith(b"\n"):
            # readline() returns an unterminated line only at end of file, so
            # the rest of it hasn't been written yet. Wait for it.
            return partial

        try:
            raw_event = json.loads(partial)
        except (json.JSONDecodeError, UnicodeDecodeError):
            partial = b""
            continue  # skip malformed lines rather than kill the tailer

        partial = b""
        envelope = build_envelope(raw_event)
        if envelope:
            event_queue.put(envelope)


def tail_and_process(path: str):
    """Continuously watch the log file and process new lines as they arrive,
    following it across Cowrie's rotation of the file."""

    f = None
    from_start = False
    partial = b""
    waiting = False

    while True:
        if f is None:
            f = open_log(path, from_start)
            if f is None:
                if not waiting:
                    print(f"Waiting for {path} — Cowrie hasn't created it yet")
                    waiting = True
                # Whatever Cowrie creates from here on is new by definition,
                # so read it from the top instead of skipping to its end.
                from_start = True
                time.sleep(POLL_INTERVAL_SECONDS)
                continue
            waiting = False
            print(f"Tailing {path}")

        partial = consume_lines(f, partial)

        # We're at the end of this file *as it stands*, which means either "no
        # new events yet" or "this file stopped being the log". A handle alone
        # cannot tell those apart — hence the check.
        if rotated_away(path, f):
            # Drain before switching: Cowrie may have written lines between
            # our last read and the rename. The rename is its final act on
            # this file, so what's left in it is complete and will not grow.
            partial = consume_lines(f, partial)
            # A fragment still standing after that drain is a line Cowrie
            # never finished. Its file is closed for good, so let it go.
            partial = b""
            f.close()
            f = None
            from_start = True
            print(f"{path} was rotated away — reopening")
            continue

        # Same file, but now shorter than the offset we're reading from: it
        # was emptied in place rather than renamed, so the identity check
        # above sees nothing wrong. Cowrie's own rotation renames, but a
        # logrotate rule with `copytruncate` does this instead.
        if os.fstat(f.fileno()).st_size < f.tell():
            print(f"{path} was truncated — reading it again from the start")
            f.seek(0, os.SEEK_SET)
            partial = b""
            continue

        time.sleep(POLL_INTERVAL_SECONDS)


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
    """Runs forever in its own thread, queueing a heartbeat every
    HEARTBEAT_INTERVAL_SECONDS."""
    while True:
        envelope = build_heartbeat()
        event_queue.put(envelope)
        time.sleep(HEARTBEAT_INTERVAL_SECONDS)


def sender_loop():
    batch = []
    last_send = time.time()
    last_retry_attempt = time.time()

    while True:
        try:
            # Capped at a second so the two deadlines below are still checked
            # promptly on a quiet node, and never longer than the flush
            # deadline itself, which a sub-second BATCH_INTERVAL_SECONDS would
            # otherwise overshoot on every pass.
            event = event_queue.get(timeout=min(1.0, BATCH_INTERVAL_SECONDS))
            batch.append(event)
        except queue.Empty:
            pass

        time_to_flush = (time.time() - last_send) >= BATCH_INTERVAL_SECONDS
        batch_full = len(batch) >= 20

        if batch and (time_to_flush or batch_full):
            send_batch(batch)
            batch = []
            last_send = time.time()

        # Separately from normal batching: every RETRY_INTERVAL_SECONDS, check
        # if there's a backlog of previously-failed events sitting on disk, and
        # retry them.
        if (time.time() - last_retry_attempt) >= RETRY_INTERVAL_SECONDS:
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
