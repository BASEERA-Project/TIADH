#!/usr/bin/env python3
"""
integration_examples/part1_shipper.py — for whoever has Part 1.

Tails Cowrie's JSON log, translates each line into the Baseline v1.3 envelope,
and POSTs batches to the collector. Cowrie itself is never modified.

Three details here are the difference between a shipper that works and one that
quietly corrupts the dataset:

1. **Namespaced session IDs.** Cowrie session IDs are short hex strings and are
   not unique across machines; `session_id` is a primary key. `node-01:a1b2c3d4`.
2. **Deterministic event IDs.** If the shipper dies after POSTing but before
   marking a line as sent, a random UUID regenerates on restart and the collector
   accepts the same event twice. Deduplication only works if the same source line
   always yields the same id.
3. **login_attempt on success too.** The v1.3 `login_success` envelope carries
   only `username`, so a cracked credential pair would be lost and the brute
   force counter would miss the attempt that actually worked. Emitting the
   attempt first fixes both without touching the frozen contract.

    python integration_examples/part1_shipper.py --log /opt/cowrie/var/log/cowrie/cowrie.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.validation import deterministic_event_id, normalize_timestamp, validate_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s  shipper: %(message)s")
log = logging.getLogger("part1")

# ---------------------------------------------------------------------------
# Cowrie eventid -> Baseline v1.3 event_type, plus the details mapping
# ---------------------------------------------------------------------------

def translate(line: dict, node_id: str, counter: int) -> dict | list[dict] | None:
    """Convert one Cowrie JSON log line into one or more v1.3 events."""
    cowrie_id = line.get("eventid")
    session = line.get("session")
    if not cowrie_id or not session:
        return None

    session_id = f"{node_id}:{session}"           # (1) namespaced
    timestamp = normalize_timestamp(line["timestamp"])
    src_ip = line.get("src_ip")
    protocol = line.get("protocol", "ssh")

    def build(event_type: str, details: dict, marker: str) -> dict:
        return {
            "event_id": deterministic_event_id(node_id, session_id, timestamp, marker),  # (2)
            "node_id": node_id,
            "event_type": event_type,
            "timestamp": timestamp,
            "session_id": session_id,
            "attacker_ip": src_ip,
            "protocol": protocol,
            "details": details,
        }

    marker = f"{cowrie_id}#{counter}"

    if cowrie_id == "cowrie.session.connect":
        return build("connection", {
            "destination_ip": line.get("dst_ip"),
            "destination_port": line.get("dst_port"),
            "source_port": line.get("src_port"),
        }, marker)

    if cowrie_id == "cowrie.login.failed":
        return build("login_attempt", {
            "username": line.get("username"),
            "password": line.get("password"),
        }, marker)

    if cowrie_id == "cowrie.login.success":
        # (3) the attempt AND the success, so the credential pair survives
        return [
            build("login_attempt",
                  {"username": line.get("username"), "password": line.get("password")},
                  marker + "a"),
            build("login_success", {"username": line.get("username")}, marker + "b"),
        ]

    if cowrie_id in ("cowrie.command.input", "cowrie.command.failed"):
        return build("command", {"command": line.get("input")}, marker)

    if cowrie_id == "cowrie.session.file_download":
        return build("file_download", {
            "download_url": line.get("url"),
            "file_hash": line.get("shasum"),
            "file_name": (line.get("destfile") or line.get("outfile") or "").split("/")[-1] or None,
        }, marker)

    if cowrie_id == "cowrie.session.closed":
        return build("session_end", {
            "status": "closed",
            "duration_seconds": int(float(line.get("duration", 0))),
        }, marker)

    return None                                   # Cowrie emits plenty we ignore


def heartbeat(node_id: str, agent_version: str = "1.0.0") -> dict:
    from db.validation import utc_now
    now = utc_now()
    return {
        "event_id": deterministic_event_id(node_id, None, now, "heartbeat"),
        "node_id": node_id,
        "event_type": "heartbeat",
        "timestamp": now,
        "session_id": None,
        "attacker_ip": None,
        "protocol": None,
        "details": {"status": "online", "agent_version": agent_version},
    }


# ---------------------------------------------------------------------------
# Shipping
# ---------------------------------------------------------------------------

class Shipper:
    def __init__(self, endpoint: str, node_id: str, node_key: str, spool: Path):
        self.endpoint, self.node_id, self.node_key = endpoint, node_id, node_key
        self.spool = spool

    def post(self, events: list[dict]) -> dict | None:
        body = json.dumps({"events": events}).encode()
        req = urllib.request.Request(
            self.endpoint, data=body, method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Node-ID": self.node_id,
                "X-Node-Key": self.node_key,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning("collector unreachable (%s); spooling %d event(s)", exc, len(events))
            self.append_spool(events)
            return None

    def append_spool(self, events: list[dict]) -> None:
        """Baseline: unsent events go to pending_events.jsonl, retried after 30s."""
        if self.spool.exists() and self.spool.stat().st_size > 50_000_000:
            log.error("spool over 50 MB — dropping oldest half to protect the disk")
            lines = self.spool.read_text().splitlines()
            self.spool.write_text("\n".join(lines[len(lines) // 2:]) + "\n")
        with self.spool.open("a", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event) + "\n")

    def drain_spool(self) -> None:
        """Deterministic IDs make this safe: re-sends land as duplicates, not doubles."""
        if not self.spool.exists() or self.spool.stat().st_size == 0:
            return
        pending = [json.loads(l) for l in self.spool.read_text().splitlines() if l.strip()]
        log.info("draining %d spooled event(s)", len(pending))
        self.spool.unlink()
        for i in range(0, len(pending), 20):
            self.post(pending[i:i + 20])

    def send(self, events: list[dict]) -> None:
        """Validate locally first — an event that fails here fails at the collector too."""
        good = []
        for event in events:
            ok, errors = validate_event(event)
            if ok:
                good.append(event)
            else:
                log.error("dropping malformed event %s: %s", event.get("event_id"), errors)
        if good:
            self.post(good)


def main() -> None:
    parser = argparse.ArgumentParser(description="Cowrie -> Baseline v1.3 shipper")
    parser.add_argument("--log", default="/opt/cowrie/var/log/cowrie/cowrie.json")
    parser.add_argument("--node-id", default=os.getenv("NODE_ID", "node-01"))
    parser.add_argument("--endpoint", default=os.getenv("COLLECTOR_URL",
                                                        "https://CENTRAL-SERVER/api/events"))
    parser.add_argument("--spool", default="pending_events.jsonl")
    parser.add_argument("--once", action="store_true", help="process the file and exit")
    args = parser.parse_args()

    key = os.getenv("NODE_KEY")
    if not key:
        sys.exit("NODE_KEY is not set. Never hard-code it, never commit it.")

    shipper = Shipper(args.endpoint, args.node_id, key, Path(args.spool))
    shipper.drain_spool()

    batch, counter, last_flush, last_heartbeat = [], 0, time.time(), 0.0
    with open(args.log, encoding="utf-8") as handle:
        if not args.once:
            handle.seek(0, 2)                     # tail from the end
        while True:
            line = handle.readline()
            if line.strip():
                counter += 1
                try:
                    translated = translate(json.loads(line), args.node_id, counter)
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    log.warning("unparseable Cowrie line: %s", exc)
                    translated = None
                if translated:
                    batch.extend(translated if isinstance(translated, list) else [translated])
            elif args.once:
                break
            else:
                time.sleep(0.2)

            now = time.time()
            if len(batch) >= 20 or (batch and now - last_flush >= 10):   # baseline batching
                shipper.send(batch)
                batch, last_flush = [], now
            if now - last_heartbeat >= 60:                               # baseline heartbeat
                shipper.send([heartbeat(args.node_id)])
                last_heartbeat = now

    if batch:
        shipper.send(batch)


if __name__ == "__main__":
    main()
