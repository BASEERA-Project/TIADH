#!/usr/bin/env python3
"""
integration_examples/part2_collector.py — for whoever has Part 2.

A complete, working implementation of `POST /api/events`. This is not
pseudocode: it runs, and the pipeline demo drives real HTTP traffic through it.

The point to notice is how little there is. Every hard problem — validation,
deduplication, out-of-order sessions, node last-seen tracking — is one call to
`db.apply_events()`. Part 2's real job is authentication, HTTP plumbing, and the
background maintenance loop.

    pip install flask
    python integration_examples/part2_collector.py

    curl -X POST http://127.0.0.1:8443/api/events \
         -H 'Content-Type: application/json' \
         -H 'X-Node-ID: node-01' -H 'X-Node-Key: dev-key-node-01' \
         -d '{"events": [ ... ]}'
"""

from __future__ import annotations

import hmac
import logging
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, jsonify, request

from db.database import Database

logging.basicConfig(level=logging.INFO, format="%(asctime)s  collector: %(message)s")
log = logging.getLogger("part2")

app = Flask(__name__)

# One Database handle for the whole process. It is thread-safe (a connection per
# thread) so it can be shared across Flask workers.
db = Database()

# ---------------------------------------------------------------------------
# Authentication
#
# Load per-node keys from the environment; never from source, never from Git.
#   export NODE_KEY_NODE_01='...'
# ---------------------------------------------------------------------------

NODE_KEYS = {
    node: os.getenv(f"NODE_KEY_{node.upper().replace('-', '_')}", f"dev-key-{node}")
    for node in ("node-01", "node-02", "node-03")
}

MAX_BATCH = 100          # baseline says 20; leave headroom, refuse the absurd
MAX_BODY_BYTES = 1_000_000


def authenticate(headers) -> str | None:
    """Return the node id when the credentials are valid, else None."""
    node_id = headers.get("X-Node-ID")
    node_key = headers.get("X-Node-Key")
    expected = NODE_KEYS.get(node_id or "")
    if not expected or not node_key:
        return None
    # Constant-time: a plain == leaks key material through response timing.
    return node_id if hmac.compare_digest(node_key, expected) else None


# ---------------------------------------------------------------------------
# The endpoint
# ---------------------------------------------------------------------------

@app.post("/api/events")
def receive_events():
    node_id = authenticate(request.headers)
    if not node_id:
        log.warning("rejected unauthenticated POST from %s", request.remote_addr)
        return jsonify({"error": "unauthorized"}), 401

    if request.content_length and request.content_length > MAX_BODY_BYTES:
        return jsonify({"error": "payload too large"}), 413

    payload = request.get_json(silent=True) or {}
    events = payload.get("events")
    if not isinstance(events, list):
        return jsonify({"error": "body must be {\"events\": [...]}"}), 400
    if len(events) > MAX_BATCH:
        return jsonify({"error": f"batch too large (max {MAX_BATCH})"}), 413

    # A node may only speak for itself, even with a valid key.
    foreign = [e for e in events if isinstance(e, dict) and e.get("node_id") != node_id]
    if foreign:
        return jsonify({"error": "batch contains events for another node_id"}), 403

    # ---- everything hard happens here -------------------------------------
    result = db.apply_events(events)
    # -----------------------------------------------------------------------

    log.info(
        "%s: %d accepted, %d duplicate, %d rejected",
        node_id, result["accepted"], result["duplicates"], result["rejected"],
    )
    return jsonify(result), 200


@app.get("/api/health")
def health():
    """Liveness probe; also handy for the dashboard's node panel."""
    return jsonify({"status": "ok", "nodes": db.get_nodes()}), 200


# ---------------------------------------------------------------------------
# Background maintenance
#
# Part 4 supplies the functions; Part 2 owns the timer. Without this, nodes stay
# 'online' forever after they die and the dashboard's active-session count only
# ever grows.
# ---------------------------------------------------------------------------

def maintenance_loop(interval_seconds: int = 60) -> None:
    worker_db = Database()                       # this thread's own handle
    while True:
        try:
            offline = worker_db.mark_stale_nodes_offline()
            stale = worker_db.close_stale_sessions()
            if offline or stale:
                log.info("maintenance: %d node(s) offline, %d session(s) closed", offline, stale)
        except Exception:
            log.exception("maintenance pass failed")
        time.sleep(interval_seconds)


def main() -> None:
    db.initialize_schema()                       # idempotent; safe on every boot
    threading.Thread(target=maintenance_loop, daemon=True).start()
    # Behind nginx/Caddy for real TLS in deployment; the baseline requires HTTPS.
    app.run(host="127.0.0.1", port=8443, threaded=True)


if __name__ == "__main__":
    main()
