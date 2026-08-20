"""
adapter.py — the Cowrie half of a sensor.

Everything that is not about Cowrie — tailing cowrie.json across its daily
rotation, batching to twenty, heartbeating every 60s, spooling a failed POST to
pending_events.jsonl and retrying it — lives in the `shipper` package, shared
with the dionaea sensor next door. What is left here is the only thing that is
actually about Cowrie: turning one of its JSON lines into Baseline v1.3
envelopes.

    cp .env.example .env        # fill in COLLECTOR_URL and NODE_KEY
    uv run adapter.py
"""

import os

from shipper import load_settings, run_sensor

# NODE_ID must appear in the collector's KNOWN_NODES, and NODE_KEY must match
# that node's entry in the collector's NODE_KEYS_JSON. Both come from the .env
# beside this file (see .env.example) so the same script runs on every sensor.
SETTINGS = load_settings(
    __file__,
    default_node_id="node-02",
    default_log_path="./cowrie-logs/cowrie.json",
)

# Stamped into every event. Not in .env.example: docker-compose.yml publishes
# Cowrie's SSH port only, so the default is already right. Set PROTOCOL=telnet
# on a sensor that has enabled Cowrie's telnet listener instead.
PROTOCOL = os.environ.get("PROTOCOL", "ssh")

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

#: Cowrie event names seen and skipped, for the periodic summary. A sensor that
#: is dropping most of what it reads should say so rather than just look quiet.
skipped: dict[str, int] = {}


def build_envelopes(raw_event: dict) -> list[dict]:
    """Convert one raw Cowrie JSON line into our shared event envelope.

    Returns an empty list if this event type isn't one we care about. Cowrie
    logs one event per line, so the list is never longer than one — dionaea's
    log_json writes one record per *connection*, which is why the shared
    interface is a list at all.

    `event_id` is deliberately absent: the live adapter and backfill.py mint it
    differently, and each does it on the way past (see shipper/run.py).
    """
    cowrie_type = raw_event.get("eventid")
    event_type = EVENT_TYPE_MAP.get(cowrie_type)
    if event_type is None:
        skipped[cowrie_type] = skipped.get(cowrie_type, 0) + 1
        return []

    return [{
        "node_id": SETTINGS.node_id,
        "event_type": event_type,
        # Cowrie gives timestamps already in ISO 8601 — reuse it directly.
        "timestamp": raw_event.get("timestamp"),
        "session_id": raw_event.get("session"),
        "attacker_ip": raw_event.get("src_ip"),
        "protocol": PROTOCOL,
        "details": build_details(event_type, raw_event),
    }]


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


def summarise() -> str | None:
    """What has been skipped since the last time this was asked."""
    if not skipped:
        return None
    ranked = sorted(skipped.items(), key=lambda item: -item[1])
    total = sum(skipped.values())
    skipped.clear()
    listed = ", ".join(f"{name} ({count})" for name, count in ranked[:5])
    return f"Skipped {total} Cowrie event(s) we don't ship: {listed}"


if __name__ == "__main__":
    run_sensor(SETTINGS, build_envelopes, summarise)
