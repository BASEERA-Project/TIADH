"""
validator.py — check shipped events against the shared schema.

This is the sensor-side copy of the Baseline v1.3 contract. The aggregator has
its own in `common/db/validation.py`, which a sensor host cannot import: another
machine, another uv project. Keep the two in step.

    uv run validator.py pending_events.jsonl
"""

import json

ALLOWED_EVENT_TYPES = {
    "connection", "login_attempt", "login_success",
    "command", "file_download", "session_end", "heartbeat",
}

REQUIRED_TOP_LEVEL_FIELDS = {
    "event_id", "node_id", "event_type", "timestamp",
    "session_id", "attacker_ip", "protocol", "details",
}

ALLOWED_DETAILS_KEYS = {
    "heartbeat": {"status", "agent_version"},
    "connection": {"destination_ip", "destination_port", "source_port"},
    "login_attempt": {"username", "password"},
    "login_success": {"username"},
    "command": {"command"},
    "file_download": {"download_url", "file_hash", "file_name"},
    "session_end": {"status", "duration_seconds"},
}

#: Section 1: `sessions.protocol` is a CHECK constraint on the aggregator, so a
#: protocol outside this set is refused at the far end however well-formed the
#: rest of the event is. Keep it in step with `common/db/validation.py`.
#:
#: The first four are Baseline v1.3's; the rest were added so a dionaea sensor
#: could report more than its FTP and SMB traffic.
ALLOWED_PROTOCOLS = {
    "ssh", "telnet", "ftp", "smb",
    "http", "mysql", "mssql", "sip", "tftp", "upnp",
    "mqtt", "memcache", "mongo", "printer", "pptp", "epmap",
}


def validate_event(event: dict) -> list[str]:
    """Returns a list of problems found with this event. Empty list = valid."""
    problems = []

    # 1. All 8 top-level fields must be PRESENT (even if their value is null)
    missing = REQUIRED_TOP_LEVEL_FIELDS - event.keys()
    if missing:
        problems.append(f"missing top-level field(s): {missing}")

    # 2. event_type must be one of the 7 allowed values
    event_type = event.get("event_type")
    if event_type not in ALLOWED_EVENT_TYPES:
        problems.append(f"invalid event_type: {event_type!r}")
        return problems  # can't check details rules without knowing a valid type

    # 3. protocol must be one the aggregator's schema will accept
    protocol = event.get("protocol")
    if protocol is not None and protocol not in ALLOWED_PROTOCOLS:
        problems.append(f"protocol {protocol!r} is not one of {sorted(ALLOWED_PROTOCOLS)}")

    # 4. details must exist and be a dict, never null
    details = event.get("details")
    if not isinstance(details, dict):
        problems.append(f"'details' must be an object, got: {type(details).__name__}")
        return problems

    # 5. details must contain ONLY keys allowed for this event_type
    allowed_keys = ALLOWED_DETAILS_KEYS.get(event_type, set())
    extra_keys = set(details.keys()) - allowed_keys
    if extra_keys:
        problems.append(f"'details' has disallowed key(s) for {event_type}: {extra_keys}")

    # 6. username/password must NOT appear at the top level (only inside details)
    if "username" in event or "password" in event:
        problems.append("username/password found at TOP LEVEL — must be inside 'details' only")

    return problems


def validate_file(path: str):
    with open(path, "r") as f:
        lines = f.readlines()

    total = 0
    failed = 0
    for i, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        total += 1
        event = json.loads(line)
        problems = validate_event(event)
        if problems:
            failed += 1
            print(f"Line {i}: INVALID")
            for p in problems:
                print(f"  - {p}")

    print(f"\n{total - failed}/{total} events valid")


def main():
    import sys
    validate_file(sys.argv[1])


if __name__ == "__main__":
    main()
