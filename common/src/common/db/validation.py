"""
db/validation.py — The Baseline v1.3 event contract, as executable code.

A contract written only in prose drifts. This module is the single machine
readable definition of Section 2 of the baseline document, and it is meant to be
imported by Part 1 (before shipping) and Part 2 (before accepting) as well as by
Part 4 (before persisting). If all three import the same validator, the three
implementations physically cannot disagree about what a valid event is.

    from db.validation import validate_event, normalize_event

    ok, errors = validate_event(evt)
    if not ok:
        reject(evt, errors)

Nothing here touches the database, so it is safe to vendor into the other parts'
repositories or to copy into a shared `common/` package.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from common.config import KNOWN_NODES, STRICT_NODE_IDS

# --------------------------------------------------------------------------
# Section 2 — allowed event types
# --------------------------------------------------------------------------

ALLOWED_EVENT_TYPES = (
    "connection",
    "login_attempt",
    "login_success",
    "command",
    "file_download",
    "session_end",
    "heartbeat",
)

#: Must stay in step with the CHECK constraint on `sessions.protocol` in
#: schema.sql — a value this allows and that one does not is an event the
#: collector accepts and then fails to store, which is the worst of the three
#: outcomes.
#:
#: The first four are Baseline v1.3's. The rest are a post-v1.3 amendment,
#: agreed so that a dionaea sensor can report more than its FTP and SMB
#: traffic; dionaea speaks all of them, and without a value to name them by
#: they could only be counted and dropped.
ALLOWED_PROTOCOLS = (
    "ssh", "telnet", "ftp", "smb",
    "http", "mysql", "mssql", "sip", "tftp", "upnp",
    "mqtt", "memcache", "mongo", "printer", "pptp", "epmap",
)

#: Every event carries every one of these keys. Absent != null.
TOP_LEVEL_FIELDS = (
    "event_id",
    "node_id",
    "event_type",
    "timestamp",
    "session_id",
    "attacker_ip",
    "protocol",
    "details",
)

#: Fields that are non-null for every event type except `heartbeat`, where the
#: baseline requires them to be explicitly null.
NULL_ONLY_FOR_HEARTBEAT = ("session_id", "attacker_ip", "protocol")

# --------------------------------------------------------------------------
# Section 2 — the `details` object contract
#   allowed:  the only keys permitted for this event type
#   required: keys that must be present AND non-null
#   any_of:   at least one of these keys must be present AND non-null
# --------------------------------------------------------------------------

DETAILS_CONTRACT: Dict[str, Dict[str, Any]] = {
    "heartbeat": {
        "allowed": {"status", "agent_version"},
        "required": {"status"},
        "any_of": set(),
    },
    "connection": {
        "allowed": {"destination_ip", "destination_port", "source_port"},
        "required": set(),
        "any_of": set(),
    },
    "login_attempt": {
        "allowed": {"username", "password"},
        "required": {"username"},          # password may legitimately be null
        "any_of": set(),
    },
    "login_success": {
        "allowed": {"username"},
        "required": set(),
        "any_of": set(),
    },
    "command": {
        "allowed": {"command"},
        "required": {"command"},
        "any_of": set(),
    },
    "file_download": {
        "allowed": {"download_url", "file_hash", "file_name"},
        "required": set(),
        "any_of": {"download_url", "file_hash"},
    },
    "session_end": {
        "allowed": {"status", "duration_seconds"},
        "required": {"status"},
        "any_of": set(),
    },
}

#: ISO 8601 UTC, seconds or fractional seconds, always Z-suffixed.
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


# --------------------------------------------------------------------------
# Time helpers
# --------------------------------------------------------------------------

def utc_now() -> str:
    """Current time as a canonical Baseline v1.3 timestamp."""
    return datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)


def utc_ago(**delta) -> str:
    """
    A canonical v1.3 timestamp N units in the past, e.g. ``utc_ago(hours=24)``.

    Time windows are built here, in Python, rather than with SQLite's
    ``datetime('now', '-1 hour')``. Stored timestamps look like
    ``2026-07-28T14:31:07Z``; SQLite's formatter emits ``2026-07-28 13:31:07``.
    Compared as strings the dates match and then ``'T'`` (0x54) beats ``' '``
    (0x20), so an "in the last hour" filter silently matches everything since
    midnight. Binding a correctly-shaped string is the fix.
    """
    return (datetime.now(timezone.utc) - timedelta(**delta)).strftime(TIMESTAMP_FORMAT)


def parse_timestamp(value: str) -> datetime:
    """Parse a v1.3 timestamp into an aware UTC datetime."""
    return datetime.strptime(value.split(".")[0].rstrip("Z") + "Z", TIMESTAMP_FORMAT).replace(
        tzinfo=timezone.utc
    )


def normalize_timestamp(value: str) -> str:
    """
    Truncate fractional seconds so every stored timestamp has identical width.

    This matters more than it looks. All of Part 4's time-window queries compare
    timestamps as SQLite *strings*, which is only correct when every string has
    the same shape. Cowrie emits microseconds ('...T15:00:00.123456Z'); we drop
    them on the way in so that string ordering and real chronological ordering
    can never disagree.
    """
    return parse_timestamp(value).strftime(TIMESTAMP_FORMAT)


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def validate_event(event: Any) -> Tuple[bool, List[str]]:
    """
    Check one event against Baseline v1.3 Section 2.

    Returns ``(ok, errors)``. ``errors`` is a list of human-readable reasons,
    suitable for returning to the sending node so it can stop retrying an event
    that will never be accepted.
    """
    errors: List[str] = []

    if not isinstance(event, dict):
        return False, ["event must be a JSON object"]

    # --- 1. every top-level field must be present -------------------------
    for field in TOP_LEVEL_FIELDS:
        if field not in event:
            errors.append(f"missing top-level field '{field}' (use null, do not omit)")

    unexpected = set(event) - set(TOP_LEVEL_FIELDS)
    if unexpected:
        errors.append(
            "unexpected top-level field(s): "
            + ", ".join(sorted(unexpected))
            + " — protocol-specific keys belong inside 'details'"
        )

    if errors:
        return False, errors

    # --- 2. event_type must be known --------------------------------------
    event_type = event["event_type"]
    if event_type not in ALLOWED_EVENT_TYPES:
        return False, [f"event_type '{event_type}' is not an allowed type"]

    is_heartbeat = event_type == "heartbeat"

    # --- 3. event_id must be a real UUID ----------------------------------
    try:
        uuid.UUID(str(event["event_id"]))
    except (ValueError, AttributeError, TypeError):
        errors.append("event_id must be a valid UUID string")

    # --- 4. node_id --------------------------------------------------------
    node_id = event["node_id"]
    if not node_id:
        errors.append("node_id must be non-null")
    elif STRICT_NODE_IDS and node_id not in KNOWN_NODES:
        errors.append(f"node_id '{node_id}' is not a registered node {list(KNOWN_NODES)}")

    # --- 5. timestamp ------------------------------------------------------
    timestamp = event["timestamp"]
    if not isinstance(timestamp, str) or not TIMESTAMP_RE.match(timestamp):
        errors.append("timestamp must be ISO 8601 UTC, e.g. 2026-07-19T15:00:00Z")
    else:
        try:
            parse_timestamp(timestamp)
        except ValueError:
            errors.append(f"timestamp '{timestamp}' is not a real date/time")

    # --- 6. the three conditionally-null fields ---------------------------
    for field in NULL_ONLY_FOR_HEARTBEAT:
        value = event[field]
        if is_heartbeat and value is not None:
            errors.append(f"{field} must be null for heartbeat events")
        elif not is_heartbeat and value in (None, ""):
            errors.append(f"{field} must be non-null for '{event_type}' events")

    protocol = event["protocol"]
    if protocol is not None and protocol not in ALLOWED_PROTOCOLS:
        errors.append(f"protocol '{protocol}' is not one of {list(ALLOWED_PROTOCOLS)}")

    # --- 7. details -------------------------------------------------------
    details = event["details"]
    if details is None:
        errors.append("details must be an object, never null")
    elif not isinstance(details, dict):
        errors.append("details must be a JSON object, not " + type(details).__name__)
    else:
        errors.extend(_validate_details(event_type, details))

    return (not errors), errors


def _validate_details(event_type: str, details: Dict[str, Any]) -> List[str]:
    """Apply the per-event-type `details` contract."""
    rules = DETAILS_CONTRACT[event_type]
    errors: List[str] = []

    extra = set(details) - rules["allowed"]
    if extra:
        errors.append(
            f"details key(s) not allowed for '{event_type}': "
            + ", ".join(sorted(extra))
            + f" (allowed: {sorted(rules['allowed']) or 'none'})"
        )

    for key in sorted(rules["required"]):
        if details.get(key) in (None, ""):
            errors.append(f"details.{key} is required and must be non-null for '{event_type}'")

    if rules["any_of"] and not any(details.get(k) not in (None, "") for k in rules["any_of"]):
        errors.append(
            f"'{event_type}' requires at least one of: " + ", ".join(sorted(rules["any_of"]))
        )

    return errors


def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a copy of ``event`` in canonical storage form.

    Call this *after* :func:`validate_event` succeeds. It does not repair
    invalid events — it only makes valid ones consistent: canonical timestamp
    width, and `details` serialised to the JSON string that the `events.details`
    column expects.
    """
    normalized = dict(event)
    normalized["timestamp"] = normalize_timestamp(event["timestamp"])
    normalized["details"] = json.dumps(event["details"], ensure_ascii=False, sort_keys=True)
    return normalized


def rebase_events(events: List[Dict[str, Any]], anchor: str = None) -> List[Dict[str, Any]]:
    """
    Shift a fixture's timestamps forward so its newest event lands at ``anchor``.

    Demo data recorded last week would otherwise fall outside every alert window
    and be swept up as stale. Rebasing preserves all the relative spacing — the
    brute force still takes 35 seconds — while placing the whole narrative in the
    live window. Only used for fixtures; real events are never rewritten.
    """
    parsed = []
    for event in events:
        if not isinstance(event, dict) or not event.get("timestamp"):
            continue
        try:
            parsed.append(parse_timestamp(event["timestamp"]))
        except (ValueError, TypeError):
            continue  # deliberately-malformed fixtures must not abort the rebase

    if not parsed:
        return events
    newest = max(parsed)

    target = parse_timestamp(anchor) if anchor else datetime.now(timezone.utc).replace(
        microsecond=0
    )
    delta = target - newest

    rebased = []
    for event in events:
        copy = dict(event)
        try:
            copy["timestamp"] = (parse_timestamp(event["timestamp"]) + delta).strftime(
                TIMESTAMP_FORMAT
            )
        except (KeyError, ValueError, TypeError):
            pass  # leave deliberately-invalid timestamps untouched
        rebased.append(copy)
    return rebased


def deterministic_event_id(node_id: str, session_id: str | None, timestamp: str, marker: str) -> str:
    """
    Build a reproducible event_id.

    Offered to Part 1. If the shipper crashes after POSTing but before marking a
    log line as sent, a random UUID would be regenerated on restart and the
    collector would accept the same event twice — the dedup rule only works when
    the same source line always yields the same id.

    ``marker`` should be whatever makes the event unique inside its session,
    e.g. the Cowrie ``eventid`` plus a line counter.
    """
    seed = f"{node_id}|{session_id or ''}|{timestamp}|{marker}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
