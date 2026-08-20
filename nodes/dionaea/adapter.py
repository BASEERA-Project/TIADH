"""
adapter.py — the dionaea half of a sensor.

Everything that is not about dionaea — tailing the log across rotation,
batching, heartbeating, spooling a failed POST and retrying it — lives in the
`shipper` package, shared with the Cowrie sensor next door. What is left here
is the mapping from dionaea's own JSON onto the Baseline v1.3 envelope.

    cp .env.example .env        # fill in COLLECTOR_URL and NODE_KEY
    uv run adapter.py

Dionaea can write two different JSON logs and this reads either, deciding per
line, because a sensor should not break because someone enabled the other one:

  log_incident  →  dionaea_incident.json  — one line per *incident*, each
                   carrying the connection it belongs to and a stable id for
                   it. The recommended source: it is the only one that reports
                   captured malware, and the only one where each event has its
                   own timestamp.
  log_json      →  dionaea.json           — one line per *connection*, written
                   when that connection closes, with its credentials and FTP
                   commands folded in. Widely deployed, but it carries no
                   downloads, no connection id, and one timestamp for the whole
                   connection.

See README.md for which to enable and why.
"""

import hashlib
from datetime import datetime
from ipaddress import ip_address

from shipper import load_settings, run_sensor

# NODE_ID must appear in the collector's KNOWN_NODES, and NODE_KEY must match
# that node's entry in the collector's NODE_KEYS_JSON. Both come from the .env
# beside this file (see .env.example) so the same script runs on every sensor.
SETTINGS = load_settings(
    __file__,
    default_node_id="node-03",
    default_log_path="./dionaea-logs/dionaea_incident.json",
)

# --------------------------------------------------------------------------
# Protocols
# --------------------------------------------------------------------------

# Dionaea names the service that accepted a connection after the class that
# implements it, so these are the strings it really writes — verified against
# dionaea 0.11.0 rather than guessed, which is why the casing is uneven
# ('SipSession', 'Memcache', 'TftpServerHandler').
#
# Baseline v1.3 allows four protocols and no more: `sessions.protocol` is a
# CHECK constraint in the frozen schema, so an event naming anything else is
# refused by the aggregator however well-formed the rest of it is. Two of those
# four — ftp and smb — are in the contract precisely because dionaea was always
# the planned second sensor, and these are they.
#
# Everything else dionaea speaks is listed in UNMAPPED_PROTOCOLS below, and
# named at startup, rather than dropped quietly.
PROTOCOL_MAP = {
    "ftpd": "ftp",
    "smbd": "smb",
}

# The rest of dionaea's services, kept here so that startup can name what this
# sensor is leaving on the floor instead of reporting silence. Widening the
# baseline's protocol set is a team decision, not this file's.
UNMAPPED_PROTOCOLS = (
    "httpd", "mysqld", "mssqld", "SipSession", "TftpServerHandler", "upnpd",
    "mqttd", "Memcache", "mongod", "printerd", "pptpd", "epmapper", "blackhole",
    # dionaea's own outbound fetches and its FTP data channels. These are not
    # attacker connections even when their protocol maps, so they stay out.
    "ftpctrl", "ftpdata", "ftpdatacon", "mirrorc", "mirrord",
)

# --------------------------------------------------------------------------
# log_incident origins → our event types
# --------------------------------------------------------------------------

# Only inbound connections belong here. dionaea reports its own listening
# sockets (`...connection.tcp.listen`) and the outbound connections it makes to
# fetch a payload (`...connect`) through the same incidents, and neither is an
# attacker touching this host.
CONNECTION_ORIGINS = {
    "dionaea.connection.tcp.accept",
    "dionaea.connection.tls.accept",
    "dionaea.connection.tcp.reject",
}

LOGIN_ORIGINS = {
    "dionaea.modules.python.ftp.login",
    "dionaea.modules.python.mysql.login",
    "dionaea.modules.python.mssql.login",
}

# Where each module keeps the thing an attacker actually typed. dionaea gives
# every module its own field names, so this is a lookup rather than a rule.
COMMAND_ORIGINS = {
    "dionaea.modules.python.ftp.command": ("command", "arguments"),
    "dionaea.modules.python.mssql.cmd": ("cmd", None),
    "dionaea.modules.python.mysql.command": ("command", "args"),
    "dionaea.modules.python.sip.command": ("method", None),
    "dionaea.modules.python.mqtt.publish": ("publishtopic", "publishmessage"),
    "dionaea.modules.python.mqtt.subscribe": ("subscribetopic", None),
}

# `dionaea.download.offer` is a URL an exploit told dionaea to fetch;
# `...complete.hash` is the file it got, with the md5 it stored it under. Both
# are worth having and they are different facts.
#
# `...complete.unique` and `...complete.again` are the same download reported a
# second time, split by whether the file was new to this sensor. Shipping them
# would double every capture.
DOWNLOAD_ORIGINS = {
    "dionaea.download.offer",
    "dionaea.download.complete.hash",
}

SESSION_END_ORIGIN = "dionaea.connection.free"

#: FTP sends the password in the clear as an ordinary command, so the argument
#: of this one never leaves the sensor. It is already carried, masked at the
#: far end, by the login_attempt event the same connection produces —
#: `details.command` has no masking anywhere in the pipeline, and a password
#: that lands there would be shown on the dashboard and published in the feed.
SECRET_COMMANDS = {"PASS"}

MASKED = "***REDACTED***"

# --------------------------------------------------------------------------
# State: what a session started at, so its end can carry a duration
# --------------------------------------------------------------------------

#: session_id → the timestamp its connection was accepted at. Filled by the
#: connection event and spent by the session_end that follows it. Only the
#: incident log gets this far: log_json writes one record per connection and
#: dates the whole thing by when it opened, so there is no end time to subtract
#: from.
_session_starts: dict[str, str] = {}

#: A connection dionaea never frees — a listening socket, or one still open
#: when this adapter is restarted — would otherwise sit in that dict forever.
MAX_TRACKED_SESSIONS = 10_000

#: What has been skipped since the last summary. A sensor dropping most of what
#: it reads must not look the same as a quiet one.
skipped_protocols: dict[str, int] = {}
skipped_origins: dict[str, int] = {}


def to_utc_z(timestamp) -> str | None:
    """Give a dionaea timestamp the UTC marker the baseline requires.

    Both of dionaea's JSON handlers stamp their records with
    `datetime.utcnow().isoformat()`, which is UTC but does not say so:
    '2026-08-20T08:34:23.301675'. The aggregator's validator matches
    `...Z`-suffixed timestamps only, so without this every event is refused as
    'timestamp must be ISO 8601 UTC' — and, worse, anything that did get
    through would be compared as a string against timestamps that do have the
    Z, which sorts them wrongly.
    """
    if not isinstance(timestamp, str) or not timestamp:
        return None
    if timestamp.endswith("Z"):
        return timestamp
    if len(timestamp) > 6 and timestamp[-6] in "+-" and timestamp[-3] == ":":
        return timestamp  # already carries an offset; leave it alone
    return timestamp + "Z"


def session_id_for(connection_id: str) -> str:
    """Namespace a dionaea connection id, per the schema's session_id note.

    Truncated because dionaea's id is a full sha256 and 64 characters of hex
    make an unreadable row on the Sessions screen. Sixteen leaves 64 bits,
    which no sensor will collide within its lifetime.
    """
    return f"{SETTINGS.node_id}:{connection_id[:16]}"


def usable_ip(value) -> str | None:
    """The attacker's address, or None when there isn't really one.

    A listening socket's remote address is the unspecified one, and dionaea
    reports a hostname-less connection with an empty string. Neither is an
    attacker, and both would be refused by the collector — as they should be.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = ip_address(value)
    except ValueError:
        return None
    return None if parsed.is_unspecified else value


def envelope(event_type: str, connection: dict, timestamp: str, details: dict) -> dict:
    """One Baseline v1.3 envelope, minus the `event_id` the shipper mints."""
    return {
        "node_id": SETTINGS.node_id,
        "event_type": event_type,
        "timestamp": timestamp,
        "session_id": connection["session_id"],
        "attacker_ip": connection["attacker_ip"],
        "protocol": connection["protocol"],
        "details": details,
    }


def shippable(raw_protocol, session_id: str, attacker_ip, count_skips: bool) -> dict | None:
    """Common part of both formats: is this connection one we can represent?

    Returns the fields every envelope needs, or None — having counted why —
    when the protocol is outside the baseline's four or there is no attacker
    behind the connection.
    """
    protocol = PROTOCOL_MAP.get(raw_protocol)
    if protocol is None:
        if count_skips:
            name = raw_protocol if isinstance(raw_protocol, str) else "unknown"
            skipped_protocols[name] = skipped_protocols.get(name, 0) + 1
        return None

    ip = usable_ip(attacker_ip)
    if ip is None:
        return None

    return {"session_id": session_id, "attacker_ip": ip, "protocol": protocol}


# --------------------------------------------------------------------------
# log_incident: one line per incident
# --------------------------------------------------------------------------

def from_incident(record: dict) -> list[dict]:
    """Map one `dionaea_incident.json` line onto zero or more envelopes."""
    origin = record.get("origin")
    data = record.get("data")
    if not isinstance(data, dict):
        return []

    connection_data = data.get("connection")
    if not isinstance(connection_data, dict):
        return []  # an incident with no connection has no attacker to attribute

    timestamp = to_utc_z(record.get("timestamp"))
    if timestamp is None:
        return []

    connection_id = connection_data.get("id")
    if not isinstance(connection_id, str) or not connection_id:
        return []

    # Origins we never ship are counted before the protocol is even looked at,
    # so that a dionaea flooding us with dcerpc requests is visible as that
    # rather than as a quiet sensor.
    known = (
        origin in CONNECTION_ORIGINS
        or origin in LOGIN_ORIGINS
        or origin in COMMAND_ORIGINS
        or origin in DOWNLOAD_ORIGINS
        or origin == SESSION_END_ORIGIN
    )
    if not known:
        name = origin if isinstance(origin, str) else "unknown"
        skipped_origins[name] = skipped_origins.get(name, 0) + 1
        return []

    connection = shippable(
        connection_data.get("protocol"),
        session_id_for(connection_id),
        connection_data.get("remote_ip"),
        # Count the connection once, not once per incident on it: an accept is
        # the one incident every connection has exactly one of.
        count_skips=origin in CONNECTION_ORIGINS,
    )
    if connection is None:
        return []

    if origin in CONNECTION_ORIGINS:
        _remember_start(connection["session_id"], timestamp)
        return [envelope("connection", connection, timestamp, {
            "destination_ip": connection_data.get("local_ip"),
            "destination_port": connection_data.get("local_port"),
            "source_port": connection_data.get("remote_port"),
        })]

    if origin in LOGIN_ORIGINS:
        return [envelope("login_attempt", connection, timestamp, {
            "username": data.get("username"),
            "password": data.get("password") or None,
        })]

    if origin in COMMAND_ORIGINS:
        name_key, argument_key = COMMAND_ORIGINS[origin]
        text = render_command(data.get(name_key), data.get(argument_key) if argument_key else None)
        if text is None:
            return []
        return [envelope("command", connection, timestamp, {"command": text})]

    if origin in DOWNLOAD_ORIGINS:
        return [envelope("file_download", connection, timestamp, {
            "download_url": data.get("url"),
            "file_hash": data.get("md5hash"),
            "file_name": data.get("file"),
        })]

    # SESSION_END_ORIGIN
    details = {"status": "closed"}
    duration = _duration_since_start(connection["session_id"], timestamp)
    if duration is not None:
        details["duration_seconds"] = duration
    return [envelope("session_end", connection, timestamp, details)]


# --------------------------------------------------------------------------
# log_json: one line per connection, written when it closes
# --------------------------------------------------------------------------

def from_connection_record(record: dict) -> list[dict]:
    """Map one `dionaea.json` line onto the events folded inside it."""
    connection_data = record.get("connection")
    if not isinstance(connection_data, dict):
        return []

    # dionaea records its own listening sockets and its outbound fetches in the
    # same file, distinguished only by this.
    if connection_data.get("type") not in ("accept", "reject"):
        return []

    timestamp = to_utc_z(record.get("timestamp"))
    if timestamp is None:
        return []

    attacker_ip = record.get("src_ip")
    connection = shippable(
        connection_data.get("protocol"),
        minted_session_id(record),
        attacker_ip,
        count_skips=True,
    )
    if connection is None:
        return []

    events = [envelope("connection", connection, timestamp, {
        "destination_ip": record.get("dst_ip"),
        "destination_port": record.get("dst_port"),
        "source_port": record.get("src_port"),
    })]

    for username, password in credentials(record):
        events.append(envelope("login_attempt", connection, timestamp, {
            "username": username,
            "password": password or None,
        }))

    for name, arguments in ftp_commands(record):
        text = render_command(name, arguments)
        if text is not None:
            events.append(envelope("command", connection, timestamp, {"command": text}))

    # Every event above carries the moment the connection *opened*, because
    # that is the only time in the record — this line was written when it
    # closed, but log_json does not say when that was. The session is closed
    # anyway rather than left open: an abandoned one is swept to 'failed' an
    # hour later, which would report a finished attack as a broken sensor.
    # `duration_seconds` is left out rather than sent as a zero we made up.
    events.append(envelope("session_end", connection, timestamp, {"status": "closed"}))
    return events


def minted_session_id(record: dict) -> str:
    """A session id for a format that carries none.

    Derived from the four things that identify a TCP connection plus the moment
    it opened, so the same record always yields the same id — which is what
    lets `backfill.py` re-send a log without duplicating its sessions.
    """
    seed = "|".join(str(record.get(k)) for k in ("src_ip", "src_port", "dst_ip", "dst_port", "timestamp"))
    return f"{SETTINGS.node_id}:{hashlib.sha256(seed.encode()).hexdigest()[:16]}"


def credentials(record: dict):
    """Yield (username, password) from either shape of the credentials list.

    log_json's `flat_data: true` — which ELK deployments turn on — transposes
    the list of objects into an object of lists. Reading both means a sensor
    does not silently stop reporting credentials because someone set that flag.
    """
    found = record.get("credentials")
    if isinstance(found, list):
        for entry in found:
            if isinstance(entry, dict):
                yield entry.get("username"), entry.get("password")
    elif isinstance(found, dict):
        usernames = found.get("username") or []
        passwords = found.get("password") or []
        for index, username in enumerate(usernames):
            yield username, passwords[index] if index < len(passwords) else None


def ftp_commands(record: dict):
    """Yield (command, arguments) from either shape of the FTP command list."""
    ftp = record.get("ftp")
    if not isinstance(ftp, dict):
        return
    found = ftp.get("commands")
    if isinstance(found, list):
        for entry in found:
            if isinstance(entry, dict):
                yield entry.get("command"), entry.get("arguments")
    elif isinstance(found, dict):
        names = found.get("command") or []
        arguments = found.get("arguments") or []
        for index, name in enumerate(names):
            yield name, arguments[index] if index < len(arguments) else None


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

def render_command(name, arguments) -> str | None:
    """One command as a line of text, or None if there is nothing to record.

    dionaea splits a command into a verb and its arguments, and each module
    types those differently — a list of strings for FTP, a scalar for MQTT, an
    integer opcode for MySQL. This flattens all of that into the single string
    `details.command` is defined to hold.
    """
    if name is None or name == "":
        return None
    verb = str(name)

    if verb.upper() in SECRET_COMMANDS:
        return f"{verb} {MASKED}"

    if arguments is None or arguments == "":
        return verb
    if isinstance(arguments, (list, tuple)):
        rendered = " ".join(str(a) for a in arguments if a is not None and a != "")
    else:
        rendered = str(arguments)
    return f"{verb} {rendered}".strip()


def _remember_start(session_id: str, timestamp: str) -> None:
    if len(_session_starts) >= MAX_TRACKED_SESSIONS:
        # Oldest first: a dict keeps insertion order, and a connection this far
        # back is one dionaea never told us it had closed.
        del _session_starts[next(iter(_session_starts))]
    _session_starts[session_id] = timestamp


def _duration_since_start(session_id: str, end: str) -> float | None:
    """How long the session lasted, when we saw it open. None otherwise."""
    start = _session_starts.pop(session_id, None)
    if start is None:
        return None
    try:
        began = datetime.fromisoformat(start.rstrip("Z"))
        ended = datetime.fromisoformat(end.rstrip("Z"))
    except ValueError:
        return None
    return round((ended - began).total_seconds(), 3)


def build_envelopes(raw_event: dict) -> list[dict]:
    """One dionaea JSON line in, zero or more Baseline v1.3 envelopes out.

    The format is decided per line rather than per file, so that pointing
    LOG_PATH at the other log — or at a file holding both, which a host that
    changed handlers mid-life will have — needs no configuration.
    """
    if "origin" in raw_event:
        return from_incident(raw_event)
    if isinstance(raw_event.get("connection"), dict):
        return from_connection_record(raw_event)
    return []


def summarise() -> str | None:
    """What has been skipped since the last time this was asked."""
    lines = []
    if skipped_protocols:
        total = sum(skipped_protocols.values())
        listed = ", ".join(
            f"{name} ({count})"
            for name, count in sorted(skipped_protocols.items(), key=lambda i: -i[1])[:6]
        )
        lines.append(
            f"Skipped {total} connection(s): {listed} — Baseline v1.3 allows "
            f"{sorted(set(PROTOCOL_MAP.values()))} and nothing else"
        )
        skipped_protocols.clear()
    if skipped_origins:
        total = sum(skipped_origins.values())
        listed = ", ".join(
            f"{name} ({count})"
            for name, count in sorted(skipped_origins.items(), key=lambda i: -i[1])[:4]
        )
        lines.append(f"Skipped {total} dionaea incident(s) we don't ship: {listed}")
        skipped_origins.clear()
    return "\n".join(lines) if lines else None


def describe_coverage() -> str:
    """What this sensor can and cannot report, said once at startup.

    On a dionaea node this is not decoration. Most of what an exposed honeypot
    sees arrives on ports Baseline v1.3 has no protocol value for, so a sensor
    that only printed 'Tailing ...' would look identical whether it was
    shipping everything or a tenth of it.
    """
    shipped = ", ".join(f"{name}→{value}" for name, value in sorted(PROTOCOL_MAP.items()))
    others = [p for p in UNMAPPED_PROTOCOLS if p not in PROTOCOL_MAP]
    return (
        f"Shipping {shipped}. dionaea's other {len(others)} service(s) have no "
        f"Baseline v1.3 protocol and are counted, not shipped: "
        f"{', '.join(others[:6])}, …"
    )


if __name__ == "__main__":
    print(describe_coverage())
    run_sensor(SETTINGS, build_envelopes, summarise)
