"""
backfill.py — ship the events already sitting in a honeypot's logs.

The live adapter starts at the *end* of the current log and never looks at the
rotated files beside it, which is what stops a restart from replaying history
at the collector. The cost of that rule is everything the honeypot recorded
before this sensor was wired up, or while the adapter was stopped: it sits on
disk and never reaches the aggregator. This sends it.

Safe to run twice. Event ids are derived from the event itself rather than
generated fresh, so a second run sends the same ids and the collector answers
`duplicates`, not a second copy of every session.

Each node's `backfill.py` is a few lines that hand `main()` its Settings and its
mapper — the same two the adapter uses — so the two cannot drift apart.
"""

from __future__ import annotations

import argparse
import glob
import gzip
import json
import os
import uuid
from datetime import datetime, timezone
from ipaddress import ip_address

import requests

from . import validator
from .run import Mapper
from .settings import Settings
from .ship import BATCH_MAX_EVENTS


def log_files(log_path: str, patterns: list[str]) -> list[str]:
    """Every log to read, oldest first.

    Rotated logs are named after the live one — `cowrie.json.2026-08-06`,
    `dionaea.json.1`, `dionaea.json.2.gz` — so sorting the suffixes puts them in
    order, and the live log, which has no suffix, belongs at the end as the
    newest of them.

    That ordering is right for date suffixes and for a `logrotate` numbering
    where a *higher* number is older; it is only cosmetic either way, because
    every event carries its own timestamp and the collector does not care what
    order a batch arrives in.
    """
    if patterns:
        paths = [p for pattern in patterns for p in glob.glob(pattern)]
    else:
        paths = glob.glob(log_path + "*")

    base = os.path.basename(log_path)

    def chronological(path: str):
        suffix = os.path.basename(path)[len(base):].lstrip(".")
        return (suffix == "", suffix)  # unsuffixed live log last, archives by name

    return sorted(set(paths), key=chronological)


def read_lines(path: str):
    """Yield raw lines, transparently decompressing an archive logrotate gzipped."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rb") as f:
        yield from f


def stable_event_id(node_id: str, raw_event: dict, index: int) -> str:
    """A UUID derived from the event itself, so that re-running this script
    produces the same id and the collector recognises the event as one it
    already has. Sorted keys and no whitespace, so that the id depends on what
    the honeypot recorded and not on how it happened to lay the JSON out.

    `index` distinguishes the events a single line can expand into — dionaea's
    log_json writes one record per *connection*, which becomes a connection, a
    login attempt or two and a session end. Without it they would all collapse
    to one id and only the first would ever be stored.

    Two byte-identical lines expanding to the same index would collapse to one
    event here. They would have to share a session, a microsecond timestamp and
    every other field — at which point they are the same event logged twice,
    and one row is right.
    """
    canonical = json.dumps(raw_event, sort_keys=True, separators=(",", ":"))
    seed = f"tiadh-backfill://{node_id}/{index}/{canonical}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def contract_problems(envelope: dict) -> list[str]:
    """Every reason the collector would refuse this event. Empty list = fine.

    Worth the duplication, because the collector validates the *whole batch*
    with pydantic before it touches the database: one bad event 422s the entire
    POST and loses every good event travelling with it. Tailing live that costs
    at most one batch, and the next batch is along in ten seconds. Backfilling
    months of logs it would throw away twenty events for each empty command an
    attacker ever typed — so they are filtered here instead of being discovered
    at the far end.

    This mirrors core/collector/app/models.py, which a sensor host cannot
    import: another machine, another uv project. It is the same reason this
    package carries its own validator.py, whose baseline rules are reused below
    rather than repeated.
    """
    problems = validator.validate_event(envelope)

    timestamp = envelope.get("timestamp")
    try:
        datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        problems.append(f"timestamp {timestamp!r} is not ISO 8601")

    event_type = envelope.get("event_type")
    details = envelope.get("details")
    if not isinstance(details, dict):
        return problems  # validate_event already said so

    if event_type != "heartbeat":
        for field in ("session_id", "attacker_ip", "protocol"):
            if not envelope.get(field):
                problems.append(f"{field} is required for {event_type}")

        attacker_ip = envelope.get("attacker_ip")
        if attacker_ip:
            try:
                ip_address(attacker_ip)
            except ValueError:
                problems.append(f"attacker_ip {attacker_ip!r} is not an IP address")

    # Fields the collector insists are present *and* non-empty, which a
    # honeypot does not guarantee: an attacker who presses Enter logs an empty
    # command.
    required = {
        "login_attempt": ("username",),
        "command": ("command",),
        "session_end": ("status",),
    }
    for key in required.get(event_type, ()):
        value = details.get(key)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"details.{key} must be a non-empty string for {event_type}")

    if event_type == "file_download" and not (details.get("download_url") or details.get("file_hash")):
        problems.append("file_download needs details.download_url or details.file_hash")

    return problems


def send(settings: Settings, batch: list[dict]) -> tuple[int, int, int]:
    """POST one batch and return (accepted, duplicates, rejected).

    Unlike the adapter's sender this does not spool a failure to
    pending_events.jsonl. A backfill that cannot reach the collector should
    stop and be run again once it can — which costs nothing, because the ids
    are stable — rather than quietly hand thousands of events to the adapter's
    retry queue.
    """
    response = requests.post(
        settings.collector_url,
        json={"events": batch},
        headers={
            "Content-Type": "application/json",
            "X-Node-ID": settings.node_id,
            "X-Node-Key": settings.node_key,
        },
        timeout=30,  # generous: a backfill batch may land mid-housekeeping
    )
    if response.status_code != 200:
        raise SystemExit(
            f"\nCollector answered {response.status_code}: {response.text}\n"
            f"Nothing was lost — fix it and run this again, the ids are stable."
        )

    body = response.json()
    return body.get("accepted", 0), body.get("duplicates", 0), body.get("rejected", 0)


def parse_since(value: str) -> datetime:
    """--since, as an aware UTC datetime. A bare date means midnight UTC."""
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        raise SystemExit(
            f"--since {value!r} is not ISO 8601 (try 2026-08-07 or 2026-08-07T12:00:00Z)"
        )
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment


def within_since(timestamp: str, since: datetime) -> bool:
    """Whether an event falls inside the --since window.

    A timestamp that won't parse counts as inside it, so that the one place
    that reports a malformed event is contract_problems() below — rather than
    this comparison killing the run over a corrupt line. A naive timestamp is
    read as UTC, because comparing one to an aware --since raises instead of
    answering.
    """
    try:
        moment = datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        return True
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment >= since


def main(
    settings: Settings,
    build_envelopes: Mapper,
    *,
    description: str,
    log_description: str,
) -> None:
    """The whole backfill run. Called by each node's three-line `backfill.py`."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "files", nargs="*",
        help=f"log files to read (globs allowed). Default: every {log_description}.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="read and check everything, send nothing.",
    )
    parser.add_argument(
        "--since", type=parse_since, metavar="TIMESTAMP",
        help="skip events older than this, e.g. 2026-08-07 or 2026-08-07T12:00:00Z. "
             "Use it to avoid re-sending what a running adapter already shipped.",
    )
    parser.add_argument(
        "--batch-size", type=int, default=BATCH_MAX_EVENTS, metavar="N",
        help=f"events per POST (default {BATCH_MAX_EVENTS}). The collector "
             f"refuses anything above its own MAX_BATCH_SIZE.",
    )
    args = parser.parse_args()

    paths = log_files(settings.log_path, args.files)
    if not paths:
        raise SystemExit(
            f"No log files found. Looked for {settings.log_path}* — is LOG_PATH right, "
            f"and are you running this from the sensor's directory?"
        )

    print(f"Node {settings.node_id} → {settings.collector_url}")
    if args.dry_run:
        print("Dry run: nothing will be sent.\n")

    batch: list[dict] = []
    seen: set[str] = set()
    totals = {"lines": 0, "skipped_type": 0, "old": 0, "repeat": 0, "unparseable": 0}
    problems_by_reason: dict[str, int] = {}
    accepted = duplicates = rejected = queued = 0

    def flush() -> None:
        nonlocal batch, accepted, duplicates, rejected
        if not batch or args.dry_run:
            batch = []
            return
        got = send(settings, batch)
        accepted += got[0]
        duplicates += got[1]
        rejected += got[2]
        batch = []

    for path in paths:
        events_here = 0
        for line in read_lines(path):
            if not line.strip():
                continue
            totals["lines"] += 1

            try:
                raw_event = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                totals["unparseable"] += 1
                continue

            # A line can be valid JSON without being an event — a bare number
            # left behind by a half-written or hand-edited archive parses fine
            # and then has no .get() to give the mapper.
            if not isinstance(raw_event, dict):
                totals["unparseable"] += 1
                continue

            envelopes = list(build_envelopes(raw_event))
            if not envelopes:
                totals["skipped_type"] += 1  # nothing in this line we ship
                continue

            for index, envelope in enumerate(envelopes):
                # The one field a mapper deliberately leaves off, because here
                # it must not come from the adapter's uuid4.
                envelope["event_id"] = stable_event_id(settings.node_id, raw_event, index)

                if args.since is not None and not within_since(envelope["timestamp"], args.since):
                    totals["old"] += 1
                    continue

                if envelope["event_id"] in seen:
                    totals["repeat"] += 1  # the same line in two files
                    continue
                seen.add(envelope["event_id"])

                problems = contract_problems(envelope)
                if problems:
                    for problem in problems:
                        problems_by_reason[problem] = problems_by_reason.get(problem, 0) + 1
                    continue

                batch.append(envelope)
                events_here += 1
                queued += 1
                if len(batch) >= args.batch_size:
                    flush()

        print(f"  {path}: {events_here} event(s)")

    flush()

    print(f"\n{totals['lines']} line(s) read from {len(paths)} file(s)")
    print(f"  {totals['skipped_type']} held nothing we ship")
    if totals["unparseable"]:
        print(f"  {totals['unparseable']} unparseable")
    if totals["old"]:
        print(f"  {totals['old']} older than --since")
    if totals["repeat"]:
        print(f"  {totals['repeat']} already seen in an earlier file")
    if problems_by_reason:
        total_bad = sum(problems_by_reason.values())
        print(f"  {total_bad} the collector would have refused, and taken their batch down with them:")
        for reason, count in sorted(problems_by_reason.items(), key=lambda item: -item[1]):
            print(f"      {count:5d}  {reason}")

    if args.dry_run:
        print(f"\n{queued} event(s) would be sent. Re-run without --dry-run to send them.")
    else:
        print(f"\n{queued} event(s) sent — collector accepted {accepted}, "
              f"{duplicates} already had, {rejected} refused")
        if duplicates and not accepted:
            print("Everything was already there. This backfill had nothing new to add.")
