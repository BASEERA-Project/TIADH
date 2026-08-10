"""
backfill.py — ship the events already sitting in Cowrie's logs.

adapter.py starts at the *end* of the live cowrie.json and never looks at the
rotated cowrie.json.YYYY-MM-DD files beside it, which is what stops a restart
from replaying history at the collector. The cost of that rule is everything
Cowrie recorded before this sensor was wired up, or while the adapter was
stopped: it sits on disk and never reaches the aggregator. This sends it.

    uv run backfill.py                          # every cowrie.json* on disk
    uv run backfill.py --dry-run                # say what would be sent
    uv run backfill.py --since 2026-08-07       # only events from then on
    uv run backfill.py cowrie-logs/cowrie.json.2026-08-06   # named files only

Safe to run twice. Event ids are derived from the event itself rather than
generated fresh, so a second run sends the same ids and the collector answers
`duplicates`, not a second copy of every session.

It reuses adapter.py for the parts that must not drift — the same event
mapping, the same envelope, the same .env and credentials — so a change to
either is a change to both.
"""

import argparse
import glob
import gzip
import json
import os
import uuid
from datetime import datetime, timezone
from ipaddress import ip_address

import requests

import adapter
import validator

# The collector refuses a POST carrying more than MAX_BATCH_SIZE events, which
# is 20 unless the aggregator's .env raises it. --batch-size follows it up.
DEFAULT_BATCH_SIZE = 20


def log_files(patterns: list[str]) -> list[str]:
    """Every Cowrie log to read, oldest first.

    Cowrie names its archives after the day they cover — cowrie.json.2026-08-06
    — so sorting the suffixes puts them in chronological order, and the live
    cowrie.json, which has no suffix, belongs at the end as the newest of them.
    """
    if patterns:
        paths = [p for pattern in patterns for p in glob.glob(pattern)]
    else:
        # Everything beside the log adapter.py tails: cowrie.json and each
        # cowrie.json.YYYY-MM-DD next to it.
        paths = glob.glob(adapter.LOG_PATH + "*")

    base = os.path.basename(adapter.LOG_PATH)

    def chronological(path: str):
        suffix = os.path.basename(path)[len(base):].lstrip(".")
        return (suffix == "", suffix)  # unsuffixed live log last, archives by date

    return sorted(set(paths), key=chronological)


def read_lines(path: str):
    """Yield raw lines, transparently decompressing an archive logrotate gzipped."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rb") as f:
        yield from f


def stable_event_id(raw_event: dict) -> str:
    """A UUID derived from the event itself, so that re-running this script
    produces the same id and the collector recognises the event as one it
    already has. Sorted keys and no whitespace, so that the id depends on what
    Cowrie recorded and not on how it happened to lay the JSON out.

    Two byte-identical Cowrie lines would collapse to one event here. They
    would have to share a session, a microsecond timestamp and every field —
    at which point they are the same event logged twice, and one row is right.
    """
    canonical = json.dumps(raw_event, sort_keys=True, separators=(",", ":"))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"tiadh-backfill://{adapter.NODE_ID}/{canonical}"))


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
    directory carries its own validator.py, whose baseline rules are reused
    below rather than repeated.
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

    # Fields the collector insists are present *and* non-empty, which Cowrie
    # does not guarantee: an attacker who presses Enter logs an empty command.
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


def send(batch: list[dict]) -> tuple[int, int, int]:
    """POST one batch and return (accepted, duplicates, rejected).

    Unlike adapter.send_batch this does not spool a failure to
    pending_events.jsonl. A backfill that cannot reach the collector should
    stop and be run again once it can — which costs nothing, because the ids
    are stable — rather than quietly hand thousands of events to the adapter's
    retry queue.
    """
    response = requests.post(
        adapter.COLLECTOR_URL,
        json={"events": batch},
        headers={
            "Content-Type": "application/json",
            "X-Node-ID": adapter.NODE_ID,
            "X-Node-Key": adapter.NODE_KEY,
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
        raise SystemExit(f"--since {value!r} is not ISO 8601 (try 2026-08-07 or 2026-08-07T12:00:00Z)")
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send the events already in Cowrie's logs, including rotated ones.",
    )
    parser.add_argument(
        "files", nargs="*",
        help="log files to read (globs allowed). Default: every cowrie.json* beside LOG_PATH.",
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
        "--batch-size", type=int, default=DEFAULT_BATCH_SIZE, metavar="N",
        help=f"events per POST (default {DEFAULT_BATCH_SIZE}). The collector "
             f"refuses anything above its own MAX_BATCH_SIZE.",
    )
    args = parser.parse_args()

    paths = log_files(args.files)
    if not paths:
        raise SystemExit(
            f"No log files found. Looked for {adapter.LOG_PATH}* — is LOG_PATH right, "
            f"and are you running this from nodes/cowrie?"
        )

    print(f"Node {adapter.NODE_ID} → {adapter.COLLECTOR_URL}")
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
        got = send(batch)
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
            # and then has no .get() to give build_envelope.
            if not isinstance(raw_event, dict):
                totals["unparseable"] += 1
                continue

            envelope = adapter.build_envelope(raw_event)
            if envelope is None:
                totals["skipped_type"] += 1  # a Cowrie event we never ship
                continue

            # The one field that must not come from adapter.py's uuid4.
            envelope["event_id"] = stable_event_id(raw_event)

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
    print(f"  {totals['skipped_type']} not an event type we ship")
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


if __name__ == "__main__":
    main()
