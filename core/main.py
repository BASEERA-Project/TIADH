#!/usr/bin/env python3
"""
main.py — Operational entry point for the aggregator host.

    python main.py serve                     the whole aggregator, one process
    python main.py init                      create the schema
    python main.py seed                      load the demo fixture events
    python main.py ingest FILE.jsonl         load events from a file (or stdin)
    python main.py alerts                    run one alert evaluation pass
    python main.py export --format all       write JSON / CSV / STIX feeds
    python main.py run                       maintenance + alerts + export, once
    python main.py watch --interval 30       the same loop, forever
    python main.py stats                     print headline numbers
    python main.py validate FILE.jsonl       contract-check without writing

`serve` is the command to run in the final deployment: it starts the collector,
the enricher and the alert/export cycle as one process against one database
handle. The dashboard stays separate — see `cmd_serve` for why.

The single-purpose commands below it all still work on their own. `watch` is
`serve` without the collector and the enricher, and `seed`, `ingest` and
`validate` exist so Part 4 can be developed and demonstrated with no dependency
on Parts 1, 2 or 3 being live.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
import time
from pathlib import Path

from common import config
from common.alerting.alert_engine import AlertEngine
from common.db.database import Database, load_jsonl, set_db
from common.db.validation import rebase_events, validate_event
from common.export.exporter import FeedExporter

LOG_FORMAT = "%(asctime)s  %(levelname)-7s %(name)s: %(message)s"


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=LOG_FORMAT,
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_init(args, db: Database) -> int:
    db.initialize_schema()
    tables = db.query(
        "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY type, name"
    )
    print(f"Schema initialised at {db.path} (Baseline v{config.SCHEMA_VERSION})")
    for row in tables:
        print(f"  {row['type']:5} {row['name']}")
    return 0


def cmd_ingest(args, db: Database) -> int:
    if args.file == "-":
        events = [json.loads(line) for line in sys.stdin if line.strip()]
    else:
        events = load_jsonl(args.file)

    result = db.apply_events(events)
    print(json.dumps({k: v for k, v in result.items() if k != "errors"}, indent=2))

    if result["errors"]:
        print(f"\n{len(result['errors'])} rejected event(s):", file=sys.stderr)
        for error in result["errors"]:
            print(f"  {error['event_id']}: {'; '.join(error['reasons'])}", file=sys.stderr)
    return 0


def cmd_seed(args, db: Database) -> int:
    fixture_dir = Path(__file__).parent / "tests" / "fixtures"
    fixture = Path(args.file) if args.file else fixture_dir / "sample_events.jsonl"
    if not fixture.exists():
        print(f"fixture not found: {fixture}", file=sys.stderr)
        return 1

    db.initialize_schema()

    events = load_jsonl(fixture)
    if not args.keep_timestamps:
        # Move the recorded narrative into the live alert window, otherwise a
        # week-old fixture produces zero findings and looks broken.
        events = rebase_events(events)

    result = db.apply_events(events)
    print(
        f"Seeded from {fixture.name}: {result['accepted']} accepted, "
        f"{result['duplicates']} duplicate, {result['rejected']} rejected "
        f"(the rejections are deliberate — the fixture ends with malformed events)"
    )

    # Stand in for Part 3 so that the reputation-driven rules have data to act on.
    reputation_fixture = fixture_dir / "sample_reputation.json"
    if not args.no_reputation and reputation_fixture.exists():
        records = json.loads(reputation_fixture.read_text(encoding="utf-8"))
        for record in records:
            db.upsert_reputation(**record)
        print(f"Seeded {len(records)} reputation record(s) (placeholder for Part 3)")

    return 0


def cmd_alerts(args, db: Database) -> int:
    summary = AlertEngine(db=db).run_once(window_minutes=args.window)
    print(
        json.dumps(
            {k: v for k, v in summary.items() if k != "alerts"},
            indent=2,
        )
    )
    for alert in summary["alerts"]:
        print(f"  [{alert['severity'].upper():6}] {alert['alert_type']:20} {alert['description']}")
    return 0


def cmd_export(args, db: Database) -> int:
    exporter = FeedExporter(db=db)
    if args.format == "json":
        print(exporter.export_json(min_severity=args.min_severity))
    elif args.format == "csv":
        for path in exporter.export_csv(min_severity=args.min_severity):
            print(path)
    elif args.format == "stix":
        print(exporter.export_stix(min_severity=args.min_severity))
    else:
        for label, value in exporter.export_all(min_severity=args.min_severity).items():
            print(f"{label}: {value}")
    return 0


def run_cycle(db: Database, window=None, min_severity=None, maintenance: bool = True) -> dict:
    """
    One maintenance cycle: housekeeping, then detection, then publication.

    `maintenance` is False only when the collector is running in this same
    process. Housekeeping belongs to whichever process is always on, and the
    collector already runs `mark_stale_nodes_offline()` / `close_stale_sessions()`
    on its own timer (collector/app/main.py) — doing it here as well would be
    the same two sweeps twice.
    """
    offline = stale = 0
    if maintenance:
        offline = db.mark_stale_nodes_offline()
        stale = db.close_stale_sessions()

    summary = AlertEngine(db=db).run_once(window_minutes=window)
    outputs = FeedExporter(db=db).export_all(min_severity=min_severity)

    return {
        "nodes_marked_offline": offline,
        "sessions_force_closed": stale,
        "findings": summary["findings"],
        "alerts_created": summary["alerts_created"],
        "suppressed": summary["suppressed"],
        "by_type": summary["by_type"],
        "exports": outputs,
    }


def cmd_run(args, db: Database) -> int:
    print(json.dumps(run_cycle(db, args.window, args.min_severity), indent=2))
    return 0


def cmd_watch(args, db: Database) -> int:
    log = logging.getLogger("watch")
    log.info("maintenance loop started, interval %ss (Ctrl-C to stop)", args.interval)
    try:
        while True:
            try:
                cmd_run(args, db)
            except Exception:  # noqa: BLE001 — never let one bad pass kill the loop
                log.exception("cycle failed; continuing")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("stopped")
    return 0


def cmd_serve(args, db: Database) -> int:
    """
    Run the whole aggregator side of the system in one process.

    Three components, one database handle:

        collector   FastAPI on --host/--port, plus its own housekeeping timer
        enricher    geolocation + profile scoring, every --enrich-interval
        cycle       alerts + feed export, every --interval

    They used to be three terminals because they started life as three
    coursework parts, not because they need three processes: same uv project,
    same environment, same HONEYPOT_DB_PATH, same write path. Sharing one
    `Database` means sharing its write lock, so their writes queue in memory
    instead of racing for SQLite's file lock and spending the busy timeout.

    The dashboard is deliberately *not* here. It is a separate uv project with
    its own environment (Flask, not FastAPI), it opens the database read-only,
    and it makes its own decision about what to expose — the collector binds
    0.0.0.0 because the sensors are remote, while the dashboard binds loopback
    because it renders attacker data. It also has to run alone against a demo
    database, and restarting a viewer should never interrupt ingestion. Run it
    with `cd dashboard && uv run python main.py`.
    """
    import uvicorn  # local: no other command in this CLI needs a web server

    log = logging.getLogger("serve")

    # The collector and the enricher both reach for the process-wide handle.
    # Hand them this one, so --db is honoured and all three share a write lock.
    db.initialize_schema()
    set_db(db)

    # The collector is imported as `app.*` from inside collector/ (the same
    # layout `uvicorn --app-dir collector` and pytest's `pythonpath` assume).
    core_dir = Path(__file__).resolve().parent
    for extra in (core_dir, core_dir / "collector"):
        if str(extra) not in sys.path:
            sys.path.insert(0, str(extra))
    from app.main import app as collector_app

    stop = threading.Event()
    threads: list[threading.Thread] = []

    def cycle_loop() -> None:
        while not stop.is_set():
            try:
                result = run_cycle(db, args.window, args.min_severity, maintenance=False)
                log.info(
                    "cycle: %d finding(s), %d alert(s) created, %d suppressed",
                    result["findings"],
                    result["alerts_created"],
                    result["suppressed"],
                )
            except Exception:  # noqa: BLE001 — never let one bad pass kill the loop
                log.exception("cycle failed; continuing")
            stop.wait(args.interval)

    threads.append(threading.Thread(target=cycle_loop, name="cycle", daemon=True))

    if args.no_enricher:
        log.info("enricher disabled (--no-enricher)")
    else:
        from enricher.enrich import run_worker_loop

        threads.append(
            threading.Thread(
                target=run_worker_loop,
                kwargs={
                    "interval_seconds": args.enrich_interval,
                    "db": db,
                    "stop_event": stop,
                },
                name="enricher",
                daemon=True,
            )
        )

    for thread in threads:
        thread.start()

    log.info("database %s", db.path)
    log.info("alert/export cycle every %ss (housekeeping is the collector's)", args.interval)
    log.info("dashboard is a separate command: cd dashboard && uv run python main.py")

    # log_config=None keeps uvicorn from installing its own handlers, so its
    # logs and ours come out of one root logger in one format.
    server = uvicorn.Server(
        uvicorn.Config(collector_app, host=args.host, port=args.port, log_config=None)
    )
    try:
        # Blocks until SIGINT/SIGTERM; uvicorn owns the signal handlers because
        # this is the main thread.
        server.run()
    except KeyboardInterrupt:
        # uvicorn shuts the server down gracefully and *then* re-raises. The
        # worker threads below still have to be stopped, and a traceback on
        # Ctrl-C helps nobody.
        pass
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=5)
        log.info("aggregator stopped")
    return 0


def cmd_stats(args, db: Database) -> int:
    print(json.dumps(db.get_overview_stats(), indent=2))

    nodes = db.get_nodes()
    if nodes:
        print("\nNodes")
        for node in nodes:
            print(f"  {node['node_id']:10} {node['status']:8} last_seen={node['last_seen']}")

    top = db.get_top_attackers(limit=5)
    if top:
        print("\nTop attackers")
        for row in top:
            location = row.get("country") or "unknown"
            print(
                f"  {row['attacker_ip']:16} events={row['event_count']:<5} "
                f"sessions={row['session_count']:<4} nodes={row['node_count']:<3} {location}"
            )

    creds = db.get_top_credentials(limit=5)
    if creds:
        print("\nMost-tried usernames")
        for row in creds:
            print(f"  {str(row['username']):20} attempts={row['attempts']}")
    return 0


def cmd_validate(args, db: Database) -> int:
    """Contract-check a file without touching the database. Useful to Part 1."""
    events = load_jsonl(args.file)
    failures = 0
    for index, event in enumerate(events, 1):
        ok, errors = validate_event(event)
        if not ok:
            failures += 1
            print(f"line {index}  event_id={event.get('event_id')}")
            for error in errors:
                print(f"    - {error}")

    print(f"\n{len(events) - failures}/{len(events)} event(s) conform to Baseline v{config.SCHEMA_VERSION}")
    return 1 if failures else 0


# --------------------------------------------------------------------------
# CLI wiring
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="core",
        description="Aggregator-host entry point: ingest, enrichment, alerting and feed export.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--db", help="path to the SQLite database (overrides HONEYPOT_DB_PATH)")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    subs = parser.add_subparsers(dest="command", required=True)

    p_serve = subs.add_parser(
        "serve",
        help="the whole aggregator in one process: collector + enricher + alert/export cycle",
    )
    # 0.0.0.0 by default because the sensors are on other hosts. This is the
    # opposite of the dashboard's default, and deliberately so.
    p_serve.add_argument("--host", default="0.0.0.0", help="collector bind address")
    p_serve.add_argument("--port", type=int, default=8000, help="collector port")
    p_serve.add_argument("--interval", type=int, default=30,
                         help="seconds between alert/export cycles")
    p_serve.add_argument("--enrich-interval", type=int, default=30,
                         help="seconds between enrichment passes")
    p_serve.add_argument("--no-enricher", action="store_true",
                         help="skip the enricher (it calls ip-api.com — use offline)")
    p_serve.add_argument("--window", type=int, help="alert lookback in minutes")
    p_serve.add_argument("--min-severity", choices=["low", "medium", "high"])
    p_serve.set_defaults(func=cmd_serve)

    subs.add_parser("init", help="create tables, indexes and views").set_defaults(func=cmd_init)

    p_seed = subs.add_parser("seed", help="load demo fixture events")
    p_seed.add_argument("--file", help="fixture path (defaults to the bundled one)")
    p_seed.add_argument("--keep-timestamps", action="store_true",
                        help="do not shift fixture times into the live alert window")
    p_seed.add_argument("--no-reputation", action="store_true",
                        help="skip the placeholder reputation records")
    p_seed.set_defaults(func=cmd_seed)

    p_ingest = subs.add_parser("ingest", help="load events from a .jsonl file or stdin")
    p_ingest.add_argument("file", help="path to a .jsonl file, or '-' for stdin")
    p_ingest.set_defaults(func=cmd_ingest)

    p_alerts = subs.add_parser("alerts", help="run one alert evaluation pass")
    p_alerts.add_argument("--window", type=int, help="lookback in minutes")
    p_alerts.set_defaults(func=cmd_alerts)

    p_export = subs.add_parser("export", help="write the threat feed")
    p_export.add_argument("--format", choices=["json", "csv", "stix", "all"], default="all")
    p_export.add_argument("--min-severity", choices=["low", "medium", "high"])
    p_export.set_defaults(func=cmd_export)

    p_run = subs.add_parser("run", help="maintenance + alerts + export, once")
    p_run.add_argument("--window", type=int)
    p_run.add_argument("--min-severity", choices=["low", "medium", "high"])
    p_run.set_defaults(func=cmd_run)

    p_watch = subs.add_parser("watch", help="repeat 'run' on a timer")
    p_watch.add_argument("--interval", type=int, default=30, help="seconds between cycles")
    p_watch.add_argument("--window", type=int)
    p_watch.add_argument("--min-severity", choices=["low", "medium", "high"])
    p_watch.set_defaults(func=cmd_watch)

    subs.add_parser("stats", help="print headline numbers").set_defaults(func=cmd_stats)

    p_validate = subs.add_parser("validate", help="contract-check a .jsonl file")
    p_validate.add_argument("file")
    p_validate.set_defaults(func=cmd_validate)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)

    # common.config folded these into os.environ on import. Say which, because
    # "is my .env actually live?" is the first question when a setting looks
    # ignored.
    if config.ENV_FILES_LOADED:
        logging.getLogger("config").info(
            "loaded %s", ", ".join(str(p) for p in config.ENV_FILES_LOADED)
        )

    db = Database(path=args.db) if args.db else Database()
    try:
        # `serve` creates the schema itself, the same way the collector does.
        if args.command not in ("init", "seed", "serve") and not db.path.exists():
            print(
                f"No database at {db.path}. Run 'python main.py init' first.",
                file=sys.stderr,
            )
            return 1
        return args.func(args, db)
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
