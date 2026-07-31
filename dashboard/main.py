#!/usr/bin/env python3
"""
main.py — Run the dashboard.

    python main.py                          serve on http://127.0.0.1:8050
    python main.py --port 9000              a different port
    python main.py --db ../demo.db          read a different database
    python main.py --debug                  reloader and tracebacks
    python main.py --host 0.0.0.0           expose on the network (see below)

The dashboard is a read model. It opens the Baseline v1.3 database read-only and
never writes to it, with one deliberate exception: acknowledging or closing an
alert, which goes through ``Database.set_alert_status()`` and can be switched off
entirely with ``DASHBOARD_ALLOW_ALERT_ACTIONS=0``.

It binds to loopback by default. This page renders attacker IPs, session
transcripts and the outbound feed; none of that should be reachable from the lab
network without a decision. ``--host 0.0.0.0`` makes that decision explicit, and
you should set ``DASHBOARD_SECRET_KEY`` when you do.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

# Running `python main.py` from anywhere: make the package importable.
sys.path.insert(0, str(Path(__file__).resolve().parent))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dashboard",
        description="Flask dashboard for the distributed honeypot TI aggregator.",
    )
    parser.add_argument("--host", help="interface to bind (default 127.0.0.1)")
    parser.add_argument("--port", type=int, help="port to listen on (default 8050)")
    parser.add_argument("--db", help="path to the SQLite database (sets HONEYPOT_DB_PATH)")
    parser.add_argument("--debug", action="store_true", help="reloader and tracebacks")
    parser.add_argument("--refresh", type=int, help="default auto-refresh, seconds (0 = manual)")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    # Settings read the environment at import time, so apply overrides first.
    if args.db:
        os.environ["HONEYPOT_DB_PATH"] = str(Path(args.db).expanduser().resolve())
    if args.refresh is not None:
        os.environ["DASHBOARD_REFRESH_SECONDS"] = str(args.refresh)
    if args.debug:
        os.environ["DASHBOARD_TEMPLATE_RELOAD"] = "1"

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s  %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    from common import config as common_config

    if common_config.ENV_FILES_LOADED:
        logging.getLogger("config").info(
            "loaded %s", ", ".join(str(p) for p in common_config.ENV_FILES_LOADED)
        )

    from app import create_app

    app = create_app()
    host = args.host or app.config["HOST"]
    port = args.port or app.config["PORT"]

    database = app.config["DB_PATH"]
    logging.getLogger("dashboard").info(
        "reading %s (%s)", database, "found" if database.exists() else "MISSING"
    )
    print(f"\n  {app.config['APP_NAME']} dashboard  ->  http://{host}:{port}\n")

    app.run(host=host, port=port, debug=args.debug, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
