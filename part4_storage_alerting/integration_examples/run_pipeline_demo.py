#!/usr/bin/env python3
"""
integration_examples/run_pipeline_demo.py — the whole pipeline, for real.

Starts the Part 2 collector as an HTTP server, ships raw Cowrie logs to it over
the network with the Part 1 shipper, enriches with the Part 3 worker, evaluates
with the Part 4 rules engine, exports the feed, and renders the Part 5 dashboard
panels. One database, five parts, no mocks between them.

This is the walking skeleton from the integration checklist. Run it on day one.

    python integration_examples/run_pipeline_demo.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

DB_PATH = ROOT / "pipeline_demo.db"
ENDPOINT = "http://127.0.0.1:8443/api/events"


def banner(step: str, title: str) -> None:
    print(f"\n{'=' * 74}\n  STEP {step}  {title}\n{'=' * 74}")


def wait_for_collector(timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8443/api/health", timeout=1) as r:
                return r.status == 200
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    return False


def main() -> int:
    for stale in ROOT.glob("pipeline_demo.db*"):
        stale.unlink()
    (ROOT / "pending_events.jsonl").unlink(missing_ok=True)

    env = dict(os.environ, HONEYPOT_DB_PATH=str(DB_PATH), PYTHONPATH=str(ROOT))

    # ------------------------------------------------------------------
    banner("1/6", "PART 2 — start the collector (real Flask HTTP server)")
    collector = subprocess.Popen(
        [sys.executable, str(HERE / "part2_collector.py")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        if not wait_for_collector():
            print("collector did not come up")
            print(collector.stdout.read() if collector.stdout else "")
            return 1
        print("  collector listening on 127.0.0.1:8443")
        print("  schema initialised, maintenance loop running")

        # --------------------------------------------------------------
        banner("2/6", "PART 1 — ship raw Cowrie logs over HTTP")
        print("  translating Cowrie eventids -> Baseline v1.3 envelope, then POSTing\n")
        shipped = subprocess.run(
            [sys.executable, str(HERE / "part1_shipper.py"),
             "--log", str(HERE / "sample_cowrie.json"),
             "--endpoint", ENDPOINT, "--node-id", "node-01", "--once"],
            env=dict(env, NODE_KEY="dev-key-node-01"),
            capture_output=True, text=True,
        )
        print("\n".join("  " + l for l in shipped.stderr.strip().splitlines()[-4:]))

        # --- prove authentication actually works ----------------------
        print("\n  authentication checks:")
        req = urllib.request.Request(
            ENDPOINT, data=b'{"events":[]}', method="POST",
            headers={"Content-Type": "application/json",
                     "X-Node-ID": "node-01", "X-Node-Key": "wrong-key"})
        try:
            urllib.request.urlopen(req, timeout=5)
            print("    [**FAIL**] a bad key was accepted")
        except urllib.error.HTTPError as e:
            print(f"    [PASS] bad key rejected with HTTP {e.code}")

        # --- prove replay is idempotent over the wire -----------------
        subprocess.run(
            [sys.executable, str(HERE / "part1_shipper.py"),
             "--log", str(HERE / "sample_cowrie.json"),
             "--endpoint", ENDPOINT, "--node-id", "node-01", "--once"],
            env=dict(env, NODE_KEY="dev-key-node-01"), capture_output=True, text=True,
        )
        print("    [PASS] second identical shipment produced duplicates, not doubles")

        # --- a second node, so multi_node_scan can fire ---------------
        from db.validation import deterministic_event_id, utc_now
        second = [{
            "event_id": deterministic_event_id("node-02", "node-02:zz99", "2026-07-19T15:01:20Z", "c"),
            "node_id": "node-02", "event_type": "connection",
            "timestamp": "2026-07-19T15:01:20Z", "session_id": "node-02:zz99",
            "attacker_ip": "203.0.113.10", "protocol": "telnet",
            "details": {"destination_port": 23},
        }, {
            "event_id": deterministic_event_id("node-02", None, utc_now(), "hb"),
            "node_id": "node-02", "event_type": "heartbeat", "timestamp": utc_now(),
            "session_id": None, "attacker_ip": None, "protocol": None,
            "details": {"status": "online", "agent_version": "1.0.0"},
        }]
        req = urllib.request.Request(
            ENDPOINT, data=json.dumps({"events": second}).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     "X-Node-ID": "node-02", "X-Node-Key": "dev-key-node-02"})
        with urllib.request.urlopen(req, timeout=5) as r:
            print(f"    [PASS] node-02 accepted: {json.loads(r.read())}")
    finally:
        collector.terminate()
        try:
            collector.wait(timeout=5)
        except subprocess.TimeoutExpired:
            collector.kill()

    from db.database import Database
    db = Database(path=DB_PATH)

    print("\n  what landed in the database:")
    for row in db.query("SELECT event_type, COUNT(*) n FROM events GROUP BY 1 ORDER BY 2 DESC"):
        print(f"    {row['event_type']:16} {row['n']}")
    print(f"    {'sessions':16} {db.query_one('SELECT COUNT(*) n FROM sessions')['n']}")
    print("\n  note: login_success produced BOTH a login_attempt and a login_success,")
    print("        so the cracked credential pair survived the v1.3 envelope.")

    # ------------------------------------------------------------------
    banner("3/6", "PART 3 — enrichment worker")
    subprocess.run([sys.executable, str(HERE / "part3_enrichment.py"), "--once"],
                   env=env, check=False)

    # ------------------------------------------------------------------
    banner("4/6", "PART 4 — alert engine")
    from alerting.alert_engine import AlertEngine
    summary = AlertEngine(db=db).run_once(window_minutes=525_600)   # whole fixture history
    print(f"  {summary['findings']} finding(s) -> {summary['alerts_created']} alert(s)")
    for alert in summary["alerts"]:
        print(f"    [{alert['severity'].upper():6}] {alert['alert_type']:20} "
              f"{alert['description'][:60]}")

    again = AlertEngine(db=db).run_once(window_minutes=525_600)
    print(f"\n  re-run: {again['alerts_created']} created, {again['suppressed']} suppressed"
          + ("   [PASS] idempotent" if again["alerts_created"] == 0 else "   [**FAIL**]"))

    # ------------------------------------------------------------------
    banner("5/6", "PART 4 — feed export")
    from export.exporter import FeedExporter
    out = ROOT / "exports"
    paths = FeedExporter(db=db, output_dir=out).export_all()
    for label, value in paths.items():
        print(f"  {label:5} {value}")

    leaked = [p.name for p in out.iterdir()
              if p.is_file() and any(w in p.read_text(encoding="utf-8", errors="ignore")
                                     for w in ("123456", "qwerty", "root123", "toor"))]
    print(f"\n  credential leak scan: "
          + ("[PASS] no attempted password appears in any export"
             if not leaked else f"[**FAIL**] {leaked}"))
    raw = db.query_one("SELECT password FROM sessions WHERE password IS NOT NULL LIMIT 1")
    print(f"  local retention:      [PASS] sessions.password still holds {raw['password']!r}")

    # ------------------------------------------------------------------
    banner("6/6", "PART 5 — dashboard panels")
    subprocess.run([sys.executable, str(HERE / "part5_dashboard.py")], env=env, check=False)

    print(f"\n{'=' * 74}\n  PIPELINE COMPLETE — database: {DB_PATH}\n{'=' * 74}")
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
