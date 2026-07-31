"""
config.py — Central configuration for Part 4 (Storage, Alerting & Feed Export).

Every value is overridable through an environment variable so that nobody has to
edit source code to point at a different database or tune a threshold. Copy
`.env.example` to `.env` and export it (`set -a; . ./.env; set +a`) before running.

Nothing secret lives in here. Node keys belong to Part 2 (the collector), not to
Part 4.
"""

from __future__ import annotations

import os
from pathlib import Path

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

#: Location of the shared SQLite database. Parts 2, 3 and 5 must point at the
#: *same* file. Keep it on local disk — SQLite over NFS/SMB corrupts.
DB_PATH = Path(os.getenv("HONEYPOT_DB_PATH", BASE_DIR / "honeypot_aggregator.db"))

#: Directory that generated threat feeds are written to.
EXPORT_DIR = Path(os.getenv("HONEYPOT_EXPORT_DIR", BASE_DIR / "exports"))

#: Path to the DDL that defines the Baseline v1.3 schema.
SCHEMA_PATH = BASE_DIR / "db" / "schema.sql"

# --------------------------------------------------------------------------
# Contract constants (Team Baseline v1.3 — do not change without group consent)
# --------------------------------------------------------------------------

SCHEMA_VERSION = "1.3"

#: Nodes allowed to appear in `node_id`. Extend via KNOWN_NODES=node-01,node-04
KNOWN_NODES = tuple(
    n.strip()
    for n in os.getenv("KNOWN_NODES", "node-01,node-02,node-03").split(",")
    if n.strip()
)

#: Reject events whose node_id is not in KNOWN_NODES. Set to 0 during a demo
#: where a teammate spins up an ad-hoc node.
STRICT_NODE_IDS = os.getenv("STRICT_NODE_IDS", "1") == "1"

#: The literal string that replaces a password everywhere outside the local DB.
MASK = "***MASKED***"

# --------------------------------------------------------------------------
# Database behaviour
# --------------------------------------------------------------------------

#: Milliseconds a writer waits for a lock before raising "database is locked".
BUSY_TIMEOUT_MS = int(os.getenv("SQLITE_BUSY_TIMEOUT_MS", "5000"))

#: A node with no event or heartbeat for this many seconds is marked offline.
#: Baseline heartbeat interval is 60s, so 180s == three missed heartbeats.
NODE_OFFLINE_AFTER_SECONDS = int(os.getenv("NODE_OFFLINE_AFTER_SECONDS", "180"))

#: A session with no activity for this long is force-closed by the sweeper, so
#: `sessions.status` does not sit on 'active' forever when a node dies mid-session.
SESSION_STALE_AFTER_SECONDS = int(os.getenv("SESSION_STALE_AFTER_SECONDS", "3600"))

# --------------------------------------------------------------------------
# Alerting thresholds
# --------------------------------------------------------------------------

#: How far back each rule looks on every evaluation pass.
ALERT_WINDOW_MINUTES = int(os.getenv("ALERT_WINDOW_MINUTES", "5"))

#: Failed login attempts from one IP inside the window before brute force fires.
BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))

#: Distinct usernames tried by one IP before credential spraying fires.
CREDENTIAL_SPRAY_THRESHOLD = int(os.getenv("CREDENTIAL_SPRAY_THRESHOLD", "5"))

#: abuse_score or profile_score at or above this value is "high risk".
HIGH_RISK_SCORE_THRESHOLD = int(os.getenv("HIGH_RISK_SCORE_THRESHOLD", "75"))

#: Distinct nodes one IP must touch before it counts as a coordinated scan.
MULTI_NODE_SCAN_THRESHOLD = int(os.getenv("MULTI_NODE_SCAN_THRESHOLD", "2"))

#: Suppression window. The same (attacker_ip, alert_type) will not produce a new
#: alert while an earlier one is still open and younger than this.
ALERT_COOLDOWN_MINUTES = int(os.getenv("ALERT_COOLDOWN_MINUTES", "30"))

#: Rules that are switched on. Comment one out (or override the env var) to
#: disable it without touching the engine.
ENABLED_RULES = tuple(
    r.strip()
    for r in os.getenv(
        "ENABLED_RULES",
        "brute_force,high_risk_ip,suspicious_command,"
        "malware_staging,credential_spray,multi_node_scan,post_auth_activity",
    ).split(",")
    if r.strip()
)

# --------------------------------------------------------------------------
# Feed export
# --------------------------------------------------------------------------

#: Only alerts at or above this severity are published to the outbound feed.
FEED_MIN_SEVERITY = os.getenv("FEED_MIN_SEVERITY", "medium")

#: Only alerts in these states are published.
FEED_STATUSES = tuple(
    s.strip() for s in os.getenv("FEED_STATUSES", "open,acknowledged").split(",") if s.strip()
)

#: Identity stamped on the feed and used as `created_by_ref` in STIX bundles.
FEED_PRODUCER = os.getenv("FEED_PRODUCER", "Distributed Honeypot TI Aggregator")

#: Ordering used for severity comparisons and for "max severity" rollups.
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
