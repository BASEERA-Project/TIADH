"""
config.py — Central configuration for the whole system.

Every value is overridable through an environment variable so that nobody has to
edit source code to point at a different database or tune a threshold.

Where the values come from
--------------------------
On import, this module loads `.env` and `.env.secrets` from the repository root
(see `_load_env_files` for the search order) and folds them into `os.environ`.
**A real environment variable always wins over the file**, so `--db`, Docker's
`environment:` block and CI overrides keep working untouched.

This has to happen here, at import time, because the constants below are
evaluated on import — a loader called from `main()` would already be too late.
Doing it in `common` rather than in each entry point means every part picks the
same file up automatically, and it is why the parsing below is hand-rolled
rather than `python-dotenv`: `common` depends on nothing outside the standard
library, and everything else depends on `common`.

Nothing secret lives in this file. Secrets live in `.env.secrets`, which is
loaded the same way but kept separate so the config template can be committed.
"""

from __future__ import annotations

import os
from pathlib import Path

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# .env loading — must run before the first os.getenv() below
# --------------------------------------------------------------------------

#: Files read from the repository root, in this order. Later files win over
#: earlier ones; a real environment variable wins over both.
ENV_FILENAMES = (".env", ".env.secrets")


def _parse_env_file(path: Path) -> dict:
    """
    Parse one `KEY=value` file.

    Deliberately not `sh`: sourcing these files with `set -a; . ./.env` strips
    the quotes out of `NODE_KEYS_JSON` (leaving invalid JSON) and truncates any
    unquoted value containing spaces at the first word. This reads the file as
    data instead, so both survive.

    An unquoted value may carry a trailing ` # comment`; a quoted value is taken
    verbatim, which is how you write a value that genuinely contains ` #`.
    """
    values: dict = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()

        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not key:
            continue

        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].rstrip()
        values[key] = value
    return values


def _search_directories():
    """
    Yield directories to look in: upwards from the working directory, then
    upwards from this package.

    Each walk stops at the repository root, and never reaches the home
    directory or the filesystem root even when there is no repository — a
    stray `~/.env` from some unrelated project must never configure this one.
    """
    home = Path.home()
    for start in (Path.cwd(), BASE_DIR):
        for directory in (start, *start.parents):
            if directory == home or directory == directory.parent:
                break
            yield directory
            if (directory / ".git").exists():
                break


def _load_env_files() -> list:
    """
    Fold the env files into `os.environ` and return the ones actually read.

    Set `TIADH_ENV_FILE` to bypass the search and name the files explicitly
    (`os.pathsep`-separated). Set it to the empty string to load nothing at all,
    which is what a test run or a fully environment-driven deployment wants.
    """
    override = os.getenv("TIADH_ENV_FILE")
    if override is not None:
        candidates = [Path(p).expanduser() for p in override.split(os.pathsep) if p.strip()]
    else:
        candidates = []
        for directory in _search_directories():
            found = [directory / name for name in ENV_FILENAMES if (directory / name).is_file()]
            if found:
                candidates = found
                break

    loaded = []
    for path in candidates:
        if not path.is_file():
            continue
        for key, value in _parse_env_file(path).items():
            # setdefault, not assignment: the real environment outranks the file.
            os.environ.setdefault(key, value)
        loaded.append(path)
    return loaded


#: The env files this process actually read. Entry points log it, because
#: "which config is live" is the question you ask when something looks wrong.
ENV_FILES_LOADED = _load_env_files()

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

#: Baseline v1.3 heartbeat interval. A contract value, not a preference: the
#: node adapters send on it, the sweeper below derives its timeout from it, and
#: the dashboard reports node health in *missed heartbeats* against it.
HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("HEARTBEAT_INTERVAL_SECONDS", "60"))

#: A node with no event or heartbeat for this many seconds is marked offline.
#: Three missed heartbeats, derived rather than hardcoded so the two cannot
#: drift apart.
NODE_OFFLINE_AFTER_SECONDS = int(
    os.getenv("NODE_OFFLINE_AFTER_SECONDS", str(3 * HEARTBEAT_INTERVAL_SECONDS))
)

#: A session with no activity for this long is force-closed by the sweeper, so
#: `sessions.status` does not sit on 'active' forever when a node dies mid-session.
SESSION_STALE_AFTER_SECONDS = int(os.getenv("SESSION_STALE_AFTER_SECONDS", "3600"))

# --------------------------------------------------------------------------
# Threat intelligence enrichment
# --------------------------------------------------------------------------

#: AbuseIPDB key for the enricher's abuse-score lookup. Secret, so it belongs in
#: `.env.secrets`; free keys come from https://www.abuseipdb.com/account/api.
#: Leaving it unset is a supported mode, not an error — the enricher then
#: records geolocation and the local profile score and leaves `abuse_score`
#: NULL, which `high_risk_ip` reads as "unknown" rather than as a clean score.
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()

#: How far back AbuseIPDB aggregates complaints when scoring an address. Their
#: free tier caps this at 365; 90 keeps the score current enough to act on.
ABUSEIPDB_MAX_AGE_DAYS = int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90"))

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
