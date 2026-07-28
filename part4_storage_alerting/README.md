# Part 4 — Storage, Alerting & Feed Export

**Project:** Threat Intelligence Aggregator from Distributed Honeypots
**Mentor:** Dr. Insaf Ullah
**Contract:** Team Baseline v1.3 (frozen)

Part 4 is the backbone the other four parts sit on. It owns the central database,
the shared read/write functions everyone else calls, the rules that turn raw
events into alerts, and the exporter that turns alerts into a feed a defensive
team could actually consume.

---

## 1. Overview & Features

### What this part is responsible for

| Responsibility | Where it lives |
|---|---|
| Turn the agreed schema into real tables | `db/schema.sql` |
| Shared read/write functions for Parts 2, 3 and 5 | `db/database.py` |
| Alert logic (brute force, risk scores, dangerous commands) | `alerting/` |
| JSON / CSV / STIX 2.1 feed export | `export/exporter.py` |
| Enforce that passwords never leave local storage | schema view + exporter |

### Features

- **Baseline v1.3 schema** — five tables, all indexes, plus a `commands` view and
  a masked `sessions_public` view.
- **Executable contract** — `db/validation.py` is Section 2 of the baseline as
  code. Parts 1 and 2 import the same module, so the three implementations
  cannot drift apart.
- **Idempotent ingestion** — replaying an event after a retry is a no-op.
- **Out-of-order tolerance** — `session_end` arriving before `connection`
  still produces a correct session row.
- **Seven detection rules**, each independently switchable.
- **Deduplicated alerts** — deterministic alert IDs plus a cooldown window, so
  running the engine every 30 seconds does not flood the table.
- **Three export formats** with a hard masking guarantee.
- **44 tests**, standard library only.
- **No mandatory third-party dependencies.**

### Detection rules

| Rule | Fires when | Severity |
|---|---|---|
| `brute_force` | ≥5 failed logins from one IP in the window | medium (high at ≥20) |
| `credential_spray` | ≥5 distinct usernames from one IP | medium |
| `high_risk_ip` | `abuse_score` ≥75 **or** `profile_score` ≥75 | high |
| `suspicious_command` | command matches a high-risk pattern | low → high |
| `malware_staging` | any `file_download` event | high |
| `multi_node_scan` | same IP seen on ≥2 sensors | medium / high |
| `post_auth_activity` | successful login followed by commands | high |

`suspicious_command` covers `wget`, `curl`, `chmod +x`, `rm -rf`, `history -c`,
`base64 -d`, `/dev/tcp/`, `crontab`, `authorized_keys`, `nmap`, and more —
see `COMMAND_PATTERNS` in `alerting/rules.py`.

> `multi_node_scan` is the one rule a single-node deployment could never produce.
> It is the clearest demonstration in the project of what the distributed
> architecture actually buys, so it is worth featuring in the demo.

### Sensitive data handling

The baseline says attempted passwords are stored locally but masked in the
dashboard and excluded from exports. That is enforced in three independent
places, because the cost of getting it wrong is a leaked credential set in a
file someone forwards by email:

1. **`sessions_public` view** masks at the database layer. Part 5 reads this
   view, so masking survives a careless `st.dataframe()` or a CSV download button.
2. **`scrub()`** rewrites any password-like key on the way into an export.
3. **`assert_no_secrets()`** re-walks the finished payload and **raises**,
   aborting the export, if an unmasked password survived.

A crash is the better failure mode here.

---

## 2. Prerequisites & Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10 – 3.14 | 3.12 recommended; uses `X \| Y` type syntax. On 3.14 use the explicit test command in section 3, not `discover` |
| SQLite | 3.38+ | bundled with Python; needs JSON1 (default since 3.38) |
| Disk | ~1 GB | events grow fastest; budget more for a long run |
| `stix2` | optional | only for validated STIX output |

Check your SQLite build:

```bash
python3 -c "import sqlite3; print(sqlite3.sqlite_version)"          # want >= 3.38
python3 -c "import sqlite3; sqlite3.connect(':memory:').execute(\"select json('{}')\"); print('JSON1 ok')"
```

**Environment variables** — every setting is overridable; see `.env.example`.
None are required to run. No secrets live in this part: node keys belong to
Part 2, API keys to Part 3.

---

## 3. Installation & Setup

```bash
cd /part4_storage_alerting

python3 -m venv .venv              # Download venv if command failed
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt    # optional — nothing here is required

cp .env.example .env
set -a; . ./.env; set +a           # optional

python main.py init                # create tables, indexes and views
```

Expected output:

```
Schema initialised at .../honeypot_aggregator.db (Baseline v1.3)
  table alerts
  table events
  table nodes
  table reputation
  table sessions
  view  attacker_summary
  view  commands
  view  sessions_public
```

Verify the install:

```bash
# Works on every supported version — prefer this form:
python -m unittest tests.test_part4 -v
# Ran 44 tests ... OK

python verify.py
# 35/35 checks passed
```

`python -m unittest discover -s tests -t .` also works on Python ≤ 3.13, but
Python 3.14 tightened directory-import rules and rejects the discovery form with
`Start directory is not importable`. The explicit `tests.test_part4` form above
avoids discovery entirely and runs everywhere. (It relies on `tests/__init__.py`
existing — it's in the repo; if it ever goes missing, `touch tests/__init__.py`.)

`verify.py` checks the runtime properties the unit tests cannot: WAL mode is
actually on, foreign keys are actually enforced, six concurrent writers produce
zero lock errors, a reader polls uninterrupted through a write burst, replayed
batches are 100% duplicates, and every query the dashboard runs hits an index.

---

## 4. How to Use

### Demo in three commands

No other part needs to be running.

```bash
python main.py seed      # load a realistic attack narrative
python main.py run       # maintenance + detection + export
python main.py stats     # headline numbers
```

`seed` reports `35 accepted, 1 duplicate, 9 rejected`. **All three numbers are
intentional**: the duplicate proves deduplication works, and the nine rejects are
deliberately malformed events that prove the validator works.

`run` produces thirteen alerts covering all seven rules:

```
[HIGH  ] high_risk_ip        203.0.113.10 (NL) flagged high risk: AbuseIPDB score 92 ...
[HIGH  ] post_auth_activity  authenticated session node-01:s7a3f1 executed 7 command(s) ...
[HIGH  ] malware_staging     payload fetched on node-01: x86
[HIGH  ] suspicious_command  making a file executable on node-01: chmod +x /tmp/payload
[MEDIUM] multi_node_scan     203.0.113.10 observed on 2 separate sensors (node-01,node-02)
[MEDIUM] credential_spray    192.0.2.77 tried 7 distinct usernames within 5 minutes
...
```

Run `python main.py alerts` again — it creates **zero** new alerts and reports 13
suppressed. That property is what makes the engine safe on a 30-second timer.

### All commands

| Command | Purpose |
|---|---|
| `python main.py init` | Create schema, indexes and views |
| `python main.py seed` | Load demo fixtures (+ placeholder reputation) |
| `python main.py ingest FILE.jsonl` | Load events from a file, or `-` for stdin |
| `python main.py validate FILE.jsonl` | Contract-check without writing |
| `python main.py alerts [--window N]` | One evaluation pass |
| `python main.py export --format json\|csv\|stix\|all` | Write feeds |
| `python main.py run` | Maintenance + alerts + export, once |
| `python main.py watch --interval 30` | The same loop, forever |
| `python main.py stats` | Headline numbers |

Global flags: `--db PATH`, `-v` (debug logging).

### Checking a teammate's events against the contract

Part 1 can verify its shipper output before a single event is sent:

```bash
python main.py validate ../part1_nodes/sample_output.jsonl
```

```
line 37  event_id=5eaebcb5-...
    - missing top-level field 'protocol' (use null, do not omit)
line 42  event_id=9bb4c162-...
    - node_id 'node-09' is not a registered node ['node-01', 'node-02', 'node-03']
line 44  event_id=f49f62d8-...
    - details key(s) not allowed for 'login_attempt': shell (allowed: ['password', 'username'])

36/45 event(s) conform to Baseline v1.3
```

### Production deployment

```bash
python main.py watch --interval 30
# or as a systemd unit / cron entry running `python main.py run`
```

### Tuning

Thresholds are environment variables, not code changes:

```bash
BRUTE_FORCE_THRESHOLD=10 ALERT_WINDOW_MINUTES=10 python main.py alerts
ENABLED_RULES=brute_force,malware_staging python main.py alerts   # subset only
```

---

## 5. Integration Guide

### Repository layout

```
part4_storage_alerting/
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
├── config.py                       # every threshold and path, env-overridable
├── main.py                         # operational CLI
│
├── db/
│   ├── __init__.py
│   ├── schema.sql                  # ← Baseline v1.3 DDL (FROZEN section)
│   ├── database.py                 # ← the shared API everyone imports
│   └── validation.py               # ← the contract, as code (share with Parts 1 & 2)
│
├── alerting/
│   ├── __init__.py
│   ├── rules.py                    # rule definitions + command patterns
│   └── alert_engine.py             # evaluation, deduplication, persistence
│
├── export/
│   ├── __init__.py
│   └── exporter.py                 # JSON / CSV / STIX 2.1 + masking guarantee
│
├── integration_examples/           # ← runnable code for your teammates
│   ├── part1_shipper.py            #   Cowrie -> v1.3 translator + batching shipper
│   ├── part2_collector.py          #   working Flask POST /api/events
│   ├── part3_enrichment.py         #   enrichment worker + profile scoring
│   ├── part5_dashboard.py          #   dashboard query layer + Streamlit skeleton
│   ├── run_pipeline_demo.py        #   all five parts, end to end, over real HTTP
│   └── sample_cowrie.json          #   raw Cowrie log fixture
│
├── tests/
│   ├── __init__.py
│   ├── test_part4.py               # 44 tests
│   └── fixtures/
│       ├── sample_events.jsonl     # ← shared team fixture: 36 valid, 9 invalid
│       └── sample_reputation.json
│
├── verify.py                       # 35 runtime property checks
└── exports/                        # generated feeds (gitignored)
```

### Run the whole pipeline first

Before reading any of the sections below, run this. It starts the collector as a
real HTTP server, ships raw Cowrie logs to it over the network, enriches,
alerts, exports and renders the dashboard — five parts, one database, no mocks:

```bash
pip install flask
python integration_examples/run_pipeline_demo.py
```

Each teammate then has a working file to start from:

| Part | File | What it gives you |
|---|---|---|
| 1 | `integration_examples/part1_shipper.py` | Cowrie eventid mapping, deterministic IDs, spooling, batching |
| 2 | `integration_examples/part2_collector.py` | Working `POST /api/events` with auth and maintenance loop |
| 3 | `integration_examples/part3_enrichment.py` | Worker loop, rate limiting, `profile_score` formula |
| 5 | `integration_examples/part5_dashboard.py` | Every query a panel needs, plus a Streamlit skeleton |

Copy the file, replace the stubbed parts, keep the structure.

### The one setup step everyone needs

All five parts must point at the **same** database file:

```bash
export HONEYPOT_DB_PATH=/srv/honeypot/honeypot_aggregator.db
```

Keep it on local disk. SQLite over NFS or SMB corrupts.

---

### → Part 1 (Sensors)

You do not write to the database — you send to Part 2. But two things here are
for you:

**Validate before you ship.** Copy `db/validation.py` into your repo (or import
it) and check every event before it goes into a batch. An event that fails
locally will fail at the collector too, and will sit in `pending_events.jsonl`
retrying forever.

```python
from db.validation import validate_event

ok, errors = validate_event(event)
if not ok:
    log.error("dropping malformed event: %s", errors)
```

**Use deterministic event IDs.** If your shipper crashes after POSTing but before
marking a log line as sent, a random UUID regenerates on restart and the
collector accepts the same event twice. Deduplication only works if the same
source line always produces the same ID:

```python
from db.validation import deterministic_event_id

event_id = deterministic_event_id(
    node_id="node-01",
    session_id="node-01:a1b2c3d4",
    timestamp="2026-07-19T15:00:00Z",
    marker="cowrie.command.input#7",   # unique within the session
)
```

Also note: **namespace your session IDs** (`node-01:a1b2c3d4`). Cowrie session
IDs are short hex strings that are not unique across machines, and `session_id`
is a primary key.

---

### → Part 2 (Ingestion)

Your `POST /api/events` handler becomes roughly this:

```python
from db.database import Database, ValidationError

db = Database()          # module-level, reused across requests

@app.post("/api/events")
def receive():
    if not authenticate(request.headers):
        return jsonify({"error": "unauthorized"}), 401

    result = db.apply_events(request.json.get("events", []))
    return jsonify(result), 200
```

`apply_events()` returns the exact response body the baseline specifies, plus an
`errors` array:

```json
{
  "accepted": 18, "duplicates": 1, "rejected": 1,
  "errors": [
    {"event_id": "...", "reasons": ["details.command is required and must be non-null"]}
  ]
}
```

The `errors` array is an **addition to the frozen contract** and needs group
sign-off. It is worth asking for: without it a node cannot tell *which* event was
rejected, so a permanently malformed event is retried forever. Adding a field is
backward compatible — Part 1 can ignore it until it is ready.

One call does everything. `apply_event()` validates, inserts into `events`
(idempotent), upserts the `sessions` row, and refreshes `nodes.last_seen` — all
in a single transaction:

| Guarantee | How |
|---|---|
| Duplicate events | `INSERT OR IGNORE` on `event_id`, reported as `duplicates` |
| Out-of-order arrival | Session row is a single UPSERT; a late `connection` never reopens a closed session |
| Node offline mid-session | `db.close_stale_sessions()` from your background loop |
| Node goes quiet | `db.mark_stale_nodes_offline()` — 180s default = three missed heartbeats |
| `last_seen` accuracy | Only ever moves forward, never rewound by a late event |

Register node metadata once at startup:

```python
db.upsert_node("node-01", hostname="hp-ams-01", location="Lab-VM-1", ip_address="10.0.0.11")
```

**Test without waiting for Part 1:**

```bash
python main.py ingest tests/fixtures/sample_events.jsonl
```

---

### → Part 3 (Enrichment)

Two functions, and you never write SQL:

```python
from db.database import Database
db = Database()

for ip in db.get_ips_needing_enrichment(max_age_days=7, limit=100):
    geo   = geoip_lookup(ip)          # MaxMind GeoLite2, local .mmdb
    abuse = abuseipdb_lookup(ip)      # free tier: 1000/day

    db.upsert_reputation(
        ip, country=geo.country, city=geo.city,
        latitude=geo.lat, longitude=geo.lon, source="GeoLite2",
    )
    db.upsert_reputation(ip, abuse_score=abuse.score, source="AbuseIPDB")
```

Notes:

- **Run this as a worker loop, not inside Part 2's request handler.** One slow
  AbuseIPDB response would otherwise block ingestion for every node.
- **`source` accumulates.** Two calls with different sources yield
  `"GeoLite2,AbuseIPDB"` — solving the baseline's one-field-two-sources problem
  with no schema change.
- **Partial updates are safe.** Pass only what you have; existing values survive.
  Geo and abuse score update independently, so an API outage cannot stall
  profiling.
- **`get_ips_needing_enrichment()` is your cache check** — it only returns IPs
  with no row or a stale `last_updated`, so you cannot re-burn quota on an IP you
  already looked up.

For `profile_score`, this returns every counter you need in one query:

```python
p = db.get_attacker_profile_inputs(ip)
# session_count, distinct_commands, distinct_usernames, node_count,
# download_count, login_attempts, login_successes, first_seen, last_seen

score = min(100,
      min(p["session_count"]     * 4,  20)
    + min(p["distinct_commands"] * 2,  20)
    + min(p["node_count"]        * 10, 20)
    + (25 if p["download_count"] else 0)
    + min(p["distinct_usernames"],     15))

db.upsert_reputation(ip, profile_score=score, source="local-profile")
```

Cap each component so one noisy dimension cannot saturate the score.

> **One trap that will cost you an afternoon.** Python's `ipaddress` module
> reports the RFC 5737 documentation ranges — `203.0.113.0/24`, `192.0.2.0/24`,
> `198.51.100.0/24` — as `is_private == True`. The baseline uses `203.0.113.10`
> as its canonical example, so **every IP in the team's fixture data is in one of
> those ranges**. A naive `if ip.is_private: continue` filter silently skips all
> of them and your enrichment looks broken for no reason.
> `get_ips_needing_enrichment()` already handles this: real RFC1918 addresses are
> filtered out, documentation ranges are not. See `is_documentation_ip()`.

---

### → Part 5 (Dashboard)

**Open the database read-only.** This is not a suggestion — it makes it
structurally impossible for the dashboard to take a write lock and stall
ingestion:

```python
import streamlit as st
from db.database import Database

@st.cache_resource
def get_db():
    return Database(read_only=True)
```

| You need | Call |
|---|---|
| KPI header | `db.get_overview_stats()` |
| Node health panel | `db.get_nodes()` |
| Sessions table | `db.get_sessions(limit=200)` — **already masked** |
| Command timeline | `db.get_session_commands(session_id)` |
| Attacker leaderboard | `db.get_top_attackers(limit=20)` |
| Map layer | `db.get_top_attackers()` → `latitude` / `longitude` |
| Alerts view | `db.get_alerts(status="open", min_severity="medium")` |
| Credentials chart | `db.get_top_credentials()` — usernames only, by design |
| Feed preview | `FeedExporter(db).build_feed()` |

`get_alerts()` already joins reputation, so country, city, coordinates and both
scores come back on the alert row — no second query.

**Always use `get_sessions()`, never `SELECT * FROM sessions`.** The helper reads
the masked view. Query the raw table and you will render plaintext passwords.

The acknowledge button is a write, so it needs a writable handle:

```python
writer = Database()                       # separate handle, not the cached reader
if st.button("Acknowledge"):
    writer.set_alert_status(alert_id, "acknowledged")
```

**Escape attacker-controlled text.** `description` and `command_text` contain
strings the attacker typed. Streamlit's `st.dataframe` and `st.table` are safe.
If you switch to Flask or React with raw HTML, you will have built stored XSS
into your own dashboard, delivered by the attacker. Never render
`download_url` as a clickable link.

`get_overview_stats()` includes `avg_ingest_lag_seconds` (`received_at −
timestamp`). Put it on the dashboard: it is your clock-skew and pipeline-health
canary, and a good number for the final report.

---




## 6. Design Notes

Decisions that are not obvious from the code:

**WAL mode is mandatory.** Collector, enrichment worker, alert engine and
dashboard all touch one file. Without `journal_mode=WAL` you get `database is
locked` within a day. Set on every write connection, along with a 5s
`busy_timeout` and short transactions.

**Timestamps are normalised to whole seconds.** All time-window queries compare
timestamps as SQLite *strings*, which is only correct when every string has the
same width. Cowrie emits microseconds, so `normalize_timestamp()` truncates them
on the way in — otherwise `15:00:00.5Z` sorts before `15:00:00Z` and window
queries quietly lose events.

**The alert window is anchored on the newest event, not the wall clock.** A
replayed fixture file, or a node draining a `pending_events.jsonl` spool after an
outage, is still evaluated correctly instead of being silently skipped for being
"too old".

**Alert deduplication has two layers.** Time-windowed rules bucket their
`dedupe_key` onto the window grid, so re-running mid-window produces the same
deterministic `alert_id` and the insert is ignored. Event-scoped rules
(`suspicious_command`, `malware_staging`) key on `event_id` instead and skip the
cooldown, because every distinct command genuinely is its own finding.

**Foreign keys are enabled**, which means an event for an unregistered node would
fail. `apply_event()` therefore auto-creates a stub `nodes` row first, so Part 2
never has to care about ordering.

**`events` is append-only and authoritative; `sessions` is derived.** If session
derivation ever needs to change, it can be rebuilt by replaying `events` — no
data is lost to a bad derivation rule.

### Known limitations

- SQLite suits Version 1 comfortably. Past roughly 10 M events or several
  concurrent writers, migrating to PostgreSQL is the natural next step; only
  `db/database.py` would change.
- The rules engine is a full scan of the window on every pass. Fine at project
  scale; a stateful streaming engine would be the upgrade path.
- TAXII *serving* is not implemented — only STIX bundle generation. Publishing
  the bundle over a TAXII 2.1 endpoint remains a stretch goal.

---

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Start directory is not importable: '.../tests'` | Python 3.14's stricter `unittest discover`. Run `python -m unittest tests.test_part4 -v` instead. If it persists, `touch tests/__init__.py`. |
| `fixture not found` / `seed` accepts 0 events | `tests/fixtures/*.jsonl` is missing — easy to drop when zipping or copying. Restore `sample_events.jsonl` and `sample_reputation.json`. |
| `database is locked` | A long transaction elsewhere. Confirm WAL is on: `PRAGMA journal_mode;` should return `wal`. Part 5 must use `read_only=True`. |
| `no such table: events` | Wrong `HONEYPOT_DB_PATH`, or `init` was never run. |
| `no such function: json_extract` | SQLite older than 3.38, or built without JSON1. |
| Events rejected as `node_id not registered` | Add the node to `KNOWN_NODES`, or set `STRICT_NODE_IDS=0`. |
| Alerts fire once then never again | Working as designed — see `ALERT_COOLDOWN_MINUTES`. |
| Seeded data produces no alerts | You used `--keep-timestamps`; the fixture then sits outside the window. |
| Part 3 sees zero IPs to enrich | The `is_private` / TEST-NET trap. See the Part 3 section. |
| `SecretLeakError` on export | Working as designed. A password reached the payload; the export aborted rather than leaking it. Find the unmasked read. |

