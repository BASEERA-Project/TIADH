# TIADH — Distributed Honeypot Threat Intelligence Aggregator

SSH honeypot sensors on separate hosts ship what attackers do to a central
collector. One shared database holds it; rules turn it into alerts, enrichment
adds geolocation and scoring, a dashboard makes it readable, and an exporter
publishes it as a threat feed in JSON, CSV and STIX 2.1.

Everything speaks one contract: **Baseline v1.3**, defined in
`common/src/common/db/schema.sql` and enforced by `common/db/validation.py`.

---

## How it runs

Two commands on the aggregator host. One for the pipeline, one for the
dashboard.

```
   SENSOR HOST(S)                          AGGREGATOR HOST
 ┌───────────────────┐          ┌─────────────────────────────────────────────┐
 │ Cowrie      :2222 │          │ main.py serve — one process, three loops    │
 │   ↓ cowrie.json   │  HTTP    │  ┌──────────────┬────────────┬───────────┐  │
 │ adapter.py ───────┼─────────►│  │ collector    │ enricher   │ alerts +  │  │
 │   batches +       │  POST    │  │ :8000        │ every 30s  │ feed, 30s │  │
 │   heartbeat 60s   │  /api/   │  │ + housekeep  │            │           │  │
 └───────────────────┘  events  │  └──────────────┴──────┬─────┴───────────┘  │
      one per node              │                        │ one shared handle  │
                                │  ┌─────────────────────▼─────────────────┐  │
                                │  │   honeypot_aggregator.db (SQLite)     │  │
                                │  └─────────────────────┬─────────────────┘  │
                                │                        │ reads, read-only   │
                                │  ┌─────────────────────▼─────────────────┐  │
                                │  │  dashboard :8050 — its own process    │  │
                                │  └───────────────────────────────────────┘  │
                                └─────────────────────────────────────────────┘
```

**The sensors are the only thing that belongs on other machines.** Everything
else runs on one host, because the processes share a SQLite file and SQLite
needs local disk — `common/config.py` says it outright: *"Keep it on local disk
— SQLite over NFS/SMB corrupts."* The nodes never touch the database; they only
speak HTTP to the collector.

The alert engine is **not** a separate service. It is a mode of the core CLI:
`main.py alerts` runs one evaluation pass, `main.py run` runs one full cycle
(housekeeping → alerts → feed export), and `main.py serve` runs that cycle on a
timer alongside the collector and the enricher.

### The processes

| Process | Host | Command (from) | Port |
|---|---|---|---|
| **Cowrie honeypot** | sensor | `docker compose up -d` (`nodes/cowrie/`) | 2222 |
| **Node adapter** | sensor | `uv run adapter.py` (`nodes/cowrie/`) | — |
| **Aggregator** | aggregator | `uv run main.py serve` (`core/`) | 8000 |
| **Dashboard** | aggregator | `uv run main.py` (`dashboard/`) | 8050 |

What each one actually does:

- **adapter.py** tails Cowrie's `cowrie.json`, maps the events it cares about
  onto the Baseline v1.3 envelope, and POSTs them in batches with
  `X-Node-ID` / `X-Node-Key` headers. It sends a heartbeat every 60s, and
  spools failed batches to `pending_events.jsonl`, retried every 30s.
- **main.py serve** is the aggregator pipeline, three loops in one process:
  - *collector* — authenticates the node, validates the envelope, and hands the
    batch to `Database.apply_events()`. It also runs the housekeeping pass
    (stale nodes offline, abandoned sessions closed) every 60s, because it is
    the only always-running writer.
  - *enricher* — polls `get_ips_needing_enrichment()` every 30s, geolocates each
    IP (ip-api.com), scores it against AbuseIPDB, computes a local profile score
    from that IP's own session and command history, and upserts a `reputation`
    row. The AbuseIPDB half is skipped when no key is configured.
  - *alerts + feed export* — re-evaluates the seven detection rules over a
    rolling window, writes deduplicated alerts, and rewrites the exported feed
    files.
- **dashboard** opens the database **read-only**. Acknowledging or closing an
  alert is its only write, and `DASHBOARD_ALLOW_ALERT_ACTIONS=0` removes even
  that.

### Why two commands and not one, or four

The three loops inside `serve` were three terminals because they started life as
three coursework parts, not because they need to be three processes. They are
one uv project, one environment, one `HONEYPOT_DB_PATH`, and all three write.
Running them together means they share a single `Database` handle and therefore
a single in-process write lock, so their writes queue in memory instead of
racing for SQLite's file lock. It also removes a duplicated housekeeping pass:
the collector and the alert cycle were both sweeping stale nodes and sessions.

The dashboard stays out of that process on purpose:

- it is a **separate uv project** with its own environment — Flask, not FastAPI
  — so folding it in would mean either fusing the two projects or shelling out
  to `uv run --project ../dashboard`;
- it opens the database **read-only** while the other three are writers;
- it makes a **different exposure decision**: the collector binds `0.0.0.0`
  because the sensors are remote, and the dashboard binds loopback because it
  renders attacker IPs, session transcripts and the outbound feed;
- it has to run **alone** against a demo database (see the quick start), and
  restarting a viewer should never interrupt ingestion.

---

## Quick start

### Just the dashboard, with generated data

No sensors, no collector — the fastest way to see every screen populated:

```bash
cd dashboard
uv sync
uv run tools/seed_demo.py            # a day of realistic traffic
uv run main.py --db demo/honeypot_demo.db
```

Then open <http://127.0.0.1:8050>. The alerts on screen were produced by the
real rules engine running over the generated events, not written directly.

### The full pipeline

**1. Start the aggregator** — collector, enricher and alert/export cycle, one
process, one terminal:

```bash
cp .env.example .env                        # from the repository root
cp .env.secrets.example .env.secrets        # then set real node keys
cd core
uv sync
uv run main.py serve
```

It creates the schema on first start, so there is no separate init step, and it
logs which env files it loaded. Ctrl-C stops all three loops.

**2. Start the dashboard** in a second terminal. It reads the same `.env` and
therefore the same database — no second configuration step:

```bash
cd dashboard
uv sync
uv run main.py
```

**3. On each sensor host**, run Cowrie and the adapter:

```bash
cd nodes/cowrie
cp .env.example .env                        # set COLLECTOR_URL and NODE_KEY
docker compose up -d                        # Cowrie on :2222
uv sync --no-dev                            # --no-dev: skip the stub collector's Flask
uv run adapter.py                           # reads the .env beside it
```

Confirm the loop closed: `ssh -p 2222 root@<sensor>` from anywhere, then watch
the session appear on the dashboard's Sessions screen.

### Running the pieces separately

`serve` is a convenience, not a lock-in. Every loop is still its own entry
point, which is what you want when you are working on one of them:

```bash
cd core && uv run uvicorn --app-dir collector app.main:app --reload
cd core && uv run enricher/enrich.py
cd core && uv run main.py watch --interval 30
```

`watch` is `serve` without the collector and the enricher — it *does* run the
housekeeping sweep, because in that shape nothing else is.

### In Docker

`core/Dockerfile` builds the whole aggregator and its `CMD` is `main.py serve`:

```bash
docker volume create tiadh_db      # once — the shared database volume
cd core
docker compose up --build
```

The dashboard, if you also containerise it, must mount that **same named
volume** or it will not be looking at the same database.

`.env` and `.env.secrets` are excluded from the build context on purpose, so a
container is configured by compose's `environment:` block (which outranks the
files anyway) or by a secrets manager — not by a file baked into the image.

---

## Configuration

One pair of files per host. On the aggregator:

```bash
cp .env.example .env                  # everything: paths, thresholds, dashboard
cp .env.secrets.example .env.secrets  # node keys + the dashboard signing key
```

That is the whole setup step. `common/config.py` loads both on import, so the
collector, the enricher, the alert cycle **and** the dashboard pick them up
with nothing exported and nothing sourced — they are two separate uv projects
reading one configuration. Both files are gitignored and excluded from Docker
build contexts; the `.example` templates are committed.

Secrets are split out so the main template stays boring enough to commit and
`.env.secrets` is the only file you have to handle carefully.

**A real environment variable always beats the file.** That is what keeps
per-run overrides, `--db`, and Docker's `environment:` block working:

```bash
FEED_MIN_SEVERITY=high uv run main.py serve     # wins over .env
```

The files are parsed as data rather than sourced by the shell, so values with
spaces (`FEED_PRODUCER`) and JSON braces (`NODE_KEYS_JSON`) do not need
quoting. Quote a value if it genuinely contains ` #`. Set `TIADH_ENV_FILE` to
point somewhere else, or to the empty string to ignore the files entirely.

The settings you will actually touch:

| Variable | Default | |
|---|---|---|
| `HONEYPOT_DB_PATH` | inside the installed `common` package | **Every part on the host must resolve to the same file.** Leave it unset unless you need to move it — and if you set it, make it **absolute**, or each process resolves it against its own working directory. |
| `HONEYPOT_EXPORT_DIR` | `common/src/common/exports` | Where the published feed files are written |
| `KNOWN_NODES` | `node-01,node-02,node-03` | Node IDs allowed to submit events |
| `COLLECTOR_HOST` / `COLLECTOR_PORT` | `0.0.0.0` / `8000` | Where the collector listens. `0.0.0.0` because the sensors are remote — the opposite of the dashboard. Change the port here **and** in every sensor's `COLLECTOR_URL`. |
| `NODE_KEYS_JSON` | *(secrets file)* | Collector's `node-id` → secret key map |
| `DASHBOARD_SECRET_KEY` | *(secrets file)* | Set before exposing the dashboard off loopback |
| `ALERT_WINDOW_MINUTES` | `5` | How far back each rule looks per pass |
| `FEED_MIN_SEVERITY` | `medium` | Severity floor for the published feed |

`.env.example` lists all 34 with comments; `common/config.py`,
`core/collector/app/config.py` and `dashboard/app/settings.py` are the three
modules that read them. Detection thresholds live in `common/config.py` and the
dashboard's rules panel reads them live, so what you see there is what the
engine is using.

`serve` takes flags for the runtime knobs:

| Flag | Default | |
|---|---|---|
| `--host` / `--port` | `COLLECTOR_HOST` / `COLLECTOR_PORT` | Collector bind address, for one run — the persistent setting is the `.env` pair above |
| `--interval` | `30` | Seconds between alert/export cycles |
| `--enrich-interval` | `30` | Seconds between enrichment passes |
| `--no-enricher` | off | Skip the enricher — it calls ip-api.com and AbuseIPDB, so use this offline |
| `--window`, `--min-severity` | from `common/config.py` | Per-run overrides |

### Sensor hosts

A sensor is a different machine with no `common` package, so it configures
itself: copy `nodes/cowrie/.env.example` to `.env` and `adapter.py` loads it via
python-dotenv, with the same precedence as here — a real environment variable
beats the file.

It loads that file **by name, from its own directory**, never by searching
upwards. On a machine with the whole repository checked out, an upward search
would climb out of `nodes/cowrie/` and find this aggregator `.env` instead,
which configures a different host entirely.

Three values have to agree with the aggregator: `NODE_ID` must appear in
`KNOWN_NODES`, `NODE_KEY` must match that node's entry in `NODE_KEYS_JSON`, and
`COLLECTOR_URL` must name the address the collector is actually bound to —
`COLLECTOR_HOST`/`COLLECTOR_PORT` written from the other end, with the
aggregator's routable IP in place of a `0.0.0.0` bind.

---

## Layout

```
.env.example          aggregator-host configuration — copy to .env
.env.secrets.example  node keys + dashboard signing key — copy to .env.secrets
common/     the shared library — installed, imported by everything
  config.py            .env loading, all thresholds and paths
  db/                  Database, schema.sql, Baseline v1.3 validation
  alerting/            detection rules + the alert engine
  export/              threat feed builder (JSON / CSV / STIX 2.1)
core/       the aggregator — one uv project, one process in deployment
  main.py              CLI: serve, init, seed, ingest, alerts, export, run, watch, stats
  collector/           FastAPI ingest service (Part 2)
  enricher/            geolocation + scoring worker (Part 3)
  Dockerfile           builds the whole aggregator; CMD is `main.py serve`
dashboard/  Flask read model over the database (Part 5)
nodes/      sensor deployment (Part 1)
  cowrie/              docker-compose, adapter, validator, stub collector
                       its own uv project — no `common`, it runs on another host
```

`common` is the only package the others depend on, and it depends on nothing
outside the standard library. Nothing imports `core` — not the dashboard, not
the collector.

### Tests

```bash
cd core && uv run pytest          # collector: HTTP, auth, dedupe, contract
```

---

## Known rough edges

Things that will bite during a deployment, all of them real as of this commit:

- **The adapter's default log path is relative.** `LOG_PATH` now comes from the
  environment, but its default is still `../cowrie-logs/cowrie.json` while
  `docker-compose.yml` mounts the logs to `./cowrie-logs` — so an adapter run
  without `LOG_PATH` set only finds them from a directory one level below the
  compose file. Set an absolute path and stop thinking about it.
- **`NODE_ID` defaults to `node-02`.** It is an environment variable now, but
  the default is a real node ID rather than an error, so a sensor started
  without one silently claims to be node-02.
- **The abuse score needs a key to exist at all.** `abuse_score` is now a real
  AbuseIPDB lookup, but with no `ABUSEIPDB_API_KEY` set the enricher leaves the
  column NULL — geolocation and the local profile score still work, and
  `high_risk_ip` then fires on the profile score alone. The enricher says so in
  its log, once, at startup.
- **ip-api.com rate-limits to 45 requests a minute** on the free tier, and
  AbuseIPDB's to 1000 checks a day. A burst of new attacker IPs will start
  failing lookups. A failed lookup is written as NULL and never as a score of
  zero — but it is still written, on a fresh `last_updated`, so
  `get_ips_needing_enrichment()` will not offer that IP again until the row ages
  past `max_age_days` (7). An IP enriched during an outage keeps its gaps for a
  week unless you clear its `reputation` row.
- **One collector test fails.** `test_rejects_bad_command_contract` expects a
  malformed event to return HTTP 200 with `rejected: 1`, but `app/models.py`
  still validates the `details` contract in the HTTP layer and returns 422.
  The test and the code disagree about where validation belongs.
- **Node health is wall-clock based**, so a seeded demo database drifts to
  amber and then red as real time passes. Re-run the seeder before a demo.
