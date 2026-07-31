# TIADH — Distributed Honeypot Threat Intelligence Aggregator

SSH honeypot sensors on separate hosts ship what attackers do to a central
collector. One shared database holds it; rules turn it into alerts, enrichment
adds geolocation and scoring, a dashboard makes it readable, and an exporter
publishes it as a threat feed in JSON, CSV and STIX 2.1.

Everything speaks one contract: **Baseline v1.3**, defined in
`common/src/common/db/schema.sql` and enforced by `common/db/validation.py`.

---

## How it runs

```
   SENSOR HOST(S)                          AGGREGATOR HOST
 ┌────────────────────┐          ┌──────────────────────────────────────────┐
 │ Cowrie   :2222     │          │  collector  :8000   (uvicorn, always on) │
 │   ↓ cowrie.json    │  HTTP    │      ↓ writes                            │
 │ adapter.py  ───────┼─────────►│  ┌────────────────────────────────────┐  │
 │   batches +        │  POST    │  │   honeypot_aggregator.db (SQLite)  │  │
 │   heartbeat 60s    │ /api/    │  └────────────────────────────────────┘  │
 └────────────────────┘  events  │      ↑ writes        ↑ writes    ↑ reads │
        one per node             │  enricher       main.py watch  dashboard │
                                 │  (30s loop)     (alerts+feed)     :8050  │
                                 └──────────────────────────────────────────┘
```

**The sensors are the only thing that belongs on other machines.** Everything
else runs on one host, because the four processes share a SQLite file and
SQLite needs local disk — `common/config.py` says it outright: *"Keep it on
local disk — SQLite over NFS/SMB corrupts."* The nodes never touch the
database; they only speak HTTP to the collector.

The alert engine is **not** a separate service. It is a mode of the core CLI:
`main.py alerts` runs one evaluation pass, `main.py run` runs one full cycle
(housekeeping → alerts → feed export), and `main.py watch` repeats that cycle
on a timer. That timer loop is what you leave running.

### The processes

| Process | Host | Command (from) | Port |
|---|---|---|---|
| **Cowrie honeypot** | sensor | `docker compose up -d` (`nodes/cowrie/`) | 2222 |
| **Node adapter** | sensor | `python3 adapter.py` (`nodes/cowrie/`) | — |
| **Collector** | aggregator | `uv run uvicorn --app-dir collector app.main:app` (`core/`) | 8000 |
| **Enricher** | aggregator | `uv run python enricher/enrich.py` (`core/`) | — |
| **Alerts + feed export** | aggregator | `uv run python main.py watch --interval 30` (`core/`) | — |
| **Dashboard** | aggregator | `uv run python main.py` (`dashboard/`) | 8050 |

What each one actually does:

- **adapter.py** tails Cowrie's `cowrie.json`, maps the events it cares about
  onto the Baseline v1.3 envelope, and POSTs them in batches with
  `X-Node-ID` / `X-Node-Key` headers. It sends a heartbeat every 60s, and
  spools failed batches to `pending_events.jsonl`, retried every 30s.
- **collector** authenticates the node, validates the envelope, and hands the
  batch to `Database.apply_events()`. It also runs the housekeeping pass
  (stale nodes offline, abandoned sessions closed) every 60s, because it is the
  only always-running writer.
- **enricher** polls `get_ips_needing_enrichment()` every 30s, geolocates each
  IP, computes a local profile score from that IP's own session and command
  history, and upserts a `reputation` row.
- **main.py watch** re-evaluates the seven detection rules over a rolling
  window, writes deduplicated alerts, and rewrites the exported feed files.
- **dashboard** opens the database **read-only**. Acknowledging or closing an
  alert is its only write, and `DASHBOARD_ALLOW_ALERT_ACTIONS=0` removes even
  that.

---

## Quick start

### Just the dashboard, with generated data

No sensors, no collector — the fastest way to see every screen populated:

```bash
cd dashboard
uv sync
uv run python tools/seed_demo.py            # a day of realistic traffic
uv run python main.py --db demo/honeypot_demo.db
```

Then open <http://127.0.0.1:8050>. The alerts on screen were produced by the
real rules engine running over the generated events, not written directly.

### The full pipeline

**1. Create the schema** (once, on the aggregator host):

```bash
cd core
uv sync
uv run python main.py init
```

**2. Start the four aggregator processes**, each in its own terminal, all with
the same `HONEYPOT_DB_PATH`:

```bash
cd core && uv run uvicorn --app-dir collector app.main:app --host 0.0.0.0 --port 8000
cd core && uv run python enricher/enrich.py
cd core && uv run python main.py watch --interval 30
cd dashboard && uv run python main.py
```

**3. On each sensor host**, run Cowrie and the adapter:

```bash
cd nodes/cowrie
cp .env.example .env                        # set COLLECTOR_URL and NODE_KEY
docker compose up -d                        # Cowrie on :2222
pip install -r requirements.txt
COLLECTOR_URL=http://<aggregator>:8000/api/events NODE_KEY=<this node's key> python3 adapter.py
```

Confirm the loop closed: `ssh -p 2222 root@<sensor>` from anywhere, then watch
the session appear on the dashboard's Sessions screen.

### In Docker

The collector ships a Dockerfile that installs `core` and `common` together:

```bash
cd core/collector
docker volume create tiadh_db      # once — the shared database volume
docker compose up --build
```

Any other part that runs in Docker must mount that **same named volume**, or it
will not be looking at the same database.

---

## Configuration

Every setting is an environment variable. The one that matters most:

| Variable | Default | |
|---|---|---|
| `HONEYPOT_DB_PATH` | `common/src/common/honeypot_aggregator.db` | **Every process on the aggregator host must point at the same file.** |
| `HONEYPOT_EXPORT_DIR` | `common/src/common/exports` | Where the published feed files are written |
| `KNOWN_NODES` | `node-01,node-02,node-03` | Node IDs allowed to submit events |
| `STRICT_NODE_IDS` | `1` | `0` to accept an ad-hoc node ID during a demo |
| `NODE_KEYS_JSON` | dev keys | Collector's `node-id` → secret key map |
| `ALERT_WINDOW_MINUTES` | `5` | How far back each rule looks per pass |
| `FEED_MIN_SEVERITY` | `medium` | Severity floor for the published feed |

Templates live next to the code that reads them: `core/.env.example` (database,
thresholds, feed policy), `core/collector/.env.example` (node keys, batch size),
`nodes/cowrie/.env.example` (collector URL, node key). Detection thresholds are
listed only in `common/config.py`; the dashboard's rules panel reads them live,
so what you see there is what the engine is using.

---

## Layout

```
common/     the shared library — installed, imported by everything
  config.py            all thresholds and paths
  db/                  Database, schema.sql, Baseline v1.3 validation
  alerting/            detection rules + the alert engine
  export/              threat feed builder (JSON / CSV / STIX 2.1)
core/       the operational layer — one uv project
  main.py              CLI: init, seed, ingest, alerts, export, run, watch, stats
  collector/           FastAPI ingest service (Part 2)
  enricher/            geolocation + scoring worker (Part 3)
dashboard/  Flask read model over the database (Part 5)
nodes/      sensor deployment (Part 1)
  cowrie/              docker-compose, adapter, validator, stub collector
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

- **`NODE_ID` is hardcoded** at the top of `nodes/cowrie/adapter.py` (currently
  `node-02`). It must be edited per sensor before running, and it must be in
  `KNOWN_NODES` or the collector rejects the events.
- **The adapter's log path is relative.** `LOG_PATH = "../cowrie-logs/cowrie.json"`,
  while `docker-compose.yml` mounts the logs to `./cowrie-logs` — so the
  adapter only finds them if it is run from a directory one level below the
  compose file. Check this before concluding the sensor is broken.
- **`nodes/cowrie/.env.example` points at `localhost:5000`**, which is
  `stub_server.py`, not the real collector. The real one is port **8000**.
- **The enricher's abuse score is a constant.** `enrich.py` sets
  `mock_external_abuse = 45` for every IP; only the geolocation (ip-api.com)
  and the locally computed profile score are real. Any rule keyed on
  `abuse_score` is therefore firing on a placeholder.
- **One collector test fails.** `test_rejects_bad_command_contract` expects a
  malformed event to return HTTP 200 with `rejected: 1`, but `app/models.py`
  still validates the `details` contract in the HTTP layer and returns 422.
  The test and the code disagree about where validation belongs.
- **Node health is wall-clock based**, so a seeded demo database drifts to
  amber and then red as real time passes. Re-run the seeder before a demo.
