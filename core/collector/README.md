# Collector — Central Log Aggregation & Ingestion (Part 2)

Lives at `core/collector/` and is part of the `core` uv project, alongside the
CLI (`core/main.py`) and the enricher (`core/enricher/`). It has no environment
of its own: `uv sync` in `core/` installs everything it needs.

**In a deployment you do not start this on its own.** `uv run main.py
serve` from `core/` runs the collector, the enricher and the alert/export cycle
in one process against one database handle — see the root README. The uvicorn
command below is still the right thing for working on the collector by itself,
with `--reload`.

This service receives team-standardised honeypot events at `POST /api/events`,
validates them against **Baseline v1.3**, authenticates the sending node, and
persists everything through the shared **`Database` class in the `common`
package**.

Part 2 no longer manages its own SQLite file. `common` owns the database;
Part 2 is the only always-running writer, so it also runs the housekeeping
loop (`mark_stale_nodes_offline` + `close_stale_sessions`) on a 60-second timer.

---

## Features

- Authenticates every request with `X-Node-ID` + `X-Node-Key` headers
- Accepts events from `node-01`, `node-02`, and `node-03`
- Validates the full Baseline v1.3 event envelope and `details` contract
- Rejects node-ID / header mismatches and oversized batches
- Delegates all storage to `common.db.database.Database.apply_events()` —
  masking, idempotency, and session derivation are handled there
- Background maintenance loop: stale nodes go offline, abandoned sessions
  are force-closed (the storage contract assigns this to Part 2)
- Endpoints: `GET /health`, `GET /api/nodes/{node_id}`, `POST /api/events`
- Interactive API docs at `http://localhost:8000/docs`

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.12+ and `uv` | |
| `uv sync` run in `core/` | Installs the collector, the enricher, the CLI and the shared `common` package into one environment |
| An initialised schema | Run `uv run main.py init` in `core/` once, before first start |
| Shared database path | Every part must point `HONEYPOT_DB_PATH` at the **same file** |

---

## Quick start (local)

### 1. Install and initialise the shared database

```bash
cd core
uv sync
uv run main.py init
```

### 2. Configure

The collector has no config file of its own. It reads the repository-root
`.env` / `.env.secrets`, which `common/config.py` loads on import:

```bash
cd ../..                              # repository root
cp .env.example .env
cp .env.secrets.example .env.secrets   # NODE_KEYS_JSON lives here
```

`COLLECTOR_HOST`, `COLLECTOR_PORT`, `MAX_BATCH_SIZE` and
`MAINTENANCE_INTERVAL_SECONDS` are in `.env`, and `NODE_KEYS_JSON` is in
`.env.secrets`. A real environment variable outranks both.

`COLLECTOR_HOST` / `COLLECTOR_PORT` (default `0.0.0.0:8000`) are the address
`main.py serve` binds; `serve --host/--port` overrides them for one run. The
bare uvicorn command below is uvicorn's own CLI and does not read them — pass
`--host`/`--port` to uvicorn instead.

Nothing points at the storage layer itself: `common` is installed as a
dependency, so `from common.db.database import Database` just works.

### 3. Run the collector on its own

From `core/`:

```bash
uv run uvicorn --app-dir collector app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` to test the API interactively. For the
deployed shape — collector plus enricher plus alert/export cycle — use
`uv run main.py serve` instead.

---

## Send a test event

```bash
curl -X POST http://127.0.0.1:8000/api/events \
  -H 'Content-Type: application/json' \
  -H 'X-Node-ID: node-01' \
  -H 'X-Node-Key: dev-node-01-key' \
  -d '{
    "events": [{
      "event_id":   "550e8400-e29b-41d4-a716-446655440000",
      "node_id":    "node-01",
      "event_type": "login_attempt",
      "timestamp":  "2026-07-28T19:00:00Z",
      "session_id": "cowrie-abc123",
      "attacker_ip": "203.0.113.10",
      "protocol":   "ssh",
      "details":    {"username": "root", "password": "123456"}
    }]
  }'
```

Expected response:

```json
{"accepted": 1, "duplicates": 0, "rejected": 0, "errors": []}
```

Sending the same request again returns:

```json
{"accepted": 0, "duplicates": 1, "rejected": 0, "errors": []}
```

---

## Run tests

From `core/` — `pyproject.toml` points pytest at `collector/tests`:

```bash
uv run pytest -q
```

---

## Docker

The image is now the whole aggregator, not just the collector, so it lives one
level up at `core/Dockerfile` and its `CMD` is `main.py serve`:

```bash
docker volume create tiadh_db      # once — the shared database volume
cd core
docker compose up --build
```

`serve` creates the schema on startup, so there is no separate init step. The
build context is the repository root so the image can install `core` and its
`common` dependency together; `.dockerignore` keeps local venvs and database
files out of it.

The compose file mounts a `tiadh_db` named volume for the database and the
exported feeds. The dashboard must mount the **same named volume** if it also
runs in Docker.

---

## Environment variables

Set in the repository-root `.env` / `.env.secrets` (see the root README), or
exported — an exported variable wins.

| Variable | Default | Lives in | Description |
|---|---|---|---|
| `HONEYPOT_DB_PATH` | inside the installed `common` package | `.env` | The shared SQLite database. Must resolve to the same file as the enricher, the alert engine and the dashboard — so make it absolute if you set it. |
| `NODE_KEYS_JSON` | dev keys | `.env.secrets` | JSON object mapping `node-id` → secret key. |
| `MAX_BATCH_SIZE` | `20` | `.env` | Maximum events per `POST /api/events` request. |
| `MAINTENANCE_INTERVAL_SECONDS` | `60` | `.env` | How often the housekeeping loop runs (stale nodes + sessions). |

---

## Integration boundary

| Direction | Who | What |
|---|---|---|
| → Part 2 | Part 1 (nodes) | `POST /api/events` with Baseline v1.3 JSON batches |
| Part 2 → | `common` `Database` | All writes go through `apply_events()`, `upsert_node()` |
| Part 2 → | `common` `Database` | Housekeeping: `mark_stale_nodes_offline()`, `close_stale_sessions()` |
| Enricher, dashboard → | Shared DB (read) | Read via `Database(read_only=True)` |

Do **not** open a direct SQLite connection to `honeypot_aggregator.db` from
Part 2. Always go through `common`'s `Database` class so masking and
idempotency are applied consistently.
