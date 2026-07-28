# Part 2 — Central Log Aggregation & Ingestion

This service receives team-standardised honeypot events at `POST /api/events`,
validates them against **Baseline v1.3**, authenticates the sending node, and
persists everything through **Part 4's shared `Database` class**.

Part 2 no longer manages its own SQLite file. Part 4 owns the database;
Part 2 is the only always-running writer, so it also runs the housekeeping
loop (`mark_stale_nodes_offline` + `close_stale_sessions`) on a 60-second timer.

---

## Features

- Authenticates every request with `X-Node-ID` + `X-Node-Key` headers
- Accepts events from `node-01`, `node-02`, and `node-03`
- Validates the full Baseline v1.3 event envelope and `details` contract
- Rejects node-ID / header mismatches and oversized batches
- Delegates all storage to Part 4's `Database.apply_events()` — masking,
  idempotency, and session derivation are handled there
- Background maintenance loop: stale nodes go offline, abandoned sessions
  are force-closed (Part 4's documented contract assigns this to Part 2)
- Endpoints: `GET /health`, `GET /api/nodes/{node_id}`, `POST /api/events`
- Interactive API docs at `http://localhost:8000/docs`

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.12+ | |
| Part 4 checked out | `part4_storage_alerting/` must exist and its schema must be initialised |
| Shared database path | Both parts must point `HONEYPOT_DB_PATH` at the **same file** |

---

## Quick start (local)

### 1. Initialise the shared database (Part 4 owns this step)

```bash
cd ../part4_storage_alerting
pip install -r requirements.txt
python main.py init
```

### 2. Set up Part 2

```bash
cd Part2_Central_Collector_API
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env
```

Edit `.env` and set at minimum:

```dotenv
# Absolute path to the same DB file Part 4 initialised
HONEYPOT_DB_PATH=/absolute/path/to/part4_storage_alerting/honeypot_aggregator.db

# Absolute path to the part4_storage_alerting directory
PART4_PATH=/absolute/path/to/part4_storage_alerting
```

### 3. Run the collector

```bash
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` to test the API interactively.

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

```bash
pytest -q
```

---

## Docker

> **Before running**, ensure the shared database volume exists and Part 4 has
> initialised the schema:
>
> ```bash
> cd ../part4_storage_alerting
> python main.py init
> ```

```bash
cd Part2_Central_Collector_API
docker compose up --build
```

The compose file mounts a shared `tiadh_db` named volume for the database.
All parts that run in Docker must use the **same named volume** so they share
one file.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `HONEYPOT_DB_PATH` | *(Part 4 default)* | Absolute path to the shared SQLite database. Must match Part 4, 3 and 5. |
| `PART4_PATH` | auto-detected | Absolute path to `part4_storage_alerting/`. Auto-detected when the full repo is checked out together. |
| `NODE_KEYS_JSON` | dev keys | JSON object mapping `node-id` → secret key. |
| `MAX_BATCH_SIZE` | `20` | Maximum events per `POST /api/events` request. |
| `MAINTENANCE_INTERVAL_SECONDS` | `60` | How often the housekeeping loop runs (stale nodes + sessions). |

---

## Integration boundary

| Direction | Who | What |
|---|---|---|
| → Part 2 | Part 1 (nodes) | `POST /api/events` with Baseline v1.3 JSON batches |
| Part 2 → | Part 4 `Database` | All writes go through `apply_events()`, `upsert_node()` |
| Part 2 → | Part 4 `Database` | Housekeeping: `mark_stale_nodes_offline()`, `close_stale_sessions()` |
| Part 3, 5 → | Shared DB (read) | Read via Part 4's `Database(read_only=True)` |

Do **not** open a direct SQLite connection to `honeypot_aggregator.db` from
Part 2. Always go through Part 4's `Database` class so masking and
idempotency are applied consistently.
