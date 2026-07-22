# Part 2 — Central Log Aggregation & Ingestion

This service receives the team-standardized honeypot events at `POST /api/events`, validates them, authenticates the sensor, stores them in SQLite, prevents duplicate events, updates node health, and maintains a session summary.

## Included behaviour

- Authenticates `X-Node-ID` + `X-Node-Key`
- Accepts only `node-01`, `node-02`, and `node-03`
- Validates the Baseline v1.3 event and `details` contracts
- Rejects body/header node mismatch
- Limits batches to 20 events by default
- Inserts every accepted event once using `event_id` as the unique key
- Updates `nodes.last_seen` and marks valid senders `online`
- Creates/updates sessions and closes them on `session_end`
- Enables SQLite WAL mode for safer local concurrent reads
- Provides `GET /health`, `GET /api/nodes/{node_id}`, and automatic FastAPI docs at `/docs`

## Quick start

```bash
cd part2_central_collector
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
export DATABASE_PATH=./data/collector.db
export NODE_KEYS_JSON='{"node-01":"dev-node-01-key","node-02":"dev-node-02-key","node-03":"dev-node-03-key"}'
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` to test the API interactively.

## Send a test event

```bash
curl -X POST http://127.0.0.1:8000/api/events \
  -H 'Content-Type: application/json' \
  -H 'X-Node-ID: node-01' \
  -H 'X-Node-Key: dev-node-01-key' \
  --data @tests/fixtures/login_attempt.json
```

The endpoint expects a batch wrapper. Use this command instead when sending the fixture directly:

```bash
curl -X POST http://127.0.0.1:8000/api/events \
  -H 'Content-Type: application/json' \
  -H 'X-Node-ID: node-01' \
  -H 'X-Node-Key: dev-node-01-key' \
  -d '{"events":[{"event_id":"550e8400-e29b-41d4-a716-446655440000","node_id":"node-01","event_type":"login_attempt","timestamp":"2026-07-22T11:00:00Z","session_id":"cowrie-abc123","attacker_ip":"203.0.113.10","protocol":"ssh","details":{"username":"root","password":"123456"}}]}'
```

Expected response:

```json
{"accepted": 1, "duplicates": 0, "rejected": 0, "errors": []}
```

## Run tests

```bash
pytest -q
```

## Docker

```bash
docker compose up --build
```

## Integration boundary

The Part 1 sensor agent sends only standardized JSON to this API. Part 3, Part 4, and Part 5 read the shared SQLite database or use future read APIs. Coordinate database-file location and migrations with the Part 4 owner before merging.
