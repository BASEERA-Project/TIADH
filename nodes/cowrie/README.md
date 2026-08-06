# Honeypot Node Deployment (Part 1)

Deploys and manages Cowrie honeypot nodes for the Distributed Honeypot Threat Intelligence Aggregator project, and ships their events to the central collector in the team's shared format.

## Role in the project

This is Part 1 of a 5-part distributed system (see the project's Technical Plan and Baseline documents). It runs SSH honeypot sensors on separate hosts, converts Cowrie's native logs into the shared event envelope defined in the team's frozen baseline, and delivers them to Part 2's central collector over HTTPS.

## Architecture

```
Cowrie (Docker) → cowrie.json → adapter.py (tail + transform) → HTTPS POST → collector
                                       │
                                       ├─ heartbeat every 60s
                                       └─ failed batches → pending_events.jsonl → retried every 30s
```

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Runs the Cowrie honeypot container |
| `adapter.py` | Tails Cowrie's logs, maps them to the shared event format, batches and ships them, with retry on failure |
| `validator.py` | Checks a batch of events against the shared schema (required fields, allowed event types, allowed `details` keys) |
| `stub_server.py` | Minimal local Flask server standing in for Part 2's real collector, for local testing |
| `requirements.txt` | Python dependencies |
| `.env.example` | Template for required environment variables |

## Configuration

Copy the template and fill in real values:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `NODE_ID` | `node-02` | This node's ID. Change it per sensor (`node-01`, `node-02`, …). Must be listed in the aggregator's `KNOWN_NODES`. |
| `NODE_KEY` | `dev-test-key` | This node's secret key. Must match this node's entry in the aggregator's `NODE_KEYS_JSON`. |
| `COLLECTOR_URL` | `http://localhost:8000/api/events` | Full URL of the collector's `/api/events` endpoint. `stub_server.py` is on **5000**, the real collector on **8000**. |
| `LOG_PATH` | `../cowrie-logs/cowrie.json` | Cowrie's JSON log. The default is relative to the working directory — set an absolute path. |
| `COWRIE_UID` / `COWRIE_GID` | `1000` / `1000` | The user the Cowrie **container** runs as. Read by `docker-compose.yml`, not by `adapter.py`. Only set these if this host's account isn't `1000` (`id -u`). |

`cowrie-logs/` and `cowrie-data/` are bind-mounted into the container, and Cowrie
writes its JSON log, sensor `uuid` and SSH host keys into them. The image's own
user is uid 999, which cannot write to directories owned by the account that
cloned this repo, so the container runs as `COWRIE_UID:COWRIE_GID` instead —
otherwise Cowrie exits at startup with:

```
"Permission denied when attempting to write uuid to var/lib/cowrie/uuid"
```

Both directories are tracked (with a `.gitkeep`) so that Docker doesn't create
them as `root` on a fresh clone, which would cause the same failure. If you hit
that error anyway, the directories are owned by the wrong user — check
`ls -ld cowrie-logs cowrie-data` against `id -u`.

`adapter.py` reads all of these from the environment, so a sensor is configured
without editing code. Nothing loads `.env` for you here: this host is a separate
machine with no `common` package, so source it yourself —

```bash
set -a; . ./.env; set +a
python3 adapter.py
```

— or pass the values inline (see "Running locally" below). The aggregator's own
configuration is a different file on a different machine; the only values that
have to agree are `NODE_ID` and `NODE_KEY`.

## Running locally

This part can be run and tested entirely on a local machine, without any AWS setup, using the included stub server.

**1. Set up the environment:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**2. Start Cowrie:**
```bash
docker compose up -d
```
Confirm it's listening:
```bash
docker ps
nc -vz localhost 2222
```

**3. Start the stub collector** (in its own terminal):
```bash
python3 stub_server.py
```

**4. Start the adapter** (in another terminal):
```bash
COLLECTOR_URL=http://localhost:5000/api/events NODE_KEY=dev-test-key python3 adapter.py
```

**5. Generate a test event** (in a third terminal):
```bash
ssh -p 2222 root@localhost
```
Any username/password will be accepted by Cowrie's default policy.

**6. Confirm the pipeline worked:**
- The adapter's terminal should print `Sent N event(s) — collector responded: 200 ...`
- The stub server's terminal should print the received event(s)
- Raw Cowrie logs are in `cowrie-logs/cowrie.json`; validate a batch of shipped events with:
```bash
python3 validator.py pending_events.jsonl
```
(only present if a send has failed at least once — see below to force this)

**To test retry/failure handling specifically:** stop `stub_server.py`, trigger another login attempt, and confirm the adapter logs `Failed to send batch... saving to pending_events.jsonl`. Restart the stub server and confirm the pending batch is retried within 30 seconds.

## Integration with the real collector

Once Part 2's collector is live:

1. Get the real collector URL and this node's real `NODE_KEY` from Part 2.
2. Set `COLLECTOR_URL` and `NODE_KEY` to the real values (update `.env` or export them).
3. Set `NODE_ID` to match this node's assigned ID — in `.env`, not in `adapter.py`.
4. Run the adapter the same way as in local testing — no code changes required, only configuration.
5. Confirm with Part 2 that events are being correctly parsed and written to the `sessions`/`commands`/`nodes` tables, not just that the HTTP response is `200`.

## Note on live deployment

This repo documents a live deployment across separate EC2 instances (see the Technical Plan's requirement for genuinely distributed nodes, not local containers on one machine). Provisioning the actual cloud infrastructure — instances, security groups, SSH access — is a manual process and isn't automated by anything in this repo. The steps above ("Running locally") are fully reproducible on any machine with Docker and Python; the AWS deployment itself is not.