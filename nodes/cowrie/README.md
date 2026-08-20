# Cowrie sensor (Part 1)

Deploys and manages Cowrie honeypot nodes for the Distributed Honeypot Threat Intelligence Aggregator project, and ships their events to the central collector in the team's shared format.

## Role in the project

This is one of the two sensors in Part 1 of a 5-part distributed system (see the project's Technical Plan and Baseline documents) — the other is `../dionaea/`. It runs SSH honeypot sensors on separate hosts, converts Cowrie's native logs into the shared event envelope defined in the team's frozen baseline, and delivers them to Part 2's central collector over HTTP.

## Architecture

```
Cowrie (Docker) → cowrie.json → adapter.py (tail + transform) → HTTP POST → collector
                       │               │
                       │               ├─ heartbeat every 60s
                       │               └─ failed batches → pending_events.jsonl → retried every 30s
                       │
                       └─ rotated daily to cowrie.json.YYYY-MM-DD, and the
                          adapter follows it (see "Log rotation" below)
```

Only the middle step is about Cowrie. Tailing across rotation, batching,
heartbeating, spooling and retrying are the same on any sensor, so they live in
`../shipper/` and are shared with the dionaea node. `adapter.py` is Cowrie's
event mapping and nothing else.

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Runs the Cowrie honeypot container |
| `adapter.py` | Maps Cowrie's JSON events onto the shared envelope, and hands them to `shipper` to tail, batch and ship |
| `backfill.py` | Sends events **already** on disk — every `cowrie.json*` including the rotated ones. For history the adapter never sees; safe to re-run |
| `validator.py` | Checks a batch of events against the shared schema (required fields, allowed event types, allowed `details` keys) |
| `stub_server.py` | Minimal local Flask server standing in for Part 2's real collector, for local testing |
| `pyproject.toml` / `uv.lock` | Python dependencies, pinned. This is a uv project like `core/` and `dashboard/` |
| `.env.example` | Template for required environment variables |

The last three are one-line entry points into `../shipper/`, which holds the
code itself. That directory is a **path dependency** of this one, so a sensor
host wants the repository checked out rather than this directory copied on its
own — which is what the deployment steps in the root README already assume.

## Configuration

Copy the template and fill in real values:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `NODE_ID` | `node-02` | This node's ID. Change it per sensor (`node-01`, `node-02`, …). Must be listed in the aggregator's `KNOWN_NODES`. |
| `NODE_KEY` | `dev-test-key` | This node's secret key. Must match this node's entry in the aggregator's `NODE_KEYS_JSON`. |
| `COLLECTOR_URL` | `http://localhost:8000/api/events` | Full URL of the collector's `/api/events` endpoint: the aggregator's address on this network, and its `COLLECTOR_PORT` — **8000** unless it was changed in the aggregator's `.env`. `stub_server.py` is on **5000** instead. |
| `LOG_PATH` | `./cowrie-logs/cowrie.json` | Cowrie's JSON log — the host side of the mount in `docker-compose.yml`. The default is relative to the **working directory**, so it only resolves when the adapter is started from this directory; set an absolute path if you start it from anywhere else. |
| `PROTOCOL` | `ssh` | Stamped into every event's `protocol` field. Not in `.env.example`: `docker-compose.yml` publishes Cowrie's SSH port only, so the default is already right. |
| `COWRIE_UID` / `COWRIE_GID` | `1000` / `1000` | The user the Cowrie **container** runs as. Read by `docker-compose.yml`, not by `adapter.py`. Only set these if this host's account isn't `1000` (`id -u`). |

### Timing

Every interval the adapter runs on is a variable too, all in seconds, all
optional. The defaults are the values these loops were hardcoded to, so a
sensor that sets none of them behaves exactly as it always has.

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL_SECONDS` | `1` | How long the tailer waits before looking at `cowrie.json` again when it has nothing new — and so how quickly a rotation is noticed. |
| `HEARTBEAT_INTERVAL_SECONDS` | `60` | How often this node sends a heartbeat. **Must agree with the aggregator** — see below. |
| `BATCH_INTERVAL_SECONDS` | `10` | How long a partly-filled batch waits before being sent anyway. A batch that reaches 20 events is sent the moment it does, whatever this says. |
| `RETRY_INTERVAL_SECONDS` | `30` | How often events spooled to `pending_events.jsonl` by a failed send are retried. Lower it if the link to the aggregator is flaky. |
| `SUMMARY_INTERVAL_SECONDS` | `300` | How often the adapter prints a line naming the Cowrie event types it has skipped, and how many of each. A sensor that is dropping most of what it reads must not look the same as a quiet one. |

A value that isn't a positive number is refused rather than obeyed — the
adapter prints a line saying so and keeps the default. Zero would turn the loop
it paces into a busy-wait, and a typo would otherwise quietly change how often
this sensor reports.

`HEARTBEAT_INTERVAL_SECONDS` is the one to be careful with, because it is a
**Baseline v1.3 contract value and not a local preference**. The aggregator
marks a node offline after three missed beats — `NODE_OFFLINE_AFTER_SECONDS`,
which `common/config.py` derives from *its* copy of this same variable — and
the dashboard reports node health in missed heartbeats. Raise it on a sensor
without raising it on the aggregator and that node flaps offline between beats,
while still shipping events perfectly well.

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

`cowrie-data/` also keeps three empty subdirectories — `tty/`, `downloads/` and
`snapshots/`. Cowrie expects them to exist and does not create them, and mounting
`cowrie-data/` over `var/lib/cowrie` hides the ones baked into the image. Without
them the honeypot starts and accepts logins, but every session dies the moment a
shell opens:

```
[twisted.conch.ssh.session#critical] Error getting shell
builtins.FileNotFoundError: [Errno 2] No such file or directory: 'var/lib/cowrie/tty/...log'
```

Don't delete them. Their contents — session recordings and malware Cowrie
captured — are ignored by git, but the empty directories themselves are tracked.

`adapter.py` reads all of these from the environment, so a sensor is configured
without editing code, and it loads `.env` itself — nothing to source:

```bash
cp .env.example .env        # fill in COLLECTOR_URL and NODE_KEY
uv run adapter.py
```

A real environment variable still outranks the file, so you can override one
value for one run without editing anything:

```bash
NODE_KEY=some-other-key uv run adapter.py
```

It loads the `.env` sitting next to `adapter.py`, named explicitly rather than
searched for. That matters on a machine with the whole repository checked out:
python-dotenv's default is to walk *up* the directory tree, which from here
finds the **aggregator's** root `.env` — a different host's configuration, with
`KNOWN_NODES`, database paths and the rest. A sensor is configured by the file
beside it or not at all. The only values that have to agree with the aggregator
are `NODE_ID` and `NODE_KEY`.

## Log rotation

Cowrie does not write to `cowrie.json` forever. Once a day it closes that file,
renames it to `cowrie.json.2026-08-06`, and creates a new, empty `cowrie.json`
in its place.

A rename disturbs nothing that already has the file open, so a tailer that
opened `cowrie.json` at startup follows the log into its archived name — where
not one more byte will ever be written — while every new event lands in the new
file under the old name. Nothing errors and nothing crashes: the sensor just
goes quiet at the first rotation, and stays quiet until someone restarts it.

`adapter.py` checks for this every time it reaches the end of the file, which
on a quiet node is once every `POLL_INTERVAL_SECONDS` (1 by default). It
compares the inode `LOG_PATH`
names now against the one it holds open, and when they differ it drains what
is left of the old file — the rename is Cowrie's last act on it, so whatever
is still in there is complete — then reopens the new one **from the start**,
and says so:

```
./cowrie-logs/cowrie.json was rotated away — reopening
```

Three neighbouring cases are handled the same way:

- **The log doesn't exist yet.** Starting the adapter before Cowrie no longer
  kills it with `FileNotFoundError`; it waits, prints that it's waiting, and
  picks the file up when Cowrie creates it.
- **The log is emptied in place** instead of renamed — what a `logrotate` rule
  with `copytruncate` does. The inode doesn't change, so the check above can't
  see it; the giveaway is a file that has become shorter than the offset being
  read from, and the adapter starts over from the top of it.
- **A half-written line.** A line caught mid-write is held until the rest of it
  arrives, rather than going to `json.loads()` — which would lose that event
  twice: once as an unparseable fragment, and again when the remainder turned
  up looking like an unparseable line of its own.

Two things this deliberately does *not* do. Archived `cowrie.json.*` files are
never read, and nothing in this repo deletes them — they're ignored by git, and
clearing them out is the host's business. And a restart resumes at the **end**
of the current log, so events that arrived while the adapter was down are not
shipped: that is the same rule that stops a restart from replaying the entire
file at the collector.

`backfill.py` is the answer to both, and it's next.

## Backfilling old logs

Those two rules leave real traffic on the floor: everything Cowrie recorded
before this sensor was wired up to a collector, and everything it recorded
while the adapter was stopped. `backfill.py` reads it all — every
`cowrie.json*` in the log directory, archives first, oldest to newest — and
sends it in one pass:

```bash
uv run backfill.py                                    # everything on disk
uv run backfill.py --dry-run                          # say what would be sent
uv run backfill.py --since 2026-08-07                 # only from then on
uv run backfill.py cowrie-logs/cowrie.json.2026-08-06 # named files only
```

It shares `adapter.py`'s event mapping, envelope, `.env` and credentials by
importing it, so the two cannot drift apart, and it reuses the shipper's
validator for the baseline rules. A gzipped archive is read without unpacking
it first.

**Running it twice is safe.** Where the adapter generates a fresh random
`event_id` per event, backfill derives the id from the event itself, so a
second run sends the same ids and the collector answers `duplicates` instead of
inserting a second copy of every session:

```
91 event(s) sent — collector accepted 91, 0 already had, 0 refused
91 event(s) sent — collector accepted 0, 91 already had, 0 refused
```

That only holds *between backfill runs*. Events the live adapter already
shipped carry its random ids, so backfilling over a window the adapter covered
does duplicate them — `--since` is there to cut the overlap out, set to
roughly when the adapter started.

**One bad event would otherwise cost twenty.** The collector validates the
whole batch before touching the database, so a single event that breaks the
contract returns 422 and loses every good event travelling with it. Cowrie
produces such events in the ordinary course of business — an attacker who
presses Enter logs a `cowrie.command.input` with an empty command, and the
baseline requires `details.command` to be non-empty. Backfill checks each event
against the collector's contract first and reports what it dropped, rather than
finding out twenty at a time:

```
335 line(s) read from 2 file(s)
  243 held nothing we ship
  1 the collector would have refused, and taken their batch down with them:
      1  details.command must be a non-empty string for command
```

Batches go out at 20 events, the collector's default `MAX_BATCH_SIZE`;
`--batch-size` follows it if the aggregator was configured higher. A failed
send stops the run rather than spooling to `pending_events.jsonl` — there is
nothing to lose by fixing the problem and running it again.

## Running locally

This part can be run and tested entirely on a local machine, without any AWS setup, using the included stub server.

**1. Set up the environment:** nothing to do. Every command below runs through
`uv run`, which creates `.venv/` and installs the pinned versions from
`uv.lock` on its own — no separate install step, no virtualenv to activate.
Shipping events needs only `requests` and `python-dotenv` (plus `../shipper`,
built from the checkout), so that is all a sensor host ever installs. Flask is
an opt-in `stub` extra, because the sole thing that uses it is the stub
collector below.

**2. Start Cowrie:**
```bash
docker compose up -d
```
Confirm it's listening:
```bash
docker ps
nc -vz localhost 2222
```

**3. Start the stub collector** (in its own terminal). This is the one command
that needs Flask, so it asks for the `stub` extra:
```bash
uv run --extra stub stub_server.py
```

**4. Start the adapter** (in another terminal). The stub listens on 5000 while
`.env` points at the real collector on 8000, so override that one value for this
run — inline variables outrank the file:
```bash
COLLECTOR_URL=http://localhost:5000/api/events NODE_KEY=dev-test-key uv run adapter.py
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
uv run validator.py pending_events.jsonl
```
(only present if a send has failed at least once — see below to force this)

**To test retry/failure handling specifically:** stop `stub_server.py`, trigger another login attempt, and confirm the adapter logs `Failed to send batch... saving to pending_events.jsonl`. Restart the stub server and confirm the pending batch is retried within 30 seconds.

**To test rotation handling specifically:** don't wait a day for it — rotate
the log by hand, and make Cowrie reopen it:

```bash
mv cowrie-logs/cowrie.json cowrie-logs/cowrie.json.$(date +%F)
docker compose restart cowrie
```

The restart is the part that matters. Renaming alone leaves Cowrie writing to
the file under its *new* name, because its own handle followed the rename just
like the adapter's would; restarting is what makes it open a fresh
`cowrie.json`, which is what a real rotation does. Then log in over SSH again
and confirm the adapter prints `… was rotated away — reopening` and that the
new event still arrives at the collector.

## Integration with the real collector

Once Part 2's collector is live:

1. Get the real collector URL and this node's real `NODE_KEY` from Part 2.
2. Set `COLLECTOR_URL` and `NODE_KEY` to the real values (update `.env` or export them).
3. Set `NODE_ID` to match this node's assigned ID — in `.env`, not in `adapter.py`.
4. Run the adapter the same way as in local testing — no code changes required, only configuration.
5. Confirm with Part 2 that events are being correctly parsed and written to the `sessions`/`commands`/`nodes` tables, not just that the HTTP response is `200`.

## Note on live deployment

This repo documents a live deployment across separate EC2 instances (see the Technical Plan's requirement for genuinely distributed nodes, not local containers on one machine). Provisioning the actual cloud infrastructure — instances, security groups, SSH access — is a manual process and isn't automated by anything in this repo. The steps above ("Running locally") are fully reproducible on any machine with Docker and Python; the AWS deployment itself is not.