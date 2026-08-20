# dionaea sensor (Part 1)

Runs a [dionaea](https://github.com/DinoTools/dionaea) honeypot and ships what
it catches to the central collector in the team's shared format.

## Role in the project

The baseline names dionaea as the project's optional second honeypot, and it
answers a different question from Cowrie. Cowrie is an SSH shell: it tells you
what an attacker *typed* once they were in. Dionaea impersonates Windows
network services — SMB above all — and tells you what an attacker *sent*, up to
and including the malware they tried to plant.

This directory is the dionaea half. `../cowrie/` is the SSH half, and
`../shipper/` is everything both of them do that is not about a honeypot.

## Architecture

```
dionaea (Docker) → dionaea_incident.json → adapter.py (map) → HTTP POST → collector
                            │                     │
                            │                     ├─ heartbeat every 60s
                            │                     └─ failed batches → pending_events.jsonl
                            │                        → retried every 30s
                            │
                            └─ not rotated by dionaea itself — see "Log rotation"
```

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Runs the dionaea container, with the JSON log turned on |
| `ihandlers-enabled/log_incident.yaml` | The config that turns it on. Mounted into the container |
| `ihandlers-available/log_json.yaml` | The other JSON log, if you prefer it. Not mounted |
| `adapter.py` | Maps dionaea's JSON onto the shared envelope, and hands it to `shipper` to tail, batch and ship |
| `backfill.py` | Sends events **already** on disk. For history the adapter never saw; safe to re-run |
| `validator.py` | Checks a batch of events against the shared schema |
| `stub_server.py` | Minimal local Flask server standing in for Part 2's real collector |
| `pyproject.toml` / `uv.lock` | Python dependencies, pinned. A uv project like `core/` and `dashboard/` |
| `.env.example` | Template for required environment variables |

The last three are one-line entry points into `../shipper/`, which is a **path
dependency** of this project — so a sensor host wants the repository checked
out rather than this directory copied on its own.

## What gets shipped, and what does not

This is the thing to understand before deploying this node.

Baseline v1.3 allows four protocol values — `ssh`, `telnet`, `ftp`, `smb` — and
`sessions.protocol` is a CHECK constraint in the frozen schema, so an event
naming anything else is refused by the aggregator however well-formed the rest
of it is. Two of those four are in the contract precisely because dionaea was
the planned second sensor:

| dionaea service | shipped as |
|---|---|
| `ftpd` | `ftp` |
| `smbd` | `smb` |

Everything else dionaea speaks — `httpd`, `mysqld`, `mssqld`, `SipSession`,
`TftpServerHandler`, `upnpd`, `mqttd`, `Memcache`, `mongod`, `printerd`,
`pptpd`, `epmapper`, `blackhole` — has no value in the contract to be named by.
Those connections are **counted and reported, never silently dropped**. The
adapter says so at startup:

```
Shipping ftpd→ftp, smbd→smb. dionaea's other 18 service(s) have no
Baseline v1.3 protocol and are counted, not shipped: httpd, mysqld, …
```

and again every `SUMMARY_INTERVAL_SECONDS` for as long as it keeps happening:

```
Skipped 412 connection(s): httpd (300), mysqld (112) — Baseline v1.3
allows ['ftp', 'smb'] and nothing else
```

`docker-compose.yml` therefore publishes **only ports 21 and 445**. Dionaea is
listening on the rest inside the container; there is no point inviting traffic
this sensor can only count. Widening the contract is a team decision — see the
change-control note at the end of the baseline document — and if it is taken,
this file's `PROTOCOL_MAP` is where the rest gets added.

Within those two protocols, the mapping is:

| dionaea incident | event |
|---|---|
| `dionaea.connection.tcp.accept` / `.tls.accept` / `.tcp.reject` | `connection` |
| `dionaea.modules.python.ftp.login` | `login_attempt` |
| `dionaea.modules.python.ftp.command` | `command` |
| `dionaea.download.offer` | `file_download` (the URL an exploit asked for) |
| `dionaea.download.complete.hash` | `file_download` (the file it got, with its md5) |
| `dionaea.connection.free` | `session_end` |

Two deliberate omissions:

- **No `login_success`.** Dionaea accepts every credential it is offered — its
  FTP module authenticates on any non-empty password and moves straight to
  `AUTHED`. A `login_success` from it would mean "dionaea said yes", not "the
  attacker guessed something real", and it would mark every dionaea IP as
  breached on the dashboard, drowning the Cowrie signal that means it. The
  credentials themselves are still shipped, in the `login_attempt`.
- **No `dionaea.download.complete.unique` / `.again`.** They are the same
  download reported a second time, split by whether the file was new to this
  sensor. Shipping them would double every capture.

### Passwords

FTP sends the password in the clear as an ordinary command, so dionaea logs
`PASS hunter2` in the command stream as well as in the login incident. The
adapter redacts the argument of `PASS` before it ever leaves this host:

```
USER root
PASS ***REDACTED***
RETR /etc/passwd
```

That is not belt-and-braces. `details.command` is masked nowhere in the
pipeline — a password landing there would be shown on the Sessions screen and
published in the exported feed. The password is still shipped where it belongs,
in `login_attempt`, which the aggregator stores in `sessions.password` and the
`sessions_public` view masks.

## Which JSON log to use

Dionaea can write two, and **neither is enabled in the shipped image**.
`adapter.py` reads either, deciding per line, so switching needs no code
change — only the mounted config and `LOG_PATH`.

| | `log_incident` (default here) | `log_json` |
|---|---|---|
| One line per | incident | connection, written when it closes |
| Captured malware | **yes** | no — it never sees `dionaea.download.*` |
| Connection id | **yes**, dionaea's own | none; the adapter mints one from the address pair |
| Timestamps | **one per event** | one per connection: every event in it is dated by when the connection *opened* |
| Session duration | **real** | not available |
| Status | "pre alpha" per its docs | documented and stable |
| Volume | every incident, most of which we skip | one line per connection |

`log_incident` is the default because the first three rows are what a threat
intelligence pipeline is for. If you would rather have the stable one, or you
are attaching this to a dionaea that already writes `dionaea.json`, mount
`ihandlers-available/log_json.yaml` instead and point `LOG_PATH` at
`dionaea-logs/dionaea.json`. Its `flat_data: true` mode is read too.

### The URL that has to be absolute

Dionaea's own shipped templates configure the handler as
`file://var/lib/dionaea/dionaea.json`. That is a two-slash URL, so `urlparse`
reads `var` as the *host* and `/lib/dionaea/dionaea.json` as the path, opening
it fails, and the loader swallows the error. Dionaea then runs perfectly
normally and writes no JSON at all. The only sign is one line, in
`dionaea-logs/dionaea.log`:

```
log_incident ...-critical: Unable to open file /lib/dionaea/dionaea_incident.json
                           Error message 'No such file or directory'
```

Both files in this directory use the absolute three-slash form. If you write
your own, do the same.

## Configuration

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `NODE_ID` | `node-03` | This node's ID. Must be listed in the aggregator's `KNOWN_NODES`. The Cowrie example uses `node-02`, so this one starts at `node-03`. |
| `NODE_KEY` | `dev-test-key` | This node's secret key. Must match this node's entry in the aggregator's `NODE_KEYS_JSON`. |
| `COLLECTOR_URL` | `http://localhost:8000/api/events` | The aggregator's address on this network plus its `COLLECTOR_PORT` — **8000** unless it was changed there. `stub_server.py` is on **5000**. |
| `LOG_PATH` | `./dionaea-logs/dionaea_incident.json` | The JSON log, host side of the mount in `docker-compose.yml`. Relative, so it only resolves when the adapter runs from this directory; set an absolute path otherwise. |

### Timing

Same four knobs as the Cowrie sensor, plus one that matters more here:

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL_SECONDS` | `1` | How long the tailer waits before looking again when it has nothing new |
| `HEARTBEAT_INTERVAL_SECONDS` | `60` | **Must agree with the aggregator** — it is a contract value, and three missed beats mark this node offline |
| `BATCH_INTERVAL_SECONDS` | `10` | How long a partly-filled batch waits. A batch reaching 20 goes immediately |
| `RETRY_INTERVAL_SECONDS` | `30` | How often `pending_events.jsonl` is retried |
| `SUMMARY_INTERVAL_SECONDS` | `300` | How often the adapter reports the services and incidents it skipped |

A value that isn't a positive number is refused rather than obeyed — the
adapter prints a line saying so and keeps the default.

### File ownership

`dionaea-logs/` and `dionaea-data/` are bind-mounted into the container, and
this is the one place dionaea is fussier than Cowrie. The container runs as
root and dionaea then **drops privileges to its own baked-in `dionaea` user,
uid 1000**, which is not something a `user:` line in compose can change. So the
two directories have to be writable by uid 1000 on this host.

That is already true if the account that cloned this repo is uid 1000, which it
usually is. If `id -u` says otherwise:

```bash
sudo chown -R 1000:1000 dionaea-logs dionaea-data
```

Both directories are tracked with a `.gitkeep` so Docker does not create them
as `root` on a fresh clone, which produces the same problem in a harder-to-read
form.

`DIONAEA_FORCE_INIT=1` in the compose file is related. The image keeps its
config and each service's document root in `/opt/dionaea/template` and copies
them out on first start — but only into directories that do not exist yet, and
every bind mount has already created one. The flag forces the copy. It is
`cp -n` underneath, so nothing dionaea has written is ever overwritten and a
restart keeps the captures.

## Log rotation

Dionaea does not rotate its JSON log, and its file handler holds the same
descriptor open for the life of the process. That has one consequence worth
knowing: a `logrotate` rule that **renames** the file will leave dionaea
writing to the renamed file forever, and no new one will appear. Use
`copytruncate`:

```
/path/to/nodes/dionaea/dionaea-logs/dionaea_incident.json {
    daily
    rotate 7
    compress
    copytruncate
}
```

The tailer handles that case, and the rename case, and a log that does not
exist yet — see `../shipper/tail.py`. On truncation it starts again from the
top of the file, so nothing written between the copy and the truncate is lost.

## Backfilling

The adapter starts at the **end** of the current log, so events from before it
was wired up, or from while it was stopped, never reach the aggregator.
`backfill.py` sends them:

```bash
uv run backfill.py                       # everything on disk
uv run backfill.py --dry-run             # say what would be sent
uv run backfill.py --since 2026-08-07    # only from then on
```

Running it twice is safe: ids are derived from the events themselves, so the
second run answers `duplicates`.

```
18 event(s) sent — collector accepted 18, 0 already had, 0 refused
18 event(s) sent — collector accepted 0, 18 already had, 0 refused
```

That only holds *between backfill runs*. Events the live adapter already
shipped carry its random ids, so backfilling over a window the adapter covered
does duplicate them — `--since` is there to cut the overlap out.

## Running locally

**1. Start dionaea:**

```bash
docker compose up -d
docker compose logs --tail 5      # should end at "Starting dionaea ..."
```

Confirm the JSON log is actually being written — this is the step that catches
a broken handler config:

```bash
ls -l dionaea-logs/dionaea_incident.json
grep -i "unable to open" dionaea-logs/dionaea.log     # should print nothing
```

**2. Start the stub collector** in its own terminal:

```bash
uv run --extra stub stub_server.py
```

**3. Start the adapter** in another. The stub is on 5000 while `.env` points at
the real collector on 8000, so override that one value — inline variables
outrank the file:

```bash
COLLECTOR_URL=http://localhost:5000/api/events NODE_KEY=dev-test-key uv run adapter.py
```

**4. Give it something to catch.** An FTP login attempt is the easiest:

```bash
python3 - <<'EOF'
import socket, time
s = socket.create_connection(("127.0.0.1", 21), timeout=5); s.recv(4096)
for c in [b"USER root\r\n", b"PASS 123456\r\n", b"SYST\r\n", b"QUIT\r\n"]:
    s.sendall(c); time.sleep(0.3)
    try: s.recv(4096)
    except Exception: pass
EOF
```

**5. Confirm the loop closed.** The adapter prints
`Sent N event(s) — collector responded: 200 …`, the stub prints the events, and
the commands come through with the password already redacted.

To test something this sensor cannot represent, `curl http://127.0.0.1:80/`
after publishing port 80 — nothing is shipped, and the next summary line names
`httpd` and how many it dropped.

## Integration with the real collector

1. Get the real collector URL and this node's `NODE_KEY` from Part 2.
2. Set `COLLECTOR_URL`, `NODE_KEY` and `NODE_ID` in `.env`, not in `adapter.py`.
3. Run the adapter the same way — no code changes, only configuration.
4. Confirm with Part 2 that the events are landing in `sessions` with
   `protocol` of `ftp`/`smb`, not just that the HTTP response is `200`.
