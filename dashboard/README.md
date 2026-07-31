# Dashboard — Part 5

A Flask read model over the Baseline v1.3 database. Six screens, dark by default,
built for someone triaging a honeypot fleet rather than for someone admiring a
chart.

```bash
cd dashboard
uv sync
uv run python tools/seed_demo.py          # optional: generate a day of demo traffic
uv run python main.py --db demo/honeypot_demo.db
```

Then open <http://127.0.0.1:8050>. Without `--db` it reads the shared database at
`common/src/common/honeypot_aggregator.db`, the same file the collector writes —
override it anywhere with `HONEYPOT_DB_PATH`.

## The screens

| Screen | What it answers |
|---|---|
| **Overview** | What is happening right now. Every tile is a filter link: `42 unique IPs` opens Attackers showing those 42. |
| **Attackers** | Reputation joined to event aggregates — score, geolocation, first/last seen, sessions, failed logins, commands, alerts. Searchable, sortable, paginated. Each row opens a profile with the IP's whole history and an export button. |
| **Sessions** | The list, and the transcript. A session renders as a terminal: connect → 20 failed logins → accepted → command sequence → session end, timestamped down the left, passwords as `***MASKED***`, risky commands flagged by the alert engine's own classifier. |
| **Alerts** | One row per `alerts` row, with acknowledge/close actions, next to a panel showing all seven detection rules and their live thresholds. |
| **Nodes** | Sensor health in missed heartbeats — amber past 2, red past 5 — plus events shipped and measured ingest lag. |
| **Feeds** | A UI over `common/export/exporter.py`. Pick a window and filters, preview the records, download JSON, CSV or STIX from a stable URL. |

## Configuration

Every setting is an environment variable (`app/settings.py`), and the dashboard
has no config file of its own. It reads the repository-root `.env` and
`.env.secrets`, which `common/config.py` loads on import — the same two files
the aggregator reads, which is what keeps them pointed at one database without
any second setup step. An exported variable outranks the file.

| Variable | Default | |
|---|---|---|
| `HONEYPOT_DB_PATH` | inside the installed `common` package | database to read |
| `DASHBOARD_HOST` / `DASHBOARD_PORT` | `127.0.0.1` / `8050` | bind address |
| `DASHBOARD_SECRET_KEY` | development fallback | **`.env.secrets`** — set before exposing the app |
| `DASHBOARD_REFRESH_SECONDS` | `30` | default auto-refresh; the header control overrides per browser |
| `DASHBOARD_PAGE_SIZE` | `50` | table page size |
| `DASHBOARD_ACTIVITY_HOURS` | `24` | hours covered by the Overview chart |
| `DASHBOARD_APP_NAME` / `_SUBTITLE` | `TIADH` / … | header text |
| `DASHBOARD_ALLOW_ALERT_ACTIONS` | `1` | `0` for strictly read-only |
| `DASHBOARD_HEARTBEAT_WARN_MISSED` / `_CRIT_MISSED` | `2` / `5` | amber and red thresholds |

`HEARTBEAT_INTERVAL_SECONDS` is **not** in that list any more. It is a Baseline
v1.3 contract value, not a dashboard preference, so it lives in
`common/config.py` — where the sweeper's offline timeout is derived from it —
and the dashboard reads it from there. Detection thresholds are absent for the
same reason: the rules panel reads them live so it always shows what the engine
is using. Anything schema-shaped belongs to `common/db/`, the feed format to
`common/export/`, and the rules to `common/alerting/` — the dashboard imports
those, never `core/`.

It binds to loopback by default. `--host 0.0.0.0` exposes attacker data and the
outbound feed to the network; set `DASHBOARD_SECRET_KEY` if you do.

## Demo data

`tools/seed_demo.py` writes its own database file and refuses to overwrite one
without `--force`, so it cannot disturb collected data.

```bash
uv run python tools/seed_demo.py --hours 24 --attackers 42
uv run python tools/seed_demo.py --force            # regenerate
```

It generates scanners, brute force, credential spraying, three attackers who get
in and run a payload, one sensor that goes quiet, and a few sessions still in
progress. Two things make it honest rather than decorative:

* every event goes in through `Database.apply_events()` and is validated against
  Baseline v1.3 — a generated event that production would reject is rejected here;
* alerts are **not** written directly. Events are inserted in chronological
  chunks the width of the evaluation window and the real `AlertEngine` runs after
  each chunk, so every alert on screen was produced by a rule firing, with the
  real deduplication and cooldown applied.

One thing to know: node health is measured against the wall clock, so healthy
sensors drift to amber and then red as real time passes after seeding. Re-run the
seeder before a demo.

## Deployment

Flask's server is fine for a demo. For anything left running:

```bash
uv sync --extra serve
uv run waitress-serve --call --host 127.0.0.1 --port 8050 app:create_app
```

Threaded workers are safe — each request gets its own read-only handle and
releases it on teardown.

## Layout

```
main.py             CLI entry point
app/
  __init__.py       application factory, CSRF, security headers, nav
  settings.py       environment-driven configuration
  db.py             request-scoped read-only handle (+ the one write path)
  queries.py        adapters — windows, pagination, gap filling, health verdict
  formatting.py     Jinja filters — timestamps, ages, severities, scores
  rule_catalog.py   prose for the rules panel; values come from common.config
  views/            one blueprint per screen, plus a small JSON API
  templates/        base, macros, one template per screen
  static/           soc.css and soc.js — no build step, no external requests
tools/seed_demo.py  demo dataset generator
```

## Design notes

Dark by default because a SOC tool is read in a dim room and photographed for a
report. Monospace for every IP, timestamp, hash, port and command; proportional
sans for labels only — that split is what makes the page read as an operational
tool. Table rows are 30px because SOC tools are dense.

Red is reserved for high severity and nothing else: amber is medium, neutral grey
is low, blue is data. Every status colour ships with a word beside it, so nothing
is carried by hue alone. The chart colours are the validated data-visualisation
palette (categorical slot 1 for data marks, the reserved status four for state)
on the surfaces they were validated against.

No CDN, no framework, no build step. The Content-Security-Policy forbids an
external request, which is the right posture for a tool that renders
attacker-supplied text.
