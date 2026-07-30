# Dashboard — Part 5

A Flask read model over the Baseline v1.3 database. Six screens, dark by default,
built for someone triaging a honeypot fleet rather than for someone admiring a
chart.

```bash
cd dashboard
uv sync
python tools/seed_demo.py          # optional: generate a day of demo traffic
python main.py --db demo/honeypot_demo.db
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
| **Feeds** | A UI over `core/export/exporter.py`. Pick a window and filters, preview the records, download JSON, CSV or STIX from a stable URL. |

## How it talks to the database

**The dashboard writes no SQL and does not import `sqlite3`.** Every read is a
method on `common.db.database.Database`, opened `read_only=True` and scoped to
one request (`app/db.py`). Table names, column names, `json_extract` and
SQLite's date functions all stop at that file — rename a column there and
nothing here has to change, because there is no second copy of the schema in a
view function or a template.

The screens are served by the storage layer's dashboard API:

| Need | Call |
|---|---|
| Overview tiles | `get_dashboard_overview(window_hours=…)` |
| Charts | `get_event_activity`, `get_event_type_counts`, `get_top_commands`, `get_top_countries` |
| Attackers table | `search_attackers(filters, sort, limit, offset)` |
| Attacker profile | `get_attacker`, `get_attacker_sessions`, `get_attacker_commands`, `get_attacker_usernames`, `get_attacker_nodes`, `get_attacker_events`, `get_attacker_activity`, `get_alerts_for_ip` |
| Sessions | `search_sessions`, `get_session`, `get_session_events`, `get_alerts_for_session` |
| Alerts | `search_alerts`, `get_alert_status_counts`, `get_alert_severity_counts`, `get_alert_type_stats` |
| Nodes | `get_node_statistics`, `get_node_activity` |
| Filter dropdowns | `get_countries`, `get_protocols`, `get_alert_types`, `get_node_ids` |
| Readiness | `exists`, `describe` |

Sort keys are whitelisted inside `Database` (`ATTACKER_SORT_KEYS`,
`SESSION_SORT_KEYS`, `ALERT_SORT_KEYS`). The dashboard passes a key like
`"score"`; it cannot supply an `ORDER BY`, and an unknown key falls back to the
default so a stale bookmark still renders.

`app/queries.py` is what is left over once the SQL is gone — window tokens to
timestamps, page numbers to limit/offset, gap-filling for charts, and the
amber/red heartbeat verdict. Those are the dashboard's business, not the
storage layer's.

The one write is acknowledging or closing an alert. It uses a separate writable
handle and calls `Database.set_alert_status()`; set
`DASHBOARD_ALLOW_ALERT_ACTIONS=0` and the buttons disappear.

### Credentials

Attempted passwords never reach this process:

* session listings read the `sessions_public` view, not `sessions`;
* `get_session_events()` selects `json_extract(details,'$.password') IS NOT NULL`
  — a boolean — so `***MASKED***` is rendered from the fact that a password was
  submitted, not from a value the template is trusted to hide. That guarantee now
  lives in the storage layer, where no caller can opt out of it;
* the per-IP export runs through the exporter's `scrub()` and
  `assert_no_secrets()`, which raise rather than redact.

Aggregate username statistics are shown; aggregate password statistics are not.

## Configuration

Every setting is an environment variable (`app/settings.py`):

| Variable | Default | |
|---|---|---|
| `HONEYPOT_DB_PATH` | `common/src/common/honeypot_aggregator.db` | database to read |
| `DASHBOARD_HOST` / `DASHBOARD_PORT` | `127.0.0.1` / `8050` | bind address |
| `DASHBOARD_SECRET_KEY` | development fallback | set before exposing the app |
| `DASHBOARD_REFRESH_SECONDS` | `30` | default auto-refresh; the header control overrides per browser |
| `DASHBOARD_PAGE_SIZE` | `50` | table page size |
| `DASHBOARD_ALLOW_ALERT_ACTIONS` | `1` | `0` for strictly read-only |
| `HEARTBEAT_INTERVAL_SECONDS` | `60` | contract heartbeat interval |
| `DASHBOARD_HEARTBEAT_WARN_MISSED` / `_CRIT_MISSED` | `2` / `5` | amber and red thresholds |

Detection thresholds are **not** listed here on purpose. They belong to
`common/config.py`, and the rules panel reads them live so it always shows what
the engine is using. Anything schema-shaped belongs to `common/db/`.

It binds to loopback by default. `--host 0.0.0.0` exposes attacker data and the
outbound feed to the network; set `DASHBOARD_SECRET_KEY` if you do.

## Demo data

`tools/seed_demo.py` writes its own database file and refuses to overwrite one
without `--force`, so it cannot disturb collected data.

```bash
python tools/seed_demo.py --hours 24 --attackers 42
python tools/seed_demo.py --force            # regenerate
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
waitress-serve --host 127.0.0.1 --port 8050 wsgi:app
```

Threaded workers are safe — each request gets its own read-only handle and
releases it on teardown.

## Layout

```
main.py             CLI entry point
wsgi.py             entry point for waitress/gunicorn
app/
  __init__.py       application factory, CSRF, security headers, nav
  settings.py       environment-driven configuration
  db.py             request-scoped read-only handle (+ the one write path)
  queries.py        adapters — windows, pagination, gap filling, health verdict
  formatting.py     Jinja filters — timestamps, ages, severities, scores
  integrations.py   borrows FeedExporter and the command classifier from core/
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
