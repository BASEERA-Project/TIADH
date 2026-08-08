# Dashboard — Part 5

A Flask read model over the Baseline v1.3 database. Seven screens, dark by
default, built for someone triaging a honeypot fleet rather than for someone
admiring a chart.

```bash
cd dashboard
uv run tools/seed_demo.py          # optional: generate a day of demo traffic
uv run main.py --db demo/honeypot_demo.db
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
| **Map** | Where the traffic comes from and which sensor it lands on. Geolocated attacker IPs as marks sized by volume and coloured by risk band, sensors as crosshairs, an arc per origin-to-node pair. Hovering a mark lights its paths and dims everything else. See [The map](#the-map). |
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
| `DASHBOARD_NODE_COORDS` | unset | where each sensor sits, e.g. `node-01:24.7136,46.6753; node-02:52.3676,4.9041` |
| `DASHBOARD_MAP_MAX_ORIGINS` / `_MAX_ARCS` | `150` / `200` | marks and paths drawn before the map starts reporting a remainder |
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

## The map

The two ends of an arc are not the same kind of fact, and the screen is built so
you can tell which is which.

**The origin end is measured.** It is `reputation.latitude` / `.longitude`,
written by the enricher from the IP itself. An IP the enricher could not place is
never dropped onto the middle of its country — it is counted under the map as
unplaced, and the panel says how many. A map that quietly fills its gaps is the
one screen in a SOC that everybody believes and nobody can check.

**The sensor end is declared.** Baseline v1.3 froze the `nodes` table without
coordinates and this dashboard does not get to add a column to a frozen
contract, so a sensor is placed by configuration:

```bash
DASHBOARD_NODE_COORDS="node-01:24.7136,46.6753; node-02:52.3676,4.9041"
```

Semicolons or newlines between entries, `lat,lon` after the node id. A node left
out is named under the map rather than guessed at; a `nodes.location` that
already holds a `lat,lon` pair is used when nothing is configured for that node.
With no sensor placed, the origins still draw — there is simply nothing to draw
an arc to.

Everything else on the panel is derived, not decorative: circle **area** is
event volume, colour is the risk band the `high_risk_ip` rule uses, a dashed
ring means that IP actually authenticated, and line weight is the volume on that
one origin-to-sensor path. Hovering any mark lights the arcs that touch it and
the marks at their far ends, which is the fastest way to answer "who reached
that sensor?".

The coastline is **vendored, not fetched**: `app/templates/_world_land.svg` is
Natural Earth 1:110m land (public domain), projected and simplified by
`tools/build_world_svg.py`. It is inlined into the page's own `<svg>` so the
marks share its coordinate space, and because the Content-Security-Policy here
would refuse a remote tile server anyway — a security tool that phones out to a
CDN to draw a map is telling on itself. Both the file and the marks are
projected by `app/geo.py`, so the land and the data cannot drift apart:

```bash
uv run tools/build_world_svg.py            # after changing the projection
```

## Demo data

`tools/seed_demo.py` writes its own database file and refuses to overwrite one
without `--force`, so it cannot disturb collected data.

```bash
uv run tools/seed_demo.py --hours 24 --attackers 42
uv run tools/seed_demo.py --force            # regenerate
```

The seeder is in the image too, so a container-only setup can populate an empty
`tiadh_db` without a host checkout:

```bash
docker compose run --rm --no-deps dashboard \
  python tools/seed_demo.py --db /app/data/honeypot_aggregator.db
```

Only into an *empty* volume, though. Once `core/` has run, that path holds
collected data and the seeder correctly refuses it — `--force` there would
overwrite the real database, which is the one case where its refusal is the
whole point.

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
uv run --extra serve waitress-serve --call --host 127.0.0.1 --port 8050 app:create_app
```

Threaded workers are safe — each request gets its own read-only handle and
releases it on teardown.

### In Docker

`Dockerfile` runs exactly that waitress command, and `docker-compose.yml` mounts
the aggregator's database volume:

```bash
docker volume create tiadh_db      # once, shared with core/ — skip if it exists
docker compose up -d --build
```

Then open <http://127.0.0.1:8050>. The build context is the repository root, not
this directory, because the image needs the sibling `common` package.

Mounting `tiadh_db` **is** the integration: it is the only thing connecting this
container to `core/`, which reaches it through the same volume at the same path.
There is no network between them. A container without that mount starts fine and
shows the setup screen, because it is reading a database nobody writes.

Three things differ from a host run, all of them in the container layer rather
than in the app:

* **`DASHBOARD_HOST` defaults to `0.0.0.0`.** Not a relaxed posture — inside the
  container's own network namespace a loopback bind would make the published
  port unreachable. The loopback default moves outward to compose, which
  publishes to `127.0.0.1:8050`, so putting this on the lab network is still
  something you type. Set `DASHBOARD_SECRET_KEY` when you do.
* **`init: true`.** waitress installs no SIGTERM handler, and the kernel does not
  deliver a default-disposition signal to PID 1, so without an init `docker
  compose down` waits out the full grace period and then SIGKILLs.
* **The volume is mounted read-write.** Acknowledging and closing an alert is a
  real write. For a strictly read-only viewer, mount it `:ro` and set
  `DASHBOARD_ALLOW_ALERT_ACTIONS=0` so the buttons disappear rather than fail
  when pressed.

The healthcheck is `/api/health`, which reports whether the shared database is
actually readable — so an aggregator that has not created the schema yet shows
up as `unhealthy` rather than as an empty page you have to interpret.

Configuration comes from compose's `environment:` block. The repository-root
`.env` and `.env.secrets` are excluded from the build context on purpose, so
nothing is baked into the image.

## Layout

```
main.py             CLI entry point
app/
  __init__.py       application factory, CSRF, security headers, nav
  settings.py       environment-driven configuration
  db.py             request-scoped read-only handle (+ the one write path)
  queries.py        adapters — windows, pagination, gap filling, health verdict
  formatting.py     Jinja filters — timestamps, ages, severities, scores
  geo.py            the map's projection, arcs and sensor placement
  rule_catalog.py   prose for the rules panel; values come from common.config
  views/            one blueprint per screen, plus a small JSON API
  templates/        base, macros, one template per screen
                    _world_land.svg — generated coastline, see tools/
  static/           soc.css and soc.js — no build step, no external requests
tools/
  seed_demo.py      demo dataset generator
  build_world_svg.py  rebuilds the coastline from Natural Earth
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
