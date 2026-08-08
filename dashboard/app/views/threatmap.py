"""
Map — where the traffic comes from, and which sensor it lands on.

Two halves, and they are not the same kind of fact. The origin end is
*measured*: the enricher geolocated the attacker IP and wrote coordinates to
`reputation`, and an IP it could not place is reported as unplaced rather than
dropped on the middle of its country. The sensor end is *declared*: Baseline
v1.3 froze the `nodes` table without coordinates, so a sensor sits where
``DASHBOARD_NODE_COORDS`` says it sits, and a node nobody has placed is listed
under the map instead of being invented.

Keeping that distinction visible is the point. A threat map that quietly fills
its gaps is the one screen in a SOC that everybody believes and nobody can
check.
"""

from __future__ import annotations

from flask import Blueprint, current_app, render_template, request

from app import geo, queries
from app.db import get_db

bp = Blueprint("threatmap", __name__, url_prefix="/map")

DEFAULT_WINDOW = "24h"


@bp.route("/")
def index():
    db = get_db()

    window = request.args.get("window") or DEFAULT_WINDOW
    if window not in dict(queries.WINDOW_CHOICES):
        window = DEFAULT_WINDOW
    since = queries.since_from_window(window)

    max_origins = current_app.config["MAP_MAX_ORIGINS"]
    # One row past the cap: enough to know the map is not showing everything,
    # without paying for a second COUNT over the join.
    origins = db.get_attack_origins(since=since, limit=max_origins + 1)
    # The window narrows the marks, not the fleet: a sensor that saw nothing in
    # the last hour is still on the map, and its health is measured from its
    # last contact regardless of which window is selected.
    nodes = queries.node_health(
        db,
        current_app.config["HEARTBEAT_INTERVAL_SECONDS"],
        current_app.config["HEARTBEAT_WARN_MISSED"],
        current_app.config["HEARTBEAT_CRIT_MISSED"],
        since=since,
    )

    threat_map = geo.build(
        origins,
        paths=db.get_attack_paths(since=since, limit=current_app.config["MAP_MAX_ARCS"]),
        nodes=nodes,
        coordinates=current_app.config["NODE_COORDINATES"],
        max_origins=max_origins,
        max_arcs=current_app.config["MAP_MAX_ARCS"],
    )

    stats = db.get_dashboard_overview(
        window_hours=current_app.config["ACTIVITY_WINDOW_HOURS"]
    )
    return render_template(
        "threatmap.html",
        title="Map",
        heading="Threat map",
        map=threat_map,
        window=window,
        window_label=dict(queries.WINDOW_CHOICES)[window].lower(),
        windows=queries.WINDOW_CHOICES,
        countries=db.get_top_countries(limit=10),
        # Attackers seen at all, against attackers the enricher gave coordinates
        # to — the honest denominator for everything drawn above.
        total_attackers=stats.get("unique_attackers") or 0,
        placed_ips=stats.get("placed_ips") or 0,
    )
