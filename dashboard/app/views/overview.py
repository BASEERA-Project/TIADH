"""
Overview — the screen that answers "what is happening right now?".

Every number on this page is a link. A tile that says 347 unique IPs is a
question, and the answer is the Attackers table filtered to exactly the rows
that produced the 347 — never a dead end.
"""

from __future__ import annotations

from flask import Blueprint, current_app, render_template

from common.db.validation import utc_ago

from app import geo, queries
from app.db import get_db

bp = Blueprint("overview", __name__)


@bp.route("/")
def index():
    db = get_db()
    hours = current_app.config["ACTIVITY_WINDOW_HOURS"]
    since = utc_ago(hours=hours)

    activity = queries.activity_series(db, hours=hours)
    nodes = queries.node_health(
        db,
        current_app.config["HEARTBEAT_INTERVAL_SECONDS"],
        current_app.config["HEARTBEAT_WARN_MISSED"],
        current_app.config["HEARTBEAT_CRIT_MISSED"],
        since=since,
    )

    # The same map the Map screen draws, over this screen's window. It is built
    # here rather than fetched by script because a page that renders its numbers
    # server-side and its geography client-side has two different ideas of
    # "now" on it at once.
    max_origins = current_app.config["MAP_MAX_ORIGINS"]
    threat_map = geo.build(
        db.get_attack_origins(since=since, limit=max_origins + 1),
        paths=db.get_attack_paths(since=since, limit=current_app.config["MAP_MAX_ARCS"]),
        nodes=nodes,
        coordinates=current_app.config["NODE_COORDINATES"],
        max_origins=max_origins,
        max_arcs=current_app.config["MAP_MAX_ARCS"],
    )

    # This screen has no window control, so an empty map here is a dead end
    # unless it can say whether there is anything outside the last `hours` to
    # go and look at. The Map screen is where that window opens.
    extent = db.get_attack_origin_extent()

    return render_template(
        "overview.html",
        title="Overview",
        stats=db.get_dashboard_overview(window_hours=hours),
        map_extent=extent,
        activity=activity,
        activity_hours=hours,
        threat_map=threat_map,
        activity_peak=max((row["total"] for row in activity), default=0),
        severity=db.get_alert_severity_counts(status="open"),
        event_types=db.get_event_type_counts(since=since),
        top_attackers=db.get_top_attackers(limit=8),
        top_credentials=db.get_top_credentials(limit=8),
        top_commands=db.get_top_commands(limit=8, since=since),
        top_countries=db.get_top_countries(limit=6),
        recent_alerts=db.get_alerts(status="open", limit=8),
        heartbeat_interval=current_app.config["HEARTBEAT_INTERVAL_SECONDS"],
        nodes=nodes,
    )
