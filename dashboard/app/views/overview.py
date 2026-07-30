"""
Overview — the screen that answers "what is happening right now?".

Every number on this page is a link. A tile that says 347 unique IPs is a
question, and the answer is the Attackers table filtered to exactly the rows
that produced the 347 — never a dead end.
"""

from __future__ import annotations

from flask import Blueprint, current_app, render_template

from common.db.validation import utc_ago

from app import queries
from app.db import get_db

bp = Blueprint("overview", __name__)


@bp.route("/")
def index():
    db = get_db()
    hours = current_app.config["ACTIVITY_WINDOW_HOURS"]
    since = utc_ago(hours=hours)

    activity = queries.activity_series(db, hours=hours)

    return render_template(
        "overview.html",
        title="Overview",
        stats=db.get_dashboard_overview(window_hours=hours),
        activity=activity,
        activity_hours=hours,
        activity_peak=max((row["total"] for row in activity), default=0),
        severity=db.get_alert_severity_counts(status="open"),
        event_types=db.get_event_type_counts(since=since),
        top_attackers=db.get_top_attackers(limit=8),
        top_credentials=db.get_top_credentials(limit=8),
        top_commands=db.get_top_commands(limit=8, since=since),
        top_countries=db.get_top_countries(limit=6),
        recent_alerts=db.get_alerts(status="open", limit=8),
        heartbeat_interval=current_app.config["HEARTBEAT_INTERVAL_SECONDS"],
        nodes=queries.node_health(
            db,
            current_app.config["HEARTBEAT_INTERVAL_SECONDS"],
            current_app.config["HEARTBEAT_WARN_MISSED"],
            current_app.config["HEARTBEAT_CRIT_MISSED"],
            since=since,
        ),
    )
