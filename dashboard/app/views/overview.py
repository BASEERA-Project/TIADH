"""
Overview — the screen that answers "what is happening right now?".

Every number on this page is a link. A tile that says 347 unique IPs is a
question, and the answer is the Attackers table filtered to exactly the rows
that produced the 347 — never a dead end.
"""

from __future__ import annotations

from flask import Blueprint, current_app, render_template

from app import queries
from app.db import get_db

bp = Blueprint("overview", __name__)


@bp.route("/")
def index():
    db = get_db()
    hours = current_app.config["ACTIVITY_WINDOW_HOURS"]

    stats = queries.overview_stats(db)
    activity = queries.activity_series(db, hours=hours)
    severity = queries.severity_breakdown(db, status="open")

    return render_template(
        "overview.html",
        title="Overview",
        stats=stats,
        activity=activity,
        activity_hours=hours,
        activity_peak=max((row["total"] for row in activity), default=0),
        severity=severity,
        event_types=queries.event_type_breakdown(db, window="24h"),
        top_attackers=db.get_top_attackers(limit=8),
        top_credentials=db.get_top_credentials(limit=8),
        top_commands=queries.top_commands(db, limit=8, window="24h"),
        top_countries=queries.top_countries(db, limit=6),
        recent_alerts=db.get_alerts(status="open", limit=8),
        heartbeat_interval=current_app.config["HEARTBEAT_INTERVAL_SECONDS"],
        nodes=queries.node_health(
            db,
            current_app.config["HEARTBEAT_INTERVAL_SECONDS"],
            current_app.config["HEARTBEAT_WARN_MISSED"],
            current_app.config["HEARTBEAT_CRIT_MISSED"],
        ),
    )
