"""
API — small JSON endpoints behind the live header.

Just enough for the page to keep its counters current without a full reload.
Read-only, same-origin, and exempt from the CSRF check because every route here
is a GET that changes nothing.
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from app import queries
from app.db import DatabaseUnavailable, get_db, health
from app.formatting import now_utc

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/summary")
def summary():
    """Counters for the header strip and the Overview tiles."""
    db = get_db()
    stats = queries.overview_stats(db)
    nodes = queries.node_health(
        db,
        current_app.config["HEARTBEAT_INTERVAL_SECONDS"],
        current_app.config["HEARTBEAT_WARN_MISSED"],
        current_app.config["HEARTBEAT_CRIT_MISSED"],
    )
    return jsonify(
        {
            "generated_at": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "stats": stats,
            "severity": queries.severity_breakdown(db, status="open"),
            "nodes": {
                "total": len(nodes),
                "healthy": sum(1 for n in nodes if n["health"] == "healthy"),
                "warning": sum(1 for n in nodes if n["health"] == "warning"),
                "critical": sum(1 for n in nodes if n["health"] == "critical"),
            },
        }
    )


@bp.route("/activity")
def activity():
    hours = current_app.config["ACTIVITY_WINDOW_HOURS"]
    return jsonify({"hours": hours, "series": queries.activity_series(get_db(), hours)})


@bp.route("/health")
def health_check():
    """Liveness probe that reports the database it is actually reading."""
    try:
        get_db()
    except DatabaseUnavailable as exc:
        return jsonify({"ok": False, "error": str(exc), "database": health()}), 503
    return jsonify({"ok": True, "database": health()})
