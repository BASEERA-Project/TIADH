"""
Alerts — one row per row in ``alerts``, next to the rules that produce them.

The rules panel is the point of this screen. Every threshold on it is read from
``common.config`` at render time, so "which rule fired, and on what number?" is
answered on the same page as the alert itself.
"""

from __future__ import annotations

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)

from common import config
from common.db.database import Database, StorageError

from app import queries, rule_catalog
from app.db import get_db, get_writable_db
from app.views import active_filters, collect, paging

bp = Blueprint("alerts", __name__, url_prefix="/alerts")

FILTER_NAMES = ("q", "status", "severity", "min_severity", "type", "ip",
                "session", "sort", "window")

VALID_STATUSES = ("open", "acknowledged", "closed")


@bp.route("/")
def index():
    db = get_db()
    page, per_page = paging()
    filters = collect(*FILTER_NAMES)

    return render_template(
        "alerts.html",
        title="Alerts",
        page=queries.alerts_page(db, filters, page, per_page),
        filters=filters,
        filter_count=active_filters(filters),
        statuses=VALID_STATUSES,
        severities=sorted(config.SEVERITY_ORDER, key=config.SEVERITY_ORDER.get, reverse=True),
        alert_types=db.get_alert_types(),
        sorts=Database.ALERT_SORT_KEYS,
        windows=queries.WINDOW_CHOICES,
        status_counts=db.get_alert_status_counts(),
        severity_counts=db.get_alert_severity_counts(status="open"),
        rules=rule_catalog.catalog(),
        rule_stats=db.get_alert_type_stats(),
        engine_settings=rule_catalog.global_settings(),
        patterns=rule_catalog.patterns_by_severity(),
    )


@bp.route("/<alert_id>/status", methods=["POST"])
def set_status(alert_id: str):
    """
    Acknowledge or close one alert — the dashboard's only write.

    It goes through ``Database.set_alert_status()`` rather than an UPDATE of its
    own, so the status CHECK constraint and the write lock are handled by the
    storage layer exactly as they are for every other writer.
    """
    status = (request.form.get("status") or "").strip()
    if status not in VALID_STATUSES:
        abort(400, f"invalid status '{status}'")

    try:
        changed = get_writable_db().set_alert_status(alert_id, status)
    except StorageError as exc:
        flash(str(exc), "error")
    else:
        flash(
            f"Alert {alert_id[:8]} marked {status}." if changed
            else f"Alert {alert_id[:8]} was not found.",
            "ok" if changed else "error",
        )

    return redirect(request.form.get("next") or url_for("alerts.index"))
