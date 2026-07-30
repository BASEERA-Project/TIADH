"""
Nodes — sensor health.

Health is stated in *missed heartbeats*, not seconds, because that maps onto the
Baseline v1.3 heartbeat interval an assessor can check: amber past
``DASHBOARD_HEARTBEAT_WARN_MISSED`` missed beats, red past
``DASHBOARD_HEARTBEAT_CRIT_MISSED``.

Spool depth — the ``pending_events.jsonl`` backlog — lives on each node and is
not part of the v1.3 event contract, so the central database cannot report it.
Ingest lag is shown instead: it is what a draining spool looks like from here,
and it is measured rather than guessed (``received_at - timestamp``).
"""

from __future__ import annotations

from flask import Blueprint, current_app, render_template

from common import config
from common.db.validation import utc_ago

from app import queries
from app.db import get_db

bp = Blueprint("nodes", __name__, url_prefix="/nodes")


@bp.route("/")
def index():
    db = get_db()
    since = utc_ago(hours=24)

    nodes = queries.node_health(
        db,
        current_app.config["HEARTBEAT_INTERVAL_SECONDS"],
        current_app.config["HEARTBEAT_WARN_MISSED"],
        current_app.config["HEARTBEAT_CRIT_MISSED"],
        since=since,
    )
    for node in nodes:
        node["activity"] = db.get_node_activity(node["node_id"], since)

    return render_template(
        "nodes.html",
        title="Nodes",
        nodes=nodes,
        peak=max((row["n"] for node in nodes for row in node["activity"]), default=0),
        heartbeat_interval=current_app.config["HEARTBEAT_INTERVAL_SECONDS"],
        warn_missed=current_app.config["HEARTBEAT_WARN_MISSED"],
        crit_missed=current_app.config["HEARTBEAT_CRIT_MISSED"],
        offline_after=config.NODE_OFFLINE_AFTER_SECONDS,
    )
