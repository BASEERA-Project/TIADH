"""
Attackers — searchable, sortable table over reputation joined to event
aggregates, and a per-IP profile with the whole history behind it.

The export button produces a dossier for one IP in the same shape as the
outbound feed, run through the exporter's own scrubber so a profile download
cannot leak what a feed download would not.
"""

from __future__ import annotations

import csv
import io
import json

from flask import Blueprint, Response, abort, current_app, render_template

from common.db.database import Database

from app import queries
from app.db import get_db
from app.formatting import now_utc
from app.integrations import classify_command, scrub_payload
from app.views import active_filters, collect, paging

bp = Blueprint("attackers", __name__, url_prefix="/attackers")

FILTER_NAMES = ("q", "country", "node", "min_score", "enriched", "sort", "window")
FILTER_FLAGS = ("alerts_only", "high_only", "breached_only")


@bp.route("/")
def index():
    db = get_db()
    page, per_page = paging()
    filters = collect(*FILTER_NAMES, flags=FILTER_FLAGS)

    return render_template(
        "attackers.html",
        title="Attackers",
        page=queries.attackers_page(db, filters, page, per_page),
        filters=filters,
        filter_count=active_filters(filters),
        countries=db.get_countries(),
        nodes=db.get_node_ids(),
        sorts=Database.ATTACKER_SORT_KEYS,
        windows=queries.WINDOW_CHOICES,
    )


@bp.route("/<ip>")
def profile(ip: str):
    db = get_db()
    summary = db.get_attacker(ip)
    if summary is None:
        # An IP can exist in reputation without ever having produced an event.
        reputation = db.get_reputation(ip)
        if reputation is None:
            abort(404, f"no activity recorded for {ip}")
        summary = {"attacker_ip": ip, **reputation}

    commands = db.get_attacker_commands(ip, limit=20)
    for row in commands:
        verdict = classify_command(row.get("command") or "")
        row["risk"] = {"severity": verdict[0], "label": verdict[1]} if verdict else None

    return render_template(
        "attacker.html",
        title=ip,
        ip=ip,
        summary=summary,
        profile_inputs=db.get_attacker_profile_inputs(ip),
        reputation=db.get_reputation(ip),
        sessions=db.get_attacker_sessions(ip, limit=25),
        alerts=db.get_alerts_for_ip(ip, limit=50),
        commands=commands,
        usernames=db.get_attacker_usernames(ip, limit=12),
        nodes=db.get_attacker_nodes(ip),
        daily=queries.daily_activity(db, ip, days=14),
        timeline=db.get_attacker_events(ip, limit=120),
    )


@bp.route("/<ip>/export.<fmt>")
def export(ip: str, fmt: str):
    """
    Download everything the platform knows about one IP.

    ``scrub_payload`` is the exporter's own masking pass. Reusing it means this
    button obeys the same "no credential leaves local storage" guarantee as the
    published feed, enforced by the same code rather than by a promise.
    """
    if fmt not in ("json", "csv"):
        abort(404)

    db = get_db()
    summary = db.get_attacker(ip) or {"attacker_ip": ip}
    reputation = db.get_reputation(ip) or {}
    dossier = {
        "generated_at": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": current_app.config["APP_NAME"],
        "attacker_ip": ip,
        "summary": summary,
        "reputation": reputation,
        "nodes": db.get_attacker_nodes(ip),
        "usernames": db.get_attacker_usernames(ip, limit=100),
        "commands": db.get_attacker_commands(ip, limit=200),
        "sessions": db.get_attacker_sessions(ip, limit=200),
        "alerts": db.get_alerts_for_ip(ip, limit=500),
        "notice": (
            "Attempted credentials are retained locally and are masked here. "
            "Honeypot observations should be corroborated before blocking."
        ),
    }
    dossier = scrub_payload(dossier)
    safe_ip = ip.replace(":", "_").replace("/", "_")

    if fmt == "json":
        return Response(
            json.dumps(dossier, indent=2, ensure_ascii=False, default=str),
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{safe_ip}-dossier.json"'
            },
        )

    buffer = io.StringIO()
    row = {**dict(summary), **{
        f"reputation_{k}": v for k, v in reputation.items() if k != "attacker_ip"
    }}
    writer = csv.DictWriter(
        buffer, fieldnames=list(row.keys()), quoting=csv.QUOTE_ALL, lineterminator="\n"
    )
    writer.writeheader()
    writer.writerow(row)
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{safe_ip}-summary.csv"'},
    )
