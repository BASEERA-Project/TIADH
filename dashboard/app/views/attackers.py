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
    result = queries.attackers_page(db, filters, page, per_page)

    return render_template(
        "attackers.html",
        title="Attackers",
        page=result,
        filters=filters,
        filter_count=active_filters(filters),
        countries=queries.known_countries(db),
        nodes=queries.distinct_nodes(db),
        sorts=queries.ATTACKER_SORTS,
        windows=queries.WINDOW_CHOICES,
    )


@bp.route("/<ip>")
def profile(ip: str):
    db = get_db()
    summary = queries.attacker_row(db, ip)
    if summary is None:
        # An IP can exist in reputation without ever having produced an event.
        reputation = db.get_reputation(ip)
        if reputation is None:
            abort(404, f"no activity recorded for {ip}")
        summary = {"attacker_ip": ip, **reputation}

    commands = queries.attacker_commands(db, ip, limit=20)
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
        sessions=queries.attacker_sessions(db, ip, limit=25),
        alerts=queries.attacker_alerts(db, ip, limit=50),
        commands=commands,
        usernames=queries.attacker_usernames(db, ip, limit=12),
        nodes=queries.attacker_nodes(db, ip),
        daily=queries.attacker_daily(db, ip, days=14),
        timeline=queries.attacker_timeline(db, ip, limit=120),
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
    summary = queries.attacker_row(db, ip) or {"attacker_ip": ip}
    reputation = db.get_reputation(ip) or {}
    dossier = {
        "generated_at": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": current_app.config["APP_NAME"],
        "attacker_ip": ip,
        "summary": summary,
        "reputation": reputation,
        "nodes": queries.attacker_nodes(db, ip),
        "usernames": queries.attacker_usernames(db, ip, limit=100),
        "commands": queries.attacker_commands(db, ip, limit=200),
        "sessions": queries.attacker_sessions(db, ip, limit=200),
        "alerts": queries.attacker_alerts(db, ip, limit=500),
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
    row = {**{k: v for k, v in summary.items()}, **{
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
