"""
Sessions — the list, and the transcript.

The transcript is the screen worth remembering: one honeypot session replayed as
a terminal, timestamped down the left, with the commands the attacker typed shown
as they were typed. Passwords render as ``***MASKED***`` because the query that
built the page asked *whether* a password was submitted and never asked what it
was — see ``queries.session_transcript``.
"""

from __future__ import annotations

from flask import Blueprint, abort, render_template

from app import queries
from app.db import get_db
from app.integrations import classify_command
from app.views import active_filters, collect, paging

bp = Blueprint("sessions", __name__, url_prefix="/sessions")

FILTER_NAMES = ("q", "status", "node", "protocol", "ip", "sort", "window")
FILTER_FLAGS = ("breached_only", "commands_only")

#: event_type -> transcript line kind. The kind drives styling, the gutter marker
#: and whether the line is treated as part of the attacker's hands-on activity.
LINE_KINDS = {
    "connection": "connect",
    "login_attempt": "auth-fail",
    "login_success": "auth-ok",
    "command": "command",
    "file_download": "download",
    "session_end": "end",
    "heartbeat": "meta",
}


@bp.route("/")
def index():
    db = get_db()
    page, per_page = paging()
    filters = collect(*FILTER_NAMES, flags=FILTER_FLAGS)
    result = queries.sessions_page(db, filters, page, per_page)

    return render_template(
        "sessions.html",
        title="Sessions",
        page=result,
        filters=filters,
        filter_count=active_filters(filters),
        nodes=queries.distinct_nodes(db),
        protocols=queries.distinct_protocols(db),
        sorts=queries.SESSION_SORTS,
        windows=queries.WINDOW_CHOICES,
    )


@bp.route("/<path:session_id>")
def detail(session_id: str):
    db = get_db()
    header = queries.session_header(db, session_id)
    if header is None:
        abort(404, f"no session {session_id}")

    events = queries.session_transcript(db, session_id)
    lines = _with_gaps([_line(event) for event in events])

    return render_template(
        "session.html",
        title=session_id,
        session=header,
        lines=lines,
        counts=_counts(events),
        alerts=queries.session_alerts(db, session_id),
        neighbours=queries.adjacent_sessions(db, session_id, header.get("attacker_ip")),
        reputation=db.get_reputation(header.get("attacker_ip")),
        risky_count=sum(1 for line in lines if line.get("risk")),
    )


def _line(event: dict) -> dict:
    """
    Turn one stored event into a transcript line.

    A command is marked risky by ``classify_command`` — the alert engine's own
    classifier — so the highlighting on this page means "a rule would fire on
    this", not "this looked scary to the dashboard".
    """
    line = dict(event)
    line["kind"] = LINE_KINDS.get(event["event_type"], "meta")

    if event["event_type"] == "login_success":
        line["kind"] = "auth-ok"
    if event["event_type"] == "session_end" and event.get("status") in ("failed", "error"):
        line["kind"] = "end-failed"

    if event["event_type"] == "command":
        verdict = classify_command(event.get("command") or "")
        if verdict:
            line["risk"] = {"severity": verdict[0], "label": verdict[1]}
    return line


#: A pause longer than this gets its own divider in the transcript. Below it the
#: gap is machine-speed and saying so adds nothing; above it, the pause is the
#: attacker thinking, and that is worth seeing.
GAP_THRESHOLD_SECONDS = 60


def _with_gaps(lines: list) -> list:
    """Annotate each line with the idle time since the previous one."""
    from app.formatting import to_datetime

    previous = None
    for line in lines:
        moment = to_datetime(line.get("timestamp"))
        if previous is not None and moment is not None:
            gap = (moment - previous).total_seconds()
            line["gap_seconds"] = gap if gap >= GAP_THRESHOLD_SECONDS else None
        if moment is not None:
            previous = moment
    return lines


def _counts(events: list) -> dict:
    """The one-line summary above the transcript."""
    counts = {"failed_logins": 0, "successes": 0, "commands": 0, "downloads": 0}
    for event in events:
        kind = event["event_type"]
        if kind == "login_attempt":
            counts["failed_logins"] += 1
        elif kind == "login_success":
            counts["successes"] += 1
        elif kind == "command":
            counts["commands"] += 1
        elif kind == "file_download":
            counts["downloads"] += 1
    return counts
