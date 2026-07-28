"""
app/formatting.py — Jinja filters and helpers.

Presentation only. Nothing here queries the database, and nothing here invents a
value: a missing timestamp renders as an em dash, never as "now" or "0".

Timestamps arrive as Baseline v1.3 strings (``2026-07-28T14:31:07Z``) and are
parsed with the project's own :func:`common.db.validation.parse_timestamp`, so
the dashboard agrees with the ingest path about what a timestamp is.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from common import config
from common.db.validation import parse_timestamp

DASH = "—"

#: severity -> css modifier. 'high' is the only one allowed to be red.
SEVERITY_CLASSES = {"high": "sev-high", "medium": "sev-medium", "low": "sev-low"}

STATUS_CLASSES = {
    "open": "state-open",
    "acknowledged": "state-ack",
    "closed": "state-closed",
    "active": "state-active",
    "failed": "state-failed",
    "online": "state-online",
    "offline": "state-offline",
}

EVENT_TYPE_LABELS = {
    "connection": "connection",
    "login_attempt": "login attempt",
    "login_success": "login success",
    "command": "command",
    "file_download": "file download",
    "session_end": "session end",
    "heartbeat": "heartbeat",
}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_datetime(value) -> Optional[datetime]:
    """Parse a v1.3 timestamp, tolerating anything unexpected."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return parse_timestamp(str(value))
    except (ValueError, TypeError, AttributeError):
        return None


def age_seconds(value) -> Optional[float]:
    """Seconds between ``value`` and now. None when unparseable."""
    moment = to_datetime(value)
    if moment is None:
        return None
    return (now_utc() - moment).total_seconds()


def iso_ago(**delta) -> str:
    """
    A v1.3 timestamp N units in the past, for use as a bound query parameter.

    Time windows are computed in Python rather than with SQLite's
    ``datetime('now', ...)`` because stored timestamps carry the ISO 'T' and 'Z'
    that SQLite's own formatter omits — comparing the two as strings silently
    matches the wrong rows.
    """
    from datetime import timedelta

    return (now_utc() - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- filters ---------------------------------------------------------------

def fmt_number(value) -> str:
    """Thousands-separated integer; blank input renders as a dash."""
    if value is None or value == "":
        return DASH
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def fmt_compact(value) -> str:
    """1,284 / 12.9K / 4.2M — for stat tiles where width is tight."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return DASH
    if abs(number) < 10_000:
        return f"{int(number):,}"
    if abs(number) < 1_000_000:
        return f"{number / 1_000:.1f}K".replace(".0K", "K")
    return f"{number / 1_000_000:.1f}M".replace(".0M", "M")


def fmt_relative(value) -> str:
    """'just now' / '4m ago' / '3h ago' / '6d ago'."""
    seconds = age_seconds(value)
    if seconds is None:
        return DASH
    if seconds < 0:
        return "in the future"
    if seconds < 45:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    return f"{int(seconds // 86400)}d ago"


def fmt_duration(seconds) -> str:
    """Compact duration: 47s / 12m 04s / 3h 21m."""
    try:
        total = int(float(seconds))
    except (TypeError, ValueError):
        return DASH
    if total < 0:
        return DASH
    if total < 60:
        return f"{total}s"
    if total < 3600:
        return f"{total // 60}m {total % 60:02d}s"
    return f"{total // 3600}h {(total % 3600) // 60:02d}m"


def fmt_date(value) -> str:
    moment = to_datetime(value)
    return moment.strftime("%Y-%m-%d") if moment else DASH


def fmt_time(value) -> str:
    moment = to_datetime(value)
    return moment.strftime("%H:%M:%S") if moment else DASH


def fmt_timestamp(value) -> str:
    moment = to_datetime(value)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ") if moment else DASH


def severity_class(value) -> str:
    return SEVERITY_CLASSES.get(str(value or "").lower(), "sev-low")


def severity_rank(value) -> int:
    return config.SEVERITY_ORDER.get(str(value or "").lower(), 0)


def state_class(value) -> str:
    return STATUS_CLASSES.get(str(value or "").lower(), "state-closed")


def event_label(value) -> str:
    return EVENT_TYPE_LABELS.get(value, str(value or DASH))


def score_band(value) -> str:
    """
    Risk band for a 0-100 score.

    The boundary that matters is ``HIGH_RISK_SCORE_THRESHOLD`` — the same
    number the ``high_risk_ip`` rule fires on — so a red score on screen always
    means "this crossed the configured threshold", never "this looks big".
    """
    try:
        score = int(value)
    except (TypeError, ValueError):
        return "none"
    if score >= config.HIGH_RISK_SCORE_THRESHOLD:
        return "high"
    if score >= config.HIGH_RISK_SCORE_THRESHOLD // 2:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def truncate_middle(value, length: int = 48) -> str:
    """Shorten long hashes/URLs from the middle, keeping both ends readable."""
    text = str(value or "")
    if len(text) <= length:
        return text
    keep = (length - 1) // 2
    return f"{text[:keep]}…{text[-keep:]}"


def percent(part, whole) -> float:
    try:
        return round((float(part) / float(whole)) * 100.0, 1) if whole else 0.0
    except (TypeError, ValueError, ZeroDivisionError):
        return 0.0


FILTERS = {
    "number": fmt_number,
    "compact": fmt_compact,
    "relative": fmt_relative,
    "duration": fmt_duration,
    "date_part": fmt_date,
    "time_part": fmt_time,
    "timestamp": fmt_timestamp,
    "severity_class": severity_class,
    "severity_rank": severity_rank,
    "state_class": state_class,
    "event_label": event_label,
    "score_band": score_band,
    "truncate_middle": truncate_middle,
}


def register(app) -> None:
    """Attach every filter and a couple of globals to a Flask app."""
    app.jinja_env.filters.update(FILTERS)
    app.jinja_env.globals.update(
        {
            "percent": percent,
            "age_seconds": age_seconds,
            "DASH": DASH,
        }
    )
