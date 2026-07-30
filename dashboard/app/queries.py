"""
app/queries.py — Adapters between the screens and the storage API.

**There is no SQL in the dashboard.** Every read is a method on
``common.db.database.Database``; this module only does the things that are the
dashboard's business rather than the storage layer's:

* turning a UI window token (``"24h"``) into a timestamp the API accepts,
* turning a page number into a limit/offset and the result into a
  :class:`Page`,
* filling the empty buckets a chart needs but a ``GROUP BY`` does not return,
* deciding how many missed heartbeats is amber and how many is red.

Anything that needs to know a table name, a column name or a SQLite function
lives in ``common/db/database.py``. That is what keeps the schema in one file:
if a column is renamed there, nothing here has to change, and nothing here can
quietly hold a stale copy of the schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Optional

from common.db.validation import utc_ago

from app.formatting import age_seconds, to_datetime

#: UI window tokens, in the order they appear in a filter dropdown.
WINDOW_CHOICES = [
    ("1h", "Last hour"),
    ("6h", "Last 6 hours"),
    ("24h", "Last 24 hours"),
    ("7d", "Last 7 days"),
    ("30d", "Last 30 days"),
    ("all", "All time"),
]

_WINDOW_DELTAS = {
    "1h": {"hours": 1},
    "6h": {"hours": 6},
    "24h": {"hours": 24},
    "7d": {"days": 7},
    "30d": {"days": 30},
}


def since_from_window(window: Optional[str]) -> Optional[str]:
    """``"24h"`` -> a canonical timestamp; ``"all"`` or unknown -> None."""
    if not window or window == "all":
        return None
    delta = _WINDOW_DELTAS.get(window)
    return utc_ago(**delta) if delta else None


@dataclass
class Page:
    """One page of rows plus everything a paginator needs to render itself."""

    rows: List[Dict[str, Any]] = field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 50

    @property
    def pages(self) -> int:
        return max(1, -(-self.total // self.per_page)) if self.per_page else 1

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.pages

    @property
    def start_index(self) -> int:
        return 0 if not self.total else (self.page - 1) * self.per_page + 1

    @property
    def end_index(self) -> int:
        return min(self.total, self.page * self.per_page)

    def window(self, span: int = 2) -> List[int]:
        """Page numbers to show either side of the current one."""
        low = max(1, self.page - span)
        high = min(self.pages, self.page + span)
        return list(range(low, high + 1))


def _api_filters(filters: Dict[str, Any]) -> Dict[str, Any]:
    """Swap the UI's window token for the timestamp the storage API expects."""
    prepared = {k: v for k, v in filters.items() if k not in ("window", "sort")}
    since = since_from_window(filters.get("window"))
    if since:
        prepared["since"] = since
    return prepared


# =========================================================================
# PAGED SEARCHES
# =========================================================================

def attackers_page(db, filters: Dict[str, Any], page: int, per_page: int) -> Page:
    rows, total = db.search_attackers(
        filters=_api_filters(filters),
        sort=filters.get("sort"),
        limit=per_page,
        offset=(page - 1) * per_page,
    )
    return Page(rows=rows, total=total, page=page, per_page=per_page)


def sessions_page(db, filters: Dict[str, Any], page: int, per_page: int) -> Page:
    rows, total = db.search_sessions(
        filters=_api_filters(filters),
        sort=filters.get("sort"),
        limit=per_page,
        offset=(page - 1) * per_page,
    )
    return Page(rows=rows, total=total, page=page, per_page=per_page)


def alerts_page(db, filters: Dict[str, Any], page: int, per_page: int) -> Page:
    rows, total = db.search_alerts(
        filters=_api_filters(filters),
        sort=filters.get("sort"),
        limit=per_page,
        offset=(page - 1) * per_page,
    )
    return Page(rows=rows, total=total, page=page, per_page=per_page)


# =========================================================================
# CHART SERIES — gap filling
# =========================================================================

def activity_series(db, hours: int = 24) -> List[Dict[str, Any]]:
    """
    Hourly event counts with the empty hours filled in.

    A ``GROUP BY`` returns no row for an hour with no events, and a chart that
    silently closes those gaps misreports a quiet period as a busy one. The
    zeroes are added here because they are a drawing concern, not a data one.
    """
    since = utc_ago(hours=hours)
    buckets = {row["bucket"]: row for row in db.get_event_activity(since, by="hour")}

    start = to_datetime(since)
    if start is None:
        return []
    start = start.replace(minute=0, second=0, microsecond=0)

    series = []
    for offset in range(hours + 1):
        moment = start + timedelta(hours=offset)
        row = buckets.get(moment.strftime("%Y-%m-%dT%H"), {})
        series.append({
            "bucket": moment.strftime("%Y-%m-%dT%H"),
            "hour": moment.strftime("%H:00"),
            "label": moment.strftime("%Y-%m-%d %H:00Z"),
            "total": row.get("total") or 0,
            "attacks": row.get("attacks") or 0,
            "logins": row.get("logins") or 0,
            "commands": row.get("commands") or 0,
            "ips": row.get("ips") or 0,
        })
    return series


def daily_activity(db, attacker_ip: str, days: int = 14) -> List[Dict[str, Any]]:
    """Per-day event counts for one IP, empty days included."""
    since = utc_ago(days=days)
    counts = {row["day"]: row["n"] for row in db.get_attacker_activity(attacker_ip, since)}

    start = to_datetime(since)
    if start is None:
        return []
    return [
        {
            "day": (start + timedelta(days=offset)).strftime("%Y-%m-%d"),
            "n": counts.get((start + timedelta(days=offset)).strftime("%Y-%m-%d"), 0),
        }
        for offset in range(days + 1)
    ]


# =========================================================================
# PRESENTATION POLICY
# =========================================================================

def node_health(db, heartbeat_interval: int, warn_missed: int, crit_missed: int,
                since: str = None) -> List[Dict[str, Any]]:
    """
    Node measurements from the storage API, plus this dashboard's verdict.

    The storage layer reports what it measured; how many missed heartbeats
    counts as degraded is a dashboard setting, so the amber/red decision is
    made here rather than being baked into shared code.

    The age is measured from any traffic, not just heartbeat events: a node
    streaming attacks is demonstrably alive even if its heartbeat timer
    drifted. It is also computed live rather than read from ``nodes.status``,
    so a stopped sweeper cannot make a dead node look healthy.
    """
    nodes = db.get_node_statistics(since=since or utc_ago(hours=24))

    for node in nodes:
        reference = max(
            [t for t in (node.get("last_seen"), node.get("last_event")) if t],
            default=None,
        )
        age = age_seconds(reference)
        node["last_contact"] = reference
        node["contact_age_seconds"] = age
        node["missed_heartbeats"] = (
            int(age // heartbeat_interval)
            if age is not None and heartbeat_interval else None
        )

        missed = node["missed_heartbeats"]
        if missed is None:
            node["health"] = "unknown"
        elif missed >= crit_missed:
            node["health"] = "critical"
        elif missed >= warn_missed:
            node["health"] = "warning"
        else:
            node["health"] = "healthy"

        # The screens speak in "24h"; the API speaks in "the window you asked
        # for". Alias them here so the templates stay readable.
        node["events_24h"] = node.get("events_recent", 0)
        node["attacks_24h"] = node.get("attacks_recent", 0)
        node["alerts_24h"] = node.get("alerts_recent", 0)
    return nodes


def adjacent_sessions(db, session_id: str, attacker_ip: str) -> Dict[str, Any]:
    """Previous/next session from the same IP, for walking an attacker's story."""
    ids = db.get_session_ids_for_ip(attacker_ip) if attacker_ip else []
    if session_id not in ids:
        return {"prev": None, "next": None, "index": None, "count": len(ids)}
    index = ids.index(session_id)
    return {
        "prev": ids[index - 1] if index > 0 else None,
        "next": ids[index + 1] if index + 1 < len(ids) else None,
        "index": index + 1,
        "count": len(ids),
    }
