"""
app/queries.py — Every read the dashboard performs, in one place.

Two rules govern this module.

**Use the storage API.** Where ``common.db.database.Database`` already exposes a
helper — ``get_overview_stats``, ``get_top_attackers``, ``get_top_credentials``,
``get_nodes``, ``get_alerts``, ``get_reputation``, ``get_attacker_profile_inputs``,
``get_feed_indicators`` — the dashboard calls it rather than writing its own SQL,
so a change to the storage contract reaches every screen at once. The remaining
functions here are the searches, filters and pagination the screens need and the
helpers do not offer; they still go through ``Database.query``, which is part of
that API, and they never open a connection of their own.

**Never touch a raw password.** Session listings read the ``sessions_public``
view, and the transcript query selects ``json_extract(details,'$.password') IS
NOT NULL`` — a boolean — so a plaintext credential from ``events.details`` is not
merely masked on screen, it is never fetched into the process.

Time windows are bound as Baseline v1.3 timestamp strings built in Python. Stored
timestamps look like ``2026-07-28T14:31:07Z``, while SQLite's ``datetime('now')``
yields ``2026-07-28 14:31:07``; comparing those two as strings matches on the
date and then ignores the time, which is the kind of bug that makes an "events in
the last hour" tile quietly report a whole day.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from common import config

from app.formatting import iso_ago, to_datetime

# Columns exposed as sort options. Anything not in one of these maps is
# rejected and replaced by the default — user input never reaches the SQL.
ATTACKER_SORTS = {
    "last_seen": "s.last_seen DESC",
    "first_seen": "s.first_seen DESC",
    "events": "s.event_count DESC",
    "sessions": "s.session_count DESC",
    "logins": "s.login_attempts DESC",
    "commands": "s.command_count DESC",
    "downloads": "s.download_count DESC",
    "nodes": "s.node_count DESC",
    "score": "risk_score DESC, s.event_count DESC",
    "alerts": "alert_count DESC, s.event_count DESC",
    "ip": "s.attacker_ip ASC",
}

SESSION_SORTS = {
    "start_time": "s.start_time DESC",
    "duration": "duration_seconds DESC",
    "events": "event_count DESC",
    "commands": "command_count DESC",
    "logins": "login_attempts DESC",
    "ip": "s.attacker_ip ASC",
    "node": "s.node_id ASC, s.start_time DESC",
}

ALERT_SORTS = {
    "timestamp": "a.timestamp DESC",
    "severity": (
        "CASE a.severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC, "
        "a.timestamp DESC"
    ),
    "type": "a.alert_type ASC, a.timestamp DESC",
    "ip": "a.attacker_ip ASC, a.timestamp DESC",
    "status": "a.status ASC, a.timestamp DESC",
}


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


def _order_by(sorts: Dict[str, str], key: Optional[str], default: str) -> str:
    return sorts.get(key or default, sorts[default])


def _since_from_window(window: Optional[str]) -> Optional[str]:
    """Translate a UI window token ('1h', '24h', '7d', 'all') into a timestamp."""
    mapping = {
        "1h": {"hours": 1},
        "6h": {"hours": 6},
        "24h": {"hours": 24},
        "7d": {"days": 7},
        "30d": {"days": 30},
    }
    if not window or window == "all":
        return None
    delta = mapping.get(window)
    return iso_ago(**delta) if delta else None


#: Public alias — other modules translate window tokens through this.
since_from_window = _since_from_window

WINDOW_CHOICES = [
    ("1h", "Last hour"),
    ("6h", "Last 6 hours"),
    ("24h", "Last 24 hours"),
    ("7d", "Last 7 days"),
    ("30d", "Last 30 days"),
    ("all", "All time"),
]


# =========================================================================
# OVERVIEW
# =========================================================================

def overview_stats(db) -> Dict[str, Any]:
    """
    Headline numbers, from ``Database.get_overview_stats()``.

    ``events_last_hour`` is recomputed here. The helper's own version compares a
    stored ``...T14:31:07Z`` against SQLite's ``... 14:31:07``, which makes the
    'T' decide the comparison and turns "last hour" into "since midnight". The
    rest of the helper's fields are counts and joins that are unaffected.
    """
    stats = db.get_overview_stats() or {}
    stats["events_last_hour"] = _count_events_since(db, iso_ago(hours=1))
    stats["events_last_24h"] = _count_events_since(db, iso_ago(hours=24))
    stats["attacks_last_24h"] = _count_events_since(
        db, iso_ago(hours=24), exclude_heartbeats=True
    )
    stats["sessions_last_24h"] = (
        db.query_one(
            "SELECT COUNT(*) AS n FROM sessions_public WHERE start_time >= :since",
            {"since": iso_ago(hours=24)},
        )
        or {}
    ).get("n", 0)
    stats["alerts_last_24h"] = (
        db.query_one(
            "SELECT COUNT(*) AS n FROM alerts WHERE timestamp >= :since",
            {"since": iso_ago(hours=24)},
        )
        or {}
    ).get("n", 0)
    stats["nodes_stale"] = max(
        0, (stats.get("nodes_total") or 0) - (stats.get("nodes_online") or 0)
    )
    stats["latest_event"] = (
        db.query_one("SELECT MAX(timestamp) AS ts FROM events") or {}
    ).get("ts")
    return stats


def _count_events_since(db, since: str, exclude_heartbeats: bool = False) -> int:
    clause = "AND event_type != 'heartbeat'" if exclude_heartbeats else ""
    row = db.query_one(
        f"SELECT COUNT(*) AS n FROM events WHERE timestamp >= :since {clause}",
        {"since": since},
    )
    return (row or {}).get("n", 0) or 0


def activity_series(db, hours: int = 24) -> List[Dict[str, Any]]:
    """
    Hourly event counts for the activity chart, with empty hours filled in.

    Buckets by ``substr(timestamp, 1, 13)`` — the canonical timestamp width makes
    the first thirteen characters an exact hour key, which keeps the whole
    rollup on the ``idx_events_ts`` index.
    """
    since = iso_ago(hours=hours)
    rows = db.query(
        """
        SELECT substr(timestamp, 1, 13) AS bucket,
               COUNT(*)                 AS total,
               SUM(CASE WHEN event_type != 'heartbeat' THEN 1 ELSE 0 END) AS attacks,
               SUM(CASE WHEN event_type = 'login_attempt' THEN 1 ELSE 0 END) AS logins,
               SUM(CASE WHEN event_type = 'command' THEN 1 ELSE 0 END) AS commands,
               COUNT(DISTINCT attacker_ip) AS ips
          FROM events
         WHERE timestamp >= :since
         GROUP BY bucket
         ORDER BY bucket
        """,
        {"since": since},
    )
    seen = {row["bucket"]: row for row in rows}

    from datetime import timedelta

    start = to_datetime(since)
    series = []
    if start is None:
        return list(rows)
    start = start.replace(minute=0, second=0, microsecond=0)
    for offset in range(hours + 1):
        moment = start + timedelta(hours=offset)
        key = moment.strftime("%Y-%m-%dT%H")
        row = seen.get(key, {})
        series.append(
            {
                "bucket": key,
                "hour": moment.strftime("%H:00"),
                "label": moment.strftime("%Y-%m-%d %H:00Z"),
                "total": row.get("total", 0) or 0,
                "attacks": row.get("attacks", 0) or 0,
                "logins": row.get("logins", 0) or 0,
                "commands": row.get("commands", 0) or 0,
                "ips": row.get("ips", 0) or 0,
            }
        )
    return series


def event_type_breakdown(db, window: str = "24h") -> List[Dict[str, Any]]:
    since = _since_from_window(window)
    where = "WHERE timestamp >= :since" if since else ""
    return db.query(
        f"""
        SELECT event_type, COUNT(*) AS n
          FROM events {where}
         GROUP BY event_type
         ORDER BY n DESC
        """,
        {"since": since} if since else {},
    )


def top_commands(db, limit: int = 10, window: Optional[str] = None) -> List[Dict[str, Any]]:
    since = _since_from_window(window)
    clause = "AND timestamp >= :since" if since else ""
    params: Dict[str, Any] = {"limit": limit}
    if since:
        params["since"] = since
    return db.query(
        f"""
        SELECT json_extract(details, '$.command') AS command,
               COUNT(*)                           AS attempts,
               COUNT(DISTINCT attacker_ip)        AS distinct_ips,
               MAX(timestamp)                     AS last_seen
          FROM events
         WHERE event_type = 'command'
           AND json_extract(details, '$.command') IS NOT NULL
           {clause}
         GROUP BY command
         ORDER BY attempts DESC
         LIMIT :limit
        """,
        params,
    )


def top_countries(db, limit: int = 8) -> List[Dict[str, Any]]:
    return db.query(
        """
        SELECT r.country, COUNT(*) AS ips, SUM(s.event_count) AS events
          FROM reputation r
          JOIN attacker_summary s ON s.attacker_ip = r.attacker_ip
         WHERE r.country IS NOT NULL AND r.country != ''
         GROUP BY r.country
         ORDER BY events DESC
         LIMIT :limit
        """,
        {"limit": limit},
    )


def severity_breakdown(db, status: Optional[str] = "open") -> Dict[str, int]:
    clause = "WHERE status = :status" if status else ""
    rows = db.query(
        f"SELECT severity, COUNT(*) AS n FROM alerts {clause} GROUP BY severity",
        {"status": status} if status else {},
    )
    counts = {name: 0 for name in config.SEVERITY_ORDER}
    for row in rows:
        counts[row["severity"]] = row["n"]
    return counts


# =========================================================================
# ATTACKERS
# =========================================================================

_ATTACKER_SELECT = """
    SELECT s.attacker_ip,
           s.first_seen, s.last_seen,
           s.event_count, s.session_count, s.node_count,
           s.login_attempts, s.login_successes,
           s.command_count, s.download_count,
           r.country, r.city, r.latitude, r.longitude,
           r.abuse_score, r.profile_score,
           r.source       AS reputation_source,
           r.last_updated AS reputation_updated,
           COALESCE(al.alert_count, 0) AS alert_count,
           COALESCE(al.high_alerts, 0) AS high_alerts,
           COALESCE(al.open_alerts, 0) AS open_alerts,
           MAX(COALESCE(r.abuse_score, 0), COALESCE(r.profile_score, 0)) AS risk_score
      FROM attacker_summary s
      LEFT JOIN reputation r ON r.attacker_ip = s.attacker_ip
      LEFT JOIN (
            SELECT attacker_ip,
                   COUNT(*)                                            AS alert_count,
                   SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END)  AS high_alerts,
                   SUM(CASE WHEN status = 'open'   THEN 1 ELSE 0 END)  AS open_alerts
              FROM alerts GROUP BY attacker_ip
      ) al ON al.attacker_ip = s.attacker_ip
"""


def _attacker_filters(filters: Dict[str, Any]) -> tuple:
    clauses: List[str] = []
    params: Dict[str, Any] = {}

    search = (filters.get("q") or "").strip()
    if search:
        clauses.append(
            "(s.attacker_ip LIKE :q OR r.country LIKE :q OR r.city LIKE :q)"
        )
        params["q"] = f"%{search}%"

    country = (filters.get("country") or "").strip()
    if country:
        clauses.append("r.country = :country")
        params["country"] = country

    min_score = filters.get("min_score")
    if min_score:
        clauses.append(
            "MAX(COALESCE(r.abuse_score, 0), COALESCE(r.profile_score, 0)) >= :min_score"
        )
        params["min_score"] = int(min_score)

    if filters.get("alerts_only"):
        clauses.append("COALESCE(al.alert_count, 0) > 0")
    if filters.get("high_only"):
        clauses.append("COALESCE(al.high_alerts, 0) > 0")
    if filters.get("breached_only"):
        clauses.append("s.login_successes > 0")
    if filters.get("enriched") == "yes":
        clauses.append("r.attacker_ip IS NOT NULL")
    elif filters.get("enriched") == "no":
        clauses.append("r.attacker_ip IS NULL")

    since = _since_from_window(filters.get("window"))
    if since:
        clauses.append("s.last_seen >= :since")
        params["since"] = since

    node = (filters.get("node") or "").strip()
    if node:
        clauses.append(
            "EXISTS (SELECT 1 FROM events e "
            "WHERE e.attacker_ip = s.attacker_ip AND e.node_id = :node)"
        )
        params["node"] = node

    return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params


def attackers_page(db, filters: Dict[str, Any], page: int, per_page: int) -> Page:
    where, params = _attacker_filters(filters)
    order = _order_by(ATTACKER_SORTS, filters.get("sort"), "last_seen")

    total = (
        db.query_one(
            f"SELECT COUNT(*) AS n FROM ({_ATTACKER_SELECT} {where})", params
        )
        or {}
    ).get("n", 0)

    rows = db.query(
        f"{_ATTACKER_SELECT} {where} ORDER BY {order} LIMIT :limit OFFSET :offset",
        {**params, "limit": per_page, "offset": (page - 1) * per_page},
    )
    return Page(rows=rows, total=total or 0, page=page, per_page=per_page)


def attacker_row(db, ip: str) -> Optional[Dict[str, Any]]:
    """The Attackers-table row for one IP, so profile and list agree exactly."""
    return db.query_one(
        f"{_ATTACKER_SELECT} WHERE s.attacker_ip = :ip", {"ip": ip}
    )


def attacker_sessions(db, ip: str, limit: int = 25) -> List[Dict[str, Any]]:
    return db.query(
        """
        SELECT s.session_id, s.node_id, s.protocol, s.username, s.password,
               s.start_time, s.end_time, s.status,
               COALESCE(e.event_count, 0)   AS event_count,
               COALESCE(e.command_count, 0) AS command_count,
               COALESCE(e.login_attempts, 0) AS login_attempts,
               COALESCE(e.login_successes, 0) AS login_successes
          FROM sessions_public s
          LEFT JOIN (
                SELECT session_id,
                       COUNT(*) AS event_count,
                       SUM(CASE WHEN event_type = 'command' THEN 1 ELSE 0 END) AS command_count,
                       SUM(CASE WHEN event_type = 'login_attempt' THEN 1 ELSE 0 END) AS login_attempts,
                       SUM(CASE WHEN event_type = 'login_success' THEN 1 ELSE 0 END) AS login_successes
                  FROM events GROUP BY session_id
          ) e ON e.session_id = s.session_id
         WHERE s.attacker_ip = :ip
         ORDER BY s.start_time DESC
         LIMIT :limit
        """,
        {"ip": ip, "limit": limit},
    )


def attacker_alerts(db, ip: str, limit: int = 50) -> List[Dict[str, Any]]:
    return db.query(
        """
        SELECT alert_id, attacker_ip, session_id, alert_type, severity,
               timestamp, description, status
          FROM alerts
         WHERE attacker_ip = :ip
         ORDER BY timestamp DESC
         LIMIT :limit
        """,
        {"ip": ip, "limit": limit},
    )


def attacker_commands(db, ip: str, limit: int = 25) -> List[Dict[str, Any]]:
    return db.query(
        """
        SELECT json_extract(details, '$.command') AS command,
               COUNT(*)       AS times,
               MAX(timestamp) AS last_seen
          FROM events
         WHERE event_type = 'command'
           AND attacker_ip = :ip
           AND json_extract(details, '$.command') IS NOT NULL
         GROUP BY command
         ORDER BY times DESC, last_seen DESC
         LIMIT :limit
        """,
        {"ip": ip, "limit": limit},
    )


def attacker_usernames(db, ip: str, limit: int = 15) -> List[Dict[str, Any]]:
    """
    Usernames tried by one IP.

    Usernames only — attempted passwords stay in local storage, so the profile
    page shows credential *breadth* without ever reading the secret half.
    """
    return db.query(
        """
        SELECT json_extract(details, '$.username') AS username,
               COUNT(*) AS attempts,
               SUM(CASE WHEN event_type = 'login_success' THEN 1 ELSE 0 END) AS successes
          FROM events
         WHERE attacker_ip = :ip
           AND event_type IN ('login_attempt', 'login_success')
           AND json_extract(details, '$.username') IS NOT NULL
         GROUP BY username
         ORDER BY attempts DESC
         LIMIT :limit
        """,
        {"ip": ip, "limit": limit},
    )


def attacker_nodes(db, ip: str) -> List[Dict[str, Any]]:
    return db.query(
        """
        SELECT node_id,
               COUNT(*)       AS events,
               MIN(timestamp) AS first_seen,
               MAX(timestamp) AS last_seen
          FROM events
         WHERE attacker_ip = :ip
         GROUP BY node_id
         ORDER BY events DESC
        """,
        {"ip": ip},
    )


def attacker_timeline(db, ip: str, limit: int = 200) -> List[Dict[str, Any]]:
    """Recent raw events for one IP. Passwords are never selected."""
    return db.query(
        """
        SELECT event_id, node_id, session_id, event_type, timestamp, protocol,
               json_extract(details, '$.username') AS username,
               json_extract(details, '$.command')  AS command,
               json_extract(details, '$.file_name') AS file_name,
               json_extract(details, '$.download_url') AS download_url,
               json_extract(details, '$.status')   AS status
          FROM events
         WHERE attacker_ip = :ip
         ORDER BY timestamp DESC
         LIMIT :limit
        """,
        {"ip": ip, "limit": limit},
    )


def attacker_daily(db, ip: str, days: int = 14) -> List[Dict[str, Any]]:
    since = iso_ago(days=days)
    rows = db.query(
        """
        SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS n
          FROM events
         WHERE attacker_ip = :ip AND timestamp >= :since
         GROUP BY day ORDER BY day
        """,
        {"ip": ip, "since": since},
    )
    seen = {row["day"]: row["n"] for row in rows}

    from datetime import timedelta

    start = to_datetime(since)
    if start is None:
        return rows
    return [
        {
            "day": (start + timedelta(days=offset)).strftime("%Y-%m-%d"),
            "n": seen.get((start + timedelta(days=offset)).strftime("%Y-%m-%d"), 0),
        }
        for offset in range(days + 1)
    ]


def known_countries(db) -> List[str]:
    rows = db.query(
        "SELECT DISTINCT country FROM reputation "
        "WHERE country IS NOT NULL AND country != '' ORDER BY country"
    )
    return [row["country"] for row in rows]


# =========================================================================
# SESSIONS
# =========================================================================

_SESSION_SELECT = """
    SELECT s.session_id, s.node_id, s.attacker_ip, s.protocol,
           s.username, s.password, s.start_time, s.end_time, s.status,
           r.country, r.city, r.abuse_score, r.profile_score,
           COALESCE(e.event_count, 0)     AS event_count,
           COALESCE(e.command_count, 0)   AS command_count,
           COALESCE(e.login_attempts, 0)  AS login_attempts,
           COALESCE(e.login_successes, 0) AS login_successes,
           COALESCE(e.download_count, 0)  AS download_count,
           e.last_event                   AS last_event,
           CASE WHEN s.end_time IS NOT NULL AND s.start_time IS NOT NULL
                THEN CAST((julianday(s.end_time) - julianday(s.start_time)) * 86400.0 AS INTEGER)
                END AS duration_seconds
      FROM sessions_public s
      LEFT JOIN reputation r ON r.attacker_ip = s.attacker_ip
      LEFT JOIN (
            SELECT session_id,
                   COUNT(*) AS event_count,
                   MAX(timestamp) AS last_event,
                   SUM(CASE WHEN event_type = 'command' THEN 1 ELSE 0 END) AS command_count,
                   SUM(CASE WHEN event_type = 'login_attempt' THEN 1 ELSE 0 END) AS login_attempts,
                   SUM(CASE WHEN event_type = 'login_success' THEN 1 ELSE 0 END) AS login_successes,
                   SUM(CASE WHEN event_type = 'file_download' THEN 1 ELSE 0 END) AS download_count
              FROM events GROUP BY session_id
      ) e ON e.session_id = s.session_id
"""


def _session_filters(filters: Dict[str, Any]) -> tuple:
    clauses: List[str] = []
    params: Dict[str, Any] = {}

    search = (filters.get("q") or "").strip()
    if search:
        clauses.append(
            "(s.session_id LIKE :q OR s.attacker_ip LIKE :q OR s.username LIKE :q)"
        )
        params["q"] = f"%{search}%"

    for key, column in (("status", "s.status"), ("node", "s.node_id"),
                        ("protocol", "s.protocol"), ("ip", "s.attacker_ip")):
        value = (filters.get(key) or "").strip()
        if value:
            clauses.append(f"{column} = :{key}")
            params[key] = value

    if filters.get("breached_only"):
        clauses.append("COALESCE(e.login_successes, 0) > 0")
    if filters.get("commands_only"):
        clauses.append("COALESCE(e.command_count, 0) > 0")

    since = _since_from_window(filters.get("window"))
    if since:
        clauses.append("s.start_time >= :since")
        params["since"] = since

    return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params


def sessions_page(db, filters: Dict[str, Any], page: int, per_page: int) -> Page:
    where, params = _session_filters(filters)
    order = _order_by(SESSION_SORTS, filters.get("sort"), "start_time")

    total = (
        db.query_one(f"SELECT COUNT(*) AS n FROM ({_SESSION_SELECT} {where})", params)
        or {}
    ).get("n", 0)

    rows = db.query(
        f"{_SESSION_SELECT} {where} ORDER BY {order} LIMIT :limit OFFSET :offset",
        {**params, "limit": per_page, "offset": (page - 1) * per_page},
    )
    return Page(rows=rows, total=total or 0, page=page, per_page=per_page)


def session_header(db, session_id: str) -> Optional[Dict[str, Any]]:
    return db.query_one(
        f"{_SESSION_SELECT} WHERE s.session_id = :sid", {"sid": session_id}
    )


def session_transcript(db, session_id: str) -> List[Dict[str, Any]]:
    """
    Every event in one session, oldest first, shaped for the terminal view.

    ``had_password`` is a boolean, not a value: the query asks whether a password
    was submitted and never selects what it was. The transcript can therefore
    render ``***MASKED***`` from a fact rather than from a string it is trusting
    itself to remember to hide.
    """
    return db.query(
        """
        SELECT event_id, event_type, timestamp, node_id, attacker_ip, protocol,
               json_extract(details, '$.username')         AS username,
               CASE WHEN json_extract(details, '$.password') IS NULL
                    THEN 0 ELSE 1 END                      AS had_password,
               json_extract(details, '$.command')          AS command,
               json_extract(details, '$.download_url')     AS download_url,
               json_extract(details, '$.file_name')        AS file_name,
               json_extract(details, '$.file_hash')        AS file_hash,
               json_extract(details, '$.status')           AS status,
               json_extract(details, '$.duration_seconds') AS duration_seconds,
               json_extract(details, '$.destination_ip')   AS destination_ip,
               json_extract(details, '$.destination_port') AS destination_port,
               json_extract(details, '$.source_port')      AS source_port,
               json_extract(details, '$.agent_version')    AS agent_version
          FROM events
         WHERE session_id = :sid
         ORDER BY timestamp ASC, received_at ASC
        """,
        {"sid": session_id},
    )


def session_alerts(db, session_id: str) -> List[Dict[str, Any]]:
    return db.query(
        """
        SELECT alert_id, alert_type, severity, timestamp, description, status
          FROM alerts WHERE session_id = :sid ORDER BY timestamp ASC
        """,
        {"sid": session_id},
    )


def adjacent_sessions(db, session_id: str, attacker_ip: str) -> Dict[str, Any]:
    """Previous/next session from the same IP, for walking an attacker's story."""
    rows = db.query(
        """
        SELECT session_id, start_time FROM sessions_public
         WHERE attacker_ip = :ip ORDER BY start_time DESC
        """,
        {"ip": attacker_ip},
    )
    ids = [row["session_id"] for row in rows]
    if session_id not in ids:
        return {"prev": None, "next": None, "index": None, "count": len(ids)}
    index = ids.index(session_id)
    return {
        "prev": ids[index - 1] if index > 0 else None,
        "next": ids[index + 1] if index + 1 < len(ids) else None,
        "index": index + 1,
        "count": len(ids),
    }


# =========================================================================
# ALERTS
# =========================================================================

_ALERT_SELECT = """
    SELECT a.alert_id, a.attacker_ip, a.session_id, a.alert_type,
           a.severity, a.timestamp, a.description, a.status,
           r.country, r.city, r.abuse_score, r.profile_score
      FROM alerts a
      LEFT JOIN reputation r ON r.attacker_ip = a.attacker_ip
"""


def _alert_filters(filters: Dict[str, Any]) -> tuple:
    clauses: List[str] = []
    params: Dict[str, Any] = {}

    search = (filters.get("q") or "").strip()
    if search:
        clauses.append(
            "(a.attacker_ip LIKE :q OR a.description LIKE :q "
            "OR a.session_id LIKE :q OR a.alert_type LIKE :q)"
        )
        params["q"] = f"%{search}%"

    for key, column in (("status", "a.status"), ("severity", "a.severity"),
                        ("type", "a.alert_type"), ("ip", "a.attacker_ip"),
                        ("session", "a.session_id")):
        value = (filters.get(key) or "").strip()
        if value:
            clauses.append(f"{column} = :f_{key}")
            params[f"f_{key}"] = value

    min_severity = (filters.get("min_severity") or "").strip()
    if min_severity in config.SEVERITY_ORDER:
        allowed = [
            name
            for name, rank in config.SEVERITY_ORDER.items()
            if rank >= config.SEVERITY_ORDER[min_severity]
        ]
        names = [f"minsev_{i}" for i in range(len(allowed))]
        clauses.append(f"a.severity IN ({', '.join(':' + n for n in names)})")
        params.update(dict(zip(names, allowed)))

    since = _since_from_window(filters.get("window"))
    if since:
        clauses.append("a.timestamp >= :since")
        params["since"] = since

    return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params


def alerts_page(db, filters: Dict[str, Any], page: int, per_page: int) -> Page:
    where, params = _alert_filters(filters)
    order = _order_by(ALERT_SORTS, filters.get("sort"), "timestamp")

    total = (
        db.query_one(f"SELECT COUNT(*) AS n FROM ({_ALERT_SELECT} {where})", params)
        or {}
    ).get("n", 0)

    rows = db.query(
        f"{_ALERT_SELECT} {where} ORDER BY {order} LIMIT :limit OFFSET :offset",
        {**params, "limit": per_page, "offset": (page - 1) * per_page},
    )
    return Page(rows=rows, total=total or 0, page=page, per_page=per_page)


def alert_type_stats(db, window: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Per-rule counts, keyed by alert_type, for the rules panel."""
    since = _since_from_window(window)
    where = "WHERE timestamp >= :since" if since else ""
    rows = db.query(
        f"""
        SELECT alert_type,
               COUNT(*) AS total,
               SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END)     AS open_count,
               SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END)   AS high_count,
               MAX(timestamp) AS last_fired,
               COUNT(DISTINCT attacker_ip) AS distinct_ips
          FROM alerts {where}
         GROUP BY alert_type
        """,
        {"since": since} if since else {},
    )
    return {row["alert_type"]: row for row in rows}


def alert_status_counts(db) -> Dict[str, int]:
    rows = db.query("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status")
    counts = {"open": 0, "acknowledged": 0, "closed": 0}
    for row in rows:
        counts[row["status"]] = row["n"]
    return counts


def alert_detail(db, alert_id: str) -> Optional[Dict[str, Any]]:
    return db.query_one(
        f"{_ALERT_SELECT} WHERE a.alert_id = :id", {"id": alert_id}
    )


# =========================================================================
# NODES
# =========================================================================

def node_health(db, heartbeat_interval: int, warn_missed: int, crit_missed: int
                ) -> List[Dict[str, Any]]:
    """
    One row per node, enriched with the numbers an operator triages on.

    Node status in the ``nodes`` table is maintained by the collector's sweeper;
    the health verdict here is computed live from ``last_seen`` so a stopped
    sweeper cannot make a dead node look healthy.
    """
    stats = {
        row["node_id"]: row
        for row in db.query(
            """
            SELECT node_id,
                   COUNT(*)                    AS events_total,
                   COUNT(DISTINCT session_id)  AS sessions_total,
                   COUNT(DISTINCT attacker_ip) AS attackers_total,
                   MAX(timestamp)              AS last_event,
                   MAX(CASE WHEN event_type = 'heartbeat' THEN timestamp END)
                                               AS last_heartbeat,
                   AVG((julianday(received_at) - julianday(timestamp)) * 86400.0)
                                               AS avg_lag_seconds,
                   MAX((julianday(received_at) - julianday(timestamp)) * 86400.0)
                                               AS max_lag_seconds
              FROM events GROUP BY node_id
            """
        )
    }
    recent = {
        row["node_id"]: row
        for row in db.query(
            """
            SELECT node_id,
                   COUNT(*) AS events_24h,
                   SUM(CASE WHEN event_type != 'heartbeat' THEN 1 ELSE 0 END) AS attacks_24h,
                   SUM(CASE WHEN event_type = 'heartbeat' THEN 1 ELSE 0 END)  AS heartbeats_24h
              FROM events WHERE timestamp >= :since GROUP BY node_id
            """,
            {"since": iso_ago(hours=24)},
        )
    }
    alerts = {
        row["node_id"]: row["n"]
        for row in db.query(
            """
            SELECT e.node_id, COUNT(DISTINCT a.alert_id) AS n
              FROM alerts a
              JOIN events e ON e.session_id = a.session_id
             WHERE a.session_id IS NOT NULL AND a.timestamp >= :since
             GROUP BY e.node_id
            """,
            {"since": iso_ago(hours=24)},
        )
    }

    from app.formatting import age_seconds

    nodes = []
    for node in db.get_nodes():
        node_id = node["node_id"]
        node.update(stats.get(node_id, {}))
        node.update(recent.get(node_id, {}))
        node.setdefault("events_total", 0)
        node.setdefault("events_24h", 0)
        node["alerts_24h"] = alerts.get(node_id, 0)

        # Heartbeat age is measured from any traffic, not just heartbeat events:
        # a node streaming attacks is demonstrably alive even if its heartbeat
        # timer drifted.
        reference = max(
            [t for t in (node.get("last_seen"), node.get("last_event")) if t],
            default=None,
        )
        age = age_seconds(reference)
        node["contact_age_seconds"] = age
        node["last_contact"] = reference
        node["missed_heartbeats"] = (
            int(age // heartbeat_interval) if age is not None and heartbeat_interval else None
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
        nodes.append(node)
    return nodes


def node_activity(db, node_id: str, hours: int = 24) -> List[Dict[str, Any]]:
    rows = db.query(
        """
        SELECT substr(timestamp, 1, 13) AS bucket, COUNT(*) AS n
          FROM events
         WHERE node_id = :node AND timestamp >= :since
         GROUP BY bucket ORDER BY bucket
        """,
        {"node": node_id, "since": iso_ago(hours=hours)},
    )
    return rows


# =========================================================================
# SHARED FILTER OPTIONS
# =========================================================================

def distinct_nodes(db) -> List[str]:
    return [row["node_id"] for row in db.get_nodes()]


def distinct_protocols(db) -> List[str]:
    rows = db.query(
        "SELECT DISTINCT protocol FROM sessions_public "
        "WHERE protocol IS NOT NULL ORDER BY protocol"
    )
    return [row["protocol"] for row in rows]


def distinct_alert_types(db) -> List[str]:
    rows = db.query("SELECT DISTINCT alert_type FROM alerts ORDER BY alert_type")
    return [row["alert_type"] for row in rows]
