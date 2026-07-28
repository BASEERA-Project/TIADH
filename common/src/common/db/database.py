"""
db/database.py — The shared storage layer for the whole team.

This module owns the database. Nobody else should open a write connection to
`honeypot_aggregator.db` directly; everyone calls the functions below. That is
what keeps the write path single-threaded enough for SQLite to cope, and what
guarantees that masking, validation and idempotency happen every time instead of
whenever someone remembers.

Who calls what
--------------
Part 2 (ingestion)   apply_event(), apply_events(), upsert_node(),
                     mark_stale_nodes_offline(), close_stale_sessions()
Part 3 (enrichment)  get_ips_needing_enrichment(), upsert_reputation(),
                     get_attacker_profile_inputs()
Part 4 (this part)   insert_alert(), get_alerts(), get_feed_indicators()
Part 5 (dashboard)   Database(read_only=True) + the get_* helpers.
                     ALWAYS read sessions through get_sessions() — it selects
                     from the masked `sessions_public` view.

Concurrency notes
-----------------
* WAL journal mode: readers never block the writer and vice versa. Without it,
  the dashboard polling every 10s will produce "database is locked" for the
  collector within a day.
* One connection per thread (``threading.local``) — sqlite3 connections are not
  safe to share across threads.
* Writers retry briefly on lock contention rather than raising immediately.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from common import config
from common.db.validation import normalize_event, utc_now, validate_event

log = logging.getLogger(__name__)

#: Namespace for every deterministic UUID this project mints.
UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "honeypot-ti-aggregator.local")


class StorageError(RuntimeError):
    """Raised when a write cannot be completed."""


class ValidationError(ValueError):
    """Raised when an event fails the Baseline v1.3 contract."""

    def __init__(self, errors: Sequence[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


class Database:
    """A thread-safe handle to the central SQLite database."""

    def __init__(
        self,
        path: Path | str = None,
        read_only: bool = False,
        busy_timeout_ms: int = None,
    ):
        self.path = Path(path or config.DB_PATH)
        self.read_only = read_only
        self.busy_timeout_ms = (
            config.BUSY_TIMEOUT_MS if busy_timeout_ms is None else busy_timeout_ms
        )
        self._local = threading.local()
        self._write_lock = threading.Lock()

    # -- connection management --------------------------------------------

    def _new_connection(self) -> sqlite3.Connection:
        if self.read_only:
            # mode=ro guarantees the dashboard can never take a write lock,
            # even by accident.
            conn = sqlite3.connect(
                f"file:{self.path}?mode=ro", uri=True, timeout=self.busy_timeout_ms / 1000
            )
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.path), timeout=self.busy_timeout_ms / 1000)

        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        conn.execute("PRAGMA foreign_keys = ON")
        if not self.read_only:
            # WAL is persistent per-database, but setting it is cheap and makes
            # a fresh clone behave correctly on first run.
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        """The calling thread's connection, created on first use."""
        existing = getattr(self._local, "conn", None)
        if existing is None:
            existing = self._new_connection()
            self._local.conn = existing
        return existing

    def close(self) -> None:
        existing = getattr(self._local, "conn", None)
        if existing is not None:
            existing.close()
            self._local.conn = None

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @contextmanager
    def transaction(self, retries: int = 3):
        """
        Run a block as one transaction, retrying briefly on lock contention.

        Keep the block short. A long transaction on SQLite blocks every other
        writer for its whole duration.
        """
        if self.read_only:
            raise StorageError("this Database handle is read-only")

        attempt = 0
        while True:
            try:
                with self._write_lock:
                    with self.conn:
                        yield self.conn
                return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or attempt >= retries:
                    raise StorageError(f"transaction failed: {exc}") from exc
                attempt += 1
                time.sleep(0.25 * attempt)
                log.warning("database locked, retry %s/%s", attempt, retries)

    # -- schema -----------------------------------------------------------

    def initialize_schema(self, schema_path: Path | str = None) -> None:
        """Create every table, index and view. Safe to call repeatedly."""
        schema_file = Path(schema_path or config.SCHEMA_PATH)
        if not schema_file.exists():
            raise StorageError(f"schema file not found: {schema_file}")

        ddl = schema_file.read_text(encoding="utf-8")
        with self.transaction() as conn:
            conn.executescript(ddl)
            conn.execute(f"PRAGMA user_version = {self.schema_user_version()}")
        log.info("schema initialised at %s", self.path)

    @staticmethod
    def schema_user_version() -> int:
        """Numeric form of Baseline v1.3, stored in PRAGMA user_version."""
        return 13

    def current_user_version(self) -> int:
        return int(self.conn.execute("PRAGMA user_version").fetchone()[0])

    # -- generic query helpers --------------------------------------------

    def query(self, sql: str, params: Sequence | Dict = ()) -> List[Dict[str, Any]]:
        """Run a SELECT and return a list of plain dicts."""
        cur = self.conn.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]

    def query_one(self, sql: str, params: Sequence | Dict = ()) -> Optional[Dict[str, Any]]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # =====================================================================
    # NODES  — called by Part 2
    # =====================================================================

    def upsert_node(
        self,
        node_id: str,
        hostname: str = None,
        location: str = None,
        ip_address: str = None,
        status: str = None,
        last_seen: str = None,
    ) -> None:
        """
        Create or update a node row.

        Only non-None arguments overwrite existing values, so the collector can
        bump `last_seen` on every event without wiping the hostname that was
        registered once at startup.
        """
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO nodes (node_id, hostname, location, ip_address, status, last_seen)
                VALUES (:node_id, :hostname, :location, :ip_address,
                        COALESCE(:status, 'offline'), :last_seen)
                ON CONFLICT(node_id) DO UPDATE SET
                    hostname   = COALESCE(excluded.hostname,   nodes.hostname),
                    location   = COALESCE(excluded.location,   nodes.location),
                    ip_address = COALESCE(excluded.ip_address, nodes.ip_address),
                    status     = COALESCE(:status,             nodes.status),
                    last_seen  = COALESCE(excluded.last_seen,  nodes.last_seen)
                """,
                {
                    "node_id": node_id,
                    "hostname": hostname,
                    "location": location,
                    "ip_address": ip_address,
                    "status": status,
                    "last_seen": last_seen,
                },
            )

    def mark_stale_nodes_offline(self, timeout_seconds: int = None) -> int:
        """
        Flip nodes to 'offline' when they have missed enough heartbeats.

        Run this from the collector's background loop or from `main.py run`.
        Returns the number of nodes whose status changed.
        """
        # `x or default` would turn an explicit 0 back into the default.
        timeout = (
            config.NODE_OFFLINE_AFTER_SECONDS if timeout_seconds is None else timeout_seconds
        )
        with self.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE nodes
                   SET status = 'offline'
                 WHERE status = 'online'
                   AND (last_seen IS NULL
                        OR (julianday('now') - julianday(last_seen)) * 86400.0 > :timeout)
                """,
                {"timeout": timeout},
            )
            return cur.rowcount

    def get_nodes(self) -> List[Dict[str, Any]]:
        return self.query("SELECT * FROM nodes ORDER BY node_id")

    # =====================================================================
    # EVENTS  — called by Part 2 for every incoming event
    # =====================================================================

    def apply_event(self, event: Dict[str, Any], validate: bool = True) -> str:
        """
        Persist one event and everything derived from it, atomically.

        This is *the* ingestion entry point. It

          1. validates the envelope against Baseline v1.3,
          2. inserts into `events` (idempotent on event_id),
          3. creates or updates the matching `sessions` row,
          4. refreshes `nodes.last_seen` and marks the node online.

        Returns ``"accepted"``, ``"duplicate"`` or raises :class:`ValidationError`
        — which maps directly onto the collector's
        ``{"accepted": n, "duplicates": n, "rejected": n}`` response body.
        """
        if validate:
            ok, errors = validate_event(event)
            if not ok:
                raise ValidationError(errors)

        normalized = normalize_event(event)
        received_at = utc_now()

        with self.transaction() as conn:
            # FKs point at nodes, so guarantee the parent row exists first.
            conn.execute(
                "INSERT OR IGNORE INTO nodes (node_id, status) VALUES (?, 'offline')",
                (normalized["node_id"],),
            )

            cur = conn.execute(
                """
                INSERT OR IGNORE INTO events
                    (event_id, node_id, session_id, event_type, timestamp,
                     attacker_ip, protocol, details, received_at)
                VALUES
                    (:event_id, :node_id, :session_id, :event_type, :timestamp,
                     :attacker_ip, :protocol, :details, :received_at)
                """,
                {**normalized, "received_at": received_at},
            )

            if cur.rowcount == 0:
                return "duplicate"

            self._touch_node(conn, normalized["node_id"], normalized["timestamp"])
            if normalized["event_type"] != "heartbeat":
                self._derive_session(conn, event, normalized)

        return "accepted"

    def apply_events(self, events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Batch form of :meth:`apply_event`, matching the collector's response shape.

        Each event succeeds or fails on its own — one malformed event in a batch
        of twenty never causes the other nineteen to be dropped. The ``errors``
        list tells the sending node *which* events were rejected and why, so it
        can drop them from `pending_events.jsonl` instead of retrying forever.
        """
        result = {"accepted": 0, "duplicates": 0, "rejected": 0, "errors": []}

        for event in events:
            event_id = event.get("event_id") if isinstance(event, dict) else None
            try:
                outcome = self.apply_event(event)
            except ValidationError as exc:
                result["rejected"] += 1
                result["errors"].append({"event_id": event_id, "reasons": exc.errors})
            except StorageError as exc:
                result["rejected"] += 1
                result["errors"].append({"event_id": event_id, "reasons": [str(exc)]})
            else:
                result["duplicates" if outcome == "duplicate" else "accepted"] += 1

        return result

    @staticmethod
    def _touch_node(conn: sqlite3.Connection, node_id: str, timestamp: str) -> None:
        """Move `last_seen` forward only — out-of-order events must not rewind it."""
        conn.execute(
            """
            UPDATE nodes
               SET last_seen = CASE
                       WHEN last_seen IS NULL OR :ts > last_seen THEN :ts
                       ELSE last_seen END,
                   status = 'online'
             WHERE node_id = :node_id
            """,
            {"ts": timestamp, "node_id": node_id},
        )

    @staticmethod
    def _derive_session(
        conn: sqlite3.Connection, raw_event: Dict[str, Any], normalized: Dict[str, Any]
    ) -> None:
        """
        Fold an event into its `sessions` row.

        Written as a single UPSERT on purpose: events arrive out of order after
        any retry, so `session_end` may well be processed before `connection`.
        Every field advances monotonically (earliest start, latest end) and a
        closed session is never reopened by a late-arriving early event.
        """
        details = raw_event.get("details") or {}
        event_type = normalized["event_type"]
        session_id = normalized["session_id"]
        timestamp = normalized["timestamp"]

        username = details.get("username")
        password = details.get("password")
        end_time = timestamp if event_type == "session_end" else None

        if event_type == "session_end":
            status = "failed" if details.get("status") in ("failed", "error") else "closed"
        else:
            status = "active"

        conn.execute(
            """
            INSERT INTO sessions
                (session_id, node_id, attacker_ip, protocol,
                 username, password, start_time, end_time, status)
            VALUES
                (:session_id, :node_id, :attacker_ip, :protocol,
                 :username, :password, :timestamp, :end_time, :status)
            ON CONFLICT(session_id) DO UPDATE SET
                attacker_ip = COALESCE(sessions.attacker_ip, excluded.attacker_ip),
                protocol    = COALESCE(sessions.protocol,    excluded.protocol),
                username    = COALESCE(excluded.username,    sessions.username),
                password    = COALESCE(excluded.password,    sessions.password),
                start_time  = MIN(COALESCE(sessions.start_time, excluded.start_time),
                                  excluded.start_time),
                end_time    = COALESCE(excluded.end_time, sessions.end_time),
                status      = CASE
                                WHEN excluded.status IN ('closed', 'failed') THEN excluded.status
                                WHEN sessions.status IN ('closed', 'failed') THEN sessions.status
                                ELSE 'active' END
            """,
            {
                "session_id": session_id,
                "node_id": normalized["node_id"],
                "attacker_ip": normalized["attacker_ip"],
                "protocol": normalized["protocol"],
                "username": username,
                "password": password,
                "timestamp": timestamp,
                "end_time": end_time,
                "status": status,
            },
        )

    def close_stale_sessions(self, timeout_seconds: int = None) -> int:
        """
        Force-close sessions abandoned by a node that died mid-session.

        Without this the dashboard's "active sessions" counter only ever grows.
        """
        timeout = (
            config.SESSION_STALE_AFTER_SECONDS if timeout_seconds is None else timeout_seconds
        )
        with self.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE sessions
                   SET status = 'failed',
                       end_time = COALESCE(end_time, start_time)
                 WHERE status = 'active'
                   AND (julianday('now') - julianday(
                            COALESCE((SELECT MAX(timestamp) FROM events e
                                       WHERE e.session_id = sessions.session_id),
                                     sessions.start_time)
                        )) * 86400.0 > :timeout
                """,
                {"timeout": timeout},
            )
            return cur.rowcount

    # =====================================================================
    # REPUTATION  — called by Part 3
    # =====================================================================

    def get_ips_needing_enrichment(
        self, max_age_days: int = 7, limit: int = 100, include_private: bool = False
    ) -> List[str]:
        """
        Attacker IPs with no reputation row, or one older than `max_age_days`.

        Part 3's worker loop calls this, enriches each result, then calls
        :meth:`upsert_reputation`. Private ranges are filtered out by default —
        during lab testing they would otherwise burn the whole AbuseIPDB quota.
        """
        rows = self.query(
            """
            SELECT DISTINCT e.attacker_ip AS ip
              FROM events e
              LEFT JOIN reputation r ON r.attacker_ip = e.attacker_ip
             WHERE e.attacker_ip IS NOT NULL
               AND (r.attacker_ip IS NULL
                    OR r.last_updated IS NULL
                    OR (julianday('now') - julianday(r.last_updated)) > :max_age)
             ORDER BY e.attacker_ip
             LIMIT :limit
            """,
            {"max_age": max_age_days, "limit": limit},
        )
        ips = [r["ip"] for r in rows]
        if include_private:
            return ips
        return [ip for ip in ips if not _is_private_ip(ip)]

    def upsert_reputation(
        self,
        attacker_ip: str,
        country: str = None,
        city: str = None,
        latitude: float = None,
        longitude: float = None,
        abuse_score: int = None,
        source: str = None,
        profile_score: int = None,
        last_updated: str = None,
    ) -> None:
        """
        Write one enrichment result.

        Geo data and abuse score come from external APIs; `profile_score` is
        computed locally from the event stream. They are deliberately updated on
        separate arguments so an AbuseIPDB outage cannot stall profiling — pass
        only what you have, and existing values survive.

        `source` accumulates: passing 'AbuseIPDB' to a row that already says
        'GeoLite2' yields 'GeoLite2,AbuseIPDB'.
        """
        with self.transaction() as conn:
            existing = conn.execute(
                "SELECT source FROM reputation WHERE attacker_ip = ?", (attacker_ip,)
            ).fetchone()

            merged_source = source
            if existing and existing["source"]:
                known = [s for s in existing["source"].split(",") if s]
                if source and source not in known:
                    known.append(source)
                merged_source = ",".join(known)

            conn.execute(
                """
                INSERT INTO reputation
                    (attacker_ip, country, city, latitude, longitude,
                     abuse_score, source, profile_score, last_updated)
                VALUES
                    (:ip, :country, :city, :lat, :lon,
                     :abuse, :source, COALESCE(:profile, 0), :updated)
                ON CONFLICT(attacker_ip) DO UPDATE SET
                    country       = COALESCE(excluded.country,   reputation.country),
                    city          = COALESCE(excluded.city,      reputation.city),
                    latitude      = COALESCE(excluded.latitude,  reputation.latitude),
                    longitude     = COALESCE(excluded.longitude, reputation.longitude),
                    abuse_score   = COALESCE(:abuse,             reputation.abuse_score),
                    source        = COALESCE(excluded.source,    reputation.source),
                    profile_score = COALESCE(:profile,           reputation.profile_score),
                    last_updated  = excluded.last_updated
                """,
                {
                    "ip": attacker_ip,
                    "country": country,
                    "city": city,
                    "lat": latitude,
                    "lon": longitude,
                    "abuse": abuse_score,
                    "source": merged_source,
                    "profile": profile_score,
                    "updated": last_updated or utc_now(),
                },
            )

    def get_attacker_profile_inputs(self, attacker_ip: str) -> Dict[str, Any]:
        """
        Behavioural counters for one IP, for Part 3's `profile_score` formula.

        Returns session/command/download counts, node spread and credential
        breadth — everything the scoring function needs, in one query, so Part 3
        never has to write SQL of its own.
        """
        summary = self.query_one(
            "SELECT * FROM attacker_summary WHERE attacker_ip = ?", (attacker_ip,)
        ) or {
            "attacker_ip": attacker_ip,
            "first_seen": None,
            "last_seen": None,
            "event_count": 0,
            "session_count": 0,
            "node_count": 0,
            "login_attempts": 0,
            "login_successes": 0,
            "command_count": 0,
            "download_count": 0,
        }

        extra = self.query_one(
            """
            SELECT COUNT(DISTINCT json_extract(details, '$.command'))  AS distinct_commands,
                   COUNT(DISTINCT json_extract(details, '$.username')) AS distinct_usernames
              FROM events
             WHERE attacker_ip = ?
            """,
            (attacker_ip,),
        )
        summary.update(extra or {"distinct_commands": 0, "distinct_usernames": 0})
        return summary

    def get_reputation(self, attacker_ip: str) -> Optional[Dict[str, Any]]:
        return self.query_one("SELECT * FROM reputation WHERE attacker_ip = ?", (attacker_ip,))

    # =====================================================================
    # ALERTS  — written by the Part 4 engine, read by Part 5
    # =====================================================================

    def insert_alert(
        self,
        attacker_ip: str,
        alert_type: str,
        severity: str,
        description: str,
        session_id: str = None,
        timestamp: str = None,
        dedupe_key: str = None,
        cooldown_minutes: int = None,
    ) -> Optional[str]:
        """
        Record an alert, unless an equivalent one is already live.

        Two independent guards stop the alert table from filling with noise when
        the engine runs every 30 seconds against the same ongoing attack:

        * **Deterministic id** — `alert_id` is a UUIDv5 of `dedupe_key`, so
          re-evaluating the same window produces the same id and the insert is
          ignored.
        * **Cooldown** — a still-open alert of the same (ip, type) younger than
          `cooldown_minutes` suppresses a new one outright.

        Returns the alert_id when a row was created, otherwise None.
        """
        if severity not in config.SEVERITY_ORDER:
            raise StorageError(f"invalid severity '{severity}'")

        cooldown = config.ALERT_COOLDOWN_MINUTES if cooldown_minutes is None else cooldown_minutes
        key = dedupe_key or f"{alert_type}|{attacker_ip}|{session_id or ''}|{timestamp or utc_now()}"
        alert_id = str(uuid.uuid5(UUID_NAMESPACE, key))

        if cooldown > 0:
            recent = self.query_one(
                """
                SELECT alert_id FROM alerts
                 WHERE attacker_ip = :ip
                   AND alert_type  = :type
                   AND status      = 'open'
                   AND (julianday('now') - julianday(timestamp)) * 1440.0 < :cooldown
                 LIMIT 1
                """,
                {"ip": attacker_ip, "type": alert_type, "cooldown": cooldown},
            )
            if recent:
                return None

        with self.transaction() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO alerts
                    (alert_id, attacker_ip, session_id, alert_type,
                     severity, timestamp, description, status)
                VALUES (:alert_id, :ip, :session_id, :type,
                        :severity, :timestamp, :description, 'open')
                """,
                {
                    "alert_id": alert_id,
                    "ip": attacker_ip,
                    "session_id": session_id,
                    "type": alert_type,
                    "severity": severity,
                    "timestamp": timestamp or utc_now(),
                    "description": description,
                },
            )
            return alert_id if cur.rowcount else None

    def set_alert_status(self, alert_id: str, status: str) -> bool:
        """Acknowledge or close an alert. Part 5's alert buttons call this."""
        if status not in ("open", "acknowledged", "closed"):
            raise StorageError(f"invalid alert status '{status}'")
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id)
            )
            return cur.rowcount > 0

    def get_alerts(
        self,
        status: str | Sequence[str] = None,
        severity: str | Sequence[str] = None,
        min_severity: str = None,
        since: str = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Alerts joined to whatever enrichment exists, newest first."""
        clauses, params = [], {}

        for column, value in (("a.status", status), ("a.severity", severity)):
            if value:
                values = [value] if isinstance(value, str) else list(value)
                names = [f"{column.replace('.', '_')}_{i}" for i in range(len(values))]
                clauses.append(f"{column} IN ({', '.join(':' + n for n in names)})")
                params.update(dict(zip(names, values)))

        if min_severity:
            allowed = [
                s
                for s, rank in config.SEVERITY_ORDER.items()
                if rank >= config.SEVERITY_ORDER[min_severity]
            ]
            names = [f"minsev_{i}" for i in range(len(allowed))]
            clauses.append(f"a.severity IN ({', '.join(':' + n for n in names)})")
            params.update(dict(zip(names, allowed)))

        if since:
            clauses.append("a.timestamp >= :since")
            params["since"] = since

        params["limit"] = limit
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        return self.query(
            f"""
            SELECT a.*,
                   r.country, r.city, r.latitude, r.longitude,
                   r.abuse_score, r.profile_score, r.source AS reputation_source
              FROM alerts a
              LEFT JOIN reputation r ON r.attacker_ip = a.attacker_ip
              {where}
             ORDER BY a.timestamp DESC
             LIMIT :limit
            """,
            params,
        )

    # =====================================================================
    # READ HELPERS  — Part 5 dashboard
    # =====================================================================

    def get_sessions(self, limit: int = 200, status: str = None) -> List[Dict[str, Any]]:
        """
        Recent sessions, **passwords already masked**.

        Reads `sessions_public`, not `sessions`. Use this everywhere in the
        dashboard: masking then happens in the database, so it survives a
        careless `st.dataframe(...)` or a CSV download button.
        """
        where = "WHERE status = :status" if status else ""
        return self.query(
            f"""
            SELECT s.*, r.country, r.city
              FROM sessions_public s
              LEFT JOIN reputation r ON r.attacker_ip = s.attacker_ip
              {where}
             ORDER BY s.start_time DESC
             LIMIT :limit
            """,
            {"limit": limit, "status": status} if status else {"limit": limit},
        )

    def get_session_commands(self, session_id: str) -> List[Dict[str, Any]]:
        """The command timeline for one session, oldest first."""
        return self.query(
            "SELECT * FROM commands WHERE session_id = ? ORDER BY timestamp ASC", (session_id,)
        )

    def get_top_attackers(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self.query(
            """
            SELECT s.*, r.country, r.city, r.latitude, r.longitude,
                   r.abuse_score, r.profile_score
              FROM attacker_summary s
              LEFT JOIN reputation r ON r.attacker_ip = s.attacker_ip
             ORDER BY s.event_count DESC
             LIMIT ?
            """,
            (limit,),
        )

    def get_top_credentials(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Most-tried usernames. Deliberately usernames only.

        Aggregate password statistics are a legitimate honeypot research output,
        but the baseline forbids passwords leaving local storage, so the counts
        below stop at the username.
        """
        return self.query(
            """
            SELECT json_extract(details, '$.username') AS username,
                   COUNT(*)                            AS attempts,
                   COUNT(DISTINCT attacker_ip)         AS distinct_ips
              FROM events
             WHERE event_type IN ('login_attempt', 'login_success')
               AND json_extract(details, '$.username') IS NOT NULL
             GROUP BY username
             ORDER BY attempts DESC
             LIMIT ?
            """,
            (limit,),
        )

    def get_overview_stats(self) -> Dict[str, Any]:
        """Headline numbers for the dashboard, and for the final report."""
        stats = self.query_one(
            """
            SELECT (SELECT COUNT(*) FROM events)                                AS total_events,
                   (SELECT COUNT(*) FROM events
                     WHERE timestamp >= datetime('now', '-1 hour'))             AS events_last_hour,
                   (SELECT COUNT(DISTINCT attacker_ip) FROM events)             AS unique_attackers,
                   (SELECT COUNT(*) FROM sessions)                              AS total_sessions,
                   (SELECT COUNT(*) FROM sessions WHERE status = 'active')      AS active_sessions,
                   (SELECT COUNT(*) FROM nodes WHERE status = 'online')         AS nodes_online,
                   (SELECT COUNT(*) FROM nodes)                                 AS nodes_total,
                   (SELECT COUNT(*) FROM alerts WHERE status = 'open')          AS open_alerts,
                   (SELECT COUNT(*) FROM alerts
                     WHERE status = 'open' AND severity = 'high')               AS open_high_alerts,
                   (SELECT COUNT(*) FROM reputation)                            AS enriched_ips
            """
        )
        lag = self.query_one(
            """
            SELECT AVG((julianday(received_at) - julianday(timestamp)) * 86400.0) AS avg_ingest_lag_s
              FROM (SELECT timestamp, received_at FROM events
                     ORDER BY received_at DESC LIMIT 500)
            """
        )
        stats["avg_ingest_lag_seconds"] = round(lag["avg_ingest_lag_s"] or 0.0, 2)
        return stats

    def get_feed_indicators(self, min_severity: str = None) -> List[Dict[str, Any]]:
        """
        One enriched row per attacker IP that currently has a publishable alert.

        This is the join the exporter publishes; keeping it here means the
        dashboard's "what would we publish?" preview and the actual feed can
        never diverge.
        """
        min_sev = min_severity or config.FEED_MIN_SEVERITY
        allowed = [
            s
            for s, rank in config.SEVERITY_ORDER.items()
            if rank >= config.SEVERITY_ORDER[min_sev]
        ]
        sev_names = [f"sev_{i}" for i in range(len(allowed))]
        status_names = [f"st_{i}" for i in range(len(config.FEED_STATUSES))]

        params = dict(zip(sev_names, allowed))
        params.update(dict(zip(status_names, config.FEED_STATUSES)))

        return self.query(
            f"""
            SELECT a.attacker_ip,
                   sm.first_seen, sm.last_seen,
                   sm.event_count, sm.session_count, sm.node_count,
                   sm.login_attempts, sm.command_count, sm.download_count,
                   r.country, r.city, r.latitude, r.longitude,
                   r.abuse_score, r.profile_score, r.source AS reputation_source,
                   COUNT(a.alert_id)                    AS alert_count,
                   GROUP_CONCAT(DISTINCT a.alert_type)  AS alert_types,
                   MAX(CASE a.severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2
                                       ELSE 1 END)      AS severity_rank,
                   MAX(a.timestamp)                     AS latest_alert
              FROM alerts a
              LEFT JOIN reputation r       ON r.attacker_ip  = a.attacker_ip
              LEFT JOIN attacker_summary sm ON sm.attacker_ip = a.attacker_ip
             WHERE a.severity IN ({', '.join(':' + n for n in sev_names)})
               AND a.status   IN ({', '.join(':' + n for n in status_names)})
             GROUP BY a.attacker_ip
             ORDER BY severity_rank DESC, alert_count DESC
            """,
            params,
        )


# --------------------------------------------------------------------------
# Module-level conveniences
# --------------------------------------------------------------------------

_default: Optional[Database] = None


def get_db(read_only: bool = False) -> Database:
    """Process-wide default handle. Part 5 should pass ``read_only=True``."""
    global _default
    if read_only:
        return Database(read_only=True)
    if _default is None:
        _default = Database()
    return _default


def init_db(path: Path | str = None) -> Database:
    """Create the database file and schema, then hand back the handle."""
    db = Database(path=path) if path else get_db()
    db.initialize_schema()
    return db


#: RFC 5737 / RFC 3849 documentation ranges. Every example IP in the baseline
#: document — and therefore every IP in the team's shared fixtures — lives here.
DOCUMENTATION_NETWORKS = (
    "192.0.2.0/24",      # TEST-NET-1
    "198.51.100.0/24",   # TEST-NET-2
    "203.0.113.0/24",    # TEST-NET-3
    "2001:db8::/32",
)


def is_documentation_ip(value: str) -> bool:
    """True for the RFC 5737 / RFC 3849 documentation ranges."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(net) for net in DOCUMENTATION_NETWORKS)


def _is_private_ip(value: str) -> bool:
    """
    True for addresses that no external lookup can say anything useful about.

    A trap worth knowing about: Python's ``ipaddress`` reports the RFC 5737
    documentation ranges as ``is_private``. The baseline document uses
    203.0.113.10 as its canonical example, so a naive ``is_private`` filter would
    silently skip *every IP in the team's fixture data* and Part 3 could never be
    tested end to end. Documentation ranges are therefore treated as enrichable —
    GeoIP simply returns nulls for them, which is the correct answer.
    """
    import ipaddress

    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return True  # unparseable is not worth an API call either

    if is_documentation_ip(value):
        return False

    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


def load_jsonl(path: Path | str) -> List[Dict[str, Any]]:
    """Read a `.jsonl` fixture file (also the format of `pending_events.jsonl`)."""
    events: List[Dict[str, Any]] = []
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            log.warning("%s:%s is not valid JSON (%s)", path, line_no, exc)
    return events
