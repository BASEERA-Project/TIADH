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
Part 5 (dashboard)   Database(read_only=True) + the "DASHBOARD API" section at
                     the bottom of this class: search_attackers(),
                     search_sessions(), search_alerts(), get_session_events(),
                     get_node_statistics(), get_dashboard_overview() and
                     friends. Part 5 writes no SQL of its own and does not
                     import sqlite3 — every screen it renders is one of these
                     calls, so the schema stops at this file.
                     ALWAYS read sessions through get_sessions() or
                     search_sessions() — both select from the masked
                     `sessions_public` view.

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
from common.db.validation import normalize_event, utc_ago, utc_now, validate_event

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


    # =====================================================================
    # DASHBOARD API  — Part 5
    #
    # Part 5 renders screens; it does not know what SQLite is. Every search,
    # filter, rollup and count it needs is a method below, so table names,
    # view names, JSON extraction and SQLite's date functions never leave this
    # module. Change a column here and the dashboard keeps working; there is no
    # second copy of the schema in a template or a view function.
    #
    # Three rules hold throughout this section:
    #
    # * **Sessions come from `sessions_public`.** Never the raw table.
    # * **Passwords are never selected.** The transcript query asks whether a
    #   password was submitted and returns a boolean, so a plaintext credential
    #   is not merely masked on screen — it is never read into the process.
    # * **Sort keys are whitelisted here.** Callers pass a key like "score";
    #   the SQL it maps to is private. A caller cannot supply an ORDER BY.
    #
    # Time windows are passed as canonical v1.3 timestamps — build them with
    # `validation.utc_ago(hours=24)` rather than with SQLite's datetime('now').
    # =====================================================================

    #: Sort key -> ORDER BY. Callers may only name a key.
    _ATTACKER_SORTS = {
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
    _SESSION_SORTS = {
        "start_time": "s.start_time DESC",
        "duration": "duration_seconds DESC",
        "events": "event_count DESC",
        "commands": "command_count DESC",
        "logins": "login_attempts DESC",
        "ip": "s.attacker_ip ASC",
        "node": "s.node_id ASC, s.start_time DESC",
    }
    _ALERT_SORTS = {
        "timestamp": "a.timestamp DESC",
        "severity": ("CASE a.severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
                     "ELSE 1 END DESC, a.timestamp DESC"),
        "type": "a.alert_type ASC, a.timestamp DESC",
        "ip": "a.attacker_ip ASC, a.timestamp DESC",
        "status": "a.status ASC, a.timestamp DESC",
    }

    ATTACKER_SORT_KEYS = tuple(_ATTACKER_SORTS)
    SESSION_SORT_KEYS = tuple(_SESSION_SORTS)
    ALERT_SORT_KEYS = tuple(_ALERT_SORTS)

    @staticmethod
    def _order_by(sorts: Dict[str, str], key: Optional[str], default: str) -> str:
        return sorts.get(key or default, sorts[default])

    # -- overview ---------------------------------------------------------

    def get_dashboard_overview(self, window_hours: int = 24) -> Dict[str, Any]:
        """
        Headline counters for the Overview screen, in one round trip.

        Deliberately separate from :meth:`get_overview_stats`, which the CLI
        uses and which compares stored timestamps against SQLite's
        ``datetime('now')`` — a comparison the ISO 'T' separator wins, turning
        "the last hour" into "since midnight". Every window here is a bound
        canonical timestamp, so the numbers mean what their labels say.
        """
        params = {
            "hour": utc_ago(hours=1),
            "window": utc_ago(hours=window_hours),
        }
        stats = self.query_one(
            """
            SELECT (SELECT COUNT(*) FROM events)                            AS total_events,
                   (SELECT COUNT(*) FROM events WHERE timestamp >= :hour)   AS events_last_hour,
                   (SELECT COUNT(*) FROM events WHERE timestamp >= :window) AS events_in_window,
                   (SELECT COUNT(*) FROM events
                     WHERE timestamp >= :window AND event_type != 'heartbeat')
                                                                            AS attacks_in_window,
                   (SELECT COUNT(DISTINCT attacker_ip) FROM events)         AS unique_attackers,
                   (SELECT COUNT(DISTINCT attacker_ip) FROM events
                     WHERE timestamp >= :window)                            AS attackers_in_window,
                   (SELECT COUNT(*) FROM sessions_public)                   AS total_sessions,
                   (SELECT COUNT(*) FROM sessions_public
                     WHERE status = 'active')                               AS active_sessions,
                   (SELECT COUNT(*) FROM sessions_public
                     WHERE start_time >= :window)                           AS sessions_in_window,
                   (SELECT COUNT(*) FROM nodes WHERE status = 'online')     AS nodes_online,
                   (SELECT COUNT(*) FROM nodes)                             AS nodes_total,
                   (SELECT COUNT(*) FROM alerts WHERE status = 'open')      AS open_alerts,
                   (SELECT COUNT(*) FROM alerts
                     WHERE status = 'open' AND severity = 'high')           AS open_high_alerts,
                   (SELECT COUNT(*) FROM alerts WHERE timestamp >= :window) AS alerts_in_window,
                   (SELECT COUNT(*) FROM reputation)                        AS enriched_ips,
                   (SELECT MAX(timestamp) FROM events)                      AS latest_event
            """,
            params,
        ) or {}

        lag = self.query_one(
            """
            SELECT AVG((julianday(received_at) - julianday(timestamp)) * 86400.0) AS lag
              FROM (SELECT timestamp, received_at FROM events
                     ORDER BY received_at DESC LIMIT 500)
            """
        )
        stats["avg_ingest_lag_seconds"] = round((lag or {}).get("lag") or 0.0, 2)
        stats["nodes_stale"] = max(
            0, (stats.get("nodes_total") or 0) - (stats.get("nodes_online") or 0)
        )
        stats["window_hours"] = window_hours
        return stats

    def get_event_activity(self, since: str, by: str = "hour") -> List[Dict[str, Any]]:
        """
        Event counts bucketed by hour or day, oldest first.

        Buckets on a prefix of the timestamp string: because every stored
        timestamp is normalised to the same width, the first 13 characters are
        exactly an hour key and the first 10 exactly a day key, which keeps the
        whole rollup on the timestamp index.
        """
        width = {"hour": 13, "day": 10}.get(by)
        if width is None:
            raise StorageError(f"unknown bucket '{by}' (use 'hour' or 'day')")

        return self.query(
            f"""
            SELECT substr(timestamp, 1, {width}) AS bucket,
                   COUNT(*)                      AS total,
                   SUM(CASE WHEN event_type != 'heartbeat' THEN 1 ELSE 0 END) AS attacks,
                   SUM(CASE WHEN event_type = 'login_attempt' THEN 1 ELSE 0 END) AS logins,
                   SUM(CASE WHEN event_type = 'command' THEN 1 ELSE 0 END) AS commands,
                   COUNT(DISTINCT attacker_ip)   AS ips
              FROM events
             WHERE timestamp >= :since
             GROUP BY bucket
             ORDER BY bucket
            """,
            {"since": since},
        )

    def get_event_type_counts(self, since: str = None) -> List[Dict[str, Any]]:
        where = "WHERE timestamp >= :since" if since else ""
        return self.query(
            f"SELECT event_type, COUNT(*) AS n FROM events {where} "
            f"GROUP BY event_type ORDER BY n DESC",
            {"since": since} if since else {},
        )

    def get_top_commands(self, limit: int = 10, since: str = None) -> List[Dict[str, Any]]:
        clause = "AND timestamp >= :since" if since else ""
        params: Dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        return self.query(
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

    def get_top_countries(self, limit: int = 8) -> List[Dict[str, Any]]:
        return self.query(
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

    def get_alert_severity_counts(self, status: str = None) -> Dict[str, int]:
        where = "WHERE status = :status" if status else ""
        rows = self.query(
            f"SELECT severity, COUNT(*) AS n FROM alerts {where} GROUP BY severity",
            {"status": status} if status else {},
        )
        counts = {name: 0 for name in config.SEVERITY_ORDER}
        counts.update({row["severity"]: row["n"] for row in rows})
        return counts

    def get_alert_status_counts(self) -> Dict[str, int]:
        rows = self.query("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status")
        counts = {"open": 0, "acknowledged": 0, "closed": 0}
        counts.update({row["status"]: row["n"] for row in rows})
        return counts

    def get_alert_type_stats(self, since: str = None) -> Dict[str, Dict[str, Any]]:
        """Per-rule alert counts, keyed by alert_type."""
        where = "WHERE timestamp >= :since" if since else ""
        rows = self.query(
            f"""
            SELECT alert_type,
                   COUNT(*) AS total,
                   SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END)   AS open_count,
                   SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high_count,
                   COUNT(DISTINCT attacker_ip)                        AS distinct_ips,
                   MAX(timestamp)                                     AS last_fired
              FROM alerts {where}
             GROUP BY alert_type
            """,
            {"since": since} if since else {},
        )
        return {row["alert_type"]: row for row in rows}

    # -- attackers --------------------------------------------------------

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
                       COUNT(*)                                           AS alert_count,
                       SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high_alerts,
                       SUM(CASE WHEN status = 'open'   THEN 1 ELSE 0 END) AS open_alerts
                  FROM alerts GROUP BY attacker_ip
          ) al ON al.attacker_ip = s.attacker_ip
    """

    @staticmethod
    def _attacker_where(filters: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """
        Build the WHERE for :meth:`search_attackers`.

        Accepted keys: q, country, node, min_score, since, enriched
        ('yes'/'no'), and the flags alerts_only, high_only, breached_only.
        Anything else is ignored — a caller cannot inject a clause.
        """
        clauses: List[str] = []
        params: Dict[str, Any] = {}

        search = (filters.get("q") or "").strip()
        if search:
            clauses.append("(s.attacker_ip LIKE :q OR r.country LIKE :q OR r.city LIKE :q)")
            params["q"] = f"%{search}%"

        country = (filters.get("country") or "").strip()
        if country:
            clauses.append("r.country = :country")
            params["country"] = country

        if filters.get("min_score"):
            clauses.append(
                "MAX(COALESCE(r.abuse_score, 0), COALESCE(r.profile_score, 0)) >= :min_score"
            )
            params["min_score"] = int(filters["min_score"])

        if filters.get("alerts_only"):
            clauses.append("COALESCE(al.alert_count, 0) > 0")
        if filters.get("high_only"):
            clauses.append("COALESCE(al.high_alerts, 0) > 0")
        if filters.get("breached_only"):
            clauses.append("s.login_successes > 0")

        enriched = filters.get("enriched")
        if enriched == "yes":
            clauses.append("r.attacker_ip IS NOT NULL")
        elif enriched == "no":
            clauses.append("r.attacker_ip IS NULL")

        if filters.get("since"):
            clauses.append("s.last_seen >= :since")
            params["since"] = filters["since"]

        node = (filters.get("node") or "").strip()
        if node:
            clauses.append(
                "EXISTS (SELECT 1 FROM events e "
                "WHERE e.attacker_ip = s.attacker_ip AND e.node_id = :node)"
            )
            params["node"] = node

        return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params

    def search_attackers(
        self,
        filters: Dict[str, Any] = None,
        sort: str = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Attackers matching `filters`, as ``(rows, total_matching)``.

        `sort` names a key from :attr:`ATTACKER_SORT_KEYS`; an unknown key falls
        back to the default rather than raising, so a stale bookmark still
        renders a page.
        """
        where, params = self._attacker_where(filters or {})
        order = self._order_by(self._ATTACKER_SORTS, sort, "last_seen")

        total = (self.query_one(
            f"SELECT COUNT(*) AS n FROM ({self._ATTACKER_SELECT} {where})", params
        ) or {}).get("n") or 0

        rows = self.query(
            f"{self._ATTACKER_SELECT} {where} ORDER BY {order} LIMIT :limit OFFSET :offset",
            {**params, "limit": limit, "offset": offset},
        )
        return rows, total

    def get_attacker(self, attacker_ip: str) -> Optional[Dict[str, Any]]:
        """The same row shape :meth:`search_attackers` returns, for one IP."""
        return self.query_one(
            f"{self._ATTACKER_SELECT} WHERE s.attacker_ip = :ip", {"ip": attacker_ip}
        )

    def get_attacker_sessions(self, attacker_ip: str, limit: int = 25) -> List[Dict[str, Any]]:
        return self.query(
            """
            SELECT s.session_id, s.node_id, s.protocol, s.username, s.password,
                   s.start_time, s.end_time, s.status,
                   COALESCE(e.event_count, 0)     AS event_count,
                   COALESCE(e.command_count, 0)   AS command_count,
                   COALESCE(e.login_attempts, 0)  AS login_attempts,
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
            {"ip": attacker_ip, "limit": limit},
        )

    def get_alerts_for_ip(self, attacker_ip: str, limit: int = 50) -> List[Dict[str, Any]]:
        return self.query(
            """
            SELECT alert_id, attacker_ip, session_id, alert_type, severity,
                   timestamp, description, status
              FROM alerts
             WHERE attacker_ip = :ip
             ORDER BY timestamp DESC
             LIMIT :limit
            """,
            {"ip": attacker_ip, "limit": limit},
        )

    def get_attacker_commands(self, attacker_ip: str, limit: int = 25) -> List[Dict[str, Any]]:
        return self.query(
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
            {"ip": attacker_ip, "limit": limit},
        )

    def get_attacker_usernames(self, attacker_ip: str, limit: int = 15) -> List[Dict[str, Any]]:
        """
        Usernames one IP tried, with how often each was accepted.

        Usernames only. Aggregate password statistics are a legitimate research
        output but the baseline keeps attempted passwords in local storage, so
        the counts stop at the username — see :meth:`get_top_credentials`.
        """
        return self.query(
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
            {"ip": attacker_ip, "limit": limit},
        )

    def get_attacker_nodes(self, attacker_ip: str) -> List[Dict[str, Any]]:
        return self.query(
            """
            SELECT node_id, COUNT(*) AS events,
                   MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
              FROM events
             WHERE attacker_ip = :ip
             GROUP BY node_id
             ORDER BY events DESC
            """,
            {"ip": attacker_ip},
        )

    def get_attacker_events(self, attacker_ip: str, limit: int = 200) -> List[Dict[str, Any]]:
        """Recent raw events for one IP. Passwords are not among the columns."""
        return self.query(
            """
            SELECT event_id, node_id, session_id, event_type, timestamp, protocol,
                   json_extract(details, '$.username')     AS username,
                   json_extract(details, '$.command')      AS command,
                   json_extract(details, '$.file_name')    AS file_name,
                   json_extract(details, '$.download_url') AS download_url,
                   json_extract(details, '$.status')       AS status
              FROM events
             WHERE attacker_ip = :ip
             ORDER BY timestamp DESC
             LIMIT :limit
            """,
            {"ip": attacker_ip, "limit": limit},
        )

    def get_attacker_activity(self, attacker_ip: str, since: str) -> List[Dict[str, Any]]:
        return self.query(
            """
            SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS n
              FROM events
             WHERE attacker_ip = :ip AND timestamp >= :since
             GROUP BY day ORDER BY day
            """,
            {"ip": attacker_ip, "since": since},
        )

    # -- sessions ---------------------------------------------------------

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
                    THEN CAST((julianday(s.end_time) - julianday(s.start_time)) * 86400.0
                              AS INTEGER)
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

    @staticmethod
    def _session_where(filters: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Accepted keys: q, status, node, protocol, ip, since, breached_only,
        commands_only. Anything else is ignored."""
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

        if filters.get("since"):
            clauses.append("s.start_time >= :since")
            params["since"] = filters["since"]

        return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params

    def search_sessions(
        self,
        filters: Dict[str, Any] = None,
        sort: str = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Sessions matching `filters`, as ``(rows, total)``. Passwords masked."""
        where, params = self._session_where(filters or {})
        order = self._order_by(self._SESSION_SORTS, sort, "start_time")

        total = (self.query_one(
            f"SELECT COUNT(*) AS n FROM ({self._SESSION_SELECT} {where})", params
        ) or {}).get("n") or 0

        rows = self.query(
            f"{self._SESSION_SELECT} {where} ORDER BY {order} LIMIT :limit OFFSET :offset",
            {**params, "limit": limit, "offset": offset},
        )
        return rows, total

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.query_one(
            f"{self._SESSION_SELECT} WHERE s.session_id = :sid", {"sid": session_id}
        )

    def get_session_events(self, session_id: str) -> List[Dict[str, Any]]:
        """
        Every event in one session, oldest first, shaped for a transcript.

        ``had_password`` is a boolean, not a value: this asks whether a password
        was submitted and never selects what it was. A renderer can therefore
        print the mask from a fact rather than from a string it is trusting
        itself to remember to hide. `sessions_public` protects the `sessions`
        copy of a credential; this protects the `events.details` copy.
        """
        return self.query(
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

    def get_alerts_for_session(self, session_id: str) -> List[Dict[str, Any]]:
        return self.query(
            "SELECT alert_id, alert_type, severity, timestamp, description, status "
            "FROM alerts WHERE session_id = :sid ORDER BY timestamp ASC",
            {"sid": session_id},
        )

    def get_session_ids_for_ip(self, attacker_ip: str) -> List[str]:
        """Session ids from one IP, newest first — for walking its history."""
        rows = self.query(
            "SELECT session_id FROM sessions_public WHERE attacker_ip = :ip "
            "ORDER BY start_time DESC",
            {"ip": attacker_ip},
        )
        return [row["session_id"] for row in rows]

    # -- alerts -----------------------------------------------------------

    _ALERT_SELECT = """
        SELECT a.alert_id, a.attacker_ip, a.session_id, a.alert_type,
               a.severity, a.timestamp, a.description, a.status,
               r.country, r.city, r.abuse_score, r.profile_score
          FROM alerts a
          LEFT JOIN reputation r ON r.attacker_ip = a.attacker_ip
    """

    @staticmethod
    def _alert_where(filters: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Accepted keys: q, status, severity, min_severity, type, ip, session,
        since. Anything else is ignored."""
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
                name for name, rank in config.SEVERITY_ORDER.items()
                if rank >= config.SEVERITY_ORDER[min_severity]
            ]
            names = [f"minsev_{i}" for i in range(len(allowed))]
            clauses.append(f"a.severity IN ({', '.join(':' + n for n in names)})")
            params.update(dict(zip(names, allowed)))

        if filters.get("since"):
            clauses.append("a.timestamp >= :since")
            params["since"] = filters["since"]

        return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params

    def search_alerts(
        self,
        filters: Dict[str, Any] = None,
        sort: str = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Alerts matching `filters`, as ``(rows, total)``.

        The filtering counterpart to :meth:`get_alerts`, which stays as the
        simple "give me the newest N" call the exporter and the CLI use.
        """
        where, params = self._alert_where(filters or {})
        order = self._order_by(self._ALERT_SORTS, sort, "timestamp")

        total = (self.query_one(
            f"SELECT COUNT(*) AS n FROM ({self._ALERT_SELECT} {where})", params
        ) or {}).get("n") or 0

        rows = self.query(
            f"{self._ALERT_SELECT} {where} ORDER BY {order} LIMIT :limit OFFSET :offset",
            {**params, "limit": limit, "offset": offset},
        )
        return rows, total

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        return self.query_one(f"{self._ALERT_SELECT} WHERE a.alert_id = :id", {"id": alert_id})

    # -- nodes ------------------------------------------------------------

    def get_node_statistics(self, since: str = None) -> List[Dict[str, Any]]:
        """
        Every node with its traffic, lag and recent-window counters.

        The registry row (`nodes`) merged with what the event stream says about
        it. The *verdict* — how many missed heartbeats counts as degraded — is a
        policy decision and stays with the caller; this reports measurements.

        Spool depth is not here because it cannot be: `pending_events.jsonl`
        lives on the node and is not part of the v1.3 contract. Ingest lag
        (`received_at - timestamp`) is what a draining spool looks like from
        the collector's side, and it is measured rather than estimated.
        """
        stats = {
            row["node_id"]: row
            for row in self.query(
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

        recent: Dict[str, Dict[str, Any]] = {}
        alerts: Dict[str, int] = {}
        if since:
            recent = {
                row["node_id"]: row
                for row in self.query(
                    """
                    SELECT node_id,
                           COUNT(*) AS events_recent,
                           SUM(CASE WHEN event_type != 'heartbeat' THEN 1 ELSE 0 END)
                                    AS attacks_recent,
                           SUM(CASE WHEN event_type = 'heartbeat' THEN 1 ELSE 0 END)
                                    AS heartbeats_recent
                      FROM events WHERE timestamp >= :since GROUP BY node_id
                    """,
                    {"since": since},
                )
            }
            alerts = {
                row["node_id"]: row["n"]
                for row in self.query(
                    """
                    SELECT e.node_id, COUNT(DISTINCT a.alert_id) AS n
                      FROM alerts a
                      JOIN events e ON e.session_id = a.session_id
                     WHERE a.session_id IS NOT NULL AND a.timestamp >= :since
                     GROUP BY e.node_id
                    """,
                    {"since": since},
                )
            }

        nodes = []
        for node in self.get_nodes():
            node_id = node["node_id"]
            node.update(stats.get(node_id, {}))
            node.update(recent.get(node_id, {}))
            node["alerts_recent"] = alerts.get(node_id, 0)
            for key in ("events_total", "sessions_total", "attackers_total",
                        "events_recent", "attacks_recent", "heartbeats_recent"):
                node.setdefault(key, 0)
            nodes.append(node)
        return nodes

    def get_node_activity(self, node_id: str, since: str) -> List[Dict[str, Any]]:
        return self.query(
            """
            SELECT substr(timestamp, 1, 13) AS bucket, COUNT(*) AS n
              FROM events
             WHERE node_id = :node AND timestamp >= :since
             GROUP BY bucket ORDER BY bucket
            """,
            {"node": node_id, "since": since},
        )

    # -- filter vocabularies ----------------------------------------------

    def get_countries(self) -> List[str]:
        rows = self.query(
            "SELECT DISTINCT country FROM reputation "
            "WHERE country IS NOT NULL AND country != '' ORDER BY country"
        )
        return [row["country"] for row in rows]

    def get_protocols(self) -> List[str]:
        rows = self.query(
            "SELECT DISTINCT protocol FROM sessions_public "
            "WHERE protocol IS NOT NULL ORDER BY protocol"
        )
        return [row["protocol"] for row in rows]

    def get_alert_types(self) -> List[str]:
        rows = self.query("SELECT DISTINCT alert_type FROM alerts ORDER BY alert_type")
        return [row["alert_type"] for row in rows]

    def get_node_ids(self) -> List[str]:
        return [row["node_id"] for row in self.get_nodes()]

    # -- introspection ----------------------------------------------------

    def exists(self) -> bool:
        """True when the database file is present. Cheap; touches no connection."""
        return self.path.exists()

    def describe(self) -> Dict[str, Any]:
        """
        What this handle is pointed at and whether it can be read.

        A readiness probe that reports facts rather than raising, so a caller
        can render a useful "here is what I looked for and what I found"
        message instead of a stack trace. Callers never need `sqlite3` for this.
        """
        info: Dict[str, Any] = {
            "path": str(self.path),
            "exists": self.path.exists(),
            "readable": False,
            "read_only": self.read_only,
            "schema_version": None,
            "expected_schema_version": self.schema_user_version(),
            "objects": [],
            "error": None,
        }
        if not info["exists"]:
            info["error"] = "database file not found"
            return info

        try:
            info["schema_version"] = self.current_user_version()
            info["objects"] = [
                row["name"]
                for row in self.query(
                    "SELECT name FROM sqlite_master "
                    "WHERE type IN ('table','view') ORDER BY type, name"
                )
            ]
            info["readable"] = True
        except sqlite3.Error as exc:
            info["error"] = str(exc)
        return info

    # -- fixtures ---------------------------------------------------------

    def rebase_received_at(self, delay_seconds: int = 1, jitter_seconds: int = 4,
                           slow_nodes: Sequence[str] = (), slow_delay_seconds: int = 11
                           ) -> int:
        """
        Rewrite `received_at` to a plausible shipping delay. **Fixtures only.**

        The ingest path stamps `received_at` with the wall clock, which is right
        in production and meaningless for a replayed history: seeding a day of
        traffic in three seconds makes every event look like it arrived up to
        24 hours late, and every ingest-lag figure downstream becomes noise.

        Same class of fixture normalisation as ``validation.rebase_events``, and
        subject to the same rule — never point it at collected data. Returns the
        number of rows rewritten.
        """
        placeholders = ", ".join(f":slow_{i}" for i in range(len(slow_nodes)))
        case = (
            f"CASE WHEN node_id IN ({placeholders}) THEN :slow ELSE :base END"
            if slow_nodes else ":base"
        )
        params: Dict[str, Any] = {
            "base": delay_seconds,
            "slow": slow_delay_seconds,
            "jitter": max(1, jitter_seconds),
        }
        params.update({f"slow_{i}": node for i, node in enumerate(slow_nodes)})

        with self.transaction() as conn:
            cur = conn.execute(
                f"""
                UPDATE events
                   SET received_at = strftime(
                           '%Y-%m-%dT%H:%M:%SZ',
                           julianday(timestamp)
                           + ({case} + (abs(random()) % :jitter)) / 86400.0)
                """,
                params,
            )
            return cur.rowcount


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


def set_db(db: Database) -> Database:
    """
    Install ``db`` as the process-wide handle that ``get_db()`` hands back.

    Only matters when several components share one process: ``core/main.py
    serve`` runs the collector, the enricher and the alert cycle as threads and
    calls this so all three land on the same handle instead of opening three.
    One handle means one ``_write_lock`` — writes queue in memory rather than
    colliding on SQLite's file lock and spending the busy timeout.
    """
    global _default
    _default = db
    return db


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
