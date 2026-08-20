-- =========================================================================
-- Distributed Honeypot Threat Intelligence Aggregator
-- Central schema — Team Baseline v1.3 (FROZEN)
--
-- Owner: Part 4 (Storage, Alerting & Feed Export)
--
-- Table names, column names and allowed values below are the frozen team
-- contract. Do NOT edit without group agreement — Parts 2, 3 and 5 all read
-- and write these tables directly.
--
-- Everything under "DERIVED OBJECTS" is additive: views and indexes that make
-- the frozen tables usable. Those are safe to change.
-- =========================================================================

-- -------------------------------------------------------------------------
-- nodes — one row per honeypot sensor VM (Part 1)
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS nodes (
    node_id     TEXT PRIMARY KEY,                  -- e.g. 'node-01'
    hostname    TEXT,                              -- node hostname
    location    TEXT,                              -- e.g. 'Lab-VM-1'
    ip_address  TEXT,                              -- node address
    status      TEXT NOT NULL DEFAULT 'offline'
                CHECK (status IN ('online', 'offline')),
    last_seen   TEXT                               -- ISO 8601 UTC
);

-- -------------------------------------------------------------------------
-- sessions — one row per honeypot session, derived from the event stream
-- -------------------------------------------------------------------------
-- The protocol list below is a post-v1.3 amendment, agreed to let the dionaea
-- sensor report more than two of its services. v1.3 allowed ssh, telnet, ftp
-- and smb; everything after 'smb' on that line is new. Nothing else about this
-- table changed, and no existing value stopped being legal.
--
-- SQLite cannot ALTER a CHECK constraint, so a database created before this
-- keeps the old four and rejects the rest. `Database.initialize_schema()`
-- rebuilds the table when it finds that — see `_widen_session_protocols`.
CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT PRIMARY KEY,                  -- namespaced, e.g. 'node-01:a1b2c3d4'
    node_id     TEXT NOT NULL,
    attacker_ip TEXT,
    protocol    TEXT CHECK (protocol IN ('ssh', 'telnet', 'ftp', 'smb',
                                         'http', 'mysql', 'mssql', 'sip',
                                         'tftp', 'upnp', 'mqtt', 'memcache',
                                         'mongo', 'printer', 'pptp', 'epmap')),
    username    TEXT,                              -- last username seen
    password    TEXT,                              -- SENSITIVE: never leaves this table unmasked
    start_time  TEXT,
    end_time    TEXT,
    status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'closed', 'failed')),
    FOREIGN KEY (node_id) REFERENCES nodes (node_id)
);

-- -------------------------------------------------------------------------
-- events — append-only source of truth. Every accepted event lands here.
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    event_id    TEXT PRIMARY KEY,                  -- UUID minted by the node
    node_id     TEXT NOT NULL,
    session_id  TEXT,                              -- NULL only for heartbeat
    event_type  TEXT NOT NULL
                CHECK (event_type IN ('connection', 'login_attempt', 'login_success',
                                      'command', 'file_download', 'session_end',
                                      'heartbeat')),
    timestamp   TEXT NOT NULL,                     -- when it happened, at the node
    attacker_ip TEXT,                              -- NULL only for heartbeat
    protocol    TEXT,                              -- NULL only for heartbeat
    details     TEXT NOT NULL DEFAULT '{}',        -- JSON string, Section 2 contract
    received_at TEXT NOT NULL,                     -- when the collector accepted it
    FOREIGN KEY (node_id) REFERENCES nodes (node_id)
);

-- -------------------------------------------------------------------------
-- reputation — one row per attacker IP (Part 3)
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reputation (
    attacker_ip   TEXT PRIMARY KEY,
    country       TEXT,
    city          TEXT,
    latitude      REAL,
    longitude     REAL,
    abuse_score   INTEGER CHECK (abuse_score IS NULL
                                 OR (abuse_score BETWEEN 0 AND 100)),
    source        TEXT,                            -- comma-joined, e.g. 'GeoLite2,AbuseIPDB'
    profile_score INTEGER NOT NULL DEFAULT 0
                  CHECK (profile_score BETWEEN 0 AND 100),
    last_updated  TEXT
);

-- -------------------------------------------------------------------------
-- alerts — output of the Part 4 rules engine
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    alert_id    TEXT PRIMARY KEY,                  -- deterministic UUIDv5, see alert_engine
    attacker_ip TEXT NOT NULL,
    session_id  TEXT,
    alert_type  TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    timestamp   TEXT NOT NULL,
    description TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open'
                CHECK (status IN ('open', 'acknowledged', 'closed'))
);

-- =========================================================================
-- DERIVED OBJECTS — additive, safe to modify
-- =========================================================================

-- Indexes. Without these the dashboard degrades badly once the events table
-- passes a few hundred thousand rows.
CREATE INDEX IF NOT EXISTS idx_events_ip        ON events (attacker_ip);
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_session   ON events (session_id);
CREATE INDEX IF NOT EXISTS idx_events_type_ts   ON events (event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_node_ts   ON events (node_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_ip      ON sessions (attacker_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_start   ON sessions (start_time);
CREATE INDEX IF NOT EXISTS idx_sessions_status  ON sessions (status);
CREATE INDEX IF NOT EXISTS idx_alerts_status_ts ON alerts (status, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_ip_type   ON alerts (attacker_ip, alert_type);
CREATE INDEX IF NOT EXISTS idx_rep_updated      ON reputation (last_updated);

-- The mentor's original plan called for a `commands` table. Baseline v1.3
-- folded commands into events.details instead, so this view satisfies both
-- documents with zero duplicated storage.
CREATE VIEW IF NOT EXISTS commands AS
SELECT event_id                          AS id,
       session_id                        AS session_id,
       timestamp                         AS timestamp,
       node_id                           AS node_id,
       attacker_ip                       AS attacker_ip,
       json_extract(details, '$.command') AS command_text
FROM events
WHERE event_type = 'command';

-- Masked projection of sessions. Part 5 and the exporter read THIS, never the
-- raw sessions table, so a plaintext password cannot reach a screen or a file
-- even if someone forgets to mask it in application code.
CREATE VIEW IF NOT EXISTS sessions_public AS
SELECT session_id,
       node_id,
       attacker_ip,
       protocol,
       username,
       CASE WHEN password IS NULL OR password = '' THEN NULL
            ELSE '***MASKED***' END AS password,
       start_time,
       end_time,
       status
FROM sessions;

-- Convenience rollup used by the dashboard and the feed exporter.
CREATE VIEW IF NOT EXISTS attacker_summary AS
SELECT e.attacker_ip                                   AS attacker_ip,
       MIN(e.timestamp)                                AS first_seen,
       MAX(e.timestamp)                                AS last_seen,
       COUNT(*)                                        AS event_count,
       COUNT(DISTINCT e.session_id)                    AS session_count,
       COUNT(DISTINCT e.node_id)                       AS node_count,
       SUM(CASE WHEN e.event_type = 'login_attempt'  THEN 1 ELSE 0 END) AS login_attempts,
       SUM(CASE WHEN e.event_type = 'login_success'  THEN 1 ELSE 0 END) AS login_successes,
       SUM(CASE WHEN e.event_type = 'command'        THEN 1 ELSE 0 END) AS command_count,
       SUM(CASE WHEN e.event_type = 'file_download'  THEN 1 ELSE 0 END) AS download_count
FROM events e
WHERE e.attacker_ip IS NOT NULL
GROUP BY e.attacker_ip;
