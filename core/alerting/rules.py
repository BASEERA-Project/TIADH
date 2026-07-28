"""
alerting/rules.py — What counts as suspicious.

Rules are kept separate from the engine so that tuning a threshold, adding a
command pattern or switching a rule off never means touching execution logic.
Each rule is a function ``rule(db, since) -> list[Finding]``; the engine takes
care of ordering, deduplication and persistence.

A Finding is the engine's internal shape, not a database row. `dedupe_key` is
the important field: it must be identical across repeated evaluations of the
same underlying condition, and different when the condition genuinely recurs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from common import config


@dataclass
class Finding:
    """A rule hit, before it becomes an `alerts` row."""

    alert_type: str
    attacker_ip: str
    severity: str
    description: str
    session_id: Optional[str] = None
    timestamp: Optional[str] = None
    dedupe_key: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------
# High-risk command patterns
#
# Matched case-insensitively against the raw command text. Ordered most to least
# severe; the first match wins, so keep destructive patterns at the top.
# --------------------------------------------------------------------------

COMMAND_PATTERNS: List[tuple] = [
    # -- destructive / anti-forensic -----------------------------------------
    (r"\brm\s+-[a-z]*[rf][a-z]*\s+/(?:\s|$)", "high", "recursive delete of filesystem root"),
    (r"\brm\s+-[a-z]*[rf]", "high", "recursive/forced delete"),
    (r"\bhistory\s+-c\b|>\s*\.bash_history", "high", "shell history wiped (anti-forensics)"),
    (r"\b(shred|dd\s+if=/dev/(zero|urandom))\b", "high", "disk wiping utility"),
    # -- payload retrieval ---------------------------------------------------
    (r"\bwget\b", "high", "remote file download via wget"),
    (r"\bcurl\b.*(-O|-o|\|)", "high", "remote file download via curl"),
    (r"\bcurl\b", "medium", "curl invocation"),
    (r"\b(tftp|ftpget|busybox\s+wget)\b", "high", "download via embedded-device tooling"),
    (r"/dev/tcp/", "high", "bash reverse shell primitive"),
    (r"\b(nc|ncat|netcat)\b.*\s-\w*e", "high", "netcat with command execution"),
    # -- payload execution ---------------------------------------------------
    (r"\bchmod\s+[+]?x\b|\bchmod\s+[0-7]*7[0-7]{2}\b", "high", "making a file executable"),
    (r"\bbase64\s+-d\b|\bbase64\s+--decode\b", "high", "base64-encoded payload decoded"),
    (r"\b(perl|python[23]?|php)\s+-e\b", "high", "inline interpreter execution"),
    (r"\|\s*(sh|bash)\b", "high", "piping downloaded content into a shell"),
    # -- persistence / privilege --------------------------------------------
    (r"\b(crontab|systemctl\s+enable|rc\.local)\b", "high", "persistence mechanism"),
    (r"authorized_keys", "high", "SSH key persistence"),
    (r"\b(useradd|adduser|passwd)\b", "high", "account manipulation"),
    (r"\b(chattr|setcap)\b", "medium", "attribute/capability manipulation"),
    # -- reconnaissance ------------------------------------------------------
    (r"\b(uname|whoami|id|hostname)\b", "low", "host reconnaissance"),
    (r"/proc/cpuinfo|/etc/(passwd|shadow)|free\s+-m", "medium", "system/credential enumeration"),
    (r"\b(nmap|masscan)\b", "high", "network scanning from inside the honeypot"),
    (r"\b(apt-get|yum|apk)\s+install\b", "medium", "package installation attempt"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), sev, label) for p, sev, label in COMMAND_PATTERNS]


def classify_command(command: str) -> Optional[tuple]:
    """Return ``(severity, label)`` for the first matching pattern, else None."""
    if not command:
        return None
    for pattern, severity, label in _COMPILED:
        if pattern.search(command):
            return severity, label
    return None


# --------------------------------------------------------------------------
# Rule implementations
# --------------------------------------------------------------------------

def rule_brute_force(db, since: str) -> List[Finding]:
    """Repeated failed logins from a single IP inside the evaluation window."""
    rows = db.query(
        """
        SELECT attacker_ip,
               COUNT(*)                  AS attempts,
               COUNT(DISTINCT node_id)   AS nodes,
               MAX(timestamp)            AS last_ts
          FROM events
         WHERE event_type  = 'login_attempt'
           AND attacker_ip IS NOT NULL
           AND timestamp  >= :since
         GROUP BY attacker_ip
        HAVING attempts >= :threshold
        """,
        {"since": since, "threshold": config.BRUTE_FORCE_THRESHOLD},
    )

    findings = []
    for row in rows:
        severity = "high" if row["attempts"] >= config.BRUTE_FORCE_THRESHOLD * 4 else "medium"
        findings.append(
            Finding(
                alert_type="brute_force",
                attacker_ip=row["attacker_ip"],
                severity=severity,
                timestamp=row["last_ts"],
                description=(
                    f"{row['attempts']} failed login attempts from {row['attacker_ip']} "
                    f"across {row['nodes']} node(s) within "
                    f"{config.ALERT_WINDOW_MINUTES} minutes"
                ),
                # Bucketed by window: an attack continuing into the next window
                # produces a fresh alert, a re-run inside this one does not.
                dedupe_key=f"brute_force|{row['attacker_ip']}|{_bucket(row['last_ts'])}",
                evidence={"attempts": row["attempts"], "nodes": row["nodes"]},
            )
        )
    return findings


def rule_credential_spray(db, since: str) -> List[Finding]:
    """One IP trying many different usernames — breadth rather than depth."""
    rows = db.query(
        """
        SELECT attacker_ip,
               COUNT(DISTINCT json_extract(details, '$.username')) AS usernames,
               MAX(timestamp)                                      AS last_ts
          FROM events
         WHERE event_type IN ('login_attempt', 'login_success')
           AND attacker_ip IS NOT NULL
           AND json_extract(details, '$.username') IS NOT NULL
           AND timestamp >= :since
         GROUP BY attacker_ip
        HAVING usernames >= :threshold
        """,
        {"since": since, "threshold": config.CREDENTIAL_SPRAY_THRESHOLD},
    )
    return [
        Finding(
            alert_type="credential_spray",
            attacker_ip=row["attacker_ip"],
            severity="medium",
            timestamp=row["last_ts"],
            description=(
                f"{row['attacker_ip']} tried {row['usernames']} distinct usernames "
                f"within {config.ALERT_WINDOW_MINUTES} minutes"
            ),
            dedupe_key=f"credential_spray|{row['attacker_ip']}|{_bucket(row['last_ts'])}",
            evidence={"distinct_usernames": row["usernames"]},
        )
        for row in rows
    ]


def rule_high_risk_ip(db, since: str) -> List[Finding]:
    """Reputation or local profiling score crossing the risk threshold."""
    rows = db.query(
        """
        SELECT r.attacker_ip, r.abuse_score, r.profile_score,
               r.country, r.last_updated
          FROM reputation r
         WHERE COALESCE(r.abuse_score, 0)   >= :threshold
            OR COALESCE(r.profile_score, 0) >= :threshold
        """,
        {"threshold": config.HIGH_RISK_SCORE_THRESHOLD},
    )

    findings = []
    for row in rows:
        abuse = row["abuse_score"] or 0
        profile = row["profile_score"] or 0
        drivers = []
        if abuse >= config.HIGH_RISK_SCORE_THRESHOLD:
            drivers.append(f"AbuseIPDB score {abuse}")
        if profile >= config.HIGH_RISK_SCORE_THRESHOLD:
            drivers.append(f"local profile score {profile}")

        findings.append(
            Finding(
                alert_type="high_risk_ip",
                attacker_ip=row["attacker_ip"],
                severity="high",
                timestamp=row["last_updated"],
                description=(
                    f"{row['attacker_ip']}"
                    + (f" ({row['country']})" if row["country"] else "")
                    + " flagged high risk: "
                    + " and ".join(drivers)
                ),
                # Scores move; re-alert only when the rounded score changes band.
                dedupe_key=(
                    f"high_risk_ip|{row['attacker_ip']}|{abuse // 10}|{profile // 10}"
                ),
                evidence={"abuse_score": abuse, "profile_score": profile},
            )
        )
    return findings


def rule_suspicious_command(db, since: str) -> List[Finding]:
    """Commands matching a high-risk pattern (wget, curl, chmod +x, rm -rf, ...)."""
    rows = db.query(
        """
        SELECT event_id, session_id, attacker_ip, node_id, timestamp,
               json_extract(details, '$.command') AS command
          FROM events
         WHERE event_type  = 'command'
           AND attacker_ip IS NOT NULL
           AND timestamp  >= :since
         ORDER BY timestamp ASC
        """,
        {"since": since},
    )

    findings = []
    for row in rows:
        verdict = classify_command(row["command"] or "")
        if not verdict:
            continue
        severity, label = verdict
        # Truncate: attacker-supplied text goes into a description that the
        # dashboard renders, so never let it be unbounded.
        snippet = (row["command"] or "")[:200]
        findings.append(
            Finding(
                alert_type="suspicious_command",
                attacker_ip=row["attacker_ip"],
                session_id=row["session_id"],
                severity=severity,
                timestamp=row["timestamp"],
                description=f"{label} on {row['node_id']}: {snippet}",
                # Scoped to the event: every distinct command is its own hit.
                dedupe_key=f"suspicious_command|{row['event_id']}",
                evidence={"command": snippet, "pattern_label": label},
            )
        )
    return findings


def rule_malware_staging(db, since: str) -> List[Finding]:
    """Any file download inside the honeypot — always worth a high alert."""
    rows = db.query(
        """
        SELECT event_id, session_id, attacker_ip, node_id, timestamp,
               json_extract(details, '$.download_url') AS url,
               json_extract(details, '$.file_hash')    AS file_hash,
               json_extract(details, '$.file_name')    AS file_name
          FROM events
         WHERE event_type  = 'file_download'
           AND attacker_ip IS NOT NULL
           AND timestamp  >= :since
        """,
        {"since": since},
    )
    return [
        Finding(
            alert_type="malware_staging",
            attacker_ip=row["attacker_ip"],
            session_id=row["session_id"],
            severity="high",
            timestamp=row["timestamp"],
            description=(
                f"payload fetched on {row['node_id']}: "
                + (row["file_name"] or row["url"] or row["file_hash"] or "unknown artefact")[:200]
            ),
            dedupe_key=f"malware_staging|{row['event_id']}",
            evidence={
                "download_url": (row["url"] or "")[:400],
                "file_hash": row["file_hash"],
                "file_name": row["file_name"],
            },
        )
        for row in rows
    ]


def rule_multi_node_scan(db, since: str) -> List[Finding]:
    """
    One IP hitting several sensors — the rule that justifies "distributed".

    A single-node deployment can never produce this finding, so it is the
    clearest demonstration in the whole project of what the architecture buys.
    """
    rows = db.query(
        """
        SELECT attacker_ip,
               COUNT(DISTINCT node_id)      AS nodes,
               GROUP_CONCAT(DISTINCT node_id) AS node_list,
               MAX(timestamp)               AS last_ts
          FROM events
         WHERE attacker_ip IS NOT NULL
           AND timestamp >= :since
         GROUP BY attacker_ip
        HAVING nodes >= :threshold
        """,
        {"since": since, "threshold": config.MULTI_NODE_SCAN_THRESHOLD},
    )
    return [
        Finding(
            alert_type="multi_node_scan",
            attacker_ip=row["attacker_ip"],
            severity="medium" if row["nodes"] == 2 else "high",
            timestamp=row["last_ts"],
            description=(
                f"{row['attacker_ip']} observed on {row['nodes']} separate sensors "
                f"({row['node_list']}) — coordinated scanning"
            ),
            dedupe_key=f"multi_node_scan|{row['attacker_ip']}|{row['nodes']}|{_bucket(row['last_ts'])}",
            evidence={"nodes": row["nodes"], "node_list": row["node_list"]},
        )
        for row in rows
    ]


def rule_post_auth_activity(db, since: str) -> List[Finding]:
    """
    A successful login followed by real commands — the attack that worked.

    This is the highest-value finding in the dataset and the one a defensive
    team would act on first.
    """
    rows = db.query(
        """
        SELECT ls.session_id,
               ls.attacker_ip,
               ls.node_id,
               COUNT(c.event_id) AS command_count,
               MAX(c.timestamp)  AS last_ts
          FROM events ls
          JOIN events c
            ON c.session_id = ls.session_id
           AND c.event_type = 'command'
         WHERE ls.event_type  = 'login_success'
           AND ls.attacker_ip IS NOT NULL
           AND c.timestamp   >= :since
         GROUP BY ls.session_id, ls.attacker_ip, ls.node_id
        """,
        {"since": since},
    )
    return [
        Finding(
            alert_type="post_auth_activity",
            attacker_ip=row["attacker_ip"],
            session_id=row["session_id"],
            severity="high",
            timestamp=row["last_ts"],
            description=(
                f"authenticated session {row['session_id']} on {row['node_id']} executed "
                f"{row['command_count']} command(s) after a successful login"
            ),
            dedupe_key=f"post_auth_activity|{row['session_id']}|{row['command_count']}",
            evidence={"command_count": row["command_count"]},
        )
        for row in rows
    ]


#: Registry consulted by the engine. Keys must match config.ENABLED_RULES.
RULE_REGISTRY: Dict[str, Callable] = {
    "brute_force": rule_brute_force,
    "credential_spray": rule_credential_spray,
    "high_risk_ip": rule_high_risk_ip,
    "suspicious_command": rule_suspicious_command,
    "malware_staging": rule_malware_staging,
    "multi_node_scan": rule_multi_node_scan,
    "post_auth_activity": rule_post_auth_activity,
}


def _bucket(timestamp: Optional[str]) -> str:
    """
    Collapse a timestamp onto the evaluation-window grid.

    Two runs of the engine three seconds apart see the same ongoing brute force
    and must produce the same dedupe key; the next window must produce a new one.
    """
    if not timestamp:
        return "nowindow"
    from common.db.validation import parse_timestamp

    moment = parse_timestamp(timestamp)
    minutes = (moment.hour * 60 + moment.minute) // max(config.ALERT_WINDOW_MINUTES, 1)
    return f"{moment.date().isoformat()}#{minutes}"
