"""
common/alerting/alert_engine.py — Evaluates the rule set and persists what it finds.

Design notes
------------
* **Stateless.** Every pass re-derives its findings from the `events` and
  `reputation` tables over a bounded time window. Nothing is remembered between
  runs, so the engine can crash, be restarted, or be run twice concurrently
  without producing corrupt or duplicated output.
* **Idempotent.** Deduplication is the rules' responsibility via
  ``Finding.dedupe_key``; the storage layer converts that key into a
  deterministic ``alert_id`` and ignores repeat inserts.
* **Isolated failures.** A rule that raises is logged and skipped — one bad
  query must not stop the other six from running.

Run it from the CLI (``python main.py alerts`` in ``core/``), on a timer
(``python main.py watch``), or import it into the collector process.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import timedelta
from typing import Any, Dict, List, Optional

from common import config
from common.alerting.rules import Finding, RULE_REGISTRY
from common.db.database import Database, get_db
from common.db.validation import parse_timestamp, utc_now

log = logging.getLogger(__name__)


class AlertEngine:
    """Runs the enabled detection rules against the central database."""

    def __init__(self, db: Database = None, enabled_rules=None):
        self.db = db or get_db()
        names = list(enabled_rules or config.ENABLED_RULES)

        unknown = [n for n in names if n not in RULE_REGISTRY]
        if unknown:
            log.warning("ignoring unknown rule(s) in configuration: %s", ", ".join(unknown))

        self.rules = {n: RULE_REGISTRY[n] for n in names if n in RULE_REGISTRY}
        if not self.rules:
            log.warning("no rules enabled — the engine will produce nothing")

    # ------------------------------------------------------------------

    def window_start(self, window_minutes: int = None) -> str:
        """
        Lower bound for this pass, as a v1.3 timestamp.

        Derived from the newest event in the database rather than from the wall
        clock. That way a replayed fixture file or an offline node draining its
        `pending_events.jsonl` spool is still evaluated correctly instead of
        being silently skipped for being "too old".
        """
        minutes = config.ALERT_WINDOW_MINUTES if window_minutes is None else window_minutes
        newest = self.db.query_one("SELECT MAX(timestamp) AS ts FROM events")
        anchor = (newest or {}).get("ts") or utc_now()
        return (parse_timestamp(anchor) - timedelta(minutes=minutes)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    def evaluate(self, window_minutes: int = None) -> List[Finding]:
        """Run every enabled rule and return the raw findings, unpersisted."""
        since = self.window_start(window_minutes)
        findings: List[Finding] = []

        for name, rule in self.rules.items():
            try:
                hits = rule(self.db, since)
            except Exception:  # noqa: BLE001 — one broken rule must not stop the rest
                log.exception("rule '%s' failed and was skipped", name)
                continue

            log.debug("rule '%s' produced %d finding(s)", name, len(hits))
            findings.extend(hits)

        # Highest severity first, so that if a cooldown suppresses later inserts
        # the most serious finding is the one that survives.
        findings.sort(
            key=lambda f: (config.SEVERITY_ORDER.get(f.severity, 0), f.timestamp or ""),
            reverse=True,
        )
        return findings

    def persist(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Write findings as alerts, skipping duplicates and cooled-down repeats."""
        created: List[Dict[str, Any]] = []

        for finding in findings:
            alert_id = self.db.insert_alert(
                attacker_ip=finding.attacker_ip,
                alert_type=finding.alert_type,
                severity=finding.severity,
                description=finding.description,
                session_id=finding.session_id,
                timestamp=finding.timestamp or utc_now(),
                dedupe_key=finding.dedupe_key or None,
                # Event-scoped rules already dedupe on the event id, so a
                # cooldown would wrongly hide a second distinct command.
                cooldown_minutes=0
                if finding.alert_type in ("suspicious_command", "malware_staging")
                else None,
            )
            if alert_id:
                record = asdict(finding)
                record["alert_id"] = alert_id
                created.append(record)
                log.info(
                    "ALERT [%s] %s — %s",
                    finding.severity.upper(),
                    finding.alert_type,
                    finding.description,
                )

        return created

    def run_once(self, window_minutes: int = None) -> Dict[str, Any]:
        """One full pass: evaluate, persist, summarise."""
        findings = self.evaluate(window_minutes)
        created = self.persist(findings)

        by_type: Dict[str, int] = {}
        for alert in created:
            by_type[alert["alert_type"]] = by_type.get(alert["alert_type"], 0) + 1

        summary = {
            "evaluated_at": utc_now(),
            "window_minutes": (
                config.ALERT_WINDOW_MINUTES if window_minutes is None else window_minutes
            ),
            "rules_run": list(self.rules),
            "findings": len(findings),
            "alerts_created": len(created),
            "suppressed": len(findings) - len(created),
            "by_type": by_type,
            "alerts": created,
        }
        log.info(
            "alert pass complete: %d finding(s), %d new alert(s), %d suppressed",
            summary["findings"],
            summary["alerts_created"],
            summary["suppressed"],
        )
        return summary

    def run_forever(self, interval_seconds: int = 30, window_minutes: int = None) -> None:
        """Blocking evaluation loop for a long-running deployment."""
        import time

        log.info("alert engine started, evaluating every %ss", interval_seconds)
        while True:
            try:
                self.run_once(window_minutes)
            except Exception:  # noqa: BLE001 — the loop must outlive any single failure
                log.exception("alert pass failed; continuing")
            time.sleep(interval_seconds)


def evaluate_now(db: Database = None, window_minutes: int = None) -> Dict[str, Any]:
    """Convenience wrapper: one alert pass with the default configuration."""
    return AlertEngine(db=db).run_once(window_minutes)
