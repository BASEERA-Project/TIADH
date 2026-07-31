"""
app/rule_catalog.py — Human-readable descriptions of the detection rules.

The *values* are never copied. Every threshold below is read live from
``common.config`` at render time, so the Alerts screen shows what the engine is
actually using — including any environment override — and being able to point at
the rule that produced a specific alert is a two-second answer rather than a
grep through source.

Prose is the only thing this module owns. If a rule is added to
``common/alerting/rules.py`` without an entry here it still appears on the panel,
labelled as undocumented, rather than silently vanishing.
"""

from __future__ import annotations

from typing import Any, Dict, List

from common import config
from common.alerting.rules import COMMAND_PATTERNS, RULE_REGISTRY


def _threshold(label: str, value: Any, env: str) -> Dict[str, Any]:
    return {"label": label, "value": value, "env": env}


def catalog() -> List[Dict[str, Any]]:
    """Every known rule, in the order an analyst would read them."""
    window = config.ALERT_WINDOW_MINUTES

    described: Dict[str, Dict[str, Any]] = {
        "brute_force": {
            "title": "Brute force",
            "fires_when": (
                f"one IP produces {config.BRUTE_FORCE_THRESHOLD} or more failed "
                f"login attempts within the {window}-minute evaluation window"
            ),
            "severity": (
                f"medium at {config.BRUTE_FORCE_THRESHOLD}, high at "
                f"{config.BRUTE_FORCE_THRESHOLD * 4} (four times the threshold)"
            ),
            "thresholds": [
                _threshold("failed logins", config.BRUTE_FORCE_THRESHOLD,
                           "BRUTE_FORCE_THRESHOLD"),
                _threshold("window (minutes)", window, "ALERT_WINDOW_MINUTES"),
            ],
            "dedupe": "bucketed by window — a continuing attack re-alerts next window",
        },
        "credential_spray": {
            "title": "Credential spraying",
            "fires_when": (
                f"one IP tries {config.CREDENTIAL_SPRAY_THRESHOLD} or more distinct "
                f"usernames within {window} minutes"
            ),
            "severity": "medium",
            "thresholds": [
                _threshold("distinct usernames", config.CREDENTIAL_SPRAY_THRESHOLD,
                           "CREDENTIAL_SPRAY_THRESHOLD"),
                _threshold("window (minutes)", window, "ALERT_WINDOW_MINUTES"),
            ],
            "dedupe": "bucketed by window",
        },
        "high_risk_ip": {
            "title": "High-risk IP",
            "fires_when": (
                f"an enriched IP has an AbuseIPDB score or a local profile score "
                f"of {config.HIGH_RISK_SCORE_THRESHOLD} or above"
            ),
            "severity": "high",
            "thresholds": [
                _threshold("score", config.HIGH_RISK_SCORE_THRESHOLD,
                           "HIGH_RISK_SCORE_THRESHOLD"),
            ],
            "dedupe": "by score band — re-alerts only when the score moves a decile",
        },
        "suspicious_command": {
            "title": "High-risk command",
            "fires_when": (
                f"a command matches one of the {len(COMMAND_PATTERNS)} high-risk "
                "patterns (payload retrieval, execution, persistence, anti-forensics, "
                "reconnaissance)"
            ),
            "severity": "carried by the matched pattern — low, medium or high",
            "thresholds": [
                _threshold("patterns", len(COMMAND_PATTERNS),
                           "common/alerting/rules.py: COMMAND_PATTERNS"),
            ],
            "dedupe": "per event — every distinct command is its own alert, no cooldown",
        },
        "malware_staging": {
            "title": "Malware staging",
            "fires_when": "any file_download event is recorded inside the honeypot",
            "severity": "high, always — nothing legitimate fetches a payload here",
            "thresholds": [_threshold("downloads", 1, "—")],
            "dedupe": "per event, no cooldown",
        },
        "multi_node_scan": {
            "title": "Multi-node scan",
            "fires_when": (
                f"one IP is observed on {config.MULTI_NODE_SCAN_THRESHOLD} or more "
                f"separate sensors within {window} minutes"
            ),
            "severity": f"medium at {config.MULTI_NODE_SCAN_THRESHOLD} nodes, high above",
            "thresholds": [
                _threshold("distinct nodes", config.MULTI_NODE_SCAN_THRESHOLD,
                           "MULTI_NODE_SCAN_THRESHOLD"),
                _threshold("window (minutes)", window, "ALERT_WINDOW_MINUTES"),
            ],
            "dedupe": "bucketed by window and node count",
            "note": "Only a distributed deployment can produce this finding.",
        },
        "post_auth_activity": {
            "title": "Post-authentication activity",
            "fires_when": "a session with a successful login goes on to execute commands",
            "severity": "high — this is the attack that worked",
            "thresholds": [_threshold("commands after login", 1, "—")],
            "dedupe": "per session and command count",
        },
    }

    enabled = set(config.ENABLED_RULES)

    rules = []
    for key in sorted(RULE_REGISTRY):
        entry = described.get(key, {
            "title": key.replace("_", " ").capitalize(),
            "fires_when": "no description registered in the dashboard catalog",
            "severity": "—",
            "thresholds": [],
            "dedupe": "—",
        })
        rules.append({"key": key, "enabled": key in enabled, **entry})

    # Enabled rules first, then alphabetically — the ones that can fire matter most.
    rules.sort(key=lambda r: (not r["enabled"], r["key"]))
    return rules


def global_settings() -> List[Dict[str, Any]]:
    """Engine-wide settings shown above the individual rules."""
    return [
        _threshold("Evaluation window", f"{config.ALERT_WINDOW_MINUTES} min",
                   "ALERT_WINDOW_MINUTES"),
        _threshold("Repeat suppression", f"{config.ALERT_COOLDOWN_MINUTES} min",
                   "ALERT_COOLDOWN_MINUTES"),
        _threshold("Rules enabled", f"{len(config.ENABLED_RULES)}", "ENABLED_RULES"),
        _threshold("Feed floor", config.FEED_MIN_SEVERITY, "FEED_MIN_SEVERITY"),
    ]


def patterns_by_severity() -> Dict[str, List[Dict[str, Any]]]:
    """The command pattern table, grouped so the high-risk ones read first."""
    grouped: Dict[str, List[Dict[str, Any]]] = {"high": [], "medium": [], "low": []}
    for pattern, severity, label in COMMAND_PATTERNS:
        grouped.setdefault(severity, []).append(
            {"pattern": pattern, "severity": severity, "label": label}
        )
    return grouped
