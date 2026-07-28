"""
app/settings.py — Runtime configuration for the Flask dashboard.

Everything is overridable by environment variable, in the same spirit as
``common/config.py``: nobody should have to edit source to point the dashboard at
a different database or slow the auto-refresh down for a screen recording.

The dashboard deliberately owns *no* detection or storage constants. Thresholds,
severities and feed settings are read live from ``common.config`` so that the
rules panel on the Alerts screen shows the values the engine is actually using,
not a copy that drifted.
"""

from __future__ import annotations

import os
from pathlib import Path

from common import config as core_config

#: dashboard/
BASE_DIR = Path(__file__).resolve().parent.parent

#: repository root (holds common/, core/, nodes/, dashboard/)
REPO_ROOT = BASE_DIR.parent


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class Settings:
    """Flask config object. Uppercase attributes land in ``app.config``."""

    # -- identity ---------------------------------------------------------
    APP_NAME = os.getenv("DASHBOARD_APP_NAME", "TIADH")
    APP_SUBTITLE = os.getenv(
        "DASHBOARD_APP_SUBTITLE", "Distributed Honeypot Threat Intelligence"
    )

    # -- storage ----------------------------------------------------------
    #: Same default as common.config, so the dashboard and the collector agree
    #: without any extra wiring. Point HONEYPOT_DB_PATH at the demo database to
    #: drive the screens from generated data instead.
    DB_PATH = Path(os.getenv("HONEYPOT_DB_PATH", core_config.DB_PATH))

    #: Alert acknowledge/close are the only writes the dashboard performs, and
    #: they go through Database.set_alert_status(). Set to 0 for a strictly
    #: read-only deployment (the buttons then disappear rather than 403).
    ALLOW_ALERT_ACTIONS = _bool("DASHBOARD_ALLOW_ALERT_ACTIONS", True)

    # -- presentation -----------------------------------------------------
    PAGE_SIZE = _int("DASHBOARD_PAGE_SIZE", 50)
    MAX_PAGE_SIZE = 500

    #: Seconds between automatic refreshes. 0 disables it; the header control
    #: overrides it per browser and remembers the choice.
    REFRESH_SECONDS = _int("DASHBOARD_REFRESH_SECONDS", 30)

    #: Hours covered by the activity chart on Overview.
    ACTIVITY_WINDOW_HOURS = _int("DASHBOARD_ACTIVITY_HOURS", 24)

    # -- node health ------------------------------------------------------
    #: Baseline v1.3 heartbeat interval. Node health is expressed in *missed
    #: heartbeats* rather than raw seconds, because that is the number an
    #: assessor can check against the contract.
    HEARTBEAT_INTERVAL_SECONDS = _int("HEARTBEAT_INTERVAL_SECONDS", 60)
    HEARTBEAT_WARN_MISSED = _int("DASHBOARD_HEARTBEAT_WARN_MISSED", 2)
    HEARTBEAT_CRIT_MISSED = _int("DASHBOARD_HEARTBEAT_CRIT_MISSED", 5)

    # -- flask ------------------------------------------------------------
    SECRET_KEY = os.getenv("DASHBOARD_SECRET_KEY") or "dev-only-not-for-production"
    JSON_SORT_KEYS = False
    TEMPLATES_AUTO_RELOAD = _bool("DASHBOARD_TEMPLATE_RELOAD", False)
    #: Local tool serving attacker data — bind to loopback unless told otherwise.
    HOST = os.getenv("DASHBOARD_HOST", "127.0.0.1")
    PORT = _int("DASHBOARD_PORT", 8050)

    @classmethod
    def as_dict(cls) -> dict:
        return {k: getattr(cls, k) for k in dir(cls) if k.isupper()}
