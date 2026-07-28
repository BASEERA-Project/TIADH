"""
app/integrations.py — Borrowing Part 4's logic instead of re-implementing it.

Two things the dashboard must not own a second copy of:

* **The feed.** The Feeds screen is a UI over ``core/export/exporter.py``. The
  bytes a user downloads are produced by the same ``FeedExporter`` that
  ``python main.py export`` writes to disk, so the preview and the published
  feed can never disagree.
* **The command classifier.** Session transcripts flag risky commands using
  ``core/alerting/rules.classify_command`` — the same patterns the alert engine
  fires on. A command highlighted red in a transcript is red *because a rule
  would fire on it*, which is exactly the question an assessor asks.

``core`` is a script directory rather than an installed package (its own
``main.py`` does ``from export.exporter import ...``), so it is added to
``sys.path`` here — in one place, wrapped, and optional. If ``core`` is missing
the dashboard still runs; the affected panels explain what is unavailable
instead of raising.
"""

from __future__ import annotations

import logging
import sys
from functools import lru_cache
from typing import Any, Optional

from app.settings import REPO_ROOT

log = logging.getLogger(__name__)

CORE_DIR = REPO_ROOT / "core"


def _ensure_core_importable() -> bool:
    if not CORE_DIR.is_dir():
        return False
    path = str(CORE_DIR)
    if path not in sys.path:
        sys.path.insert(0, path)
    return True


@lru_cache(maxsize=1)
def feed_exporter_class() -> Optional[type]:
    """``core.export.exporter.FeedExporter``, or None if core is unavailable."""
    if not _ensure_core_importable():
        log.warning("core/ not found at %s — feed export disabled", CORE_DIR)
        return None
    try:
        from export.exporter import FeedExporter  # type: ignore

        return FeedExporter
    except Exception:  # noqa: BLE001 - a broken import must not kill the app
        log.exception("could not import FeedExporter; feed export disabled")
        return None


@lru_cache(maxsize=1)
def exporter_module() -> Optional[Any]:
    """``core.export.exporter``, for its masking helpers."""
    if not _ensure_core_importable():
        return None
    try:
        from export import exporter  # type: ignore

        return exporter
    except Exception:  # noqa: BLE001
        log.exception("could not import export.exporter")
        return None


def scrub_payload(payload: Any) -> Any:
    """
    Run a payload through the exporter's masking and leak assertion.

    Used by the per-IP dossier download. The dashboard already reads masked
    views, so this is belt and braces — but it is the *same* belt the published
    feed wears, and it raises rather than redacts if an unmasked credential ever
    reaches an export path.
    """
    exporter = exporter_module()
    if exporter is None:
        return payload
    cleaned = exporter.scrub(payload)
    exporter.assert_no_secrets(cleaned)
    return cleaned


@lru_cache(maxsize=1)
def rules_module() -> Optional[Any]:
    """``core.alerting.rules``, or None if core is unavailable."""
    if not _ensure_core_importable():
        return None
    try:
        from alerting import rules  # type: ignore

        return rules
    except Exception:  # noqa: BLE001
        log.exception("could not import alerting.rules; rule details disabled")
        return None


def classify_command(command: str) -> Optional[tuple]:
    """
    ``(severity, label)`` for a command the engine would alert on, else None.

    Falls back to None — never an exception — when core is unavailable, so a
    transcript renders with plain commands rather than failing to render.
    """
    rules = rules_module()
    if rules is None or not command:
        return None
    try:
        return rules.classify_command(command)
    except Exception:  # noqa: BLE001
        return None


def command_patterns() -> list:
    """The high-risk command pattern table, for the Alerts rules panel."""
    rules = rules_module()
    if rules is None:
        return []
    return [
        {"pattern": pattern, "severity": severity, "label": label}
        for pattern, severity, label in getattr(rules, "COMMAND_PATTERNS", [])
    ]


def rule_names() -> list:
    """Names of every rule the engine knows about, enabled or not."""
    rules = rules_module()
    if rules is None:
        return []
    return sorted(getattr(rules, "RULE_REGISTRY", {}))
