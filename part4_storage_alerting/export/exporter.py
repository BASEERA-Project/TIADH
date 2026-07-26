"""
export/exporter.py — Turns the database into a shareable threat feed.

Formats
-------
JSON   the native feed: indicators + alerts + provenance metadata
CSV    two flat files (indicators, alerts) for spreadsheets and grep
STIX   STIX 2.1 bundle of Indicator SDOs, for anything that speaks TAXII

Sensitive data
--------------
The baseline is unambiguous: attempted passwords stay in local SQLite and never
appear in an export. That is enforced three times over, on purpose:

1. every query here reads `sessions_public`, the masked view, never `sessions`;
2. :func:`scrub` rewrites any password-like key it finds in a payload;
3. :func:`assert_no_secrets` re-walks the finished payload and *raises* if an
   unmasked password survived.

Step 3 exists because the cost of being wrong is a leaked credential set in a
file someone forwards by email. A crash is the better failure.
"""

from __future__ import annotations

import csv
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
from db.database import UUID_NAMESPACE, Database, get_db
from db.validation import utc_now

log = logging.getLogger(__name__)

#: Optional dependency. The exporter builds spec-compliant STIX 2.1 without it;
#: installing it just adds schema validation.
try:  # pragma: no cover - depends on the environment
    import stix2  # type: ignore

    STIX2_AVAILABLE = True
except ImportError:  # pragma: no cover
    stix2 = None
    STIX2_AVAILABLE = False

#: Keys whose values must never leave local storage.
SENSITIVE_KEYS = {"password", "passwd", "pwd", "secret", "node_key", "x-node-key", "api_key"}


class SecretLeakError(RuntimeError):
    """Raised when an unmasked sensitive value reaches an export payload."""


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------

def scrub(payload: Any) -> Any:
    """Recursively replace every sensitive value with the mask constant."""
    if isinstance(payload, dict):
        return {
            key: (config.MASK if key.lower() in SENSITIVE_KEYS and value not in (None, "")
                  else scrub(value))
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [scrub(item) for item in payload]
    return payload


def assert_no_secrets(payload: Any, path: str = "$") -> None:
    """Fail loudly if a sensitive key holds anything other than null or the mask."""
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key.lower() in SENSITIVE_KEYS and value not in (None, "", config.MASK):
                raise SecretLeakError(
                    f"unmasked sensitive value at {path}.{key} — export aborted"
                )
            assert_no_secrets(value, f"{path}.{key}")
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            assert_no_secrets(item, f"{path}[{index}]")


# --------------------------------------------------------------------------
# Feed assembly
# --------------------------------------------------------------------------

class FeedExporter:
    """Builds and writes the outbound threat feed in every supported format."""

    def __init__(self, db: Database = None, output_dir: Path | str = None):
        self.db = db or get_db(read_only=False)
        self.output_dir = Path(output_dir or config.EXPORT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # -- payload -------------------------------------------------------

    def build_feed(self, min_severity: str = None) -> Dict[str, Any]:
        """
        Assemble the full feed payload in memory.

        Also used by Part 5 to preview exactly what would be published without
        writing a file.
        """
        min_sev = min_severity or config.FEED_MIN_SEVERITY
        indicators = [
            self._build_indicator(row) for row in self.db.get_feed_indicators(min_sev)
        ]
        alerts = [
            self._build_alert(row)
            for row in self.db.get_alerts(
                status=list(config.FEED_STATUSES), min_severity=min_sev, limit=10_000
            )
        ]

        feed = {
            "feed": {
                "name": "Distributed Honeypot Threat Intelligence Feed",
                "producer": config.FEED_PRODUCER,
                "schema_version": config.SCHEMA_VERSION,
                "generated_at": utc_now(),
                "min_severity": min_sev,
                "statuses": list(config.FEED_STATUSES),
                "counts": {"indicators": len(indicators), "alerts": len(alerts)},
                "notice": (
                    "Attempted credentials are retained locally for analysis and are "
                    "masked in this feed. Indicators are honeypot observations and "
                    "should be corroborated before being used for blocking."
                ),
            },
            "indicators": indicators,
            "alerts": alerts,
        }

        feed = scrub(feed)
        assert_no_secrets(feed)
        return feed

    def _build_indicator(self, row: Dict[str, Any]) -> Dict[str, Any]:
        alert_types = sorted(set((row.get("alert_types") or "").split(","))) if row.get(
            "alert_types"
        ) else []
        return {
            "attacker_ip": row["attacker_ip"],
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "confidence": self._confidence(row),
            "severity": _rank_to_severity(row.get("severity_rank")),
            "alert_count": row.get("alert_count", 0),
            "alert_types": [t for t in alert_types if t],
            "activity": {
                "events": row.get("event_count", 0),
                "sessions": row.get("session_count", 0),
                "nodes_touched": row.get("node_count", 0),
                "login_attempts": row.get("login_attempts", 0),
                "commands": row.get("command_count", 0),
                "downloads": row.get("download_count", 0),
            },
            "geo": {
                "country": row.get("country"),
                "city": row.get("city"),
                "latitude": row.get("latitude"),
                "longitude": row.get("longitude"),
            },
            "scores": {
                "abuse_score": row.get("abuse_score"),
                "profile_score": row.get("profile_score"),
                "sources": [s for s in (row.get("reputation_source") or "").split(",") if s],
            },
        }

    @staticmethod
    def _build_alert(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "alert_id": row["alert_id"],
            "attacker_ip": row["attacker_ip"],
            "session_id": row.get("session_id"),
            "alert_type": row["alert_type"],
            "severity": row["severity"],
            "timestamp": row["timestamp"],
            "description": row["description"],
            "status": row["status"],
            "country": row.get("country"),
            "abuse_score": row.get("abuse_score"),
            "profile_score": row.get("profile_score"),
        }

    @staticmethod
    def _confidence(row: Dict[str, Any]) -> int:
        """
        0–100 confidence that this IP is genuinely hostile.

        Honeypot logic: nothing legitimate has any reason to touch these hosts,
        so a single interaction already starts high. Corroboration from an
        external feed, breadth across sensors and hands-on-keyboard behaviour
        each push it further up.
        """
        score = 50
        if (row.get("abuse_score") or 0) >= 50:
            score += 20
        if (row.get("profile_score") or 0) >= 50:
            score += 10
        if (row.get("node_count") or 0) >= 2:
            score += 10
        if (row.get("download_count") or 0) > 0:
            score += 10
        if (row.get("command_count") or 0) > 0:
            score += 5
        return min(score, 100)

    # -- writers -------------------------------------------------------

    def export_json(self, path: Path | str = None, min_severity: str = None) -> Path:
        """Write the native JSON feed."""
        feed = self.build_feed(min_severity)
        target = Path(path) if path else self.output_dir / "threat_feed.json"
        target.write_text(json.dumps(feed, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info(
            "wrote %s (%d indicators, %d alerts)",
            target,
            feed["feed"]["counts"]["indicators"],
            feed["feed"]["counts"]["alerts"],
        )
        return target

    def export_csv(self, directory: Path | str = None, min_severity: str = None) -> List[Path]:
        """Write `indicators.csv` and `alerts.csv`, flattened for spreadsheets."""
        feed = self.build_feed(min_severity)
        out_dir = Path(directory) if directory else self.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        indicator_rows = [
            {
                "attacker_ip": i["attacker_ip"],
                "first_seen": i["first_seen"],
                "last_seen": i["last_seen"],
                "severity": i["severity"],
                "confidence": i["confidence"],
                "alert_count": i["alert_count"],
                "alert_types": ";".join(i["alert_types"]),
                "country": i["geo"]["country"],
                "city": i["geo"]["city"],
                "latitude": i["geo"]["latitude"],
                "longitude": i["geo"]["longitude"],
                "abuse_score": i["scores"]["abuse_score"],
                "profile_score": i["scores"]["profile_score"],
                "sources": ";".join(i["scores"]["sources"]),
                "events": i["activity"]["events"],
                "sessions": i["activity"]["sessions"],
                "nodes_touched": i["activity"]["nodes_touched"],
                "login_attempts": i["activity"]["login_attempts"],
                "commands": i["activity"]["commands"],
                "downloads": i["activity"]["downloads"],
            }
            for i in feed["indicators"]
        ]

        written = [
            _write_csv(out_dir / "indicators.csv", indicator_rows),
            _write_csv(out_dir / "alerts.csv", feed["alerts"]),
        ]
        log.info("wrote %s", ", ".join(str(p) for p in written))
        return written

    def export_stix(self, path: Path | str = None, min_severity: str = None) -> Path:
        """
        Write a STIX 2.1 bundle of Indicator SDOs.

        Uses the `stix2` library when it is installed (which adds spec
        validation) and falls back to constructing the same objects by hand
        otherwise, so the stretch goal never becomes a blocking dependency.
        """
        feed = self.build_feed(min_severity)
        target = Path(path) if path else self.output_dir / "threat_feed_stix.json"

        identity_id = f"identity--{uuid.uuid5(UUID_NAMESPACE, config.FEED_PRODUCER)}"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        objects: List[Dict[str, Any]] = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": now,
                "modified": now,
                "name": config.FEED_PRODUCER,
                "identity_class": "system",
                "sectors": ["technology"],
            }
        ]

        for indicator in feed["indicators"]:
            ip = indicator["attacker_ip"]
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid5(UUID_NAMESPACE, 'indicator|' + ip)}",
                    "created_by_ref": identity_id,
                    "created": now,
                    "modified": now,
                    "name": f"Honeypot activity from {ip}",
                    "description": _stix_description(indicator),
                    "indicator_types": ["malicious-activity"],
                    "pattern": f"[ipv4-addr:value = '{ip}']",
                    "pattern_type": "stix",
                    "pattern_version": "2.1",
                    "valid_from": _to_stix_time(indicator["first_seen"]) or now,
                    "confidence": indicator["confidence"],
                    "labels": indicator["alert_types"] or ["scanning"],
                }
            )

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

        if STIX2_AVAILABLE:  # pragma: no cover - only when the optional dep is present
            try:
                parsed = stix2.parse(bundle, allow_custom=False)
                target.write_text(parsed.serialize(pretty=True), encoding="utf-8")
                log.info("wrote %s (validated by stix2)", target)
                return target
            except Exception as exc:  # noqa: BLE001
                log.warning("stix2 validation failed (%s); writing unvalidated bundle", exc)

        target.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("wrote %s (%d STIX object(s))", target, len(objects))
        return target

    def export_all(self, min_severity: str = None) -> Dict[str, Any]:
        """Produce every format in one call. Used by `main.py run`."""
        return {
            "json": str(self.export_json(min_severity=min_severity)),
            "csv": [str(p) for p in self.export_csv(min_severity=min_severity)],
            "stix": str(self.export_stix(min_severity=min_severity)),
        }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> Path:
    """
    Write rows to CSV.

    ``quoting=QUOTE_ALL`` is not cosmetic: descriptions contain attacker-supplied
    command text, and an unquoted comma or newline would silently corrupt the
    file for whoever opens it next.
    """
    if not rows:
        path.write_text("", encoding="utf-8")
        return path

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _rank_to_severity(rank: Optional[int]) -> str:
    return {3: "high", 2: "medium", 1: "low"}.get(rank or 1, "low")


def _to_stix_time(value: Optional[str]) -> Optional[str]:
    """v1.3 timestamps are already ISO 8601 UTC; STIX wants millisecond precision."""
    if not value:
        return None
    return value.replace("Z", ".000Z") if "." not in value else value


def _stix_description(indicator: Dict[str, Any]) -> str:
    activity = indicator["activity"]
    parts = [
        f"Observed on {activity['nodes_touched']} honeypot sensor(s)",
        f"{activity['sessions']} session(s)",
        f"{activity['login_attempts']} login attempt(s)",
    ]
    if activity["commands"]:
        parts.append(f"{activity['commands']} command(s) executed")
    if activity["downloads"]:
        parts.append(f"{activity['downloads']} payload download(s)")
    if indicator["geo"]["country"]:
        parts.append(f"geolocated to {indicator['geo']['country']}")
    if indicator["scores"]["abuse_score"] is not None:
        parts.append(f"AbuseIPDB score {indicator['scores']['abuse_score']}")
    return ". ".join(parts) + "."


def export_feed(fmt: str = "all", db: Database = None, min_severity: str = None):
    """Module-level entry point used by the CLI."""
    exporter = FeedExporter(db=db)
    if fmt == "json":
        return exporter.export_json(min_severity=min_severity)
    if fmt == "csv":
        return exporter.export_csv(min_severity=min_severity)
    if fmt == "stix":
        return exporter.export_stix(min_severity=min_severity)
    if fmt == "all":
        return exporter.export_all(min_severity=min_severity)
    raise ValueError(f"unknown export format '{fmt}'")
