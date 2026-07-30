"""
Feeds — a UI over ``core/export/exporter.py``.

The preview and the download are produced by the same ``FeedExporter`` that
``python main.py export`` runs, driven through a subclass whose ``build_feed``
returns the payload the filters produced. Every format therefore comes out of
the exporter's own writer: the JSON is its JSON, the CSV is its CSV with its
quoting, the STIX bundle is its bundle. There is no second implementation to
drift, and the exporter's ``assert_no_secrets`` pass still guards the payload.

Each feed has a stable URL that carries its filters in the query string, so a
feed can be bookmarked, curl'd or handed to a consumer rather than being a button
that only works while someone is looking at the screen.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Blueprint, Response, abort, render_template, request, url_for

from app import queries
from app.db import get_db
from app.formatting import to_datetime
from app.integrations import feed_exporter_class
from common import config

bp = Blueprint("feeds", __name__, url_prefix="/feeds")

#: filename -> how to produce and serve it. The keys are the stable URLs.
FEED_FILES = {
    "threat-feed.json": {
        "label": "Threat feed (JSON)",
        "writer": "json",
        "member": None,
        "mimetype": "application/json",
        "blurb": "Native feed: indicators, alerts and provenance in one document.",
    },
    "indicators.csv": {
        "label": "Indicators (CSV)",
        "writer": "csv",
        "member": "indicators.csv",
        "mimetype": "text/csv",
        "blurb": "One flat row per attacker IP, for spreadsheets and blocklists.",
    },
    "alerts.csv": {
        "label": "Alerts (CSV)",
        "writer": "csv",
        "member": "alerts.csv",
        "mimetype": "text/csv",
        "blurb": "One flat row per published alert.",
    },
    "threat-feed.stix.json": {
        "label": "STIX 2.1 bundle",
        "writer": "stix",
        "member": None,
        "mimetype": "application/json",
        "blurb": "Indicator SDOs for anything that speaks TAXII.",
    },
}

PREVIEW_ROWS = 5


@bp.route("/")
def index():
    db = get_db()
    params = _params()
    feed = _build(db, params)

    if feed is None:
        return render_template(
            "feeds.html", title="Feeds", feed=None, params=params,
            countries=db.get_countries(),
            alert_types=db.get_alert_types(),
            windows=queries.WINDOW_CHOICES, files=FEED_FILES, urls={},
        )

    urls = {
        name: url_for("feeds.download", filename=name, **_query(params))
        for name in FEED_FILES
    }
    return render_template(
        "feeds.html",
        title="Feeds",
        feed=feed,
        params=params,
        preview_indicators=feed["indicators"][:PREVIEW_ROWS],
        preview_alerts=feed["alerts"][:PREVIEW_ROWS],
        preview_json=json.dumps(
            {
                "feed": feed["feed"],
                "indicators": feed["indicators"][:2],
                "alerts": feed["alerts"][:2],
            },
            indent=2,
            ensure_ascii=False,
        ),
        countries=db.get_countries(),
        alert_types=db.get_alert_types(),
        windows=queries.WINDOW_CHOICES,
        files=FEED_FILES,
        urls=urls,
    )


@bp.route("/<filename>")
def download(filename: str):
    spec = FEED_FILES.get(filename)
    if spec is None:
        abort(404)

    db = get_db()
    feed = _build(db, _params())
    if feed is None:
        abort(503, "feed export is unavailable — core/export/exporter.py not found")

    exporter_class = feed_exporter_class()
    workdir = Path(tempfile.mkdtemp(prefix="tiadh-feed-"))
    try:
        exporter = _prepared_exporter(exporter_class, feed, db, workdir)
        writer = spec["writer"]
        if writer == "json":
            path = exporter.export_json()
        elif writer == "stix":
            path = exporter.export_stix()
        else:
            written = exporter.export_csv()
            path = next(
                (p for p in written if Path(p).name == spec["member"]), written[0]
            )
        payload = Path(path).read_text(encoding="utf-8")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    return Response(
        payload,
        mimetype=spec["mimetype"],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --------------------------------------------------------------------------
# Building and filtering
# --------------------------------------------------------------------------

def _params() -> Dict[str, Any]:
    """The feed's filter set, defaulted to the configured publication policy."""
    min_severity = request.args.get("min_severity") or config.FEED_MIN_SEVERITY
    if min_severity not in config.SEVERITY_ORDER:
        min_severity = config.FEED_MIN_SEVERITY
    try:
        min_confidence = int(request.args.get("min_confidence") or 0)
    except ValueError:
        min_confidence = 0
    return {
        "min_severity": min_severity,
        "window": request.args.get("window") or "all",
        "country": (request.args.get("country") or "").strip(),
        "type": (request.args.get("type") or "").strip(),
        "min_confidence": max(0, min(100, min_confidence)),
    }


def _query(params: Dict[str, Any]) -> Dict[str, Any]:
    """Only the non-default parameters, so shared URLs stay readable."""
    query = {}
    if params["min_severity"] != config.FEED_MIN_SEVERITY:
        query["min_severity"] = params["min_severity"]
    if params["window"] != "all":
        query["window"] = params["window"]
    for key in ("country", "type"):
        if params[key]:
            query[key] = params[key]
    if params["min_confidence"]:
        query["min_confidence"] = params["min_confidence"]
    return query


def _build(db, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    exporter_class = feed_exporter_class()
    if exporter_class is None:
        return None

    workdir = Path(tempfile.mkdtemp(prefix="tiadh-feed-"))
    try:
        exporter = exporter_class(db=db, output_dir=workdir)
        feed = exporter.build_feed(min_severity=params["min_severity"])
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return _apply_filters(feed, params)


def _apply_filters(feed: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Narrow an already-built feed.

    Filtering happens on the payload rather than in SQL so that whatever the
    exporter decided to publish is what gets filtered — a UI filter can only ever
    remove records from the feed, never add one the exporter would have withheld.
    """
    since = _window_start(params["window"])
    country = params["country"]
    alert_type = params["type"]
    min_confidence = params["min_confidence"]

    indicators = []
    for indicator in feed["indicators"]:
        if since and not _at_or_after(indicator.get("last_seen"), since):
            continue
        if country and (indicator.get("geo") or {}).get("country") != country:
            continue
        if alert_type and alert_type not in (indicator.get("alert_types") or []):
            continue
        if min_confidence and (indicator.get("confidence") or 0) < min_confidence:
            continue
        indicators.append(indicator)

    alerts = []
    for alert in feed["alerts"]:
        if since and not _at_or_after(alert.get("timestamp"), since):
            continue
        if country and alert.get("country") != country:
            continue
        if alert_type and alert.get("alert_type") != alert_type:
            continue
        alerts.append(alert)

    feed["indicators"] = indicators
    feed["alerts"] = alerts
    feed["feed"]["counts"] = {"indicators": len(indicators), "alerts": len(alerts)}
    feed["feed"]["filters"] = {
        "window": params["window"],
        "country": country or None,
        "alert_type": alert_type or None,
        "min_confidence": min_confidence or None,
    }
    return feed


def _window_start(window: str) -> Optional[str]:
    return queries.since_from_window(window)


def _at_or_after(value: Optional[str], since: str) -> bool:
    moment = to_datetime(value)
    boundary = to_datetime(since)
    if moment is None or boundary is None:
        return False
    return moment >= boundary


def _prepared_exporter(exporter_class, feed: Dict[str, Any], db, workdir: Path):
    """
    A ``FeedExporter`` whose payload is already decided.

    Overriding ``build_feed`` is what lets the filtered preview and the
    downloaded file be the same bytes: ``export_json``, ``export_csv`` and
    ``export_stix`` all call it, so all three serialise the payload shown on
    screen rather than re-querying and quietly returning something else.
    """

    class _Prepared(exporter_class):  # type: ignore[misc, valid-type]
        def build_feed(self, min_severity=None):  # noqa: D102 - see above
            return feed

    return _Prepared(db=db, output_dir=workdir)
