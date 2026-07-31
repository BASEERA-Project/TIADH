"""
app/__init__.py — Application factory.

    from app import create_app
    app = create_app()

The dashboard is a read model over the Baseline v1.3 database. It owns no
detection logic and no schema: thresholds come from ``common.config``, the feed
comes from ``common.export.exporter``, and every table it renders is one the
collector, the enricher and the alert engine wrote.
"""

from __future__ import annotations

import hmac
import logging
import secrets

from flask import Flask, abort, render_template, request, session, url_for

from app import db as database
from app import formatting
from app.settings import Settings

log = logging.getLogger(__name__)

#: Left-hand navigation. Order is the analyst's workflow: what happened, who did
#: it, what did they do, what fired, is the fleet healthy, what do we publish.
NAV = [
    {"endpoint": "overview.index", "label": "Overview", "icon": "grid",
     "hint": "Fleet-wide posture"},
    {"endpoint": "attackers.index", "label": "Attackers", "icon": "target",
     "hint": "Reputation and behaviour per IP"},
    {"endpoint": "sessions.index", "label": "Sessions", "icon": "terminal",
     "hint": "Session transcripts"},
    {"endpoint": "alerts.index", "label": "Alerts", "icon": "alert",
     "hint": "Rule hits and the rules that produced them"},
    {"endpoint": "nodes.index", "label": "Nodes", "icon": "server",
     "hint": "Sensor health"},
    {"endpoint": "feeds.index", "label": "Feeds", "icon": "share",
     "hint": "Outbound threat feed"},
]

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def create_app(config_object=Settings) -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(config_object)

    if app.config["SECRET_KEY"] == "dev-only-not-for-production":
        log.warning(
            "DASHBOARD_SECRET_KEY is unset - using the development key. "
            "Set it before serving this anywhere but localhost."
        )

    formatting.register(app)
    _register_security(app)
    _register_blueprints(app)
    _register_errors(app)
    _register_context(app)

    app.teardown_appcontext(database.close_db)
    return app


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------

def _register_blueprints(app: Flask) -> None:
    from app.views import alerts, api, attackers, feeds, nodes, overview, sessions

    app.register_blueprint(overview.bp)
    app.register_blueprint(attackers.bp)
    app.register_blueprint(sessions.bp)
    app.register_blueprint(alerts.bp)
    app.register_blueprint(nodes.bp)
    app.register_blueprint(feeds.bp)
    app.register_blueprint(api.bp)


def _register_security(app: Flask) -> None:
    """
    A CSRF token for the two state-changing actions, and conservative headers.

    The dashboard renders attacker-supplied text — usernames, command lines,
    download URLs. Jinja autoescaping handles the markup; the CSP is the second
    layer, and it is strict because nothing here loads a remote asset.
    """

    @app.before_request
    def _check_csrf():
        if request.method in SAFE_METHODS or request.blueprint == "api":
            return
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(str(sent), str(expected)):
            abort(400, "invalid or missing CSRF token")

    @app.after_request
    def _headers(response):
        # script-src stays strict — that is the directive that matters when a
        # page renders attacker-supplied text. style-src allows inline because
        # chart geometry (a bar's width, a column's height) is a style attribute
        # computed per row; no user-controlled value ever reaches one.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response


def _register_errors(app: Flask) -> None:
    @app.errorhandler(database.DatabaseUnavailable)
    def _no_database(exc):
        return render_template("setup.html", health=database.health(), error=str(exc)), 503

    @app.errorhandler(404)
    def _not_found(exc):
        return render_template("errors/404.html", error=exc), 404

    @app.errorhandler(400)
    def _bad_request(exc):
        return render_template("errors/400.html", error=exc), 400

    @app.errorhandler(500)
    def _server_error(exc):  # pragma: no cover - only on an unexpected fault
        log.exception("unhandled error rendering %s", request.path)
        return render_template("errors/500.html", error=exc), 500


def _register_context(app: Flask) -> None:
    from common import config as core_config

    def url_with(**overrides):
        """
        The current URL with some query parameters changed.

        Every filter, sort header and page link is built with this, so adding a
        sort never silently drops the filters already applied — the bug that
        makes a dashboard's controls feel untrustworthy.
        """
        args = request.args.to_dict()
        args.update(overrides)
        args = {k: v for k, v in args.items() if v not in (None, "", False)}
        return url_for(request.endpoint, **{**(request.view_args or {}), **args})

    def open_high_alerts():
        """Badge count for the nav. Never allowed to break a page render."""
        try:
            return database.get_db().get_alert_severity_counts(status="open")["high"]
        except Exception:  # noqa: BLE001 - includes the no-database case
            return 0

    @app.context_processor
    def _inject():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return {
            "url_with": url_with,
            "open_high_alerts": open_high_alerts,
            "nav": NAV,
            "app_name": app.config["APP_NAME"],
            "app_subtitle": app.config["APP_SUBTITLE"],
            "schema_version": core_config.SCHEMA_VERSION,
            "refresh_seconds": app.config["REFRESH_SECONDS"],
            "allow_alert_actions": app.config["ALLOW_ALERT_ACTIONS"],
            "csrf_token": session["csrf_token"],
            "thresholds": core_config,
            "current_endpoint": request.endpoint or "",
        }
