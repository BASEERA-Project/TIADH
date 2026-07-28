"""
wsgi.py — Entry point for a real WSGI server.

    waitress-serve --host 127.0.0.1 --port 8050 wsgi:app     (Windows)
    gunicorn -w 4 -b 127.0.0.1:8050 wsgi:app                 (Linux/macOS)

Flask's own server is fine for a demo; use one of the above for anything left
running. Set ``DASHBOARD_SECRET_KEY`` first — the development fallback logs a
warning on startup for a reason.

Threaded workers are safe: every request gets its own read-only SQLite handle
and releases it on teardown (see ``app/db.py``).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import create_app  # noqa: E402

app = create_app()
