"""
app/views — one blueprint per screen.

Views are thin on purpose: parse the query string, call ``app.queries``, render.
No SQL lives in this package, and no view opens a database connection of its own.
"""

from __future__ import annotations

from typing import Any, Dict

from flask import current_app, request


def paging() -> tuple:
    """``(page, per_page)`` from the query string, clamped to sane bounds."""
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    try:
        per_page = int(request.args.get("per_page", current_app.config["PAGE_SIZE"]))
    except ValueError:
        per_page = current_app.config["PAGE_SIZE"]
    per_page = max(10, min(per_page, current_app.config["MAX_PAGE_SIZE"]))
    return page, per_page


def collect(*names: str, flags: tuple = ()) -> Dict[str, Any]:
    """
    Pull named filters out of the query string.

    Empty strings are dropped rather than passed on as ``= ''`` clauses, so a
    filter the user cleared behaves like a filter they never set.
    """
    filters: Dict[str, Any] = {}
    for name in names:
        value = (request.args.get(name) or "").strip()
        if value:
            filters[name] = value
    for name in flags:
        filters[name] = request.args.get(name) in ("1", "true", "on", "yes")
    return filters


def active_filters(filters: Dict[str, Any], ignore: tuple = ("sort", "window")) -> int:
    """How many filters are actually narrowing the result, for the 'clear' chip."""
    return sum(1 for key, value in filters.items() if value and key not in ignore)
