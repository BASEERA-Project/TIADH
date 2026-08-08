#!/usr/bin/env python3
"""
tools/build_world_svg.py — Regenerate the coastline the threat map draws on.

    python tools/build_world_svg.py                     download and rebuild
    python tools/build_world_svg.py --source land.json  from a local file
    python tools/build_world_svg.py --tolerance 0.4     finer coastline

Why this exists: ``app/templates/_world_land.svg`` is a 28 KB blob of path data,
and a blob nobody can regenerate is a blob nobody can check. This script is how
it was produced, so the file can be audited, re-simplified, or rebuilt against a
newer edition of the source rather than being trusted on sight.

The source is **Natural Earth 1:110m land** — public domain, no attribution
required, the same dataset every offline atlas starts from. It is coastlines
only: no borders, no names, no disputed lines, nothing this project would have
to take a position on.

The projection is **not** configured here. It is imported from ``app.geo``,
which is the one place a latitude becomes a pixel — so the coastline and the
attack marks drawn over it are guaranteed to use the same viewBox. Change the
crop or the width there, rerun this, and the two stay in step.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Tuple

DASHBOARD_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(DASHBOARD_DIR))

from app import geo  # noqa: E402  - after the path is set up

SOURCE_URL = (
    "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/"
    "geojson/ne_110m_land.geojson"
)

TARGET = DASHBOARD_DIR / "app" / "templates" / "_world_land.svg"

#: Rings whose northernmost point is below this are Antarctica, which the crop
#: cuts off anyway. Dropped whole rather than clipped to the bottom edge, where
#: it would render as a meaningless bar across the foot of the panel.
ANTARCTIC_LAT = -58.0

#: Rings simplified to fewer than this many points are specks at 1000px wide.
MIN_POINTS = 4

Point = Tuple[float, float]


def simplify(points: List[Point], tolerance: float) -> List[Point]:
    """Ramer-Douglas-Peucker, iterative so a long coastline cannot recurse away."""
    if len(points) < 3:
        return points

    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]

    while stack:
        first, last = stack.pop()
        ax, ay = points[first]
        bx, by = points[last]
        dx, dy = bx - ax, by - ay
        span = (dx * dx + dy * dy) ** 0.5

        worst, index = tolerance, -1
        for i in range(first + 1, last):
            px, py = points[i]
            distance = (
                abs(dy * (px - ax) - dx * (py - ay)) / span if span
                else ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5
            )
            if distance > worst:
                worst, index = distance, i

        if index > 0:
            keep[index] = True
            stack.append((first, index))
            stack.append((index, last))

    return [point for point, keeper in zip(points, keep) if keeper]


def rings(geometry: Dict[str, Any]) -> List[List[Point]]:
    """Every ring of a Polygon or MultiPolygon, holes included."""
    kind = geometry.get("type")
    if kind == "Polygon":
        return list(geometry["coordinates"])
    if kind == "MultiPolygon":
        return [ring for polygon in geometry["coordinates"] for ring in polygon]
    return []


def build(collection: Dict[str, Any], tolerance: float) -> Tuple[str, int, int]:
    subpaths: List[str] = []
    kept = dropped = 0

    for feature in collection.get("features", []):
        for ring in rings(feature.get("geometry") or {}):
            if max(lat for _, lat in ring) < ANTARCTIC_LAT:
                dropped += 1
                continue

            projected = [geo.project(lat, lon) for lon, lat in ring]
            points = simplify([p for p in projected if p], tolerance)
            if len(points) < MIN_POINTS:
                dropped += 1
                continue

            kept += 1
            head = points[0]
            body = " ".join(f"{x:g} {y:g}" for x, y in points[1:-1])
            subpaths.append(f"M{head[0]:g} {head[1]:g}L{body}Z")

    return "".join(subpaths), kept, dropped


def render(path_data: str, tolerance: float) -> str:
    """The template partial, provenance in a Jinja comment that never ships."""
    return (
        "{#  =========================================================================\n"
        "    _world_land.svg — the world's coastlines, vendored.\n"
        "\n"
        "    GENERATED FILE. Rebuild it with `python tools/build_world_svg.py`;\n"
        "    hand edits are lost the next time anyone does.\n"
        "\n"
        "    Source:     Natural Earth 1:110m land (public domain).\n"
        f"    Projection: equirectangular, viewBox 0 0 {geo.WIDTH:g} {geo.HEIGHT:g},\n"
        f"                latitude +{geo.TOP_LAT:g}° to {geo.BOTTOM_LAT:g}°, from app/geo.py.\n"
        f"    Simplified: Ramer-Douglas-Peucker, {tolerance:g} user units.\n"
        "\n"
        "    It is drawn inside the map's own <svg>, not loaded as an image: the\n"
        "    marks share its coordinate space, and the Content-Security-Policy this\n"
        "    dashboard sets would refuse a remote tile anyway.\n"
        "    ========================================================================= #}\n"
        f'<path class="wm-land" fill-rule="evenodd" d="{path_data}"/>\n'
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--source", help="local GeoJSON instead of downloading")
    parser.add_argument("--url", default=SOURCE_URL, help="where to download from")
    parser.add_argument("--tolerance", type=float, default=0.6,
                        help="simplification, in SVG user units (default 0.6)")
    parser.add_argument("--out", default=str(TARGET), help="file to write")
    args = parser.parse_args(argv)

    if args.source:
        collection = json.loads(Path(args.source).read_text())
    else:
        print(f"downloading {args.url}")
        with urllib.request.urlopen(args.url, timeout=60) as response:
            collection = json.load(response)

    path_data, kept, dropped = build(collection, args.tolerance)
    Path(args.out).write_text(render(path_data, args.tolerance))

    print(f"{args.out}: {kept} rings kept, {dropped} dropped, "
          f"{len(path_data):,} chars of path data")
    return 0


if __name__ == "__main__":
    sys.exit(main())
