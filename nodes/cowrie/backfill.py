"""
backfill.py — ship the events already sitting in Cowrie's logs.

adapter.py starts at the *end* of the live cowrie.json and never looks at the
rotated cowrie.json.YYYY-MM-DD files beside it, which is what stops a restart
from replaying history at the collector. The cost of that rule is everything
Cowrie recorded before this sensor was wired up, or while the adapter was
stopped: it sits on disk and never reaches the aggregator. This sends it.

    uv run backfill.py                          # every cowrie.json* on disk
    uv run backfill.py --dry-run                # say what would be sent
    uv run backfill.py --since 2026-08-07       # only events from then on
    uv run backfill.py cowrie-logs/cowrie.json.2026-08-06   # named files only

Safe to run twice: the ids are derived from the events themselves, so a second
run answers `duplicates` rather than inserting a second copy of every session.
The run itself is shipper/backfill.py, handed adapter.py's settings and its
event mapping so the two cannot drift apart.
"""

from shipper import backfill

from adapter import SETTINGS, build_envelopes

if __name__ == "__main__":
    backfill.main(
        SETTINGS,
        build_envelopes,
        description="Send the events already in Cowrie's logs, including rotated ones.",
        log_description="cowrie.json* beside LOG_PATH",
    )
