"""
backfill.py — ship the events already sitting in dionaea's logs.

adapter.py starts at the *end* of the live log and never looks at the rotated
files beside it, which is what stops a restart from replaying history at the
collector. The cost of that rule is everything dionaea recorded before this
sensor was wired up, or while the adapter was stopped: it sits on disk and
never reaches the aggregator. This sends it.

    uv run backfill.py                          # every dionaea log on disk
    uv run backfill.py --dry-run                # say what would be sent
    uv run backfill.py --since 2026-08-07       # only events from then on
    uv run backfill.py dionaea-data/dionaea_incident.json.1   # named files only

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
        description="Send the events already in dionaea's JSON logs, including rotated ones.",
        log_description="file beside LOG_PATH whose name starts with it",
    )
