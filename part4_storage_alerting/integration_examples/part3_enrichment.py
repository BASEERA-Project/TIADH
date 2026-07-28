#!/usr/bin/env python3
"""
integration_examples/part3_enrichment.py — for whoever has Part 3.

The complete enrichment worker. Swap the two stub providers for real MaxMind and
AbuseIPDB clients and this is production code — nothing else changes.

Four things it demonstrates that are easy to get wrong:

* It is a **worker loop, not a request handler.** Enrichment inside Part 2's POST
  handler means one slow AbuseIPDB response blocks ingestion for every node.
* **Geo and abuse are written separately.** An API outage cannot stall profiling.
* **`get_ips_needing_enrichment()` is the cache.** It only returns IPs with no row
  or a stale `last_updated`, so quota is never re-burnt on a known IP.
* **`profile_score` components are capped.** One noisy dimension must not
  saturate the score.

    python integration_examples/part3_enrichment.py --once
"""

from __future__ import annotations

import argparse
import logging
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.database import Database

logging.basicConfig(level=logging.INFO, format="%(asctime)s  enrichment: %(message)s")
log = logging.getLogger("part3")


# ---------------------------------------------------------------------------
# Providers — replace these two functions with the real clients
# ---------------------------------------------------------------------------

def geoip_lookup(ip: str) -> dict:
    """
    Real version:

        import geoip2.database
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")   # open ONCE, module level
        r = reader.city(ip)
        return {"country": r.country.iso_code, "city": r.city.name,
                "latitude": r.location.latitude, "longitude": r.location.longitude}

    Local .mmdb file, so no rate limit and no network round trip. Note that the
    RFC 5737 documentation ranges the team's fixtures use have no geo data at
    all — real MaxMind raises AddressNotFoundError. Return nulls, do not crash.
    """
    demo = {
        "203.0.113.10": ("NL", "Amsterdam", 52.3676, 4.9041),
        "192.0.2.77": ("CN", "Shanghai", 31.2304, 121.4737),
        "198.51.100.5": ("DE", "Frankfurt", 50.1109, 8.6821),
    }
    country, city, lat, lon = demo.get(ip, (None, None, None, None))
    return {"country": country, "city": city, "latitude": lat, "longitude": lon}


def abuseipdb_lookup(ip: str) -> int | None:
    """
    Real version:

        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": os.environ["ABUSEIPDB_KEY"], "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
        if r.status_code == 429:
            raise RateLimited
        return r.json()["data"]["abuseConfidenceScore"]

    Free tier is 1000 checks/day. Back off on 429; never let it kill the worker.
    """
    demo = {"203.0.113.10": 92, "192.0.2.77": 64, "198.51.100.5": 3}
    return demo.get(ip, random.randint(0, 40))


# ---------------------------------------------------------------------------
# Attacker profiling — the team-calculated score, from behaviour not reputation
# ---------------------------------------------------------------------------

def compute_profile_score(inputs: dict) -> int:
    """
    0-100, from the event stream alone.

    Every component is capped so a single dimension cannot saturate the score:
    ten thousand login attempts from a dumb bot should not outrank one attacker
    who logged in, looked around and pulled down a binary.
    """
    volume       = min(inputs["session_count"] * 4, 20)
    curiosity    = min(inputs["distinct_commands"] * 2, 20)
    spread       = min(inputs["node_count"] * 10, 20)
    staging      = 25 if inputs["download_count"] else 0
    breadth      = min(inputs["distinct_usernames"], 15)
    return min(volume + curiosity + spread + staging + breadth, 100)


# ---------------------------------------------------------------------------
# The worker
# ---------------------------------------------------------------------------

class EnrichmentWorker:
    def __init__(self, db: Database = None, max_age_days: int = 7, per_pass: int = 100):
        self.db = db or Database()
        self.max_age_days = max_age_days
        self.per_pass = per_pass
        self._last_call = 0.0
        self.min_interval = 0.1          # crude rate limit; a token bucket is better

    def _throttle(self) -> None:
        gap = time.time() - self._last_call
        if gap < self.min_interval:
            time.sleep(self.min_interval - gap)
        self._last_call = time.time()

    def enrich_one(self, ip: str) -> None:
        # --- geo: local database, essentially free ---------------------------
        try:
            geo = geoip_lookup(ip)
            self.db.upsert_reputation(ip, source="GeoLite2", **geo)
        except Exception:
            log.exception("geo lookup failed for %s", ip)

        # --- abuse score: external API, rate limited, may be down ------------
        try:
            self._throttle()
            score = abuseipdb_lookup(ip)
            if score is not None:
                self.db.upsert_reputation(ip, abuse_score=score, source="AbuseIPDB")
        except Exception:
            # Deliberately non-fatal: profiling below must still run.
            log.warning("abuse lookup failed for %s; continuing", ip)

        # --- behavioural profile: local, always available --------------------
        inputs = self.db.get_attacker_profile_inputs(ip)
        profile = compute_profile_score(inputs)
        self.db.upsert_reputation(ip, profile_score=profile, source="local-profile")

        current = self.db.get_reputation(ip)
        log.info(
            "%-16s %-3s abuse=%-4s profile=%-4s sources=%s",
            ip, current["country"] or "--", current["abuse_score"],
            current["profile_score"], current["source"],
        )

    def run_once(self) -> int:
        """New or stale IPs only — this call IS the cache check."""
        pending = self.db.get_ips_needing_enrichment(
            max_age_days=self.max_age_days, limit=self.per_pass
        )
        if not pending:
            log.info("nothing to enrich")
            return 0
        log.info("enriching %d IP(s)", len(pending))
        for ip in pending:
            self.enrich_one(ip)
        return len(pending)

    def rescore_all(self) -> int:
        """
        Recompute profile scores without touching any external API.

        profile_score is a function of accumulated events, so it must be
        refreshed as new activity arrives — not written once and forgotten.
        Cheap enough to run every few minutes.
        """
        rows = self.db.query("SELECT attacker_ip FROM reputation")
        for row in rows:
            inputs = self.db.get_attacker_profile_inputs(row["attacker_ip"])
            self.db.upsert_reputation(
                row["attacker_ip"], profile_score=compute_profile_score(inputs),
                source="local-profile",
            )
        return len(rows)

    def run_forever(self, interval_seconds: int = 300) -> None:
        while True:
            try:
                self.run_once()
                self.rescore_all()
            except Exception:
                log.exception("enrichment pass failed; continuing")
            time.sleep(interval_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="Threat intelligence enrichment worker")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--max-age-days", type=int, default=7)
    args = parser.parse_args()

    worker = EnrichmentWorker(max_age_days=args.max_age_days)
    if args.once:
        worker.run_once()
        worker.rescore_all()
    else:
        worker.run_forever(args.interval)


if __name__ == "__main__":
    main()
