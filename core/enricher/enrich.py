import requests
import json
import logging
import threading
from datetime import datetime, timezone

# Part 4's central Database API, now an installed package rather than a
# sibling directory, so the import can no longer fail.
from common.db.database import Database

# Logging rather than print: this module runs standalone *and* as a thread
# inside `core/main.py serve`, where three components share one output stream
# and the level prefix is what tells them apart.
log = logging.getLogger("enricher")

# Global cache dictionary to prevent API rate-limiting[cite: 1]
IP_CACHE = {}

def calculate_dynamic_profile_score(ip_address, external_abuse_score, db=None, db_path=None):
    """
    Calculates a dynamic 0-100 profile score based on honeypot activity[cite: 1, 3].
    Uses Part 4's db.get_attacker_profile_inputs() helper while retaining 
    our custom scoring weights[cite: 4, 5].
    """
    session_count = 0
    unique_commands = 0

    try:
        # Initialize Part 4 Database connection if not provided[cite: 4]
        if db is None and Database is not None:
            db = Database(db_path) if db_path else Database()

        if db is not None:
            # Query metrics using Part 4's shared reader function[cite: 4, 5]
            inputs = db.get_attacker_profile_inputs(ip_address)
            session_count = inputs.get("session_count", 0)
            unique_commands = inputs.get("distinct_commands", 0)
    except Exception as e:
        log.warning("could not retrieve local metrics for %s: %s", ip_address, e)

    # Calculate Score (Preserving original team weighting logic)[cite: 1]
    score = external_abuse_score if external_abuse_score is not None else 0
    
    # Add weight for repeated connections (+5 per session, max +25)
    score += min(session_count * 5, 25)
    
    # Add weight for interactive commands (+2 per unique command, max +25)
    score += min(unique_commands * 2, 25)
    
    # Ensure score stays within the 0-100 boundary dictated by Baseline v1.3[cite: 3]
    return min(max(int(score), 0), 100)

def get_threat_intel(ip_address, db=None, db_path=None):
    """
    Takes an attacker IP, checks local cache, queries an API,
    and returns a record matching Team Baseline FINAL v1.3[cite: 1, 3].
    """
    # Current time in strict ISO 8601 UTC format using timezone-aware objects[cite: 3]
    current_utc_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if ip_address.startswith("127.") or ip_address.startswith("172."):
        return {
            "attacker_ip": ip_address,
            "country": "Local Lab",
            "city": "Internal Bridge",
            "latitude": None,
            "longitude": None,
            "abuse_score": 0,
            "source": "System Filter",
            "profile_score": 0,  # Clean baseline for local traffic[cite: 3]
            "last_updated": current_utc_time
        }

    if ip_address in IP_CACHE:
        log.debug("cache hit — pulling profile for %s from memory", ip_address)
        return IP_CACHE[ip_address]

    log.info("fetching baseline threat intel for %s", ip_address)
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,country,city,lat,lon"
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") == "success":
            # Simulate/calculate external abuse score (0-100)[cite: 1, 3]
            mock_external_abuse = 45

            # Calculate team profiling score dynamically via Part 4 database metrics[cite: 1, 4]
            calculated_profile_score = calculate_dynamic_profile_score(
                ip_address, 
                mock_external_abuse, 
                db=db,
                db_path=db_path
            )

            intel_record = {
                "attacker_ip": ip_address,
                "country": data.get("country", None),
                "city": data.get("city", None),
                "latitude": data.get("lat", None),
                "longitude": data.get("lon", None),
                "abuse_score": mock_external_abuse,
                "source": "ip-api / custom",
                "profile_score": calculated_profile_score,
                "last_updated": current_utc_time
            }
            IP_CACHE[ip_address] = intel_record
            return intel_record

    except Exception as e:
        log.error("threat intelligence lookup failed for %s: %s", ip_address, e)

    # Fallback record utilizing NULL (None) for nullable fields as permitted in v1.3[cite: 3]
    return {
        "attacker_ip": ip_address,
        "country": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "abuse_score": None,
        "source": "Error Fallback",
        "profile_score": 0,
        "last_updated": current_utc_time
    }

def save_reputation_to_db(intel_record, db=None, db_path=None):
    """
    Writes the enriched profile cleanly into the Baseline FINAL v1.3 reputation table[cite: 1, 3]
    using Part 4's shared Database interface[cite: 4].
    """
    try:
        # Initialize Part 4 Database connection if not provided[cite: 4]
        if db is None and Database is not None:
            db = Database(db_path) if db_path else Database()

        if db is not None:
            # Call Part 4's shared upsert_reputation helper function[cite: 4, 5]
            db.upsert_reputation(
                attacker_ip=intel_record['attacker_ip'],
                country=intel_record['country'],
                city=intel_record['city'],
                latitude=intel_record['latitude'],
                longitude=intel_record['longitude'],
                abuse_score=intel_record['abuse_score'],
                source=intel_record['source'],
                profile_score=intel_record['profile_score'],
                last_updated=intel_record['last_updated']
            )
            log.info("threat profile committed for %s", intel_record['attacker_ip'])
        else:
            log.error("Part 4 Database module not found")
    except Exception as e:
        log.error("out of sync with Baseline spec / Part 4 DB interface: %s", e)

def enrich_and_log_ip(ip_address, db=None, db_path=None):
    """
    The master pipeline entry point. Takes an incoming IP,
    fetches threat intel, and saves it via Part 4's database interface[cite: 1, 4].
    """
    if db is None and Database is not None:
        db = Database(db_path) if db_path else Database()

    # Step 1: Run the API/Cache enrichment engine[cite: 1]
    profile = get_threat_intel(ip_address, db=db, db_path=db_path)

    # Step 2: Write it directly using Part 4's shared Database interface[cite: 1, 4]
    save_reputation_to_db(profile, db=db, db_path=db_path)
    return profile

def run_worker_loop(interval_seconds=30, max_age_days=7, db_path=None, db=None,
                    stop_event=None):
    """
    Way 2 Execution: Runs continuously in the background, polling the database
    for un-enriched or stale attacker IPs and feeding them into our pipeline[cite: 5].

    Two callers, one loop:

    * standalone — `python enricher/enrich.py`, which opens its own connection;
    * `core/main.py serve`, which passes its own `db` so the whole aggregator
      shares one write lock, and a `stop_event` so Ctrl-C ends the loop
      immediately instead of after the remaining sleep.
    """
    log.info("enrichment worker started (interval %ss)", interval_seconds)

    # Connect to the central database, unless the caller already has a handle[cite: 4]
    if db is None:
        db = Database(db_path) if db_path else Database()
    if stop_event is None:
        stop_event = threading.Event()

    while not stop_event.is_set():
        try:
            # Step 1: Ask Part 4's DB which IPs need enrichment[cite: 4, 5]
            pending_ips = db.get_ips_needing_enrichment(max_age_days=max_age_days, limit=50)

            if pending_ips:
                log.info("found %d IP(s) needing enrichment", len(pending_ips))
                for ip in pending_ips:
                    if stop_event.is_set():
                        break
                    # Step 2: Feed each IP into our existing enrichment pipeline[cite: 1]
                    enrich_and_log_ip(ip, db=db, db_path=db_path)
            else:
                # Debug, not info: this fires every pass and would otherwise bury
                # the collector's logs when the two share a process.
                log.debug("no new IPs to enrich")

        except Exception as e:
            log.error("pass failed: %s", e)

        # Step 3: Wait for the specified interval before checking again[cite: 5]
        stop_event.wait(interval_seconds)

    log.info("enrichment worker stopped")

# Executes Way 2 background loop when run directly from the terminal[cite: 5]
# `main.py serve` runs this same loop in a thread; this entry point stays for
# running the enricher on its own.
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    try:
        # Runs continuously every 30 seconds as a background service[cite: 5]
        run_worker_loop(interval_seconds=30)
    except KeyboardInterrupt:
        log.info("stopped")
