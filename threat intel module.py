import requests
import json
import logging
from datetime import datetime, timezone

# Import Part 4's central Database API
try:
    from db.database import Database
except ImportError:
    Database = None

# Global cache dictionary to prevent API rate-limiting
IP_CACHE = {}

def calculate_dynamic_profile_score(ip_address, external_abuse_score, db=None, db_path=None):
    """
    Calculates a dynamic 0-100 profile score based on honeypot activity.
    Uses Part 4's db.get_attacker_profile_inputs() helper while retaining 
    our custom scoring weights.
    """
    session_count = 0
    unique_commands = 0

    try:
        # Initialize Part 4 Database connection if not provided
        if db is None and Database is not None:
            db = Database(db_path) if db_path else Database()

        if db is not None:
            # Query metrics using Part 4's shared reader function
            inputs = db.get_attacker_profile_inputs(ip_address)
            session_count = inputs.get("session_count", 0)
            unique_commands = inputs.get("distinct_commands", 0)
    except Exception as e:
        print(f"[WARNING] Could not retrieve local metrics for {ip_address}: {e}")

    # Calculate Score (Preserving original team weighting logic)
    score = external_abuse_score if external_abuse_score is not None else 0
    
    # Add weight for repeated connections (+5 per session, max +25)
    score += min(session_count * 5, 25)
    
    # Add weight for interactive commands (+2 per unique command, max +25)
    score += min(unique_commands * 2, 25)
    
    # Ensure score stays within the 0-100 boundary dictated by Baseline v1.3
    return min(max(int(score), 0), 100)

def get_threat_intel(ip_address, db=None, db_path=None):
    """
    Takes an attacker IP, checks local cache, queries an API,
    and returns a record matching Team Baseline FINAL v1.3.
    """
    # Current time in strict ISO 8601 UTC format using timezone-aware objects
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
            "profile_score": 0,  # Clean baseline for local traffic
            "last_updated": current_utc_time
        }

    if ip_address in IP_CACHE:
        print(f"[CACHE HIT] Pulling profile for {ip_address} from memory.")
        return IP_CACHE[ip_address]

    print(f"[API REQUEST] Fetching baseline threat intel for {ip_address}...")
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,country,city,lat,lon"
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") == "success":
            # Simulate/calculate external abuse score (0-100)
            mock_external_abuse = 45

            # Calculate team profiling score dynamically via Part 4 database metrics
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
        print(f"[ERROR] Threat intelligence lookup failed: {e}")

    # Fallback record utilizing NULL (None) for nullable fields as permitted in v1.3
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
    Writes the enriched profile cleanly into the Baseline FINAL v1.3 reputation table
    using Part 4's shared Database interface.
    """
    try:
        # Initialize Part 4 Database connection if not provided
        if db is None and Database is not None:
            db = Database(db_path) if db_path else Database()

        if db is not None:
            # Call Part 4's shared upsert_reputation helper function
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
            print(f"✅ [V1.3 DB SUCCESS] Threat profile committed for IP: {intel_record['attacker_ip']}")
        else:
            print("❌ [DB ERROR] Part 4 Database module not found.")
    except Exception as e:
        print(f"❌ [DB ERROR] Out of sync with Baseline spec / Part 4 DB interface: {e}")

def enrich_and_log_ip(ip_address, db=None, db_path=None):
    """
    The master pipeline entry point. Takes an incoming IP,
    fetches threat intel, and saves it via Part 4's database interface.
    """
    if db is None and Database is not None:
        db = Database(db_path) if db_path else Database()

    # Step 1: Run the API/Cache enrichment engine
    profile = get_threat_intel(ip_address, db=db, db_path=db_path)

    # Step 2: Write it directly using Part 4's shared Database interface
    save_reputation_to_db(profile, db=db, db_path=db_path)
    return profile

# Keep a clean test runner at the bottom for verification
if __name__ == "__main__":
    print("Testing master pipeline execution with Part 4 DB integration...")
    enrich_and_log_ip("185.156.74.65")
