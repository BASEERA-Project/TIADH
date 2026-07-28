"""
tests/test_part4.py — Regression suite for Part 4.

    python -m unittest discover -s tests -v

Uses only the standard library, so it runs anywhere Python 3.10+ does. Each test
builds its own temporary database; nothing touches the real one.

The tests worth reading before you change anything are the idempotency and
out-of-order ones. Those encode the two assumptions the rest of the team relies
on: an event replayed after a retry must not be counted twice, and events that
arrive in the wrong order must still produce a correct `sessions` row.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
from alerting.alert_engine import AlertEngine  # noqa: E402
from alerting.rules import classify_command  # noqa: E402
from db.database import Database, ValidationError  # noqa: E402
from db.validation import (  # noqa: E402
    deterministic_event_id,
    normalize_timestamp,
    rebase_events,
    validate_event,
)
from export.exporter import FeedExporter, SecretLeakError, assert_no_secrets, scrub  # noqa: E402


def ts(offset_seconds: int = 0) -> str:
    """A valid v1.3 timestamp, `offset_seconds` before now."""
    moment = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(**overrides):
    """A minimal valid event; override any field."""
    event = {
        "event_id": str(uuid.uuid4()),
        "node_id": "node-01",
        "event_type": "login_attempt",
        "timestamp": ts(),
        "session_id": "node-01:test01",
        "attacker_ip": "203.0.113.10",
        "protocol": "ssh",
        "details": {"username": "root", "password": "123456"},
    }
    event.update(overrides)
    return event


class BaseCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(path=Path(self._tmp.name) / "test.db")
        self.db.initialize_schema()

    def tearDown(self):
        self.db.close()
        self._tmp.cleanup()


# ==========================================================================
# The Baseline v1.3 contract
# ==========================================================================

class TestValidation(unittest.TestCase):
    def test_valid_event_passes(self):
        ok, errors = validate_event(make_event())
        self.assertTrue(ok, errors)

    def test_omitted_field_is_not_the_same_as_null(self):
        event = make_event()
        del event["protocol"]
        ok, errors = validate_event(event)
        self.assertFalse(ok)
        self.assertIn("protocol", errors[0])

    def test_heartbeat_requires_nulls(self):
        good = make_event(
            event_type="heartbeat",
            session_id=None,
            attacker_ip=None,
            protocol=None,
            details={"status": "online", "agent_version": "1.0.0"},
        )
        self.assertTrue(validate_event(good)[0])

        bad = dict(good, attacker_ip="203.0.113.10")
        ok, errors = validate_event(bad)
        self.assertFalse(ok)
        self.assertTrue(any("heartbeat" in e for e in errors))

    def test_non_heartbeat_rejects_nulls(self):
        ok, errors = validate_event(make_event(attacker_ip=None))
        self.assertFalse(ok)
        self.assertTrue(any("attacker_ip" in e for e in errors))

    def test_unknown_event_type_rejected(self):
        self.assertFalse(validate_event(make_event(event_type="port_scan"))[0])

    def test_details_must_be_an_object(self):
        for value in (None, "string", 42, []):
            self.assertFalse(validate_event(make_event(details=value))[0], value)

    def test_details_keys_are_whitelisted(self):
        ok, errors = validate_event(
            make_event(details={"username": "root", "password": "x", "shell": "/bin/sh"})
        )
        self.assertFalse(ok)
        self.assertTrue(any("shell" in e for e in errors))

    def test_login_attempt_allows_null_password_but_not_null_username(self):
        self.assertTrue(validate_event(make_event(details={"username": "root", "password": None}))[0])
        self.assertFalse(validate_event(make_event(details={"username": None}))[0])

    def test_file_download_needs_url_or_hash(self):
        base = {"event_type": "file_download"}
        self.assertFalse(
            validate_event(make_event(**base, details={"file_name": "x.sh"}))[0]
        )
        self.assertTrue(
            validate_event(make_event(**base, details={"download_url": "http://x.invalid/a"}))[0]
        )
        self.assertTrue(validate_event(make_event(**base, details={"file_hash": "ab12"}))[0])

    def test_no_extra_top_level_fields(self):
        ok, errors = validate_event(make_event(username="root"))
        self.assertFalse(ok)
        self.assertTrue(any("details" in e for e in errors))

    def test_timestamp_format_enforced(self):
        for bad in ("19/07/2026 15:05", "2026-07-19 15:00:00", "2026-07-19T15:00:00+03:00"):
            self.assertFalse(validate_event(make_event(timestamp=bad))[0], bad)

    def test_fractional_seconds_are_normalized(self):
        # Cowrie emits microseconds; every stored timestamp must be the same width
        # or SQLite's string comparisons stop matching chronological order.
        self.assertEqual(normalize_timestamp("2026-07-19T15:00:00.123456Z"),
                         "2026-07-19T15:00:00Z")

    def test_deterministic_event_id_is_stable(self):
        args = ("node-01", "node-01:abc", "2026-07-19T15:00:00Z", "cowrie.command.input#4")
        self.assertEqual(deterministic_event_id(*args), deterministic_event_id(*args))
        self.assertNotEqual(
            deterministic_event_id(*args),
            deterministic_event_id("node-02", *args[1:]),
        )

    def test_rebase_survives_a_malformed_timestamp(self):
        events = [make_event(timestamp="2020-01-01T00:00:00Z"), make_event(timestamp="garbage")]
        rebased = rebase_events(events)
        self.assertNotEqual(rebased[0]["timestamp"], "2020-01-01T00:00:00Z")
        self.assertEqual(rebased[1]["timestamp"], "garbage")


# ==========================================================================
# Storage behaviour
# ==========================================================================

class TestStorage(BaseCase):
    def test_apply_event_writes_event_session_and_node(self):
        self.db.apply_event(make_event())
        self.assertEqual(len(self.db.query("SELECT * FROM events")), 1)
        self.assertEqual(len(self.db.query("SELECT * FROM sessions")), 1)
        self.assertEqual(self.db.get_nodes()[0]["status"], "online")

    def test_duplicate_event_id_is_ignored(self):
        event = make_event()
        self.assertEqual(self.db.apply_event(event), "accepted")
        self.assertEqual(self.db.apply_event(event), "duplicate")
        self.assertEqual(len(self.db.query("SELECT * FROM events")), 1)

    def test_invalid_event_raises_with_reasons(self):
        with self.assertRaises(ValidationError) as ctx:
            self.db.apply_event(make_event(event_type="nope"))
        self.assertTrue(ctx.exception.errors)

    def test_batch_isolates_failures(self):
        result = self.db.apply_events(
            [make_event(), make_event(event_type="nope"), make_event()]
        )
        self.assertEqual(result["accepted"], 2)
        self.assertEqual(result["rejected"], 1)
        self.assertEqual(len(result["errors"]), 1)
        self.assertIn("reasons", result["errors"][0])

    def test_out_of_order_session_end_before_connection(self):
        """The retry case: an end event overtakes the connect event."""
        session = "node-01:ooo"
        self.db.apply_event(
            make_event(
                event_type="session_end",
                session_id=session,
                timestamp=ts(0),
                details={"status": "closed", "duration_seconds": 30},
            )
        )
        self.db.apply_event(
            make_event(
                event_type="connection",
                session_id=session,
                timestamp=ts(30),
                details={"destination_port": 22},
            )
        )

        row = self.db.query_one("SELECT * FROM sessions WHERE session_id = ?", (session,))
        self.assertEqual(row["status"], "closed", "a late connect must not reopen the session")
        self.assertLess(row["start_time"], row["end_time"], "start must precede end")

    def test_last_seen_never_moves_backwards(self):
        self.db.apply_event(make_event(timestamp=ts(0)))
        self.db.apply_event(make_event(timestamp=ts(600)))
        node = self.db.get_nodes()[0]
        self.assertEqual(node["last_seen"], ts(0))

    def test_reputation_source_accumulates(self):
        self.db.upsert_reputation("203.0.113.10", country="NL", source="GeoLite2")
        self.db.upsert_reputation("203.0.113.10", abuse_score=90, source="AbuseIPDB")
        row = self.db.get_reputation("203.0.113.10")
        self.assertEqual(row["source"], "GeoLite2,AbuseIPDB")
        self.assertEqual(row["country"], "NL", "geo data must survive the second write")
        self.assertEqual(row["abuse_score"], 90)

    def test_enrichment_queue_skips_private_ips(self):
        self.db.apply_event(make_event(attacker_ip="192.168.1.50"))
        self.db.apply_event(make_event(event_id=str(uuid.uuid4()), attacker_ip="203.0.113.10"))
        pending = self.db.get_ips_needing_enrichment()
        self.assertIn("203.0.113.10", pending)
        self.assertNotIn("192.168.1.50", pending)

    def test_documentation_ranges_are_enrichable(self):
        """
        Guards a trap that would silently break Part 3.

        Python reports the RFC 5737 documentation ranges as `is_private`, and the
        baseline uses 203.0.113.10 everywhere. A naive is_private filter would
        drop every fixture IP and Part 3 would look broken for no reason.
        """
        from db.database import is_documentation_ip

        for ip in ("203.0.113.10", "192.0.2.77", "198.51.100.5"):
            self.assertTrue(is_documentation_ip(ip), ip)
            self.db.apply_event(
                make_event(event_id=str(uuid.uuid4()), attacker_ip=ip, session_id=f"node-01:{ip}")
            )

        pending = self.db.get_ips_needing_enrichment()
        for ip in ("203.0.113.10", "192.0.2.77", "198.51.100.5"):
            self.assertIn(ip, pending)

        self.assertFalse(is_documentation_ip("8.8.8.8"))

    def test_commands_view_extracts_command_text(self):
        self.db.apply_event(make_event(event_type="command", details={"command": "uname -a"}))
        rows = self.db.get_session_commands("node-01:test01")
        self.assertEqual(rows[0]["command_text"], "uname -a")

    def test_stale_nodes_go_offline(self):
        self.db.apply_event(make_event(timestamp=ts(0)))
        self.assertEqual(self.db.mark_stale_nodes_offline(timeout_seconds=3600), 0)
        self.assertEqual(self.db.mark_stale_nodes_offline(timeout_seconds=0), 1)
        self.assertEqual(self.db.get_nodes()[0]["status"], "offline")


# ==========================================================================
# Detection
# ==========================================================================

class TestAlerting(BaseCase):
    def _brute_force(self, ip="203.0.113.10", count=None):
        count = count or config.BRUTE_FORCE_THRESHOLD
        for i in range(count):
            self.db.apply_event(
                make_event(
                    attacker_ip=ip,
                    session_id=f"node-01:{ip}",
                    timestamp=ts(count - i),
                    details={"username": "root", "password": f"pw{i}"},
                )
            )

    def test_brute_force_fires_at_threshold(self):
        self._brute_force()
        summary = AlertEngine(db=self.db, enabled_rules=["brute_force"]).run_once()
        self.assertEqual(summary["alerts_created"], 1)

    def test_brute_force_silent_below_threshold(self):
        self._brute_force(count=config.BRUTE_FORCE_THRESHOLD - 1)
        summary = AlertEngine(db=self.db, enabled_rules=["brute_force"]).run_once()
        self.assertEqual(summary["alerts_created"], 0)

    def test_repeated_passes_do_not_duplicate_alerts(self):
        """The single most important property: the engine is safe to re-run."""
        self._brute_force()
        engine = AlertEngine(db=self.db, enabled_rules=["brute_force"])
        first = engine.run_once()
        second = engine.run_once()
        self.assertEqual(first["alerts_created"], 1)
        self.assertEqual(second["alerts_created"], 0)
        self.assertEqual(second["suppressed"], second["findings"])
        self.assertEqual(len(self.db.get_alerts()), 1)

    def test_high_risk_ip_from_either_score(self):
        self.db.apply_event(make_event())
        self.db.upsert_reputation("203.0.113.10", abuse_score=90, source="AbuseIPDB")
        self.assertEqual(
            AlertEngine(db=self.db, enabled_rules=["high_risk_ip"]).run_once()["alerts_created"], 1
        )

        self.db.apply_event(make_event(attacker_ip="192.0.2.5", session_id="node-01:x"))
        self.db.upsert_reputation("192.0.2.5", profile_score=88, source="local")
        alerts = self.db.get_alerts(severity="high")
        AlertEngine(db=self.db, enabled_rules=["high_risk_ip"]).run_once()
        self.assertGreater(len(self.db.get_alerts(severity="high")), len(alerts))

    def test_suspicious_command_patterns(self):
        self.assertEqual(classify_command("wget http://x.invalid/a")[0], "high")
        self.assertEqual(classify_command("chmod +x /tmp/p")[0], "high")
        self.assertEqual(classify_command("rm -rf /tmp/p")[0], "high")
        self.assertEqual(classify_command("curl -O http://x.invalid/a")[0], "high")
        self.assertEqual(classify_command("uname -a")[0], "low")
        self.assertIsNone(classify_command("cd /var/www"))
        self.assertIsNone(classify_command(""))

    def test_suspicious_command_creates_one_alert_per_command(self):
        for i, cmd in enumerate(["wget http://x.invalid/a", "chmod +x a", "rm -rf /tmp/a"]):
            self.db.apply_event(
                make_event(event_type="command", timestamp=ts(10 - i), details={"command": cmd})
            )
        summary = AlertEngine(db=self.db, enabled_rules=["suspicious_command"]).run_once()
        self.assertEqual(summary["alerts_created"], 3, "each distinct command is its own finding")

    def test_multi_node_scan_needs_two_sensors(self):
        self.db.apply_event(make_event(node_id="node-01", session_id="node-01:a"))
        engine = AlertEngine(db=self.db, enabled_rules=["multi_node_scan"])
        self.assertEqual(engine.run_once()["alerts_created"], 0)

        self.db.apply_event(make_event(node_id="node-02", session_id="node-02:a"))
        self.assertEqual(engine.run_once()["alerts_created"], 1)

    def test_post_auth_activity(self):
        session = "node-01:owned"
        self.db.apply_event(
            make_event(
                event_type="login_success", session_id=session, timestamp=ts(20),
                details={"username": "root"},
            )
        )
        self.db.apply_event(
            make_event(
                event_type="command", session_id=session, timestamp=ts(10),
                details={"command": "ls"},
            )
        )
        summary = AlertEngine(db=self.db, enabled_rules=["post_auth_activity"]).run_once()
        self.assertEqual(summary["alerts_created"], 1)

    def test_unknown_rule_name_is_ignored_not_fatal(self):
        engine = AlertEngine(db=self.db, enabled_rules=["brute_force", "does_not_exist"])
        self.assertEqual(list(engine.rules), ["brute_force"])

    def test_alert_status_transitions(self):
        self._brute_force()
        AlertEngine(db=self.db, enabled_rules=["brute_force"]).run_once()
        alert_id = self.db.get_alerts()[0]["alert_id"]
        self.assertTrue(self.db.set_alert_status(alert_id, "acknowledged"))
        self.assertEqual(self.db.get_alerts(status="acknowledged")[0]["alert_id"], alert_id)


# ==========================================================================
# Export and the masking guarantee
# ==========================================================================

class TestExport(BaseCase):
    def setUp(self):
        super().setUp()
        for i in range(config.BRUTE_FORCE_THRESHOLD + 2):
            self.db.apply_event(
                make_event(
                    timestamp=ts(20 - i),
                    details={"username": "root", "password": "hunter2"},
                )
            )
        self.db.upsert_reputation(
            "203.0.113.10", country="NL", city="Amsterdam",
            latitude=52.36, longitude=4.90, abuse_score=92, source="AbuseIPDB",
        )
        AlertEngine(db=self.db).run_once()
        self.exporter = FeedExporter(db=self.db, output_dir=Path(self._tmp.name) / "out")

    def test_scrub_masks_nested_passwords(self):
        scrubbed = scrub({"a": {"password": "hunter2"}, "b": [{"pwd": "x"}]})
        self.assertEqual(scrubbed["a"]["password"], config.MASK)
        self.assertEqual(scrubbed["b"][0]["pwd"], config.MASK)

    def test_assert_no_secrets_raises_on_a_leak(self):
        with self.assertRaises(SecretLeakError):
            assert_no_secrets({"sessions": [{"password": "hunter2"}]})
        assert_no_secrets({"sessions": [{"password": config.MASK}]})
        assert_no_secrets({"sessions": [{"password": None}]})

    def test_password_never_appears_in_any_export(self):
        self.exporter.export_json()
        self.exporter.export_csv()
        self.exporter.export_stix()
        for path in self.exporter.output_dir.iterdir():
            self.assertNotIn(
                "hunter2", path.read_text(encoding="utf-8"), f"credential leaked into {path.name}"
            )

    def test_password_is_still_retained_locally(self):
        row = self.db.query_one("SELECT password FROM sessions LIMIT 1")
        self.assertEqual(row["password"], "hunter2", "the baseline keeps credentials in SQLite")
        masked = self.db.get_sessions()[0]
        self.assertEqual(masked["password"], config.MASK, "but the read helper masks them")

    def test_json_feed_shape(self):
        feed = json.loads(self.exporter.export_json().read_text(encoding="utf-8"))
        self.assertIn("feed", feed)
        self.assertIn("indicators", feed)
        self.assertEqual(feed["feed"]["schema_version"], config.SCHEMA_VERSION)
        self.assertGreaterEqual(feed["feed"]["counts"]["indicators"], 1)
        indicator = feed["indicators"][0]
        self.assertEqual(indicator["attacker_ip"], "203.0.113.10")
        self.assertLessEqual(indicator["confidence"], 100)

    def test_csv_is_written_with_headers(self):
        paths = self.exporter.export_csv()
        self.assertEqual(len(paths), 2)
        header = paths[0].read_text(encoding="utf-8").splitlines()[0]
        self.assertIn("attacker_ip", header)

    def test_stix_bundle_is_well_formed(self):
        bundle = json.loads(self.exporter.export_stix().read_text(encoding="utf-8"))
        self.assertEqual(bundle["type"], "bundle")
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        self.assertTrue(indicators)
        self.assertEqual(indicators[0]["spec_version"], "2.1")
        self.assertTrue(indicators[0]["pattern"].startswith("[ipv4-addr:value = "))

    def test_min_severity_filters_the_feed(self):
        everything = self.exporter.build_feed(min_severity="low")
        only_high = self.exporter.build_feed(min_severity="high")
        self.assertGreaterEqual(
            everything["feed"]["counts"]["alerts"], only_high["feed"]["counts"]["alerts"]
        )


class TestReadOnlyHandle(BaseCase):
    def test_read_only_handle_cannot_write(self):
        """Part 5 opens the database like this; it must be structurally unable to lock it."""
        self.db.apply_event(make_event())
        reader = Database(path=self.db.path, read_only=True)
        self.assertEqual(len(reader.query("SELECT * FROM events")), 1)
        with self.assertRaises(Exception):
            with reader.transaction():
                pass
        reader.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
