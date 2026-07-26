#!/usr/bin/env python3
"""
integration_examples/part5_dashboard.py — for whoever has Part 5.

Every query a Streamlit dashboard needs, in a layer that runs and can be tested
without Streamlit installed. Build the UI on top of `DashboardData`; keep the
queries here so the dashboard stays testable and so nobody is tempted to write
`SELECT * FROM sessions` in a render function.

Two rules that matter:

* **Read-only handle.** `Database(read_only=True)` opens the file with
  `mode=ro`, so the dashboard is structurally incapable of taking a write lock
  and stalling ingestion. Not a convention — the OS enforces it.
* **Never query `sessions` directly.** `get_sessions()` reads the masked
  `sessions_public` view. Query the raw table and you will render plaintext
  passwords into a screen, a screenshot, and a CSV download button.

    python integration_examples/part5_dashboard.py          # text render of every panel
"""

from __future__ import annotations

import html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.database import Database
from export.exporter import FeedExporter


class DashboardData:
    """Read-only query layer. One method per dashboard panel."""

    def __init__(self, db: Database = None):
        # read_only=True is the important argument on this whole page.
        self.db = db or Database(read_only=True)

    # -- panels ---------------------------------------------------------

    def kpis(self) -> dict:
        return self.db.get_overview_stats()

    def node_health(self) -> list[dict]:
        return self.db.get_nodes()

    def sessions(self, limit: int = 200, status: str = None) -> list[dict]:
        return self.db.get_sessions(limit=limit, status=status)   # already masked

    def session_timeline(self, session_id: str) -> list[dict]:
        return self.db.get_session_commands(session_id)

    def attackers(self, limit: int = 20) -> list[dict]:
        return self.db.get_top_attackers(limit=limit)

    def map_points(self) -> list[dict]:
        return [
            {"lat": r["latitude"], "lon": r["longitude"], "ip": r["attacker_ip"],
             "country": r["country"], "weight": r["event_count"]}
            for r in self.db.get_top_attackers(limit=500)
            if r.get("latitude") is not None and r.get("longitude") is not None
        ]

    def alerts(self, status: str = "open", min_severity: str = "low") -> list[dict]:
        # Already joined to reputation — country, city, coords and both scores
        # come back on the alert row. No second query needed.
        return self.db.get_alerts(status=status, min_severity=min_severity, limit=500)

    def credentials(self, limit: int = 20) -> list[dict]:
        return self.db.get_top_credentials(limit=limit)   # usernames only, by design

    def feed_preview(self) -> dict:
        """Show what would be published, without writing a file."""
        return FeedExporter(db=self.db).build_feed()


# ---------------------------------------------------------------------------
# Writes
#
# Acknowledging an alert is a write, so it needs a separate writable handle.
# Keep it out of the cached read-only resource.
# ---------------------------------------------------------------------------

def acknowledge_alert(alert_id: str) -> bool:
    return Database().set_alert_status(alert_id, "acknowledged")


def close_alert(alert_id: str) -> bool:
    return Database().set_alert_status(alert_id, "closed")


# ---------------------------------------------------------------------------
# Rendering attacker-controlled text
# ---------------------------------------------------------------------------

def safe(text: str | None) -> str:
    """
    Escape before rendering anything an attacker typed.

    `description`, `command_text` and `download_url` all contain strings chosen
    by the attacker. st.dataframe and st.table escape for you. The moment anyone
    reaches for st.markdown(unsafe_allow_html=True), or swaps Streamlit for
    Flask/React with raw HTML, this becomes stored XSS in your own dashboard —
    delivered by the person you are monitoring. Never render download_url as a
    clickable link either.
    """
    return html.escape(text or "", quote=True)


# ---------------------------------------------------------------------------
# The Streamlit app this layer is built for
# ---------------------------------------------------------------------------

STREAMLIT_SKELETON = '''
import streamlit as st
from integration_examples.part5_dashboard import DashboardData, acknowledge_alert, safe

st.set_page_config(page_title="Honeypot TI Aggregator", layout="wide")

@st.cache_resource                       # one read-only handle for the session
def data():
    return DashboardData()

@st.cache_data(ttl=10)                   # 10s cache; the DB is not hit per rerun
def kpis():
    return data().kpis()

k = kpis()
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Events (1h)", k["events_last_hour"])
c2.metric("Unique attackers", k["unique_attackers"])
c3.metric("Active sessions", k["active_sessions"])
c4.metric("Nodes online", f'{k["nodes_online"]}/{k["nodes_total"]}')
c5.metric("Open alerts", k["open_alerts"], delta=f'{k["open_high_alerts"]} high')

st.caption(f'Ingest lag: {k["avg_ingest_lag_seconds"]}s')   # clock-skew canary

tab_alerts, tab_sessions, tab_map = st.tabs(["Alerts", "Sessions", "Map"])

with tab_alerts:
    severity = st.selectbox("Minimum severity", ["low", "medium", "high"], index=1)
    for a in data().alerts(min_severity=severity):
        with st.expander(f'[{a["severity"].upper()}] {a["alert_type"]} — {a["attacker_ip"]}'):
            st.text(a["description"])            # st.text never interprets markup
            if st.button("Acknowledge", key=a["alert_id"]):
                acknowledge_alert(a["alert_id"])
                st.rerun()

with tab_sessions:
    st.dataframe(data().sessions(limit=200))     # passwords already masked

with tab_map:
    points = data().map_points()
    if points:
        st.map([{"lat": p["lat"], "lon": p["lon"]} for p in points])
'''


# ---------------------------------------------------------------------------
# Text render, so the layer is verifiable without Streamlit
# ---------------------------------------------------------------------------

def main() -> None:
    d = DashboardData()

    print("=" * 72)
    print("DASHBOARD — KPI HEADER")
    print("=" * 72)
    for key, value in d.kpis().items():
        print(f"  {key:26} {value}")

    print("\nNODE HEALTH")
    for n in d.node_health():
        print(f"  {n['node_id']:10} {n['status']:8} last_seen={n['last_seen']}")

    print("\nSESSIONS  (note the password column)")
    print(f"  {'session_id':22} {'attacker_ip':16} {'user':10} {'password':14} {'status'}")
    for s in d.sessions(limit=8):
        print(f"  {s['session_id']:22} {str(s['attacker_ip']):16} "
              f"{str(s['username']):10} {str(s['password']):14} {s['status']}")

    print("\nTOP ATTACKERS")
    for a in d.attackers(limit=5):
        print(f"  {a['attacker_ip']:16} events={a['event_count']:<4} "
              f"nodes={a['node_count']} country={a['country']} "
              f"abuse={a['abuse_score']} profile={a['profile_score']}")

    print("\nMAP POINTS")
    for p in d.map_points():
        print(f"  {p['ip']:16} {p['lat']:>8.4f},{p['lon']:<9.4f} {p['country']} w={p['weight']}")

    print("\nOPEN ALERTS (medium+)")
    for a in d.alerts(min_severity="medium")[:8]:
        print(f"  [{a['severity'].upper():6}] {a['alert_type']:20} {a['description'][:64]}")

    print("\nMOST-TRIED USERNAMES")
    for c in d.credentials(limit=5):
        print(f"  {str(c['username']):16} attempts={c['attempts']} ips={c['distinct_ips']}")

    print("\nFEED PREVIEW")
    print(f"  {d.feed_preview()['feed']['counts']}")

    sessions = d.sessions(limit=50)
    busiest = max(sessions, key=lambda s: len(d.session_timeline(s["session_id"])), default=None)
    if busiest:
        print(f"\nCOMMAND TIMELINE — {busiest['session_id']}")
        for c in d.session_timeline(busiest["session_id"]):
            print(f"  {c['timestamp']}  {safe(c['command_text'])}")


if __name__ == "__main__":
    main()
