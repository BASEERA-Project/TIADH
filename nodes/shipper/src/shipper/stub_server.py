"""
stub_server.py — a collector-shaped thing to point a sensor at.

Stands in for Part 2 while testing an adapter on its own: it accepts any node
key, prints what it was sent, and answers the shape the baseline promises. It
validates nothing — use `validator.py` for that.

    uv run --extra stub stub_server.py
"""

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/api/events", methods=["POST"])
def receive_events():
    data = request.get_json()
    events = data.get("events", [])
    node_id = request.headers.get("X-Node-ID")
    node_key = request.headers.get("X-Node-Key")

    print(f"Received {len(events)} event(s) from {node_id} (key: {node_key})")
    for e in events:
        print(f"  - {e['event_type']} at {e['timestamp']}")

    return jsonify({"accepted": len(events), "duplicates": 0, "rejected": 0})


def main():
    app.run(host="0.0.0.0", port=5000)


if __name__ == "__main__":
    main()
