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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
