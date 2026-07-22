from .conftest import headers

LOGIN = {
  "event_id":"550e8400-e29b-41d4-a716-446655440000", "node_id":"node-01",
  "event_type":"login_attempt", "timestamp":"2026-07-22T11:00:00Z",
  "session_id":"cowrie-abc123", "attacker_ip":"203.0.113.10", "protocol":"ssh",
  "details":{"username":"root","password":"123456"}
}

def test_accepts_event_and_deduplicates(client):
    first = client.post("/api/events", headers=headers(), json={"events":[LOGIN]})
    assert first.status_code == 200
    assert first.json() == {"accepted":1,"duplicates":0,"rejected":0,"errors":[]}
    second = client.post("/api/events", headers=headers(), json={"events":[LOGIN]})
    assert second.status_code == 200
    assert second.json()["accepted"] == 0
    assert second.json()["duplicates"] == 1

def test_heartbeat_updates_node(client):
    heartbeat = {"event_id":"62b7a1c5-a20e-49e3-9eb2-111111111111","node_id":"node-01","event_type":"heartbeat","timestamp":"2026-07-22T11:05:00Z","session_id":None,"attacker_ip":None,"protocol":None,"details":{"status":"online"}}
    assert client.post("/api/events", headers=headers(), json={"events":[heartbeat]}).status_code == 200
    node = client.get("/api/nodes/node-01").json()
    assert node["status"] == "online"
    assert node["last_seen"] is not None

def test_rejects_bad_command_contract(client):
    event = LOGIN | {"event_id":"6a9e8400-e29b-41d4-a716-446655440000", "event_type":"command", "details":{}}
    response = client.post("/api/events", headers=headers(), json={"events":[event]})
    assert response.status_code == 422

def test_rejects_node_mismatch(client):
    response = client.post("/api/events", headers=headers("node-02", "key-02"), json={"events":[LOGIN]})
    assert response.status_code == 403

def test_rejects_bad_key(client):
    response = client.post("/api/events", headers=headers(key="wrong"), json={"events":[LOGIN]})
    assert response.status_code == 401

def test_session_end_updates_session(client):
    assert client.post("/api/events", headers=headers(), json={"events":[LOGIN]}).status_code == 200
    end = LOGIN | {"event_id":"7b9e8400-e29b-41d4-a716-446655440000", "event_type":"session_end", "timestamp":"2026-07-22T11:02:00Z", "details":{"status":"closed"}}
    assert client.post("/api/events", headers=headers(), json={"events":[end]}).status_code == 200
