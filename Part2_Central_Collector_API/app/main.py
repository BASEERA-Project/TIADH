from fastapi import FastAPI, Header, HTTPException, status
from .config import get_settings
from .database import get_node, ingest, initialise
from .models import BatchResult, EventBatch

settings = get_settings()
app = FastAPI(title="Distributed Honeypot Collector", version="1.0.0")

@app.on_event("startup")
def startup() -> None:
    initialise(settings.database_path)

def authenticate(header_node_id: str | None, node_key: str | None) -> str:
    if not header_node_id or not node_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing node credentials")
    expected_key = settings.node_keys.get(header_node_id)
    if expected_key is None or node_key != expected_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid node credentials")
    return header_node_id

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/api/nodes/{node_id}")
def node_status(node_id: str):
    node = get_node(settings.database_path, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    return node

@app.post("/api/events", response_model=BatchResult)
def receive_events(
    batch: EventBatch,
    x_node_id: str | None = Header(default=None),
    x_node_key: str | None = Header(default=None),
):
    header_node_id = authenticate(x_node_id, x_node_key)
    if len(batch.events) > settings.max_batch_size:
        raise HTTPException(status_code=422, detail=f"Batch cannot exceed {settings.max_batch_size} events")
    if any(event.node_id != header_node_id for event in batch.events):
        raise HTTPException(status_code=403, detail="Node ID mismatch")
    accepted, duplicates = ingest(settings.database_path, batch.events)
    return BatchResult(accepted=accepted, duplicates=duplicates, rejected=0)
