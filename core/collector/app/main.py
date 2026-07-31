"""
main.py — FastAPI collector for Part 2.

This is the HTTP entry point that honeypot nodes talk to. On every request
it validates the event batch against Baseline v1.3, then hands the raw events
to the shared Database in `common` via app/database.py.

Background maintenance
----------------------
The storage contract (common/db/database.py) explicitly assigns two
housekeeping tasks to Part 2 (the only always-running service):

    mark_stale_nodes_offline()  — flip nodes offline after missed heartbeats
    close_stale_sessions()      — force-close abandoned sessions

These run in a background asyncio task every MAINTENANCE_INTERVAL_SECONDS
(default 60 s). The task starts on app startup and is cancelled on shutdown.
"""

from __future__ import annotations

import asyncio
import logging

from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, HTTPException, status

from .config import get_settings
from .database import get_node, initialise, ingest, run_maintenance
from .models import BatchResult, EventBatch

log = logging.getLogger(__name__)
settings = get_settings()


async def _maintenance_loop(interval: int) -> None:
    """Run housekeeping on a timer. Never raises — a bad pass is only logged."""
    while True:
        await asyncio.sleep(interval)
        try:
            run_maintenance()
        except Exception:  # noqa: BLE001
            log.exception("maintenance pass failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initialise DB and launch maintenance loop. Shutdown: cancel it."""
    initialise()
    task = asyncio.create_task(_maintenance_loop(settings.maintenance_interval))
    log.info(
        "collector started — maintenance every %ds",
        settings.maintenance_interval,
    )
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="Distributed Honeypot Collector",
    version="2.0.0",
    lifespan=lifespan,
)


def authenticate(header_node_id: str | None, node_key: str | None) -> str:
    if not header_node_id or not node_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing node credentials",
        )
    expected_key = settings.node_keys.get(header_node_id)
    if expected_key is None or node_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid node credentials",
        )
    return header_node_id


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/nodes/{node_id}")
def node_status(node_id: str):
    node = get_node(node_id)
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
        raise HTTPException(
            status_code=422,
            detail=f"Batch cannot exceed {settings.max_batch_size} events",
        )
    if any(event.node_id != header_node_id for event in batch.events):
        raise HTTPException(status_code=403, detail="Node ID mismatch")

    accepted, duplicates, rejected = ingest(batch.events)
    return BatchResult(accepted=accepted, duplicates=duplicates, rejected=rejected)
