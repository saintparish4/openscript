from __future__ import annotations

import os
from collections.abc import AsyncIterator

from dotenv import load_dotenv
load_dotenv()
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import Depends, FastAPI, Query
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import create_async_engine

from contracts.server_types import EventType
from contracts.session_graph import SessionGraph
from events.store import EventStore
from server.auth import require_api_key
from server.routers import sessions as sessions_router
from server.routers import sse as sse_router
from server.routers import threat as threat_router

logger = structlog.get_logger(__name__)

_STATIC_DIR = Path(__file__).parent / "static" / "dashboard"


def _database_url() -> str:
    return os.environ.get(
        "DATABASE_URL", "postgresql+asyncpg://openscript:openscript@localhost:5432/openscript"
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    db_url = _database_url()
    engine = create_async_engine(db_url, pool_size=10, max_overflow=20)
    app.state.engine = engine
    app.state.event_store = EventStore(engine)
    logger.info("server_started", database=db_url.split("@")[-1])
    yield
    await engine.dispose()
    logger.info("server_stopped")


app = FastAPI(title="OpenScript Server", version="0.1.0", lifespan=lifespan)

# Routers
app.include_router(threat_router.router)
app.include_router(sessions_router.router)
app.include_router(sse_router.router)

# Dashboard static files — served at /dashboard/
if _STATIC_DIR.exists():
    app.mount(
        "/dashboard",
        StaticFiles(directory=str(_STATIC_DIR), html=True),
        name="dashboard",
    )


def _get_event_store() -> EventStore:
    return app.state.event_store


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/events/{session_id}", dependencies=[Depends(require_api_key)])
async def get_events(
    session_id: str,
    event_type: EventType | None = None,
    after_sequence: int | None = None,
    limit: int = Query(default=1000, le=10_000),
    store: EventStore = Depends(_get_event_store),
) -> dict:
    event_types = [event_type] if event_type else None
    events = await store.get_events(
        session_id=session_id,
        event_types=event_types,
        after_sequence=after_sequence,
        limit=limit,
    )
    return {
        "session_id": session_id,
        "count": len(events),
        "events": [e.model_dump(mode="json") for e in events],
    }


@app.get("/sessions/{session_id}/graph", dependencies=[Depends(require_api_key)])
async def get_session_graph(
    session_id: str,
    store: EventStore = Depends(_get_event_store),
) -> dict:
    graph = await SessionGraph.from_store(session_id, store)
    return {
        "session_id": session_id,
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "nodes": [
            {"id": n.id, "node_type": n.node_type, "sequence_num": n.event.sequence_num}
            for n in sorted(graph.nodes.values(), key=lambda n: n.event.sequence_num)
        ],
        "edges": [
            {"source": e.source_id, "target": e.target_id, "type": e.edge_type} for e in graph.edges
        ],
    }
