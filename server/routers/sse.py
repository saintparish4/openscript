from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from events.store import EventStore
from server.auth import require_api_key

router = APIRouter(tags=["streaming"])

_POLL_INTERVAL = 0.5  # seconds between EventStore polls
_KEEPALIVE_INTERVAL = 15  # seconds between SSE keepalive comments


def _get_event_store(request: Request) -> EventStore:
    return request.app.state.event_store  # type: ignore[no-any-return]


@router.get(
    "/events/{session_id}/stream",
    dependencies=[Depends(require_api_key)],
    response_class=StreamingResponse,
)
async def stream_events(
    session_id: str,
    after_sequence: int = Query(default=0, ge=0),
    store: EventStore = Depends(_get_event_store),
) -> StreamingResponse:
    """Server-Sent Events stream for a session.

    Clients pass ?after_sequence=N to resume from a known position.
    The server polls EventStore every 0.5 s and pushes new events.
    A keepalive comment is emitted every 15 s to prevent proxy timeouts.
    """

    async def _generate():
        cursor = after_sequence
        keepalive_ticks = 0

        while True:
            events = await store.get_events(
                session_id=session_id,
                after_sequence=cursor,
                limit=100,
            )

            for event in events:
                data = json.dumps(event.model_dump(mode="json"))
                yield f"data: {data}\n\n"
                cursor = max(cursor, event.sequence_num)

            keepalive_ticks += 1
            if keepalive_ticks * _POLL_INTERVAL >= _KEEPALIVE_INTERVAL:
                yield ": keepalive\n\n"
                keepalive_ticks = 0

            await asyncio.sleep(_POLL_INTERVAL)

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
