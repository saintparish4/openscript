from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import case, func, select

from contracts.server_types import EventType
from events.models import EventRow
from events.store import EventStore
from server.auth import require_api_key

router = APIRouter(prefix="/sessions", tags=["sessions"])


def _get_event_store(request: Request) -> EventStore:
    return request.app.state.event_store  # type: ignore[no-any-return]


@router.get("", dependencies=[Depends(require_api_key)])
async def list_sessions(store: EventStore = Depends(_get_event_store)) -> dict:
    """List all sessions with aggregate metadata."""
    async with store._session_factory() as session:
        stmt = (
            select(
                EventRow.session_id,
                func.count(EventRow.id).label("event_count"),
                func.max(EventRow.timestamp).label("last_activity"),
                func.sum(
                    case(
                        (EventRow.event_type == EventType.THREAT_DETECTED.value, 1),
                        else_=0,
                    )
                ).label("threat_count"),
            )
            .group_by(EventRow.session_id)
            .order_by(func.max(EventRow.timestamp).desc())
        )
        result = await session.execute(stmt)
        rows = result.all()

    sessions = [
        {
            "session_id": row.session_id,
            "event_count": row.event_count,
            "threat_count": int(row.threat_count or 0),
            "last_activity": row.last_activity.isoformat() if row.last_activity else None,
            "flagged": int(row.threat_count or 0) > 0,
        }
        for row in rows
    ]
    return {"count": len(sessions), "sessions": sessions}


@router.get("/{session_id}/stats", dependencies=[Depends(require_api_key)])
async def session_stats(
    session_id: str,
    store: EventStore = Depends(_get_event_store),
) -> dict:
    """Return per-event-type counts and threat info for a session."""
    events = await store.get_events(session_id=session_id, limit=10_000)

    type_counts: dict[str, int] = {}
    threat_scores: list[float] = []

    for event in events:
        type_counts[event.event_type.value] = type_counts.get(event.event_type.value, 0) + 1
        if event.event_type == EventType.THREAT_DETECTED:
            score = event.payload.get("score")
            if isinstance(score, (int, float)):
                threat_scores.append(float(score))

    return {
        "session_id": session_id,
        "event_count": len(events),
        "event_type_counts": type_counts,
        "threat_count": len(threat_scores),
        "max_threat_score": round(max(threat_scores), 4) if threat_scores else 0.0,
        "flagged": len(threat_scores) > 0,
        "first_event": events[0].timestamp.isoformat() if events else None,
        "last_event": events[-1].timestamp.isoformat() if events else None,
    }
