from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from contracts.server_types import Event, EventType
from events.approvals import ApprovalStore
from server.auth import require_api_key

router = APIRouter(prefix="/v1", tags=["approvals"])


class ApprovalDecisionRequest(BaseModel):
    approved: bool
    decided_by: str = ""


def _get_store(request: Request) -> ApprovalStore:
    return request.app.state.approval_store


@router.get("/approvals", dependencies=[Depends(require_api_key)])
async def list_pending_approvals(store: ApprovalStore = Depends(_get_store)) -> dict:
    """List approval records awaiting a human decision."""
    pending = await store.list_pending()
    return {
        "count": len(pending),
        "approvals": [record.to_dict() for record in pending],
    }


@router.post("/approvals/{approval_id}/decide", dependencies=[Depends(require_api_key)])
async def decide_approval(
    approval_id: str,
    req: ApprovalDecisionRequest,
    request: Request,
    store: ApprovalStore = Depends(_get_store),
) -> dict:
    """Approve or deny a pending approval and emit APPROVAL_RESOLVED."""
    try:
        record = await store.decide(approval_id, req.approved, req.decided_by)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail=f"approval '{approval_id}' not found")

    event_store = getattr(request.app.state, "event_store", None)
    if event_store is not None:
        await event_store.insert_events(
            [
                Event(
                    session_id=record.session_id,
                    agent_id=record.agent_id,
                    event_type=EventType.APPROVAL_RESOLVED,
                    payload={
                        "approval_id": record.approval_id,
                        "action": record.action,
                        "status": record.status.value,
                        "decided_by": record.decided_by,
                    },
                    sequence_num=0,  # decided outside the session's sequence
                )
            ]
        )

    return record.to_dict()
