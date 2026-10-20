from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from contracts.types import ActionBlockedError, ActionContext
from server.auth import require_api_key
from server.guard import SECTIONS, Checkpoint

router = APIRouter(prefix="/v1", tags=["guard"])


class GuardRequest(BaseModel):
    """One phase of one action, asked by a client that runs the action itself."""

    phase: Literal["input", "output"]
    #: "invoke" for an agent's input and output, "tool_call" for a tool's
    #: {"name", "args"} and its result. The two go to different policy lists.
    action: Literal["invoke", "tool_call"]
    session_id: str = "default"
    agent_id: str = "default"
    input: dict[str, Any]
    #: Required for phase "output": what the agent or tool returned.
    output: dict[str, Any] | None = None
    #: The caller's role, for tool rules restricted by role.
    role: str | None = None
    #: An approved approval to redeem in the input phase.
    approval_id: str = ""


class GuardResponse(BaseModel):
    decision: Literal["allow", "deny", "require_approval"]
    reason: str = ""
    blocked_by: str = ""
    #: Set when decision is "require_approval": decide it through
    #: /v1/approvals, then ask again with it.
    approval_id: str = ""
    #: The input as the policies left it. Give the agent or tool this, not
    #: what was sent: a redacting policy replaces what it redacts.
    input: dict[str, Any]
    #: The output as the policies left it (phase "output" only).
    output: dict[str, Any] | None = None
    risk_score: float = 0.0
    risk_categories: dict[str, float] = Field(default_factory=dict)
    #: What each policy wrote about this phase, keyed by its category.
    findings: dict[str, Any] = Field(default_factory=dict)


def _checkpoint(request: Request, action: str) -> Checkpoint:
    checkpoints: dict[str, Checkpoint] | None = getattr(request.app.state, "guard", None)
    if not checkpoints:
        raise HTTPException(
            status_code=503,
            detail="no policies configured; start the server with OPENSCRIPT_GUARD_CONFIG",
        )
    checkpoint = checkpoints.get(action)
    if checkpoint is None:
        raise HTTPException(
            status_code=503,
            detail=f"the guard config has no '{SECTIONS[action]}' section for action '{action}'",
        )
    return checkpoint


def _response(
    context: ActionContext,
    phase: str,
    decision: str,
    blocked_by: str = "",
    approval_id: str = "",
) -> GuardResponse:
    findings = {
        key: value
        for key, value in context.metadata.items()
        if isinstance(value, dict) and ("risk" in value or "category" in value)
    }
    return GuardResponse(
        decision=decision,  # type: ignore[arg-type]
        reason=context.decision_reason,
        blocked_by=blocked_by,
        approval_id=approval_id,
        input=jsonable_encoder(context.input_data),
        # Withheld when refused: what a policy blocked is not handed back to be used.
        output=(
            jsonable_encoder(context.output_data)
            if phase == "output" and decision == "allow"
            else None
        ),
        risk_score=round(context.risk_score, 4),
        risk_categories=context.risk_categories,
        findings=jsonable_encoder(findings),
    )


@router.post("/guard", dependencies=[Depends(require_api_key)])
async def guard(req: GuardRequest, request: Request) -> GuardResponse:
    """Run one phase of the configured policies over an action the caller runs.

    A refusal is an answer, not an error: it comes back with status 200 and
    decision "deny" or "require_approval". A policy that fails closed is an
    error (500), and so is a server with nothing configured (503). A client
    must treat every error as a refusal.
    """
    checkpoint = _checkpoint(request, req.action)
    if req.phase == "output" and req.output is None:
        raise HTTPException(status_code=422, detail="phase 'output' needs 'output'")

    metadata: dict[str, Any] = {}
    if req.action == "tool_call":
        name, args = req.input.get("name"), req.input.get("args")
        if not isinstance(name, str) or not name or not isinstance(args, dict):
            raise HTTPException(
                status_code=422,
                detail="a tool_call's input is {'name': <tool>, 'args': {...}}",
            )
        # Every argument came from the caller: there are no defaults to tell apart.
        metadata["defaulted_args"] = []
    if req.role is not None:
        metadata["role"] = req.role

    context = ActionContext(
        action=req.action,
        agent_id=req.agent_id,
        session_id=req.session_id,
        input_data=req.input,
        output_data=req.output or {},
        metadata=metadata,
    )
    try:
        if req.phase == "input":
            context = await checkpoint.check_input(context, req.approval_id)
        else:
            context = await checkpoint.check_output(context)
    except ActionBlockedError as blocked:
        context = blocked.context or context
        decision = "require_approval" if blocked.approval_id else "deny"
        return _response(context, req.phase, decision, blocked.interceptor, blocked.approval_id)
    except RuntimeError as exc:
        # A FAIL_CLOSED policy that raised. The action is refused either way.
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return _response(context, req.phase, "allow")
