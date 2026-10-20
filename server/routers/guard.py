from __future__ import annotations

import time
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
    #: "invoke" for an agent's input and output, "stream" for the same when
    #: the answer is streamed (SecureAgent.stream's action), "tool_call" for a
    #: tool's {"name", "args"} and its result. Tools go to a different list.
    action: Literal["invoke", "stream", "tool_call"]
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
    #: Time spent in the pipeline, measured inside the server, so a client can
    #: tell the policies' cost from the network's.
    pipeline_ms: float = 0.0
    #: Action "stream", phase "input" only: the guards that scan a guarded
    #: stream as it goes, and the tail a client must hold back for them.
    stream_guards: list[str] | None = None
    stream_window: int | None = None


class StreamScanRequest(BaseModel):
    """The text a client is holding back in a guarded stream, to be scanned."""

    session_id: str = "default"
    agent_id: str = "default"
    #: The input as the input phase left it. Only for the record of a refusal.
    input: dict[str, Any] = Field(default_factory=dict)
    #: The held tail plus whatever has arrived since.
    text: str
    #: True at the end of the stream: matches at the edge are now definite.
    final: bool = False


class StreamScanResponse(BaseModel):
    decision: Literal["allow", "deny"]
    #: The text as the guards left it (redacted); "" when denied.
    text: str = ""
    reason: str = ""
    blocked_by: str = ""
    labels: list[str] = Field(default_factory=list)
    risk: float = 0.0
    pipeline_ms: float = 0.0


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


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def _response(
    context: ActionContext,
    phase: str,
    decision: str,
    start: float,
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
        pipeline_ms=_ms(start),
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
    start = time.perf_counter()
    try:
        if req.phase == "input":
            context = await checkpoint.check_input(context, req.approval_id)
        else:
            context = await checkpoint.check_output(context)
    except ActionBlockedError as blocked:
        context = blocked.context or context
        decision = "require_approval" if blocked.approval_id else "deny"
        return _response(
            context, req.phase, decision, start, blocked.interceptor, blocked.approval_id
        )
    except RuntimeError as exc:
        # A FAIL_CLOSED policy that raised. The action is refused either way.
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    response = _response(context, req.phase, "allow", start)
    if req.action == "stream" and req.phase == "input":
        guards = checkpoint.stream_guards()
        response.stream_guards = [guard.name for guard in guards]
        # What SecureAgent holds back: no match a guard can make is longer.
        response.stream_window = max((guard.max_match_len for guard in guards), default=0)
    return response


@router.post("/guard/stream", dependencies=[Depends(require_api_key)])
async def guard_stream(req: StreamScanRequest, request: Request) -> StreamScanResponse:
    """Scan the held-back text of a guarded stream, as SecureAgent does per chunk.

    The client releases everything but the last stream_window characters of
    what comes back, and sends the rest again with the next chunk. A deny
    comes back as an answer with no text: nothing of the match is released.
    """
    checkpoint = _checkpoint(request, "stream")
    context = ActionContext(
        action="stream",
        agent_id=req.agent_id,
        session_id=req.session_id,
        input_data=req.input,
    )
    start = time.perf_counter()
    try:
        text = await checkpoint.scan_stream(context, req.text, req.final)
    except ActionBlockedError as blocked:
        found = context.metadata.get("stream_guard", {})
        return StreamScanResponse(
            decision="deny",
            reason=blocked.reason,
            blocked_by=blocked.interceptor,
            labels=found.get("labels", []),
            risk=found.get("risk", 0.0),
            pipeline_ms=_ms(start),
        )
    found = context.metadata.get("stream_guard", {})
    return StreamScanResponse(
        decision="allow",
        text=text,
        labels=found.get("labels", []),
        risk=found.get("risk", 0.0),
        pipeline_ms=_ms(start),
    )
