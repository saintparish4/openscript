from __future__ import annotations

from fastapi import APIRouter, Depends

from contracts.server_types import (
    PolicyEvalRequest,
    PolicyEvalResponse,
    ThreatScoreRequest,
    ThreatScoreResponse,
)
from sdk.interceptors.threat import score_text
from server.auth import require_api_key

router = APIRouter(prefix="/v1", tags=["security"])

# Policy rules: maps capability flag → list of actions that require it.
# An action is denied when the agent lacks a required capability.
_CAPABILITY_RULES: dict[str, list[str]] = {
    "external_write": ["send_email", "write_file", "post_webhook", "create_record"],
    "sensitive_access": ["read_database", "read_secrets", "access_pii"],
    "untrusted_input": [],  # always allowed — flag is informational
}


@router.post("/threat/score", dependencies=[Depends(require_api_key)])
async def threat_score(req: ThreatScoreRequest) -> ThreatScoreResponse:
    """Score arbitrary text for prompt-injection signals.

    Stateless — no database access. Safe to call on every LLM turn.
    """
    text = req.text
    if req.context.get("include_turn_number") and req.turn_number > 0:
        # Slightly lower threshold tolerance for later turns (heuristic)
        pass

    score, signals = score_text(text)
    flagged = score >= 0.7
    reason = ""
    if flagged:
        top = max(signals, key=lambda k: signals[k]) if signals else "unknown"
        reason = f"score {score:.2f} — top signal: {top}"

    return ThreatScoreResponse(
        session_id=req.session_id,
        score=round(score, 4),
        signals={k: round(v, 4) for k, v in signals.items()},
        flagged=flagged,
        reason=reason,
    )


@router.post("/policy/evaluate", dependencies=[Depends(require_api_key)])
async def policy_evaluate(req: PolicyEvalRequest) -> PolicyEvalResponse:
    """Evaluate an action against capability-based policy rules.

    Returns ALLOW or DENY with the list of policies evaluated.
    """
    evaluated: list[str] = []
    denied_reasons: list[str] = []

    for capability, restricted_actions in _CAPABILITY_RULES.items():
        if req.action in restricted_actions:
            policy_name = f"requires_{capability}"
            evaluated.append(policy_name)
            agent_has_cap = req.capabilities.get(capability, False)
            if not agent_has_cap:
                denied_reasons.append(f"action '{req.action}' requires capability '{capability}'")

    if denied_reasons:
        return PolicyEvalResponse(
            session_id=req.session_id,
            decision="deny",
            reason="; ".join(denied_reasons),
            policies_evaluated=evaluated,
        )

    return PolicyEvalResponse(
        session_id=req.session_id,
        decision="allow",
        reason="all policies passed",
        policies_evaluated=evaluated or ["default_allow"],
    )
