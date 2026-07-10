from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FailureMode(Enum):
    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"
    FAIL_EXCEPTION = "fail_exception"


class InterceptorDecision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ActionBlockedError(RuntimeError):
    """Raised by middleware when an interceptor sets decision=DENY or REQUIRE_APPROVAL.

    Carries the final ActionContext and aggregated risk_score so blocked
    calls surface the same risk signal as allowed ones.
    """

    def __init__(
        self,
        reason: str = "",
        interceptor: str = "",
        context: ActionContext | None = None,
        risk_score: float = 0.0,
    ) -> None:
        self.reason = reason
        self.interceptor = interceptor
        self.context = context
        self.risk_score = risk_score
        msg = (
            f"Action blocked by {interceptor}: {reason}"
            if interceptor
            else f"Action blocked: {reason}"
        )
        super().__init__(msg)


@dataclass(frozen=True)
class AgentCapabilities:
    untrusted_input: bool = False
    sensitive_access: bool = False
    external_write: bool = False


@dataclass
class ActionContext:
    action: str
    agent_id: str
    session_id: str
    input_data: dict[str, Any] = field(default_factory=dict)
    output_data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    capabilities: AgentCapabilities = field(default_factory=AgentCapabilities)
    decision: InterceptorDecision = field(default=InterceptorDecision.ALLOW)
    decision_reason: str = ""
    risk_score: float = 0.0
    risk_categories: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class InterceptorResult:
    decision: InterceptorDecision
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
