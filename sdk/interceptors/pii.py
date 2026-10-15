from __future__ import annotations

import warnings
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import structlog

from contracts.interceptor import GuardScan, StreamGuard
from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode, InterceptorDecision
from sdk.policies.redaction import _find_pii as _find_pii
from sdk.policies.redaction import _redact_pii_text as _redact_text
from sdk.policies.redaction import _walk_redact_pii as _walk_redact

if TYPE_CHECKING:
    from events.writer import EventWriter

logger = structlog.get_logger(__name__)


class PIIMode(StrEnum):
    REDACT = "redact"
    DENY = "deny"


# Labels whose exposure is directly exploitable (identity theft, account
# takeover); the rest are contact/network identifiers.
_HIGH_SEVERITY_LABELS = frozenset({"ssn", "credit_card", "api_key"})


def _pii_risk(found_labels: list[str]) -> float:
    if not found_labels:
        return 0.0
    return 0.8 if any(label in _HIGH_SEVERITY_LABELS for label in found_labels) else 0.4


class _PIIStreamGuard:
    """Incremental scanner backing PIIPolicy in guarded streams."""

    name = "PIIPolicy"
    # generous bound: the longest realistic PII match (emails, spaced card
    # numbers) is well under this
    max_match_len = 256

    def __init__(self, mode: PIIMode) -> None:
        self._mode = mode

    def scan(self, text: str, final: bool = False) -> GuardScan:
        redacted, labels = _redact_text(text, final=final)
        if not labels:
            return GuardScan(text=text)
        risk = _pii_risk(labels)
        if self._mode == PIIMode.DENY:
            return GuardScan(
                text=text,
                labels=labels,
                risk=risk,
                deny=True,
                reason=f"PII detected in stream: {', '.join(set(labels))}",
            )
        return GuardScan(text=redacted, labels=labels, risk=risk)


class PIIPolicy:
    """Scans agent output for PII and either redacts or blocks.

    Runs in after_action. before_action is a pass-through.
    Default mode is REDACT so observability is preserved; use DENY for
    strict environments.

    Results land in context.metadata["pii"] using the standardized shape:
      {"risk": float, "category": "pii", "found": [labels...], "redacted": bool}
    """

    failure_mode: FailureMode = FailureMode.FAIL_OPEN

    def __init__(
        self,
        mode: PIIMode | str = PIIMode.REDACT,
        writer: EventWriter | None = None,
    ) -> None:
        self._mode = PIIMode(mode)
        self._writer = writer
        self._sequence_counters: dict[str, int] = {}

    async def before_action(self, context: ActionContext) -> ActionContext:
        return context

    def stream_guard(self) -> StreamGuard:
        return _PIIStreamGuard(self._mode)

    async def after_action(self, context: ActionContext) -> ActionContext:
        redacted_output, found_labels = _walk_redact(context.output_data)

        if not found_labels:
            context.metadata["pii"] = {
                "risk": 0.0,
                "category": "pii",
                "found": [],
                "redacted": False,
            }
            return context

        logger.warning(
            "pii_detected",
            session_id=context.session_id,
            agent_id=context.agent_id,
            types=found_labels,
            mode=self._mode.value,
        )

        risk = _pii_risk(found_labels)
        if self._mode == PIIMode.DENY:
            context.metadata["pii"] = {
                "risk": risk,
                "category": "pii",
                "found": found_labels,
                "redacted": False,
            }
            context.decision = InterceptorDecision.DENY
            context.decision_reason = f"PII detected in output: {', '.join(set(found_labels))}"
        else:
            context.output_data = redacted_output
            context.metadata["pii"] = {
                "risk": risk,
                "category": "pii",
                "found": found_labels,
                "redacted": True,
            }

        if self._writer is not None:
            await self._emit_pii_event(context, found_labels)

        return context

    async def _emit_pii_event(self, context: ActionContext, found_labels: list[str]) -> None:
        seq = self._next_sequence(context.session_id)
        event = Event(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.POLICY_EVALUATED,
            payload={
                "policy": "pii_check",
                "pii_types": list(set(found_labels)),
                "mode": self._mode.value,
                "decision": context.decision.value,
            },
            sequence_num=seq,
        )
        await self._writer.write(event)  # type: ignore[union-attr]

    def _next_sequence(self, session_id: str) -> int:
        count = self._sequence_counters.get(session_id, 0) + 1
        self._sequence_counters[session_id] = count
        return count


class PIIInterceptor(PIIPolicy):
    """Deprecated — use PIIPolicy instead."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "PIIInterceptor is deprecated; use PIIPolicy instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)
