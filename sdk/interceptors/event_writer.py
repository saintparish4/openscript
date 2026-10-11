from __future__ import annotations

import warnings
from typing import Any

import structlog

from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode
from events.approvals import action_hash
from events.writer import EventWriter
from sdk.observability.risk import aggregate_risk

logger = structlog.get_logger(__name__)


class AuditPolicy:
    """Writes before/after events to the event store for every agent action,
    and an ``action_blocked`` event for every action the pipeline refuses.

    Satisfies the contracts/Policy protocol. Lives alongside
    NoopInterceptor in sdk/interceptors/.

    A refused action is recorded through on_blocked(), which SecureAgent calls
    wherever this policy sits in the list. That matters because the place it is
    meant to sit is last: a prompt denied by an earlier policy never reaches
    before_action here, and used to leave no event at all.

    The blocked event carries the input as it stood when the action was
    refused, so redactions made by policies listed *before* the one that denied
    are applied and later ones are not. Pass ``record_blocked_input=False`` to
    store only the input hash when the raw text of a refused prompt should not
    reach the event store.
    """

    failure_mode: FailureMode = FailureMode.FAIL_OPEN

    def __init__(self, writer: EventWriter, record_blocked_input: bool = True) -> None:
        self._writer = writer
        self._record_blocked_input = record_blocked_input
        self._sequence_counters: dict[str, int] = {}

    async def before_action(self, context: ActionContext) -> ActionContext:
        seq = self._next_sequence(context.session_id)
        event = Event(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.INTERCEPTOR_BEFORE,
            payload={
                "action": context.action,
                "input_data": context.input_data,
                "capabilities": {
                    "untrusted_input": context.capabilities.untrusted_input,
                    "sensitive_access": context.capabilities.sensitive_access,
                    "external_write": context.capabilities.external_write,
                },
            },
            sequence_num=seq,
        )
        await self._writer.write(event)
        return context

    async def after_action(self, context: ActionContext) -> ActionContext:
        # Computed here (not read from context) because SecureAgent's final
        # aggregation runs after the policy loop; place AuditPolicy last in
        # policies=[...] so the recorded score covers every other policy.
        risk_score, risk_categories = aggregate_risk(context)
        seq = self._next_sequence(context.session_id)
        event = Event(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.INTERCEPTOR_AFTER,
            payload={
                "action": context.action,
                "output_data": context.output_data,
                "risk_score": risk_score,
                "risk_categories": risk_categories,
            },
            sequence_num=seq,
        )
        await self._writer.write(event)
        return context

    async def on_blocked(
        self,
        context: ActionContext,
        *,
        blocked_by: str,
        phase: str,
        approval_id: str = "",
    ) -> None:
        payload: dict[str, Any] = {
            "action": context.action,
            "phase": phase,
            "blocked_by": blocked_by,
            "decision": context.decision.value,
            "reason": context.decision_reason,
            # Final: SecureAgent aggregates before it calls this hook.
            "risk_score": context.risk_score,
            "risk_categories": context.risk_categories,
            "input_hash": action_hash(context.action, context.input_data),
        }
        if self._record_blocked_input:
            payload["input_data"] = context.input_data
        if approval_id:
            payload["approval_id"] = approval_id
        event = Event(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.ACTION_BLOCKED,
            payload=payload,
            sequence_num=self._next_sequence(context.session_id),
        )
        await self._writer.write(event)

    def _next_sequence(self, session_id: str) -> int:
        count = self._sequence_counters.get(session_id, 0) + 1
        self._sequence_counters[session_id] = count
        return count


class EventWriterInterceptor(AuditPolicy):
    """Deprecated — use AuditPolicy instead."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "EventWriterInterceptor is deprecated; use AuditPolicy instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)
