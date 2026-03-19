from __future__ import annotations

import structlog

from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode
from events.writer import EventWriter

logger = structlog.get_logger(__name__)


class EventWriterInterceptor:
    """Writes before/after events to the event store for every agent action.

    Satisfies the contracts/Interceptor protocol. Lives alongside
    NoopInterceptor in sdk/interceptors/.
    """

    failure_mode: FailureMode = FailureMode.FAIL_OPEN

    def __init__(self, writer: EventWriter) -> None:
        self._writer = writer
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
        seq = self._next_sequence(context.session_id)
        event = Event(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.INTERCEPTOR_AFTER,
            payload={
                "action": context.action,
                "output_data": context.output_data,
            },
            sequence_num=seq,
        )
        await self._writer.write(event)
        return context

    def _next_sequence(self, session_id: str) -> int:
        count = self._sequence_counters.get(session_id, 0) + 1
        self._sequence_counters[session_id] = count
        return count
