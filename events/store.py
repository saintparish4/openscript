from __future__ import annotations

from collections.abc import AsyncIterator

import structlog
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from contracts.server_types import Event, EventType
from events.models import EventRow

logger = structlog.get_logger(__name__)


class EventStore:
    """Read/write interface for the append-only events table."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._session_factory = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )

    async def insert_events(self, events: list[Event]) -> None:
        async with self._session_factory() as session:
            for event in events:
                row = EventRow(
                    id=event.id,
                    session_id=event.session_id,
                    agent_id=event.agent_id,
                    event_type=event.event_type.value,
                    payload=event.payload,
                    timestamp=event.timestamp,
                    sequence_num=event.sequence_num,
                )
                session.add(row)
            await session.commit()
        logger.debug("events_inserted", count=len(events))

    async def get_events(
        self,
        session_id: str,
        event_types: list[EventType] | None = None,
        after_sequence: int | None = None,
        limit: int = 1000,
    ) -> list[Event]:
        async with self._session_factory() as session:
            conditions = [EventRow.session_id == session_id]
            if event_types:
                conditions.append(EventRow.event_type.in_([et.value for et in event_types]))
            if after_sequence is not None:
                conditions.append(EventRow.sequence_num > after_sequence)

            stmt = (
                select(EventRow)
                .where(and_(*conditions))
                .order_by(EventRow.sequence_num)
                .limit(limit)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

        return [
            Event(
                id=row.id,
                session_id=row.session_id,
                agent_id=row.agent_id,
                event_type=EventType(row.event_type),
                payload=row.payload,
                timestamp=row.timestamp,
                sequence_num=row.sequence_num,
            )
            for row in rows
        ]

    async def stream_events(self, session_id: str) -> AsyncIterator[Event]:
        events = await self.get_events(session_id=session_id)
        for event in events:
            yield event
