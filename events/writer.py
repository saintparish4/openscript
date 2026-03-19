from __future__ import annotations

import asyncio
import contextlib
from typing import Protocol

import structlog

from contracts.server_types import Event

logger = structlog.get_logger(__name__)


class EventSink(Protocol):
    """Anything that can persist a batch of events."""

    async def insert_events(self, events: list[Event]) -> None: ...


class EventWriter:
    """Async bounded queue that drains events to a sink in batches.

    Uses DROP_OLDEST policy when the queue is full — the newest event
    always wins. Every drop is logged with a running counter so ops
    can alert on sustained back-pressure.
    """

    def __init__(
        self,
        store: EventSink,
        max_queue_size: int = 10_000,
        batch_size: int = 100,
        flush_interval: float = 0.1,
    ) -> None:
        self._store = store
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=max_queue_size)
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._events_dropped_count: int = 0
        self._task: asyncio.Task[None] | None = None
        self._running = False

    @property
    def events_dropped_count(self) -> int:
        return self._events_dropped_count

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._drain_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            await self._task
            self._task = None

    async def write(self, event: Event) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            with contextlib.suppress(asyncio.QueueEmpty):
                self._queue.get_nowait()
            self._events_dropped_count += 1
            logger.warning(
                "event_queue_full_drop_oldest",
                events_dropped_count=self._events_dropped_count,
                session_id=event.session_id,
            )
            self._queue.put_nowait(event)

    async def _drain_loop(self) -> None:
        while self._running or not self._queue.empty():
            batch: list[Event] = []

            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=self._flush_interval)
                batch.append(event)
            except TimeoutError:
                if not self._running:
                    break
                continue

            while len(batch) < self._batch_size:
                try:
                    batch.append(self._queue.get_nowait())
                except asyncio.QueueEmpty:
                    break

            if batch:
                try:
                    await self._store.insert_events(batch)
                except Exception:
                    logger.exception(
                        "event_writer_flush_failed",
                        batch_size=len(batch),
                    )
