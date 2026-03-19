from __future__ import annotations

import asyncio

import pytest

from contracts.interceptor import Interceptor
from contracts.server_types import Event, EventType
from contracts.session_graph import SessionGraph
from contracts.types import FailureMode
from events.writer import EventWriter
from sdk import OpenScriptMiddleware
from sdk.interceptors.event_writer import EventWriterInterceptor


class FakeAgent:
    async def ainvoke(self, input_data, **kwargs):
        return {"output": f"echo: {input_data.get('input', '')}"}


class InMemoryEvents:
    """Drop-in EventSink for tests -- no database required."""

    def __init__(self):
        self.events: list[Event] = []

    async def insert_events(self, events: list[Event]) -> None:
        self.events.extend(events)

    async def get_events(
        self,
        session_id: str,
        event_types: list[EventType] | None = None,
        after_sequence: int | None = None,
        limit: int = 1000,
    ) -> list[Event]:
        result = [e for e in self.events if e.session_id == session_id]
        if event_types:
            result = [e for e in result if e.event_type in event_types]
        if after_sequence is not None:
            result = [e for e in result if e.sequence_num > after_sequence]
        result.sort(key=lambda e: e.sequence_num)
        return result[:limit]


@pytest.mark.asyncio
async def test_event_writer_interceptor_writes_before_and_after():
    """End-to-end: OpenScriptMiddleware -> EventWriterInterceptor -> events persisted."""
    store = InMemoryEvents()
    writer = EventWriter(store=store, flush_interval=0.05)
    await writer.start()

    interceptor = EventWriterInterceptor(writer=writer)
    agent = FakeAgent()
    mw = OpenScriptMiddleware(agent=agent, interceptors=[interceptor])

    result = await mw.invoke(
        {"input": "hello"},
        session_id="sess-1",
        agent_id="agent-1",
    )

    await asyncio.sleep(0.2)
    await writer.stop()

    assert result["output"] == "echo: hello"
    assert len(store.events) == 2
    assert store.events[0].event_type == EventType.INTERCEPTOR_BEFORE
    assert store.events[1].event_type == EventType.INTERCEPTOR_AFTER
    assert store.events[0].session_id == "sess-1"
    assert store.events[0].agent_id == "agent-1"
    assert store.events[0].sequence_num < store.events[1].sequence_num


@pytest.mark.asyncio
async def test_event_writer_interceptor_satisfies_protocol():
    """EventWriterInterceptor is a valid Interceptor per contracts."""
    store = InMemoryEvents()
    writer = EventWriter(store=store)
    interceptor = EventWriterInterceptor(writer=writer)

    assert isinstance(interceptor, Interceptor)
    assert interceptor.failure_mode == FailureMode.FAIL_OPEN


@pytest.mark.asyncio
async def test_session_graph_from_store_matches_direct_build():
    """from_store and build produce identical DAGs for the same events."""
    store = InMemoryEvents()
    writer = EventWriter(store=store, flush_interval=0.05)
    await writer.start()

    interceptor = EventWriterInterceptor(writer=writer)
    agent = FakeAgent()
    mw = OpenScriptMiddleware(agent=agent, interceptors=[interceptor])

    for i in range(5):
        await mw.invoke(
            {"input": f"turn {i}"},
            session_id="sess-graph",
            agent_id="agent-1",
        )

    await asyncio.sleep(0.3)
    await writer.stop()

    graph_from_store = await SessionGraph.from_store("sess-graph", store)
    graph_from_build = SessionGraph.build("sess-graph", store.events)

    assert len(graph_from_store.nodes) == len(graph_from_build.nodes)
    assert len(graph_from_store.edges) == len(graph_from_build.edges)
    assert set(graph_from_store.nodes.keys()) == set(graph_from_build.nodes.keys())


@pytest.mark.asyncio
async def test_session_graph_from_live_stream_matches_from_store():
    """from_live_stream and from_store produce identical DAGs."""
    store = InMemoryEvents()
    writer = EventWriter(store=store, flush_interval=0.05)
    await writer.start()

    interceptor = EventWriterInterceptor(writer=writer)
    agent = FakeAgent()
    mw = OpenScriptMiddleware(agent=agent, interceptors=[interceptor])

    await mw.invoke(
        {"input": "test"},
        session_id="sess-live",
        agent_id="agent-1",
    )
    await asyncio.sleep(0.2)
    await writer.stop()

    graph_store = await SessionGraph.from_store("sess-live", store)

    async def event_stream():
        for e in store.events:
            yield e

    graph_live = await SessionGraph.from_live_stream(event_stream())

    assert set(graph_store.nodes.keys()) == set(graph_live.nodes.keys())
    assert len(graph_store.edges) == len(graph_live.edges)


@pytest.mark.asyncio
async def test_event_writer_drop_oldest_under_pressure():
    """Queue saturates gracefully: drops are logged, no silent loss."""
    store = InMemoryEvents()
    writer = EventWriter(store=store, max_queue_size=10, flush_interval=10.0)

    await writer.start()

    for i in range(25):
        event = Event(
            session_id="sess-burst",
            agent_id="agent-1",
            event_type=EventType.AGENT_MESSAGE,
            payload={"i": i},
            sequence_num=i,
        )
        await writer.write(event)

    assert writer.events_dropped_count > 0
    assert writer.queue_size <= 10

    await writer.stop()


@pytest.mark.asyncio
async def test_multi_session_events_isolated():
    """Events from different sessions don't leak into each other's graph."""
    store = InMemoryEvents()
    writer = EventWriter(store=store, flush_interval=0.05)
    await writer.start()

    interceptor = EventWriterInterceptor(writer=writer)
    agent = FakeAgent()
    mw = OpenScriptMiddleware(agent=agent, interceptors=[interceptor])

    await mw.invoke({"input": "a"}, session_id="sess-A", agent_id="agent-1")
    await mw.invoke({"input": "b"}, session_id="sess-B", agent_id="agent-2")

    await asyncio.sleep(0.2)
    await writer.stop()

    graph_a = await SessionGraph.from_store("sess-A", store)
    graph_b = await SessionGraph.from_store("sess-B", store)

    for node in graph_a.nodes.values():
        assert node.event.session_id == "sess-A"
    for node in graph_b.nodes.values():
        assert node.event.session_id == "sess-B"

    assert set(graph_a.nodes.keys()).isdisjoint(set(graph_b.nodes.keys()))
