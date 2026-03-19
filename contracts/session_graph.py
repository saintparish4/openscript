from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from contracts.server_types import Event, EventType

if TYPE_CHECKING:
    from events.store import EventStore


class NodeType(str, Enum):  # noqa: UP042
    TURN = "turn"
    TOOL_CALL = "tool_call"
    MEMORY_WRITE = "memory_write"
    AGENT_MESSAGE = "agent_message"
    INTERCEPTOR = "interceptor"
    THREAT = "threat"
    POLICY = "policy"


_EVENT_TO_NODE: dict[EventType, NodeType] = {
    EventType.TURN_STARTED: NodeType.TURN,
    EventType.TURN_END: NodeType.TURN,
    EventType.TOOL_CALL: NodeType.TOOL_CALL,
    EventType.TOOL_RESULT: NodeType.TOOL_CALL,
    EventType.MEMORY_WRITE: NodeType.MEMORY_WRITE,
    EventType.MEMORY_READ: NodeType.MEMORY_WRITE,
    EventType.INTERCEPTOR_BEFORE: NodeType.INTERCEPTOR,
    EventType.INTERCEPTOR_AFTER: NodeType.INTERCEPTOR,
    EventType.THREAT_DETECTED: NodeType.THREAT,
    EventType.POLICY_EVALUATED: NodeType.POLICY,
    EventType.AGENT_MESSAGE: NodeType.AGENT_MESSAGE,
}


@dataclass(frozen=True)
class GraphNode:
    id: str
    node_type: str
    event: Event
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    source_id: str
    target_id: str
    edge_type: str = "causal"


@dataclass
class SessionGraph:
    session_id: str
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)

    @classmethod
    def build(cls, session_id: str, events: list[Event]) -> SessionGraph:
        """Build a DAG from an ordered list of events.

        Nodes map 1:1 to events. Edges encode sequential causality and
        parent-child relationships (tool calls / memory writes nested
        inside turns).
        """
        sorted_events = sorted(events, key=lambda e: e.sequence_num)
        graph = cls(session_id=session_id)

        prev_node_id: str | None = None
        turn_stack: list[str] = []

        for event in sorted_events:
            node_type = _EVENT_TO_NODE.get(event.event_type, NodeType.AGENT_MESSAGE)
            node = GraphNode(
                id=event.id,
                node_type=node_type.value,
                event=event,
            )
            graph.add_node(node)

            if prev_node_id is not None:
                graph.add_edge(GraphEdge(source_id=prev_node_id, target_id=node.id))

            if event.event_type == EventType.TURN_STARTED:
                turn_stack.append(node.id)
            elif event.event_type in (EventType.TOOL_CALL, EventType.MEMORY_WRITE):
                if turn_stack:
                    graph.add_edge(
                        GraphEdge(
                            source_id=turn_stack[-1],
                            target_id=node.id,
                            edge_type="parent",
                        )
                    )
            elif event.event_type == EventType.TURN_END and turn_stack:
                turn_stack.pop()

            prev_node_id = node.id

        return graph

    @classmethod
    async def from_live_stream(cls, events: AsyncIterator[Event]) -> SessionGraph:
        collected: list[Event] = []
        session_id = ""
        async for event in events:
            if not session_id:
                session_id = event.session_id
            collected.append(event)
        return cls.build(session_id=session_id, events=collected)

    @classmethod
    async def from_store(cls, session_id: str, event_store: EventStore) -> SessionGraph:
        events = await event_store.get_events(session_id=session_id)
        return cls.build(session_id=session_id, events=events)
