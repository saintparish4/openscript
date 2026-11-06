"""OpenScript contract: public framework types and protocols."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

# Every public name, and the module it lives in. Nothing is imported until a
# name is first asked for, so a caller that needs one policy does not pay for
# all of them (a Claude Code hook pays this on every tool call).
_EXPORTS: dict[str, str] = {
    "ActionContext": "openscript_sdk.contracts.types",
    "AgentCapabilities": "openscript_sdk.contracts.types",
    "DetectionResult": "openscript_sdk.contracts.server_types",
    "Event": "openscript_sdk.contracts.server_types",
    "EventType": "openscript_sdk.contracts.server_types",
    "FailureMode": "openscript_sdk.contracts.types",
    "GraphEdge": "openscript_sdk.contracts.session_graph",
    "GraphNode": "openscript_sdk.contracts.session_graph",
    "Interceptor": "openscript_sdk.contracts.interceptor",
    "InterceptorDecision": "openscript_sdk.contracts.types",
    "InterceptorResult": "openscript_sdk.contracts.types",
    "NodeType": "openscript_sdk.contracts.session_graph",
    "PolicyEvalRequest": "openscript_sdk.contracts.server_types",
    "PolicyEvalResponse": "openscript_sdk.contracts.server_types",
    "SessionGraph": "openscript_sdk.contracts.session_graph",
    "ThreatScoreRequest": "openscript_sdk.contracts.server_types",
    "ThreatScoreResponse": "openscript_sdk.contracts.server_types",
}

if TYPE_CHECKING:
    from openscript_sdk.contracts.interceptor import Interceptor
    from openscript_sdk.contracts.server_types import (
        DetectionResult,
        Event,
        EventType,
        PolicyEvalRequest,
        PolicyEvalResponse,
        ThreatScoreRequest,
        ThreatScoreResponse,
    )
    from openscript_sdk.contracts.session_graph import GraphEdge, GraphNode, NodeType, SessionGraph
    from openscript_sdk.contracts.types import (
        ActionContext,
        AgentCapabilities,
        FailureMode,
        InterceptorDecision,
        InterceptorResult,
    )

__all__ = [
    "ActionContext",
    "AgentCapabilities",
    "DetectionResult",
    "Event",
    "EventType",
    "FailureMode",
    "GraphEdge",
    "GraphNode",
    "Interceptor",
    "InterceptorDecision",
    "InterceptorResult",
    "NodeType",
    "PolicyEvalRequest",
    "PolicyEvalResponse",
    "SessionGraph",
    "ThreatScoreRequest",
    "ThreatScoreResponse",
]


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value  # asked for once, then a plain attribute
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
