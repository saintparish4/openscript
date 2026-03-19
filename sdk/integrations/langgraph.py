from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from contracts.interceptor import Interceptor
from sdk.middleware.middleware import OpenScriptMiddleware


def wrap_graph_agent(
    graph: Any,
    interceptors: Sequence[Interceptor] | None = None,
) -> OpenScriptMiddleware:
    """Wrap a LangGraph compiled graph with OpenScript interception.

    Hooks into node execution via the middleware pipeline. The graph's
    invoke/stream methods are proxied through interceptors.
    """
    return OpenScriptMiddleware(agent=graph, interceptors=interceptors)
