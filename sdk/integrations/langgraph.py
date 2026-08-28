from __future__ import annotations

import warnings
from collections.abc import Sequence
from typing import Any

from contracts.interceptor import Policy
from sdk.middleware.middleware import SecureAgent


def wrap_graph_agent(
    graph: Any,
    policies: Sequence[Policy] | None = None,
    *,
    interceptors: Sequence[Policy] | None = None,
) -> SecureAgent:
    """Wrap a LangGraph compiled graph with OpenScript policies.

    A named alias for SecureAgent(graph, policies=...) — it proxies the
    graph's whole invoke()/stream() call through the policy pipeline, not
    individual node executions. Nothing here is LangGraph-specific beyond
    the name: any object exposing that same invoke/stream shape works
    identically via SecureAgent directly.
    """
    if interceptors is not None:
        warnings.warn(
            "interceptors= is deprecated; use policies= instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        policies = policies or interceptors
    return SecureAgent(agent=graph, policies=policies)
