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

    Hooks into node execution via the policy pipeline. The graph's
    invoke/stream methods are proxied through policies.
    """
    if interceptors is not None:
        warnings.warn(
            "interceptors= is deprecated; use policies= instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        policies = policies or interceptors
    return SecureAgent(agent=graph, policies=policies)
