from __future__ import annotations

import warnings
from collections.abc import Sequence
from typing import Any

from contracts.interceptor import Policy
from sdk.middleware.middleware import SecureAgent


def wrap_agent(
    agent: Any,
    policies: Sequence[Policy] | None = None,
    *,
    interceptors: Sequence[Policy] | None = None,
) -> SecureAgent:
    """Wrap a LangChain AgentExecutor with OpenScript policies.

    Usage:
      from openscript import wrap_agent, NoopInterceptor
      secure = wrap_agent(agent, policies=[NoopInterceptor()])
      result = await secure.invoke({"input": "hello"})
    """
    if interceptors is not None:
        warnings.warn(
            "interceptors= is deprecated; use policies= instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        policies = policies or interceptors
    return SecureAgent(agent=agent, policies=policies)
