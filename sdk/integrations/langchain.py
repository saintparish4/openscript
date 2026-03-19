from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from contracts.interceptor import Interceptor
from sdk.middleware.middleware import OpenScriptMiddleware


def wrap_agent(
    agent: Any,
    interceptors: Sequence[Interceptor] | None = None,
) -> OpenScriptMiddleware:
    """Wrap a LangChain AgentExecutor with OpenScript interception.

    Usage:
      from openscript import wrap_agent, NoopInterceptor
      secure = wrap_agent(agent, interceptors=[NoopInterceptor()])
      result = await secure.invoke({"input": "hello"})
    """
    return OpenScriptMiddleware(agent=agent, interceptors=interceptors)
