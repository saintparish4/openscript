from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Sequence
from typing import Any

import structlog

from contracts.interceptor import Interceptor
from contracts.types import ActionContext, FailureMode
from sdk.interceptors.base import NoopInterceptor
from sdk.logging import _ensure_configured

logger = structlog.get_logger(__name__)


class OpenScriptMiddleware:
    """Thin orchestrator that runs a list of Interceptors around agent actions.

    Contains zero detection or security logic — all behavior is provided by
    the registered Interceptor implementations.
    """

    def __init__(
        self,
        agent: Any,
        interceptors: Sequence[Interceptor] | None = None,
    ) -> None:
        _ensure_configured()
        self._agent = agent
        self._interceptors: Sequence[Interceptor] = interceptors or [NoopInterceptor()]

    async def invoke(self, input_data: dict[str, Any], **kwargs: Any) -> Any:
        context = ActionContext(
            action="invoke",
            agent_id=kwargs.get("agent_id", "default"),
            session_id=kwargs.get("session_id", "default"),
            input_data=input_data,
            metadata=kwargs,
        )

        context = await self._run_before(context)

        result = await self._call_agent(input_data, **kwargs)

        context.output_data = result if isinstance(result, dict) else {"output": result}
        await self._run_after(context)

        return result

    async def stream(self, input_data: dict[str, Any], **kwargs: Any) -> AsyncGenerator[Any, None]:
        context = ActionContext(
            action="stream",
            agent_id=kwargs.get("agent_id", "default"),
            session_id=kwargs.get("session_id", "default"),
            input_data=input_data,
            metadata=kwargs,
        )

        context = await self._run_before(context)

        async for chunk in self._stream_agent(input_data, **kwargs):
            yield chunk

        await self._run_after(context)

    async def _run_before(self, context: ActionContext) -> ActionContext:
        for interceptor in self._interceptors:
            try:
                context = await interceptor.before_action(context)
            except Exception as exc:
                context = self._handle_failure(interceptor, exc, context, "before_action")
        return context

    async def _run_after(self, context: ActionContext) -> ActionContext:
        for interceptor in self._interceptors:
            try:
                context = await interceptor.after_action(context)
            except Exception as exc:
                context = self._handle_failure(interceptor, exc, context, "after_action")
        return context

    def _handle_failure(
        self,
        interceptor: Interceptor,
        exc: Exception,
        context: ActionContext,
        phase: str,
    ) -> ActionContext:
        interceptor_name = type(interceptor).__name__
        log = logger.bind(interceptor=interceptor_name, phase=phase, error=str(exc))

        match interceptor.failure_mode:
            case FailureMode.FAIL_OPEN:
                log.warning("interceptor_error_fail_open")
                return context
            case FailureMode.FAIL_CLOSED:
                log.error("interceptor_error_fail_closed")
                raise RuntimeError(
                    f"Action blocked: {interceptor_name} failed during {phase}"
                ) from exc
            case FailureMode.FAIL_EXCEPTION:
                log.error("interceptor_error_fail_exception")
                raise
            case _:
                log.error("interceptor_error_unknown_failure_mode")
                raise

    async def _call_agent(self, input_data: dict[str, Any], **kwargs: Any) -> Any:
        if hasattr(self._agent, "ainvoke"):
            return await self._agent.ainvoke(input_data, **kwargs)
        if hasattr(self._agent, "invoke"):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self._agent.invoke(input_data, **kwargs)
            )
        raise TypeError(f"Agent {type(self._agent)} has no invoke or ainvoke method")

    async def _stream_agent(
        self, input_data: dict[str, Any], **kwargs: Any
    ) -> AsyncGenerator[Any, None]:
        if hasattr(self._agent, "astream"):
            async for chunk in self._agent.astream(input_data, **kwargs):
                yield chunk
        elif hasattr(self._agent, "stream"):
            for chunk in self._agent.stream(input_data, **kwargs):
                yield chunk
        else:
            raise TypeError(f"Agent {type(self._agent)} has no stream or astream method")
