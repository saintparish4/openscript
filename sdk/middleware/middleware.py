from __future__ import annotations

import asyncio
import warnings
from collections.abc import AsyncGenerator, Sequence
from typing import Any

import structlog

from contracts.interceptor import Policy
from contracts.types import ActionBlockedError, ActionContext, FailureMode, InterceptorDecision
from sdk.interceptors.base import NoopInterceptor
from sdk.logging import _ensure_configured
from sdk.observability.risk import RiskScorer

logger = structlog.get_logger(__name__)


class SecureAgent:
    """Orchestrates a list of Policies around agent actions.

    Contains zero detection or security logic — all behavior is provided by
    the registered Policy implementations.
    """

    def __init__(
        self,
        agent: Any,
        policies: Sequence[Policy] | None = None,
        *,
        interceptors: Sequence[Policy] | None = None,
        risk_scorer: RiskScorer | None = None,
    ) -> None:
        _ensure_configured()
        if interceptors is not None:
            warnings.warn(
                "interceptors= is deprecated; use policies= instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            if policies is not None:
                raise ValueError("Cannot specify both policies= and interceptors=.")
            policies = interceptors
        self._agent = agent
        self._policies: Sequence[Policy] = policies or [NoopInterceptor()]
        self._risk_scorer = risk_scorer or RiskScorer()

    async def invoke(self, input_data: dict[str, Any], **kwargs: Any) -> Any:
        result, _ = await self.invoke_with_context(input_data, **kwargs)
        return result

    async def invoke_with_context(
        self, input_data: dict[str, Any], **kwargs: Any
    ) -> tuple[Any, ActionContext]:
        """Like invoke(), but also returns the final ActionContext so callers
        can read risk_score, risk_categories, and per-policy metadata."""
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
        context = await self._run_after(context)
        self._risk_scorer.aggregate(context)

        # Return context.output_data so after_action policies (e.g. PIIPolicy)
        # can modify the output that callers receive.
        if isinstance(result, dict):
            return context.output_data, context
        return context.output_data.get("output", result), context

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

        context = await self._run_after(context)
        self._risk_scorer.aggregate(context)

    async def _run_before(self, context: ActionContext) -> ActionContext:
        for policy in self._policies:
            try:
                context = await policy.before_action(context)
            except Exception as exc:
                context = self._handle_failure(policy, exc, context, "before_action")
                continue
            if context.decision in (InterceptorDecision.DENY, InterceptorDecision.REQUIRE_APPROVAL):
                self._risk_scorer.aggregate(context)
                raise ActionBlockedError(
                    reason=context.decision_reason,
                    interceptor=type(policy).__name__,
                    context=context,
                    risk_score=context.risk_score,
                )
        return context

    async def _run_after(self, context: ActionContext) -> ActionContext:
        blocked_by = ""
        for policy in self._policies:
            try:
                context = await policy.after_action(context)
            except Exception as exc:
                context = self._handle_failure(policy, exc, context, "after_action")
                continue
            if not blocked_by and context.decision != InterceptorDecision.ALLOW:
                blocked_by = type(policy).__name__
        # Unlike the before phase, all policies run to completion (so audit and
        # metadata are complete) before an output-side DENY blocks the response.
        if context.decision in (InterceptorDecision.DENY, InterceptorDecision.REQUIRE_APPROVAL):
            self._risk_scorer.aggregate(context)
            raise ActionBlockedError(
                reason=context.decision_reason,
                interceptor=blocked_by,
                context=context,
                risk_score=context.risk_score,
            )
        return context

    def _handle_failure(
        self,
        policy: Policy,
        exc: Exception,
        context: ActionContext,
        phase: str,
    ) -> ActionContext:
        interceptor_name = type(policy).__name__
        log = logger.bind(interceptor=interceptor_name, phase=phase, error=str(exc))

        match policy.failure_mode:
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


class OpenScriptMiddleware(SecureAgent):
    """Deprecated — use SecureAgent instead."""

    def __init__(self, agent: Any, **kwargs: Any) -> None:
        warnings.warn(
            "OpenScriptMiddleware is deprecated; use SecureAgent instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(agent, **kwargs)
