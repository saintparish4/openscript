from __future__ import annotations

from contracts.types import ActionContext, FailureMode


class NoopInterceptor:
    """Pass-through interceptor with zero logic. Default when no interceptors configured."""

    failure_mode: FailureMode = FailureMode.FAIL_OPEN

    async def before_action(self, context: ActionContext) -> ActionContext:
        return context

    async def after_action(self, context: ActionContext) -> ActionContext:
        return context
