from __future__ import annotations

from typing import Protocol, runtime_checkable

from contracts.types import ActionContext, FailureMode


@runtime_checkable
class Policy(Protocol):
    """Protocol all OpenScript policies must satisfy."""

    failure_mode: FailureMode

    async def before_action(self, context: ActionContext) -> ActionContext: ...
    async def after_action(self, context: ActionContext) -> ActionContext: ...


class BasePolicy:
    """Concrete base class for policies; subclasses override only the hooks they need."""

    failure_mode: FailureMode = FailureMode.FAIL_OPEN

    async def before_action(self, context: ActionContext) -> ActionContext:
        return context

    async def after_action(self, context: ActionContext) -> ActionContext:
        return context


# Deprecated alias — prefer Policy
Interceptor = Policy
