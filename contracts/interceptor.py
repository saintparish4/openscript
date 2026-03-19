from __future__ import annotations

from typing import Protocol, runtime_checkable

from contracts.types import ActionContext, FailureMode


@runtime_checkable
class Interceptor(Protocol):
    failure_mode: FailureMode

    async def before_action(self, context: ActionContext) -> ActionContext: ...
    async def after_action(self, context: ActionContext) -> ActionContext: ...
