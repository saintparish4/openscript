from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from contracts.types import ActionContext, FailureMode


@dataclass
class GuardScan:
    """Result of one incremental scan by a StreamGuard.

    text is the (possibly redacted) input text; labels/risk mirror the
    owning policy's metadata conventions; deny=True aborts the stream with
    *reason* before the offending text is released.
    """

    text: str
    labels: list[str] = field(default_factory=list)
    risk: float = 0.0
    deny: bool = False
    reason: str = ""


@runtime_checkable
class StreamGuard(Protocol):
    """Bounded incremental text scanner for guarded streaming.

    max_match_len is the guard's honest upper bound on how many characters
    one of its patterns can span — the middleware holds back a tail of that
    size, which is what guarantees a match is never split across the
    released/held boundary. Unbounded constructs must be handled by their
    prefix (e.g. a PEM header) or must deny.

    final=False means more text may follow: a match ending exactly at the
    end of *text* is tentative (it could extend) and must be left untouched
    and unreported — it sits inside the held tail, so deferring never leaks
    it. final=True (stream end) acts on everything.
    """

    name: str
    max_match_len: int

    def scan(self, text: str, final: bool = False) -> GuardScan: ...


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

    def stream_guard(self) -> StreamGuard | None:
        """Override to participate in guarded streaming. Only policies whose
        checks are bounded text patterns can do so; policies needing the
        complete output (schema validation, grounding) return None and run
        at stream end."""
        return None


# Deprecated alias — prefer Policy
Interceptor = Policy
