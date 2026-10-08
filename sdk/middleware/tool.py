"""SecureTool — the policy pipeline around one tool, instead of around the agent.

SecureAgent sees two moments: what the caller sent and what the agent finally
returned. Everything an agent does in between — the tools it decides to call,
with the arguments it decides to pass — happens inside ``agent.invoke()`` where
no policy is looking. A prompt-injected agent does its damage there.

SecureTool is the other half. It wraps a single tool callable and runs the same
before / after pipeline on every call to it, with ``action="tool_call"``, so
the checks that are about actions (ToolFirewallPolicy, approvals, audit) sit
where the action is. It imports no agent framework: whatever calls the tool
calls this instead.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from contracts.interceptor import Policy
from contracts.types import ActionContext
from events.approvals import ApprovalStore
from sdk.middleware.middleware import SecureAgent
from sdk.observability.metrics import MetricsRecorder
from sdk.observability.risk import RiskScorer
from sdk.observability.tracing import ActionTracer

_BY_POSITION_ONLY = (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.VAR_POSITIONAL)


class _ToolPipeline(SecureAgent):
    """SecureAgent's phases with a tool in the middle instead of an agent.

    A subclass rather than a second pipeline, so there is exactly one
    definition of what a failure mode, an approval and a refusal mean.
    """

    async def run(
        self, context: ActionContext, fn: Callable[..., Any], approval_id: str
    ) -> ActionContext:
        with self._trace(context):
            context, granted = await self._run_before(context, approval_id)

            # Read back from the context, not from what the caller passed: a
            # policy may have rewritten an argument (a redacted credential),
            # and the call that runs has to be the call that was checked.
            args = context.input_data.get("args")
            if not isinstance(args, dict):
                raise RuntimeError(
                    "a policy left the tool call without a mapping of arguments; refusing to run it"
                )
            if inspect.iscoroutinefunction(fn):
                result = await fn(**args)
            else:
                # Off the event loop, as SecureAgent does for a sync agent. A
                # callable object with an async __call__ comes back from the
                # thread as a coroutine, which is awaited here.
                result = await asyncio.to_thread(functools.partial(fn, **args))
                if inspect.isawaitable(result):
                    result = await result

            context.output_data = {"output": result}
            context = await self._run_after(context, approval_id, granted)
            self._finalize(context)
        return context


class SecureTool:
    """One tool, behind the same policies an agent gets.

        send = SecureTool(send_email, policies=[ToolFirewallPolicy(rules_path="tools.yaml")])
        await send(to="ops@example.com", body="done")     # called like the function

    Each call becomes an ActionContext with ``action="tool_call"`` and
    ``input_data={"name": ..., "args": {...}}``, where ``args`` holds every
    argument by name *including the tool's own defaults* — a bound on ``amount``
    is checked against the amount the tool will actually use, not skipped
    because the caller left it out. (Which ones were defaults travels beside
    the call, so a rule that refuses unlisted arguments refuses what a caller
    passed and not what the tool's author wrote into its signature.)

    A policy that denies in the before phase raises ActionBlockedError and the
    tool does not run. One that requires approval raises it with an
    ``approval_id``; once a human has approved, retry with
    ``call(args, approval_id=...)``. The approval is single-use and bound to the
    tool's name and exact arguments, so it cannot be spent on a different
    recipient or a larger amount.

    A deny in the after phase is a different thing and worth being clear about:
    the tool has already run by then. What is withheld is its *result*, which
    is how a tool's output is kept away from the model, not how its side
    effects are undone.

    A plain (non-async) tool runs in a worker thread so it cannot stall the
    event loop.
    """

    def __init__(
        self,
        fn: Callable[..., Any],
        policies: Sequence[Policy],
        *,
        name: str | None = None,
        role: str | None = None,
        agent_id: str = "default",
        session_id: str = "default",
        approval_store: ApprovalStore | None = None,
        writer: Any | None = None,
        risk_scorer: RiskScorer | None = None,
        metrics: MetricsRecorder | None = None,
        tracer: ActionTracer | None = None,
    ) -> None:
        if not callable(fn):
            raise TypeError(f"SecureTool wraps a callable, got {type(fn).__name__}")
        if not policies:
            # SecureAgent falls back to a no-op here. A wrapper called
            # SecureTool that lets every call through is not a default.
            raise ValueError("SecureTool needs at least one policy")
        resolved = name or getattr(fn, "__name__", "")
        if not resolved:
            raise ValueError("this tool has no __name__; pass name=")

        try:
            signature: inspect.Signature | None = inspect.signature(fn)
        except (TypeError, ValueError):
            # Builtins and some extension callables have none to read.
            signature = None
        if signature is not None:
            for param in signature.parameters.values():
                if param.kind in _BY_POSITION_ONLY:
                    raise TypeError(
                        f"{resolved}() takes '{param.name}' by position only. Rules are "
                        "written against argument names, so every parameter of a guarded "
                        "tool has to be passable by name."
                    )

        # Name, docstring and __wrapped__, so a framework that builds a tool
        # schema by inspecting the callable sees the tool and not this class.
        functools.update_wrapper(self, fn, updated=())
        self.name = resolved
        self._fn = fn
        self._signature = signature
        self._role = role
        self._agent_id = agent_id
        self._session_id = session_id
        self._pipeline = _ToolPipeline(
            agent=None,
            policies=policies,
            approval_store=approval_store,
            writer=writer,
            risk_scorer=risk_scorer,
            metrics=metrics,
            tracer=tracer,
        )

    async def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Call the tool the way the tool is called."""
        result, _ = await self._run(*self._bind(args, kwargs), "", None, None, None)
        return result

    async def call(
        self,
        args: Mapping[str, Any] | None = None,
        *,
        approval_id: str = "",
        role: str | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> Any:
        """Call the tool with its arguments as a mapping.

        The explicit form, for what a plain call has no room for: redeeming an
        approval, or saying which role, agent and session the call belongs to
        when one wrapped tool serves several.
        """
        result, _ = await self.call_with_context(
            args, approval_id=approval_id, role=role, agent_id=agent_id, session_id=session_id
        )
        return result

    async def call_with_context(
        self,
        args: Mapping[str, Any] | None = None,
        *,
        approval_id: str = "",
        role: str | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> tuple[Any, ActionContext]:
        """Like call(), but also returns the final ActionContext so callers can
        read risk_score, risk_categories and per-policy metadata."""
        return await self._run(*self._bind((), args or {}), approval_id, role, agent_id, session_id)

    def _bind(
        self, args: tuple[Any, ...], kwargs: Mapping[str, Any]
    ) -> tuple[dict[str, Any], list[str]]:
        """Every argument by name with the tool's defaults filled in, and the
        names of the ones that came from a default rather than from the caller."""
        if self._signature is None:
            if args:
                raise TypeError(
                    f"{self.name}() has no readable signature, so its arguments "
                    "have to be passed by name"
                )
            return dict(kwargs), []
        # Raises the TypeError the tool itself would have, before any policy runs.
        bound = self._signature.bind(*args, **kwargs)
        passed = set(bound.arguments)
        bound.apply_defaults()
        named = dict(bound.arguments)
        defaulted = [name for name in named if name not in passed]
        for param in self._signature.parameters.values():
            if param.kind is inspect.Parameter.VAR_KEYWORD:
                # def tool(**options): the firewall should see the options, not
                # one argument called "options".
                named.update(named.pop(param.name))
                defaulted = [name for name in defaulted if name != param.name]
        return named, defaulted

    async def _run(
        self,
        named: dict[str, Any],
        defaulted: list[str],
        approval_id: str,
        role: str | None,
        agent_id: str | None,
        session_id: str | None,
    ) -> tuple[Any, ActionContext]:
        role = role if role is not None else self._role
        # Beside the call, not in it: which arguments were defaulted is a fact
        # about how the call was made, and must not change what an approval of
        # the call is bound to.
        metadata: dict[str, Any] = {"defaulted_args": defaulted}
        if role is not None:
            metadata["role"] = role
        context = ActionContext(
            action="tool_call",
            agent_id=agent_id or self._agent_id,
            session_id=session_id or self._session_id,
            input_data={"name": self.name, "args": named},
            metadata=metadata,
        )
        context = await self._pipeline.run(context, self._fn, approval_id)
        return context.output_data.get("output"), context
