from __future__ import annotations

import asyncio
import time
import warnings
from collections.abc import AsyncGenerator, Sequence
from contextlib import AbstractContextManager, nullcontext
from enum import Enum
from typing import Any

import structlog

from contracts.interceptor import Policy
from contracts.server_types import Event, EventType
from contracts.types import ActionBlockedError, ActionContext, FailureMode, InterceptorDecision
from events.approvals import ApprovalRecord, ApprovalStore, InMemoryApprovalStore, action_hash
from sdk.interceptors.base import NoopInterceptor
from sdk.logging import _ensure_configured
from sdk.observability.metrics import MetricsRecorder
from sdk.observability.risk import RiskScorer
from sdk.observability.tracing import ActionTracer, tracer_from_env

logger = structlog.get_logger(__name__)


class StreamOutputMode(str, Enum):
    """How stream() applies output policies to streamed chunks.

    BUFFER (default): collect every chunk, run after_action policies over
    the assembled output, then yield the (possibly redacted) result —
    nothing reaches the caller unscanned, at the cost of time-to-first-token
    (and, for text streams, chunk granularity: one combined chunk).

    GUARDED: near-real-time streaming for TEXT chunks. Policies that expose
    a stream_guard() (bounded pattern scanners: SecretsPolicy, PIIPolicy)
    scan incrementally while the middleware holds back a tail window sized
    to their longest pattern — matches within the bound are redacted before
    release or abort the stream with nothing of the match emitted. Policies
    without a guard (schema validation, grounding) run at stream end, where
    a DENY still raises. Latency cost is one window (~a few dozen tokens),
    not the whole response.

    PASSTHROUGH: chunks reach the caller immediately and UNSCANNED — output
    policies cannot redact or block what has already been delivered. They
    still run post-hoc over the assembled output for metadata/audit, and a
    post-hoc DENY still raises at stream end (too late to prevent the leak,
    loud by design).
    """

    BUFFER = "buffer"
    GUARDED = "guarded"
    PASSTHROUGH = "passthrough"


class SecureAgent:
    """Orchestrates a list of Policies around agent actions.

    Contains zero detection or security logic — all behavior is provided by
    the registered Policy implementations.

    When a policy returns REQUIRE_APPROVAL, a pending ApprovalRecord is
    created in approval_store and ActionBlockedError carries its approval_id.
    Once a human approves it, retry with invoke(..., approval_id=...): the
    approval redeems (single-use, bound to the exact action+input hash) and
    the gate is treated as ALLOW. The default in-memory store only works when
    approvals are decided in this same process — pass a RedisApprovalStore
    when they are decided via the server's /v1/approvals API.

    stream_output selects how streamed output is protected (see
    StreamOutputMode); the default buffers so output policies always see —
    and can redact or block — the full response before the caller does.
    """

    def __init__(
        self,
        agent: Any,
        policies: Sequence[Policy] | None = None,
        *,
        interceptors: Sequence[Policy] | None = None,
        risk_scorer: RiskScorer | None = None,
        approval_store: ApprovalStore | None = None,
        writer: Any | None = None,
        stream_output: StreamOutputMode | str = StreamOutputMode.BUFFER,
        guard_window: int | None = None,
        metrics: MetricsRecorder | None = None,
        tracer: ActionTracer | None = None,
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
        self._approval_store = approval_store or InMemoryApprovalStore()
        self._writer = writer
        self._stream_output = StreamOutputMode(stream_output)
        # guarded-mode hold-back override; None derives it from the guards'
        # max_match_len (the only size that preserves the zero-leak guarantee)
        self._guard_window = guard_window
        self._metrics = metrics
        self._tracer = tracer if tracer is not None else tracer_from_env()
        self._sequence_counters: dict[str, int] = {}

    async def invoke(
        self, input_data: dict[str, Any], *, approval_id: str = "", **kwargs: Any
    ) -> Any:
        result, _ = await self.invoke_with_context(input_data, approval_id=approval_id, **kwargs)
        return result

    async def invoke_with_context(
        self, input_data: dict[str, Any], *, approval_id: str = "", **kwargs: Any
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

        with self._trace(context):
            context, granted = await self._run_before(context, approval_id)

            result = await self._call_agent(input_data, **kwargs)

            context.output_data = result if isinstance(result, dict) else {"output": result}
            context = await self._run_after(context, approval_id, granted)
            self._finalize(context)

            # Return context.output_data so after_action policies (e.g. PIIPolicy)
            # can modify the output that callers receive.
            if isinstance(result, dict):
                return context.output_data, context
            return context.output_data.get("output", result), context

    async def stream(
        self,
        input_data: dict[str, Any],
        *,
        approval_id: str = "",
        stream_output: StreamOutputMode | str | None = None,
        **kwargs: Any,
    ) -> AsyncGenerator[Any, None]:
        """Stream the agent's output through the policy pipeline.

        stream_output overrides the constructor default per call. In BUFFER
        mode (default) chunks are collected, after_action policies run over
        the assembled output, and the scanned result is yielded — an
        output-side DENY blocks before anything reaches the caller. In
        PASSTHROUGH mode chunks are yielded unscanned as they arrive; output
        policies run post-hoc for metadata/audit only.
        """
        mode = StreamOutputMode(stream_output) if stream_output is not None else self._stream_output
        context = ActionContext(
            action="stream",
            agent_id=kwargs.get("agent_id", "default"),
            session_id=kwargs.get("session_id", "default"),
            input_data=input_data,
            metadata=kwargs,
        )

        with self._trace(context):
            context, granted = await self._run_before(context, approval_id)

            if mode == StreamOutputMode.GUARDED:
                async for release in self._stream_guarded(
                    context, input_data, kwargs, approval_id, granted
                ):
                    yield release
                return

            chunks: list[Any] = []
            if mode == StreamOutputMode.PASSTHROUGH:
                async for chunk in self._stream_agent(input_data, **kwargs):
                    chunks.append(chunk)
                    yield chunk
                # post-hoc only: metadata/audit and a (too-late but loud) DENY —
                # redaction here mutates a copy the caller never sees
                context.output_data = self._assemble_output(chunks)
                context = await self._run_after(context, approval_id, granted)
                self._finalize(context)
                return

            # BUFFER: nothing reaches the caller until output policies have run
            async for chunk in self._stream_agent(input_data, **kwargs):
                chunks.append(chunk)
            was_text = bool(chunks) and all(isinstance(c, str) for c in chunks)
            context.output_data = self._assemble_output(chunks)
            context = await self._run_after(context, approval_id, granted)
            self._finalize(context)

            if was_text:
                yield context.output_data.get("output", "")
            else:
                for chunk in context.output_data.get("chunks", []):
                    yield chunk

    @staticmethod
    def _assemble_output(chunks: list[Any]) -> dict[str, Any]:
        """Text streams join into {"output": str} so patterns spanning chunk
        boundaries are caught; anything else stays per-chunk under "chunks"
        (policies recurse into nested dicts/lists)."""
        if chunks and all(isinstance(c, str) for c in chunks):
            return {"output": "".join(chunks)}
        return {"chunks": chunks}

    async def _stream_guarded(
        self,
        context: ActionContext,
        input_data: dict[str, Any],
        kwargs: dict[str, Any],
        approval_id: str,
        granted: bool,
    ) -> AsyncGenerator[str, None]:
        """Sliding-window guarded streaming over text chunks.

        Everything except the last *window* characters is released after the
        guards scan it. Because window >= every guard's max_match_len, a
        match can never straddle the released/held boundary: any pattern
        that could still complete with future text lies entirely in the held
        tail, so redaction happens before delivery and a deny aborts with
        nothing of the match emitted. Matches longer than the window (only
        pathological cases; PEM blocks deny on their header) may partially
        leak before detection.
        """
        guards = []
        for policy in self._policies:
            factory = getattr(policy, "stream_guard", None)
            guard = factory() if callable(factory) else None
            if guard is not None:
                guards.append(guard)
        window = (
            self._guard_window
            if self._guard_window is not None
            else max((g.max_match_len for g in guards), default=0)
        )

        buffer = ""
        emitted: list[str] = []
        async for chunk in self._stream_agent(input_data, **kwargs):
            if not isinstance(chunk, str):
                raise TypeError(
                    "guarded stream mode requires text chunks; "
                    "use stream_output='buffer' for structured chunks"
                )
            buffer += chunk
            buffer = self._apply_guards(buffer, guards, context, final=False)
            if len(buffer) > window:
                release = buffer[: len(buffer) - window]
                buffer = buffer[len(release) :]
                emitted.append(release)
                yield release
        # final flush: matches deferred at the buffer edge are now definite
        buffer = self._apply_guards(buffer, guards, context, final=True)
        if buffer:
            emitted.append(buffer)
            yield buffer

        # policies without a guard (schema, grounding, audit) run at stream
        # end over the released output; a DENY from them raises here
        context.output_data = {"output": "".join(emitted)}
        context = await self._run_after(context, approval_id, granted)
        self._finalize(context)

    def _apply_guards(
        self, text: str, guards: list[Any], context: ActionContext, final: bool
    ) -> str:
        for guard in guards:
            scan = guard.scan(text, final=final)
            if scan.labels:
                meta = context.metadata.setdefault(
                    "stream_guard",
                    {"risk": 0.0, "category": "stream_guard", "labels": [], "denied": False},
                )
                meta["labels"] = list(dict.fromkeys([*meta["labels"], *scan.labels]))
                meta["risk"] = max(meta["risk"], scan.risk)
                if scan.deny:
                    meta["denied"] = True
                    logger.warning(
                        "stream_guard_denied",
                        session_id=context.session_id,
                        guard=guard.name,
                        labels=scan.labels,
                    )
                    self._finalize(context)
                    raise ActionBlockedError(
                        reason=scan.reason,
                        interceptor=guard.name,
                        context=context,
                        risk_score=context.risk_score,
                    )
            text = scan.text
        return text

    async def _run_before(
        self, context: ActionContext, approval_id: str = ""
    ) -> tuple[ActionContext, bool]:
        """Returns (context, approval_granted) — granted carries into the
        after phase so one approved action doesn't re-block on output gates."""
        granted = False
        for policy in self._policies:
            start = time.perf_counter()
            try:
                context = await policy.before_action(context)
            except Exception as exc:
                self._observe_latency(policy, "before", start)
                context = self._handle_failure(policy, exc, context, "before_action")
                continue
            self._observe_latency(policy, "before", start)
            if context.decision == InterceptorDecision.REQUIRE_APPROVAL:
                if granted or await self._redeem_approval(approval_id, context):
                    granted = True
                    context.decision = InterceptorDecision.ALLOW
                    context.decision_reason = ""
                    continue
                await self._request_approval(context, type(policy).__name__)
            if context.decision == InterceptorDecision.DENY:
                self._finalize(context)
                raise ActionBlockedError(
                    reason=context.decision_reason,
                    interceptor=type(policy).__name__,
                    context=context,
                    risk_score=context.risk_score,
                )
        return context, granted

    async def _run_after(
        self, context: ActionContext, approval_id: str = "", granted: bool = False
    ) -> ActionContext:
        blocked_by = ""
        for policy in self._policies:
            start = time.perf_counter()
            try:
                context = await policy.after_action(context)
            except Exception as exc:
                self._observe_latency(policy, "after", start)
                context = self._handle_failure(policy, exc, context, "after_action")
                continue
            self._observe_latency(policy, "after", start)
            if not blocked_by and context.decision != InterceptorDecision.ALLOW:
                blocked_by = type(policy).__name__
        # Unlike the before phase, all policies run to completion (so audit and
        # metadata are complete) before an output-side DENY blocks the response.
        if context.decision == InterceptorDecision.REQUIRE_APPROVAL:
            if granted or await self._redeem_approval(approval_id, context):
                context.decision = InterceptorDecision.ALLOW
                context.decision_reason = ""
                return context
            await self._request_approval(context, blocked_by)
        if context.decision == InterceptorDecision.DENY:
            self._finalize(context)
            raise ActionBlockedError(
                reason=context.decision_reason,
                interceptor=blocked_by,
                context=context,
                risk_score=context.risk_score,
            )
        return context

    async def _redeem_approval(self, approval_id: str, context: ActionContext) -> bool:
        if not approval_id:
            return False
        return await self._approval_store.consume(
            approval_id, action_hash(context.action, context.input_data)
        )

    async def _request_approval(self, context: ActionContext, interceptor_name: str) -> None:
        """Create a pending approval record, emit APPROVAL_REQUESTED, and
        raise ActionBlockedError carrying the approval id."""
        record = ApprovalRecord(
            session_id=context.session_id,
            agent_id=context.agent_id,
            action=context.action,
            reason=context.decision_reason,
            action_hash=action_hash(context.action, context.input_data),
        )
        await self._approval_store.create(record)
        logger.info(
            "approval_requested",
            approval_id=record.approval_id,
            session_id=context.session_id,
            interceptor=interceptor_name,
            reason=context.decision_reason,
        )
        if self._writer is not None:
            seq = self._next_sequence(context.session_id)
            await self._writer.write(
                Event(
                    session_id=context.session_id,
                    agent_id=context.agent_id,
                    event_type=EventType.APPROVAL_REQUESTED,
                    payload={
                        "approval_id": record.approval_id,
                        "action": context.action,
                        "reason": context.decision_reason,
                        "interceptor": interceptor_name,
                        "expires_at": record.expires_at.isoformat(),
                    },
                    sequence_num=seq,
                )
            )
        self._finalize(context)
        raise ActionBlockedError(
            reason=context.decision_reason,
            interceptor=interceptor_name,
            context=context,
            risk_score=context.risk_score,
            approval_id=record.approval_id,
        )

    def _finalize(self, context: ActionContext) -> ActionContext:
        """Aggregate risk and record metrics — runs at every exit point
        (allow, deny, approval-requested), so metrics see every action."""
        self._risk_scorer.aggregate(context)
        if self._metrics is not None:
            self._metrics.record_action(context)
        return context

    def _trace(self, context: ActionContext) -> AbstractContextManager[Any]:
        if self._tracer is None:
            return nullcontext()
        return self._tracer.span(context)

    def _observe_latency(self, policy: Policy, phase: str, start: float) -> None:
        if self._metrics is not None:
            self._metrics.observe_policy_latency(
                type(policy).__name__, phase, time.perf_counter() - start
            )

    def _next_sequence(self, session_id: str) -> int:
        count = self._sequence_counters.get(session_id, 0) + 1
        self._sequence_counters[session_id] = count
        return count

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
