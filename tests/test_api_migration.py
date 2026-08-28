"""Tests for the SecureAgent/Policy canonical API and deprecated aliases."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from contracts.interceptor import BasePolicy, Interceptor, Policy
from contracts.types import ActionContext, FailureMode, InterceptorDecision
from sdk import (
    AuditPolicy,
    EventWriterInterceptor,
    OpenScriptMiddleware,
    PIIInterceptor,
    PIIPolicy,
    PromptInjectionPolicy,
    SecureAgent,
    ThreatInterceptor,
)
from sdk.interceptors.base import NoopInterceptor
from sdk.interceptors.pii import PIIMode


class FakeAgent:
    async def ainvoke(self, input_data, **kwargs):
        return {"output": "ok"}


# ---------------------------------------------------------------------------
# Policy protocol and BasePolicy
# ---------------------------------------------------------------------------


def test_interceptor_is_alias_for_policy():
    assert Interceptor is Policy


def test_base_policy_default_failure_mode():
    assert BasePolicy().failure_mode == FailureMode.FAIL_OPEN


@pytest.mark.asyncio
async def test_base_policy_both_hooks_are_pass_through():
    policy = BasePolicy()
    ctx = ActionContext(action="invoke", agent_id="a", session_id="s")
    assert await policy.before_action(ctx) is ctx
    assert await policy.after_action(ctx) is ctx


def test_base_policy_satisfies_policy_protocol():
    assert isinstance(BasePolicy(), Policy)


def test_noop_interceptor_satisfies_policy_protocol():
    assert isinstance(NoopInterceptor(), Policy)


# ---------------------------------------------------------------------------
# SecureAgent — canonical name
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secure_agent_policies_kwarg():
    sa = SecureAgent(agent=FakeAgent(), policies=[NoopInterceptor()])
    assert (await sa.invoke({"input": "hello"}))["output"] == "ok"


@pytest.mark.asyncio
async def test_secure_agent_no_policies_defaults_to_noop():
    sa = SecureAgent(agent=FakeAgent())
    assert (await sa.invoke({"input": "hello"}))["output"] == "ok"


@pytest.mark.asyncio
async def test_secure_agent_interceptors_kwarg_emits_deprecation_warning():
    with pytest.warns(DeprecationWarning, match="interceptors="):
        sa = SecureAgent(agent=FakeAgent(), interceptors=[NoopInterceptor()])
    assert (await sa.invoke({"input": "hello"}))["output"] == "ok"


def test_secure_agent_both_policies_and_interceptors_raises():
    with pytest.raises(ValueError, match="Cannot specify both"):
        SecureAgent(
            agent=FakeAgent(),
            policies=[NoopInterceptor()],
            interceptors=[NoopInterceptor()],
        )


# ---------------------------------------------------------------------------
# OpenScriptMiddleware — deprecated alias
# ---------------------------------------------------------------------------


def test_open_script_middleware_is_subclass_of_secure_agent():
    assert issubclass(OpenScriptMiddleware, SecureAgent)


@pytest.mark.asyncio
async def test_open_script_middleware_warns_on_instantiation():
    with pytest.warns(DeprecationWarning, match="OpenScriptMiddleware"):
        mw = OpenScriptMiddleware(agent=FakeAgent())
    assert (await mw.invoke({"input": "hello"}))["output"] == "ok"


@pytest.mark.asyncio
async def test_open_script_middleware_with_policies_kwarg_still_works():
    with pytest.warns(DeprecationWarning, match="OpenScriptMiddleware"):
        mw = OpenScriptMiddleware(agent=FakeAgent(), policies=[NoopInterceptor()])
    assert (await mw.invoke({"input": "hello"}))["output"] == "ok"


# ---------------------------------------------------------------------------
# PromptInjectionPolicy — renamed from ThreatInterceptor
# ---------------------------------------------------------------------------


def test_threat_interceptor_is_subclass_of_prompt_injection_policy():
    assert issubclass(ThreatInterceptor, PromptInjectionPolicy)


@pytest.mark.asyncio
async def test_prompt_injection_policy_allows_clean_input():
    policy = PromptInjectionPolicy(threshold=0.5)
    ctx = ActionContext(
        action="invoke",
        agent_id="a",
        session_id="s",
        input_data={"input": "What is the capital of France?"},
    )
    result = await policy.before_action(ctx)
    assert result.decision == InterceptorDecision.ALLOW


@pytest.mark.asyncio
async def test_threat_interceptor_alias_warns_and_still_works():
    with pytest.warns(DeprecationWarning, match="ThreatInterceptor"):
        ti = ThreatInterceptor(threshold=0.5)
    ctx = ActionContext(
        action="invoke",
        agent_id="a",
        session_id="s",
        input_data={"input": "hello"},
    )
    result = await ti.before_action(ctx)
    assert result.decision == InterceptorDecision.ALLOW


# ---------------------------------------------------------------------------
# PIIPolicy — renamed from PIIInterceptor
# ---------------------------------------------------------------------------


def test_pii_interceptor_is_subclass_of_pii_policy():
    assert issubclass(PIIInterceptor, PIIPolicy)


@pytest.mark.asyncio
async def test_pii_policy_clean_output_untouched():
    policy = PIIPolicy(mode=PIIMode.REDACT)
    ctx = ActionContext(
        action="invoke",
        agent_id="a",
        session_id="s",
        input_data={"input": "q"},
        output_data={"output": "The answer is 42."},
    )
    result = await policy.after_action(ctx)
    assert result.metadata["pii"]["found"] == []
    assert result.output_data["output"] == "The answer is 42."


@pytest.mark.asyncio
async def test_pii_interceptor_alias_warns_and_still_works():
    with pytest.warns(DeprecationWarning, match="PIIInterceptor"):
        pi = PIIInterceptor(mode=PIIMode.REDACT)
    ctx = ActionContext(
        action="invoke",
        agent_id="a",
        session_id="s",
        input_data={"input": "q"},
        output_data={"output": "clean output"},
    )
    result = await pi.after_action(ctx)
    assert result.metadata["pii"]["found"] == []


# ---------------------------------------------------------------------------
# AuditPolicy — renamed from EventWriterInterceptor
# ---------------------------------------------------------------------------


def test_event_writer_interceptor_is_subclass_of_audit_policy():
    assert issubclass(EventWriterInterceptor, AuditPolicy)


@pytest.mark.asyncio
async def test_audit_policy_before_action_returns_context():
    from events.writer import EventWriter

    mock_store = AsyncMock()
    mock_store.insert_events = AsyncMock()
    writer = EventWriter(store=mock_store, flush_interval=9999)
    policy = AuditPolicy(writer=writer)
    ctx = ActionContext(
        action="invoke",
        agent_id="a",
        session_id="s",
        input_data={"input": "q"},
    )
    result = await policy.before_action(ctx)
    assert result is ctx


@pytest.mark.asyncio
async def test_event_writer_interceptor_alias_warns():
    from events.writer import EventWriter

    mock_store = AsyncMock()
    mock_store.insert_events = AsyncMock()
    writer = EventWriter(store=mock_store, flush_interval=9999)
    with pytest.warns(DeprecationWarning, match="EventWriterInterceptor"):
        ewi = EventWriterInterceptor(writer=writer)
    assert isinstance(ewi, AuditPolicy)


# ---------------------------------------------------------------------------
# Integration: SecureAgent with canonical policy names end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secure_agent_with_multiple_canonical_policies():
    sa = SecureAgent(
        agent=FakeAgent(),
        policies=[
            PromptInjectionPolicy(threshold=0.5),
            PIIPolicy(mode=PIIMode.REDACT),
        ],
    )
    result = await sa.invoke({"input": "What time is it?"})
    assert result["output"] == "ok"
