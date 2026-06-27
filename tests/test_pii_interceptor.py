from __future__ import annotations

import pytest

from contracts.types import ActionContext, FailureMode, InterceptorDecision
from sdk.interceptors.pii import PIIMode, PIIPolicy, _find_pii, _redact_text


def _ctx(output: str, session_id: str = "s1") -> ActionContext:
    return ActionContext(
        action="invoke",
        agent_id="test-agent",
        session_id=session_id,
        input_data={"input": "some question"},
        output_data={"output": output},
    )


# ---------------------------------------------------------------------------
# _find_pii unit tests
# ---------------------------------------------------------------------------


def test_detects_email():
    found = _find_pii("Contact us at alice@example.com for more info.")
    labels = [label for _, label in found]
    assert "email" in labels


def test_detects_phone():
    found = _find_pii("Call 555-867-5309 for help.")
    labels = [label for _, label in found]
    assert "phone" in labels


def test_detects_ssn():
    found = _find_pii("SSN: 123-45-6789")
    labels = [label for _, label in found]
    assert "ssn" in labels


def test_detects_credit_card():
    found = _find_pii("Card: 4111 1111 1111 1111")
    labels = [label for _, label in found]
    assert "credit_card" in labels


def test_rejects_invalid_credit_card():
    # 1234 5678 9012 3456 fails Luhn check
    found = _find_pii("Card: 1234 5678 9012 3456")
    labels = [label for _, label in found]
    assert "credit_card" not in labels


def test_detects_api_key():
    found = _find_pii("token=sk-abc123defghijklmnopqrst")
    labels = [label for _, label in found]
    assert "api_key" in labels


def test_clean_text_returns_empty():
    found = _find_pii("The weather is nice today.")
    assert found == []


# ---------------------------------------------------------------------------
# _redact_text unit tests
# ---------------------------------------------------------------------------


def test_redact_email():
    text, labels = _redact_text("Email me at bob@test.org")
    assert "[REDACTED:email]" in text
    assert "email" in labels
    assert "bob@test.org" not in text


def test_redact_ssn():
    text, _labels = _redact_text("His SSN is 987-65-4321.")
    assert "[REDACTED:ssn]" in text


def test_redact_multiple_types():
    raw = "email: user@example.com and SSN: 123-45-6789"
    text, labels = _redact_text(raw)
    assert "[REDACTED:email]" in text
    assert "[REDACTED:ssn]" in text
    assert len(set(labels)) == 2


def test_no_pii_returns_original():
    original = "Nothing sensitive here."
    text, labels = _redact_text(original)
    assert text == original
    assert labels == []


# ---------------------------------------------------------------------------
# PIIPolicy integration tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redact_mode_replaces_pii():
    policy = PIIPolicy(mode=PIIMode.REDACT)
    ctx = _ctx("Your email is alice@example.com")
    result = await policy.after_action(ctx)
    assert "[REDACTED:email]" in result.output_data["output"]
    assert result.decision == InterceptorDecision.ALLOW
    assert result.metadata["pii"]["redacted"] is True


@pytest.mark.asyncio
async def test_deny_mode_sets_decision():
    policy = PIIPolicy(mode=PIIMode.DENY)
    ctx = _ctx("SSN: 123-45-6789")
    result = await policy.after_action(ctx)
    assert result.decision == InterceptorDecision.DENY
    assert result.metadata["pii"]["redacted"] is False
    assert "ssn" in result.metadata["pii"]["found"]


@pytest.mark.asyncio
async def test_clean_output_untouched():
    policy = PIIPolicy()
    ctx = _ctx("The answer is 42.")
    result = await policy.after_action(ctx)
    assert result.output_data["output"] == "The answer is 42."
    assert result.metadata["pii"]["found"] == []
    assert result.metadata["pii"]["redacted"] is False


@pytest.mark.asyncio
async def test_before_action_passthrough():
    policy = PIIPolicy()
    ctx = _ctx("some output")
    ctx.input_data = {"input": "my email is me@example.com"}
    result = await policy.before_action(ctx)
    # before_action should NOT scan input — only after_action scans output
    assert result.input_data == ctx.input_data


@pytest.mark.asyncio
async def test_failure_mode_is_fail_open():
    policy = PIIPolicy()
    assert policy.failure_mode == FailureMode.FAIL_OPEN


@pytest.mark.asyncio
async def test_nested_dict_output_redacted():
    policy = PIIPolicy(mode=PIIMode.REDACT)
    ctx = ActionContext(
        action="invoke",
        agent_id="agent",
        session_id="s1",
        input_data={"input": "q"},
        output_data={"result": {"user": "alice@example.com", "note": "call 555-867-5309"}},
    )
    result = await policy.after_action(ctx)
    assert "[REDACTED:email]" in result.output_data["result"]["user"]
    assert "[REDACTED:phone]" in result.output_data["result"]["note"]


@pytest.mark.asyncio
async def test_multiple_pii_types_all_found():
    policy = PIIPolicy(mode=PIIMode.REDACT)
    raw = "email: user@example.com | SSN: 123-45-6789 | card: 4111 1111 1111 1111"
    ctx = _ctx(raw)
    result = await policy.after_action(ctx)
    found = result.metadata["pii"]["found"]
    assert "email" in found
    assert "ssn" in found
    assert "credit_card" in found
