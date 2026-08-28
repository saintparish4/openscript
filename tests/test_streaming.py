from __future__ import annotations

from typing import Any

import pytest

from contracts.interceptor import BasePolicy
from contracts.server_types import Event, EventType
from contracts.types import ActionBlockedError, InterceptorDecision
from sdk.interceptors.event_writer import AuditPolicy
from sdk.interceptors.pii import PIIMode, PIIPolicy
from sdk.middleware.middleware import SecureAgent, StreamOutputMode
from sdk.policies.secrets import SecretsPolicy

# A secret deliberately split across two chunks: neither fragment matches the
# sk- pattern on its own, only the assembled text does.
_SECRET = "sk-abcdefghijklmnopqrstuvwx"
_SPLIT_SECRET_CHUNKS = ["the key is sk-abcdefghij", "klmnopqrstuvwx done"]


class StreamingAgent:
    def __init__(self, chunks: list[Any]) -> None:
        self._chunks = chunks

    async def astream(self, input_data: dict[str, Any], **kwargs: Any):
        for chunk in self._chunks:
            yield chunk


class FakeWriter:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def write(self, event: Event) -> None:
        self.events.append(event)


async def _collect(agen) -> list[Any]:
    return [chunk async for chunk in agen]


# ---------------------------------------------------------------------------
# BUFFER mode (default)
# ---------------------------------------------------------------------------


async def test_buffer_is_the_default_and_redacts_across_chunk_boundaries():
    agent = StreamingAgent(list(_SPLIT_SECRET_CHUNKS))
    sa = SecureAgent(agent, policies=[SecretsPolicy(mode=PIIMode.REDACT)])

    chunks = await _collect(sa.stream({"input": "hi"}))

    assert chunks == ["the key is sk-a********** done"]
    assert _SECRET not in chunks[0]


async def test_buffer_deny_blocks_before_any_chunk_is_yielded():
    agent = StreamingAgent(list(_SPLIT_SECRET_CHUNKS))
    sa = SecureAgent(agent, policies=[SecretsPolicy(mode=PIIMode.DENY)])

    received: list[Any] = []
    with pytest.raises(ActionBlockedError) as excinfo:
        async for chunk in sa.stream({"input": "hi"}):
            received.append(chunk)

    assert received == []
    assert excinfo.value.interceptor == "SecretsPolicy"
    assert excinfo.value.risk_score == 0.9


async def test_buffer_preserves_dict_chunks_and_redacts_inside():
    agent = StreamingAgent([{"token": "email is"}, {"token": "alice@example.com"}])
    sa = SecureAgent(agent, policies=[PIIPolicy()])

    chunks = await _collect(sa.stream({"input": "hi"}))

    assert len(chunks) == 2
    assert chunks[0] == {"token": "email is"}
    assert chunks[1] == {"token": "[REDACTED:email]"}


async def test_buffer_empty_stream_yields_nothing():
    sa = SecureAgent(StreamingAgent([]), policies=[PIIPolicy()])
    assert await _collect(sa.stream({"input": "hi"})) == []


# ---------------------------------------------------------------------------
# PASSTHROUGH mode
# ---------------------------------------------------------------------------


async def test_passthrough_delivers_unscanned_but_records_metadata():
    writer = FakeWriter()
    agent = StreamingAgent(list(_SPLIT_SECRET_CHUNKS))
    sa = SecureAgent(
        agent,
        policies=[SecretsPolicy(mode=PIIMode.REDACT), AuditPolicy(writer)],
        stream_output=StreamOutputMode.PASSTHROUGH,
    )

    chunks = await _collect(sa.stream({"input": "hi"}))

    assert chunks == _SPLIT_SECRET_CHUNKS  # verbatim — caller got the raw secret
    after = [e for e in writer.events if e.event_type == EventType.INTERCEPTOR_AFTER]
    assert after[0].payload["risk_score"] == 0.9  # but the leak was recorded


async def test_passthrough_deny_raises_after_delivery():
    agent = StreamingAgent(list(_SPLIT_SECRET_CHUNKS))
    sa = SecureAgent(
        agent,
        policies=[SecretsPolicy(mode=PIIMode.DENY)],
        stream_output="passthrough",
    )

    received: list[Any] = []
    with pytest.raises(ActionBlockedError):
        async for chunk in sa.stream({"input": "hi"}):
            received.append(chunk)

    assert received == _SPLIT_SECRET_CHUNKS  # too late to prevent, loud by design


async def test_per_call_override_wins_over_constructor_default():
    agent = StreamingAgent(list(_SPLIT_SECRET_CHUNKS))
    sa = SecureAgent(agent, policies=[SecretsPolicy(mode=PIIMode.REDACT)])  # buffer default

    chunks = await _collect(sa.stream({"input": "hi"}, stream_output="passthrough"))

    assert chunks == _SPLIT_SECRET_CHUNKS


# ---------------------------------------------------------------------------
# GUARDED mode
# ---------------------------------------------------------------------------

_GUARDED_CHUNKS = [
    "Hello, here is the answer. ",
    "It goes on for a while. ",
    "key is sk-abcdefghij",
    "klmnopqrstuvwx",
    " and that is all.",
]
_GUARDED_TEXT = "".join(_GUARDED_CHUNKS)


async def test_guarded_streams_incrementally_and_redacts_across_chunks():
    agent = StreamingAgent(list(_GUARDED_CHUNKS))
    sa = SecureAgent(
        agent,
        policies=[SecretsPolicy(mode=PIIMode.REDACT)],
        stream_output="guarded",
        guard_window=32,
    )

    received = await _collect(sa.stream({"input": "hi"}))

    assert len(received) > 1  # streaming stayed incremental
    joined = "".join(received)
    assert joined == _GUARDED_TEXT.replace(_SECRET, "sk-a**********")
    assert _SECRET not in joined


async def test_guarded_deny_leaks_nothing_of_the_match():
    agent = StreamingAgent(list(_GUARDED_CHUNKS))
    sa = SecureAgent(
        agent,
        policies=[SecretsPolicy(mode=PIIMode.DENY)],
        stream_output="guarded",
        guard_window=32,
    )

    received: list[str] = []
    with pytest.raises(ActionBlockedError) as excinfo:
        async for release in sa.stream({"input": "hi"}):
            received.append(release)

    joined = "".join(received)
    assert joined != ""  # safe text streamed before the abort
    assert "sk-" not in joined  # no fragment of the secret was released
    err = excinfo.value
    assert err.interceptor == "SecretsPolicy"
    assert err.context.metadata["stream_guard"]["denied"] is True
    assert err.risk_score == 0.9


async def test_guarded_defers_boundary_match_instead_of_leaking_its_tail():
    # The first chunk ends mid-secret with enough characters to already
    # satisfy the sk- pattern; redacting that shorter match early would let
    # "vwxyz999" stream out as plain text.
    agent = StreamingAgent(["key sk-abcdefghijklmnopqrstu", "vwxyz999 end padding padding padding"])
    sa = SecureAgent(
        agent,
        policies=[SecretsPolicy(mode=PIIMode.REDACT)],
        stream_output="guarded",
        guard_window=64,
    )

    joined = "".join(await _collect(sa.stream({"input": "hi"})))

    assert joined == "key sk-a********** end padding padding padding"
    assert "vwxyz999" not in joined
    assert "qrstu" not in joined


async def test_guarded_pem_header_aborts_even_in_redact_mode():
    agent = StreamingAgent(["config dump: ", "-----BEGIN RSA PRIVATE KEY-----", "MIIEowIBAAKCAQ=="])
    sa = SecureAgent(agent, policies=[SecretsPolicy(mode=PIIMode.REDACT)], stream_output="guarded")

    received: list[str] = []
    with pytest.raises(ActionBlockedError, match="private key"):
        async for release in sa.stream({"input": "hi"}):
            received.append(release)

    assert "PRIVATE KEY" not in "".join(received)


async def test_guarded_pii_redacts_email():
    agent = StreamingAgent(
        ["contact me at alice", "@example.com thanks", " goodbye friend padding padding"]
    )
    sa = SecureAgent(agent, policies=[PIIPolicy()], stream_output="guarded", guard_window=32)

    joined = "".join(await _collect(sa.stream({"input": "hi"})))

    assert "[REDACTED:email]" in joined
    assert "alice@example.com" not in joined
    assert joined.endswith("goodbye friend padding padding")


async def test_guarded_records_findings_for_risk_scoring():
    writer = FakeWriter()
    agent = StreamingAgent(list(_GUARDED_CHUNKS))
    sa = SecureAgent(
        agent,
        policies=[SecretsPolicy(mode=PIIMode.REDACT), AuditPolicy(writer)],
        stream_output="guarded",
        guard_window=32,
    )

    await _collect(sa.stream({"input": "hi"}))

    after = [e for e in writer.events if e.event_type == EventType.INTERCEPTOR_AFTER]
    assert after[0].payload["risk_score"] == 0.9
    assert after[0].payload["risk_categories"] == {"stream_guard": 0.9, "secrets": 0.0}


async def test_guarded_requires_text_chunks():
    agent = StreamingAgent([{"token": "structured"}])
    sa = SecureAgent(agent, policies=[PIIPolicy()], stream_output="guarded")

    with pytest.raises(TypeError, match="guarded stream mode requires text chunks"):
        await _collect(sa.stream({"input": "hi"}))


async def test_guarded_without_guards_passes_chunks_through_immediately():
    agent = StreamingAgent(["one ", "two ", "three"])
    sa = SecureAgent(agent, stream_output="guarded")  # NoopInterceptor — no guards

    received = await _collect(sa.stream({"input": "hi"}))

    assert received == ["one ", "two ", "three"]


async def test_guarded_global_policy_still_denies_at_stream_end():
    class DenyAtEndPolicy(BasePolicy):
        async def after_action(self, context):
            context.decision = InterceptorDecision.DENY
            context.decision_reason = "schema says no"
            return context

    agent = StreamingAgent(["already ", "delivered"])
    sa = SecureAgent(agent, policies=[DenyAtEndPolicy()], stream_output="guarded")

    received: list[str] = []
    with pytest.raises(ActionBlockedError, match="schema says no"):
        async for release in sa.stream({"input": "hi"}):
            received.append(release)

    assert "".join(received) == "already delivered"


# ---------------------------------------------------------------------------
# Shared semantics
# ---------------------------------------------------------------------------


async def test_before_phase_deny_blocks_both_modes():
    for mode in ("buffer", "passthrough"):
        agent = StreamingAgent(["never yielded"])
        sa = SecureAgent(agent, policies=[SecretsPolicy(mode=PIIMode.DENY)], stream_output=mode)
        received: list[Any] = []
        with pytest.raises(ActionBlockedError):
            async for chunk in sa.stream({"input": f"key {_SECRET}"}):
                received.append(chunk)
        assert received == []


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        SecureAgent(StreamingAgent([]), stream_output="incremental")
