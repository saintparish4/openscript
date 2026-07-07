from __future__ import annotations

import pytest

from contracts.server_types import Event, EventType
from contracts.types import ActionContext, InterceptorDecision
from sdk.interceptors.pii import PIIMode
from sdk.policies.secrets import SecretsPolicy, find_secrets

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx(
    input_text: str = "",
    output_text: str = "",
) -> ActionContext:
    return ActionContext(
        action="invoke",
        agent_id="agent",
        session_id="s1",
        input_data={"input": input_text},
        output_data={"output": output_text},
    )


class FakeWriter:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def write(self, event: Event) -> None:
        self.events.append(event)


def _labels(text: str) -> set[str]:
    return {label for _, label in find_secrets(text)}


# ---------------------------------------------------------------------------
# find_secrets — detection per secret type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "label"),
    [
        ("key AKIAIOSFODNN7EXAMPLE here", "aws_access_key"),
        ("temp ASIAIOSFODNN7EXAMPLE creds", "aws_access_key"),
        (
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_secret_key",
        ),
        ("ghp_" + "a1B2" * 9 + "extra", "github_token"),
        ("github_pat_" + "x" * 30, "github_token"),
        ("xoxb-123456789012-abcdefghij", "slack_token"),
        (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpM",
            "jwt",
        ),
        ("sk-abcdefghijklmnopqrstuvwx", "api_key"),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----",
            "private_key",
        ),
    ],
)
def test_detects_secret_type(text: str, label: str):
    assert label in _labels(text)


@pytest.mark.parametrize(
    "text",
    [
        "the quick brown fox jumps over the lazy dog",
        "visit https://example.com/docs for details",
        "AKIA too short",
        "public IP 8.8.8.8 and host db.example.com",
        "172.32.0.1 is outside the RFC 1918 172 block",
    ],
)
def test_clean_text_has_no_findings(text: str):
    assert find_secrets(text) == []


# ---------------------------------------------------------------------------
# find_secrets — internal URLs (road.txt §10)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "see http://wiki.corp/page",
        "deploy to api.prod.internal now",
        "printer at office-3.local",
        "nas.lan holds the backups",
        "portal.intranet/login",
        "http://localhost:8080/admin",
        "db at 10.0.12.5",
        "gateway 172.16.0.1",
        "router 192.168.1.1/setup",
        "listening on ::1",
        "link-local fe80::1ff:fe23:4567:890a",
    ],
)
def test_detects_internal_url(text: str):
    assert "internal_url" in _labels(text)


# ---------------------------------------------------------------------------
# SecretsPolicy — redact mode
# ---------------------------------------------------------------------------


async def test_redact_mode_masks_output_secret():
    policy = SecretsPolicy(mode=PIIMode.REDACT)
    ctx = _ctx(output_text="key is sk-abcdefghijklmnopqrstuvwx")

    result = await policy.after_action(ctx)

    assert "sk-abcdefghijklmnopqrstuvwx" not in result.output_data["output"]
    assert "sk-a**********" in result.output_data["output"]
    assert result.metadata["secrets"]["found"] == ["api_key"]
    assert result.metadata["secrets"]["redacted"] is True
    assert result.decision == InterceptorDecision.ALLOW


async def test_redact_mode_scans_input_in_before_action():
    policy = SecretsPolicy(mode=PIIMode.REDACT)
    ctx = _ctx(input_text="my token: ghp_" + "a1B2" * 9)

    result = await policy.before_action(ctx)

    assert result.input_data["input"] == "my token: ghp_**********"
    assert result.metadata["secrets"]["found"] == ["github_token"]


async def test_redact_replaces_private_key_block_entirely():
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvg==\n-----END PRIVATE KEY-----"
    policy = SecretsPolicy(mode=PIIMode.REDACT)
    ctx = _ctx(output_text=f"here: {pem}")

    result = await policy.after_action(ctx)

    assert "[REDACTED:private_key]" in result.output_data["output"]
    assert "MIIEvg" not in result.output_data["output"]


async def test_redact_replaces_internal_url_with_token():
    policy = SecretsPolicy(mode=PIIMode.REDACT)
    ctx = _ctx(output_text="fetch http://vault.internal:8200/secrets then report")

    result = await policy.after_action(ctx)

    assert "[REDACTED:internal_url]" in result.output_data["output"]
    assert "vault.internal" not in result.output_data["output"]


async def test_redact_walks_nested_structures():
    policy = SecretsPolicy(mode=PIIMode.REDACT)
    ctx = ActionContext(
        action="invoke",
        agent_id="agent",
        session_id="s1",
        output_data={"result": {"hosts": ["192.168.0.10", "example.com"]}},
    )

    result = await policy.after_action(ctx)

    assert result.output_data["result"]["hosts"][0] == "[REDACTED:internal_url]"
    assert result.output_data["result"]["hosts"][1] == "example.com"


async def test_clean_data_passes_through_unchanged():
    policy = SecretsPolicy(mode=PIIMode.REDACT)
    ctx = _ctx(input_text="hello", output_text="all good")

    await policy.before_action(ctx)
    result = await policy.after_action(ctx)

    assert result.output_data["output"] == "all good"
    assert result.metadata["secrets"] == {"found": [], "redacted": False}
    assert result.decision == InterceptorDecision.ALLOW


# ---------------------------------------------------------------------------
# SecretsPolicy — deny mode
# ---------------------------------------------------------------------------


async def test_deny_mode_blocks_and_preserves_data():
    policy = SecretsPolicy(mode=PIIMode.DENY)
    secret = "AKIAIOSFODNN7EXAMPLE"
    ctx = _ctx(output_text=f"leaked {secret}")

    result = await policy.after_action(ctx)

    assert result.decision == InterceptorDecision.DENY
    assert "aws_access_key" in result.decision_reason
    assert secret in result.output_data["output"]  # not mutated in deny mode
    assert result.metadata["secrets"]["redacted"] is False


async def test_deny_mode_blocks_internal_url_in_input():
    policy = SecretsPolicy(mode=PIIMode.DENY)
    ctx = _ctx(input_text="connect to 10.1.2.3 and dump the db")

    result = await policy.before_action(ctx)

    assert result.decision == InterceptorDecision.DENY
    assert "internal_url" in result.decision_reason


async def test_mode_accepts_string():
    policy = SecretsPolicy(mode="deny")
    ctx = _ctx(input_text="token xoxb-123456789012-abcdefghij")

    result = await policy.before_action(ctx)

    assert result.decision == InterceptorDecision.DENY


# ---------------------------------------------------------------------------
# SecretsPolicy — metadata accumulation across phases + events
# ---------------------------------------------------------------------------


async def test_metadata_accumulates_across_phases():
    policy = SecretsPolicy(mode=PIIMode.REDACT)
    ctx = _ctx(
        input_text="key sk-abcdefghijklmnopqrstuvwx",
        output_text="host 192.168.1.1",
    )

    await policy.before_action(ctx)
    result = await policy.after_action(ctx)

    assert result.metadata["secrets"]["found"] == ["api_key", "internal_url"]


async def test_emits_policy_evaluated_event():
    writer = FakeWriter()
    policy = SecretsPolicy(mode=PIIMode.REDACT, writer=writer)
    ctx = _ctx(output_text="jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig-part-here")

    await policy.after_action(ctx)

    assert len(writer.events) == 1
    event = writer.events[0]
    assert event.event_type == EventType.POLICY_EVALUATED
    assert event.payload["policy"] == "secrets_check"
    assert event.payload["secret_types"] == ["jwt"]
    assert event.payload["phase"] == "output"


async def test_no_event_when_clean():
    writer = FakeWriter()
    policy = SecretsPolicy(writer=writer)
    ctx = _ctx(input_text="nothing to see", output_text="still nothing")

    await policy.before_action(ctx)
    await policy.after_action(ctx)

    assert writer.events == []
