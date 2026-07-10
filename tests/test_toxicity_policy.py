from __future__ import annotations

import pytest

from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode, InterceptorDecision
from sdk.policies.toxicity import ToxicityPolicy, score_toxicity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx(input_text: str = "") -> ActionContext:
    return ActionContext(
        action="invoke",
        agent_id="agent",
        session_id="s1",
        input_data={"input": input_text},
    )


class FakeWriter:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def write(self, event: Event) -> None:
        self.events.append(event)


# ---------------------------------------------------------------------------
# score_toxicity — detection per category
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "category"),
    [
        ("I am going to kill you", "violence"),
        ("I will hurt them if they show up", "violence"),
        ("you deserve to die", "violence"),
        ("I know where you live", "violence"),
        ("those people are vermin", "hate_speech"),
        ("they should all be exterminated", "hate_speech"),
        ("go back to your country", "hate_speech"),
        ("you are worthless", "harassment"),
        ("nobody likes you anyway", "harassment"),
        ("just kill yourself", "harassment"),
        ("I want to hurt myself", "self_harm"),
        ("I plan to end my life", "self_harm"),
    ],
)
def test_detects_toxic_category(text: str, category: str):
    score, signals = score_toxicity(text)
    assert category in signals
    assert score > 0.0


@pytest.mark.parametrize(
    "text",
    [
        "Tell me about Python async/await.",
        "The weather is going to be sunny tomorrow.",
        "This restaurant's food is terrible.",
        "The character in the novel faces her own mortality.",
    ],
)
def test_clean_text_scores_zero(text: str):
    score, signals = score_toxicity(text)
    assert score == 0.0
    assert signals == {}


def test_category_contributions_are_capped():
    text = "I am going to kill you. I will hurt you. You deserve to die. I know where you live."
    score, signals = score_toxicity(text)
    assert signals["violence"] == 0.7  # category cap
    assert score <= 1.0


# ---------------------------------------------------------------------------
# ToxicityPolicy
# ---------------------------------------------------------------------------


def test_invalid_threshold_rejected():
    with pytest.raises(ValueError, match="threshold"):
        ToxicityPolicy(threshold=1.5)


def test_fails_closed():
    assert ToxicityPolicy().failure_mode == FailureMode.FAIL_CLOSED


async def test_clean_input_allows():
    policy = ToxicityPolicy(threshold=0.5)
    ctx = _ctx("Summarize this quarterly report for me.")

    result = await policy.before_action(ctx)

    assert result.decision == InterceptorDecision.ALLOW
    assert result.metadata["toxicity"]["risk"] == 0.0
    assert result.metadata["toxicity"]["category"] == "toxicity"
    assert result.metadata["toxicity"]["flagged"] is False


async def test_toxic_input_sets_deny():
    policy = ToxicityPolicy(threshold=0.5)
    ctx = _ctx("I am going to kill you and I know where you live.")

    result = await policy.before_action(ctx)

    assert result.decision == InterceptorDecision.DENY
    assert result.metadata["toxicity"]["flagged"] is True
    assert result.metadata["toxicity"]["risk"] >= 0.5
    assert "violence" in result.metadata["toxicity"]["signals"]
    assert result.decision_reason != ""


async def test_threshold_is_respected():
    lenient = ToxicityPolicy(threshold=0.99)
    ctx = _ctx("you are worthless")

    result = await lenient.before_action(ctx)

    assert result.decision == InterceptorDecision.ALLOW
    assert result.metadata["toxicity"]["risk"] > 0.0
    assert result.metadata["toxicity"]["flagged"] is False


async def test_after_action_is_passthrough():
    policy = ToxicityPolicy()
    ctx = _ctx("anything")
    ctx.output_data = {"output": "just kill yourself"}

    result = await policy.after_action(ctx)

    assert result.decision == InterceptorDecision.ALLOW
    assert "toxicity" not in result.metadata


async def test_emits_event_on_block():
    writer = FakeWriter()
    policy = ToxicityPolicy(threshold=0.5, writer=writer)
    ctx = _ctx("those people are vermin and should all be exterminated")

    await policy.before_action(ctx)

    assert len(writer.events) == 1
    event = writer.events[0]
    assert event.event_type == EventType.POLICY_EVALUATED
    assert event.payload["policy"] == "toxicity_check"
    assert "hate_speech" in event.payload["signals"]


async def test_no_event_when_clean():
    writer = FakeWriter()
    policy = ToxicityPolicy(writer=writer)
    ctx = _ctx("What is the capital of France?")

    await policy.before_action(ctx)

    assert writer.events == []
