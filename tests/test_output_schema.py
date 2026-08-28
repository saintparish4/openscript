from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import BaseModel

from contracts.server_types import Event, EventType
from contracts.types import ActionContext, InterceptorDecision
from sdk.policies.config import load_policies
from sdk.policies.output_schema import (
    HallucinationMode,
    OnInvalid,
    OutputSchemaPolicy,
    keyword_grounding_score,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class Report(BaseModel):
    title: str
    total: int


def _ctx(output_data: dict[str, Any] | None = None, **metadata: Any) -> ActionContext:
    return ActionContext(
        action="invoke",
        agent_id="agent",
        session_id="s1",
        output_data=output_data or {},
        metadata=metadata,
    )


class FakeWriter:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def write(self, event: Event) -> None:
        self.events.append(event)


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


async def test_valid_output_passes():
    policy = OutputSchemaPolicy(model=Report)
    ctx = _ctx({"title": "Q3", "total": 42})

    result = await policy.after_action(ctx)

    assert result.decision == InterceptorDecision.ALLOW
    assert result.metadata["output_validation"] == {
        "risk": 0.0,
        "category": "output_validation",
        "valid": True,
        "errors": [],
        "missing_fields": [],
        "dangerous_content": [],
        "on_invalid": "deny",
    }


async def test_missing_field_denied_by_default():
    policy = OutputSchemaPolicy(model=Report)
    ctx = _ctx({"title": "Q3"})

    result = await policy.after_action(ctx)

    assert result.metadata["output_validation"]["missing_fields"] == ["total"]
    assert result.metadata["output_validation"]["risk"] == 0.5
    assert result.decision == InterceptorDecision.DENY
    assert "missing field: total" in result.decision_reason


async def test_annotate_mode_does_not_block():
    policy = OutputSchemaPolicy(model=Report, on_invalid=OnInvalid.ANNOTATE)
    ctx = _ctx({"title": "Q3"})

    result = await policy.after_action(ctx)

    assert result.metadata["output_validation"]["valid"] is False
    assert result.decision == InterceptorDecision.ALLOW


async def test_wrong_type_reported_as_error():
    policy = OutputSchemaPolicy(model=Report, on_invalid="annotate")
    ctx = _ctx({"title": "Q3", "total": "not-a-number"})

    result = await policy.after_action(ctx)

    errors = result.metadata["output_validation"]["errors"]
    assert len(errors) == 1
    assert errors[0].startswith("total:")


async def test_json_string_payload_is_parsed_and_validated():
    policy = OutputSchemaPolicy(model=Report)
    ctx = _ctx({"output": json.dumps({"title": "Q3", "total": 42})})

    result = await policy.after_action(ctx)

    assert result.metadata["output_validation"]["valid"] is True


async def test_invalid_json_string_flagged():
    policy = OutputSchemaPolicy(model=Report)
    ctx = _ctx({"output": "{title: Q3, total:"})

    result = await policy.after_action(ctx)

    errors = result.metadata["output_validation"]["errors"]
    assert any("not valid JSON" in e for e in errors)
    assert result.decision == InterceptorDecision.DENY


async def test_no_model_skips_schema_checks():
    policy = OutputSchemaPolicy()
    ctx = _ctx({"output": "free-form prose, no schema to satisfy"})

    result = await policy.after_action(ctx)

    assert result.metadata["output_validation"]["valid"] is True
    assert result.decision == InterceptorDecision.ALLOW


# ---------------------------------------------------------------------------
# Dangerous-content scan (reuses secrets patterns)
# ---------------------------------------------------------------------------


async def test_dangerous_content_detected_without_model():
    policy = OutputSchemaPolicy()
    ctx = _ctx({"output": "the key is sk-abcdefghijklmnopqrstuvwx"})

    result = await policy.after_action(ctx)

    assert result.metadata["output_validation"]["dangerous_content"] == ["api_key"]
    assert result.metadata["output_validation"]["risk"] == 0.8
    assert result.decision == InterceptorDecision.DENY
    assert "dangerous content" in result.decision_reason


async def test_dangerous_content_in_nested_valid_output():
    class Answer(BaseModel):
        note: str

    policy = OutputSchemaPolicy(model=Answer)
    ctx = _ctx({"note": "reach me at http://vault.internal:8200"})

    result = await policy.after_action(ctx)

    assert result.metadata["output_validation"]["dangerous_content"] == ["internal_url"]
    assert result.metadata["output_validation"]["valid"] is False


# ---------------------------------------------------------------------------
# Hallucination / grounding
# ---------------------------------------------------------------------------


def test_keyword_grounding_score_bounds():
    source = "the quarterly revenue grew twelve percent in Europe"
    assert keyword_grounding_score("revenue grew twelve percent", source) == 0.0
    assert keyword_grounding_score("dolphins invented cryptocurrency", source) == 1.0
    assert keyword_grounding_score("", source) == 0.0


async def test_grounded_output_not_flagged():
    policy = OutputSchemaPolicy(
        grounding_source="quarterly revenue grew twelve percent in Europe",
    )
    ctx = _ctx({"output": "Revenue grew twelve percent."})

    result = await policy.after_action(ctx)

    hallucination = result.metadata["hallucination"]
    assert hallucination["flagged"] is False
    assert hallucination["mode"] == "keyword"
    assert result.decision == InterceptorDecision.ALLOW


async def test_ungrounded_output_flagged_but_not_blocked():
    policy = OutputSchemaPolicy(
        grounding_source="quarterly revenue grew twelve percent in Europe",
    )
    ctx = _ctx({"output": "Dolphins invented cryptocurrency yesterday."})

    result = await policy.after_action(ctx)

    hallucination = result.metadata["hallucination"]
    assert hallucination["flagged"] is True
    assert hallucination["risk"] == 1.0
    assert hallucination["category"] == "hallucination"
    # hallucination is annotation-only; it never blocks on its own
    assert result.decision == InterceptorDecision.ALLOW


async def test_per_request_grounding_source_overrides_constructor():
    policy = OutputSchemaPolicy(grounding_source="completely unrelated words")
    ctx = _ctx(
        {"output": "Dolphins invented cryptocurrency."},
        grounding_source="dolphins invented cryptocurrency long ago",
    )

    result = await policy.after_action(ctx)

    assert result.metadata["hallucination"]["flagged"] is False


async def test_no_grounding_source_no_hallucination_metadata():
    policy = OutputSchemaPolicy(model=Report)
    ctx = _ctx({"title": "Q3", "total": 1})

    result = await policy.after_action(ctx)

    assert "hallucination" not in result.metadata


async def test_embedding_mode_falls_back_to_keyword_without_ml_extra():
    policy = OutputSchemaPolicy(
        grounding_source="quarterly revenue grew twelve percent",
        hallucination_mode=HallucinationMode.EMBEDDING,
    )
    ctx = _ctx({"output": "Revenue grew twelve percent."})

    result = await policy.after_action(ctx)

    # sentence-transformers is not installed in the test env, so the policy
    # must degrade to keyword scoring rather than crash
    assert result.metadata["hallucination"]["mode"] == "keyword"


def test_invalid_threshold_rejected():
    with pytest.raises(ValueError, match="hallucination_threshold"):
        OutputSchemaPolicy(hallucination_threshold=1.5)


# ---------------------------------------------------------------------------
# Events + config loader
# ---------------------------------------------------------------------------


async def test_emits_policy_evaluated_event_on_failure():
    writer = FakeWriter()
    policy = OutputSchemaPolicy(model=Report, writer=writer)
    ctx = _ctx({"title": "Q3"})

    await policy.after_action(ctx)

    assert len(writer.events) == 1
    event = writer.events[0]
    assert event.event_type == EventType.POLICY_EVALUATED
    assert event.payload["policy"] == "output_schema"
    assert event.payload["output_validation"]["missing_fields"] == ["total"]


async def test_no_event_when_valid():
    writer = FakeWriter()
    policy = OutputSchemaPolicy(model=Report, writer=writer)
    ctx = _ctx({"title": "Q3", "total": 1})

    await policy.after_action(ctx)

    assert writer.events == []


def test_load_policies_builds_output_schema_from_dotted_path():
    from sdk.policies.tool_firewall import ToolRule

    (policy,) = load_policies(
        {
            "output_schema": {
                "model": "sdk.policies.tool_firewall:ToolRule",
                "on_invalid": "annotate",
                "hallucination_threshold": 0.7,
            }
        }
    )
    assert isinstance(policy, OutputSchemaPolicy)
    assert policy._model is ToolRule
    assert policy._on_invalid is OnInvalid.ANNOTATE
    assert policy._hallucination_threshold == 0.7


def test_load_policies_rejects_non_model_path():
    with pytest.raises(ValueError, match="not a pydantic BaseModel"):
        load_policies({"output_schema": {"model": "sdk.policies.tool_firewall:validate_tool_call"}})


def test_load_policies_rejects_bad_model_path():
    with pytest.raises(ValueError, match="cannot import"):
        load_policies({"output_schema": {"model": "no.such.module:Nope"}})
