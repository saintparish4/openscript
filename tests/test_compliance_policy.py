from __future__ import annotations

import pytest

from contracts.server_types import Event, EventType
from contracts.types import ActionContext, InterceptorDecision
from sdk.policies.compliance import CompliancePolicy, PHIMode, find_phi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx(
    input_text: str = "",
    output_text: str = "",
    action: str = "invoke",
) -> ActionContext:
    return ActionContext(
        action=action,
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
    return {label for _, label in find_phi(text)}


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_unknown_rule_rejected():
    with pytest.raises(ValueError, match="unknown compliance rule"):
        CompliancePolicy(rules=["gdpr"])


def test_empty_rules_rejected():
    with pytest.raises(ValueError, match="at least one"):
        CompliancePolicy(rules=[])


# ---------------------------------------------------------------------------
# find_phi — detection per PHI category
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "label"),
    [
        ("primary diagnosis E11.9 recorded", "icd10_code"),
        ("patient MRN: 1234567", "mrn"),
        ("medical record number 987654", "mrn"),
        ("member id: ABC-12345", "insurance_id"),
        ("policy number XZ99887", "insurance_id"),
        ("takes metformin 500 mg daily", "medication_dosage"),
        ("prescribed atorvastatin 20mg", "medication_dosage"),
        ("was diagnosed with hypertension", "diagnosis_mention"),
    ],
)
def test_detects_phi_category(text: str, label: str):
    assert label in _labels(text)


@pytest.mark.parametrize(
    "text",
    [
        "the quarterly revenue grew twelve percent",
        "install version 2.9 of the library",
        "the meeting is at 500 Main Street",
    ],
)
def test_clean_text_has_no_phi(text: str):
    assert find_phi(text) == []


# ---------------------------------------------------------------------------
# phi_detection rule
# ---------------------------------------------------------------------------


async def test_phi_annotate_default_does_not_block():
    policy = CompliancePolicy(rules=["phi_detection"])
    ctx = _ctx(input_text="patient MRN: 1234567, diagnosis E11.9")

    result = await policy.before_action(ctx)

    assert result.decision == InterceptorDecision.ALLOW
    assert result.metadata["compliance"]["phi"] == ["icd10_code", "mrn"]
    assert result.metadata["compliance"]["risk"] == 0.6
    assert result.metadata["compliance"]["category"] == "compliance"


async def test_phi_deny_mode_blocks():
    policy = CompliancePolicy(rules=["phi_detection"], phi_mode=PHIMode.DENY)
    ctx = _ctx(input_text="member id: ABC-12345")

    result = await policy.before_action(ctx)

    assert result.decision == InterceptorDecision.DENY
    assert "insurance_id" in result.decision_reason


async def test_phi_scanned_in_output_phase():
    policy = CompliancePolicy(rules=["phi_detection"])
    ctx = _ctx(output_text="the patient was diagnosed with asthma")

    result = await policy.after_action(ctx)

    assert result.metadata["compliance"]["phi"] == ["diagnosis_mention"]


async def test_clean_data_gets_default_metadata():
    policy = CompliancePolicy(rules=["phi_detection"])
    ctx = _ctx(input_text="hello", output_text="all good")

    await policy.before_action(ctx)
    result = await policy.after_action(ctx)

    assert result.metadata["compliance"] == {
        "risk": 0.0,
        "category": "compliance",
        "rules": ["phi_detection"],
        "phi": [],
        "credentials": [],
        "audited": False,
    }


# ---------------------------------------------------------------------------
# credential_output_guard rule
# ---------------------------------------------------------------------------


async def test_credential_in_output_is_blocked():
    policy = CompliancePolicy(rules=["credential_output_guard"])
    ctx = _ctx(output_text="here is the key: sk-abcdefghijklmnopqrstuvwx")

    result = await policy.after_action(ctx)

    assert result.decision == InterceptorDecision.DENY
    assert "api_key" in result.decision_reason
    assert result.metadata["compliance"]["credentials"] == ["api_key"]
    assert result.metadata["compliance"]["risk"] == 0.9


async def test_internal_url_alone_does_not_trigger_credential_guard():
    policy = CompliancePolicy(rules=["credential_output_guard"])
    ctx = _ctx(output_text="see http://vault.internal:8200 for details")

    result = await policy.after_action(ctx)

    assert result.decision == InterceptorDecision.ALLOW
    assert result.metadata["compliance"]["credentials"] == []


async def test_credential_guard_ignores_input_phase():
    policy = CompliancePolicy(rules=["credential_output_guard"])
    ctx = _ctx(input_text="my token is sk-abcdefghijklmnopqrstuvwx")

    result = await policy.before_action(ctx)

    assert result.decision == InterceptorDecision.ALLOW


# ---------------------------------------------------------------------------
# data_access_audit rule
# ---------------------------------------------------------------------------


async def test_tool_call_is_audited():
    writer = FakeWriter()
    policy = CompliancePolicy(rules=["data_access_audit"], writer=writer)
    ctx = ActionContext(
        action="tool_call",
        agent_id="agent",
        session_id="s1",
        input_data={"name": "read_db", "args": {"table": "users", "limit": 10}},
    )

    result = await policy.before_action(ctx)

    assert result.decision == InterceptorDecision.ALLOW
    assert result.metadata["compliance"]["audited"] is True
    assert len(writer.events) == 1
    event = writer.events[0]
    assert event.event_type == EventType.POLICY_EVALUATED
    assert event.payload["policy"] == "data_access_audit"
    assert event.payload["tool"] == "read_db"
    assert event.payload["arg_keys"] == ["limit", "table"]


async def test_non_tool_call_is_not_audited():
    writer = FakeWriter()
    policy = CompliancePolicy(rules=["data_access_audit"], writer=writer)
    ctx = _ctx(input_text="just a normal invoke")

    result = await policy.before_action(ctx)

    assert result.metadata["compliance"]["audited"] is False
    assert writer.events == []


# ---------------------------------------------------------------------------
# Combined rules + events
# ---------------------------------------------------------------------------


async def test_combined_rules_accumulate_risk():
    policy = CompliancePolicy(rules=["phi_detection", "credential_output_guard"])
    ctx = _ctx(
        input_text="patient MRN: 1234567",
        output_text="key sk-abcdefghijklmnopqrstuvwx",
    )

    await policy.before_action(ctx)
    result = await policy.after_action(ctx)

    assert result.metadata["compliance"]["phi"] == ["mrn"]
    assert result.metadata["compliance"]["credentials"] == ["api_key"]
    assert result.metadata["compliance"]["risk"] == 0.9  # max, not sum


async def test_phi_event_emitted_with_writer():
    writer = FakeWriter()
    policy = CompliancePolicy(rules=["phi_detection"], writer=writer)
    ctx = _ctx(input_text="diagnosis code E11.9")

    await policy.before_action(ctx)

    assert len(writer.events) == 1
    assert writer.events[0].payload["policy"] == "phi_detection"
    assert writer.events[0].payload["phi_types"] == ["icd10_code"]
    assert writer.events[0].payload["phase"] == "input"


async def test_mode_accepts_string():
    policy = CompliancePolicy(rules=["phi_detection"], phi_mode="deny")
    ctx = _ctx(input_text="patient MRN: 1234567")

    result = await policy.before_action(ctx)

    assert result.decision == InterceptorDecision.DENY
