from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from contracts.types import ActionContext, InterceptorDecision
from sdk.policies.tool_firewall import (
    ToolFirewallPolicy,
    ToolRule,
    ToolRules,
    load_rules,
    validate_tool_call,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rules(**tool_overrides: ToolRule) -> ToolRules:
    return ToolRules(rules=tool_overrides)


def _tool_ctx(name: str, args: dict | None = None, role: str | None = None) -> ActionContext:
    meta = {}
    if role is not None:
        meta["role"] = role
    return ActionContext(
        action="tool_call",
        agent_id="agent",
        session_id="s1",
        input_data={"name": name, "args": args or {}},
        metadata=meta,
    )


# ---------------------------------------------------------------------------
# validate_tool_call — standalone helper
# ---------------------------------------------------------------------------


def test_no_rules_returns_allowed():
    result = validate_tool_call({"name": "do_thing", "args": {}}, rules=None)
    assert result["allowed"] is True
    assert result["requires_approval"] is False


def test_unknown_tool_default_allow():
    rules = ToolRules(default_deny=False)
    result = validate_tool_call({"name": "unknown", "args": {}}, rules=rules)
    assert result["allowed"] is True


def test_unknown_tool_default_deny():
    rules = ToolRules(default_deny=True)
    result = validate_tool_call({"name": "unknown", "args": {}}, rules=rules)
    assert result["allowed"] is False
    assert "allowlist" in result["reason"]


def test_explicit_deny_rule():
    rules = _rules(nuke=ToolRule(deny=True))
    result = validate_tool_call({"name": "nuke", "args": {}}, rules=rules)
    assert result["allowed"] is False
    assert "explicitly denied" in result["reason"]


def test_wildcard_role_allows_any_caller():
    rules = _rules(get_weather=ToolRule(allowed_roles=["*"]))
    for role in (None, "admin", "guest", "hacker"):
        result = validate_tool_call({"name": "get_weather", "args": {}}, role=role, rules=rules)
        assert result["allowed"] is True, f"expected allow for role={role}"


def test_rbac_deny_wrong_role():
    rules = _rules(read_db=ToolRule(allowed_roles=["admin", "operator"]))
    result = validate_tool_call({"name": "read_db", "args": {}}, role="guest", rules=rules)
    assert result["allowed"] is False
    assert "guest" in result["reason"]


def test_rbac_allow_correct_role():
    rules = _rules(read_db=ToolRule(allowed_roles=["admin", "operator"]))
    result = validate_tool_call({"name": "read_db", "args": {}}, role="admin", rules=rules)
    assert result["allowed"] is True


def test_rbac_no_role_provided_passes_when_wildcard():
    rules = _rules(get_weather=ToolRule(allowed_roles=["*"]))
    result = validate_tool_call({"name": "get_weather", "args": {}}, role=None, rules=rules)
    assert result["allowed"] is True


def test_arg_constraint_max_exceeded():
    rules = _rules(transfer=ToolRule(arg_constraints={"max_amount": 500.0}))
    result = validate_tool_call({"name": "transfer", "args": {"amount": 1000.0}}, rules=rules)
    assert result["allowed"] is False
    assert "amount" in result["reason"]
    assert "1000" in result["reason"]


def test_arg_constraint_max_at_limit_passes():
    rules = _rules(transfer=ToolRule(arg_constraints={"max_amount": 500.0}))
    result = validate_tool_call({"name": "transfer", "args": {"amount": 500.0}}, rules=rules)
    assert result["allowed"] is True


def test_arg_constraint_missing_field_is_ignored():
    rules = _rules(transfer=ToolRule(arg_constraints={"max_amount": 100.0}))
    result = validate_tool_call({"name": "transfer", "args": {}}, rules=rules)
    assert result["allowed"] is True


def test_requires_approval_returns_approval_flag():
    rules = _rules(send_email=ToolRule(requires_approval=True))
    result = validate_tool_call({"name": "send_email", "args": {}}, rules=rules)
    assert result["allowed"] is True
    assert result["requires_approval"] is True
    assert result["reason"] != ""


# ---------------------------------------------------------------------------
# ToolFirewallPolicy — before_action
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_tool_call_action_passes_through():
    policy = ToolFirewallPolicy(rules=ToolRules(default_deny=True))
    ctx = ActionContext(
        action="invoke",
        agent_id="a",
        session_id="s",
        input_data={"input": "hello"},
    )
    result = await policy.before_action(ctx)
    assert result.decision == InterceptorDecision.ALLOW
    assert "tool_firewall" not in result.metadata


@pytest.mark.asyncio
async def test_allowed_tool_sets_allow_decision():
    rules = _rules(get_weather=ToolRule(allowed_roles=["*"]))
    policy = ToolFirewallPolicy(rules=rules)
    ctx = _tool_ctx("get_weather")
    result = await policy.before_action(ctx)
    assert result.decision == InterceptorDecision.ALLOW
    assert result.metadata["tool_firewall"]["allowed"] is True


@pytest.mark.asyncio
async def test_denied_tool_sets_deny_decision():
    rules = _rules(nuke=ToolRule(deny=True))
    policy = ToolFirewallPolicy(rules=rules)
    ctx = _tool_ctx("nuke")
    result = await policy.before_action(ctx)
    assert result.decision == InterceptorDecision.DENY
    assert result.decision_reason != ""
    assert result.metadata["tool_firewall"]["allowed"] is False


@pytest.mark.asyncio
async def test_rbac_violation_sets_deny():
    rules = _rules(read_db=ToolRule(allowed_roles=["admin"]))
    policy = ToolFirewallPolicy(rules=rules)
    ctx = _tool_ctx("read_db", role="guest")
    result = await policy.before_action(ctx)
    assert result.decision == InterceptorDecision.DENY


@pytest.mark.asyncio
async def test_requires_approval_sets_require_approval_decision():
    rules = _rules(send_email=ToolRule(requires_approval=True))
    policy = ToolFirewallPolicy(rules=rules)
    ctx = _tool_ctx("send_email")
    result = await policy.before_action(ctx)
    assert result.decision == InterceptorDecision.REQUIRE_APPROVAL
    assert result.metadata["tool_firewall"]["requires_approval"] is True


@pytest.mark.asyncio
async def test_arg_constraint_violation_sets_deny():
    rules = _rules(pay=ToolRule(arg_constraints={"max_amount": 100.0}))
    policy = ToolFirewallPolicy(rules=rules)
    ctx = _tool_ctx("pay", args={"amount": 9999.0})
    result = await policy.before_action(ctx)
    assert result.decision == InterceptorDecision.DENY
    assert "amount" in result.decision_reason


@pytest.mark.asyncio
async def test_metadata_always_written_on_tool_call():
    policy = ToolFirewallPolicy(rules=ToolRules())
    ctx = _tool_ctx("anything")
    result = await policy.before_action(ctx)
    assert "tool_firewall" in result.metadata


# ---------------------------------------------------------------------------
# load_rules — YAML loading
# ---------------------------------------------------------------------------


def test_load_rules_from_yaml(tmp_path: Path):
    yaml_text = textwrap.dedent("""
        default_deny: true
        rules:
          get_weather:
            allowed_roles: ["*"]
          transfer:
            allowed_roles: ["finance"]
            requires_approval: true
            arg_constraints:
              max_amount: 500.0
          nuke:
            deny: true
    """)
    rules_file = tmp_path / "tools.yaml"
    rules_file.write_text(yaml_text)

    rules = load_rules(rules_file)

    assert rules.default_deny is True
    assert "get_weather" in rules.rules
    assert rules.rules["transfer"].requires_approval is True
    assert rules.rules["transfer"].arg_constraints["max_amount"] == 500.0
    assert rules.rules["nuke"].deny is True


@pytest.mark.asyncio
async def test_policy_loads_rules_from_path(tmp_path: Path):
    yaml_text = textwrap.dedent("""
        default_deny: false
        rules:
          allowed_tool:
            allowed_roles: ["*"]
    """)
    rules_file = tmp_path / "tools.yaml"
    rules_file.write_text(yaml_text)

    policy = ToolFirewallPolicy(rules_path=rules_file)
    ctx = _tool_ctx("allowed_tool")
    result = await policy.before_action(ctx)
    assert result.decision == InterceptorDecision.ALLOW
