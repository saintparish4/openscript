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


def test_no_rules_is_an_error_not_an_allow():
    """It used to answer "allowed: no rules configured"."""
    with pytest.raises(TypeError):
        validate_tool_call({"name": "do_thing", "args": {}}, rules=None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        validate_tool_call({"name": "do_thing", "args": {}})  # type: ignore[call-arg]


def test_rules_cannot_be_passed_by_position():
    """validate_tool_call(call, rules) used to bind the rules to `role` and allow."""
    rules = _rules(nuke=ToolRule(deny=True))
    with pytest.raises(TypeError):
        validate_tool_call({"name": "nuke", "args": {}}, rules)  # type: ignore[misc]


def test_policy_without_rules_cannot_be_built():
    with pytest.raises(ValueError, match="rules"):
        ToolFirewallPolicy()
    with pytest.raises(ValueError, match="not both"):
        ToolFirewallPolicy(rules=ToolRules(), rules_path="tools.yaml")


def test_nameless_or_malformed_call_is_refused():
    rules = ToolRules()
    assert validate_tool_call({"args": {}}, rules=rules)["allowed"] is False
    assert (
        validate_tool_call({"name": "t", "args": ["not", "a", "mapping"]}, rules=rules)["allowed"]
        is False
    )


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
    assert result.metadata["tool_firewall"]["risk"] == 0.0
    assert result.metadata["tool_firewall"]["category"] == "tool_firewall"


@pytest.mark.asyncio
async def test_denied_tool_sets_deny_decision():
    rules = _rules(nuke=ToolRule(deny=True))
    policy = ToolFirewallPolicy(rules=rules)
    ctx = _tool_ctx("nuke")
    result = await policy.before_action(ctx)
    assert result.decision == InterceptorDecision.DENY
    assert result.decision_reason != ""
    assert result.metadata["tool_firewall"]["allowed"] is False
    assert result.metadata["tool_firewall"]["risk"] == 0.8


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
    assert result.metadata["tool_firewall"]["risk"] == 0.6


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


# ---------------------------------------------------------------------------
# Fail-closed behaviour of the checks that already existed
# ---------------------------------------------------------------------------


def test_restricted_tool_refuses_a_call_with_no_role():
    """No role is not every role."""
    rules = _rules(read_db=ToolRule(allowed_roles=["admin", "operator"]))
    result = validate_tool_call({"name": "read_db", "args": {}}, role=None, rules=rules)
    assert result["allowed"] is False
    assert "role" in result["reason"]


@pytest.mark.parametrize("amount", ["9999", " 9999 ", "1e9", 10**400, float("inf")])
def test_numeric_bound_is_not_skipped_for_values_that_are_not_plain_numbers(amount):
    rules = _rules(transfer=ToolRule(arg_constraints={"max_amount": 100}))
    assert (
        validate_tool_call({"name": "transfer", "args": {"amount": amount}}, rules=rules)["allowed"]
        is False
    )


@pytest.mark.parametrize("amount", [float("nan"), "nan", True, "a lot", {"value": 5}, b"\xff"])
def test_value_that_cannot_be_compared_is_refused(amount):
    """NaN is the sharp one: every comparison against it is false."""
    rules = _rules(transfer=ToolRule(arg_constraints={"max_amount": 100}))
    result = validate_tool_call({"name": "transfer", "args": {"amount": amount}}, rules=rules)
    assert result["allowed"] is False
    assert "cannot be checked" in result["reason"]


def test_numeric_text_within_the_bound_passes():
    rules = _rules(transfer=ToolRule(arg_constraints={"max_amount": 100}))
    assert (
        validate_tool_call({"name": "transfer", "args": {"amount": "50"}}, rules=rules)["allowed"]
        is True
    )


def test_reason_does_not_echo_an_unbounded_value():
    rules = _rules(transfer=ToolRule(arg_constraints={"max_amount": 100}))
    result = validate_tool_call({"name": "transfer", "args": {"amount": "9" * 5000}}, rules=rules)
    assert result["allowed"] is False
    assert len(result["reason"]) < 200


# ---------------------------------------------------------------------------
# The rule language: args
# ---------------------------------------------------------------------------


def _one(arg: str, **constraint) -> ToolRules:
    return ToolRules.model_validate({"rules": {"tool": {"args": {arg: constraint}}}})


def _allowed(rules: ToolRules, **args) -> bool:
    return validate_tool_call({"name": "tool", "args": args}, rules=rules)["allowed"]


def test_min_and_max():
    rules = _one("amount", min=0, max=100)
    assert _allowed(rules, amount=0) and _allowed(rules, amount=100)
    assert not _allowed(rules, amount=-1)
    assert not _allowed(rules, amount=100.01)


def test_legacy_min_constraint_is_honoured():
    """min_<arg> used to be accepted and silently ignored."""
    rules = _rules(transfer=ToolRule(arg_constraints={"min_amount": 0, "max_amount": 100}))
    assert (
        validate_tool_call({"name": "transfer", "args": {"amount": -5000}}, rules=rules)["allowed"]
        is False
    )


def test_required():
    rules = _one("to", required=True)
    assert _allowed(rules, to="a@example.com")
    assert not _allowed(rules)
    assert not _allowed(rules, to=None)


def test_one_of_is_exact_and_does_not_confuse_true_with_one():
    rules = _one("env", one_of=["staging", "dev", 1])
    assert _allowed(rules, env="staging") and _allowed(rules, env=1)
    assert not _allowed(rules, env="production")
    assert not _allowed(rules, env="Staging")
    assert not _allowed(rules, env=True)


def test_pattern_has_to_match_the_whole_value():
    rules = _one("to", pattern=r"[^@\s]+@example\.com")
    assert _allowed(rules, to="ops@example.com")
    assert not _allowed(rules, to="ops@example.com.attacker.io")
    assert not _allowed(rules, to="ops@example.com\nbcc: x@attacker.io")
    assert not _allowed(rules, to=42)


def test_list_arguments_are_checked_item_by_item():
    rules = _one("to", pattern=r"[^@\s]+@example\.com")
    assert _allowed(rules, to=["a@example.com", "b@example.com"])
    assert not _allowed(rules, to=["a@example.com", "x@attacker.io"])
    assert not _allowed(rules, to={"primary": "a@example.com"})


@pytest.mark.parametrize(
    "path",
    ["reports/q3.pdf", "./reports/q3.pdf", "reports/2026/../q3.pdf", "reports", "reports//q3.pdf"],
)
def test_path_inside_the_prefix(path):
    assert _allowed(_one("path", path_prefix="reports"), path=path)


@pytest.mark.parametrize(
    "path",
    [
        "reports/../../etc/passwd",
        "reports/..",
        "../reports/q3.pdf",
        "/reports/q3.pdf",
        "~/.ssh/id_rsa",
        "reports-old/q3.pdf",
        "reports\\..\\secrets.txt",
        "reports/q3.pdf\x00.png",
        "",
        "/etc/passwd",
    ],
)
def test_path_outside_the_prefix(path):
    assert not _allowed(_one("path", path_prefix="reports"), path=path)


@pytest.mark.parametrize("path", ["/etc/passwd", "../x", "~/x", "C:/Windows/x", "file:/etc/passwd"])
def test_working_directory_prefix_admits_only_what_is_really_relative(path):
    rules = _one("path", path_prefix=".")
    assert _allowed(rules, path="notes/todo.txt")
    assert not _allowed(rules, path=path)


def test_several_prefixes_and_absolute_ones():
    rules = _one("path", path_prefix=["/srv/data", "/tmp/scratch"])
    assert _allowed(rules, path="/srv/data/a.csv") and _allowed(rules, path="/tmp/scratch/b")
    assert not _allowed(rules, path="/srv/data-old/a.csv")
    assert not _allowed(rules, path="/srv/data/../secrets")


def test_unlisted_args_can_be_refused():
    """An allowlist on `to` means little while `bcc` is free."""
    open_rule = ToolRules.model_validate(
        {"rules": {"tool": {"args": {"to": {"pattern": r".*@example\.com"}}}}}
    )
    closed_rule = ToolRules.model_validate(
        {
            "rules": {
                "tool": {
                    "unlisted_args": "deny",
                    "args": {"to": {"pattern": r".*@example\.com"}, "body": {}},
                }
            }
        }
    )
    call = {"to": "a@example.com", "bcc": "x@attacker.io"}
    assert _allowed(open_rule, **call)
    assert not _allowed(closed_rule, **call)
    assert _allowed(closed_rule, to="a@example.com", body="hello")


def test_out_of_bounds_call_is_denied_not_sent_for_approval():
    rules = ToolRules.model_validate(
        {"rules": {"tool": {"requires_approval": True, "args": {"amount": {"max": 100}}}}}
    )
    over = validate_tool_call({"name": "tool", "args": {"amount": 500}}, rules=rules)
    under = validate_tool_call({"name": "tool", "args": {"amount": 50}}, rules=rules)
    assert over["allowed"] is False and over["requires_approval"] is False
    assert under["allowed"] is True and under["requires_approval"] is True


# ---------------------------------------------------------------------------
# A rule file that does not mean what it says fails at load
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        {"rules": {"t": {"requries_approval": True}}},  # misspelt key
        {"rules": {"t": {"args": {"a": {"patern": "x"}}}}},
        {"rulez": {}},
        {"rules": {"t": {"arg_constraints": {"limit_amount": 5}}}},
        {"rules": {"t": {"arg_constraints": {"max_amount": True}}}},
        {"rules": {"t": {"arg_constraints": {"max_amount": "100"}}}},
        {"rules": {"t": {"args": {"a": {"pattern": "("}}}}},
        {"rules": {"t": {"args": {"a": {"min": 5, "max": 1}}}}},
        {"rules": {"t": {"args": {"a": {"max": 1}}, "arg_constraints": {"max_a": 2}}}},
        {"rules": {"t": {"unlisted_args": "reject"}}},
    ],
)
def test_rules_that_would_silently_not_apply_are_rejected(bad):
    with pytest.raises(ValueError):
        ToolRules.model_validate(bad)


def test_empty_rules_file_is_an_error(tmp_path: Path):
    """It used to load as "no rules", which allows everything."""
    empty = tmp_path / "tools.yaml"
    empty.write_text("# nothing yet\n")
    with pytest.raises(ValueError, match="empty"):
        load_rules(empty)


def test_example_rules_file_loads():
    example = Path(__file__).resolve().parent.parent / "sdk" / "policies" / "tools_example.yaml"
    rules = load_rules(example)
    assert rules.rules["delete_record"].deny is True
