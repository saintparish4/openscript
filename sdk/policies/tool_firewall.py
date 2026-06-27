from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from contracts.interceptor import BasePolicy
from contracts.types import ActionContext, FailureMode, InterceptorDecision


class ToolRule(BaseModel):
    """Firewall rule for a single named tool."""

    deny: bool = False
    allowed_roles: list[str] = Field(default_factory=lambda: ["*"])
    requires_approval: bool = False
    arg_constraints: dict[str, Any] = Field(default_factory=dict)


class ToolRules(BaseModel):
    """Top-level rules model -- maps tool name -> ToolRule.

    Loaded from tools.yaml via load_rules(), or constructed directly.
    """

    rules: dict[str, ToolRule] = Field(default_factory=dict)
    default_deny: bool = False


def load_rules(path: str | Path) -> ToolRules:
    """Load ToolRules from a YAML file at *path*."""
    with open(path) as fh:
        data = yaml.safe_load(fh)
    return ToolRules.model_validate(data or {})


def validate_tool_call(
    tool_call: dict[str, Any],
    role: str | None = None,
    rules: ToolRules | None = None,
) -> dict[str, Any]:
    """Validate *tool_call* against *rules* for an optional *role*.

    Returns a dict with shape:
    {"allowed": bool, "reason": str, "requires_approval": bool}

    This is the standalone helper -- callable outside a policy pipeline
    (e.g. directly from the /v1/tools.validate endpoint).
    """
    if rules is None:
        return {"allowed": True, "reason": "no rules configured", "requires_approval": False}

    tool_name = tool_call.get("name", "")
    tool_args = tool_call.get("args", {})
    rule = rules.rules.get(tool_name)

    # Tool not in rules
    if rule is None:
        if rules.default_deny:
            return {
                "allowed": False,
                "reason": f"tool '{tool_name}' is not in the allowlist",
                "requires_approval": False,
            }
        return {"allowed": True, "reason": "no rule -- default allow", "requires_approval": False}

    # Explicit deny
    if rule.deny:
        return {
            "allowed": False,
            "reason": f"tool '{tool_name}' is explicitly denied",
            "requires_approval": False,
        }

    # RBAC -- skip when wildcard is present
    if role is not None and "*" not in rule.allowed_roles and role not in rule.allowed_roles:
        return {
            "allowed": False,
            "reason": f"role '{role}' is not permitted to call '{tool_name}'",
            "requires_approval": False,
        }

    # Arg constraints -- keys prefixed "max_<field>" impose an upper bound
    for key, limit in rule.arg_constraints.items():
        if key.startswith("max_"):
            field = key[4:]  # e.g. "amount" from "max_amount"
            if field in tool_args:
                val = tool_args[field]
                if isinstance(val, (int, float)) and val > limit:
                    return {
                        "allowed": False,
                        "reason": f"arg '{field}' value {val} exceeds max {limit}",
                        "requires_approval": False,
                    }

    # Requires manual review
    if rule.requires_approval:
        return {
            "allowed": True,
            "reason": f"tool '{tool_name}' requires manual review",
            "requires_approval": True,
        }

    return {"allowed": True, "reason": "tool call permitted", "requires_approval": False}


class ToolFirewallPolicy(BasePolicy):
    """Policy that validates tool calls against a YAML-configured rules set.

    Only acts when context.action == "tool_call"; all other actions pass through.

    Expected context.input_data shape:
      {"name": str, "args": {<arg_name>: <value>, ...}}

    Optional context.metadata key:
      "role": str  — used for RBAC checks against allowed_roles

    Results are written to context.metadata["tool_firewall"] as the same
    {"allowed", "reason", "requires_approval"} dict returned by validate_tool_call.
    """

    failure_mode: FailureMode = FailureMode.FAIL_CLOSED

    def __init__(
        self,
        rules: ToolRules | None = None,
        rules_path: str | Path | None = None,
    ) -> None:
        if rules_path is not None:
            self._rules: ToolRules | None = load_rules(rules_path)
        else:
            self._rules = rules

    async def before_action(self, context: ActionContext) -> ActionContext:
        if context.action != "tool_call":
            return context

        result = validate_tool_call(
            {
                "name": context.input_data.get("name", ""),
                "args": context.input_data.get("args", {}),
            },
            role=context.metadata.get("role"),
            rules=self._rules,
        )

        context.metadata["tool_firewall"] = result

        if result.get("requires_approval"):
            context.decision = InterceptorDecision.REQUIRE_APPROVAL
            context.decision_reason = result["reason"]
        elif not result["allowed"]:
            context.decision = InterceptorDecision.DENY
            context.decision_reason = result["reason"]

        return context
