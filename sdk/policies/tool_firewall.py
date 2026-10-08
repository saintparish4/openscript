from __future__ import annotations

import math
import posixpath
import re
from collections.abc import Collection
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from contracts.interceptor import BasePolicy
from contracts.types import ActionContext, FailureMode, InterceptorDecision


class ArgRule(BaseModel):
    """What one argument of a tool is allowed to be.

    Every constraint that is set has to hold. A list or tuple is checked item
    by item, so ``to=["a@x", "b@y"]`` passes only if both recipients do. A
    value a constraint cannot be evaluated against — a dict where text was
    expected, text where a number was — is refused, not waved through: a check
    that could not run is not a check that passed.
    """

    # A misspelt constraint must fail the load. Ignored, it would be a rule
    # that reads as enforced and enforces nothing.
    model_config = ConfigDict(extra="forbid")

    required: bool = False
    #: Exact values, compared with ==. True never matches 1.
    one_of: list[Any] | None = None
    #: A regular expression the whole value has to match (re.fullmatch), so
    #: "example\\.com" cannot be satisfied by "example.com.attacker.io".
    pattern: str | None = None
    #: Directories the path has to sit inside, once ".." has been resolved.
    path_prefix: list[str] | None = None
    min: int | float | None = None
    max: int | float | None = None

    @field_validator("pattern")
    @classmethod
    def _pattern_compiles(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(
                    f"pattern {value!r} is not a valid regular expression: {exc}"
                ) from exc
        return value

    @field_validator("path_prefix", mode="before")
    @classmethod
    def _one_prefix_or_many(cls, value: Any) -> Any:
        return [value] if isinstance(value, str) else value

    @field_validator("min", "max", mode="before")
    @classmethod
    def _bound_is_a_number(cls, value: Any) -> Any:
        if isinstance(value, bool) or (isinstance(value, float) and not math.isfinite(value)):
            raise ValueError("a bound has to be a finite number")
        return value

    @model_validator(mode="after")
    def _bounds_are_ordered(self) -> ArgRule:
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError(f"min {self.min} is greater than max {self.max}")
        return self


class ToolRule(BaseModel):
    """Firewall rule for a single named tool."""

    model_config = ConfigDict(extra="forbid")

    deny: bool = False
    allowed_roles: list[str] = Field(default_factory=lambda: ["*"])
    requires_approval: bool = False
    #: Per-argument constraints, keyed by argument name.
    args: dict[str, ArgRule] = Field(default_factory=dict)
    #: What to do with an argument the caller passes that ``args`` does not
    #: name. An allowlist on ``to`` means little while ``bcc`` is free, so a
    #: rule that is meant to be the whole truth about what may be passed to a
    #: tool should say "deny".
    unlisted_args: Literal["allow", "deny"] = "allow"
    #: The older spelling of a numeric bound: ``max_<arg>`` / ``min_<arg>``.
    #: Still honoured, and folded into the same checks as ``args``.
    arg_constraints: dict[str, int | float] = Field(default_factory=dict)

    @field_validator("arg_constraints", mode="before")
    @classmethod
    def _limits_are_numbers(cls, value: Any) -> Any:
        # Before pydantic coerces: True would otherwise arrive here as 1.
        if isinstance(value, dict):
            for key, limit in value.items():
                if isinstance(limit, bool) or not isinstance(limit, (int, float)):
                    raise ValueError(f"arg_constraints {key!r} has to be a number")
        return value

    @model_validator(mode="after")
    def _arg_constraints_make_sense(self) -> ToolRule:
        # Raises on a key that is not a bound, or a bound set twice. Done at
        # load so a bad rule file fails there and not on the first tool call.
        self.arg_rules  # noqa: B018
        return self

    @property
    def arg_rules(self) -> dict[str, ArgRule]:
        """``args`` and ``arg_constraints`` as one set of per-argument rules."""
        merged = dict(self.args)
        for key, limit in self.arg_constraints.items():
            bound, _, arg = key.partition("_")
            if bound not in ("max", "min") or not arg:
                raise ValueError(
                    f"arg_constraints key {key!r} is not max_<arg> or min_<arg>; "
                    "use args: for anything else"
                )
            current = merged.get(arg, ArgRule())
            if getattr(current, bound) is not None:
                raise ValueError(f"{bound} for {arg!r} is set under both args and arg_constraints")
            merged[arg] = ArgRule.model_validate(
                {**current.model_dump(exclude_none=True), bound: limit}
            )
        return merged


class ToolRules(BaseModel):
    """Top-level rules model -- maps tool name -> ToolRule.

    Loaded from tools.yaml via load_rules(), or constructed directly.
    """

    model_config = ConfigDict(extra="forbid")

    rules: dict[str, ToolRule] = Field(default_factory=dict)
    default_deny: bool = False


def load_rules(path: str | Path) -> ToolRules:
    """Load ToolRules from a YAML file at *path*."""
    with open(path) as fh:
        data = yaml.safe_load(fh)
    if data is None:
        # An empty file would otherwise load as "no rules, allow everything".
        raise ValueError(f"tool rules file {str(path)!r} is empty")
    return ToolRules.model_validate(data)


def _show(value: Any) -> str:
    """A value for a reason string. The value is the caller's, so it is cut short."""
    text = repr(value)
    return text if len(text) <= 60 else text[:57] + "..."


def _as_number(value: Any) -> float | None:
    """The finite number *value* stands for, or None if it does not stand for one.

    Numeric text counts, because a tool that takes "9999" will read it as 9999
    and a bound that only looked at real numbers would let it past. NaN and
    infinity do not: every comparison against NaN is false, which is how a
    limit gets skipped without anything looking wrong.
    """
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _normalise_path(path: str) -> str | None:
    if not path or "\x00" in path:
        return None
    # Backslashes first, so "reports\\..\\secrets" cannot skip the resolution.
    return posixpath.normpath(path.replace("\\", "/"))


def _within(path: str, prefix: str) -> bool:
    """Whether *path* sits inside *prefix* once ".." and "." are resolved.

    Lexical only: nothing here touches a filesystem, so it runs the same in a
    browser tab as on a server — and it cannot see a symlink inside the allowed
    directory that points back out of it. "~" is not expanded either; a path
    that begins with it only matches a prefix spelt the same way.
    """
    target, root = _normalise_path(path), _normalise_path(prefix)
    if target is None or root is None:
        return False
    if root == ".":
        # "anything under the working directory": relative, not climbing out,
        # and not something that only looks relative (C:/..., file:/..., ~/...).
        head = target.split("/", 1)[0]
        return not (target.startswith("/") or head == ".." or head.startswith("~") or ":" in head)
    if target == root:
        return True
    # Compared a whole component at a time: "/srv/data-old" is not in "/srv/data".
    return target.startswith(root.rstrip("/") + "/")


def _check_value(arg: str, value: Any, rule: ArgRule) -> str | None:
    """Why *value* breaks *rule*, or None if it does not."""
    if rule.one_of is not None and not any(
        isinstance(permitted, bool) == isinstance(value, bool) and permitted == value
        for permitted in rule.one_of
    ):
        return f"arg '{arg}' value {_show(value)} is not one of the permitted values"
    if rule.pattern is not None and (
        not isinstance(value, str) or re.fullmatch(rule.pattern, value) is None
    ):
        return f"arg '{arg}' value {_show(value)} does not match the permitted pattern"
    if rule.path_prefix is not None and (
        not isinstance(value, str) or not any(_within(value, p) for p in rule.path_prefix)
    ):
        return f"arg '{arg}' value {_show(value)} is outside the permitted paths"
    if rule.min is not None or rule.max is not None:
        number = _as_number(value)
        if number is None:
            return (
                f"arg '{arg}' value {_show(value)} is not a finite number, "
                "so it cannot be checked against its limit"
            )
        if rule.max is not None and number > rule.max:
            return f"arg '{arg}' value {_show(value)} exceeds max {rule.max}"
        if rule.min is not None and number < rule.min:
            return f"arg '{arg}' value {_show(value)} is below min {rule.min}"
    return None


def _check_arg(arg: str, args: dict[str, Any], rule: ArgRule) -> str | None:
    value = args.get(arg)
    if value is None:
        return f"arg '{arg}' is required" if rule.required else None
    for item in value if isinstance(value, (list, tuple)) else [value]:
        problem = _check_value(arg, item, rule)
        if problem is not None:
            return problem
    return None


def _refuse(reason: str) -> dict[str, Any]:
    return {"allowed": False, "reason": reason, "requires_approval": False}


def validate_tool_call(
    tool_call: dict[str, Any],
    *,
    role: str | None = None,
    rules: ToolRules,
    defaulted: Collection[str] = (),
) -> dict[str, Any]:
    """Validate *tool_call* against *rules* for an optional *role*.

    Returns a dict with shape:
    {"allowed": bool, "reason": str, "requires_approval": bool}

    This is the standalone helper -- callable outside a policy pipeline
    (e.g. directly from the /v1/tools.validate endpoint). To put the same
    check in front of a tool an agent calls, wrap the tool in SecureTool.

    *role* and *rules* are keyword-only and *rules* is required. Both used to
    be optional and positional, which made ``validate_tool_call(call, rules)``
    bind the rules to *role* and answer "allowed: no rules configured".

    *defaulted* names the arguments in the call that the caller did not pass:
    values the tool's own signature supplied. They are checked against any
    rule that names them, like every other argument, but ``unlisted_args:
    deny`` does not refuse them — that setting is about what a caller may
    pass, and a default is the tool author's choice, not the caller's.
    """
    if not isinstance(rules, ToolRules):
        raise TypeError(f"rules must be a ToolRules, got {type(rules).__name__}")

    tool_name = tool_call.get("name", "")
    if not isinstance(tool_name, str) or not tool_name:
        return _refuse("tool call has no name")
    tool_args = tool_call.get("args")
    if tool_args is None:
        tool_args = {}
    if not isinstance(tool_args, dict):
        return _refuse(f"arguments for '{tool_name}' are not a mapping of name to value")

    rule = rules.rules.get(tool_name)

    # Tool not in rules
    if rule is None:
        if rules.default_deny:
            return _refuse(f"tool '{tool_name}' is not in the allowlist")
        return {"allowed": True, "reason": "no rule -- default allow", "requires_approval": False}

    # Explicit deny
    if rule.deny:
        return _refuse(f"tool '{tool_name}' is explicitly denied")

    # RBAC -- skip when wildcard is present. A call that names no role is not a
    # call from every role: against a restricted tool it is refused.
    if "*" not in rule.allowed_roles:
        if role is None:
            return _refuse(f"'{tool_name}' is restricted by role and the call carries none")
        if role not in rule.allowed_roles:
            return _refuse(f"role '{role}' is not permitted to call '{tool_name}'")

    arg_rules = rule.arg_rules
    if rule.unlisted_args == "deny":
        unlisted = sorted(
            str(arg) for arg in tool_args if arg not in arg_rules and arg not in defaulted
        )
        if unlisted:
            return _refuse(f"arg '{unlisted[0]}' is not one '{tool_name}' is permitted to take")
    for arg, arg_rule in arg_rules.items():
        problem = _check_arg(arg, tool_args, arg_rule)
        if problem is not None:
            return _refuse(problem)

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
    SecureAgent never produces that action — it sees an agent's input and its
    final output, not the tools called in between — so this policy does nothing
    in a SecureAgent's list. It belongs in the list given to SecureTool, which
    wraps one tool and runs these checks on every call to it.

    Expected context.input_data shape:
      {"name": str, "args": {<arg_name>: <value>, ...}}

    Optional context.metadata keys:
      "role": str  — used for RBAC checks against allowed_roles
      "defaulted_args": [str]  — arguments the caller left to the tool's own
        defaults (SecureTool fills this in); see validate_tool_call

    Results are written to context.metadata["tool_firewall"] using the
    standardized shape — the {"allowed", "reason", "requires_approval"} dict
    returned by validate_tool_call plus "risk" (denied 0.8, requires
    approval 0.6, allowed 0.0) and "category": "tool_firewall".
    """

    failure_mode: FailureMode = FailureMode.FAIL_CLOSED

    def __init__(
        self,
        rules: ToolRules | None = None,
        rules_path: str | Path | None = None,
    ) -> None:
        if rules is not None and rules_path is not None:
            raise ValueError("pass rules or rules_path, not both")
        if rules_path is not None:
            self._rules = load_rules(rules_path)
        elif rules is not None:
            self._rules = rules
        else:
            # It used to be accepted and meant "allow every call", which is not
            # what anyone constructing a firewall is asking for.
            raise ValueError("ToolFirewallPolicy needs rules= or rules_path=")

    async def before_action(self, context: ActionContext) -> ActionContext:
        if context.action != "tool_call":
            return context

        result = validate_tool_call(
            {
                "name": context.input_data.get("name", ""),
                "args": context.input_data.get("args"),
            },
            role=context.metadata.get("role"),
            rules=self._rules,
            defaulted=context.metadata.get("defaulted_args") or (),
        )

        if result.get("requires_approval"):
            risk = 0.6
        elif not result["allowed"]:
            risk = 0.8
        else:
            risk = 0.0
        context.metadata["tool_firewall"] = {
            "risk": risk,
            "category": "tool_firewall",
            **result,
        }

        if result.get("requires_approval"):
            context.decision = InterceptorDecision.REQUIRE_APPROVAL
            context.decision_reason = result["reason"]
        elif not result["allowed"]:
            context.decision = InterceptorDecision.DENY
            context.decision_reason = result["reason"]

        return context
