from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, Field

from contracts.interceptor import Policy
from sdk.interceptors.base import NoopInterceptor
from sdk.interceptors.event_writer import AuditPolicy
from sdk.interceptors.pii import PIIMode, PIIPolicy
from sdk.interceptors.threat import PromptInjectionPolicy
from sdk.policies.secrets import SecretsPolicy
from sdk.policies.tool_firewall import ToolFirewallPolicy, ToolRules

if TYPE_CHECKING:
    from events.writer import EventWriter


class PolicyConfig(BaseModel):
    """Declarative policy pipeline: ordered mapping of policy name -> params.

    Example YAML (see policies_example.yaml):

        policies:
          prompt_injection:
            threshold: 0.6
          pii:
            mode: redact
          secrets:
            mode: deny
          tool_firewall:
            rules_path: tools.yaml

    Order is significant — policies run in declaration order.
    """

    policies: dict[str, dict[str, Any] | None] = Field(default_factory=dict)


# A factory receives the (possibly empty) params dict for its entry plus the
# shared EventWriter (None when the caller doesn't persist events).
PolicyFactory = Callable[[dict[str, Any], "EventWriter | None"], Policy]


def _take(params: dict[str, Any], name: str, allowed: set[str]) -> None:
    unknown = set(params) - allowed
    if unknown:
        raise ValueError(
            f"unknown parameter(s) for policy '{name}': {sorted(unknown)}; "
            f"allowed: {sorted(allowed)}"
        )


def _build_prompt_injection(params: dict[str, Any], writer: EventWriter | None) -> Policy:
    _take(params, "prompt_injection", {"threshold"})
    return PromptInjectionPolicy(threshold=params.get("threshold", 0.5), writer=writer)


def _build_pii(params: dict[str, Any], writer: EventWriter | None) -> Policy:
    _take(params, "pii", {"mode"})
    return PIIPolicy(mode=PIIMode(params.get("mode", "redact")), writer=writer)


def _build_secrets(params: dict[str, Any], writer: EventWriter | None) -> Policy:
    _take(params, "secrets", {"mode"})
    return SecretsPolicy(mode=PIIMode(params.get("mode", "redact")), writer=writer)


def _build_tool_firewall(params: dict[str, Any], writer: EventWriter | None) -> Policy:
    _take(params, "tool_firewall", {"rules", "rules_path"})
    rules = params.get("rules")
    return ToolFirewallPolicy(
        rules=ToolRules.model_validate(rules) if rules is not None else None,
        rules_path=params.get("rules_path"),
    )


def _build_audit(params: dict[str, Any], writer: EventWriter | None) -> Policy:
    _take(params, "audit", set())
    if writer is None:
        raise ValueError("policy 'audit' requires load_policies(..., writer=<EventWriter>)")
    return AuditPolicy(writer)


def _build_noop(params: dict[str, Any], writer: EventWriter | None) -> Policy:
    _take(params, "noop", set())
    return NoopInterceptor()


_REGISTRY: dict[str, PolicyFactory] = {
    "prompt_injection": _build_prompt_injection,
    "pii": _build_pii,
    "secrets": _build_secrets,
    "tool_firewall": _build_tool_firewall,
    "audit": _build_audit,
    "noop": _build_noop,
}


def register_policy(name: str, factory: PolicyFactory) -> None:
    """Register a custom policy factory under *name* for use in load_policies configs."""
    _REGISTRY[name] = factory


def load_policies(
    config: PolicyConfig | dict[str, Any] | str | Path,
    writer: EventWriter | None = None,
) -> list[Policy]:
    """Assemble a ``policies=[...]`` list from a config.

    *config* may be a PolicyConfig, a dict (with or without the top-level
    "policies" key), or a path to a YAML file. *writer* is injected into
    policies that emit events (prompt_injection, pii, secrets, audit).

    Raises ValueError on unknown policy names or parameters.
    """
    if isinstance(config, (str, Path)):
        with open(config) as fh:
            raw = yaml.safe_load(fh) or {}
        cfg = PolicyConfig.model_validate(raw)
    elif isinstance(config, PolicyConfig):
        cfg = config
    else:
        if "policies" not in config:
            config = {"policies": config}
        cfg = PolicyConfig.model_validate(config)

    policies: list[Policy] = []
    for name, params in cfg.policies.items():
        factory = _REGISTRY.get(name)
        if factory is None:
            raise ValueError(f"unknown policy '{name}'; known policies: {sorted(_REGISTRY)}")
        policies.append(factory(params or {}, writer))
    return policies
