"""The Claude Code hook's configuration: one YAML file, checked strictly.

    version: 1
    firewall:  {rules: {...}}                     # ToolRules, or rules_path next to this file
    session:   {sources: [...], sinks: [...]}     # SessionTaintPolicy, names may end in *
    redact:    {secrets: true, pii: false, tools: [...]}
    audit:     {path: null, include_args: false}

Every section is optional except ``version``, and every key is checked: a
misspelt one is an error, not a setting quietly ignored. A section that is
present but would never act (a firewall with no rules, a session rule with no
sources) is an error too, as it is everywhere else in this package.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from sdk.policies.session_taint import TaintAction
from sdk.policies.tool_firewall import ToolRules, load_rules

#: Claude Code's own tool names, for telling a typo from an MCP tool.
BUILT_IN_TOOLS = frozenset(
    {
        "Agent",
        "Bash",
        "Edit",
        "Glob",
        "Grep",
        "MultiEdit",
        "NotebookEdit",
        "Read",
        "Task",
        "TodoWrite",
        "WebFetch",
        "WebSearch",
        "Write",
    }
)


class ConfigError(Exception):
    """The configuration is missing, unreadable, or would not do what it says."""


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FirewallSection(_Section):
    rules: dict[str, Any] = Field(default_factory=dict)
    default_deny: bool = False
    rules_path: str | None = None

    @model_validator(mode="after")
    def _one_source_of_rules(self) -> FirewallSection:
        if self.rules_path and self.rules:
            raise ValueError("firewall takes rules or rules_path, not both")
        if not self.rules_path and not self.rules:
            raise ValueError("firewall has no rules, so it would never act; remove the section")
        return self


class SessionSection(_Section):
    sources: list[str]
    sinks: list[str]
    on_taint: TaintAction = TaintAction.REQUIRE_APPROVAL


class RedactSection(_Section):
    secrets: bool = True
    pii: bool = False
    internal_urls: bool = False
    tools: list[str] = Field(
        default_factory=lambda: ["Bash", "Read", "WebFetch", "WebSearch", "mcp__*"]
    )

    def covers(self, name: str) -> bool:
        return (self.secrets or self.pii or self.internal_urls) and any(
            name == tool or (tool.endswith("*") and name.startswith(tool[:-1]))
            for tool in self.tools
        )


class AuditSection(_Section):
    path: str | None = None
    include_args: bool = False


class HookConfig(_Section):
    version: Literal[1]
    role: str | None = None
    firewall: FirewallSection | None = None
    session: SessionSection | None = None
    redact: RedactSection = Field(default_factory=RedactSection)
    audit: AuditSection = Field(default_factory=AuditSection)


def load_config(path: Path) -> tuple[HookConfig, ToolRules | None]:
    """The config at *path*, and its firewall rules (None when there is no firewall)."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"no OpenScript config at {path}") from None
    except (OSError, yaml.YAMLError) as error:
        raise ConfigError(f"cannot read the OpenScript config at {path}: {error}") from None
    if not isinstance(raw, dict):
        raise ConfigError(f"the OpenScript config at {path} is empty or not a mapping")
    try:
        config = HookConfig.model_validate(raw)
        rules = None
        if config.firewall is not None:
            if config.firewall.rules_path:
                rules = load_rules(str(path.parent / config.firewall.rules_path))
            else:
                rules = ToolRules.model_validate(
                    {"rules": config.firewall.rules, "default_deny": config.firewall.default_deny}
                )
    except (ValidationError, ValueError, OSError) as error:
        raise ConfigError(f"the OpenScript config at {path} is not valid: {error}") from None
    return config, rules


def unknown_names(config: HookConfig, rules: ToolRules | None) -> list[str]:
    """Tool names in the config that are neither Claude Code's nor an MCP tool's.

    A misspelt name ("Webfetch") matches nothing and nobody is told, so the
    hook's ``check`` command reports them.
    """
    names: set[str] = set(rules.rules) if rules is not None else set()
    if config.session is not None:
        names |= set(config.session.sources) | set(config.session.sinks)
    names |= set(config.redact.tools)
    return sorted(
        name
        for name in names
        if name != "*" and not name.startswith("mcp__") and name.rstrip("*") not in BUILT_IN_TOOLS
    )
