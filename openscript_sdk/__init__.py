"""OpenScript: a policy pipeline for LLM agents and the tools they call."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

# Every public name, and the module it lives in. Nothing is imported until a
# name is first asked for, so a caller that needs one policy does not pay for
# all of them (a Claude Code hook pays this on every tool call).
_EXPORTS: dict[str, str] = {
    "ActionBlockedError": "openscript_sdk.contracts.types",
    "ActionContext": "openscript_sdk.contracts.types",
    "ActionTracer": "openscript_sdk.observability.tracing",
    "AgentCapabilities": "openscript_sdk.contracts.types",
    "ApprovalRecord": "openscript_sdk.events.approvals",
    "ApprovalStatus": "openscript_sdk.events.approvals",
    "ApprovalStore": "openscript_sdk.events.approvals",
    "AuditPolicy": "openscript_sdk.interceptors.event_writer",
    "BasePolicy": "openscript_sdk.contracts.interceptor",
    "CompliancePolicy": "openscript_sdk.policies.compliance",
    "EventWriterInterceptor": "openscript_sdk.interceptors.event_writer",
    "FailureMode": "openscript_sdk.contracts.types",
    "GuardScan": "openscript_sdk.contracts.interceptor",
    "HallucinationMode": "openscript_sdk.policies.output_schema",
    "HarmfulRequestPolicy": "openscript_sdk.policies.harmful_request",
    "InMemoryApprovalStore": "openscript_sdk.events.approvals",
    "InMemoryTaintStore": "openscript_sdk.policies.session_taint",
    "Interceptor": "openscript_sdk.contracts.interceptor",
    "InterceptorDecision": "openscript_sdk.contracts.types",
    "InterceptorResult": "openscript_sdk.contracts.types",
    "InternalURLMode": "openscript_sdk.policies.secrets",
    "MetricsRecorder": "openscript_sdk.observability.metrics",
    "NoopInterceptor": "openscript_sdk.interceptors.base",
    "OnInvalid": "openscript_sdk.policies.output_schema",
    "OpenScriptMiddleware": "openscript_sdk.middleware.middleware",
    "OutputSchemaPolicy": "openscript_sdk.policies.output_schema",
    "PHIMode": "openscript_sdk.policies.compliance",
    "PIIInterceptor": "openscript_sdk.interceptors.pii",
    "PIIMode": "openscript_sdk.interceptors.pii",
    "PIIPolicy": "openscript_sdk.interceptors.pii",
    "Policy": "openscript_sdk.contracts.interceptor",
    "PolicyConfig": "openscript_sdk.policies.config",
    "PromptInjectionPolicy": "openscript_sdk.interceptors.threat",
    "RedisApprovalStore": "openscript_sdk.events.approvals",
    "RiskScorer": "openscript_sdk.observability.risk",
    "SecretsPolicy": "openscript_sdk.policies.secrets",
    "SecureAgent": "openscript_sdk.middleware.middleware",
    "SecureTool": "openscript_sdk.middleware.tool",
    "SemanticHead": "openscript_sdk.policies.semantic",
    "SemanticMode": "openscript_sdk.policies.semantic",
    "SemanticPolicy": "openscript_sdk.policies.semantic",
    "SessionTaintPolicy": "openscript_sdk.policies.session_taint",
    "StreamGuard": "openscript_sdk.contracts.interceptor",
    "StreamOutputMode": "openscript_sdk.middleware.middleware",
    "TaintAction": "openscript_sdk.policies.session_taint",
    "TaintStore": "openscript_sdk.policies.session_taint",
    "ThreatInterceptor": "openscript_sdk.interceptors.threat",
    "ToolFirewallPolicy": "openscript_sdk.policies.tool_firewall",
    "ToolRules": "openscript_sdk.policies.tool_firewall",
    "ToxicityPolicy": "openscript_sdk.policies.toxicity",
    "aggregate_risk": "openscript_sdk.observability.risk",
    "configure_logging": "openscript_sdk.logging",
    "find_phi": "openscript_sdk.policies.compliance",
    "find_pii": "openscript_sdk.policies.redaction",
    "find_secrets": "openscript_sdk.policies.secrets",
    "load_policies": "openscript_sdk.policies.config",
    "redact_data": "openscript_sdk.policies.redaction",
    "redact_pii": "openscript_sdk.policies.redaction",
    "redact_secrets": "openscript_sdk.policies.redaction",
    "register_policy": "openscript_sdk.policies.config",
    "validate_tool_call": "openscript_sdk.policies.tool_firewall",
    "wrap_agent": "openscript_sdk.integrations.langchain",
    "wrap_graph_agent": "openscript_sdk.integrations.langgraph",
}

if TYPE_CHECKING:
    from openscript_sdk.contracts.interceptor import (
        BasePolicy,
        GuardScan,
        Interceptor,
        Policy,
        StreamGuard,
    )
    from openscript_sdk.contracts.types import (
        ActionBlockedError,
        ActionContext,
        AgentCapabilities,
        FailureMode,
        InterceptorDecision,
        InterceptorResult,
    )
    from openscript_sdk.events.approvals import (
        ApprovalRecord,
        ApprovalStatus,
        ApprovalStore,
        InMemoryApprovalStore,
        RedisApprovalStore,
    )
    from openscript_sdk.integrations.langchain import wrap_agent
    from openscript_sdk.integrations.langgraph import wrap_graph_agent
    from openscript_sdk.interceptors.base import NoopInterceptor
    from openscript_sdk.interceptors.event_writer import AuditPolicy, EventWriterInterceptor
    from openscript_sdk.interceptors.pii import PIIInterceptor, PIIMode, PIIPolicy
    from openscript_sdk.interceptors.threat import PromptInjectionPolicy, ThreatInterceptor
    from openscript_sdk.logging import configure_logging
    from openscript_sdk.middleware.middleware import (
        OpenScriptMiddleware,
        SecureAgent,
        StreamOutputMode,
    )
    from openscript_sdk.middleware.tool import SecureTool
    from openscript_sdk.observability.metrics import MetricsRecorder
    from openscript_sdk.observability.risk import RiskScorer, aggregate_risk
    from openscript_sdk.observability.tracing import ActionTracer
    from openscript_sdk.policies.compliance import CompliancePolicy, PHIMode, find_phi
    from openscript_sdk.policies.config import PolicyConfig, load_policies, register_policy
    from openscript_sdk.policies.harmful_request import HarmfulRequestPolicy
    from openscript_sdk.policies.output_schema import (
        HallucinationMode,
        OnInvalid,
        OutputSchemaPolicy,
    )
    from openscript_sdk.policies.redaction import find_pii, redact_data, redact_pii, redact_secrets
    from openscript_sdk.policies.secrets import InternalURLMode, SecretsPolicy, find_secrets
    from openscript_sdk.policies.semantic import SemanticHead, SemanticMode, SemanticPolicy
    from openscript_sdk.policies.session_taint import (
        InMemoryTaintStore,
        SessionTaintPolicy,
        TaintAction,
        TaintStore,
    )
    from openscript_sdk.policies.tool_firewall import (
        ToolFirewallPolicy,
        ToolRules,
        validate_tool_call,
    )
    from openscript_sdk.policies.toxicity import ToxicityPolicy

__all__ = [
    "ActionBlockedError",
    "ActionContext",
    "ActionTracer",
    "AgentCapabilities",
    "ApprovalRecord",
    "ApprovalStatus",
    "ApprovalStore",
    "AuditPolicy",
    "BasePolicy",
    "CompliancePolicy",
    "EventWriterInterceptor",  # deprecated alias
    "FailureMode",
    "GuardScan",
    "HallucinationMode",
    "HarmfulRequestPolicy",
    "InMemoryApprovalStore",
    "InMemoryTaintStore",
    "Interceptor",  # deprecated alias
    "InterceptorDecision",
    "InterceptorResult",
    "InternalURLMode",
    "MetricsRecorder",
    "NoopInterceptor",
    "OnInvalid",
    "OpenScriptMiddleware",  # deprecated alias
    "OutputSchemaPolicy",
    "PHIMode",
    "PIIInterceptor",  # deprecated alias
    "PIIMode",
    "PIIPolicy",
    "Policy",
    "PolicyConfig",
    "PromptInjectionPolicy",
    "RedisApprovalStore",
    "RiskScorer",
    "SecretsPolicy",
    "SecureAgent",
    "SecureTool",
    "SemanticHead",
    "SemanticMode",
    "SemanticPolicy",
    "SessionTaintPolicy",
    "StreamGuard",
    "StreamOutputMode",
    "TaintAction",
    "TaintStore",
    "ThreatInterceptor",  # deprecated alias
    "ToolFirewallPolicy",
    "ToolRules",
    "ToxicityPolicy",
    "aggregate_risk",
    "configure_logging",
    "find_phi",
    "find_pii",
    "find_secrets",
    "load_policies",
    "redact_data",
    "redact_pii",
    "redact_secrets",
    "register_policy",
    "validate_tool_call",
    "wrap_agent",
    "wrap_graph_agent",
]


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value  # asked for once, then a plain attribute
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
