"""OpenScript: a policy pipeline for LLM agents and the tools they call."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

# Every public name, and the module it lives in. Nothing is imported until a
# name is first asked for, so a caller that needs one policy does not pay for
# all of them (a Claude Code hook pays this on every tool call).
_EXPORTS: dict[str, str] = {
    "ActionBlockedError": "contracts.types",
    "ActionContext": "contracts.types",
    "ActionTracer": "sdk.observability.tracing",
    "AgentCapabilities": "contracts.types",
    "ApprovalRecord": "events.approvals",
    "ApprovalStatus": "events.approvals",
    "ApprovalStore": "events.approvals",
    "AuditPolicy": "sdk.interceptors.event_writer",
    "BasePolicy": "contracts.interceptor",
    "CompliancePolicy": "sdk.policies.compliance",
    "EventWriterInterceptor": "sdk.interceptors.event_writer",
    "FailureMode": "contracts.types",
    "GuardScan": "contracts.interceptor",
    "HallucinationMode": "sdk.policies.output_schema",
    "HarmfulRequestPolicy": "sdk.policies.harmful_request",
    "InMemoryApprovalStore": "events.approvals",
    "InMemoryTaintStore": "sdk.policies.session_taint",
    "Interceptor": "contracts.interceptor",
    "InterceptorDecision": "contracts.types",
    "InterceptorResult": "contracts.types",
    "InternalURLMode": "sdk.policies.secrets",
    "MetricsRecorder": "sdk.observability.metrics",
    "NoopInterceptor": "sdk.interceptors.base",
    "OnInvalid": "sdk.policies.output_schema",
    "OpenScriptMiddleware": "sdk.middleware.middleware",
    "OutputSchemaPolicy": "sdk.policies.output_schema",
    "PHIMode": "sdk.policies.compliance",
    "PIIInterceptor": "sdk.interceptors.pii",
    "PIIMode": "sdk.interceptors.pii",
    "PIIPolicy": "sdk.interceptors.pii",
    "Policy": "contracts.interceptor",
    "PolicyConfig": "sdk.policies.config",
    "PromptInjectionPolicy": "sdk.interceptors.threat",
    "RedisApprovalStore": "events.approvals",
    "RiskScorer": "sdk.observability.risk",
    "SecretsPolicy": "sdk.policies.secrets",
    "SecureAgent": "sdk.middleware.middleware",
    "SecureTool": "sdk.middleware.tool",
    "SemanticHead": "sdk.policies.semantic",
    "SemanticMode": "sdk.policies.semantic",
    "SemanticPolicy": "sdk.policies.semantic",
    "SessionTaintPolicy": "sdk.policies.session_taint",
    "StreamGuard": "contracts.interceptor",
    "StreamOutputMode": "sdk.middleware.middleware",
    "TaintAction": "sdk.policies.session_taint",
    "TaintStore": "sdk.policies.session_taint",
    "ThreatInterceptor": "sdk.interceptors.threat",
    "ToolFirewallPolicy": "sdk.policies.tool_firewall",
    "ToolRules": "sdk.policies.tool_firewall",
    "ToxicityPolicy": "sdk.policies.toxicity",
    "aggregate_risk": "sdk.observability.risk",
    "configure_logging": "sdk.logging",
    "find_phi": "sdk.policies.compliance",
    "find_pii": "sdk.policies.redaction",
    "find_secrets": "sdk.policies.secrets",
    "load_policies": "sdk.policies.config",
    "redact_data": "sdk.policies.redaction",
    "redact_pii": "sdk.policies.redaction",
    "redact_secrets": "sdk.policies.redaction",
    "register_policy": "sdk.policies.config",
    "validate_tool_call": "sdk.policies.tool_firewall",
    "wrap_agent": "sdk.integrations.langchain",
    "wrap_graph_agent": "sdk.integrations.langgraph",
}

if TYPE_CHECKING:
    from contracts.interceptor import BasePolicy, GuardScan, Interceptor, Policy, StreamGuard
    from contracts.types import (
        ActionBlockedError,
        ActionContext,
        AgentCapabilities,
        FailureMode,
        InterceptorDecision,
        InterceptorResult,
    )
    from events.approvals import (
        ApprovalRecord,
        ApprovalStatus,
        ApprovalStore,
        InMemoryApprovalStore,
        RedisApprovalStore,
    )
    from sdk.integrations.langchain import wrap_agent
    from sdk.integrations.langgraph import wrap_graph_agent
    from sdk.interceptors.base import NoopInterceptor
    from sdk.interceptors.event_writer import AuditPolicy, EventWriterInterceptor
    from sdk.interceptors.pii import PIIInterceptor, PIIMode, PIIPolicy
    from sdk.interceptors.threat import PromptInjectionPolicy, ThreatInterceptor
    from sdk.logging import configure_logging
    from sdk.middleware.middleware import OpenScriptMiddleware, SecureAgent, StreamOutputMode
    from sdk.middleware.tool import SecureTool
    from sdk.observability.metrics import MetricsRecorder
    from sdk.observability.risk import RiskScorer, aggregate_risk
    from sdk.observability.tracing import ActionTracer
    from sdk.policies.compliance import CompliancePolicy, PHIMode, find_phi
    from sdk.policies.config import PolicyConfig, load_policies, register_policy
    from sdk.policies.harmful_request import HarmfulRequestPolicy
    from sdk.policies.output_schema import HallucinationMode, OnInvalid, OutputSchemaPolicy
    from sdk.policies.redaction import find_pii, redact_data, redact_pii, redact_secrets
    from sdk.policies.secrets import InternalURLMode, SecretsPolicy, find_secrets
    from sdk.policies.semantic import SemanticHead, SemanticMode, SemanticPolicy
    from sdk.policies.session_taint import (
        InMemoryTaintStore,
        SessionTaintPolicy,
        TaintAction,
        TaintStore,
    )
    from sdk.policies.tool_firewall import ToolFirewallPolicy, ToolRules, validate_tool_call
    from sdk.policies.toxicity import ToxicityPolicy

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
