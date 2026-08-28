from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from contracts.types import ActionContext

_RISK_BUCKETS = (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0)


class MetricsRecorder:
    """Prometheus metrics for SecureAgent actions (pip install openscript[metrics]).

    Pass one instance per registry: SecureAgent(metrics=MetricsRecorder()).
    Metric families:

    - openscript_actions_total{decision}: every completed action, by final
      decision (allow/deny/require_approval)
    - openscript_action_risk_score: histogram of the aggregated risk_score
    - openscript_policy_violations_total{policy}: one increment per policy
      category that found something (metadata risk > 0) in an action
    - openscript_injections_blocked_total: threat scorer flagged the input
    - openscript_tool_calls_denied_total: tool firewall rejected a call
    - openscript_pii_redacted_total: an action's output had PII redacted
    - openscript_policy_latency_seconds{policy,phase}: per-hook latency
      (recorded by SecureAgent around each before/after call)

    Instantiating twice against the same registry raises (Prometheus forbids
    duplicate timeseries) — share the instance, or pass a fresh
    CollectorRegistry in tests.
    """

    def __init__(self, registry: Any | None = None) -> None:
        try:
            from prometheus_client import REGISTRY, Counter, Histogram
        except ImportError as exc:  # pragma: no cover - exercised without the extra
            raise ImportError(
                "MetricsRecorder requires prometheus-client: pip install openscript[metrics]"
            ) from exc

        registry = registry if registry is not None else REGISTRY
        self._actions = Counter(
            "openscript_actions",
            "Actions processed by SecureAgent, by final decision",
            labelnames=("decision",),
            registry=registry,
        )
        self._risk_score = Histogram(
            "openscript_action_risk_score",
            "Aggregated cross-policy risk score per action",
            buckets=_RISK_BUCKETS,
            registry=registry,
        )
        self._violations = Counter(
            "openscript_policy_violations",
            "Actions where a policy category found something (risk > 0)",
            labelnames=("policy",),
            registry=registry,
        )
        self._injections_blocked = Counter(
            "openscript_injections_blocked",
            "Actions flagged by the prompt-injection scorer",
            registry=registry,
        )
        self._tool_calls_denied = Counter(
            "openscript_tool_calls_denied",
            "Tool calls rejected by the tool firewall",
            registry=registry,
        )
        self._pii_redacted = Counter(
            "openscript_pii_redacted",
            "Actions whose output had PII redacted",
            registry=registry,
        )
        self._policy_latency = Histogram(
            "openscript_policy_latency_seconds",
            "Latency of individual policy hooks",
            labelnames=("policy", "phase"),
            registry=registry,
        )

    def record_action(self, context: ActionContext) -> None:
        """Record final counters for one action; called by SecureAgent at
        every exit point, after risk aggregation."""
        self._actions.labels(decision=context.decision.value).inc()
        self._risk_score.observe(context.risk_score)

        for category, risk in context.risk_categories.items():
            if risk > 0:
                self._violations.labels(policy=category).inc()

        threat = context.metadata.get("threat")
        if isinstance(threat, dict) and threat.get("flagged"):
            self._injections_blocked.inc()

        firewall = context.metadata.get("tool_firewall")
        if isinstance(firewall, dict) and firewall.get("allowed") is False:
            self._tool_calls_denied.inc()

        pii = context.metadata.get("pii")
        if isinstance(pii, dict) and pii.get("redacted"):
            self._pii_redacted.inc()

    def observe_policy_latency(self, policy: str, phase: str, seconds: float) -> None:
        self._policy_latency.labels(policy=policy, phase=phase).observe(seconds)
