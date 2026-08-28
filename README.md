# OpenScript

**Security gateway SDK for LLM/agent workflows.** Block prompt injection, redact PII and secrets, firewall tool calls, gate risky actions behind human approval, and score every action's risk — across any LLM provider.

OpenScript wraps any agent in a **policy pipeline**: policies run before and after every action, and each one can allow, mutate (redact), deny, or require human approval. The pipeline itself contains zero detection logic — everything is a `Policy` you can swap, configure from YAML, or write yourself.

![OpenScript demo](demo/injection_demo.gif)

## Try It in Your Browser

`site/` is an interactive demo that runs **this package** — compiled to WebAssembly with
Pyodide — entirely inside the visitor's tab. Every policy executes locally: there is no
backend and no API endpoint, so nothing typed into it is sent anywhere, and the network tab
proves it. That is possible because all eight built-in policies are pure-local heuristics,
a property enforced in CI rather than merely asserted.

```bash
make demo-serve    # build the wheel bundle, export the app, serve it on :8081
make demo-verify   # run every gallery example through the export, headless
```

## Getting Started in 5 Minutes

### 1. Install

```bash
pip install openscript
```

Or from source:

```bash
git clone https://github.com/OrdinalScale/openscript.git
cd openscript
python -m venv .venv
.venv/Scripts/activate   # Windows
# source .venv/bin/activate  # Unix
pip install -r requirements.txt
pip install -e .
```

Optional extras: `openscript[redis]` (shared approval store), `openscript[metrics]` (Prometheus), `openscript[otel]` (tracing), `openscript[ml]` (embedding-based checks).

### 2. Wrap an Agent

```python
import asyncio
from sdk import PIIPolicy, PromptInjectionPolicy, SecretsPolicy, SecureAgent

class MyAgent:
    async def ainvoke(self, input_data, **kwargs):
        return {"output": f"Hello, {input_data.get('input', 'world')}!"}

async def main():
    secure = SecureAgent(
        agent=MyAgent(),
        policies=[
            PromptInjectionPolicy(threshold=0.5),  # blocks injection attempts
            PIIPolicy(mode="redact"),              # redacts PII from output
            SecretsPolicy(mode="redact"),          # redacts credentials, flags internal URLs
        ],
    )
    result = await secure.invoke({"input": "OpenScript"})
    print(result)  # {"output": "Hello, OpenScript!"}

asyncio.run(main())
```

A blocked action raises `ActionBlockedError` with the reason, the policy that blocked it, and the action's aggregated `risk_score`.

### 3. Or Configure Policies from YAML

```yaml
# policies.yaml
policies:
  prompt_injection:
    threshold: 0.6
  toxicity:
    threshold: 0.5
  pii:
    mode: redact
  secrets:
    mode: deny
    internal_url_mode: annotate
  compliance:
    rules: [phi_detection, credential_output_guard]
  tool_firewall:
    rules_path: tools.yaml
```

```python
from sdk import SecureAgent, load_policies

secure = SecureAgent(agent, policies=load_policies("policies.yaml"))
```

## Built-in Policies

| Policy | Phase | What it does |
|--------|-------|--------------|
| `PromptInjectionPolicy` | input | Scores role injection, prompt extraction, goal hijacking, delimiter/indirect injection; denies on threshold |
| `ToxicityPolicy` | input | Detects threats, hate speech, harassment, self-harm content; denies on threshold |
| `PIIPolicy` | output | Redacts or denies emails, phones, SSNs, credit cards (Luhn-checked), API keys, IPs |
| `SecretsPolicy` | input + output | Redacts or denies AWS/GitHub/Slack tokens, JWTs, private-key blocks; separately flags internal URLs/private IPs (`internal_url_mode`: annotate by default, plus allowlist) |
| `CompliancePolicy` | input + output | Honestly-scoped presets: `phi_detection`, `credential_output_guard`, `data_access_audit` — see [Compliance positioning](#compliance-positioning) |
| `ToolFirewallPolicy` | input | Allowlist/deny/RBAC/argument constraints for tool calls; can require human approval. Also usable standalone via `validate_tool_call()` or `POST /v1/tools/validate` |
| `OutputSchemaPolicy` | output | Pydantic schema validation, dangerous-content scan, optional hallucination/grounding check against a source |
| `AuditPolicy` | both | Writes every action to the event store; place it **last** so its events carry the final risk score |

Every policy writes standardized metadata — `{"risk": float, "category": str, ...}` — which the built-in `RiskScorer` aggregates into a single `risk_score` per action:

```python
result, ctx = await secure.invoke_with_context({"input": "..."})
print(ctx.risk_score)        # 0.0 – 1.0
print(ctx.risk_categories)   # {"pii": 0.4, "prompt_injection": 0.0, ...}
```

## Human Approval (retry-after-approval)

When a policy returns `REQUIRE_APPROVAL` (e.g. a firewalled tool call), the action is blocked and a pending approval record is created:

```python
from sdk import ActionBlockedError, RedisApprovalStore, SecureAgent

secure = SecureAgent(
    agent,
    policies=[...],
    # Redis is REQUIRED when approvals are decided via the server API —
    # the default in-memory store only works within a single process.
    approval_store=RedisApprovalStore("redis://localhost:6379/0"),
)

try:
    await secure.invoke({"input": "transfer $5,000"})
except ActionBlockedError as e:
    approval_id = e.approval_id  # a human decides via POST /v1/approvals/{id}/decide

# after approval, retry the SAME action with the approval id:
result = await secure.invoke({"input": "transfer $5,000"}, approval_id=approval_id)
```

Approvals are **single-use**, expire after 1 hour, and are bound to the exact action + input hash — an approval granted for one transfer cannot be replayed against a different one.

## Streaming

`stream()` supports three protection modes (`stream_output=` on the constructor or per call):

| Mode | Protection | Latency | Use for |
|------|-----------|---------|---------|
| `buffer` (default) | Full — output policies see, redact, and can block the complete response before anything is yielded | Full response time | Machine-consumed output |
| `guarded` | Full for bounded patterns (secrets, PII) via incremental scanning with a hold-back window; a deny aborts with nothing of the match emitted. Schema/grounding checks run at stream end | ~One window (tens of tokens) | Human-facing chat UIs (text streams) |
| `passthrough` | **None** — chunks are delivered unscanned; policies run post-hoc for metadata/audit only, and a post-hoc deny raises after the fact | None | Observability-only setups, consciously |

```python
async for chunk in secure.stream({"input": "..."}, stream_output="guarded"):
    print(chunk, end="")
```

Custom policies can participate in guarded streaming by implementing `stream_guard()` (see `contracts.interceptor.StreamGuard`).

## Observability

```python
from sdk import MetricsRecorder, SecureAgent

secure = SecureAgent(agent, policies=[...], metrics=MetricsRecorder())
```

Prometheus metrics (`pip install openscript[metrics]`): actions by decision, a `risk_score` histogram, per-category violation counters, injection/tool-denial/PII-redaction counters, and per-policy latency histograms. The server exposes them at `GET /metrics` (API-key gated).

OpenTelemetry (`pip install openscript[otel]`): set `OPENSCRIPT_OTEL=1` for one span per action carrying the final decision and risk score; configure your OTLP exporter via standard `OTEL_*` env vars.

## Write a Custom Policy

```python
from contracts.types import ActionContext, InterceptorDecision
from sdk import BasePolicy

class BusinessHoursPolicy(BasePolicy):
    async def before_action(self, context: ActionContext) -> ActionContext:
        if not is_business_hours():
            context.decision = InterceptorDecision.DENY
            context.decision_reason = "agent actions are restricted to business hours"
        return context
```

Any object with `before_action`, `after_action`, and `failure_mode` satisfies the `Policy` protocol — subclassing `BasePolicy` just gives you pass-through defaults. Declare `failure_mode` to control error handling:

| Mode | Behavior |
|------|----------|
| `FAIL_OPEN` | Log warning, allow action to proceed |
| `FAIL_CLOSED` | Log error, block action |
| `FAIL_EXCEPTION` | Re-raise the original exception |

Security policies default to `FAIL_CLOSED`; observability policies to `FAIL_OPEN`.

## Architecture

```
User Request
    │
    ▼
┌────────────────────────────────────────────┐
│  SecureAgent                               │
│                                            │
│  ┌─ before_action ─────────────────────┐   │
│  │  PromptInjectionPolicy   ──► DENY?  │   │
│  │  ToxicityPolicy          ──► DENY?  │   │
│  │  ToolFirewallPolicy ──► APPROVAL?   │   │
│  └─────────────────────────────────────┘   │
│                  │                         │
│      Agent.invoke() / stream()             │
│                  │                         │
│  ┌─ after_action ──────────────────────┐   │
│  │  OutputSchemaPolicy      ──► DENY?  │   │
│  │  PIIPolicy / SecretsPolicy (redact) │   │
│  │  CompliancePolicy                   │   │
│  │  AuditPolicy (events + risk)        │   │
│  └─────────────────────────────────────┘   │
│                  │                         │
│   RiskScorer ──► risk_score, metrics       │
└────────────────────────────────────────────┘
    │
    ▼
  Response (or ActionBlockedError with
  reason, risk_score, approval_id)
```

The pipeline is deliberately dumb — all detection lives in the policies. Deny in the *before* phase blocks before the agent runs; deny in the *after* phase blocks the response after all policies (including audit) complete.

## Framework Integrations

LangChain and LangGraph wrappers ship today:

```python
from sdk import wrap_agent, wrap_graph_agent, load_policies

secure = wrap_agent(langchain_agent, policies=load_policies("policies.yaml"))
result = await secure.invoke({"input": "What is prompt injection?"})
```

CrewAI, PydanticAI, AutoGen, and OpenAI Agents SDK adapters are on the roadmap (each as an optional extra, built on the frameworks' official guardrail/callback hooks).

## Compliance Positioning

`CompliancePolicy` **assists** compliance programs — its checks (PHI identifier detection, credential-output guarding, data-access auditing) map onto common GDPR/HIPAA/SOC 2 controls. It does **not** confer or certify compliance with any regulation, and its presets are deliberately named after what they check, not after regulations.

## Server

An optional FastAPI server (`uvicorn server.app:app`) provides the event store, SSE feeds, a session dashboard (`/dashboard/`), stateless scoring endpoints (`/v1/threat/score`, `/v1/tools/validate`), the approval queue (`/v1/approvals`), and Prometheus metrics (`/metrics`). All endpoints except `/health` require the `X-API-KEY` header (`OPENSCRIPT_API_KEY`).

Try the full pipeline end-to-end:

```bash
python demo/injection_demo.py
```

## Migrating from the Interceptor API

The pre-1.0 names still work but emit `DeprecationWarning`: `OpenScriptMiddleware` → `SecureAgent`, `interceptors=` → `policies=`, `ThreatInterceptor` → `PromptInjectionPolicy`, `PIIInterceptor` → `PIIPolicy`, `EventWriterInterceptor` → `AuditPolicy`, `Interceptor` protocol → `Policy`.

## Development

```bash
# Setup
python -m venv .venv && .venv/Scripts/activate
pip install -r requirements.txt && pip install -e .

# Test
pytest

# Lint + format + type-check
ruff check .
black .
mypy sdk/ contracts/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

## License

Apache 2.0 — see [LICENSE](LICENSE).
