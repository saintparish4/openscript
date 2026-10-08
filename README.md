# OpenScript

**Security gateway SDK for LLM/agent workflows.** Block prompt injection, redact PII and secrets, firewall tool calls, gate risky actions behind human approval, and score every action's risk — across any LLM provider.

OpenScript wraps any agent in a **policy pipeline**: policies run before and after every action, and each one can allow, mutate (redact), deny, or require human approval. The pipeline itself contains zero detection logic — everything is a `Policy` you can swap, configure from YAML, or write yourself.

**[Try the live demo →](https://openscript-rho.vercel.app/)**

![OpenScript demo](demo/injection_demo.gif)

## Try It in Your Browser

**[openscript-rho.vercel.app](https://openscript-rho.vercel.app/)** — an interactive demo
that runs **this package** — compiled to WebAssembly with Pyodide — entirely inside your
tab. Pick a prompt from the gallery and every policy runs locally: there is no backend and
no API endpoint, so the prompt and the verdicts never leave the tab, and the network tab
proves it. That is possible because all nine built-in policies are pure-local heuristics, a
property enforced in CI rather than merely asserted. Requires a browser with WebAssembly and
access to the jsDelivr CDN (which serves the Pyodide runtime).

The gallery is eleven prompts from three fictional users — a customer, a contractor and a support agent. Each one shows what the sender is asking for, what reaching the agent unchecked would have meant, and what the pipeline did instead; tool prompts show the call the firewall refused next to the rule it hit, and the disguised jailbreak names the obfuscation that had to be undone before any pattern matched.

To run it locally instead, `site/` is the source for that demo:

```bash
make demo-serve    # build the wheel bundle, export the app, serve it on :8081
make demo-verify   # run every gallery example through the export, headless
```

## Getting Started in 5 Minutes

### 1. Install

Install from source — OpenScript is not published to PyPI:

```bash
git clone https://github.com/saintparish4/openscript.git
cd openscript
python -m venv .venv
.venv/Scripts/activate   # Windows
# source .venv/bin/activate  # Unix
pip install -e .
```

`pip install -e .` alone is enough for everything below — it pulls only `pydantic`, `structlog`, `pyyaml`. `requirements.txt` installs the full dev+server stack (FastAPI, SQLAlchemy, Postgres driver, Redis client, pytest, mypy, …) and is only needed if you're running the test suite, the server, or the demo script — not for using the SDK.

Optional extras: `pip install -e ".[redis]"` (shared approval store), `[metrics]` (Prometheus), `[otel]` (tracing), `[ml]` (embedding-based checks), `[demo]` (deps for `demo/injection_demo.py`).

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
  harmful_request:
    threshold: 0.5
  pii:
    mode: redact
  secrets:
    mode: deny
    internal_url_mode: annotate
  compliance:
    rules: [phi_detection, credential_output_guard]
```

```python
from sdk import SecureAgent, load_policies

secure = SecureAgent(agent, policies=load_policies("policies.yaml"))
```

### 4. Guard the Tools the Agent Calls

`SecureAgent` sees two moments: what the caller sent and what the agent finally returned. The tools an agent calls in between run inside `agent.invoke()`, where none of its policies are looking — and that is where a manipulated agent does its damage. `SecureTool` wraps one tool and runs the same before/after pipeline on every call to it:

```python
from sdk import SecureTool, ToolFirewallPolicy

async def send_email(to: str, body: str = "") -> str:
    ...

send = SecureTool(send_email, policies=[ToolFirewallPolicy(rules_path="tools.yaml")])

await send(to="ops@example.com", body="done")   # called like the function it wraps
```

Give `send` to your agent in place of `send_email`. It imports no framework: whatever calls the tool calls this instead. Sync and async tools both work (a sync one runs in a worker thread). A call the rules deny raises `ActionBlockedError` and **the tool does not run**.

Rules are written per tool and per argument:

```yaml
# tools.yaml
default_deny: true              # a tool with no rule is refused
rules:
  send_email:
    unlisted_args: deny         # no cc or bcc around the allowlist on `to`
    args:
      to:   {required: true, pattern: '[^@\s]+@example\.com'}
      body: {}
  read_file:
    args:
      path: {required: true, path_prefix: [reports]}
  transfer_funds:
    requires_approval: true     # see Human Approval below
    args:
      amount: {min: 0, max: 1000}
  delete_account:
    deny: true
```

What that buys, and what it does not:

- **`ToolFirewallPolicy` belongs in a `SecureTool`'s list.** It acts on tool calls only; in a `SecureAgent`'s list it sees none and does nothing.
- **Arguments are checked by name, with the tool's own defaults filled in.** A bound on `amount` applies to the amount the tool will actually use, including when the caller leaves it out. `unlisted_args: deny` is about what the caller passes: an argument left to its default is not refused for being unlisted, but is still held to any rule that names it.
- **A value a rule cannot evaluate is refused.** Numeric text is read as the number it spells, so `"9999"` does not slip under a `max`; NaN, booleans and anything else that is not a number are denied. A list is checked item by item.
- **`pattern` has to match the whole value**, so an allowlist for `example.com` is not satisfied by `example.com.attacker.io`.
- **`path_prefix` resolves `..` before comparing** and does not expand `~`. It reads the path as text, so it cannot see a symlink inside the allowed directory that leads back out.
- **A misspelt key fails the load.** A rules file that reads as enforced and enforces nothing is worse than no file.
- **Output policies in the tool's list apply to what the tool returns.** `PIIPolicy` and `SecretsPolicy` redact it. `PromptInjectionPolicy` scores it, because a tool's result is how the text of a fetched page or an email reaches the model. That score is recorded and let through by default (`tool_output="annotate"`), since the patterns behind it miss most attacks they were not written for; `tool_output="deny"` withholds the result. Withholding is not undoing: by then the tool has run.
- **It does not stop harm done through a call the rules permit.** If `send_email` may write to anyone, an injected agent can still send mail. The rules are the boundary, and it is only as tight as they are.

Start from `sdk/policies/tools_example.yaml`. The same check is available without the wrapper as `validate_tool_call(call, rules=rules)` and `POST /v1/tools/validate`.

## Built-in Policies

| Policy | Phase | What it does |
|--------|-------|--------------|
| `PromptInjectionPolicy` | input, tool output | Scores role injection, prompt extraction, goal hijacking, delimiter/indirect injection; denies on threshold. Around a tool it also scores what the tool returned — recorded by default, `tool_output="deny"` to withhold it |
| `ToxicityPolicy` | input | Detects threats, hate speech, harassment, self-harm content; denies on threshold |
| `HarmfulRequestPolicy` | input | Scores requests for harmful capability — weapons, malware, doxxing, illicit acquisition, fraud, violence planning, covert surveillance, exploitation, self-harm methods; denies on threshold |
| `PIIPolicy` | output | Redacts or denies emails, phones, SSNs, credit cards (Luhn-checked), API keys, IPs |
| `SecretsPolicy` | input + output | Redacts or denies AWS/GitHub/Slack tokens, JWTs, private-key blocks; separately flags internal URLs/private IPs (`internal_url_mode`: annotate by default, plus allowlist) |
| `CompliancePolicy` | input + output | Honestly-scoped presets: `phi_detection`, `credential_output_guard`, `data_access_audit` — see [Compliance positioning](#compliance-positioning) |
| `ToolFirewallPolicy` | tool call | Per-tool deny/RBAC and per-argument rules (bounds, allowlists, patterns, path prefixes); can require human approval. Acts on tool calls only, so it goes in a [`SecureTool`](#4-guard-the-tools-the-agent-calls)'s list, not a `SecureAgent`'s. Also usable standalone via `validate_tool_call()` or `POST /v1/tools/validate` |
| `OutputSchemaPolicy` | output | Pydantic schema validation, dangerous-content scan, optional hallucination/grounding check against a source |
| `AuditPolicy` | both | Writes every action to the event store; place it **last** so its events carry the final risk score |

The three input-side policies scan the prompt as it arrived **and** normalized views of it, so an attack disguised with zero-width characters, Cyrillic look-alikes, leetspeak, spaced-out letters, full-width forms or a base64 payload scores like the attack it is. Plain prose produces one view and costs what it always did. See `sdk/policies/normalize.py`.

### What the detection actually measures

Asserting that a security tool works is cheap. `evals/` holds labelled corpora and `make evals` scores the policies against them; `tests/test_evals.py` fails the build if the numbers regress. Measured 2026-09-20:

| Corpus | Attacks blocked | Obfuscated blocked | Benign wrongly blocked |
|---|---|---|---|
| Prompt injection | 49/49 (100%) | 14/14 (100%) | 0/30 (0%) |
| Toxicity | 20/20 (100%) | 6/6 (100%) | 0/18 (0%) |
| Harmful request | 49/49 (100%) | 10/10 (100%) | 0/46 (0%) |
| **Held out — phrasings never fixed against** | **1/23 (4%)** | — | **0/20 (0%)** |

Both halves of that matter. A pattern bank recognises shapes, so it is close to perfect on attack families it has seen (including disguised ones) and close to useless against an attack phrased in words nobody wrote a rule for. **0 false positives across all 154 benign prompts** — prompts that report on malware, teach about phishing and quote threats in HR reports — is the other number worth having, because a gateway that blocks the security team gets switched off.

What this does not catch, stated plainly: attacks in languages other than English, novel paraphrase, and anything that needs to understand a sentence rather than match it. Closing that needs a model, which is a deliberate architecture change and would end the no-backend property the browser demo depends on. Full numbers and history: [`docs/metrics.md`](docs/metrics.md); methodology: [`evals/README.md`](evals/README.md).

Every policy writes standardized metadata — `{"risk": float, "category": str, ...}` — which the built-in `RiskScorer` aggregates into a single `risk_score` per action:

```python
result, ctx = await secure.invoke_with_context({"input": "..."})
print(ctx.risk_score)        # 0.0 – 1.0
print(ctx.risk_categories)   # {"pii": 0.4, "prompt_injection": 0.0, ...}
```

## Human Approval (retry-after-approval)

When a policy returns `REQUIRE_APPROVAL`, the action is blocked and a pending approval record is created. The usual source is a tool rule with `requires_approval: true`:

```python
from sdk import ActionBlockedError, RedisApprovalStore, SecureTool, ToolFirewallPolicy

transfer = SecureTool(
    transfer_funds,
    policies=[ToolFirewallPolicy(rules_path="tools.yaml")],
    # Redis is REQUIRED when approvals are decided via the server API —
    # the default in-memory store only works within a single process.
    approval_store=RedisApprovalStore("redis://localhost:6379/0"),
)

call = {"to": "acct-22", "amount": 500}
try:
    await transfer.call(call)
except ActionBlockedError as e:
    approval_id = e.approval_id  # a human decides via POST /v1/approvals/{id}/decide

# after approval, retry the SAME call with the approval id:
result = await transfer.call(call, approval_id=approval_id)
```

Approvals are **single-use**, expire after 1 hour, and are bound to the tool's name and its exact arguments — an approval for $500 to one account cannot be spent on another account or a larger amount, and cannot be replayed. A call that breaks an argument rule is denied outright rather than sent for approval.

`SecureAgent.invoke(..., approval_id=...)` redeems an approval the same way when a custom policy gates the whole agent call. There the approval is bound to the agent's input, not to anything the agent goes on to do.

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

Prometheus metrics (`pip install -e ".[metrics]"`): actions by decision, a `risk_score` histogram, per-category violation counters, injection/tool-denial/PII-redaction counters, and per-policy latency histograms. The server exposes them at `GET /metrics` (API-key gated).

OpenTelemetry (`pip install -e ".[otel]"`): set `OPENSCRIPT_OTEL=1` for one span per action carrying the final decision and risk score; configure your OTLP exporter via standard `OTEL_*` env vars.

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
│  │  HarmfulRequestPolicy    ──► DENY?  │   │
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

The tools the agent calls are not in that picture: they run inside `Agent.invoke()`. Each tool wrapped in a `SecureTool` gets the same two phases of its own:

```
Agent calls a tool
    │
    ▼
┌────────────────────────────────────────────┐
│  SecureTool  (one per tool)                │
│                                            │
│  ┌─ before_action ─────────────────────┐   │
│  │  ToolFirewallPolicy ──► DENY?       │   │
│  │                     ──► APPROVAL?   │   │
│  └─────────────────────────────────────┘   │
│                  │                         │
│      the tool runs, with the arguments     │
│      the policies saw                      │
│                  │                         │
│  ┌─ after_action ──────────────────────┐   │
│  │  PromptInjectionPolicy (its result) │   │
│  │  PIIPolicy / SecretsPolicy (redact) │   │
│  │  AuditPolicy (events + risk)        │   │
│  └─────────────────────────────────────┘   │
└────────────────────────────────────────────┘
    │
    ▼
  Result (or ActionBlockedError with
  reason, risk_score, approval_id)
```

The pipeline is deliberately dumb — all detection lives in the policies. Deny in the *before* phase blocks before the agent runs; deny in the *after* phase blocks the response after all policies (including audit) complete.

## Framework Integrations

`SecureAgent` wraps any object exposing `ainvoke`/`invoke` (and `astream`/`stream`) — `wrap_agent` and `wrap_graph_agent` are named convenience aliases over that for LangChain and LangGraph:

```python
from sdk import wrap_agent, wrap_graph_agent, load_policies

secure = wrap_agent(langchain_agent, policies=load_policies("policies.yaml"))
result = await secure.invoke({"input": "What is prompt injection?"})
```

This means any framework whose runnables expose that same shape — CrewAI, PydanticAI, AutoGen, the OpenAI Agents SDK — already works with `SecureAgent(agent, policies=...)` directly today; named wrappers for them are on the roadmap for ergonomics, not because the underlying capability is missing. What none of the current wrappers do yet is hook a framework's own per-step primitives (LangGraph node execution, LangChain callbacks) — policies see the whole call, not individual steps inside it. The step that matters most, the tool call, does not need a framework hook: wrap the tools themselves in [`SecureTool`](#4-guard-the-tools-the-agent-calls).

## Compliance Positioning

`CompliancePolicy` **assists** compliance programs — its checks (PHI identifier detection, credential-output guarding, data-access auditing) map onto common GDPR/HIPAA/SOC 2 controls. It does **not** confer or certify compliance with any regulation, and its presets are deliberately named after what they check, not after regulations.

## Server

An optional FastAPI server (`uvicorn server.app:app`) provides the event store, SSE feeds, a session dashboard (`/dashboard/`), stateless scoring endpoints (`/v1/threat/score`, `/v1/tools/validate`), the approval queue (`/v1/approvals`), and Prometheus metrics (`/metrics`). All endpoints except `/health` require the `X-API-KEY` header (`OPENSCRIPT_API_KEY`). The server needs a running Postgres with migrations applied before it will boot — `docker compose up -d && alembic upgrade head` (see `docker-compose.yml`), or point `DATABASE_URL` at your own instance. The approval queue is only shared with SDK clients in other processes when the server has `REDIS_URL`; the compose file starts a Redis and sets it. Without one the server keeps approvals in its own memory and says so in its log.

Try the full pipeline end-to-end (in-memory, no server or database required):

```bash
pip install -e ".[demo]"
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

# Lint + format + type-check (CI runs mypy --strict on sdk/ and contracts/)
ruff check .
black .
mypy --strict sdk/ contracts/

# Measure detection and false positives against the labelled corpora
make evals
make evals-misses       # plus every prompt the policies got wrong
```

CI skips every job for changes that only touch markdown, so documentation edits
do not spend six runners proving nothing.

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

## License

Apache 2.0 — see [LICENSE](LICENSE).
