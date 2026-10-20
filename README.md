# OpenScript

[![CI](https://github.com/saintparish4/openscript/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/saintparish4/openscript/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776ab)](pyproject.toml)
[![Types: mypy --strict](https://img.shields.io/badge/types-mypy%20--strict-2a6db2)](.github/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Live demo](https://img.shields.io/badge/demo-live%20in%20your%20browser-22c55e)](https://openscript-demo.vercel.app/)

**Hard limits and a record for LLM agents, for when the model gets it wrong.**

OpenScript is a Python security gateway between an AI agent and the tools it calls. It refuses calls outside rules you write in advance (which tools, which arguments, which recipients, how much), holds the ones you choose for a person to approve, masks secrets and PII, and records every decision. Current models already resist most prompt injection, and OpenScript does not replace that judgement. It is the boundary that still holds when the model is fooled, wrong, or swapped for another, and none of it depends on recognising an attack.

**[Try the live demo →](https://openscript-demo.vercel.app/)** It is this package compiled to WebAssembly and running in your tab, with no backend, so the prompts never leave the page.

## Key Features

### What it does

- **Tool firewall.** Per-tool, per-argument rules in YAML: bounds, allowlists, full-match patterns, path prefixes and roles. A call the rules refuse never runs.
- **Approvals bound to the exact call.** A held call waits for a person. The approval is single-use, expires after an hour, and is bound to the tool and its exact arguments, so a yes for $500 to one account cannot be spent on another account or a larger amount.
- **A memory of what the session has read.** Once an agent has read something a stranger could have written, such as a web page, an issue or an email, the state-changing calls you list wait for a person. It reads no text, so the wording of an attack cannot talk it round. It can also let a call through when it only sends somewhere the user has sent before.
- **Redaction in both directions.** Secrets are masked before the model sees them, and PII is masked before the caller gets it back. The same masking applies to what a tool returns.
- **Input screening.** Prompt injection, toxicity and harmful requests are scored against pattern banks. A disguised prompt is scored again with the disguise undone: zero-width characters, look-alike letters, leetspeak, spaced-out letters, base64.
- **An audit trail.** With `AuditPolicy` in the list, every action and every refusal becomes an event with an aggregated risk score, including calls stopped before anything ran.
- **A Claude Code hook.** `openscript-hook` gives Claude Code argument rules, the session memory, secret masking and an audit log. It only ever makes Claude Code stricter.
- **Any agent framework.** Anything with `ainvoke`/`invoke` (or `astream`/`stream`) can be wrapped. Streaming has a guarded mode that scans as it goes, and an optional FastAPI server adds an event store, a dashboard, an approval queue, Prometheus and OpenTelemetry.
- **A Java client.** `clients/java` puts a Java agent and its tools behind the same Python policies, run by the server. Nothing is reimplemented in Java, and it has no dependencies beyond the JDK.

### Why it matters

- **Nothing load-bearing depends on detection, and that choice is measured.** On AgentDojo's banking suite (Claude Haiku 4.5 and Claude Sonnet 5.5) and its Slack suite (Sonnet), the models followed none of the planted instructions in 4,086 attacked conversations, so those runs could not test what the rules contain. The pattern detectors catch only 2 to 7% of attacks they were not written for. So the boundary is the rules, the approvals and the record, not recognising an attack.
- **Benchmarked against a public suite, with each protocol frozen before its results.**
  - In a replay of [AgentDojo](https://github.com/ethz-spylab/agentdojo) with no model, the session rule stopped 570 of 617 attacks with an approver who refused the attacker's calls.
  - Its cost is published alongside: it asked a person on 55 of 97 ordinary tasks. Every one of those tasks is built to read something an attacker can write, the worst case for this rule. With Sonnet doing the work, it asked on 11 of 16 banking tasks, as often as asking every time, and on 16 of 21 Slack tasks.
  - Holding only calls to new destinations cut that to 44 of 97 and let no attacker call through. It helps only where there is a sending history to know, and over all four suites it is still over the one-third bar set beforehand. Run live with Sonnet on banking, where the user has a payment history, it asked on 4 of 16 tasks. It does not make approvals rare.
- **Pure local, enforced in CI.** All ten built-in policies are regexes, heuristics, checksums or declarative rules, with no network or LLM call. `tests/test_audit.py` fails the build if one grows a network import, which is why the same code runs in a browser with nothing behind it.
- **Fast enough to sit in the loop.**
  - The input policies take 0.05 to 0.7 ms per prompt (p50, native).
  - The demo's whole pipeline takes 5.3 ms p50 under WebAssembly on a CI runner.
  - The Claude Code hook adds about 150 ms before a call and 70 ms after it on a quiet machine, each a fresh process, inside a latency budget written down before it was measured.
- **Fails closed.**
  - Security policies block when they error.
  - Rule files reject misspelt keys, and a value a rule cannot evaluate is refused.
  - The Claude Code hook blocks the call if anything goes wrong while it is deciding.
- **Tested like a security tool.** 844 tests, `mypy --strict` on the SDK, and six CI jobs. One job boots the package under Pyodide headless, and another runs every demo prompt through the exported site.

Every number above, with its date, command and caveats, is in [`docs/metrics.md`](docs/metrics.md).

### Built-in Policies

| Policy | Phase | What it does |
|--------|-------|--------------|
| `PromptInjectionPolicy` | input, tool output | Scores role injection, prompt extraction, goal hijacking, delimiter/indirect injection; denies on threshold. Around a tool it also scores what the tool returned — recorded by default, `tool_output="deny"` to withhold it |
| `ToxicityPolicy` | input | Detects threats, hate speech, harassment, self-harm content; denies on threshold |
| `HarmfulRequestPolicy` | input | Scores requests for harmful capability — weapons, malware, doxxing, illicit acquisition, fraud, violence planning, covert surveillance, exploitation, self-harm methods; denies on threshold |
| `PIIPolicy` | output | Redacts or denies emails, phones, SSNs, credit cards (Luhn-checked), API keys, IPs |
| `SecretsPolicy` | input + output | Redacts or denies AWS/GitHub/Slack tokens, JWTs, private-key blocks; separately flags internal URLs/private IPs (`internal_url_mode`: annotate by default, plus allowlist) |
| `CompliancePolicy` | input + output | Honestly-scoped presets: `phi_detection`, `credential_output_guard`, `data_access_audit` — it assists a compliance program and certifies nothing, see [Compliance positioning](docs/guide.md#compliance-positioning) |
| `ToolFirewallPolicy` | tool call | Per-tool deny/RBAC and per-argument rules (bounds, allowlists, patterns, path prefixes); can require human approval. Acts on tool calls only, so it goes in a [`SecureTool`](#3-guard-the-tools-the-agent-calls)'s list, not a `SecureAgent`'s. Also usable standalone via `validate_tool_call()` or `POST /v1/tools/validate` |
| `SessionTaintPolicy` | tool call | Remembers which sessions have read untrusted content (the tools you name as sources) and holds, or refuses, every later call to a tool you name as state-changing. It reads no text, so it does not depend on recognising an attack, and it holds the benign follow-up too: with a model doing AgentDojo's banking tasks it asked on 11 of 16. Goes in a [`SecureTool`](#4-hold-what-follows-an-untrusted-read)'s list, one instance shared by all of a session's tools |
| `OutputSchemaPolicy` | output | Pydantic schema validation, dangerous-content scan, optional hallucination/grounding check against a source |
| `AuditPolicy` | both | Writes every action to the event store, and an `action_blocked` event for every action the pipeline refuses; place it **last** so its events carry the final risk score |

## Tech Stack & Architecture

### Technologies

| Layer | Built with |
|---|---|
| Core SDK | Python 3.11+, with three runtime dependencies: pydantic 2 (≥ 2.10), structlog, PyYAML |
| In the browser | Pyodide 0.28.3 (CPython on WebAssembly), Next.js 16 static export, React 19, TypeScript |
| Browser extension | Chrome Manifest V3, with Pyodide running in the side panel |
| Optional server | FastAPI, SQLAlchemy with asyncpg on Postgres, Alembic, Redis, Prometheus, OpenTelemetry |
| Java client | Java 17, the JDK's `HttpClient`, Maven; JUnit 5 for its tests |
| Evaluation | Labelled corpora (1,799 prompts, 1,451 of them public), AgentDojo 0.1.35, the Anthropic Python SDK for runs with a model |
| Quality | pytest, mypy `--strict`, ruff, black, GitHub Actions, a daily check of the deployed demo |

### How a call flows

The pipeline contains no detection logic. Every check is a `Policy`, and each one can allow, rewrite (redact), deny, or require a person's approval. `SecureAgent` guards what goes into an agent and what comes out of it. `SecureTool` guards each tool the agent calls, because those calls happen inside the agent where the outer pipeline cannot see them. With a typical set of policies:

```
caller ──► SecureAgent ──► before_action: injection · toxicity · harmful request · secrets
                │
                ▼
              agent ──── calls a tool ───► SecureTool (one per tool)
                │                            before_action: firewall · session rule ──► deny / ask
                │                            the tool runs, with the arguments that were checked
                │                            after_action:  redact · score the result · audit
                ▼
           after_action: output schema · PII / secrets redaction · compliance · audit
                │
                ▼
caller ◄── response, or ActionBlockedError(reason, risk_score, approval_id)
```

A deny before the agent runs means the agent never runs. A deny after it means the response is withheld once every policy, audit included, has finished. With `AuditPolicy` in the list, a refusal is recorded even when it comes before the audit policy's turn.

### Repository layout

```
openscript/
├── sdk/                      the package (there is no `import openscript`: it is `import sdk`)
│   ├── middleware/           SecureAgent (middleware.py) and SecureTool (tool.py)
│   ├── policies/             the built-in policies, the YAML loader, example configs
│   ├── interceptors/         PII, threat scoring and the event writer (the pre-1.0 names)
│   ├── hooks/                openscript-hook for Claude Code, its config model and examples
│   ├── integrations/         wrap_agent / wrap_graph_agent for LangChain and LangGraph
│   └── observability/        risk scoring, Prometheus metrics, OpenTelemetry tracing
├── contracts/                the Policy protocol, ActionContext, decisions, failure modes
├── events/                   event writer and store; approval stores (in-memory, Redis)
├── server/                   optional FastAPI server: events, SSE, dashboard, approvals, /v1/guard, /metrics
├── clients/java/             a Java client: SecureAgent and SecureTool over /v1/guard
├── site/                     the live demo: a Next.js static export that runs the package via Pyodide
├── extension/                a Chrome extension: the package around a scripted browsing agent
├── web/                      a bare Pyodide probe page and its headless check
├── evals/                    labelled corpora and run.py; agentdojo/ is the benchmark harness
├── demo/                     a terminal walkthrough of the pipeline
├── tools/                    policy audit, browser wheel builds, hook latency, the Java client's live check
├── tests/                    the test suite
└── docs/                     guide.md (the full reference), metrics.md (every number), the demo recording
```

## Getting Started

### Prerequisites

- **Python 3.11 or newer** and **git**. That is all the SDK needs.
- Only for the optional parts:
  - **Docker**, to run the server's Postgres and Redis.
  - **Node.js** and npm, to build the demo site or the extension.
  - **Chrome or Chromium**, to load the extension.
  - **[uv](https://docs.astral.sh/uv/)**, for the AgentDojo harness, which keeps its own Python 3.13 environment.
  - **Java 17 or newer** and **Maven**, for the Java client in `clients/java`.

### Installation

OpenScript installs from source. It is not published to PyPI.

```bash
git clone https://github.com/saintparish4/openscript.git
cd openscript
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
```

`pip install -e .` pulls only pydantic, structlog and PyYAML, and it is enough for everything in [Usage](#usage). It also puts the `openscript-hook` command in the virtual environment. Check the install:

```bash
python -c "import sdk; print(sdk.SecureAgent, sdk.SecureTool)"
openscript-hook --help
```

Optional extras, installed the same way (`pip install -e ".[redis]"`):

| Extra | Adds |
|---|---|
| `redis` | `RedisApprovalStore`, so approvals can be decided from another process |
| `metrics` | Prometheus metrics |
| `otel` | OpenTelemetry spans |
| `demo` | the dependencies of `demo/injection_demo.py` |
| `ml` | the opt-in `SemanticPolicy`. Its classifier is not trained yet, so it refuses to construct, and no number is claimed for it |

To work on the project itself (tests, server, linters), install everything:

```bash
make install                     # .venv, requirements.txt, then pip install -e .
```

## Usage

![The live demo: a page tells Lena's browsing agent to send her session elsewhere. The scan misses the note, and the tool rule refuses the form post it provokes](docs/demo.gif)

The full walkthrough, under a minute: [`docs/demo.mp4`](docs/demo.mp4). It goes on to a call held for a team lead and approved once, and an API key masked before the model is given it.

### 1. Wrap an Agent

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
            PromptInjectionPolicy(threshold=0.5),  # denies known injection shapes
            PIIPolicy(mode="redact"),              # redacts PII from output
            SecretsPolicy(mode="redact"),          # redacts credentials, flags internal URLs
        ],
    )
    result = await secure.invoke({"input": "OpenScript"})
    print(result)  # {'output': 'Hello, OpenScript!'}

asyncio.run(main())
```

A blocked action raises `ActionBlockedError` with the reason, the policy that blocked it, and the action's aggregated `risk_score`. LangChain and LangGraph agents already have this shape. `wrap_agent` and `wrap_graph_agent` are named aliases for the same call.

### 2. Configure Policies from YAML

```yaml
# policies.yaml
policies:
  prompt_injection:
    threshold: 0.6
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

### 3. Guard the Tools the Agent Calls

The tools an agent calls run inside the agent, where `SecureAgent`'s policies cannot see them, and that is where a manipulated agent does its damage. `SecureTool` wraps one tool and runs the same pipeline on every call to it:

```python
from sdk import SecureTool, ToolFirewallPolicy

async def send_email(to: str, body: str = "") -> str:
    ...

send = SecureTool(send_email, policies=[ToolFirewallPolicy(rules_path="tools.yaml")])

await send(to="ops@example.com", body="done")   # called like the function it wraps
```

```yaml
# tools.yaml
default_deny: true              # a tool with no rule is refused
rules:
  send_email:
    unlisted_args: deny         # no cc or bcc around the allowlist on `to`
    args:
      to:   {required: true, pattern: '[^@\s]+@example\.com'}
      body: {}
  fetch_issue:
    args:
      number: {min: 1}
  transfer_funds:
    requires_approval: true     # held for a person, see step 5
    args:
      amount: {min: 0, max: 1000}
  delete_account:
    deny: true
```

A refused call raises `ActionBlockedError` and **the tool does not run**. The rules are the boundary, and only as tight as you write them: if `send_email` may write to anyone, an injected agent can still send mail. The guide covers [what the rules check and what they cannot see](docs/guide.md#tool-rules-what-they-check-and-what-they-cannot-see), such as redirects and symlinks.

### 4. Hold What Follows an Untrusted Read

A prompt injection works in two steps: the agent reads something a stranger wrote, then it acts. `SessionTaintPolicy` remembers the first step and holds the second:

```python
from sdk import SecureTool, SessionTaintPolicy, ToolFirewallPolicy

firewall = ToolFirewallPolicy(rules_path="tools.yaml")
taint = SessionTaintPolicy(
    sources=["fetch_issue", "read_page"],   # what they return, a stranger may have written
    sinks=["send_email", "run_shell"],      # what they do cannot be taken back
)

fetch = SecureTool(fetch_issue, policies=[firewall, taint])
send = SecureTool(send_email, policies=[firewall, taint])

await send.call({"to": "ops@example.com"}, session_id="s1")   # runs: nothing untrusted read yet
await fetch.call({"number": 482}, session_id="s1")            # runs, and taints the session
await send.call({"to": "ops@example.com"}, session_id="s1")   # ActionBlockedError, with an approval_id
```

Share one instance between all of a session's tools, because the memory lives on the instance. It holds the benign follow-up exactly as it holds an attack, and it asks often: see [the measured cost](docs/guide.md#the-session-rule-what-it-buys-and-what-it-costs). `known={"send_email": {"to": [...], "cc": [...], "bcc": [...]}}` lets a held call through when every destination it names is one the user has already sent to. A call that names none is still held, unless its tool is listed in `updates` because it edits something that already exists.

### 5. Approve a Held Call

```python
from sdk import ActionBlockedError, RedisApprovalStore, SecureTool, ToolFirewallPolicy

transfer = SecureTool(
    transfer_funds,
    policies=[ToolFirewallPolicy(rules_path="tools.yaml")],
    approval_store=RedisApprovalStore("redis://localhost:6379/0"),  # shared with the server
)

call = {"to": "acct-22", "amount": 500}
try:
    await transfer.call(call)
except ActionBlockedError as e:
    approval_id = e.approval_id  # a person decides: POST /v1/approvals/{id}/decide

result = await transfer.call(call, approval_id=approval_id)  # the same call, once
```

The default in-memory store works within one process. Approvals decided through the server need Redis.

### 6. Guard Claude Code with a Hook

`openscript-hook` runs the tool policies as a [Claude Code hook](https://code.claude.com/docs/en/hooks). It adds what Claude Code's per-tool permissions cannot express: rules on a call's arguments, a memory of what the session has read, secrets masked in tool output, and a JSON line for every decision.

```bash
cp sdk/hooks/claude_code_example.yaml your-project/.claude/openscript.yaml   # name your MCP servers' tools
openscript-hook --config your-project/.claude/openscript.yaml check          # what it will do, and any likely typo
```

Then merge [`sdk/hooks/settings_example.json`](sdk/hooks/settings_example.json) into `your-project/.claude/settings.json`, using the absolute path to `openscript-hook`.

On each call it answers **deny** (the call does not run, and Claude is told why), **ask** (Claude Code's own prompt, carrying OpenScript's reason), or nothing. It never approves anything, so your own permission settings still apply.

It was tried in a real Claude Code session with a small MCP issue tracker:
- After the agent read an issue, its next comment brought up the prompt.
- A comment on an issue the rules did not allow was refused.
- A `.env` reached the model masked.

The payloads from that session are replayed in the tests. The guide covers [its limits](docs/guide.md#the-claude-code-hook-what-it-adds-and-what-it-does-not-do): Bash is not held by default, and the transcript keeps the unmasked output.

### 7. Guard a Java Agent

The policies run in Python. A Java program reaches them through the server, which runs one phase of the pipeline per request: the client asks about the input, runs its agent or tool on what came back, then asks about the output. The two lists are configured on the server, as a Python program would build them for `SecureAgent` and `SecureTool`:

```bash
OPENSCRIPT_GUARD_CONFIG=server/guard_example.yaml uvicorn server.app:app   # Postgres up, OPENSCRIPT_API_KEY set
```

```java
OpenScriptClient client = OpenScriptClient.builder()
    .baseUrl("http://localhost:8000")
    .apiKey(System.getenv("OPENSCRIPT_API_KEY"))
    .build();

SecureAgent agent = client.secureAgent(input -> model.complete((String) input.get("prompt")));
String answer = (String) agent.invoke(Map.of("prompt", userText));   // the model gets the redacted prompt

SecureTool wire = client.secureTool("wire_money", args -> bank.wire(args),
    CheckOptions.defaults().withRole("finance"));
try {
  wire.call(Map.of("amount", 250, "to", "acct-7"));
} catch (ActionBlockedException e) {
  if (e.requiresApproval()) { /* a person decides e.approvalId(); retry with withApprovalId(...) */ }
}
```

Every call also has an async form (`invokeAsync`, `callAsync`, `checkInputAsync`, ...) returning a `CompletableFuture`. A streaming agent gets Python's three stream modes, including guarded streaming, where the server scans a held-back tail before any text is released. An `InMemoryMetrics` recorder counts every check and writes Prometheus text.

It fails closed: an unreachable server, a wrong key or a policy that raised is an `OpenScriptException`, and the agent or tool does not run. Each guarded call costs two round trips to the server: 4.7 ms p50 for an agent call with the server on the same machine ([measured](docs/metrics.md#the-java-client-per-call)). The session rule's memory is in the server process, so run one worker, and the approval store is shared with `/v1/approvals` (in memory unless `REDIS_URL` is set). Details in [`clients/java/README.md`](clients/java/README.md); `make java-live` runs its tests against the real policies.

### 8. Run the Demos

```bash
pip install -e ".[demo]" && python demo/injection_demo.py   # a terminal walkthrough, in memory
make demo-serve                                              # the browser demo, served on :8081
make extension                                               # assemble the Chrome extension, then load extension/ unpacked
```

The [browser demo](https://openscript-demo.vercel.app/) is twenty-one prompts from seven fictional people. Each one shows what the sender asked for, what reaching the agent unchecked would have meant, and what the pipeline did instead. One prompt is there because it gets through, and is shown as a miss. Another is a page that politely tells a browsing agent to send the session elsewhere. The detector scores it zero, and the form post it provokes is refused anyway, because the destination is not on the allowlist.

## Configuration

### Environment variables

| Variable | Read by | Default | What it does |
|---|---|---|---|
| `OPENSCRIPT_LOG_LEVEL` | the SDK's logging | `INFO` | Log level |
| `OPENSCRIPT_LOG_FORMAT` | the SDK's logging | JSON when stderr is not a terminal | `json` forces JSON logs |
| `OPENSCRIPT_OTEL` | `SecureAgent` | off | `1` or `true` opens one span per action. The exporter is configured with the standard `OTEL_*` variables |
| `OPENSCRIPT_API_KEY` | the server | none: protected endpoints return 500 until it is set | The key every endpoint except `/health` expects in `X-API-KEY` |
| `DATABASE_URL` | the server, Alembic | `postgresql+asyncpg://openscript:openscript@localhost:5432/openscript` | The event store |
| `REDIS_URL` | the server | none: approvals stay in the server's memory | Shares the approval queue with SDK clients in other processes |
| `OPENSCRIPT_GUARD_CONFIG` | the server | none: `/v1/guard` answers 503 | The policies behind `/v1/guard`, for the Java client ([example](server/guard_example.yaml)). An invalid file stops the server from starting |
| `OPENSCRIPT_HOOK_CONFIG` | `openscript-hook` | `$CLAUDE_PROJECT_DIR/.claude/openscript.yaml` | The hook's config (`--config` overrides it) |
| `OPENSCRIPT_STATE_DIR` | `openscript-hook` | `$XDG_STATE_HOME/openscript`, else `~/.local/state/openscript` | Where the hook keeps session memory, its config cache and the audit log (under `claude-code/`). Keep it on a local disk |
| `ANTHROPIC_API_KEY` | `evals/agentdojo/run_model.py` | none | Only for AgentDojo runs with a real model, which also need `--budget` and `--yes` |

For the server, `cp .env.example .env` (or `make env`) gives a working starting point, and `docker compose up -d && alembic upgrade head` brings up Postgres and Redis with the schema applied.

### Configuration files

| File | Configures | Start from |
|---|---|---|
| `policies.yaml` | Which policies run and their options, via `load_policies()` | [`sdk/policies/policies_example.yaml`](sdk/policies/policies_example.yaml) |
| `tools.yaml` | Tool and argument rules, via `ToolFirewallPolicy(rules_path=...)` | [`sdk/policies/tools_example.yaml`](sdk/policies/tools_example.yaml) |
| `.claude/openscript.yaml` | The Claude Code hook: rules, session sources and sinks, redaction, audit | [`sdk/hooks/claude_code_example.yaml`](sdk/hooks/claude_code_example.yaml) |
| `.claude/settings.json` | Which Claude Code tool calls go through the hook | [`sdk/hooks/settings_example.json`](sdk/hooks/settings_example.json) |
| `.env` | The server | [`.env.example`](.env.example) |
| `guard.yaml`, named by `OPENSCRIPT_GUARD_CONFIG` | The policies `/v1/guard` runs for the Java client: an `agent` list and a `tool` list | [`server/guard_example.yaml`](server/guard_example.yaml) |

Every rule file is validated strictly, so a misspelt key fails at load instead of being quietly ignored.

### Options worth knowing

| Option | Values | Default |
|---|---|---|
| `SecureAgent(stream_output=...)` | `buffer` (full protection), `guarded` (scans as it streams, with a hold-back window), `passthrough` (no protection, audit only) | `buffer` |
| `PIIPolicy(mode=...)`, `SecretsPolicy(mode=...)` | `redact`, `deny` | `redact` |
| `PromptInjectionPolicy(tool_output=...)` | `annotate` (record the score), `deny` (withhold the result), `off` | `annotate` |
| `SessionTaintPolicy(on_taint=...)` | `require_approval`, `deny` | `require_approval` |
| A policy's `failure_mode` | `FAIL_CLOSED`, `FAIL_OPEN`, `FAIL_EXCEPTION` | closed for security policies, open for redaction and observability |

The guide covers each feature in full, including streaming, observability, custom policies and the server: [`docs/guide.md`](docs/guide.md).

## Contributing & License

### Contributing

Pull requests are welcome. Before opening one, run what CI runs:

```bash
pytest                            # the full suite; Redis tests skip unless OPENSCRIPT_TEST_REDIS_URL is set
ruff check . && black --check .   # lint and format
mypy --strict sdk/ contracts/     # type-check
```

If you touch `sdk/policies/` or `sdk/interceptors/`, also run `pytest tests/test_audit.py tests/test_pyodide_compat.py`. Every built-in policy must stay pure local and importable under Pyodide, because the browser demo runs it with no backend. If you touch `clients/java/` or the server's `/v1/guard`, run `make java-test`, and `make java-live` with Postgres up: CI runs the Java client against the real server and fails if those tests were skipped. [CONTRIBUTING.md](CONTRIBUTING.md) has the full checklist, including how to add a policy.

Report bugs through [GitHub Issues](https://github.com/saintparish4/openscript/issues), with the policy, the input that misbehaved, and what you expected instead.

### License

Apache License 2.0. See [LICENSE](LICENSE).
