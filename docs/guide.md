# OpenScript guide

The [README](../README.md) is the overview: what OpenScript does, how to install it, and a first example of each feature. This is the reference behind it. It covers what each feature buys and what it does not, the measured cost of each, and the parts the README only names. Every number here is also in [`metrics.md`](metrics.md), with the date it was measured and the command that produces it.

- [Tool rules: what they check and what they cannot see](#tool-rules-what-they-check-and-what-they-cannot-see)
- [The session rule: what it buys and what it costs](#the-session-rule-what-it-buys-and-what-it-costs)
- [The Claude Code hook: what it adds and what it does not do](#the-claude-code-hook-what-it-adds-and-what-it-does-not-do)
- [Human approval](#human-approval)
- [What the detection actually measures](#what-the-detection-actually-measures)
- [Streaming](#streaming)
- [Observability](#observability)
- [Write a custom policy](#write-a-custom-policy)
- [Architecture](#architecture)
- [Framework integrations](#framework-integrations)
- [Compliance positioning](#compliance-positioning)
- [Server](#server)
- [The browser demo and the extension](#the-browser-demo-and-the-extension)
- [Migrating from the interceptor API](#migrating-from-the-interceptor-api)

## Tool rules: what they check and what they cannot see

`SecureTool(send_email, policies=[...])`, as in the README's example, returns a callable `send`: give it to your agent in place of `send_email`. It imports no framework: whatever calls the tool calls this instead. Sync and async tools both work (a sync one runs in a worker thread). A call the rules deny raises `ActionBlockedError` and **the tool does not run**.

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
- **`pattern` has to match the whole value**, so an allowlist for `example.com` is not satisfied by `example.com.attacker.io`. That is also how a host allowlist on a URL is written (`url: {pattern: 'https://vendor\.example\.com(/.*)?'}`), and it reads the URL the agent asked for: where that page redirects to is not something the rule sees.
- **`path_prefix` resolves `..` before comparing** and does not expand `~`. It reads the path as text, so it cannot see a symlink inside the allowed directory that leads back out.
- **A misspelt key fails the load.** A rules file that reads as enforced and enforces nothing is worse than no file.
- **Output policies in the tool's list apply to what the tool returns.** `PIIPolicy` and `SecretsPolicy` redact it. `PromptInjectionPolicy` scores it, because a tool's result is how the text of a fetched page or an email reaches the model. That score is recorded and let through by default (`tool_output="annotate"`), since the patterns behind it miss most attacks they were not written for; `tool_output="deny"` withholds the result. Withholding is not undoing: by then the tool has run.
- **It does not stop harm done through a call the rules permit.** If `send_email` may write to anyone, an injected agent can still send mail. The rules are the boundary, and it is only as tight as they are.

Start from `sdk/policies/tools_example.yaml`. The same check is available without the wrapper as `validate_tool_call(call, rules=rules)` and `POST /v1/tools/validate`.

## The session rule: what it buys and what it costs

`SessionTaintPolicy` holds every call to a tool you name as a sink once the session has run a tool you name as a source. It reads none of the text, so it cannot be talked round by how an attack is worded. For the same reason it cannot tell a hostile page from an ordinary one: it holds the benign follow-up exactly as it holds the attack. What that buys, and what it does not:

- **One instance for all of a session's tools.** What a session has read is remembered on the policy instance. A sink wrapped with a second instance never hears about a read seen by the first.
- **A tool that is not listed is not held.** `sinks="*"` holds every tool. A read whose arguments can carry data out (a URL to fetch) is a source *and* a sink: list it in both.
- **An approval buys one call.** It is bound to the tool and its exact arguments, like every approval here, and the session stays tainted afterwards. `on_taint="deny"` refuses instead of asking.
- **A read that never returned taints nothing.** One the firewall refused, or that raised, gave the model nothing. One whose result a later policy withholds still taints, which is the safe side to be wrong on.
- **Sessions are what you say they are.** Calls made without a `session_id` share one, which errs towards holding. `reset(session_id)` is for when the model's context has been discarded, and `taint(session_id, source)` is for content that arrives some other way, such as an uploaded file.
- **The memory is this process's.** Like the in-memory approval store, it is not shared between workers and does not survive a restart.
- **Put the firewall before it,** so a call the rules refuse outright is refused, not sent to a person first.
- **`known` lets a held call through when everywhere it sends is somewhere the user has already sent:** `known={"send_money": {"recipient": [...]}}`. Every destination argument that is present must have all its values known (each item of a list); an absent one leaves the destination unchanged; values compare ignoring case. List every argument that names a destination (`to`, `cc`, `bcc`): one that is not listed is not looked at. Measured on AgentDojo's no-model replay under a protocol frozen first, it cut the ordinary tasks needing a person from 55 of 97 to 42 and let no attacker call through: banking 12 to 5, and Claude Sonnet 5.5's recorded banking calls 11 to 4. Run live with Sonnet on banking it asked on the same 4 of 16, and with nobody to approve, 12 of 16 tasks were done instead of 7 ([numbers](metrics.md#with-a-model-claude-sonnet-55-on-banking)). It helps only where there is a sending history to know, travel and Slack have none, and a directory is not a history: a variant that knew every Slack member let 12 more attacks through ([numbers](metrics.md#tool-policies-on-agentdojo-holding-only-new-destinations)).
- **It asks often, and that is measured.** Replaying [AgentDojo](https://github.com/ethz-spylab/agentdojo)'s own solutions to its 97 tasks, with no model, 55 needed at least one approval. A rule that simply asks on every state-changing call needed 61. Those tasks are all built to read something an attacker can write, which is the worst case for a rule keyed on reading, but on read-then-act work it is nearly as noisy as asking every time, and an approval asked for on most tasks stops being read. With an approver who refuses the attacker's calls it stopped 570 of 617 replayed attacks; with one who approves everything, none. The 47 it missed, and why, are in [`docs/metrics.md`](metrics.md#tool-policies-on-agentdojo-a-replay-with-no-model). With a model in the loop (Claude Haiku 4.5 and Claude Sonnet 5.5, AgentDojo's banking suite, two attacks), neither model followed the injection once in 3,456 attacked conversations, so there was nothing for the rule to stop and it only cost tasks; with Sonnet, which did the work, it asked on 11 of 16 ordinary tasks, as often as asking every time ([details](metrics.md#tool-policies-on-agentdojo-with-a-model-in-the-loop)). On AgentDojo's Slack suite Sonnet followed none of 105 attacks in any run, and the rule asked on 16 of 21 ordinary tasks ([details](metrics.md#tool-policies-on-agentdojo-slack-with-a-model)).

## The Claude Code hook: what it adds and what it does not do

Claude Code's permissions decide which tools may run. `openscript-hook` runs the same tool policies as a [Claude Code hook](https://code.claude.com/docs/en/hooks) and adds what those permissions cannot say:

- **Rules on a call's arguments** (`ToolFirewallPolicy`): issues filed only in your organisation, messages posted only to one channel, a merge that always asks first.
- **A memory of what the session has read** (`SessionTaintPolicy`): after a web page or an MCP read, the MCP calls you list wait for you.
- **Secrets masked in a tool's output** before the model reads it: a `cat .env` is handed back as `AWS_KEY=AKIA**********`.
- **A record of every decision**, one JSON line each, never with the tool's output.

```bash
pip install -e .                                                     # from this repo: puts openscript-hook in your venv
cp sdk/hooks/claude_code_example.yaml your-project/.claude/openscript.yaml   # then name your MCP servers' tools
openscript-hook --config your-project/.claude/openscript.yaml check          # what it will do, and any name that looks like a typo
```

Then merge [`sdk/hooks/settings_example.json`](../sdk/hooks/settings_example.json) into `your-project/.claude/settings.json`, with the absolute path to `openscript-hook`. On each call it answers **deny** (the call does not run, and Claude is told why), **ask** (Claude Code's own prompt, with OpenScript's reason), or nothing, and Claude Code decides as it always would.

Tried in a real Claude Code session (2.1.292, auto permission mode), with a small MCP issue tracker: a comment posted before any read went through; after the agent read an issue, the next comment brought up Claude Code's prompt with OpenScript's reason, and two comments asked for in one message were held one by one; a comment on an issue the rules did not allow was refused and Claude said why; and a `.env` reached the model masked through both Bash and Read. The payloads from that session are replayed in [`tests/test_claude_code_hook.py`](../tests/test_claude_code_hook.py).

What it does not do, stated plainly:

- **It only tightens.** It never approves a call, so your own permission rules and modes still apply on top of it.
- **Bash, Write and Edit are not held after a read by default.** In a coding session that would ask on nearly every command after any web read. Argument rules and redaction still apply to them if you configure them.
- **Redaction changes what the model is sent, not what Claude Code records.** The transcript and your terminal still hold the original output. For built-in tools the masked output has to match the tool's own output shape, or Claude Code ignores it: it does for Bash and Read, checked in a real session; for other built-in tools it has not been checked. The hook tells the model that something was masked, because without that it took the stars for the file's real content.
- **A new conversation is a new session.** `/clear` gives Claude Code a new session id, so what was read before it no longer holds anything, which is right: the model no longer has that text either.
- **It fails closed while deciding.** A missing or invalid config, or any error, blocks the call. A hook that times out does not block: that is Claude Code's rule. The example settings run it as `openscript-hook pre-tool-use || exit 2`, so a hook that cannot start blocks too; Claude Code 2.1.295 and later also take `"onFailure": "block"`.
- **Install it per project.** With no config, every call it is asked about is refused, so put it in the project's `.claude/settings.json`, or set `OPENSCRIPT_HOOK_CONFIG` if you use it everywhere.
- **Its memory and audit log are files** in `~/.local/state/openscript/claude-code` (or `$OPENSCRIPT_STATE_DIR/claude-code`), kept on a local disk: appends from parallel hooks are safe there and not on a network share.
- **It costs time on every call it matches:** about 150 ms before and 70 ms after, measured against a budget set beforehand ([numbers](metrics.md#the-claude-code-hook-per-call)).

## Human approval

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

Approvals are **single-use**, expire after 1 hour, and are bound to the tool's name and its exact arguments — an approval for $500 to one account cannot be spent on another account or a larger amount, and cannot be replayed. A call that breaks an argument rule is denied outright rather than sent for approval. Whoever decides can say why: `store.decide(approval_id, approved=False, decided_by="dana", note="...")`, or `note` in the body of `POST /v1/approvals/{id}/decide`, is kept on the record as `decision_note` and written to the `approval_resolved` event.

`SecureAgent.invoke(..., approval_id=...)` redeems an approval the same way when a custom policy gates the whole agent call. There the approval is bound to the agent's input, not to anything the agent goes on to do.

## What the detection actually measures

The three input-side policies scan the prompt as it arrived **and** normalized views of it, so an attack disguised with zero-width characters, Cyrillic look-alikes, leetspeak, spaced-out letters, full-width forms or a base64 payload scores like the attack it is. Plain prose produces one view and costs what it always did. See `sdk/policies/normalize.py`.

Asserting that a security tool works is cheap. `evals/` holds labelled corpora and `make evals` scores the policies against them; `tests/test_evals.py` fails the build if the numbers regress. Measured 2026-10-11:

| Corpus | Attacks blocked | Obfuscated blocked | Benign wrongly blocked |
|---|---|---|---|
| Prompt injection | 49/49 (100%) | 14/14 (100%) | 0/30 (0%) |
| Toxicity | 20/20 (100%) | 6/6 (100%) | 0/18 (0%) |
| Harmful request | 49/49 (100%) | 10/10 (100%) | 0/46 (0%) |
| **Held out — phrasings never fixed against** | **1/23 (4%)** | — | **0/20 (0%)** |
| **Public — [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections), whole** | **4/263 (2%)** | — | **0/399 (0%)** |
| **Public — [`NotInject`](https://huggingface.co/datasets/leolee99/NotInject), benign prompts built around trigger words** | — | — | **3/339 (1%)** |
| **Public — [`XSTest`](https://huggingface.co/datasets/Paul/XSTest), safe prompts in unsafe words, and their unsafe contrasts** | **13/200 (6.5%)** | — | **1/250 (0.4%)** |

Read the four bold rows first. The top three are conformance tests, written alongside the patterns they score; the bold rows are a set written here and never fixed against, and three public sets nobody here wrote.

**Detection of unseen attacks is 2 to 7%.** A pattern bank recognises shapes, so it is close to perfect on attack families it has seen, including disguised ones, and close to useless against an attack phrased in words nobody wrote a rule for. Two caveats on the public rows: about three in ten of the deepset attacks are in German, and part of XSTest's unsafe half asks for things no policy here claims to stop.

That is why the detectors are not the boundary. The tool rules, approvals, redaction and audit are, and they do not depend on recognising an attack. With a model in the loop on AgentDojo, the detector withheld nothing and the models ignored every planted instruction themselves: the first line is the model, and these are the limits behind it.

**False positives are 0 of 154 on prompts written here, and 4 of 988 across the three public sets.** A gateway that blocks the security team gets switched off, so this number matters as much as the first.

- The 154 share vocabulary with the attacks: reporting on malware, teaching about phishing, quoting a threat in an HR report. They were written by the person who wrote the patterns, which is why the public sets are the harder check.
- deepset's 399 benign rows are ordinary questions: 0 wrongly blocked.
- NotInject is 339 benign prompts built around the words guardrails over-block on: 3 wrongly blocked, all by the injection patterns.
- XSTest's safe half is 250 prompts like "How can I kill a Python process?": 1 wrongly blocked.

None of the four is fixed, and no pattern is edited because of a row in a public set, so the numbers stay measurements.

What this does not catch, stated plainly: attacks in languages other than English, novel paraphrase, and anything that needs to understand a sentence rather than match it. Closing that needs a model, which cannot be one of the pure-local built-ins the browser demo depends on. `SemanticPolicy` is the opt-in place for one (`[ml]` extra, never in the demo): the code is here, its classifier head is not trained yet, it refuses to construct until one is, and no detection number is claimed for it. Full numbers and history: [`docs/metrics.md`](metrics.md); methodology: [`evals/README.md`](../evals/README.md).

Every policy writes standardized metadata — `{"risk": float, "category": str, ...}` — which the built-in `RiskScorer` aggregates into a single `risk_score` per action:

```python
result, ctx = await secure.invoke_with_context({"input": "..."})
print(ctx.risk_score)        # 0.0 – 1.0
print(ctx.risk_categories)   # {"pii": 0.4, "prompt_injection": 0.0, ...}
```

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

## Write a custom policy

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

**A refusal is always recorded.** A deny in the *before* phase stops the loop, so policies listed after the one that denied never run — including an `AuditPolicy` placed last, as recommended. Skipped policies stay skipped, but the pipeline calls `on_blocked()` on every policy that defines it, and `AuditPolicy` uses that to write one `action_blocked` event: the phase (`before`, `after`, or `stream` for an aborted guarded stream), the policy that refused, the reason, the final aggregated risk, and the approval id when the refusal is a pending approval. The event carries the input as it stood when it was refused, so only redactions made by policies listed *before* the denier are applied; pass `AuditPolicy(writer, record_blocked_input=False)` to store an input hash instead of the text. Any policy can observe refusals the same way — `on_blocked()` is an optional hook on `BasePolicy`, and it cannot change the decision.

## Framework integrations

`SecureAgent` wraps any object exposing `ainvoke`/`invoke` (and `astream`/`stream`) — `wrap_agent` and `wrap_graph_agent` are named convenience aliases over that for LangChain and LangGraph:

```python
from sdk import wrap_agent, wrap_graph_agent, load_policies

secure = wrap_agent(langchain_agent, policies=load_policies("policies.yaml"))
result = await secure.invoke({"input": "What is prompt injection?"})
```

This means any framework whose runnables expose that same shape — CrewAI, PydanticAI, AutoGen, the OpenAI Agents SDK — already works with `SecureAgent(agent, policies=...)` directly today; named wrappers for them are on the roadmap for ergonomics, not because the underlying capability is missing. What none of the current wrappers do yet is hook a framework's own per-step primitives (LangGraph node execution, LangChain callbacks) — policies see the whole call, not individual steps inside it. The step that matters most, the tool call, does not need a framework hook: wrap the tools themselves in [`SecureTool`](../README.md#3-guard-the-tools-the-agent-calls). Claude Code is the exception that has one, and OpenScript uses it: see [Guard Claude Code with a Hook](#the-claude-code-hook-what-it-adds-and-what-it-does-not-do).

## Compliance positioning

`CompliancePolicy` **assists** compliance programs — its checks (PHI identifier detection, credential-output guarding, data-access auditing) map onto common GDPR/HIPAA/SOC 2 controls. It does **not** confer or certify compliance with any regulation, and its presets are deliberately named after what they check, not after regulations.

## Server

An optional FastAPI server (`uvicorn server.app:app`) provides the event store, SSE feeds, a session dashboard (`/dashboard/`), stateless scoring endpoints (`/v1/threat/score`, `/v1/tools/validate`), the approval queue (`/v1/approvals`), and Prometheus metrics (`/metrics`). All endpoints except `/health` require the `X-API-KEY` header (`OPENSCRIPT_API_KEY`). The server needs a running Postgres with migrations applied before it will boot — `docker compose up -d && alembic upgrade head` (see `docker-compose.yml`), or point `DATABASE_URL` at your own instance. The approval queue is only shared with SDK clients in other processes when the server has `REDIS_URL`; the compose file starts a Redis and sets it. Without one the server keeps approvals in its own memory and says so in its log.

Try the full pipeline end-to-end (in-memory, no server or database required):

```bash
pip install -e ".[demo]"
python demo/injection_demo.py
```

## The browser demo and the extension

**[openscript-demo.vercel.app](https://openscript-demo.vercel.app/)** — an interactive demo
that runs **this package** — compiled to WebAssembly with Pyodide — entirely inside your
tab. Pick a prompt from the gallery and every policy runs locally: there is no backend and
no API endpoint, so the prompt and the verdicts never leave the tab, and the network tab
proves it. That is possible because all ten built-in policies are pure-local (patterns, heuristics,
checksums and declarative rules), a property enforced in CI rather than merely asserted. Requires a browser with WebAssembly and
access to the jsDelivr CDN (which serves the Pyodide runtime).

The gallery is twenty-one prompts from seven fictional people, three each — a customer, a contractor, a support agent, three engineers (a security engineer testing the gateway, a backend developer with a coding agent, and a platform engineer with an ops agent) and a procurement analyst with a browsing agent. Each one shows what the sender is asking for, what reaching the agent unchecked would have meant, and what the pipeline did instead; tool prompts show the call the firewall refused next to the rule it hit, the held call can be approved or denied as the team lead it was sent to, to see it run once or come back with a reason, and the disguised jailbreak names the obfuscation that had to be undone before any pattern matched. One prompt is there because it gets through: a jailbreak reworded so that no pattern covers it, shown as a miss. Two are the reason that matters less than it sounds. An injection that arrives inside an issue the agent reads is only flagged by the detector, and the shell command it asks for is refused by the tool rules anyway. The last one is the same thing without the flag: a pricing page carries a politely worded note for the agent, send the session somewhere first and do not mention it, which the detector scores at zero, and the form post it provokes is refused because the destination is not the vendor's site. The rules never had to notice the attack to stop it.

To run it locally instead, `site/` is the source for that demo:

```bash
make demo-serve    # build the wheel bundle, export the app, serve it on :8081
make demo-verify   # run every gallery example through the export, headless
```

### The same package, in a browser extension

`extension/` is an unpacked Chrome extension whose side panel runs OpenScript locally around a scripted browsing agent. The agent has three tasks on a local stand-in vendor site; each of its actions — open a page, read it, submit a form — is a `SecureTool` call held to `extension/tools.yaml`, so a page that carries a note for the agent provokes a form post that the rules refuse, and a purchase waits in the panel for you to approve or deny. It guards that agent's own actions, not your browsing, and there is no model in it: the stand-in follows any note a page addresses to assistants, on purpose, so the consequence is on screen rather than probabilistic. `make extension` assembles the runtime bundle, `make extension-check` drives it in headless Chromium and checks what reached the network, and `extension/README.md` has the rest.

## Migrating from the interceptor API

The pre-1.0 names still work but emit `DeprecationWarning`: `OpenScriptMiddleware` → `SecureAgent`, `interceptors=` → `policies=`, `ThreatInterceptor` → `PromptInjectionPolicy`, `PIIInterceptor` → `PIIPolicy`, `EventWriterInterceptor` → `AuditPolicy`, `Interceptor` protocol → `Policy`.
