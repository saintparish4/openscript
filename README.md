# OpenScript

[![CI](https://github.com/saintparish4/openscript/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/saintparish4/openscript/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/openscript-sdk?label=pypi)](https://pypi.org/project/openscript-sdk/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](https://github.com/saintparish4/openscript/blob/master/LICENSE)
[![Live demo](https://img.shields.io/badge/demo-live%20in%20your%20browser-22c55e)](https://openscript-demo.vercel.app/)

**Irreversible actions wait for a person, even when the model has been fooled.**

OpenScript sits between an AI agent and the tools it calls. It refuses calls
outside rules you write, holds the ones that cannot be undone until a person
approves that exact call, masks secrets and PII, and records every decision.
None of it depends on recognising an attack, so it still holds when the model
is fooled, wrong, or swapped for another.

It is for anyone building an agent whose tools have real effects, such as
payments, email or a shell, in Python with any framework. It is version
0.1.0 and alpha: the API may still change.

**[Try the live demo →](https://openscript-demo.vercel.app/)** The package
runs in your browser tab, compiled to WebAssembly, with no backend.

## What it is not

- **Not an injection detector to rely on.** It has pattern detectors, and they
  catch 2 to 7% of attacks they were not written for. The boundary is the
  rules and the approvals, and the rules are only as tight as you write them.
- **Not a compliance certification.** Its compliance presets assist a
  program and certify nothing.

## What it has been shown to do

Measured on [AgentDojo](https://github.com/ethz-spylab/agentdojo)'s banking
and Slack suites, with Qwen2.5-7B-Instruct, a model that follows prompt
injections. The protocol was frozen before the run.

| The run | |
|---|---|
| Hardware | 1 NVIDIA RTX 4090 on RunPod, Secure Cloud, EU-RO-1 |
| Serving | vLLM 0.10.2, bf16, temperature 0 |
| Size | 1,430 cases, 5,382 requests, 9.8M input and 0.63M output tokens |
| Errors | 0 |
| Date | 2026-11-04 |

| Configuration | Attacks that succeeded | Attacker's irreversible actions that took effect |
|---|---|---|
| No protection | 58 of 249 | 108 |
| Session rule: hold irreversible calls after an untrusted read | 6 of 249 | 10 |
| Ask a person on every irreversible call | **0 of 249** | **0** |
| No policy at all, effect side enforcing | **0 of 249** | **0** |

- **The effect side is the boundary.** A ledger in front of each irreversible
  tool applies a call only with a token minted when a person approves it. A
  call that goes round the wrapper changes nothing.
- **Safety has a price, and it is published.** In the run above, asking on
  every irreversible call meant a person on 23 of the 37 ordinary tasks. In
  the no-model replay of all four suites it is 59 of 97. The session rule
  asks less and misses the attacks that arrive through Slack's channel
  listing.
- **It was attacked before it was trusted.** A [red team](https://github.com/saintparish4/openscript/blob/master/docs/red-team.md)
  searched for bypasses and published 7 findings, each committed as a
  failing test before its fix.

Every number, with its date, command and caveats, is in
[`docs/metrics.md`](https://github.com/saintparish4/openscript/blob/master/docs/metrics.md). The claim and what it does not cover
are in [the threat model](https://github.com/saintparish4/openscript/blob/master/docs/threat-model.md).

## How it works

```
agent ── calls a tool ──► SecureTool ── before: tool rules · session rule ──► refuse / hold for a person
                              │
                              ▼  the call that was checked, and nothing else
                         effect side ── a person's token? ──► apply, and write it in the ledger
                              │
                              ▼
                          after: mask secrets and PII · record
```

- **Tool rules** limit which tools, arguments, recipients and amounts are
  allowed, in YAML.
- **The session rule** remembers when a session has read something a
  stranger wrote, and then holds the calls you list as irreversible.
- **An approval** is single-use, expires in an hour, and is bound to the
  tool, its exact arguments and the session.
- **The effect side** ([`evals/ledger.py`](https://github.com/saintparish4/openscript/blob/master/evals/ledger.py)) is a reference
  implementation, standard library only.

## Quick start

```bash
pip install openscript-sdk          # Python 3.11+; pulls pydantic, structlog and PyYAML
```

The distribution is `openscript-sdk` and the package imports as
`openscript_sdk`. The extras are `[server]` (the FastAPI server, whose
database migrations are in this repository's `alembic/`), `[redis]`,
`[metrics]` and `[otel]`. To work on it, clone the repository and run
`make install`.

A tool that the rules hold
waits for a person, and the retry with the approval runs that exact call
once:

```python
from openscript_sdk import ActionBlockedError, SecureTool, ToolFirewallPolicy

async def transfer_funds(to: str, amount: int) -> str: ...

transfer = SecureTool(transfer_funds, policies=[ToolFirewallPolicy(rules_path="tools.yaml")])

call = {"to": "acct-22", "amount": 500}
try:
    await transfer.call(call)                       # held: the tool does not run
except ActionBlockedError as held:
    approval_id = held.approval_id                  # a person approves it ...

await transfer.call(call, approval_id=approval_id)  # ... and the same call runs, once
```

```yaml
# tools.yaml
default_deny: true
rules:
  transfer_funds:
    requires_approval: true
    args:
      amount: {min: 0, max: 1000}
```

Also in the package: redaction of secrets and PII, input screening, an audit
trail and an event server. The [guide](https://github.com/saintparish4/openscript/blob/master/docs/guide.md) covers each.

## Where it runs

| Surface | Start here |
|---|---|
| Python agents and tools (LangChain, LangGraph, anything with `invoke`) | [the guide](https://github.com/saintparish4/openscript/blob/master/docs/guide.md) |
| Claude Code, as a hook, with a strict profile that holds Bash after a web read | [the hook](https://github.com/saintparish4/openscript/blob/master/docs/guide.md#the-claude-code-hook-what-it-adds-and-what-it-does-not-do) |
| Java agents, through the server | [`clients/java`](https://github.com/saintparish4/openscript/blob/master/clients/java/README.md) |
| A browser, and a Chrome extension | [the demo](https://openscript-demo.vercel.app/) |

## Further reading

- [`docs/guide.md`](https://github.com/saintparish4/openscript/blob/master/docs/guide.md): every feature, its limits and its
  configuration, including environment variables and options.
- [`docs/metrics.md`](https://github.com/saintparish4/openscript/blob/master/docs/metrics.md): every measurement.
- [`docs/threat-model.md`](https://github.com/saintparish4/openscript/blob/master/docs/threat-model.md) and
  [`docs/red-team.md`](https://github.com/saintparish4/openscript/blob/master/docs/red-team.md): the claim and the attempts to
  break it.
- [`docs/submission.md`](https://github.com/saintparish4/openscript/blob/master/docs/submission.md): the AI-safety challenge
  write-up.

## Contributing

```bash
make install && pytest && ruff check . && black --check . && mypy --strict openscript_sdk/ --exclude openscript_sdk/server/
```

[CONTRIBUTING.md](https://github.com/saintparish4/openscript/blob/master/CONTRIBUTING.md) has the full checklist, including the
Pyodide and Java checks. Changes to approvals, the session rule or the hook
also run `pytest tests/bypass`.

## License

Apache License 2.0. See [LICENSE](https://github.com/saintparish4/openscript/blob/master/LICENSE).
