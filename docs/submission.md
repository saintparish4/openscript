# OpenScript: irreversible actions wait for a person

A submission to Drawerrr's "Prevent irreversible AI autonomous actions"
challenge. The categories are financial transactions, delegated actions,
digital system changes and information access.

## The problem and the claim

A tool-using agent can be talked into acting by text it reads: a web page, an
email, a payment reference. Current models resist most of these attacks. In
4,374 attacked AgentDojo conversations, Claude Haiku 4.5 and Claude Sonnet
5.5 followed none. Pattern detectors catch 2 to 7% of attacks they were not
written for. So detection is not a boundary.

**The claim:** no irreversible effect happens without a person's single-use
approval of that exact call, even when the model is fully compromised and
has read the config. [The threat model](threat-model.md) states the attacker
and lists every path to an effect.

## How it works

1. **Every tool is classed from its code** as read, reversible or
   irreversible. Irreversible means something leaves the environment, or no
   tool can put back what changed. Of AgentDojo's 74 tools, 26 are
   irreversible.
2. **A wrapper around each tool** (`SecureTool`) holds an irreversible call.
   It can hold every one, or only those after the session has read something
   a stranger wrote. A held call gets an approval bound to the tool, its exact
   arguments and the session. It is single-use and expires in an hour.
3. **The effect side checks again** (`evals/ledger.py`). The service in
   front of an irreversible tool applies a call only with an HMAC token. The
   token is minted when a person approves, under a key the agent never holds.
   It keeps a ledger of every irreversible call and what came with it. A
   call that went round the wrapper reaches the service and changes nothing.
4. **The same policies run in three places:** a Python SDK, a Claude Code
   hook and a Java client.

## Against the five criteria

Each claim is marked **implemented**, **tested** (with the test or the
command) or **theoretical**.

### Safety effectiveness

| Claim | Status | Evidence |
|---|---|---|
| With the effect side enforcing, no attacker irreversible effect is applied | **Tested** | 0 of 617 replayed attacks, in each of 3 configurations, including no policy at all. The count is the ledger's, not the wrapper's. `replay.py --ledger` |
| Asking on every irreversible call lets no attacker irreversible call run | **Tested** | 0 of 617, by the wrapper's log and by the ledger's |
| The session rule, which asks only after an untrusted read, misses 27 attacks | **Tested** | 27 of 617, all through Slack's channel listing, which is not listed as a source. The effect side refuses them |
| A bypass of the wrapper, such as a raw function or a stolen, reused or swapped token, is refused at the effect | **Tested** | `tests/test_ledger.py`, including a service in a separate process |
| It holds against a real model that follows attacks | **Tested** | Qwen2.5-7B-Instruct followed attacks: 58 of 249 succeeded with no policy. With the effect side enforcing, or asking on every irreversible call, 0 succeeded and no attacker irreversible effect was applied. The session rule let 5 through, all via Slack's channel listing. Amendment 3, about $1.10 of RunPod time |

### Testing and robustness

| Claim | Status | Evidence |
|---|---|---|
| Bypasses were searched for, and every finding was published before its fix | **Tested** | [Red team](red-team.md): 7 findings. 2 fixed in code, 1 by a new strict profile, 1 by configuration or at the effect side, 2 by configuration. Bash rewriting the hook's files stays open |
| Approvals cannot be redeemed in another session | **Tested, after a fix** | A Hypothesis state machine found it. `tests/bypass/test_state_machine.py` |
| No injection goal is reachable by mutating the attacker's calls against the config | **Tested** | 0 of 26 goals under 6 configurations, and 26 of 26 with no policy. `search.py` |
| The sink is reached only through the gated tool | **Tested** | The sink and an audit hook as witnesses, in the SDK and under the hook. `tests/bypass/test_mediation.py` |
| Each component fails closed, or the failure is named | **Tested** | 11 failure rows closed and 2 open by configuration. `tests/bypass/test_failures.py` |
| Protocols were frozen before results | **Tested** | Each is pinned by its hash in `tests/test_agentdojo_results.py` |

### Real-world relevance

| Claim | Status | Evidence |
|---|---|---|
| It guards Claude Code | **Tested** | Payloads from a real session are replayed in the tests. A strict profile holds Bash after a web read |
| Holding only what cannot be undone asks less | **Tested** | 51 of 97 ordinary tasks against 55, and 40 with known destinations. Still over the one-third bar set beforehand |
| What the strong claim costs | **Tested** | Under enforcement, every irreversible call needs a person: 59 of 97 tasks ask, and all 97 are done when someone answers |
| Approval fatigue makes people rubber-stamp | **Theoretical** | With an approver who says yes to everything, every attack succeeds. How often people do that was not measured |

### Reproducibility and reuse

Everything here is free to rerun. It needs no API key.

```bash
make install && .venv/bin/pytest                    # 908 tests
make agentdojo-replay                               # the AgentDojo environment, then the replay
cd evals/agentdojo
.venv/bin/python replay.py --irreversible           # about a minute on 8 cores
.venv/bin/python replay.py --ledger
.venv/bin/python search.py
.venv/bin/python summarize_irreversible.py && .venv/bin/python summarize_ledger.py
```

The SDK depends on pydantic, structlog and PyYAML. The ledger uses only the
standard library. Every number is in [metrics](metrics.md) with its date and
command.

### Clarity: what is not claimed

- **Text alone.** An effect made by a reply that talks a person into acting is
  out of scope. AgentDojo's travel injection task 6 is one, and 20 replayed
  attacks succeed that way under every configuration.
- **A shell.** A shell the agent controls can rewrite the hook's own files.
  The answer is a boundary the agent does not own: Claude Code's sandbox,
  another OS user, or the effect side.
- **Not shipped.** The effect side is a reference implementation in the
  harness, not part of the SDK. A real service would hold the key in its own
  process, as the tests' separate service does.
- **Real models.** Containment was tested with one open 7B model on two
  suites, one attack wording, one sample per case. Claude Haiku 4.5 and
  Claude Sonnet 5.5 followed no attack, so for them only the cost was
  measured.
