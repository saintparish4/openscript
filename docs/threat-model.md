# Threat model and complete mediation

Written 2026-11-03, after [reading the raw material](raw-material.md) and
before any fix. This page states what is claimed and lists every path to an
irreversible effect. It marks each path mediated or not, and fixes nothing.
It stays as it was written. What became of each row is in
[the red-team report](red-team.md).

## The attacker, the claim, and what is trusted

- **The attacker is the model.** Assume it is fully compromised, from the
  first turn. It holds every tool it was given, including Bash where it has
  Bash. It has read the policy config, the source lists, the known
  destinations and this page. It acts as fast and as often as it likes.
- **The claim:** no irreversible effect happens without a person's
  single-use approval of that exact call.
- **Trusted:** the host code that builds the tools and policies; the config
  as the host wrote it before the session; the approval store; the person
  who answers; the operating system boundary, where there is one.
- **Out of scope:** an effect made with text alone, such as a reply that
  talks a person into acting. AgentDojo's travel injection task 6 is one, and
  no tool policy can touch it.

**Mediated** below means every call on the path passes a check that the
attacker cannot skip, and an irreversible call waits for the approval.

## The SDK: SecureTool in the agent's process

| # | Path from the agent to the effect | Mediated? |
|---|---|---|
| S1 | The agent calls a `SecureTool` | **Yes.** Policies run before the tool, and the tool runs on the arguments that were checked |
| S2 | The agent calls the function underneath | **No, if the agent can run code.** The raw function sits on the wrapper as `__wrapped__`. An agent with a Python or shell tool can reach it, or import the client the function uses |
| S3 | Another tool reaches the same effect: a shell, an HTTP fetch, a generic API tool | **No,** unless that tool is wrapped too and listed as a sink. The session rule holds only what is listed. `default_deny` covers only wrapped tools |
| S4 | The sink service is called by anything else holding its credentials | **No.** The bank or mail service never sees the approval. It cannot tell a held call from one that went round the wrapper |
| S5 | An approval granted in one session is redeemed in another | **Partly.** An approval is bound to the tool and its exact arguments, single-use, for an hour. It is not bound to the session or the agent, so a yes given elsewhere redeems the identical call here |
| S6 | A tainted session continues in a second worker process | **No.** The session's memory lives in one process unless a `store` is passed. The second worker sees an untainted session |
| S7 | The approval store is unreachable | **Not yet established.** It is tested in part 4 |

## The Claude Code hook: openscript-hook

| # | Path | Mediated? |
|---|---|---|
| H1 | An MCP tool, WebFetch or WebSearch, matched by the PreToolUse hook | **Yes,** while the hook answers inside its timeout. It denies or asks, and never allows |
| H2 | Bash, Write, Edit or NotebookEdit | **No.** The example matcher does not name them. `curl`, `git push --force` and `rm -rf` see only Claude Code's own permissions |
| H3 | The agent changes the hook's own inputs | **No.** The agent runs as the user who owns these files. Write, Edit or Bash can rewrite them: `.claude/openscript.yaml`, `.claude/settings.json`, the session files, the config cache and the audit log under `~/.local/state/openscript`. Bash can also run `openscript-hook reset` |
| H4 | The hook times out | **No.** Claude Code goes ahead with the call. That is its rule, not the hook's |
| H5 | A person answers Claude Code's prompt | **Yes, per call.** This was seen in auto mode in 2.1.292. It has not been checked in `bypassPermissions` mode |
| H6 | A subagent's tool calls | **Not verified.** It is not known whether they carry the parent's session id, and so whether the parent's taint holds them |

## The Java client: policies on the server

| # | Path | Mediated? |
|---|---|---|
| J1 | The agent calls a `client.secureTool` | **Yes.** The server's verdict comes before the tool runs. An unreachable server or a policy that raised blocks the call |
| J2 | The raw lambda, or a tool the host did not wrap | **No,** as S2 and S3 |
| J3 | The sink service is called by anything else holding its credentials | **No,** as S4 |
| J4 | Two server workers | **No.** The session rule's memory is in the server process |
| J5 | Approvals decided through `/v1/approvals` | **Yes,** with Redis set. Without it the store is in the server's memory, which J1 shares |

## What this says

1. **Every guarantee ends at the wrapper.** S4 and J3 are the same hole. The
   effect side trusts whoever holds the credentials. Part 3 moves the check
   there: an irreversible call carries a token the agent cannot mint.
2. **Where the agent can run code, nothing here is a boundary.** Those paths
   are S2, S3, H2 and H3. That is a statement about deployment: give the
   agent no shell, or put the shell's network and files behind a boundary
   the agent does not own. Part 4 tests what the hook does about it.
3. **State is part of the boundary.** S5, S6, J4 and H3 are about where the
   memory and the approvals live. Part 4 injects their failures.
