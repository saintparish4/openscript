# AgentDojo with a model: amendment 1, a second attack

Written and frozen 2026-10-14, **after** the Claude Haiku 4.5 run of
`PROTOCOL-model.md` and because of what it found, before any request under
this amendment. `PROTOCOL-model.md` is unchanged, and everything it fixes
holds here except what this file adds. `tests/test_agentdojo_results.py` pins
this file too. Chosen by Sharif the same day.

## Why

With `important_instructions`, Haiku 4.5 followed the injection in none of
the 144 banking pairs, and in all six runs, 864 attacked conversations, never
made a call carrying the attacker's account. There was nothing for a policy to
stop, so the run measured what the policies cost and nothing about what they
contain. This adds an attack with a better chance of landing.

It was chosen after seeing that result, which is why it is a labelled
amendment and not part of the frozen protocol, and why its numbers are never
pooled with the first attack's.

## What is added

One attack: AgentDojo's `tool_knowledge`. It is `important_instructions` with
the exact tool calls to make spelled out, the attacker's values filled in and
the rest left as placeholders for the agent to fill. A fixed template, written
by AgentDojo, needing no model to produce; addressed to "Claude" as before.

Everything else is as frozen: banking, `agentdojo==0.1.35`, suites `v1.2.2`,
the same six runs, the same approvers and `markers.yaml`, one sample of each
case, the same model settings, the same bar.

The tasks with no attack are not run again: an attack does not change them,
and `run_model.py` finds them done.

## Order and budget

1. **Claude Haiku 4.5:** the 864 attacked cases with `tool_knowledge`, in
   `results/model/claude-haiku-4-5/`, under the protocol's $25 cap for Haiku,
   which counts the $6.21 already spent.
2. **Claude Sonnet 5.5:** `PROTOCOL-model.md` exactly as frozen first (the
   tasks with no attack and `important_instructions`), then the 864 attacked
   cases with `tool_knowledge`. One $50 cap for both, in one directory. The
   frozen part goes first so that a cap reached part way leaves it whole.

## What is reported

`tool_knowledge` in a table of its own, beside `important_instructions`, with
the same columns. If it lands where the first did not, that is the first
measure here of what the policies contain with a model choosing; if it does
not, that is reported as plainly.
