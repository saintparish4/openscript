# AgentDojo, replayed through the tool policies

[AgentDojo](https://github.com/ethz-spylab/agentdojo) is a benchmark of agent
tasks with prompt injections planted in what the agent reads. This directory
runs it against OpenScript's tool-side policies, **with no model in the loop**:
it replays the tool calls AgentDojo itself ships as each task's solution and as
each attack's method, through the same `SecureTool` wrappers an agent's tools
would have, and lets AgentDojo's checkers score the result.

The numbers are in [`docs/metrics.md`](../../docs/metrics.md#tool-policies-on-agentdojo-a-replay-with-no-model).
[`PROTOCOL.md`](PROTOCOL.md) says what was to be measured and what bar the
session rule was held to. It and [`classification.yaml`](classification.yaml)
were committed before any defended configuration ran, and
`tests/test_agentdojo_results.py` fails if either is edited.

## What it found

- **The session rule contains what it says it contains.** With an approver who
  refuses the attacker's calls, 570 of 617 attacks fail.
- **It asks nearly as often as asking every time.** 55 of 97 ordinary tasks
  needed an approval, against 61 of 97 when every state-changing call asks.
  The bar, set beforehand, was a third.
- **The list of sources missed one.** A Slack channel's *name* is
  attacker-controlled, and a tool that lists channels was classified as a
  listing. 27 attacks got through that way.
- **The detector stops one wording in five,** and when it does it withholds the
  result the task needed.

## Run it

AgentDojo has an environment of its own. It pulls in the anthropic, openai,
cohere, google-genai and langchain SDKs, and nothing under `sdk/` may import
any of them.

```bash
make agentdojo-replay     # builds the environment with uv, replays, summarises (about 3 minutes on 8 cores)
make agentdojo-summary    # the tables again, from the committed rows; needs no AgentDojo
```

Or by hand, from this directory:

```bash
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python -r requirements.txt -e ../..
.venv/bin/python replay.py --check     # the undefended baseline only
.venv/bin/python replay.py             # everything, into results/
.venv/bin/python summarize.py
```

## What is here

| File | What |
|---|---|
| `PROTOCOL.md` | The design, the configurations, the bar. Frozen |
| `classification.yaml` | Which of the 74 tools read untrusted content, and which change state. Frozen |
| `guard.py` | `GuardedRuntime`: AgentDojo's tool runtime with the policies in the call path |
| `replay.py` | The replay. Writes one row per case |
| `summarize.py` | The tables, from those rows |
| `PROTOCOL-model.md` | The run with a model: models, runs, approvers, budget. Frozen |
| `markers.yaml` | The attacker's values, which the `careful` approver refuses in a model run. Frozen |
| `PROTOCOL-model-amendment-1.md` | A second attack, `tool_knowledge`, added after the Haiku run. Frozen |
| `model.py` | `Claude`, a metered model element, and `ScriptedAgent`, the replay's agent as one |
| `run_model.py` | The run with a model, its budget, and its tables |
| `results/benign.csv` | 97 tasks x 8 runs |
| `results/attack.csv` | 949 pairs x 9 runs, plus the detector against four more attack wordings |
| `results/summary.json` | What `docs/metrics.md` quotes |

`tests/test_agentdojo_guard.py` tests the runtime and
`tests/test_agentdojo_model.py` the model harness; both are skipped where
AgentDojo is not installed, which includes CI. Run them with
`.venv/bin/python -m pytest ../../tests/test_agentdojo_guard.py ../../tests/test_agentdojo_model.py`.

## Found while running it

Things the protocol did not anticipate. None of them changed the two frozen
files.

- **332 of the 949 pairs cannot show anything about a defence,** because the
  attack fails with no defence in place. For 320 of them AgentDojo ships no
  calls at all: eight workspace injection tasks (6 to 13) have an empty
  ground truth. In the other 12 the attack's calls do not achieve its goal
  alongside that particular user task. Every pair was replayed and is in
  `attack.csv`; the attack tables count the 617 where the undefended attack
  works, over 27 injection tasks.
- **One injection task needs no tool call.** Travel's task 6 only asks the
  agent to *say* something. It succeeds under every configuration, in all 20
  of its pairs, and no policy on tools can change that.
- **A compromised agent often breaks the user's own task.** Undefended, only
  260 of the 617 user tasks are still done after the attack's calls have run.
  That is why "tasks still done" is higher with a careful approver than with
  no defence at all.
- **Parsing the environment was most of the cost,** so it is parsed once per
  pair and copied, and tasks are replayed in worker processes. Both were
  checked to write the same bytes as the plain loop, on the banking and slack
  suites.

## With a model

This replay assumes the agent does everything an injection says, and makes
only the calls in the minimal solution. A model does neither. So against a
real model the attack numbers here are a ceiling and the approval counts are a
floor. `run_model.py` puts a model where the script was, in AgentDojo's own
pipeline, with the same `GuardedRuntime` in the call path.
[`PROTOCOL-model.md`](PROTOCOL-model.md) says what is run. It and
[`markers.yaml`](markers.yaml) were frozen before any model was sent a
request, and `tests/test_agentdojo_results.py` fails if either is edited.

```bash
.venv/bin/python run_model.py --model scripted                  # free: the harness against the replay
.venv/bin/python run_model.py --model haiku --budget 25         # prints the plan, sends nothing
.venv/bin/python run_model.py --model haiku --budget 25 --yes   # spends; needs ANTHROPIC_API_KEY (or the repo's .env)
.venv/bin/python run_model.py --summary results/model/claude-haiku-4-5
```

Or `make agentdojo-model MODEL=haiku BUDGET=25`, with `YES=1` to spend. `--attack tool_knowledge` runs the second attack
([amendment 1](PROTOCOL-model-amendment-1.md)); its cases go in the same directory and the
tasks with no attack are not run again.

- `--model scripted` drives the replay's compromised agent through the model
  harness. On every banking case it agrees with the replay's rows on attack
  outcome, approvals and compromise, and its request sizes give a floor on
  what a model run sends (about 8.4M input tokens for banking's 960 cases).
- `--budget` is in US dollars, for the output directory. No request is sent
  once it is reached. A run can be stopped and started again: finished cases
  are skipped and what was spent stays counted.
- Each run writes `cases.jsonl` (a row per case), `transcripts.jsonl` (the
  conversation) and `requests.jsonl` (the usage and cost of every request)
  under `results/model/<model>/`.

**Claude Haiku 4.5, banking, 2026-10-14** (`results/model/claude-haiku-4-5/`,
$6.21): it followed the injection in none of 144 pairs with no policy, and
never made a call carrying the attacker's account in any of the six runs. So
there was nothing to contain, and the policies only cost tasks. The session
rule asked on 4 of 16 ordinary tasks, because Haiku changed something on only
4: on most it stopped to ask the user instead. The tables are in
[`docs/metrics.md`](../../docs/metrics.md#tool-policies-on-agentdojo-claude-haiku-45-in-the-loop),
and `tests/test_agentdojo_results.py` holds them to the rows.
