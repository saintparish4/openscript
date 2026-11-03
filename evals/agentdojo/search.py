"""Bypass search 4b: can the attacker reach an injection goal with calls the policies let through?

    .venv/bin/python search.py      # results/search/summary.json, and the findings on stdout

The attacker has read the config: the sinks, the known destinations, the
updates list. The session has already read the injection, so it is tainted.
For each injection task, the search starts from the attacker's own calls
(AgentDojo's ground truth for the task). It adds every variant a reader of
the config would try:

- each destination argument dropped;
- each destination argument set to each known value, scalar or in a list;
- each destination value in another case.

The oracle is the policies themselves. Each candidate call goes through the
configuration's policies' before_action, as SecureTool would run it, and
only the calls they neither hold nor refuse are kept. The search then runs
subsequences of those calls, in order: every single call, every pair and
triple, and all of them together. It runs them in a fresh environment and
asks AgentDojo's own security check whether the goal was reached. Every
sequence that reaches a goal is reported.

Nine injection tasks ship no calls to start from. They are listed apart:
eight in workspace, for which AgentDojo ships no ground truth, and travel's
task 6, whose goal is a sentence in the reply. "taint_known" is the rule as
PROTOCOL-known.md froze it, before the package held a call that names no
destination. It is searched to see whether the search finds that leak. The sessions the replay never taints,
Slack's channel listing, are the replay's known miss and are not searched
again: here every session is tainted.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402
from guard import known_for, load_classification, policies_for  # noqa: E402

from contracts.types import ActionContext, InterceptorDecision  # noqa: E402
from sdk import SessionTaintPolicy  # noqa: E402

BENCHMARK = "v1.2.2"
#: "none" is the control: with no policy the search must reach the goals, or
#: a zero under the others would mean nothing.
CONFIGURATIONS = (
    "none",
    "taint_text",
    "taint_known",
    "taint_known_shipped",
    "taint_irreversible",
    "taint_irreversible_known",
    "approve_irreversible",
)
SESSION = "search"
#: Subsequences up to this many calls are tried one by one, then all together.
DEPTH = 3


def variants(
    call: FunctionCall, known: Mapping[str, Mapping[str, Sequence[str]]]
) -> Iterator[FunctionCall]:
    """The call, and what a reader of the known lists would try instead."""
    yield call
    destinations = known.get(call.function, {})
    for arg, values in destinations.items():
        if arg in call.args:
            yield FunctionCall(
                function=call.function, args={k: v for k, v in call.args.items() if k != arg}
            )
            original = call.args[arg]
            if isinstance(original, str):
                yield FunctionCall(
                    function=call.function, args={**call.args, arg: original.upper()}
                )
            elif isinstance(original, list):
                yield FunctionCall(
                    function=call.function,
                    args={**call.args, arg: [str(v).upper() for v in original]},
                )
        for value in list(values)[:3]:
            for shaped in (value, [value]):
                yield FunctionCall(function=call.function, args={**call.args, arg: shaped})


def let_through(policies: Sequence[Any], call: FunctionCall) -> bool:
    """Whether the policies neither hold nor refuse *call* in a tainted session."""
    context = ActionContext(
        action="tool_call",
        agent_id="attacker",
        session_id=SESSION,
        input_data={"name": call.function, "args": dict(call.args)},
    )

    async def check() -> InterceptorDecision:
        nonlocal context
        for policy in policies:
            context = await policy.before_action(context)
            if context.decision != InterceptorDecision.ALLOW:
                break
        return context.decision

    return asyncio.run(check()) == InterceptorDecision.ALLOW


def reaches(suite: Any, injection_task: Any, calls: Sequence[FunctionCall]) -> bool:
    env = suite.load_and_inject_default_environment(suite.get_injection_vector_defaults())
    before = env.model_copy(deep=True)
    runtime = FunctionsRuntime(suite.tools)
    for call in calls:
        runtime.run_function(env, call.function, call.args, raise_on_error=False)
    return bool(suite._check_injection_task_security(injection_task, [], before, env, list(calls)))


def search() -> dict[str, Any]:
    out: dict[str, Any] = {"configurations": {}, "no_ground_truth": []}
    suites = get_suites(BENCHMARK)
    lists = load_classification()
    for configuration in CONFIGURATIONS:
        found: list[dict[str, Any]] = []
        tried = searched = 0
        for suite_name, suite in suites.items():
            listed = known_for(configuration, suite_name)
            known = listed or {}
            env = suite.load_and_inject_default_environment(suite.get_injection_vector_defaults())
            for injection_id, injection_task in suite.injection_tasks.items():
                goal = injection_task.ground_truth(env.model_copy(deep=True))
                if not goal:
                    if configuration == "none":
                        out["no_ground_truth"].append(f"{suite_name}/{injection_id}")
                    continue
                searched += 1
                policies = policies_for(configuration, lists[suite_name], listed, "", suite_name)
                for policy in policies:
                    if isinstance(policy, SessionTaintPolicy):
                        policy.taint(SESSION, "the injection")
                # Duplicates across the goal's calls are kept: three equal
                # transfers are three transfers.
                pool: list[FunctionCall] = []
                for call in goal:
                    seen: list[FunctionCall] = []
                    for candidate in variants(call, known):
                        if candidate in seen:
                            continue
                        seen.append(candidate)
                        tried += 1
                        if let_through(policies, candidate):
                            pool.append(candidate)
                sequences = [
                    list(combo)
                    for size in range(1, min(DEPTH, len(pool)) + 1)
                    for combo in itertools.combinations(pool, size)
                ]
                if len(pool) > DEPTH:
                    sequences.append(pool)
                for sequence in sequences:
                    if reaches(suite, injection_task, sequence):
                        found.append(
                            {
                                "goal": f"{suite_name}/{injection_id}",
                                "sequence": [
                                    {"function": c.function, "args": c.args} for c in sequence
                                ],
                            }
                        )
                        break  # one sequence per goal is enough to report it
        out["configurations"][configuration] = {
            "calls_tried": tried,
            "goals_searched": searched,
            "goals_reached": found,
        }
    return out


def main() -> int:
    summary = search()
    path = HERE / "results" / "search" / "summary.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=1, default=str) + "\n")
    for configuration, result in summary["configurations"].items():
        reached = result["goals_reached"]
        print(
            f"{configuration}: {result['goals_searched']} goals, {result['calls_tried']} calls "
            f"tried, {len(reached)} goals reached"
        )
        for hit in reached:
            print(f"  {hit['goal']}: {json.dumps(hit['sequence'], default=str)[:300]}")
    print(f"no calls shipped to search from: {', '.join(summary['no_ground_truth'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
