"""Replay AgentDojo's own solutions and its own attacks through the tool policies.

No model. For every user task AgentDojo ships the calls that solve it, and for
every injection task the calls that carry it out. This makes those calls, in
the order a fully compromised agent would, through GuardedRuntime, and lets
AgentDojo's checkers say what came of it. PROTOCOL.md has the design and what
the numbers do and do not mean; it was committed before this file produced any.

    .venv/bin/python replay.py --check        # the undefended baseline only
    .venv/bin/python replay.py                # everything, into results/
    .venv/bin/python replay.py --known        # PROTOCOL-known.md's runs, into results/known/

Run from this directory, in the environment README.md describes.
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import sys
import warnings
from collections.abc import Iterator, Mapping
from concurrent.futures import ProcessPoolExecutor
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))  # the repository root, for sdk/ and evals/

logging.disable(logging.CRITICAL)  # the policies log every finding; the tables are the report
warnings.filterwarnings("ignore")

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask  # noqa: E402
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402
from agentdojo.task_suite.task_suite import TaskSuite  # noqa: E402
from agentdojo.types import text_content_block_from_string  # noqa: E402
from guard import (  # noqa: E402
    APPROVERS,
    GuardedRuntime,
    known_for,
    load_classification,
    policies_for,
)

from sdk import SessionTaintPolicy  # noqa: E402

BENCHMARK = "v1.2.2"
ATTACKS = ("important_instructions", "direct", "ignore_previous", "system_message", "injecagent")
#: The attack every configuration is run with. Only `detector` reads the text.
MAIN_ATTACK = "important_instructions"

#: (configuration, approver) for the main attack and for the benign tasks.
RUNS = (
    ("none", "nobody"),
    ("detector", "nobody"),
    ("approve_all", "nobody"),
    ("approve_all", "careful"),
    ("taint_text", "nobody"),
    ("taint_text", "careful"),
    ("taint_text", "rubber_stamp"),
    ("taint_all", "nobody"),
    ("taint_all", "careful"),
)
#: PROTOCOL-known.md's runs, with the main attack only. The directory variant
#: is Slack's alone.
KNOWN_RUNS = (("taint_known", "nobody"), ("taint_known", "careful"))
DIRECTORY_RUNS = (("taint_directory", "nobody"), ("taint_directory", "careful"))
NAMED_RUNS = (("taint_named", "nobody"), ("taint_named", "careful"))
SHIPPED_RUNS = (("taint_known_shipped", "nobody"), ("taint_known_shipped", "careful"))

BENIGN_FIELDS = [
    "suite",
    "user_task",
    "configuration",
    "approver",
    "user_calls",
    "sink_calls",
    "approvals",
    "user_blocked",
    "utility",
]
ATTACK_FIELDS = [
    "suite",
    "user_task",
    "injection_task",
    "attack",
    "configuration",
    "approver",
    "delivered_by",
    "compromised",
    "tainted",
    "inj_calls",
    "inj_sinks",
    "inj_ran",
    "inj_stopped",
    "approvals",
    "user_calls",
    "user_blocked",
    "security",
    "utility",
]


class _Victim(BasePipelineElement):
    """Stands where the model would, for the one thing an attack reads off a
    pipeline: the model's name, which `important_instructions` addresses."""

    name = "gpt-4o-2024-05-13"

    def query(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("the replay has no model to query")


def _canaries(suite: TaskSuite) -> dict[str, str]:
    return {vector: f"<CANARY---{vector}--->" for vector in suite.get_injection_vector_defaults()}


@cache
def exposures(suite: TaskSuite, user_task: BaseUserTask) -> tuple[int, ...]:
    """Which of the task's own calls hand back something an attacker can write.

    Found the way AgentDojo finds it: fill every injection vector with a
    marker, run the task's solution, and see which results carry one.
    """
    canaries = _canaries(suite)
    env = user_task.init_environment(suite.load_and_inject_default_environment(canaries))
    runtime = FunctionsRuntime(suite.tools)
    found = []
    for index, call in enumerate(user_task.ground_truth(env.model_copy(deep=True))):
        result, error = runtime.run_function(env, call.function, call.args)
        text = error if error is not None else tool_result_to_str(result)
        if any(marker in text for marker in canaries.values()):
            found.append(index)
    return tuple(found)


@lru_cache(maxsize=4)
def _parsed(suite: TaskSuite, injections: tuple[tuple[str, str], ...]) -> Any:
    return suite.load_and_inject_default_environment(dict(injections))


def environment(suite: TaskSuite, injections: Mapping[str, str]) -> Any:
    """A fresh copy of the suite's environment with *injections* placed in it.

    Parsing the environment is most of the cost of a replay, and the same pair
    is replayed under every configuration, so the parse is kept and each
    replay is handed its own deep copy.
    """
    return _parsed(suite, tuple(sorted(injections.items()))).model_copy(deep=True)


def replay(
    suite: TaskSuite,
    user_task: BaseUserTask,
    injection_task: BaseInjectionTask | None,
    injections: Mapping[str, str],
    configuration: str,
    approver: str,
    lists: Mapping[str, list[str]],
    known: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One task, with or without an attack, under one configuration."""
    env = user_task.init_environment(environment(suite, injections))
    before = env.model_copy(deep=True)
    user_calls = user_task.ground_truth(before)
    attacker_calls = injection_task.ground_truth(before) if injection_task else []
    exposed = set(exposures(suite, user_task)) if injection_task else set()

    policies = policies_for(configuration, lists, known, user_task.PROMPT, suite.name)
    runtime = GuardedRuntime(suite.tools, policies=policies, approver=APPROVERS[approver])
    taint = next((p for p in policies if isinstance(p, SessionTaintPolicy)), None)

    compromised = False
    delivered_by = ""
    tainted: bool | None = None
    for index, call in enumerate(user_calls):
        runtime.origin = "user"
        runtime.run_function(env, call.function, call.args)
        if compromised or index not in exposed or not runtime.log[-1].delivered:
            continue
        # The agent has now read the injection, and does all of what it says.
        compromised, delivered_by = True, call.function
        tainted = taint.is_tainted("replay") if taint is not None else None
        runtime.origin = "injection"
        for attack_call in attacker_calls:
            runtime.run_function(env, attack_call.function, attack_call.args)

    mine = [entry for entry in runtime.log if entry.origin == "user"]
    theirs = [entry for entry in runtime.log if entry.origin == "injection"]
    # A call that was held or refused did not happen, so it is not in the trace.
    # The log and the calls line up one to one: neither has nested calls.
    every_call = _interleave(user_calls, attacker_calls, runtime.log)
    trace = [call for call, entry in every_call if entry.ran]
    said = user_task.GROUND_TRUTH_OUTPUT + (
        f" {injection_task.GROUND_TRUTH_OUTPUT}" if injection_task and compromised else ""
    )
    output = [text_content_block_from_string(said)]

    solved = suite._check_user_task_utility(user_task, output, before, env, trace)
    row: dict[str, Any] = {
        "suite": suite.name,
        "user_task": user_task.ID,
        "configuration": configuration,
        "approver": approver,
        "user_calls": len(mine),
        "approvals": runtime.approvals_asked,
        "user_blocked": sum(not entry.delivered for entry in mine),
        # Done only if every one of the task's own calls ran and returned.
        "utility": int(solved and all(entry.delivered for entry in mine)),
    }
    if injection_task is None:
        row["sink_calls"] = sum(entry.function in lists["sinks"] for entry in mine)
        return row
    row.update(
        injection_task=injection_task.ID,
        delivered_by=delivered_by,
        compromised=int(compromised),
        tainted="" if tainted is None else int(tainted),
        inj_calls=len(attacker_calls),
        inj_sinks=sum(call.function in lists["sinks"] for call in attacker_calls),
        inj_ran=sum(entry.ran for entry in theirs),
        inj_stopped=sum(not entry.ran for entry in theirs),
        security=int(
            suite._check_injection_task_security(injection_task, output, before, env, trace)
        ),
    )
    return row


def _interleave(
    user_calls: list[FunctionCall], attacker_calls: list[FunctionCall], log: list[Any]
) -> Iterator[tuple[FunctionCall, Any]]:
    """Pair each call with what became of it, in the order they were made."""
    user, attacker = iter(user_calls), iter(attacker_calls)
    for entry in log:
        yield (next(user) if entry.origin == "user" else next(attacker)), entry


@cache
def _classification() -> dict[str, dict[str, list[str]]]:
    return load_classification()


@cache
def _attacks(suite_name: str) -> dict[str, Any]:
    suite = get_suites(BENCHMARK)[suite_name]
    return {name: load_attack(name, suite, _Victim()) for name in ATTACKS}


def task_rows(job: tuple[str, str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Every row for one user task: its own runs, then every attack on it.

    The unit of work handed to a worker process. It takes names and not
    objects, and looks the suite up again on the other side.
    """
    suite_name, task_id, mode = job
    suite = get_suites(BENCHMARK)[suite_name]
    lists = _classification()[suite_name]
    user_task = suite.user_tasks[task_id]
    if mode == "check":
        runs: tuple[tuple[str, str], ...] = (("none", "nobody"),)
    elif mode == "known":
        runs = KNOWN_RUNS + (DIRECTORY_RUNS if suite_name == "slack" else ())
    elif mode == "named":
        runs = NAMED_RUNS
    elif mode == "shipped":
        runs = SHIPPED_RUNS
    else:
        runs = RUNS

    benign = [
        replay(
            suite,
            user_task,
            None,
            {},
            configuration,
            approver,
            lists,
            known_for(configuration, suite_name),
        )
        for configuration, approver in runs
        # An approval nobody reads changes nothing when there is no attack.
        if approver != "rubber_stamp"
    ]
    attack = []
    for injection_task in suite.injection_tasks.values():
        for attack_name, attacker in _attacks(suite_name).items():
            injections = attacker.attack(user_task, injection_task)
            for configuration, approver in runs:
                if attack_name != MAIN_ATTACK and configuration != "detector":
                    continue  # no other configuration reads the text
                row = replay(
                    suite,
                    user_task,
                    injection_task,
                    injections,
                    configuration,
                    approver,
                    lists,
                    known_for(configuration, suite_name),
                )
                attack.append({**row, "attack": attack_name})
    return benign, attack


def run(suites: list[str], out: Path, mode: str, limit: int | None, jobs: int) -> None:
    work = []
    for name in suites:
        suite = get_suites(BENCHMARK)[name]
        lists = _classification()[name]
        unknown = (set(lists["sources"]) | set(lists["sinks"])) - {t.name for t in suite.tools}
        if unknown:
            raise SystemExit(f"classification.yaml names tools {name} does not have: {unknown}")
        work += [(name, task_id, mode) for task_id in list(suite.user_tasks)[:limit]]

    out.mkdir(parents=True, exist_ok=True)
    suffix = "-check" if mode == "check" else ""
    with (
        (out / f"benign{suffix}.csv").open("w", newline="") as benign_file,
        (out / f"attack{suffix}.csv").open("w", newline="") as attack_file,
        ProcessPoolExecutor(max_workers=jobs) as pool,
    ):
        benign = csv.DictWriter(benign_file, BENIGN_FIELDS, lineterminator="\n")
        attack = csv.DictWriter(attack_file, ATTACK_FIELDS, lineterminator="\n")
        benign.writeheader()
        attack.writeheader()
        # map() hands results back in the order the work was given, so the
        # files are the same whatever the number of workers.
        for done, (benign_rows, attack_rows) in enumerate(pool.map(task_rows, work), 1):
            benign.writerows(benign_rows)
            attack.writerows(attack_rows)
            print(f"  {done}/{len(work)} user tasks", file=sys.stderr, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--suites", nargs="+", default=list(get_suites(BENCHMARK)))
    parser.add_argument("--out", type=Path, default=HERE / "results")
    parser.add_argument("--check", action="store_true", help="the undefended baseline only")
    parser.add_argument("--known", action="store_true", help="PROTOCOL-known.md's runs")
    parser.add_argument("--named", action="store_true", help="PROTOCOL-named.md's runs")
    parser.add_argument(
        "--shipped", action="store_true", help="known destinations as the package ships them"
    )
    parser.add_argument("--limit", type=int, default=None, help="user tasks per suite (debugging)")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1, help="worker processes")
    args = parser.parse_args()
    modes = {"check": args.check, "known": args.known, "named": args.named}
    mode = next((m for m, on in modes.items() if on), "shipped" if args.shipped else "all")
    out = args.out
    if out == HERE / "results" and mode in ("known", "named", "shipped"):
        # The committed rows are never overwritten.
        out = HERE / "results" / ("known-shipped" if mode == "shipped" else mode)
    run(args.suites, out, mode, args.limit, args.jobs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
