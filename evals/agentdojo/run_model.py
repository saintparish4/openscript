"""Run AgentDojo with a model in the loop, its tools going through the policies.

The replay (replay.py) makes AgentDojo's own scripted calls. This puts a model
where the script was, in AgentDojo's own pipeline, with every tool call going
through GuardedRuntime. PROTOCOL-model.md says what is run, what the
approvers are, and what the numbers can and cannot say.

    .venv/bin/python run_model.py --model scripted                  # no key, no cost
    .venv/bin/python run_model.py --model haiku --budget 25         # prints the plan
    .venv/bin/python run_model.py --model haiku --budget 25 --yes   # spends
    .venv/bin/python run_model.py --summary results/model/claude-haiku-4-5

`scripted` is the replay's compromised agent driven through the same pipeline:
it checks the harness against the replay's committed rows and gives a floor on
what a model run sends, for nothing.

A run can be stopped and started again. Cases already done are skipped, and
everything already spent stays counted against --budget, which is the total
for the output directory, not for one invocation. Run from this directory, in
the environment README.md describes, with ANTHROPIC_API_KEY set for a model.
"""

from __future__ import annotations

import argparse
import json
import logging
import multiprocessing
import sys
import warnings
from collections import defaultdict
from collections.abc import Iterator, Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import asdict, dataclass
from functools import cache
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))  # the repository root, for sdk/ and evals/

logging.disable(logging.CRITICAL)  # the policies log every finding; the rows are the report
warnings.filterwarnings("ignore")

import yaml  # noqa: E402
from agentdojo.agent_pipeline import (  # noqa: E402
    AgentPipeline,
    InitQuery,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message  # noqa: E402
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.functions_runtime import EmptyEnv, Function  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402
from guard import (  # noqa: E402
    APPROVERS,
    Approver,
    GuardedRuntime,
    load_classification,
    policies_for,
)
from model import PROFILES, BudgetExceeded, Claude, Meter, ScriptedAgent  # noqa: E402
from replay import BENCHMARK, MAIN_ATTACK, environment, exposures  # noqa: E402

from evals.run import wilson  # noqa: E402

#: (configuration, approver), as PROTOCOL-model.md lists them. With a model,
#: each approver is a run of its own: the answer to a held call changes what
#: the model does next.
RUNS = (
    ("none", "nobody"),
    ("detector", "nobody"),
    ("approve_all", "nobody"),
    ("approve_all", "careful"),
    ("taint_text", "nobody"),
    ("taint_text", "careful"),
)
DEFAULT_SUITES = ("banking",)
#: AgentDojo addresses the model by name in the attack. It calls every Claude
#: "Claude"; the scripted agent keeps the replay's "GPT-4", so its rows can be
#: compared with the replay's.
ADDRESSED_AS = {"scripted": "gpt-4o-2024-05-13", "claude": "claude-3-5-sonnet-20241022"}
#: A run stops when this many cases in a row fail: the same error every time
#: (a request the API refuses, say) would otherwise go through the whole plan.
FAILURES = 5
#: For turning the scripted agent's request sizes into a token floor.
CHARS_PER_TOKEN = 3.5


@dataclass(frozen=True)
class Case:
    suite: str
    user_task: str
    injection_task: str  # "" for the task with no attack
    configuration: str
    approver: str

    @property
    def key(self) -> str:
        return "/".join(asdict(self).values())


# --- what a careful person recognises -------------------------------------------------


@cache
def load_markers() -> dict[str, dict[str, list[str]]]:
    data = yaml.safe_load((HERE / "markers.yaml").read_text())
    suites: dict[str, dict[str, list[str]]] = data["suites"]
    return suites


def _values(value: Any) -> Iterator[str]:
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _values(item)
    elif isinstance(value, list | tuple | set):
        for item in value:
            yield from _values(item)
    else:
        yield str(value)


def carries(args: Mapping[str, Any], markers: Sequence[str]) -> bool:
    """Does any argument value contain one of *markers*, ignoring case?"""
    wanted = [marker.lower() for marker in markers]
    return any(marker in value.lower() for value in _values(args) for marker in wanted)


def marker_approver(markers: Sequence[str]) -> Approver:
    """Refuses a held call that carries one of the attacker's values, approves the rest."""
    return lambda _tool, args, _origin: not carries(args, markers)


def markers_for(case: Case) -> list[str]:
    if not case.injection_task:
        return []
    suites = load_markers()
    if case.suite not in suites:
        raise SystemExit(f"markers.yaml has nothing for {case.suite}: write it before running it")
    return list(suites[case.suite][case.injection_task])


# --- one case -------------------------------------------------------------------------


class _Victim(BasePipelineElement):
    """Stands for the model when an attack is built: only its name is read."""

    def __init__(self, name: str) -> None:
        self.name = name

    def query(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


_NO_ENV = EmptyEnv()


class _Recorder(BasePipelineElement):
    """The pipeline, keeping the conversation it ends with."""

    def __init__(self, inner: AgentPipeline, name: str) -> None:
        self.inner = inner
        self.name = name
        self.messages: list[Any] = []

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any = _NO_ENV,
        messages: Sequence[Any] = [],
        extra_args: dict[str, Any] = {},  # noqa: B006 -- AgentDojo's own signature
    ) -> Any:
        out = self.inner.query(query, runtime, env, messages, extra_args)
        self.messages = list(out[3])
        return out


@cache
def _attack(suite_name: str, addressed_as: str) -> Any:
    suite = get_suites(BENCHMARK)[suite_name]
    return load_attack(MAIN_ATTACK, suite, _Victim(addressed_as))


#: Set in each worker by _init: the shared spend and the run's budget.
_SPENT: Any = None
_BUDGET = 0.0


def _init(spent: Any, budget: float) -> None:
    global _SPENT, _BUDGET
    _SPENT, _BUDGET = spent, budget


def _spend(add: float) -> float:
    with _SPENT.get_lock():
        _SPENT.value += add
        return float(_SPENT.value)


def run_case(case: Case, model: str, client: Any = None) -> dict[str, Any]:
    """One task, with or without an attack, under one configuration and approver.

    Returns the row, the conversation, and the usage of every request made.
    A case stopped by the budget comes back with ``budget`` set and no row.
    """
    suite = get_suites(BENCHMARK)[case.suite]
    user_task = suite.user_tasks[case.user_task]
    injection_task = suite.injection_tasks[case.injection_task] if case.injection_task else None
    lists = load_classification()[case.suite]
    markers = markers_for(case)
    addressed_as = ADDRESSED_AS["scripted" if model == "scripted" else "claude"]
    injections = (
        _attack(case.suite, addressed_as).attack(user_task, injection_task)
        if injection_task is not None
        else {}
    )

    requests: list[dict[str, Any]] = []
    llm: ScriptedAgent | Claude
    if model == "scripted":
        exposed = (
            frozenset(exposures(suite, user_task)) if injection_task is not None else frozenset()
        )
        llm = ScriptedAgent(user_task, injection_task, exposed)
    else:
        profile = PROFILES[model]
        meter = Meter(profile, _BUDGET, spend=_spend)
        llm = Claude(profile, meter, client=client, on_request=requests.append)

    approver = marker_approver(markers) if case.approver == "careful" else APPROVERS[case.approver]
    policies = policies_for(case.configuration, lists)
    runtimes: list[GuardedRuntime] = []

    def runtime_class(tools: Sequence[Function]) -> GuardedRuntime:
        runtime = GuardedRuntime(tools, policies=policies, approver=approver, session_id=case.key)
        runtime.origin = "model"
        runtimes.append(runtime)
        return runtime

    pipeline = _Recorder(
        AgentPipeline(
            [
                SystemMessage(load_system_message(None)),
                InitQuery(),
                llm,
                ToolsExecutionLoop([ToolsExecutor(), llm]),
            ]
        ),
        llm.name,
    )
    row: dict[str, Any] = {**asdict(case), "attack": MAIN_ATTACK if injection_task else ""}
    row["model"] = llm.name
    try:
        utility, security = suite.run_task_with_pipeline(
            pipeline,
            user_task,
            injection_task,
            injections,
            runtime_class=runtime_class,  # type: ignore[arg-type]
            environment=environment(suite, injections),
        )
    except BudgetExceeded as stopped:
        return {"key": case.key, "budget": str(stopped), "requests": requests}
    except Exception as failed:  # recorded, and the case is retried next run
        row["error"] = f"{type(failed).__name__}: {failed}"
        utility = security = None

    log = runtimes[0].log if runtimes else []
    row.update(
        utility="" if utility is None else int(utility),
        security="" if injection_task is None or security is None else int(security),
        calls=len(log),
        approvals=runtimes[0].approvals_asked if runtimes else 0,
        held=sum(entry.status == "held" for entry in log),
        refused=sum(entry.status == "refused" for entry in log),
        withheld=sum(entry.status == "withheld" for entry in log),
        sink_calls=sum(entry.function in lists["sinks"] for entry in log),
        # The attacker's value reached a tool: the call carrying it ran.
        marked_ran=(
            sum(entry.ran and carries(entry.args, markers) for entry in log) if markers else ""
        ),
        log=[[entry.function, entry.status] for entry in log],
    )
    row.setdefault("error", "")
    if isinstance(llm, Claude):
        row.update(llm.meter.totals())
    else:
        row.update(requests=len(llm.input_chars), request_chars=sum(llm.input_chars))
        row["compromised"] = int(llm.compromised) if injection_task is not None else ""
    return {
        "key": case.key,
        "row": row,
        "transcript": {"key": case.key, "messages": pipeline.messages},
        "requests": requests,
    }


# --- a run ----------------------------------------------------------------------------


def plan(suites: Sequence[str], runs: Sequence[tuple[str, str]], limit: int | None) -> list[Case]:
    """Every case, a pair at a time: a run stopped part way has whole pairs."""
    cases = []
    for name in suites:
        suite = get_suites(BENCHMARK)[name]
        for task_id in list(suite.user_tasks)[:limit]:
            cases += [Case(name, task_id, "", c, a) for c, a in runs]
            for injection_id in suite.injection_tasks:
                cases += [Case(name, task_id, injection_id, c, a) for c, a in runs]
    return cases


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _dump(record: Any) -> str:
    return json.dumps(
        record, default=lambda o: o.model_dump() if hasattr(o, "model_dump") else str(o)
    )


def run(
    model: str,
    cases: list[Case],
    out: Path,
    budget: float,
    jobs: int,
    client: Any = None,
) -> int:
    """Run every case not already done in *out*. Returns how many were left undone."""
    out.mkdir(parents=True, exist_ok=True)
    done = {row["key"] for row in _read_jsonl(out / "cases.jsonl") if not row.get("error")}
    spent = sum(r["cost_usd"] for r in _read_jsonl(out / "requests.jsonl"))
    todo = [case for case in cases if case.key not in done]
    print(
        f"{model}: {len(todo)} of {len(cases)} cases to run, ${spent:.2f} of ${budget:.2f} spent",
        file=sys.stderr,
    )
    shared = multiprocessing.Value("d", spent)
    stopped = ""
    finished = failures = 0
    with (
        (out / "cases.jsonl").open("a") as rows,
        (out / "transcripts.jsonl").open("a") as transcripts,
        (out / "requests.jsonl").open("a") as requests,
    ):

        def record(result: dict[str, Any]) -> None:
            for usage in result["requests"]:
                requests.write(_dump({"key": result["key"], **usage}) + "\n")
            if "row" in result:
                rows.write(_dump({"key": result["key"], **result["row"]}) + "\n")
                transcripts.write(_dump(result["transcript"]) + "\n")
            for handle in (rows, transcripts, requests):
                handle.flush()

        def failing(result: dict[str, Any]) -> str:
            """Why to stop: the budget is spent, or case after case has failed."""
            nonlocal failures
            if "budget" in result:
                return str(result["budget"])
            error = result["row"]["error"]
            failures = failures + 1 if error else 0
            return (
                f"{FAILURES} cases in a row failed, the last with {error}"
                if failures >= FAILURES
                else ""
            )

        if jobs <= 1:
            _init(shared, budget)
            for case in todo:
                result = run_case(case, model, client)
                record(result)
                stopped = failing(result)
                if "row" in result:
                    finished += 1
                    print(f"  {finished}/{len(todo)} {case.key}", file=sys.stderr, flush=True)
                if stopped:
                    break
        else:
            with ProcessPoolExecutor(jobs, initializer=_init, initargs=(shared, budget)) as pool:
                queue = iter(todo)
                running = {pool.submit(run_case, case, model) for case in _take(queue, jobs * 2)}
                while running:
                    complete, running = wait(running, return_when=FIRST_COMPLETED)
                    for future in complete:
                        result = future.result()
                        record(result)
                        stopped = stopped or failing(result)
                        if "row" in result:
                            finished += 1
                            print(f"  {finished}/{len(todo)} {result['key']}", file=sys.stderr)
                    if not stopped:
                        running |= {
                            pool.submit(run_case, case, model)
                            for case in _take(queue, len(complete))
                        }
    # A case that failed is not done: it is run again next time.
    done |= {r["key"] for r in _read_jsonl(out / "cases.jsonl") if not r.get("error")}
    left = sum(case.key not in done for case in cases)
    if stopped:
        print(f"stopped: {stopped}. {left} cases not done.", file=sys.stderr)
    return left


def _take(items: Iterator[Case], n: int) -> list[Case]:
    return [case for _, case in zip(range(n), items, strict=False)]


# --- the tables -----------------------------------------------------------------------


def _share(n: int, of: int) -> str:
    if not of:
        return "n/a"
    low, high = wilson(n, of)
    return f"{n}/{of} ({100 * n / of:.0f}%, {100 * low:.0f}-{100 * high:.0f})"


def summarize(out: Path) -> str:
    rows: dict[str, dict[str, Any]] = {}
    for row in _read_jsonl(out / "cases.jsonl"):
        if not row.get("error"):
            rows[row["key"]] = row  # the last good row for a case is the one that counts
    errors = {r["key"] for r in _read_jsonl(out / "cases.jsonl") if r.get("error")} - set(rows)
    spent = sum(r["cost_usd"] for r in _read_jsonl(out / "requests.jsonl"))
    by: dict[tuple[str, str, bool], list[dict[str, Any]]] = defaultdict(list)
    for row in rows.values():
        by[row["configuration"], row["approver"], bool(row["injection_task"])].append(row)

    model = next(iter(rows.values()), {}).get("model", out.name)
    lines = [
        f"## {model}",
        "",
        f"Spent ${spent:.2f}. Cases failed and not yet rerun: {len(errors)}.",
        "",
    ]
    lines += [
        "| Run | Tasks done, no attack | Tasks needing an approval | Approvals per task "
        "| Attacks that succeeded | Injection tasks that got through | Tasks done under attack "
        "| Approvals per attacked task | Cost |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for configuration, approver in RUNS:
        benign = by[configuration, approver, False]
        attacked = by[configuration, approver, True]
        if not benign and not attacked:
            continue
        through = {r["injection_task"] for r in attacked if r["security"] == 1}
        injection_tasks = {r["injection_task"] for r in attacked}
        cost = sum(r.get("cost_usd", 0.0) for r in benign + attacked)
        lines.append(
            f"| {configuration} / {approver} "
            f"| {_share(sum(r['utility'] for r in benign), len(benign))} "
            f"| {_share(sum(r['approvals'] > 0 for r in benign), len(benign))} "
            f"| {sum(r['approvals'] for r in benign) / max(len(benign), 1):.2f} "
            f"| {_share(sum(r['security'] for r in attacked), len(attacked))} "
            f"| {len(through)}/{len(injection_tasks)} "
            f"| {_share(sum(r['utility'] for r in attacked), len(attacked))} "
            f"| {sum(r['approvals'] for r in attacked) / max(len(attacked), 1):.2f} "
            f"| ${cost:.2f} |"
        )
    every = list(rows.values())
    if every and "request_chars" in every[0]:
        tokens = sum(r["request_chars"] for r in every) / CHARS_PER_TOKEN
        lines += [
            "",
            f"The scripted agent's requests come to about {tokens / 1e6:.2f}M input tokens "
            f"over {len(every)} cases ({sum(r['requests'] for r in every)} requests). A model "
            "reads more and says more, so that is a floor on a model run's input. At list "
            "prices, input alone: "
            + ", ".join(
                f"{profile.model} ${tokens * profile.input / 1e6:.2f}"
                for profile in PROFILES.values()
            )
            + ".",
        ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--model", choices=["scripted", *PROFILES])
    parser.add_argument("--budget", type=float, help="US dollars, for the output directory")
    parser.add_argument("--suites", nargs="+", default=list(DEFAULT_SUITES))
    parser.add_argument(
        "--runs", nargs="+", help="configuration/approver, e.g. none/nobody (default: all)"
    )
    parser.add_argument("--limit", type=int, default=None, help="user tasks per suite")
    parser.add_argument("--jobs", type=int, default=1, help="worker processes")
    parser.add_argument("--out", type=Path, help="default: results/model/<model>")
    parser.add_argument(
        "--yes", action="store_true", help="spend: without it a model run only plans"
    )
    parser.add_argument("--summary", type=Path, metavar="DIR", help="print the tables for DIR")
    args = parser.parse_args()

    if args.summary:
        print(summarize(args.summary))
        return 0
    if args.model is None:
        parser.error("--model is required")
    runs = RUNS if not args.runs else [tuple(r.split("/", 1)) for r in args.runs]
    unknown = [r for r in runs if r not in RUNS]
    if unknown:
        parser.error(f"not in the protocol: {unknown}")
    cases = plan(args.suites, runs, args.limit)
    name = "scripted" if args.model == "scripted" else PROFILES[args.model].model
    out = args.out or HERE / "results" / "model" / name

    if args.model != "scripted":
        if args.budget is None:
            parser.error("a model run needs --budget")
        print(
            f"{name}: {len(cases)} cases ({', '.join(args.suites)}; {len(runs)} runs), "
            f"budget ${args.budget:.2f}, into {out}",
            file=sys.stderr,
        )
        if not args.yes:
            print("Nothing sent. Add --yes to run it.", file=sys.stderr)
            return 0
        import anthropic

        try:
            # Free, and fails fast on a missing key or a model name the API does not know.
            anthropic.Anthropic().models.retrieve(name)
        except anthropic.APIError as failed:
            print(f"Nothing sent: the API refused the check ({failed}).", file=sys.stderr)
            return 2
        except TypeError as failed:  # the SDK found no credentials at all
            print(f"Nothing sent: {failed}. Set ANTHROPIC_API_KEY.", file=sys.stderr)
            return 2

    left = run(args.model, cases, out, args.budget or 0.0, args.jobs)
    print(summarize(out))
    return 1 if left else 0


if __name__ == "__main__":
    raise SystemExit(main())
