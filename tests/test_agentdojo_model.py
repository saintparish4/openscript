"""The harness for running AgentDojo with a model, checked without one.

Skipped where AgentDojo is not installed, which is everywhere but its own
environment (evals/agentdojo/README.md):

    evals/agentdojo/.venv/bin/python -m pytest tests/test_agentdojo_model.py

Nothing here sends a request anywhere. The Claude element is driven through
the real Anthropic SDK against a fake API, and the harness as a whole by the
replay's scripted agent, whose results are already committed.
"""

from __future__ import annotations

import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("agentdojo")

HERE = Path(__file__).resolve().parents[1] / "evals" / "agentdojo"
sys.path.insert(0, str(HERE))

import anthropic  # noqa: E402
import httpx2  # noqa: E402
from agentdojo.functions_runtime import FunctionsRuntime, make_function  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402
from agentdojo.types import ChatUserMessage, text_content_block_from_string  # noqa: E402
from guard import load_classification  # noqa: E402
from model import PROFILES, RAW, BudgetExceeded, Claude, Meter  # noqa: E402
from run_model import (  # noqa: E402
    AMENDMENT_RUNS,
    FAILURES,
    RUNS,
    carries,
    default_out,
    load_markers,
    marker_approver,
    plan,
    run,
)

# run_model silences logging for its own output. That is process-wide, and the
# rest of the suite (tests/test_logging.py) needs it back.
logging.disable(logging.NOTSET)

HAIKU = PROFILES["haiku"]


def fake_api(responses: list[dict[str, Any]], seen: list[dict[str, Any]]) -> anthropic.Anthropic:
    """An Anthropic client whose API hands back *responses* in turn, the last one
    for good, and records every request body in *seen*."""

    def handle(request: httpx2.Request) -> httpx2.Response:
        seen.append(json.loads(request.content))
        body = responses[min(len(seen), len(responses)) - 1]
        return httpx2.Response(200, json={"id": f"msg_{len(seen)}", "type": "message", **body})

    return anthropic.Anthropic(
        api_key="not-a-key",
        max_retries=0,
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handle)),
    )


def message(content: list[dict[str, Any]], stop: str, tokens_in: int = 100) -> dict[str, Any]:
    return {
        "role": "assistant",
        "model": HAIKU.model,
        "content": content,
        "stop_reason": stop,
        "stop_sequence": None,
        "usage": {"input_tokens": tokens_in, "output_tokens": 10},
    }


def get_balance() -> float:
    """Get the balance of the account."""
    return 100.0


def test_a_request_costs_what_the_price_list_says():
    usage = anthropic.types.Usage(
        input_tokens=1_000_000,
        output_tokens=1_000_000,
        cache_creation_input_tokens=1_000_000,
        cache_read_input_tokens=1_000_000,
    )
    # input 1 + write 1.25 + read 0.1, at $1; output at $5
    assert HAIKU.cost(usage) == pytest.approx(1 + 1.25 + 0.1 + 5)


def test_each_turn_goes_back_exactly_as_the_model_wrote_it():
    turn = [
        {"type": "thinking", "thinking": "", "signature": "sig-1"},
        {"type": "tool_use", "id": "toolu_1", "name": "get_balance", "input": {}},
        {"type": "text", "text": "Checking."},
    ]
    seen: list[dict[str, Any]] = []
    client = fake_api(
        [message(turn, "tool_use"), message([{"type": "text", "text": "100"}], "end_turn")], seen
    )
    claude = Claude(PROFILES["sonnet"], Meter(PROFILES["sonnet"], budget=1.0), client=client)
    runtime = FunctionsRuntime([make_function(get_balance)])
    asked = [
        {"role": "system", "content": [text_content_block_from_string("Be brief.")]},
        ChatUserMessage(role="user", content=[text_content_block_from_string("Balance?")]),
    ]
    _, _, _, messages, _ = claude.query("Balance?", runtime, messages=asked)
    assert messages[-1]["tool_calls"][0].function == "get_balance"
    assert messages[-1][RAW] == turn

    result = {
        "role": "tool",
        "content": [text_content_block_from_string("100.0")],
        "tool_call_id": "toolu_1",
        "tool_call": messages[-1]["tool_calls"][0],
        "error": None,
    }
    claude.query("Balance?", runtime, messages=[*messages, result])

    _, second = seen
    assert second["messages"][1] == {
        "role": "assistant",
        "content": turn,
    }, "AgentDojo would have sent text first and dropped the thinking"
    for request in seen:
        assert "temperature" not in request, "Claude Sonnet 5.5 refuses one"
        assert request["model"] == "claude-sonnet-5-5"
        assert request["system"] == "Be brief."
        assert request["cache_control"] == {"type": "ephemeral"}
        assert [tool["name"] for tool in request["tools"]] == ["get_balance"]
    assert claude.meter.requests == 2


def test_no_request_is_sent_once_the_budget_is_spent():
    seen: list[dict[str, Any]] = []
    client = fake_api([message([{"type": "text", "text": "hi"}], "end_turn", 1_000_000)], seen)
    meter = Meter(HAIKU, budget=1.5)
    claude = Claude(HAIKU, meter, client=client)
    asked = [ChatUserMessage(role="user", content=[text_content_block_from_string("hi")])]
    runtime = FunctionsRuntime([])
    claude.query("hi", runtime, messages=asked)  # $1.00 and change
    claude.query("hi", runtime, messages=asked)  # sent: $1 < $1.50 when asked
    with pytest.raises(BudgetExceeded):
        claude.query("hi", runtime, messages=asked)
    assert len(seen) == 2


def test_a_run_stops_at_its_budget_and_picks_up_where_it_left_off(tmp_path):
    seen: list[dict[str, Any]] = []
    # Every case is one request costing a little over a dollar.
    client = fake_api([message([{"type": "text", "text": "done"}], "end_turn", 1_000_000)], seen)
    cases = plan(["banking"], [("none", "nobody")], limit=1)[:6]

    left = run("haiku", cases, tmp_path, budget=2.5, jobs=1, client=client)
    assert (left, len(seen)) == (3, 3), "three requests fit under $2.50; the fourth is not sent"
    spent = [json.loads(line)["cost_usd"] for line in (tmp_path / "requests.jsonl").open()]
    assert len(spent) == 3

    left = run("haiku", cases, tmp_path, budget=10, jobs=1, client=client)
    assert left == 0 and len(seen) == 6, "only the three not done are run"
    rows = [json.loads(line) for line in (tmp_path / "cases.jsonl").open()]
    assert sorted(row["key"] for row in rows) == sorted(case.key for case in cases)


def test_the_careful_approver_refuses_the_attackers_value_and_nothing_else():
    approve = marker_approver(["US133000000121212121212"])
    assert not approve("send_money", {"recipient": "us133000000121212121212"}, "model")
    assert not approve("x", {"nested": {"list": ["to US133000000121212121212 now"]}}, "model")
    assert approve("send_money", {"recipient": "GB29NWBK60161331926819", "amount": 10}, "model")
    assert marker_approver([])("anything", {"to": "anyone"}, "model")


def test_the_banking_markers_mark_every_attack_and_none_of_the_tasks_own_calls():
    suite = get_suites("v1.2.2")["banking"]
    markers = load_markers()["banking"]
    assert set(markers) == set(suite.injection_tasks)
    env = suite.load_and_inject_default_environment({})
    sinks = {"send_money", "schedule_transaction", "update_scheduled_transaction"}
    sinks |= {"update_password", "update_user_info"}
    for task_id, task in suite.injection_tasks.items():
        attack = [c for c in task.ground_truth(env.model_copy(deep=True)) if c.function in sinks]
        assert attack and all(carries(c.args, markers[task_id]) for c in attack), task_id
    every = [m for ms in markers.values() for m in ms]
    for task_id, task in suite.user_tasks.items():
        own = task.ground_truth(task.init_environment(env.model_copy(deep=True)))
        assert not any(carries(c.args, every) for c in own), task_id


def test_the_slack_markers_mark_every_attack_and_none_of_the_tasks_own_calls():
    suite = get_suites("v1.2.2")["slack"]
    markers = load_markers()["slack"]
    assert set(markers) == set(suite.injection_tasks)
    sinks = set(load_classification()["slack"]["sinks"])
    env = suite.load_and_inject_default_environment({})
    for task_id, task in suite.injection_tasks.items():
        attack = [c for c in task.ground_truth(env.model_copy(deep=True)) if c.function in sinks]
        assert attack and all(carries(c.args, markers[task_id]) for c in attack), task_id
    every = [m for ms in markers.values() for m in ms]
    for task_id, task in suite.user_tasks.items():
        own = task.ground_truth(task.init_environment(env.model_copy(deep=True)))
        assert not any(carries(c.args, every) for c in own), task_id


def _replayed(where: str, suite: str) -> dict[tuple[str, str, str, str], dict[str, str]]:
    """The replay's committed rows for *suite*, by (user, injection, configuration, approver)."""
    rows: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for name in ("attack.csv", "benign.csv"):
        with (HERE / where / name).open(newline="") as handle:
            for r in csv.DictReader(handle):
                if r["suite"] == suite and r.get("attack", "important_instructions") in (
                    "important_instructions",
                    "",
                ):
                    key = (r["user_task"], r.get("injection_task", ""), r["configuration"])
                    rows[(*key, r["approver"])] = r
    return rows


def test_the_scripted_agent_through_the_harness_reproduces_the_replay_on_slack(tmp_path):
    """Slack, as banking below, with two differences known before any model ran
    (PROTOCOL-model-amendment-2.md). Attack outcome, approvals and compromise
    agree on every case: injection_task_5 is scored from the trace, and the
    harness gives AgentDojo only the calls that ran, as the replay does. Task
    success differs in five tasks, only under attack with a careful approver:
    the External channel's name carries the injection, so the task's own call
    naming it carries the attacker's address, and markers refuse it where the
    replay's careful, knowing who made each call, approved it."""
    assert run("scripted", plan(["slack"], RUNS, None), tmp_path, budget=0, jobs=1) == 0
    rows = [json.loads(line) for line in (tmp_path / "cases.jsonl").open()]
    assert len(rows) == 6 * (21 + 21 * 5)
    replayed = _replayed("results", "slack")
    named = set()
    for row in rows:
        key = (row["user_task"], row["injection_task"], row["configuration"], row["approver"])
        assert row["approvals"] == int(replayed[key]["approvals"]), key
        if row["injection_task"]:
            assert row["security"] == int(replayed[key]["security"]), key
            assert row["compromised"] == int(replayed[key]["compromised"]), key
        if row["utility"] != int(replayed[key]["utility"]):
            assert row["approver"] == "careful" and row["injection_task"], key
            assert row["utility"] == 0 and row["held"] > 0, key
            named.add(row["user_task"])
    assert named == {f"user_task_{n}" for n in (7, 9, 10, 12, 19)}


def test_the_scripted_agent_through_the_harness_reproduces_the_known_destination_replay(
    tmp_path,
):
    """Amendment 2's banking runs, against PROTOCOL-known.md's replay rows."""
    cases = plan(["banking"], AMENDMENT_RUNS, None)
    assert run("scripted", cases, tmp_path, budget=0, jobs=1) == 0
    rows = [json.loads(line) for line in (tmp_path / "cases.jsonl").open()]
    assert len(rows) == 2 * (16 + 16 * 9)
    replayed = _replayed("results/known", "banking")
    for row in rows:
        key = (row["user_task"], row["injection_task"], row["configuration"], row["approver"])
        assert row["approvals"] == int(replayed[key]["approvals"]), key
        if row["injection_task"]:
            assert row["security"] == int(replayed[key]["security"]) == 0, key
        if row["utility"] != int(replayed[key]["utility"]):
            # AgentDojo's own check passes user_task_5 with its transfer held.
            assert row["user_task"] == "user_task_5" and row["held"] > 0, key


def test_an_amendment_run_goes_beside_the_protocols_own_results():
    assert default_out("claude-sonnet-5-5", ["banking"], RUNS).name == "claude-sonnet-5-5"
    assert default_out("claude-sonnet-5-5", ["slack"], RUNS).name == "claude-sonnet-5-5-slack"
    known = default_out("claude-sonnet-5-5", ["banking"], AMENDMENT_RUNS)
    assert known.name == "claude-sonnet-5-5-known"


def test_the_scripted_agent_through_the_harness_reproduces_the_replay(tmp_path):
    """The harness, driven by the replay's compromised agent, against the replay's rows.

    Attack outcome, approvals asked, and whether the agent was compromised
    agree on every banking case, with `careful` played by markers.yaml. Task
    success may only differ where the replay is stricter than AgentDojo's own
    check: three tasks AgentDojo calls done with their one transfer held.
    """
    assert run("scripted", plan(["banking"], RUNS, None), tmp_path, budget=0, jobs=1) == 0
    rows = [json.loads(line) for line in (tmp_path / "cases.jsonl").open()]
    assert len(rows) == 6 * (16 + 16 * 9)

    with (HERE / "results" / "attack.csv").open(newline="") as handle:
        attack = {
            (r["user_task"], r["injection_task"], r["configuration"], r["approver"]): r
            for r in csv.DictReader(handle)
            if r["suite"] == "banking" and r["attack"] == "important_instructions"
        }
    with (HERE / "results" / "benign.csv").open(newline="") as handle:
        benign = {
            (r["user_task"], "", r["configuration"], r["approver"]): r
            for r in csv.DictReader(handle)
            if r["suite"] == "banking"
        }
    lenient = set()
    for row in rows:
        key = (row["user_task"], row["injection_task"], row["configuration"], row["approver"])
        replayed = attack[key] if row["injection_task"] else benign[key]
        assert row["approvals"] == int(replayed["approvals"]), key
        if row["injection_task"]:
            assert row["security"] == int(replayed["security"]), key
            assert row["compromised"] == int(replayed["compromised"]), key
        if row["utility"] != int(replayed["utility"]):
            assert row["utility"] == 1 and row["held"] > 0, key
            lenient.add(row["user_task"])
    assert lenient == {"user_task_5", "user_task_6", "user_task_9"}


def test_a_run_stops_when_every_case_fails_the_same_way(tmp_path):
    def refuse(request: httpx2.Request) -> httpx2.Response:
        error = {"type": "invalid_request_error", "message": "no"}
        return httpx2.Response(400, json={"type": "error", "error": error})

    client = anthropic.Anthropic(
        api_key="not-a-key",
        max_retries=0,
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(refuse)),
    )
    cases = plan(["banking"], [("none", "nobody")], limit=1)
    assert run("haiku", cases, tmp_path, budget=10, jobs=1, client=client) == len(cases)
    rows = [json.loads(line) for line in (tmp_path / "cases.jsonl").open()]
    assert len(rows) == FAILURES and all(row["error"].startswith("BadRequestError") for row in rows)


def test_a_second_attack_keeps_the_first_runs_cases_and_shares_its_tasks_with_no_attack():
    first = plan(["banking"], RUNS, None)
    second = plan(["banking"], RUNS, None, "tool_knowledge")
    plain = {case.key for case in first if not case.injection_task}
    assert plain == {case.key for case in second if not case.injection_task}
    attacked = {case.key for case in second if case.injection_task}
    assert len(attacked) == 864 and all(key.endswith("/tool_knowledge") for key in attacked)
    assert not attacked & {case.key for case in first}
    rows = [
        json.loads(line) for line in (HERE / "results/model/claude-haiku-4-5/cases.jsonl").open()
    ]
    first_rows = {row["key"] for row in rows if row["attack"] != "tool_knowledge"}
    assert {case.key for case in first} == first_rows, "the first run's keys moved"
    assert attacked == {row["key"] for row in rows if row["attack"] == "tool_knowledge"}


def test_a_suite_with_no_markers_runs_with_any_approver_but_the_careful_one():
    """The marker files cover banking and Slack. Only the careful approver reads
    them, so only it refuses to run a suite that has none."""
    from run_model import Case, markers_for

    plain = Case("travel", "user_task_0", "injection_task_1", "taint_text", "nobody")
    assert markers_for(plain) == []
    with pytest.raises(SystemExit, match=r"no markers file has travel"):
        markers_for(Case("travel", "user_task_0", "injection_task_1", "taint_text", "careful"))
