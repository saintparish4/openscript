"""PROTOCOL-named.md's tables, from the rows, and the exact re-score of the model runs.

    python evals/agentdojo/summarize_named.py     # markdown to stdout, results/named/summary.json

Reads results/named/*.csv (taint_named), results/known/*.csv (taint_known)
and the committed results/*.csv (approve_all, taint_text). As in
summarize_known.py, attacks are counted over the pairs where the undefended
attack works, and an attacker call is "released" when more of them ran than
under taint_text, pair for pair.

The re-score puts the ordinary tasks of the committed careful-approver runs
with a model (taint_text: Sonnet 5.5 on banking and Slack, Haiku 4.5 on
banking) through taint_named, in the order the calls were made. Their careful
approver approved every ordinary call, so holding one changed nothing that
followed and the re-score is exact; the count without the candidate must equal
the approvals the run recorded, or nothing is written.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))

from named import NamedTaintPolicy, load_named  # noqa: E402
from rescore_known import held  # noqa: E402
from summarize_known import MAIN_ATTACK, SUITES, Row, _fmt, _read, _share  # noqa: E402

from sdk.policies.session_taint import SessionTaintPolicy  # noqa: E402

#: (configuration, where its rows are)
COLUMNS = (
    ("approve_all", "."),
    ("taint_text", "."),
    ("taint_known", "known"),
    ("taint_named", "named"),
)
#: (results/model directory, suite) for the re-score.
MODEL_RUNS = (
    ("claude-sonnet-5-5", "banking"),
    ("claude-sonnet-5-5-slack", "slack"),
    ("claude-haiku-4-5", "banking"),
)


def tables(rows: dict[str, tuple[list[Row], list[Row]]]) -> dict[str, Any]:
    """*rows* maps where ("." for the committed rows, "known", "named") to
    (benign, attack) rows."""
    attack_rows = {
        where: [r for r in attack if r.get("attack", MAIN_ATTACK) == MAIN_ATTACK]
        for where, (_, attack) in rows.items()
    }
    working = {
        (r["suite"], r["user_task"], r["injection_task"])
        for r in attack_rows["."]
        if r["configuration"] == "none" and r["security"] == "1"
    }

    def pick(kind: str, where: str, configuration: str, approver: str, suite: str) -> list[Row]:
        source = rows[where][0] if kind == "benign" else attack_rows[where]
        return [
            r
            for r in source
            if r["configuration"] == configuration
            and r["approver"] == approver
            and (suite == "all" or r["suite"] == suite)
            and (kind == "benign" or (r["suite"], r["user_task"], r["injection_task"]) in working)
        ]

    out: dict[str, Any] = {"benign": {}, "attack": {}, "released": []}
    for suite in (*SUITES, "all"):
        out["benign"][suite] = {}
        out["attack"][suite] = {}
        for configuration, where in COLUMNS:
            asked = pick("benign", where, configuration, "nobody", suite)
            careful = pick("attack", where, configuration, "careful", suite)
            out["benign"][suite][configuration] = {
                "needed_a_person": _share(sum(r["approvals"] != "0" for r in asked), len(asked)),
                "done_with_nobody": _share(sum(r["utility"] == "1" for r in asked), len(asked)),
            }
            out["attack"][suite][configuration] = {
                "succeeded": _share(sum(r["security"] == "1" for r in careful), len(careful)),
            }
    baseline = {
        (r["suite"], r["user_task"], r["injection_task"]): int(r["inj_ran"])
        for r in pick("attack", ".", "taint_text", "careful", "all")
    }
    for r in pick("attack", "named", "taint_named", "careful", "all"):
        pair = (r["suite"], r["user_task"], r["injection_task"])
        extra = int(r["inj_ran"]) - baseline[pair]
        if extra > 0:
            out["released"].append(
                {"pair": list(pair), "calls": extra, "succeeded": r["security"] == "1"}
            )
    return out


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _request(messages: list[dict[str, Any]]) -> str:
    """The user's own request: the first user message, never a tool's result."""
    first = next(m for m in messages if m["role"] == "user")
    return " ".join(block.get("content", "") for block in first["content"] or [])


def rescore() -> dict[str, Any]:
    lists = yaml.safe_load((HERE / "classification.yaml").read_text())["suites"]
    known = yaml.safe_load((HERE / "known.yaml").read_text())["suites"]
    named = load_named()["suites"]
    out: dict[str, Any] = {}
    for directory, suite in MODEL_RUNS:
        base = HERE / "results" / "model" / directory
        rows = {r["key"]: r for r in _jsonl(base / "cases.jsonl")}
        tasks: dict[str, tuple[int, int]] = {}
        for transcript in _jsonl(base / "transcripts.jsonl"):
            row = rows[transcript["key"]]
            if row["injection_task"] or (row["configuration"], row["approver"]) != (
                "taint_text",
                "careful",
            ):
                continue
            sources, sinks = lists[suite]["sources"], lists[suite]["sinks"]
            old = held(SessionTaintPolicy(sources=sources, sinks=sinks), transcript["messages"])
            if old != row["approvals"]:
                raise SystemExit(
                    f"{directory} {row['user_task']}: re-scored {old} held calls, the run "
                    f"recorded {row['approvals']}; the re-score is not exact, nothing is written"
                )
            candidate = NamedTaintPolicy(
                sources=sources,
                sinks=sinks,
                destinations=named[suite],
                said_by_user=_request(transcript["messages"]),
                known=known.get(suite) or None,
            )
            tasks[row["user_task"]] = (old, held(candidate, transcript["messages"]))
        out[directory] = {
            "suite": suite,
            "tasks": len(tasks),
            "taint_text": sum(old > 0 for old, _ in tasks.values()),
            "taint_named": sum(new > 0 for _, new in tasks.values()),
            "by_task": {task: list(counts) for task, counts in sorted(tasks.items())},
        }
    return out


def markdown(summary: dict[str, Any], rescored: dict[str, Any]) -> str:
    lines = [
        "Ordinary tasks needing a person (nobody approving):",
        "",
        "| Suite | approve_all | taint_text | taint_known | taint_named |",
        "|---|---|---|---|---|",
    ]
    for suite, by in summary["benign"].items():
        cells = [_fmt(by[c]["needed_a_person"]) for c, _ in COLUMNS]
        lines.append(f"| {suite} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "Ordinary tasks done with nobody approving:",
        "",
        "| Suite | approve_all | taint_text | taint_known | taint_named |",
        "|---|---|---|---|---|",
    ]
    for suite, by in summary["benign"].items():
        cells = [_fmt(by[c]["done_with_nobody"]) for c, _ in COLUMNS]
        lines.append(f"| {suite} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "Attacks that succeeded, careful approver, over pairs where the undefended attack works:",
        "",
        "| Suite | approve_all | taint_text | taint_known | taint_named |",
        "|---|---|---|---|---|",
    ]
    for suite, by in summary["attack"].items():
        cells = [_fmt(by[c]["succeeded"]) for c, _ in COLUMNS]
        lines.append(f"| {suite} | " + " | ".join(cells) + " |")
    released = summary["released"]
    lines += [
        "",
        f"Attacker calls released under taint_named: {sum(r['calls'] for r in released)} "
        f"calls in {len(released)} pairs",
    ]
    lines += [
        f"- {'/'.join(r['pair'])}: {r['calls']}, succeeded {r['succeeded']}" for r in released
    ]
    lines += ["", "Model runs re-scored (ordinary tasks needing a person):"]
    for directory, r in rescored.items():
        lines.append(
            f"- {directory} ({r['suite']}): taint_text {r['taint_text']}/{r['tasks']}, "
            f"taint_named {r['taint_named']}/{r['tasks']}"
        )
    return "\n".join(lines)


def main() -> int:
    rows = {
        where: (
            _read(HERE / "results" / where / "benign.csv"),
            _read(HERE / "results" / where / "attack.csv"),
        )
        for where in (".", "known", "named")
    }
    summary = tables(rows)
    rescored = rescore()
    out = HERE / "results" / "named"
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    (out / "rescore.json").write_text(json.dumps(rescored, indent=1) + "\n")
    print(markdown(summary, rescored))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
