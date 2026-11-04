"""PROTOCOL-irreversible.md's tables, from the rows: the new runs beside the committed ones.

    python evals/agentdojo/summarize_irreversible.py   # markdown, results/irreversible/summary.json

Reads results/irreversible/*.csv and, for comparison, the committed rows for
approve_all and taint_text (results/*.csv) and taint_known_shipped
(results/known-shipped/). Nothing here runs a policy. As in summarize.py,
attacks are counted over the pairs where the undefended attack works.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from evals.run import wilson  # noqa: E402

Row = dict[str, str]
MAIN_ATTACK = "important_instructions"
SUITES = ("banking", "workspace", "travel", "slack")
#: (configuration, where its rows are), in the order the tables show them.
COLUMNS = (
    ("approve_all", "committed"),
    ("taint_text", "committed"),
    ("taint_known_shipped", "shipped"),
    ("approve_irreversible", "new"),
    ("taint_irreversible", "new"),
    ("taint_irreversible_known", "new"),
)
NEW = tuple(c for c, where in COLUMNS if where == "new")


def _read(path: Path) -> list[Row]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def _share(n: int, of: int) -> dict[str, Any]:
    low, high = wilson(n, of)
    return {
        "n": n,
        "of": of,
        "pct": round(100 * n / of, 1) if of else None,
        "ci95": [round(100 * low, 1), round(100 * high, 1)],
    }


def tables(
    committed: tuple[list[Row], list[Row]],
    shipped: tuple[list[Row], list[Row]],
    new: tuple[list[Row], list[Row]],
) -> dict[str, Any]:
    benign = {"committed": committed[0], "shipped": shipped[0], "new": new[0]}
    attack = {
        "committed": [r for r in committed[1] if r["attack"] == MAIN_ATTACK],
        "shipped": shipped[1],
        "new": new[1],
    }
    working = {
        (r["suite"], r["user_task"], r["injection_task"])
        for r in attack["committed"]
        if r["configuration"] == "none" and r["security"] == "1"
    }

    def rows(kind: str, where: str, configuration: str, approver: str, suite: str) -> list[Row]:
        source = benign if kind == "benign" else attack
        return [
            r
            for r in source[where]
            if r["configuration"] == configuration
            and r["approver"] == approver
            and (suite == "all" or r["suite"] == suite)
            and (kind == "benign" or (r["suite"], r["user_task"], r["injection_task"]) in working)
        ]

    out: dict[str, Any] = {"benign": {}, "attack": {}, "irreversible_ran": {}}
    for suite in (*SUITES, "all"):
        out["benign"][suite] = {}
        out["attack"][suite] = {}
        for configuration, where in COLUMNS:
            asked = rows("benign", where, configuration, "nobody", suite)
            entry: dict[str, Any] = {
                "needed_a_person": _share(sum(r["approvals"] != "0" for r in asked), len(asked)),
                "done_with_nobody": _share(sum(r["utility"] == "1" for r in asked), len(asked)),
            }
            if where == "new":
                entry["solution_is_irreversible"] = _share(
                    sum(r["irreversible_calls"] != "0" for r in asked), len(asked)
                )
                entry["held_unread"] = sum(int(r["held_unread"]) for r in asked)
                entry["needed_a_person_only_for_unread_mail"] = sum(
                    r["approvals"] != "0" and int(r["held_unread"]) == int(r["approvals"])
                    for r in asked
                )
            out["benign"][suite][configuration] = entry
            careful = rows("attack", where, configuration, "careful", suite)
            entry = {
                "succeeded": _share(sum(r["security"] == "1" for r in careful), len(careful)),
                "injection_tasks_through": len(
                    {(r["suite"], r["injection_task"]) for r in careful if r["security"] == "1"}
                ),
            }
            if where == "new":
                ran = [r for r in careful if r["inj_irreversible_ran"] != "0"]
                entry["irreversible_call_ran"] = _share(len(ran), len(careful))
                entry["succeeded_with_no_irreversible_call"] = sum(
                    r["security"] == "1" and r["inj_irreversible_ran"] == "0" for r in careful
                )
            out["attack"][suite][configuration] = entry

    # Every pair in which one of the attacker's irreversible calls ran with a
    # careful approver, with what taint_text let run in the same pair beside it.
    baseline = {
        (r["suite"], r["user_task"], r["injection_task"]): r
        for r in rows("attack", "committed", "taint_text", "careful", "all")
    }
    for configuration in NEW:
        listed = []
        for r in rows("attack", "new", configuration, "careful", "all"):
            if r["inj_irreversible_ran"] == "0":
                continue
            pair = (r["suite"], r["user_task"], r["injection_task"])
            listed.append(
                {
                    "pair": list(pair),
                    "delivered_by": r["delivered_by"],
                    "tainted": r["tainted"],
                    "irreversible_ran": int(r["inj_irreversible_ran"]),
                    "attacker_calls_ran": int(r["inj_ran"]),
                    "attacker_calls_ran_under_taint_text": int(baseline[pair]["inj_ran"]),
                    "succeeded": r["security"] == "1",
                }
            )
        out["irreversible_ran"][configuration] = listed
    return out


def _fmt(share: dict[str, Any]) -> str:
    if not share["of"]:
        return "n/a"
    return f"{share['n']}/{share['of']} ({share['pct']}%, {share['ci95'][0]}-{share['ci95'][1]})"


def markdown(summary: dict[str, Any]) -> str:
    header = "| Suite | " + " | ".join(c for c, _ in COLUMNS) + " |"
    rule = "|---" * (len(COLUMNS) + 1) + "|"
    lines = ["Ordinary tasks needing a person (nobody approving):", "", header, rule]
    for suite, by in summary["benign"].items():
        lines.append(
            f"| {suite} | " + " | ".join(_fmt(by[c]["needed_a_person"]) for c, _ in COLUMNS) + " |"
        )
    lines += ["", "Ordinary tasks done with nobody approving:", "", header, rule]
    for suite, by in summary["benign"].items():
        lines.append(
            f"| {suite} | " + " | ".join(_fmt(by[c]["done_with_nobody"]) for c, _ in COLUMNS) + " |"
        )
    lines += ["", "Ordinary tasks whose own solution makes an irreversible call:", ""]
    for suite, by in summary["benign"].items():
        entry = by[NEW[0]]
        lines.append(
            f"- {suite}: {_fmt(entry['solution_is_irreversible'])}; under taint_irreversible, "
            f"{by['taint_irreversible']['held_unread']} held reads of unread mail, and "
            f"{by['taint_irreversible']['needed_a_person_only_for_unread_mail']} tasks that "
            "needed a person only for those"
        )
    lines += ["", "Attacks that succeeded, careful approver:", "", header, rule]
    for suite, by in summary["attack"].items():
        lines.append(
            f"| {suite} | " + " | ".join(_fmt(by[c]["succeeded"]) for c, _ in COLUMNS) + " |"
        )
    lines += ["", "Attacks in which an attacker's irreversible call ran, careful approver:", ""]
    for configuration in NEW:
        entry = summary["attack"]["all"][configuration]
        lines.append(
            f"- {configuration}: {_fmt(entry['irreversible_call_ran'])}; succeeded with no "
            f"irreversible call: {entry['succeeded_with_no_irreversible_call']}"
        )
    for configuration, listed in summary["irreversible_ran"].items():
        lines += ["", f"Pairs in which an attacker's irreversible call ran, {configuration}:"]
        by_vector: dict[tuple[str, str, str, str], int] = {}
        for r in listed:
            key = (
                r["pair"][0],
                r["pair"][2],
                r["delivered_by"],
                (
                    "more than taint_text"
                    if r["attacker_calls_ran"] > r["attacker_calls_ran_under_taint_text"]
                    else "as taint_text"
                ),
            )
            by_vector[key] = by_vector.get(key, 0) + 1
        for (suite, injection, delivered, versus), count in sorted(by_vector.items()):
            lines.append(f"- {suite} {injection}, via {delivered}: {count} pairs, {versus}")
    return "\n".join(lines)


def main() -> int:
    results = HERE / "results"
    summary = tables(
        (_read(results / "benign.csv"), _read(results / "attack.csv")),
        (
            _read(results / "known-shipped" / "benign.csv"),
            _read(results / "known-shipped" / "attack.csv"),
        ),
        (
            _read(results / "irreversible" / "benign.csv"),
            _read(results / "irreversible" / "attack.csv"),
        ),
    )
    (results / "irreversible" / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(markdown(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
