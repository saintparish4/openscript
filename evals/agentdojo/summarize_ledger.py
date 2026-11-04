"""PROTOCOL-ledger.md's tables, from what the effect side recorded.

    python evals/agentdojo/summarize_ledger.py   # markdown, results/ledger/summary.json

Reads results/ledger/*.csv. Every effect count here is the ledger's, not the
wrapper's. The one number taken from the wrapper, inj_irreversible_ran, is
read only to check it against the ledger. As in summarize.py, attacks are
counted over the pairs where the undefended attack works, from the
committed results/attack.csv.
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
#: The runs PROTOCOL-ledger.md names, in its order.
RUNS = (
    ("taint_text", "careful", "record"),
    ("taint_irreversible", "careful", "record"),
    ("approve_irreversible", "careful", "record"),
    ("approve_irreversible", "careful", "enforce"),
    ("taint_irreversible", "careful", "enforce"),
    ("none", "nobody", "enforce"),
)


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


def _total(rows: list[Row], column: str) -> int:
    return sum(int(r[column]) for r in rows)


def tables(committed_attack: list[Row], benign: list[Row], attack: list[Row]) -> dict[str, Any]:
    working = {
        (r["suite"], r["user_task"], r["injection_task"])
        for r in committed_attack
        if r["attack"] == MAIN_ATTACK and r["configuration"] == "none" and r["security"] == "1"
    }
    out: dict[str, Any] = {}
    for configuration, approver, mode in RUNS:
        name = f"{configuration}/{approver}/{mode}"

        def mine(
            rows: list[Row], *, cfg: str = configuration, who: str = approver, m: str = mode
        ) -> list[Row]:
            return [
                r
                for r in rows
                if r["configuration"] == cfg and r["approver"] == who and r["ledger"] == m
            ]

        b = mine(benign)
        a = [
            r for r in mine(attack) if (r["suite"], r["user_task"], r["injection_task"]) in working
        ]
        disagree = [
            [r["suite"], r["user_task"], r["injection_task"]]
            for r in a
            if mode == "record" and r["ledger_inj_applied"] != r["inj_irreversible_ran"]
        ]
        out[name] = {
            "benign": {
                "done": _share(sum(r["utility"] == "1" for r in b), len(b)),
                "needed_a_person": _share(sum(r["approvals"] != "0" for r in b), len(b)),
                "irreversible_applied": _total(b, "ledger_user_applied"),
                "applied_without_a_person": _total(b, "ledger_user_untokened"),
                "tasks_with_one_applied_without_a_person": sum(
                    r["ledger_user_untokened"] != "0" for r in b
                ),
                "refused_at_the_effect": _total(b, "ledger_refused"),
            },
            "attack": {
                "succeeded": _share(sum(r["security"] == "1" for r in a), len(a)),
                "user_task_done": _share(sum(r["utility"] == "1" for r in a), len(a)),
                "attacker_irreversible_applied": _total(a, "ledger_inj_applied"),
                "attacker_applied_without_a_person": _total(a, "ledger_inj_untokened"),
                "pairs_with_an_attacker_effect": sum(r["ledger_inj_applied"] != "0" for r in a),
                "injection_tasks_with_an_attacker_effect": sorted(
                    {
                        f"{r['suite']}/{r['injection_task']}"
                        for r in a
                        if r["ledger_inj_applied"] != "0"
                    }
                ),
                "refused_at_the_effect": _total(a, "ledger_refused"),
                "ledger_and_wrapper_disagree": disagree,
            },
        }
    return out


def _fmt(share: dict[str, Any]) -> str:
    return f"{share['n']}/{share['of']} ({share['pct']}%)" if share["of"] else "n/a"


def markdown(summary: dict[str, Any]) -> str:
    lines = [
        "| Run | Ordinary tasks done | Needed a person | Task effects with no person | "
        "Attacks succeeded | Attacker effects applied | Pairs | Refused at the effect (attack) "
        "| Ledger and wrapper disagree |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, s in summary.items():
        b, a = s["benign"], s["attack"]
        lines.append(
            f"| {name} | {_fmt(b['done'])} | {_fmt(b['needed_a_person'])} | "
            f"{b['applied_without_a_person']} in {b['tasks_with_one_applied_without_a_person']} tasks | "
            f"{_fmt(a['succeeded'])} | {a['attacker_irreversible_applied']} "
            f"({a['attacker_applied_without_a_person']} with no person) | "
            f"{a['pairs_with_an_attacker_effect']} | {a['refused_at_the_effect']} | "
            f"{len(a['ledger_and_wrapper_disagree'])} pairs |"
        )
    for name, s in summary.items():
        through = s["attack"]["injection_tasks_with_an_attacker_effect"]
        if through:
            lines.append(f"\n{name}: attacker effects applied in {', '.join(through)}")
    return "\n".join(lines)


def main() -> int:
    results = HERE / "results"
    summary = tables(
        _read(results / "attack.csv"),
        _read(results / "ledger" / "benign.csv"),
        _read(results / "ledger" / "attack.csv"),
    )
    (results / "ledger" / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(markdown(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
