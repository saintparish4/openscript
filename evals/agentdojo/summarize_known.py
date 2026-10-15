"""PROTOCOL-known.md's tables, from the rows: the new runs beside the committed ones.

    python evals/agentdojo/summarize_known.py     # markdown to stdout, results/known/summary.json

Reads results/known/*.csv (taint_known, and taint_directory on Slack) and the
committed results/*.csv (approve_all, taint_text). Nothing here runs a policy:
every number is a count over rows replay.py wrote. As in summarize.py, attacks
are counted over the pairs where the undefended attack works.
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
#: (configuration, where its rows are)
COLUMNS = (
    ("approve_all", "committed"),
    ("taint_text", "committed"),
    ("taint_known", "known"),
    ("taint_directory", "known"),
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


def tables(
    committed: tuple[list[Row], list[Row]], known: tuple[list[Row], list[Row]]
) -> dict[str, Any]:
    benign = {"committed": committed[0], "known": known[0]}
    attack = {
        "committed": [r for r in committed[1] if r["attack"] == MAIN_ATTACK],
        "known": known[1],
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

    out: dict[str, Any] = {"benign": {}, "attack": {}, "released": {}}
    for suite in (*SUITES, "all"):
        out["benign"][suite] = {}
        out["attack"][suite] = {}
        for configuration, where in COLUMNS:
            asked = rows("benign", where, configuration, "nobody", suite)
            if not asked:
                continue
            out["benign"][suite][configuration] = {
                "needed_a_person": _share(sum(r["approvals"] != "0" for r in asked), len(asked)),
                "done_with_nobody": _share(sum(r["utility"] == "1" for r in asked), len(asked)),
            }
            careful = rows("attack", where, configuration, "careful", suite)
            out["attack"][suite][configuration] = {
                "succeeded": _share(sum(r["security"] == "1" for r in careful), len(careful)),
                "injection_tasks_through": len(
                    {(r["suite"], r["injection_task"]) for r in careful if r["security"] == "1"}
                ),
            }

    # Attacker calls that ran with no person because their destination was
    # known: more of the attacker's calls ran than under taint_text, pair for pair.
    baseline = {
        (r["suite"], r["user_task"], r["injection_task"]): int(r["inj_ran"])
        for r in rows("attack", "committed", "taint_text", "careful", "all")
    }
    for configuration in ("taint_known", "taint_directory"):
        released = []
        for r in rows("attack", "known", configuration, "careful", "all"):
            pair = (r["suite"], r["user_task"], r["injection_task"])
            extra = int(r["inj_ran"]) - baseline[pair]
            if extra > 0:
                released.append(
                    {"pair": list(pair), "calls": extra, "succeeded": r["security"] == "1"}
                )
        out["released"][configuration] = released
    return out


def _fmt(share: dict[str, Any]) -> str:
    if not share["of"]:
        return "n/a"
    return f"{share['n']}/{share['of']} ({share['pct']}%, {share['ci95'][0]}-{share['ci95'][1]})"


def markdown(summary: dict[str, Any]) -> str:
    lines = [
        "Ordinary tasks needing a person (nobody approving):",
        "",
        "| Suite | approve_all | taint_text | taint_known | taint_directory |",
        "|---|---|---|---|---|",
    ]
    for suite, by in summary["benign"].items():
        cells = [_fmt(by[c]["needed_a_person"]) if c in by else "—" for c, _ in COLUMNS]
        lines.append(f"| {suite} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "Attacks that succeeded, careful approver, over pairs where the undefended attack works:",
        "",
        "| Suite | approve_all | taint_text | taint_known | taint_directory |",
        "|---|---|---|---|---|",
    ]
    for suite, by in summary["attack"].items():
        cells = [_fmt(by[c]["succeeded"]) if c in by else "—" for c, _ in COLUMNS]
        lines.append(f"| {suite} | " + " | ".join(cells) + " |")
    for configuration, released in summary["released"].items():
        lines += [
            "",
            f"Attacker calls released by a known destination under {configuration}: "
            f"{sum(r['calls'] for r in released)} calls in {len(released)} pairs",
        ]
        for r in released[:20]:
            lines.append(
                f"- {'/'.join(r['pair'])}: {r['calls']} call(s), attack succeeded: {r['succeeded']}"
            )
    return "\n".join(lines)


def main() -> int:
    summary = tables(
        (_read(HERE / "results" / "benign.csv"), _read(HERE / "results" / "attack.csv")),
        (
            _read(HERE / "results" / "known" / "benign.csv"),
            _read(HERE / "results" / "known" / "attack.csv"),
        ),
    )
    (HERE / "results" / "known" / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(markdown(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
