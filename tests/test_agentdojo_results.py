"""The AgentDojo replay's published numbers, held to the rows they came from.

The replay itself needs AgentDojo, which lives in its own environment and is
not installed here (evals/agentdojo/README.md). What can be checked without it
is everything that could drift after the run: that the summary is what the
per-case rows add up to, and that the two files written before any result
existed have not been edited since.
"""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parents[1] / "evals" / "agentdojo"

# sha256 of the files as committed in the freeze, before any defended
# configuration was run. A change to either is a new version of the protocol,
# to be labelled as one, and this is where that has to be said out loud.
FROZEN = {
    "classification.yaml": "acf0bdf1147787164a3a8504da52316d202079599d005a4c540357d9696e6103",
    "PROTOCOL.md": "e59f13d2f09ba361b137bd3f115c04127fca6449c1feb8cc43dd0cc415a2bbe1",
    # The run with a model, frozen before any model was sent a request.
    "PROTOCOL-model.md": "5146bd42aae523d5aa966b5cea5f2b2a784e0e16cccac70341e76d0e68aa63b6",
    "markers.yaml": "275ba25d153a1e125f573b8c5f904249ef6407fe5cf4165657bd7ff7014cce51",
}


def _summarize():
    spec = importlib.util.spec_from_file_location("agentdojo_summarize", HERE / "summarize.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _rows(name: str) -> list[dict[str, str]]:
    with (HERE / "results" / name).open(newline="") as handle:
        return list(csv.DictReader(handle))


def test_the_protocol_and_the_tool_lists_have_not_moved_since_the_freeze():
    for name, digest in FROZEN.items():
        assert hashlib.sha256((HERE / name).read_bytes()).hexdigest() == digest, (
            f"{name} was written before any result and is frozen. If the change is "
            "deliberate it is a new, labelled version: say so in evals/agentdojo/README.md, "
            "re-run what it governs, and update this hash."
        )


def test_no_tool_is_listed_as_both_untrusted_and_harmless():
    suites = yaml.safe_load((HERE / "classification.yaml").read_text())["suites"]
    assert set(suites) == {"workspace", "travel", "banking", "slack"}
    for name, lists in suites.items():
        acted_on = set(lists["sources"]) | set(lists["sinks"])
        assert not acted_on & set(lists["neither"]), name
        for key in ("sources", "sinks", "neither"):
            assert len(lists[key]) == len(set(lists[key])), f"{name}.{key} repeats a tool"


def test_the_published_summary_is_what_the_per_case_rows_add_up_to():
    summarize = _summarize()
    recomputed = {
        "benign": summarize.benign_table(_rows("benign.csv")),
        "attack": summarize.attack_tables(_rows("attack.csv")),
    }
    published = json.loads((HERE / "results" / "summary.json").read_text())
    assert json.loads(json.dumps(recomputed)) == published


def test_every_pair_and_every_task_is_in_the_results_once_per_run():
    """Nothing sampled, nothing dropped: 97 user tasks and 949 pairs."""
    benign, attack = _rows("benign.csv"), _rows("attack.csv")
    tasks = {(row["suite"], row["user_task"]) for row in benign}
    assert len(tasks) == 97
    runs = {(row["configuration"], row["approver"]) for row in benign}
    assert len(benign) == len(tasks) * len(runs)

    main = [row for row in attack if row["attack"] == "important_instructions"]
    pairs = {(row["suite"], row["user_task"], row["injection_task"]) for row in main}
    assert len(pairs) == 949
    runs = {(row["configuration"], row["approver"]) for row in main}
    assert len(main) == len(pairs) * len(runs)


def test_the_undefended_replay_solves_every_task_with_its_own_solution():
    """The harness's own baseline: if this is not 97 of 97, a number further
    down the table is about the harness and not about a policy."""
    alone = [row for row in _rows("benign.csv") if row["configuration"] == "none"]
    assert len(alone) == 97 and all(row["utility"] == "1" for row in alone)


def test_an_approver_who_approves_everything_is_no_defence():
    """Asserted because it is the claim the rest depends on: a held call is
    only worth what the person answering it does."""
    attack = [row for row in _rows("attack.csv") if row["attack"] == "important_instructions"]
    undefended = {
        (r["suite"], r["user_task"], r["injection_task"]): r["security"]
        for r in attack
        if r["configuration"] == "none"
    }
    stamped = [r for r in attack if r["approver"] == "rubber_stamp"]
    assert stamped
    for row in stamped:
        assert row["security"] == undefended[row["suite"], row["user_task"], row["injection_task"]]
