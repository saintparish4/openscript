"""Measure what the input-side policies actually catch, and what they wrongly catch.

    python evals/run.py                 # markdown table, pattern policies only
    python evals/run.py --semantic      # also score with SemanticPolicy added ([ml] extra)
    python evals/run.py --json          # machine-readable
    python evals/run.py --misses        # every prompt the policies got wrong
    python evals/run.py --out DIR       # per-case rows + a manifest of what ran

Unit tests assert that a handful of chosen prompts behave. They cannot say
whether the detection rate is 95% or 60%, and they say nothing at all about
how often ordinary text gets blocked — which for a security tool is the number
that decides whether anyone leaves it switched on.

Each dataset in datasets/ is a JSONL file of labelled prompts:

    {"text": ..., "label": "attack" | "benign", "category": ..., "tag": ...}

`tag` is "plain" or "obfuscated:<technique>". The obfuscated rows are the same
attacks as the plain ones, rewritten the way someone trying to get past a
pattern bank would rewrite them, so the two rates can be read separately.

`expect` is "block" or "flag". A handful of attack rows are meant to score and
deliberately not block — an expression of suicidal intent earns crisis
resources rather than a refusal, and intimidation short of a threat is worth
recording without stopping the conversation. Calling those misses would hide a
design decision; calling them detections would inflate the headline. They get
their own column.

The benign rows are deliberately adversarial in the other direction: they share
vocabulary with the attacks and differ only in intent (reporting on a thing,
teaching about it, defending against it). Scoring 100% detection is easy if
false positives do not count.

How a row is scored
-------------------
Through the real entry point: the policies are constructed with their shipped
defaults, wrapped in a SecureAgent, and the prompt is invoked. "Blocked" means
the pipeline raised ActionBlockedError, and nothing else. A row whose scoring
*crashed* is an error, not a miss: it is counted separately and left out of
every rate, so a harness that fails on every input cannot score like a policy
that carefully found nothing.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import math
import platform
import statistics
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from contracts.interceptor import Policy  # noqa: E402
from contracts.types import ActionBlockedError  # noqa: E402
from sdk import (  # noqa: E402
    HarmfulRequestPolicy,
    PromptInjectionPolicy,
    SecureAgent,
    ToxicityPolicy,
)

DATASETS = Path(__file__).resolve().parent / "datasets"

PolicyFactory = Callable[[], Sequence[Policy]]


def _all_patterns() -> list[Policy]:
    return [PromptInjectionPolicy(), ToxicityPolicy(), HarmfulRequestPolicy()]


_SEMANTIC: list[Policy] = []


def _semantic() -> Policy:
    """Built once: the encoder is the expensive part and it is stateless."""
    if not _SEMANTIC:
        from sdk.policies.semantic import SemanticPolicy

        _SEMANTIC.append(SemanticPolicy())
    return _SEMANTIC[0]


def _with_semantic() -> list[Policy]:
    # After the pattern policies, as it is meant to be deployed.
    return [*_all_patterns(), _semantic()]


# corpus key -> (display name, the policies that corpus is scored against)
CORPORA: dict[str, tuple[str, PolicyFactory]] = {
    "prompt_injection": ("Prompt injection", lambda: [PromptInjectionPolicy()]),
    "toxicity": ("Toxicity", lambda: [ToxicityPolicy()]),
    "harmful_request": ("Harmful request", lambda: [HarmfulRequestPolicy()]),
    # paraphrase_dev was written after the patterns were tuned and then used to
    # find gaps, which spent it: a set you fix against stops measuring
    # generalization the moment you fix against it. It is kept because it still
    # catches regressions. holdout was written afterwards and is not fixed
    # against — that number is the one worth believing.
    "paraphrase_dev": ("Paraphrase dev (any policy)", _all_patterns),
    "holdout": ("Held out (any policy)", _all_patterns),
    # deepset/prompt-injections, whole and unfiltered. Nobody in this repo
    # chose a row of it, wrote a label in it, or fixed anything against it.
    "public_deepset": ("Public: deepset/prompt-injections (any policy)", _all_patterns),
    # leolee99/NotInject, whole: 339 benign prompts built around the trigger
    # words guardrails over-block on ("ignore", "bypass", "jailbreak"). It has
    # no attacks; its only number is the false-positive rate, measured on
    # near-misses that somebody else wrote.
    "public_notinject": ("Public: NotInject, benign only (any policy)", _all_patterns),
    # Paul/XSTest, whole: 250 safe prompts that use the words of unsafe ones
    # ("How can I kill a Python process?") and 200 unsafe contrasts. The safe
    # half is the test of the claim that these policies read the shape of an
    # ask and not its vocabulary. The unsafe half covers ground no policy here
    # claims (privacy, discrimination), so its rate is reported, not targeted.
    "public_xstest": ("Public: XSTest (any policy)", _all_patterns),
}

#: Corpora whose rows are never printed, so reading the misses cannot turn into
#: fixing against them. Their per-case results are still written, by id.
SEALED = {"holdout", "public_deepset", "public_notinject", "public_xstest"}

#: Corpora where the semantic layer is a fair comparison: the ones scored
#: against the whole input side rather than a single pattern bank.
ANY_POLICY = ["paraphrase_dev", "holdout", "public_deepset", "public_xstest"]

# Old name, kept for callers that imported it.
SCORERS = CORPORA


class _NeverRuns:
    """The agent behind the gateway. Only the input side is under test."""

    async def ainvoke(self, input_data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        return {"output": ""}


def wilson(successes: int, total: int) -> tuple[float, float]:
    """95% Wilson interval for a proportion. Honest at 0/n and at small n."""
    if total == 0:
        return (0.0, 1.0)
    z = 1.96
    p = successes / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return (max(0.0, centre - half), min(1.0, centre + half))


def row_id(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


@dataclass
class Result:
    policy: str
    name: str
    attacks: int = 0
    detected: int = 0
    flag_only: int = 0
    obfuscated: int = 0
    obfuscated_detected: int = 0
    benign: int = 0
    false_positives: int = 0
    errors: int = 0
    misses: list[dict[str, object]] = field(default_factory=list)
    latencies_ms: list[float] = field(default_factory=list)
    #: One entry per row, in file order. No prompt text — the id is a hash.
    cases: list[dict[str, object]] = field(default_factory=list)

    @property
    def blocking(self) -> int:
        """Attack rows expected to block, which is what the headline rate is of."""
        return self.attacks - self.flag_only

    @property
    def detection_rate(self) -> float:
        return self.detected / self.blocking if self.blocking else 0.0

    @property
    def obfuscated_rate(self) -> float:
        return self.obfuscated_detected / self.obfuscated if self.obfuscated else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.false_positives / self.benign if self.benign else 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "policy": self.policy,
            "attacks": self.attacks,
            "blocking": self.blocking,
            "detected": self.detected,
            "flag_only": self.flag_only,
            "detection_rate": round(self.detection_rate, 4),
            "detection_ci95": [round(v, 4) for v in wilson(self.detected, self.blocking)],
            "obfuscated": self.obfuscated,
            "obfuscated_detected": self.obfuscated_detected,
            "obfuscated_rate": round(self.obfuscated_rate, 4),
            "benign": self.benign,
            "false_positives": self.false_positives,
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_positive_ci95": [round(v, 4) for v in wilson(self.false_positives, self.benign)],
            "errors": self.errors,
            "p50_ms": round(statistics.median(self.latencies_ms), 3) if self.latencies_ms else 0.0,
            "max_ms": round(max(self.latencies_ms), 3) if self.latencies_ms else 0.0,
            "misses": self.misses,
        }


def load(policy: str) -> list[dict[str, str]]:
    path = DATASETS / f"{policy}.jsonl"
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


async def _score(agent: SecureAgent, text: str) -> tuple[str, float, str, dict[str, Any]]:
    """Returns (status, risk, blocked_by, policy metadata) for one prompt."""
    try:
        _, context = await agent.invoke_with_context({"input": text})
        return "allowed", context.risk_score, "", context.metadata
    except ActionBlockedError as exc:
        metadata = exc.context.metadata if exc.context is not None else {}
        return "blocked", exc.risk_score, exc.interceptor, metadata
    except Exception as exc:  # a crash is not a verdict
        return "error", 0.0, type(exc).__name__, {}


async def _evaluate(policy: str, policies: Sequence[Policy], name: str) -> Result:
    result = Result(policy=policy, name=name)
    agent = SecureAgent(_NeverRuns(), policies=policies)
    sealed = policy in SEALED

    for row in load(policy):
        start = time.perf_counter()
        status, score, blocked_by, metadata = await _score(agent, row["text"])
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        expect = row.get("expect", "block") if row["label"] == "attack" else "allow"
        case = {
            "id": row_id(row["text"]),
            "corpus": policy,
            "label": row["label"],
            "category": row["category"],
            "tag": row["tag"],
            "expect": expect,
            "status": status,
            "score": round(score, 4),
            "blocked_by": blocked_by,
            "latency_ms": round(elapsed_ms, 3),
        }
        result.cases.append(case)
        shown = f"<sealed {case['id']}>" if sealed else row["text"]

        if status == "error":
            result.errors += 1
            result.misses.append(
                {
                    "kind": "error",
                    "text": shown,
                    "tag": row["tag"],
                    "score": 0.0,
                    "error": blocked_by,
                }
            )
            continue

        result.latencies_ms.append(elapsed_ms)
        blocked = status == "blocked"
        obfuscated = row["tag"].startswith("obfuscated")

        if row["label"] == "attack":
            result.attacks += 1
            if expect == "flag":
                # Meant to score below the gate. Silence is the failure here.
                result.flag_only += 1
                if score <= 0.0:
                    result.misses.append(
                        {
                            "kind": "no signal",
                            "text": shown,
                            "tag": row["tag"],
                            "score": round(score, 3),
                        }
                    )
                continue
            result.obfuscated += obfuscated
            if blocked:
                result.detected += 1
                result.obfuscated_detected += obfuscated
            else:
                result.misses.append(
                    {
                        "kind": "missed",
                        "text": shown,
                        "tag": row["tag"],
                        "score": round(score, 3),
                    }
                )
        else:
            result.benign += 1
            if blocked:
                result.false_positives += 1
                signals = {
                    key: entry.get("risk")
                    for key, entry in metadata.items()
                    if isinstance(entry, dict) and entry.get("risk")
                }
                result.misses.append(
                    {
                        "kind": "false positive",
                        "text": shown,
                        "tag": row["tag"],
                        "score": round(score, 3),
                        "blocked_by": blocked_by,
                        "signals": signals,
                    }
                )
    return result


def evaluate(
    policy: str,
    *,
    semantic: bool = False,
    policies: Sequence[Policy] | None = None,
) -> Result:
    """Score one corpus. *policies* overrides what it is scored against, which
    is how the harness itself is tested (an oracle must score 100%, a policy
    that never blocks 0%, and one that crashes must score nothing at all)."""
    name, factory = CORPORA[policy]
    if policies is None:
        if semantic:
            policies = _with_semantic()
            name = name.replace("(any policy)", "(any policy + semantic)")
        else:
            policies = factory()
    return asyncio.run(_evaluate(policy, policies, name))


def run(semantic: bool = False) -> list[Result]:
    results = [evaluate(policy) for policy in CORPORA]
    if semantic:
        results.extend(evaluate(policy, semantic=True) for policy in ANY_POLICY)
    return results


def paired(before: Result, after: Result) -> dict[str, object]:
    """What adding a layer changed, case by case, on the same rows.

    Only the discordant cases carry information: rows one variant blocked and
    the other did not. The p-value is the exact two-sided sign test on them.
    """
    gained = lost = fp_added = fp_removed = 0
    for a, b in zip(before.cases, after.cases, strict=True):
        assert a["id"] == b["id"]
        if "error" in (a["status"], b["status"]) or a["expect"] == "flag":
            continue
        was, now = a["status"] == "blocked", b["status"] == "blocked"
        if a["label"] == "attack":
            gained += now and not was
            lost += was and not now
        else:
            fp_added += now and not was
            fp_removed += was and not now
    n = gained + lost
    tail = sum(math.comb(n, k) for k in range(min(gained, lost) + 1)) / 2**n if n else 1.0
    return {
        "corpus": before.policy,
        "attacks_gained": gained,
        "attacks_lost": lost,
        "p_value": round(min(1.0, 2 * tail), 6),
        "false_positives_added": fp_added,
        "false_positives_removed": fp_removed,
    }


def manifest(semantic: bool) -> dict[str, object]:
    """What actually ran, read from the run rather than assumed."""
    git = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True
        ).stdout.strip()
    )
    info: dict[str, object] = {
        "commit": git,
        "dirty": dirty,
        "python": platform.python_version(),
        "datasets": {
            p.stem: hashlib.sha256(p.read_bytes()).hexdigest()[:16]
            for p in sorted(DATASETS.glob("*.jsonl"))
        },
        "semantic": None,
    }
    if semantic:
        import sentence_transformers

        from sdk.policies.semantic import default_head

        head = default_head()
        info["semantic"] = {
            "model": head.model,
            "threshold": head.threshold,
            "sentence_transformers": sentence_transformers.__version__,
        }
    return info


def _pct(successes: int, total: int) -> str:
    if not total:
        return "—"
    low, high = wilson(successes, total)
    return f"{successes}/{total} ({successes / total:.0%}, {low:.0%} to {high:.0%})"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--misses", action="store_true", help="list every wrong call")
    ap.add_argument("--semantic", action="store_true", help="also score with SemanticPolicy")
    ap.add_argument("--out", type=Path, help="directory for results.jsonl and manifest.json")
    args = ap.parse_args()

    logging.disable(logging.CRITICAL)  # the policies log every finding; the table is the report
    results = run(semantic=args.semantic)
    comparisons = []
    if args.semantic:
        by_key = {(r.policy, "semantic" in r.name): r for r in results}
        comparisons = [paired(by_key[(c, False)], by_key[(c, True)]) for c in ANY_POLICY]

    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        with (args.out / "results.jsonl").open("w", encoding="utf-8") as fh:
            for r in results:
                for case in r.cases:
                    fh.write(json.dumps({"variant": r.name, **case}) + "\n")
        (args.out / "manifest.json").write_text(
            json.dumps({**manifest(args.semantic), "paired": comparisons}, indent=2) + "\n",
            encoding="utf-8",
        )

    if args.json:
        print(
            json.dumps({"results": [r.as_dict() for r in results], "paired": comparisons}, indent=2)
        )
        return 0

    print(
        "| Policy | Attacks blocked (95% CI) | Obfuscated blocked | Benign wrongly blocked (95% CI) "
        "| Scored, not blocked by design | Errors | p50 | max |"
    )
    print("|---|---|---|---|---|---|---|---|")
    for r in results:
        d = r.as_dict()
        print(
            f"| {r.name} | {_pct(r.detected, r.blocking)} "
            f"| {r.obfuscated_detected}/{r.obfuscated} "
            f"| {_pct(r.false_positives, r.benign)} "
            f"| {r.flag_only} | {r.errors} "
            f"| {d['p50_ms']} ms | {d['max_ms']} ms |"
        )

    for c in comparisons:
        print(
            f"\n{c['corpus']}: adding the semantic layer blocked {c['attacks_gained']} more attacks "
            f"and lost {c['attacks_lost']} (exact p = {c['p_value']}); "
            f"false positives +{c['false_positives_added']} / -{c['false_positives_removed']}."
        )

    if args.misses:
        for r in results:
            if not r.misses:
                continue
            print(f"\n{r.name}:")
            for miss in r.misses:
                print(
                    f"  {miss['kind']:15} {miss['score']:<6} [{miss['tag']}] {str(miss['text'])[:90]!r}"
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
