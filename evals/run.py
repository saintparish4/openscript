"""Measure what the input-side policies actually catch, and what they wrongly catch.

    python evals/run.py                 # markdown table
    python evals/run.py --json          # machine-readable
    python evals/run.py --misses        # every prompt the policies got wrong

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
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sdk.interceptors.threat import score_text  # noqa: E402
from sdk.policies.harmful_request import score_harmful_request  # noqa: E402
from sdk.policies.toxicity import score_toxicity  # noqa: E402

DATASETS = Path(__file__).resolve().parent / "datasets"


def score_any(text: str) -> tuple[float, dict[str, float]]:
    """The strongest verdict any input-side policy reaches, and its signals.

    The holdout set is not about one policy. It asks whether the input side of
    the pipeline stops a prompt it has never been shown a phrasing of.
    """
    best = (0.0, {})
    for scorer in (score_text, score_toxicity, score_harmful_request):
        score, signals = scorer(text)
        if score > best[0]:
            best = (score, signals)
    return best


# policy key -> (display name, scorer, decision threshold as shipped)
SCORERS = {
    "prompt_injection": ("Prompt injection", score_text, 0.5),
    "toxicity": ("Toxicity", score_toxicity, 0.5),
    "harmful_request": ("Harmful request", score_harmful_request, 0.5),
    # paraphrase_dev was written after the patterns were tuned and then used to
    # find gaps, which spent it: a set you fix against stops measuring
    # generalization the moment you fix against it. It is kept because it still
    # catches regressions. holdout was written afterwards, scored once, and is
    # not fixed against — that number is the one worth believing.
    "paraphrase_dev": ("Paraphrase dev (any policy)", score_any, 0.5),
    "holdout": ("Held out (any policy)", score_any, 0.5),
}


@dataclass
class Result:
    policy: str
    name: str
    threshold: float
    attacks: int = 0
    detected: int = 0
    flag_only: int = 0
    obfuscated: int = 0
    obfuscated_detected: int = 0
    benign: int = 0
    false_positives: int = 0
    misses: list[dict[str, object]] = field(default_factory=list)
    latencies_ms: list[float] = field(default_factory=list)

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
            "obfuscated": self.obfuscated,
            "obfuscated_detected": self.obfuscated_detected,
            "obfuscated_rate": round(self.obfuscated_rate, 4),
            "benign": self.benign,
            "false_positives": self.false_positives,
            "false_positive_rate": round(self.false_positive_rate, 4),
            "p50_ms": round(statistics.median(self.latencies_ms), 3) if self.latencies_ms else 0.0,
            "max_ms": round(max(self.latencies_ms), 3) if self.latencies_ms else 0.0,
            "misses": self.misses,
        }


def load(policy: str) -> list[dict[str, str]]:
    path = DATASETS / f"{policy}.jsonl"
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def evaluate(policy: str) -> Result:
    name, scorer, threshold = SCORERS[policy]
    result = Result(policy=policy, name=name, threshold=threshold)

    for row in load(policy):
        start = time.perf_counter()
        score, signals = scorer(row["text"])
        result.latencies_ms.append((time.perf_counter() - start) * 1000.0)
        blocked = score >= threshold
        obfuscated = row["tag"].startswith("obfuscated")

        if row["label"] == "attack":
            result.attacks += 1
            if row.get("expect", "block") == "flag":
                # Meant to score below the gate. Silence is the failure here.
                result.flag_only += 1
                if score <= 0.0:
                    result.misses.append(
                        {
                            "kind": "no signal",
                            "text": row["text"],
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
                        "text": row["text"],
                        "tag": row["tag"],
                        "score": round(score, 3),
                    }
                )
        else:
            result.benign += 1
            if blocked:
                result.false_positives += 1
                result.misses.append(
                    {
                        "kind": "false positive",
                        "text": row["text"],
                        "tag": row["tag"],
                        "score": round(score, 3),
                        "signals": {k: round(v, 3) for k, v in signals.items()},
                    }
                )
    return result


def run() -> list[Result]:
    return [evaluate(policy) for policy in SCORERS]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--misses", action="store_true", help="list every wrong call")
    args = ap.parse_args()

    results = run()

    if args.json:
        print(json.dumps([r.as_dict() for r in results], indent=2))
        return 0

    print(
        "| Policy | Attacks blocked | Obfuscated blocked | Benign wrongly blocked "
        "| Scored, not blocked by design | p50 | max |"
    )
    print("|---|---|---|---|---|---|---|")
    for r in results:
        d = r.as_dict()
        print(
            f"| {r.name} | {r.detected}/{r.blocking} ({r.detection_rate:.0%}) "
            f"| {r.obfuscated_detected}/{r.obfuscated} ({r.obfuscated_rate:.0%}) "
            f"| {r.false_positives}/{r.benign} ({r.false_positive_rate:.0%}) "
            f"| {r.flag_only} "
            f"| {d['p50_ms']} ms | {d['max_ms']} ms |"
        )

    if args.misses:
        for r in results:
            if not r.misses:
                continue
            print(f"\n{r.name}:")
            for miss in r.misses:
                print(
                    f"  {miss['kind']:15} {miss['score']:<6} [{miss['tag']}] {miss['text'][:90]!r}"
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
