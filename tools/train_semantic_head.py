"""Train, cross-validate and write the linear head SemanticPolicy ships with.

    pip install -e ".[ml]" scikit-learn pandas pyarrow     # training-only extras
    python tools/train_semantic_head.py --data-dir ~/.cache/openscript-semantic
    python tools/train_semantic_head.py --write-head       # also rewrite sdk/policies/semantic_head.py

Not part of `make install`, CI or the test suite: it downloads ~50 MB of public
datasets and an encoder. The committed head is its output, and
evals/semantic/report.json is the record of the run that produced it.

What it trains on
-----------------
Public data (downloaded here, never committed) plus this repo's *dev* corpora:

  prompt_injection   jackhhao/jailbreak-classification (train), Lakera/gandalf_ignore_instructions,
                     yanismiraoui/prompt_injections, evals/datasets dev rows
  harmful_request    AdvBench, HarmBench (standard, minus misinformation), JBB-Behaviors, dev rows
  toxicity           google/civil_comments (threat / identity attack), dev rows
  benign             databricks-dolly-15k, jackhhao benign, in-the-wild regular prompts,
                     JBB benign behaviors, civil_comments with toxicity 0, dev benign rows

What it never sees
------------------
evals/datasets/holdout.jsonl, public_deepset.jsonl and public_notinject.jsonl. None is
read for training, model selection or threshold calibration; the only thing
taken from them is a set of text hashes, used to drop any training row that
duplicates one. They are scored once, afterwards, by evals/run.py.

How the choices are made (fixed before any score existed)
----------------------------------------------------------
Every candidate (encoder x regularization) is scored out-of-fold with 5-fold
cross-validation, through the same SemanticScorer the policy uses — windows,
normalized views and all — so the calibrated threshold belongs to the code path
that ships.

  threshold   the lowest value on a 0.01 grid with zero out-of-fold false
              positives on the dev benign prompts (the near-misses) and at most
              0.5% on the public benign prompts.
  winner      the candidate with the highest out-of-fold recall on the dev
              attack rows at its own threshold. Ties go to the smaller encoder.

Static-embedding candidates (model2vec) are scored for comparison because they
are the only ones that could run in a browser tab; they are reported, and only
picked if they win outright.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import subprocess
import sys
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sdk.policies import normalize  # noqa: E402
from sdk.policies.semantic import (  # noqa: E402
    BENIGN,
    SemanticHead,
    SemanticScorer,
    windows,
)

HF = "https://huggingface.co/datasets"
SOURCES = {
    "jackhhao_train.csv": f"{HF}/jackhhao/jailbreak-classification/resolve/main/default/jailbreak_dataset_train.csv",
    "gandalf_train.parquet": f"{HF}/Lakera/gandalf_ignore_instructions/resolve/main/data/train-00000-of-00001-ded53be747ff55cd.parquet",
    "yanis.csv": f"{HF}/yanismiraoui/prompt_injections/resolve/main/prompt_injections.csv",
    "jbb_harmful.csv": f"{HF}/JailbreakBench/JBB-Behaviors/resolve/main/data/harmful-behaviors.csv",
    "jbb_benign.csv": f"{HF}/JailbreakBench/JBB-Behaviors/resolve/main/data/benign-behaviors.csv",
    "advbench.csv": "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv",
    "harmbench.csv": "https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_all.csv",
    "dolly.jsonl": f"{HF}/databricks/databricks-dolly-15k/resolve/main/databricks-dolly-15k.jsonl",
    "civil_val.parquet": f"{HF}/google/civil_comments/resolve/main/data/validation-00000-of-00001.parquet",
    "regular.parquet": f"{HF}/TrustAIRLab/in-the-wild-jailbreak-prompts/resolve/main/regular_2023_12_25/train-00000-of-00001.parquet",
}

LABELS = [BENIGN, "prompt_injection", "harmful_request", "toxicity"]
INJECTION_CATEGORIES = {
    "role_injection",
    "goal_hijacking",
    "prompt_extraction",
    "delimiter_injection",
    "indirect_injection",
    "social_engineering",
}
TOXICITY_CATEGORIES = {"violence", "hate_speech", "harassment", "self_harm"}
DEV_CORPORA = ["prompt_injection", "toxicity", "harmful_request", "paraphrase_dev"]
NEVER_TRAINED_ON = ["holdout", "public_deepset", "public_notinject"]

# (name, model id, kind). "static" candidates go through model2vec.
CANDIDATES = [
    ("minilm-l6", "sentence-transformers/all-MiniLM-L6-v2", "st"),
    ("bge-small", "BAAI/bge-small-en-v1.5", "st"),
    ("multilingual-minilm", "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2", "st"),
    ("potion-8m-static", "minishlab/potion-base-8M", "static"),
]
C_GRID = [1.0, 4.0, 16.0]
DEV_WEIGHT = 5.0  # dev rows are the near-misses; they are few, so they count for more
FOLDS = 5
SEED = 0
MAX_PUBLIC_BENIGN_FP = 0.005


@dataclass(frozen=True)
class Row:
    id: str
    text: str
    label: str
    source: str
    dev: bool


def _norm(text: str) -> str:
    return re.sub(r"\W+", " ", text.lower()).strip()


def _hash(text: str) -> str:
    return hashlib.sha256(_norm(text).encode()).hexdigest()


def download(data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        target = data_dir / name
        if not target.exists():
            print(f"downloading {name}", file=sys.stderr)
            urllib.request.urlretrieve(url, target)


def _dev_label(corpus: str, row: dict[str, str]) -> str:
    if row["label"] == "benign":
        return BENIGN
    if corpus != "paraphrase_dev":
        return corpus
    if row["category"] in INJECTION_CATEGORIES:
        return "prompt_injection"
    if row["category"] in TOXICITY_CATEGORIES:
        return "toxicity"
    return "harmful_request"


def build_pool(data_dir: Path) -> tuple[list[Row], dict[str, int]]:
    import pandas as pd

    rng = random.Random(SEED)
    raw: list[tuple[str, str, str, bool]] = []  # text, label, source, dev

    def add(texts: list[str], label: str, source: str, cap: int | None = None) -> None:
        texts = [t for t in texts if isinstance(t, str) and t.strip()]
        if cap is not None and len(texts) > cap:
            texts = rng.sample(texts, cap)
        raw.extend((t.strip(), label, source, False) for t in texts)

    jack = pd.read_csv(data_dir / "jackhhao_train.csv")
    add(jack[jack.type == "jailbreak"].prompt.tolist(), "prompt_injection", "jackhhao")
    add(jack[jack.type == "benign"].prompt.tolist(), BENIGN, "jackhhao")
    add(
        pd.read_parquet(data_dir / "gandalf_train.parquet").text.tolist(),
        "prompt_injection",
        "gandalf",
        400,
    )
    add(
        pd.read_csv(data_dir / "yanis.csv").prompt_injections.tolist(),
        "prompt_injection",
        "yanis",
        400,
    )
    add(pd.read_csv(data_dir / "advbench.csv").goal.tolist(), "harmful_request", "advbench")
    hb = pd.read_csv(data_dir / "harmbench.csv")
    hb = hb[(hb.FunctionalCategory == "standard")]
    hb = hb[hb.SemanticCategory != "misinformation_disinformation"]
    add(hb.Behavior.tolist(), "harmful_request", "harmbench")
    add(pd.read_csv(data_dir / "jbb_harmful.csv").Goal.tolist(), "harmful_request", "jbb")
    add(pd.read_csv(data_dir / "jbb_benign.csv").Goal.tolist(), BENIGN, "jbb")
    civil = pd.read_parquet(data_dir / "civil_val.parquet")
    add(civil[civil.threat >= 0.5].text.tolist(), "toxicity", "civil", 300)
    add(civil[civil.identity_attack >= 0.5].text.tolist(), "toxicity", "civil", 300)
    add(civil[civil.toxicity == 0].text.tolist(), BENIGN, "civil", 1500)
    dolly = [
        json.loads(line)["instruction"]
        for line in (data_dir / "dolly.jsonl").open(encoding="utf-8")
    ]
    add(dolly, BENIGN, "dolly", 3000)
    add(pd.read_parquet(data_dir / "regular.parquet").prompt.tolist(), BENIGN, "regular", 500)

    for corpus in DEV_CORPORA:
        for line in (REPO_ROOT / "evals/datasets" / f"{corpus}.jsonl").open(encoding="utf-8"):
            row = json.loads(line)
            # Obfuscated rows are rewrites of plain rows; normalization folds
            # them back at inference. Flag-only rows are deliberately not
            # blocked, so they are not taught as attacks or as benign.
            if row["tag"] != "plain" or row.get("expect", "block") == "flag":
                continue
            raw.append((row["text"], _dev_label(corpus, row), f"dev:{corpus}", True))

    forbidden: set[str] = set()
    for corpus in NEVER_TRAINED_ON:
        path = REPO_ROOT / "evals/datasets" / f"{corpus}.jsonl"
        if path.exists():
            forbidden |= {_hash(json.loads(line)["text"]) for line in path.open(encoding="utf-8")}

    stats = {"dropped_duplicate": 0, "dropped_overlaps_test": 0}
    seen: set[str] = set()
    pool: list[Row] = []
    # Dev rows first so that a public row duplicating one is the one dropped.
    for text, label, source, dev in sorted(raw, key=lambda r: not r[3]):
        h = _hash(text)
        if h in forbidden:
            stats["dropped_overlaps_test"] += 1
            continue
        if h in seen:
            stats["dropped_duplicate"] += 1
            continue
        seen.add(h)
        pool.append(Row(id=h[:12], text=text, label=label, source=source, dev=dev))
    return pool, stats


class CachedEncoder:
    """Embeds each distinct string once, so CV re-scoring costs no encoding."""

    def __init__(self, model_id: str, kind: str) -> None:
        self.model_id = model_id
        self._cache: dict[str, list[float]] = {}
        if kind == "static":
            from sentence_transformers import SentenceTransformer
            from sentence_transformers.models import StaticEmbedding

            self._model = SentenceTransformer(
                modules=[StaticEmbedding.from_model2vec(model_id)], device="cpu"
            )
        else:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(model_id, device="cpu")

    def warm(self, texts: list[str]) -> None:
        todo = sorted({t for t in texts if t not in self._cache}, key=len)
        if not todo:
            return
        vectors = self._model.encode(
            todo, normalize_embeddings=True, show_progress_bar=False, batch_size=64
        )
        for text, vector in zip(todo, vectors, strict=True):
            self._cache[text] = vector.tolist()

    def __call__(self, texts: list[str]) -> list[list[float]]:
        self.warm(texts)
        return [self._cache[t] for t in texts]


def pieces(text: str) -> list[str]:
    """Every string SemanticScorer will embed for *text*."""
    out: list[str] = []
    for view in normalize.prepare(text).views:
        out.extend(w for w in windows(view.text) if w.strip())
    return out


def fit_head(encoder: CachedEncoder, rows: list[Row], c: float) -> SemanticHead:
    """Trained on the first window of the text as written."""
    import numpy as np
    from sklearn.linear_model import LogisticRegression

    x = np.array(encoder([windows(r.text)[0] for r in rows]))
    y = np.array([LABELS.index(r.label) for r in rows])
    weight = np.array([DEV_WEIGHT if r.dev else 1.0 for r in rows])
    # Balance classes on top of the dev weighting: benign is ~75% of the pool.
    totals = {k: weight[y == k].sum() for k in set(y)}
    weight = weight * np.array([weight.sum() / (len(totals) * totals[k]) for k in y])
    model = LogisticRegression(C=c, max_iter=2000)
    model.fit(x, y, sample_weight=weight)
    return SemanticHead(
        model=encoder.model_id,
        labels=tuple(LABELS[k] for k in model.classes_),
        weights=tuple(tuple(float(v) for v in row) for row in model.coef_),
        bias=tuple(float(v) for v in model.intercept_),
        threshold=1.0,
    )


def out_of_fold(encoder: CachedEncoder, rows: list[Row], c: float) -> list[float]:
    from sklearn.model_selection import StratifiedKFold

    strata = [f"{r.label}|{r.source}" for r in rows]
    risks = [0.0] * len(rows)
    folds = StratifiedKFold(n_splits=FOLDS, shuffle=True, random_state=SEED)
    for train_idx, test_idx in folds.split(rows, strata):
        scorer = SemanticScorer(encoder, fit_head(encoder, [rows[i] for i in train_idx], c))
        for i in test_idx:
            risks[i] = scorer.score(rows[i].text).risk
    return risks


def calibrate(rows: list[Row], risks: list[float]) -> dict[str, object]:
    dev_benign = [s for r, s in zip(rows, risks, strict=True) if r.dev and r.label == BENIGN]
    pub_benign = [s for r, s in zip(rows, risks, strict=True) if not r.dev and r.label == BENIGN]
    dev_attack = [s for r, s in zip(rows, risks, strict=True) if r.dev and r.label != BENIGN]
    pub_attack = [s for r, s in zip(rows, risks, strict=True) if not r.dev and r.label != BENIGN]

    threshold = 1.0
    for step in range(1, 101):
        t = step / 100
        if (
            not any(s >= t for s in dev_benign)
            and sum(s >= t for s in pub_benign) / len(pub_benign) <= MAX_PUBLIC_BENIGN_FP
        ):
            threshold = t
            break

    def rate(scores: list[float]) -> list[int]:
        return [sum(s >= threshold for s in scores), len(scores)]

    by_source: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r, s in zip(rows, risks, strict=True):
        key = f"{r.source}|{'benign' if r.label == BENIGN else 'attack'}"
        by_source[key][0] += s >= threshold
        by_source[key][1] += 1
    # What the threshold costs: recall on dev attacks if false positives were tolerated.
    curve = {
        f"{t:.2f}": {
            "dev_attack_recall": round(sum(s >= t for s in dev_attack) / len(dev_attack), 4),
            "dev_benign_fp": sum(s >= t for s in dev_benign),
            "public_benign_fp_rate": round(sum(s >= t for s in pub_benign) / len(pub_benign), 4),
        }
        for t in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95)
    }
    return {
        "threshold": threshold,
        "dev_attack_blocked": rate(dev_attack),
        "public_attack_blocked": rate(pub_attack),
        "dev_benign_blocked": rate(dev_benign),
        "public_benign_blocked": rate(pub_benign),
        "by_source": dict(sorted(by_source.items())),
        "curve": curve,
    }


def write_head(head: SemanticHead, meta: dict[str, object]) -> None:
    lines = [
        '"""The linear head SemanticPolicy applies to sentence embeddings.',
        "",
        "Generated by tools/train_semantic_head.py — do not edit by hand. The run",
        "that produced it is recorded in evals/semantic/report.json.",
        '"""',
        "",
        "from typing import Any",
        "",
        "HEAD: dict[str, Any] = {",
        f'    "model": {head.model!r},',
        f'    "labels": {list(head.labels)!r},',
        f'    "threshold": {head.threshold!r},',
        f'    "trained": {meta!r},',
        f'    "bias": {[round(b, 5) for b in head.bias]!r},',
        '    "weights": [',
    ]
    for row in head.weights:
        lines.append("        [" + ", ".join(f"{w:.4f}" for w in row) + "],")
    lines += ["    ],", "}", ""]
    target = REPO_ROOT / "sdk/policies/semantic_head.py"
    target.write_text("\n".join(lines), encoding="utf-8")
    subprocess.run([sys.executable, "-m", "black", "-q", str(target)], check=False)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data-dir", type=Path, default=Path.home() / ".cache/openscript-semantic")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "evals/semantic")
    ap.add_argument("--write-head", action="store_true")
    ap.add_argument("--only", help="comma-separated candidate names")
    args = ap.parse_args()

    download(args.data_dir)
    pool, stats = build_pool(args.data_dir)
    composition = Counter(f"{r.source}|{r.label}" for r in pool)
    print(f"pool: {len(pool)} rows; {stats}", file=sys.stderr)

    wanted = set(args.only.split(",")) if args.only else None
    results = []
    encoders: dict[str, CachedEncoder] = {}
    every_piece = sorted({p for r in pool for p in pieces(r.text)})
    for name, model_id, kind in CANDIDATES:
        if wanted and name not in wanted:
            continue
        encoder = CachedEncoder(model_id, kind)
        encoder.warm(every_piece)
        encoders[name] = encoder
        for c in C_GRID:
            risks = out_of_fold(encoder, pool, c)
            entry = {"candidate": name, "model": model_id, "kind": kind, "C": c}
            entry.update(calibrate(pool, risks))
            entry["_risks"] = risks
            results.append(entry)
            blocked, total = entry["dev_attack_blocked"]  # type: ignore[misc]
            print(
                f"{name} C={c}: threshold {entry['threshold']}, dev attacks {blocked}/{total}, "
                f"public attacks {entry['public_attack_blocked']}, "
                f"public benign {entry['public_benign_blocked']}",
                file=sys.stderr,
            )

    order = [name for name, _, _ in CANDIDATES]
    winner = max(
        results,
        key=lambda e: (
            e["dev_attack_blocked"][0],  # type: ignore[index]
            e["kind"] == "st",  # a static candidate has to win outright
            -order.index(str(e["candidate"])),
            -float(e["C"]),  # type: ignore[arg-type]
        ),
    )
    winner_risks = winner["_risks"]

    args.out.mkdir(parents=True, exist_ok=True)
    commit = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True
    ).stdout.strip()
    meta = {
        "date": datetime.now(UTC).date().isoformat(),
        "rows": len(pool),
        "C": winner["C"],
        "commit": commit,
    }
    report = {
        "meta": meta,
        "protocol": {
            "folds": FOLDS,
            "seed": SEED,
            "dev_weight": DEV_WEIGHT,
            "max_public_benign_fp": MAX_PUBLIC_BENIGN_FP,
            "never_trained_on": NEVER_TRAINED_ON,
        },
        "pool": {"rows": len(pool), **stats, "composition": dict(sorted(composition.items()))},
        "winner": {k: v for k, v in winner.items() if k != "_risks"},
        "candidates": [{k: v for k, v in e.items() if k != "_risks"} for e in results],
    }
    (args.out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with (args.out / "cv_rows.jsonl").open("w", encoding="utf-8") as fh:
        for row, risk in zip(pool, winner_risks, strict=True):  # type: ignore[arg-type]
            fh.write(
                json.dumps(
                    {
                        "id": row.id,
                        "source": row.source,
                        "label": row.label,
                        "oof_risk": round(risk, 4),
                    }
                )
                + "\n"
            )
    print(json.dumps(report["winner"], indent=2))

    if args.write_head:
        encoder = encoders[str(winner["candidate"])]
        head = fit_head(encoder, pool, float(winner["C"]))  # type: ignore[arg-type]
        head = SemanticHead(
            model=head.model,
            labels=head.labels,
            weights=head.weights,
            bias=head.bias,
            threshold=float(winner["threshold"]),  # type: ignore[arg-type]
        )
        write_head(head, meta)
        print("wrote sdk/policies/semantic_head.py", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
