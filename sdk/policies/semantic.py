"""SemanticPolicy — the opt-in layer that reads a sentence instead of matching it.

The pattern banks recognise shapes. Measured against attacks phrased in words
nobody wrote a rule for, they block almost nothing (docs/metrics.md), and no
amount of extra patterns changes that. This policy is the other half: it embeds
the prompt with a small sentence encoder and scores the embedding with a linear
head trained on labelled attacks and the benign prompts that resemble them.

It is **not** one of the pure-local built-ins and is never part of the browser
demo. It needs the ``[ml]`` extra, and the encoder weights are downloaded from
the Hugging Face Hub the first time the model loads (pass
``local_files_only=True`` once they are cached to rule the network out). Every
heavy import is inside a function, so ``import sdk`` stays exactly as light as
it was.

Three pieces, kept separate so each can be checked on its own:

- an **encoder**: any callable mapping a list of strings to unit-length vectors.
  The default wraps sentence-transformers; tests pass a stub.
- a **head**: class weights for {benign, prompt_injection, harmful_request,
  toxicity}, shipped as plain numbers in ``semantic_head.py`` and applied in
  pure Python. ``tools/train_semantic_head.py`` regenerates it.
- the **policy**: scores every normalized view and every window of the text,
  keeps the strongest, and denies (or annotates) at the head's calibrated
  threshold.
"""

from __future__ import annotations

import asyncio
import importlib.util
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import structlog

from contracts.interceptor import BasePolicy
from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode, InterceptorDecision
from sdk.policies import normalize

if TYPE_CHECKING:
    from events.writer import EventWriter

logger = structlog.get_logger(__name__)

#: Texts in, one unit-length vector per text out.
Encoder = Callable[[list[str]], Sequence[Sequence[float]]]

BENIGN = "benign"

# The encoder truncates at its own token limit, so a long prompt is scored in
# overlapping windows and the strongest window decides — an instruction buried
# on page three is still an instruction. The cap bounds the cost of one call.
WINDOW_WORDS = 120
WINDOW_STRIDE = 80
MAX_WINDOWS = 24


class SemanticMode(StrEnum):
    DENY = "deny"
    ANNOTATE = "annotate"


@dataclass(frozen=True)
class SemanticHead:
    """A linear classifier over one specific encoder's embedding space."""

    model: str
    labels: tuple[str, ...]
    weights: tuple[tuple[float, ...], ...]
    bias: tuple[float, ...]
    threshold: float

    def __post_init__(self) -> None:
        if BENIGN not in self.labels:
            raise ValueError(f"head needs a {BENIGN!r} class, got {self.labels}")
        if not (len(self.labels) == len(self.weights) == len(self.bias)):
            raise ValueError("head labels, weights and bias disagree on the number of classes")
        if len({len(row) for row in self.weights}) != 1:
            raise ValueError("head weight rows have different lengths")

    @property
    def dim(self) -> int:
        return len(self.weights[0])

    @property
    def trained(self) -> bool:
        """False for the all-zero placeholder that ships until a head is trained."""
        return any(w != 0.0 for row in self.weights for w in row) or any(
            b != 0.0 for b in self.bias
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SemanticHead:
        return cls(
            model=str(data["model"]),
            labels=tuple(data["labels"]),
            weights=tuple(tuple(float(w) for w in row) for row in data["weights"]),
            bias=tuple(float(b) for b in data["bias"]),
            threshold=float(data["threshold"]),
        )

    def probabilities(self, vector: Sequence[float]) -> dict[str, float]:
        if len(vector) != self.dim:
            raise ValueError(
                f"encoder produced {len(vector)}-d vectors; this head was trained on "
                f"{self.dim}-d vectors from {self.model}"
            )
        logits = [
            sum(w * x for w, x in zip(row, vector, strict=True)) + b
            for row, b in zip(self.weights, self.bias, strict=True)
        ]
        peak = max(logits)
        exps = [math.exp(v - peak) for v in logits]
        total = sum(exps)
        return {label: e / total for label, e in zip(self.labels, exps, strict=True)}


def default_head() -> SemanticHead:
    """The head shipped with the package, trained by tools/train_semantic_head.py."""
    from sdk.policies.semantic_head import HEAD

    return SemanticHead.from_dict(HEAD)


@dataclass(frozen=True)
class SemanticScore:
    """The strongest reading of one prompt."""

    risk: float
    #: The most likely attack class, even when the risk is low.
    predicted: str
    probabilities: dict[str, float] = field(default_factory=dict)
    view: str = "raw"
    markers: list[str] = field(default_factory=list)
    windows: int = 1


def windows(text: str) -> list[str]:
    """Split *text* into overlapping word windows. Short text is one window."""
    words = text.split()
    if len(words) <= WINDOW_WORDS:
        return [text]
    starts = list(range(0, len(words) - WINDOW_WORDS + WINDOW_STRIDE, WINDOW_STRIDE))
    if len(starts) > MAX_WINDOWS:
        # Keep the ends and sample the middle evenly: openings and closings are
        # where an instruction to the model usually sits.
        step = (len(starts) - 1) / (MAX_WINDOWS - 1)
        starts = sorted({starts[round(i * step)] for i in range(MAX_WINDOWS)})
    return [" ".join(words[s : s + WINDOW_WORDS]) for s in starts]


class SentenceTransformerEncoder:
    """The default encoder. Loads the model on first use, not on import."""

    def __init__(self, model_name: str, local_files_only: bool = False) -> None:
        self.model_name = model_name
        self._local_files_only = local_files_only
        self._model: Any = None

    def __call__(self, texts: list[str]) -> Sequence[Sequence[float]]:
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(
                self.model_name, local_files_only=self._local_files_only
            )
        vectors = self._model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
        return vectors.tolist()  # type: ignore[no-any-return]


class SemanticScorer:
    """Encoder + head. Stateless apart from the loaded model; safe to share."""

    def __init__(self, encoder: Encoder, head: SemanticHead) -> None:
        self._encoder = encoder
        self.head = head

    def score(self, text: str) -> SemanticScore:
        prepared = normalize.prepare(text)
        pieces: list[tuple[str, str]] = []  # (view name, window text)
        for view in prepared.views:
            pieces.extend((view.name, w) for w in windows(view.text) if w.strip())
        if not pieces:
            return SemanticScore(risk=0.0, predicted=BENIGN, markers=prepared.markers, windows=0)

        vectors = self._encoder([p[1] for p in pieces])
        best: SemanticScore | None = None
        for (view_name, _), vector in zip(pieces, vectors, strict=True):
            probs = self.head.probabilities(vector)
            risk = 1.0 - probs[BENIGN]
            # Strictly greater: ties go to the earliest view, so a prompt that
            # reads the same before and after normalization is reported as raw.
            if best is None or risk > best.risk:
                attack = max((k for k in probs if k != BENIGN), key=lambda k: probs[k])
                best = SemanticScore(
                    risk=risk,
                    predicted=attack,
                    probabilities=probs,
                    view=view_name,
                    markers=prepared.markers,
                    windows=len(pieces),
                )
        assert best is not None
        return best


class SemanticPolicy(BasePolicy):
    """Scores the meaning of the input and blocks at a calibrated threshold.

    Opt-in. Needs ``pip install -e ".[ml]"`` unless an *encoder* is supplied,
    and raises ImportError at construction rather than failing closed on every
    request later. It also refuses to construct on an untrained head, which is
    what the package ships until tools/train_semantic_head.py has been run: no
    detection number is published for this policy yet. Place it after the pattern policies: they are a thousand
    times cheaper and settle the obvious cases first.

    Results land in context.metadata["semantic"] in the standardized shape:
      {"risk": float, "category": "semantic", "predicted": str,
       "probabilities": {...}, "flagged": bool, "threshold": float,
       "model": str, "obfuscation": [...], "matched_view": str}

    *threshold* defaults to the one calibrated when the head was trained (the
    lowest that produced no false positive on held-out benign prompts). Lower
    it and it catches more and blocks more ordinary text; that trade is
    measured in docs/metrics.md, not assumed.

    ``mode="annotate"`` records the score without blocking, which is the right
    first step in a deployment: read what it would have blocked before letting
    it block.
    """

    failure_mode: FailureMode = FailureMode.FAIL_CLOSED

    def __init__(
        self,
        threshold: float | None = None,
        mode: SemanticMode | str = SemanticMode.DENY,
        encoder: Encoder | None = None,
        head: SemanticHead | None = None,
        local_files_only: bool = False,
        writer: EventWriter | None = None,
    ) -> None:
        self._head = head if head is not None else default_head()
        if not self._head.trained:
            # A policy that constructs, sits in the list and decides nothing is
            # the worst outcome available: it reads as protection.
            raise RuntimeError(
                "SemanticPolicy has no trained head: sdk/policies/semantic_head.py is "
                "still the placeholder. Run tools/train_semantic_head.py --write-head, "
                "or pass head=..."
            )
        self._threshold = self._head.threshold if threshold is None else threshold
        if not 0.0 <= self._threshold <= 1.0:
            raise ValueError(f"threshold must be in [0, 1], got {self._threshold}")
        self._mode = SemanticMode(mode)
        if encoder is None:
            if importlib.util.find_spec("sentence_transformers") is None:
                raise ImportError(
                    "SemanticPolicy needs sentence-transformers: pip install -e '.[ml]' "
                    "(or pass encoder=...)"
                )
            encoder = SentenceTransformerEncoder(self._head.model, local_files_only)
        self._scorer = SemanticScorer(encoder, self._head)
        self._writer = writer
        self._sequence_counters: dict[str, int] = {}

    def score(self, text: str) -> SemanticScore:
        """Score one string synchronously — what before_action runs in a thread."""
        return self._scorer.score(text)

    async def before_action(self, context: ActionContext) -> ActionContext:
        text = _extract_text(context.input_data)
        # Encoding is CPU-bound for a few milliseconds; keep it off the loop.
        result = await asyncio.to_thread(self._scorer.score, text)
        flagged = result.risk >= self._threshold

        context.metadata["semantic"] = {
            "risk": round(result.risk, 4),
            "category": "semantic",
            "predicted": result.predicted,
            "probabilities": {k: round(v, 4) for k, v in result.probabilities.items()},
            "flagged": flagged,
            "threshold": self._threshold,
            "model": self._head.model,
            "obfuscation": result.markers,
            "matched_view": result.view,
        }

        if flagged and self._mode is SemanticMode.DENY:
            reason = (
                f"semantic score {result.risk:.2f} >= threshold {self._threshold:.2f} "
                f"(reads as: {result.predicted})"
            )
            context.decision = InterceptorDecision.DENY
            context.decision_reason = reason
            logger.warning(
                "semantic_detected",
                session_id=context.session_id,
                agent_id=context.agent_id,
                score=round(result.risk, 4),
                predicted=result.predicted,
            )
            if self._writer is not None:
                await self._emit_event(context, result, reason)

        return context

    async def _emit_event(self, context: ActionContext, result: SemanticScore, reason: str) -> None:
        assert self._writer is not None
        count = self._sequence_counters.get(context.session_id, 0) + 1
        self._sequence_counters[context.session_id] = count
        await self._writer.write(
            Event(
                session_id=context.session_id,
                agent_id=context.agent_id,
                event_type=EventType.POLICY_EVALUATED,
                payload={
                    "policy": "semantic_check",
                    "score": round(result.risk, 4),
                    "predicted": result.predicted,
                    "reason": reason,
                    "action": context.action,
                    "threshold": self._threshold,
                    "model": self._head.model,
                },
                sequence_num=count,
            )
        )


def _extract_text(input_data: dict[str, Any]) -> str:
    """Pull a single string from common input_data shapes."""
    if "input" in input_data:
        return str(input_data["input"])
    if "messages" in input_data:
        parts = []
        for msg in input_data["messages"]:
            if isinstance(msg, dict):
                parts.append(str(msg.get("content", "")))
            else:
                parts.append(str(msg))
        return " ".join(parts)
    return " ".join(str(v) for v in input_data.values())
