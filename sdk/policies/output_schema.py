from __future__ import annotations

import json
import re
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog
from pydantic import BaseModel, ValidationError

from contracts.interceptor import BasePolicy
from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode, InterceptorDecision
from sdk.policies.secrets import find_secrets

if TYPE_CHECKING:
    from events.writer import EventWriter

logger = structlog.get_logger(__name__)


class OnInvalid(str, Enum):
    DENY = "deny"
    ANNOTATE = "annotate"


class HallucinationMode(str, Enum):
    KEYWORD = "keyword"
    EMBEDDING = "embedding"


# Keys checked (in order) for a JSON-string payload when the output dict
# itself does not validate against the schema.
_JSON_CANDIDATE_KEYS = ("output", "result", "content", "text", "data")

# Grounding: content words are 4+ alphanumeric chars, minus common English
# words that carry no factual signal.
_WORD_RE = re.compile(r"[a-z0-9]{4,}")
_STOPWORDS = frozenset(
    [
        "about",
        "above",
        "after",
        "again",
        "also",
        "because",
        "been",
        "before",
        "being",
        "below",
        "between",
        "both",
        "cannot",
        "could",
        "does",
        "doing",
        "down",
        "during",
        "each",
        "even",
        "every",
        "from",
        "further",
        "have",
        "having",
        "here",
        "how",
        "into",
        "itself",
        "just",
        "like",
        "made",
        "make",
        "many",
        "more",
        "most",
        "much",
        "must",
        "only",
        "other",
        "over",
        "same",
        "shall",
        "should",
        "some",
        "such",
        "than",
        "that",
        "their",
        "theirs",
        "them",
        "then",
        "there",
        "these",
        "they",
        "this",
        "those",
        "through",
        "under",
        "until",
        "very",
        "were",
        "what",
        "when",
        "where",
        "which",
        "while",
        "will",
        "with",
        "would",
        "your",
        "yours",
    ]
)


def keyword_grounding_score(output_text: str, source_text: str) -> float:
    """Fraction of output content words absent from the grounding source.

    0.0 = every content word appears in the source; 1.0 = none do.
    """
    terms = {w for w in _WORD_RE.findall(output_text.lower()) if w not in _STOPWORDS}
    if not terms:
        return 0.0
    source_terms = set(_WORD_RE.findall(source_text.lower()))
    missing = terms - source_terms
    return len(missing) / len(terms)


def _flatten_text(obj: Any) -> str:
    """Join all strings inside nested dicts/lists into one scannable text."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten_text(v) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_flatten_text(item) for item in obj)
    return ""


class OutputSchemaPolicy(BasePolicy):
    """Validates agent output against a Pydantic schema and scans for
    dangerous content and hallucination signals. Runs in after_action.

    Checks, in order:
      1. Schema: ``model.model_validate(context.output_data)``; if the dict
         itself doesn't validate, a JSON string under one of the keys
         "output"/"result"/"content"/"text"/"data" is parsed (flagging
         invalid JSON) and validated instead. Missing required fields are
         reported separately from other validation errors.
      2. Dangerous content: secrets/internal-URL patterns from SecretsPolicy
         found anywhere in the output (detection only — pair with
         SecretsPolicy for redaction).
      3. Grounding: when a grounding source is available (the
         ``grounding_source`` kwarg, or per-request via
         ``context.metadata["grounding_source"]``), scores how much of the
         output is unsupported by the source and annotates
         ``context.metadata["hallucination"]``. Annotation only — it does
         not block; RiskScorer aggregates it. ``mode="embedding"`` uses
         sentence-transformers (``pip install openscript[ml]``) and falls
         back to keyword scoring when unavailable.

    Results land in ``context.metadata["output_validation"]`` using the
    standardized shape (``risk``: dangerous content 0.8, schema errors or
    missing fields 0.5, valid 0.0; ``category``: "output_validation").
    Grounding results land in ``context.metadata["hallucination"]`` with
    ``risk`` set to the grounding score. When invalid and
    ``on_invalid=DENY``, sets ``decision=DENY``.
    """

    failure_mode: FailureMode = FailureMode.FAIL_OPEN

    def __init__(
        self,
        model: type[BaseModel] | None = None,
        on_invalid: OnInvalid | str = OnInvalid.DENY,
        grounding_source: str | None = None,
        hallucination_mode: HallucinationMode | str = HallucinationMode.KEYWORD,
        hallucination_threshold: float = 0.5,
        writer: EventWriter | None = None,
    ) -> None:
        if not 0.0 <= hallucination_threshold <= 1.0:
            raise ValueError(
                f"hallucination_threshold must be in [0, 1], got {hallucination_threshold}"
            )
        self._model = model
        self._on_invalid = OnInvalid(on_invalid)
        self._grounding_source = grounding_source
        self._hallucination_mode = HallucinationMode(hallucination_mode)
        self._hallucination_threshold = hallucination_threshold
        self._writer = writer
        self._embedder: Any = None
        self._sequence_counters: dict[str, int] = {}

    async def after_action(self, context: ActionContext) -> ActionContext:
        errors: list[str] = []
        missing_fields: list[str] = []
        if self._model is not None:
            errors, missing_fields = self._validate_schema(context.output_data)

        output_text = _flatten_text(context.output_data)
        dangerous = sorted({label for _, label in find_secrets(output_text)})

        valid = not errors and not missing_fields and not dangerous
        if dangerous:
            risk = 0.8
        elif errors or missing_fields:
            risk = 0.5
        else:
            risk = 0.0
        context.metadata["output_validation"] = {
            "risk": risk,
            "category": "output_validation",
            "valid": valid,
            "errors": errors,
            "missing_fields": missing_fields,
            "dangerous_content": dangerous,
            "on_invalid": self._on_invalid.value,
        }

        source = context.metadata.get("grounding_source", self._grounding_source)
        if source is not None:
            self._check_grounding(context, output_text, str(source))

        if not valid:
            logger.warning(
                "output_validation_failed",
                session_id=context.session_id,
                agent_id=context.agent_id,
                errors=errors,
                missing_fields=missing_fields,
                dangerous_content=dangerous,
                on_invalid=self._on_invalid.value,
            )
            if self._on_invalid == OnInvalid.DENY:
                problems = errors + [f"missing field: {f}" for f in missing_fields]
                if dangerous:
                    problems.append(f"dangerous content: {', '.join(dangerous)}")
                context.decision = InterceptorDecision.DENY
                context.decision_reason = f"Output validation failed: {'; '.join(problems[:3])}"
            if self._writer is not None:
                await self._emit_validation_event(context)

        return context

    # -- schema ------------------------------------------------------------

    def _validate_schema(self, output_data: dict[str, Any]) -> tuple[list[str], list[str]]:
        """Return (errors, missing_fields); both empty when the output validates."""
        assert self._model is not None
        try:
            self._model.model_validate(output_data)
            return [], []
        except ValidationError as direct_err:
            candidate = self._json_candidate(output_data)
            if candidate is None:
                return self._collect_errors(direct_err)
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError as exc:
                return [f"output is not valid JSON: {exc.msg}"], []
            try:
                self._model.model_validate(parsed)
                return [], []
            except ValidationError as parsed_err:
                return self._collect_errors(parsed_err)

    @staticmethod
    def _json_candidate(output_data: dict[str, Any]) -> str | None:
        for key in _JSON_CANDIDATE_KEYS:
            val = output_data.get(key)
            if isinstance(val, str):
                return val
        return None

    @staticmethod
    def _collect_errors(err: ValidationError) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        missing: list[str] = []
        for detail in err.errors():
            loc = ".".join(str(part) for part in detail["loc"]) or "<root>"
            if detail["type"] == "missing":
                missing.append(loc)
            else:
                errors.append(f"{loc}: {detail['msg']}")
        return errors, missing

    # -- grounding / hallucination ------------------------------------------

    def _check_grounding(self, context: ActionContext, output_text: str, source: str) -> None:
        mode = self._hallucination_mode
        score: float | None = None
        if mode == HallucinationMode.EMBEDDING:
            score = self._embedding_score(output_text, source)
            if score is None:
                mode = HallucinationMode.KEYWORD
        if score is None:
            score = keyword_grounding_score(output_text, source)

        flagged = score >= self._hallucination_threshold
        context.metadata["hallucination"] = {
            "risk": round(score, 4),
            "category": "hallucination",
            "mode": mode.value,
            "flagged": flagged,
            "threshold": self._hallucination_threshold,
        }
        if flagged:
            logger.warning(
                "hallucination_flagged",
                session_id=context.session_id,
                agent_id=context.agent_id,
                score=round(score, 4),
                mode=mode.value,
            )

    def _embedding_score(self, output_text: str, source: str) -> float | None:
        """1 - cosine similarity via sentence-transformers; None when unavailable."""
        try:
            from sentence_transformers import SentenceTransformer, util
        except ImportError:
            logger.warning(
                "embedding_backend_unavailable",
                hint="pip install openscript[ml]; falling back to keyword grounding",
            )
            return None
        if self._embedder is None:
            self._embedder = SentenceTransformer("all-MiniLM-L6-v2")
        embeddings = self._embedder.encode([output_text, source])
        similarity = float(util.cos_sim(embeddings[0], embeddings[1]).item())
        return max(0.0, 1.0 - similarity)

    # -- events --------------------------------------------------------------

    async def _emit_validation_event(self, context: ActionContext) -> None:
        seq = self._next_sequence(context.session_id)
        event = Event(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.POLICY_EVALUATED,
            payload={
                "policy": "output_schema",
                "output_validation": context.metadata["output_validation"],
                "decision": context.decision.value,
            },
            sequence_num=seq,
        )
        await self._writer.write(event)  # type: ignore[union-attr]

    def _next_sequence(self, session_id: str) -> int:
        count = self._sequence_counters.get(session_id, 0) + 1
        self._sequence_counters[session_id] = count
        return count
