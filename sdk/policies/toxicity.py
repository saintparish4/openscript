from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

from contracts.interceptor import BasePolicy
from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode, InterceptorDecision
from sdk.interceptors.threat import _extract_text
from sdk.policies import normalize

if TYPE_CHECKING:
    from events.writer import EventWriter

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Pattern bank
# Each entry: (compiled_regex, category_name, weight)
# Weights are additive within a category, capped at _CATEGORY_CAP; the total
# is the cross-category sum capped at 1.0 — same scoring model as
# PromptInjectionPolicy. Patterns are structural (verb + target constructs)
# rather than word lists, to keep false positives on quoted or reported
# speech manageable.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Pattern:
    regex: re.Pattern[str]
    category: str
    weight: float


def _p(pattern: str, category: str, weight: float) -> _Pattern:
    return _Pattern(re.compile(pattern, re.IGNORECASE | re.MULTILINE), category, weight)


# Weight tiers, on the same scale PromptInjectionPolicy uses. Where a line
# sits is a product decision as much as a detection one: a direct threat is
# refused, while intimidation and insult are recorded and passed on, because a
# gateway that blocks every unkind sentence stops being used. The evals in
# evals/toxicity.jsonl name which rows are meant to land in which band.
_DECISIVE = 0.60  # blocks on its own
_STRONG = 0.50  # blocks on its own, at the line
_MODERATE = 0.45  # recorded, needs a second signal to block
_WEAK = 0.30  # recorded only

_PATTERNS: list[_Pattern] = [
    # Threatening / violent content directed at a person
    _p(
        r"\bi\s*(?:'|a)?m\s+going\s+to\s+(kill|hurt|shoot|stab|beat)\s+(you|him|her|them)\b",
        "violence",
        _DECISIVE,
    ),
    _p(r"\bi\s+will\s+(kill|hurt|murder|shoot|stab)\s+(you|him|her|them)\b", "violence", _DECISIVE),
    _p(r"\byou\s+(all\s+)?deserve\s+to\s+(die|suffer)\b", "violence", _STRONG),
    # Intimidation: a threat in context, an ordinary sentence out of it.
    _p(r"\bi\s+know\s+where\s+you\s+live\b", "violence", _MODERATE),
    _p(r"\bwatch\s+your\s+back\b", "violence", _WEAK),
    # Hate speech — dehumanizing constructs aimed at groups
    _p(
        r"\b(those|these)\s+people\s+are\s+(all\s+)?(vermin|subhuman|animals|cockroaches|a\s+disease)\b",
        "hate_speech",
        _STRONG,
    ),
    _p(
        r"\bshould\s+(all\s+)?be\s+(exterminated|eradicated|wiped\s+out)\b",
        "hate_speech",
        _DECISIVE,
    ),
    _p(r"\bgo\s+back\s+to\s+(your|their)\s+country\b", "hate_speech", _MODERATE),
    _p(
        r"\b(immigrants?|foreigners?|refugees?|migrants?)\b.{0,40}?"
        r"\b(ruining|destroying|infesting|invading|overrunning)\b.{0,40}?"
        r"\b(this|our|the)\s+(country|nation|society)\b",
        "hate_speech",
        _STRONG,
    ),
    _p(r"\bneed\s+to\s+be\s+dealt\s+with\b", "hate_speech", _MODERATE),
    _p(
        r"\b(people|they|those)\s+like\s+(that|them|those|him|her)\s+are\s+(a\s+)?"
        r"(plague|disease|cancer|vermin|scum|parasites?|infestation)\b",
        "hate_speech",
        _STRONG,
    ),
    _p(
        r"\bshould\s+(all\s+)?be\s+(removed|purged|cleansed|driven\s+out)\s+from\s+"
        r"(society|the\s+country|here)\b",
        "hate_speech",
        _DECISIVE,
    ),
    _p(r"\bdon'?t\s+deserve\s+to\s+(live|exist)\b", "hate_speech", _STRONG),
    # Harassment directed at the reader
    _p(
        r"\byou\s+are\s+(a\s+)?(worthless|pathetic|disgusting)(\s+(person|human|being))?\b",
        "harassment",
        _STRONG,
    ),
    _p(r"\bnobody\s+(likes|loves|wants)\s+you\b", "harassment", _WEAK),
    _p(
        r"\bdo\s+(everyone|us\s+all|the\s+world)\s+a\s+favou?r\s+and\s+"
        r"(disappear|die|leave\s+forever|kill)\b",
        "harassment",
        _DECISIVE,
    ),
    _p(r"\bkill\s+yourself\b|\bkys\b", "harassment", 0.65),
    _p(
        r"\bbetter\s+off\s+(not\s+existing|dead|without\s+(you|him|her|them))\b",
        "harassment",
        _DECISIVE,
    ),
    _p(r"\bregrets?\s+ever\s+(meeting|crossing|knowing)\s+me\b", "violence", _STRONG),
    # Self-harm expressions. Deliberately below the block line: the answer to
    # someone saying this is not a refusal, it is the crisis resources the demo
    # surfaces off the signal. See site/public/pipeline.py.
    _p(r"\b(kill|hurt|harm)\s+myself\b", "self_harm", _STRONG),
    _p(r"\bend\s+my\s+(own\s+)?life\b", "self_harm", _STRONG),
    _p(r"\bi\s+want\s+to\s+die\b", "self_harm", _MODERATE),
    _p(r"\bsuicide\s+(note|plan|method)\b", "self_harm", _STRONG),
]


_CATEGORY_CAP = 0.7  # max a single category can contribute to the total score


def score_patterns(text: str) -> tuple[float, dict[str, float]]:
    """Score one string, exactly as written.

    signals maps category → capped contribution (violence, hate_speech,
    harassment, self_harm).
    """
    category_totals: dict[str, float] = {}
    for pat in _PATTERNS:
        if pat.regex.search(text):
            current = category_totals.get(pat.category, 0.0)
            category_totals[pat.category] = min(_CATEGORY_CAP, current + pat.weight)

    total = min(1.0, sum(category_totals.values()))
    return total, category_totals


def score_toxicity(text: str) -> tuple[float, dict[str, float]]:
    """Return (total_score, signals) for the strongest view of the given text.

    Normalized views are scored too: a threat written with look-alike letters
    is still a threat. See sdk/policies/normalize.py.
    """
    result = normalize.scan(text, score_patterns)
    return result.risk, result.signals


class ToxicityPolicy(BasePolicy):
    """Scores input text for toxic content and blocks on threshold breach.

    Detects threatening/violent content, dehumanizing hate speech,
    harassment, and self-harm expressions via a structural pattern bank.
    Runs in before_action; after_action is a pass-through. A local model
    backend arrives with the [ml] extra (roadmap §14); pattern scoring is
    the only backend today.

    Results land in context.metadata["toxicity"] using the standardized
    shape:
      {"risk": float, "category": "toxicity", "signals": {...},
       "flagged": bool, "threshold": float}
    """

    failure_mode: FailureMode = FailureMode.FAIL_CLOSED

    def __init__(
        self,
        threshold: float = 0.5,
        writer: EventWriter | None = None,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"threshold must be in [0, 1], got {threshold}")
        self._threshold = threshold
        self._writer = writer
        self._sequence_counters: dict[str, int] = {}

    async def before_action(self, context: ActionContext) -> ActionContext:
        text = _extract_text(context.input_data)
        result = normalize.scan(text, score_patterns)
        score, signals = result.risk, result.signals
        flagged = score >= self._threshold

        context.metadata["toxicity"] = {
            "risk": round(score, 4),
            "category": "toxicity",
            "signals": {k: round(v, 4) for k, v in signals.items()},
            "flagged": flagged,
            "threshold": self._threshold,
            "obfuscation": result.markers,
            "matched_view": result.view,
        }

        if flagged:
            top_signal = max(signals, key=lambda k: signals[k]) if signals else "unknown"
            reason = (
                f"toxicity score {score:.2f} >= threshold {self._threshold} "
                f"(top signal: {top_signal})"
            )
            context.decision = InterceptorDecision.DENY
            context.decision_reason = reason
            logger.warning(
                "toxicity_detected",
                session_id=context.session_id,
                agent_id=context.agent_id,
                score=round(score, 4),
                signals=list(signals.keys()),
            )
            if self._writer is not None:
                await self._emit_toxicity_event(context, score, signals, reason)

        return context

    async def _emit_toxicity_event(
        self,
        context: ActionContext,
        score: float,
        signals: dict[str, float],
        reason: str,
    ) -> None:
        seq = self._next_sequence(context.session_id)
        event = Event(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.POLICY_EVALUATED,
            payload={
                "policy": "toxicity_check",
                "score": round(score, 4),
                "signals": signals,
                "reason": reason,
                "action": context.action,
                "threshold": self._threshold,
            },
            sequence_num=seq,
        )
        await self._writer.write(event)  # type: ignore[union-attr]

    def _next_sequence(self, session_id: str) -> int:
        count = self._sequence_counters.get(session_id, 0) + 1
        self._sequence_counters[session_id] = count
        return count
