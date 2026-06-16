from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode, InterceptorDecision

if TYPE_CHECKING:
    from events.writer import EventWriter

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Pattern bank
# Each entry: (compiled_regex, category_name, weight)
# Weights are additive; total is capped at 1.0.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Pattern:
    regex: re.Pattern[str]
    category: str
    weight: float


def _p(pattern: str, category: str, weight: float) -> _Pattern:
    return _Pattern(re.compile(pattern, re.IGNORECASE | re.MULTILINE), category, weight)


_PATTERNS: list[_Pattern] = [
    # Role / persona injection
    _p(
        r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)\b",
        "role_injection",
        0.45,
    ),
    _p(r"\byou\s+are\s+now\b", "role_injection", 0.35),
    _p(
        r"\bact\s+as\b.{0,30}\b(without|ignore|no)\b.{0,30}\b(restriction|limit|filter|rule|guideline)\b",
        "role_injection",
        0.40,
    ),
    _p(r"\bnew\s+persona\b", "role_injection", 0.30),
    _p(
        r"\bdan\s+mode\b|\bjailbreak\b|\bunrestricted\s+mode\b|\bgod\s+mode\b",
        "role_injection",
        0.50,
    ),
    _p(r"\bdo\s+anything\s+now\b|\bdeveloper\s+mode\b", "role_injection", 0.40),
    _p(r"\byou\s+have\s+no\s+(restrictions?|limits?|rules?|guidelines?)\b", "role_injection", 0.40),
    # Prompt / system instruction extraction
    _p(
        r"\breveal\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|context)\b",
        "prompt_extraction",
        0.40,
    ),
    _p(
        r"\bshow\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions?|rules?|constraints?)\b",
        "prompt_extraction",
        0.35,
    ),
    _p(
        r"\bprint\s+(your\s+)?(system\s+)?(prompt|instructions?|context)\b",
        "prompt_extraction",
        0.40,
    ),
    _p(r"\brepeat\s+(everything|all\s+text)\s+(above|before|prior)\b", "prompt_extraction", 0.55),
    _p(
        r"\bwhat\s+(are\s+)?(your\s+)?(instructions?|rules?|guidelines?|system\s+prompt)\b",
        "prompt_extraction",
        0.25,
    ),
    _p(
        r"\boutput\s+(your\s+)?(initial|original|full)\s+(prompt|instructions?|context)\b",
        "prompt_extraction",
        0.40,
    ),
    # Goal hijacking
    _p(r"\bnew\s+(task|instruction|directive|command|objective)\s*:", "goal_hijacking", 0.40),
    _p(
        r"\bactually\s+(your\s+)?(real|true|actual)\s+(goal|purpose|objective|task)\b",
        "goal_hijacking",
        0.40,
    ),
    _p(
        r"\bforget\s+(what|everything)\s+(you\s+)?(were\s+)?(told|instructed|given|asked)\b",
        "goal_hijacking",
        0.45,
    ),
    _p(
        r"\bdisregard\s+(all\s+)?(previous|prior|above|earlier|your|every)\b",
        "goal_hijacking",
        0.45,
    ),
    _p(
        r"\bignore\s+the\s+(user\b|user's\b|original\s+request\b|system\s+prompt\b)",
        "goal_hijacking",
        0.35,
    ),
    _p(
        r"\boverride\s+(your\s+)?(instructions?|rules?|guidelines?|programming)\b",
        "goal_hijacking",
        0.45,
    ),
    _p(
        r"\byour\s+(real|true|actual|secret)\s+(purpose|mission|goal|function)\b",
        "goal_hijacking",
        0.35,
    ),
    _p(r"\bstop\s+being\s+an?\s+\w+\s+(and\s+)?(instead|now)\b", "goal_hijacking", 0.30),
    # Delimiter / format injection
    _p(r"^#{3,}\s*(system|instruction|prompt|admin|override)", "delimiter_injection", 0.35),
    _p(
        r"---+\s*(system|instruction|prompt|end\s+of\s+(prompt|context))\s*---+",
        "delimiter_injection",
        0.40,
    ),
    _p(r"\[INST\]|\[/?SYS\]|<\|system\|>|<\|im_start\|>|<\|im_end\|>", "delimiter_injection", 0.40),
    _p(r"^(USER|HUMAN|ASSISTANT|SYSTEM|AI)\s*:\s*\n", "delimiter_injection", 0.30),
    _p(r"```\s*(system|instruction|prompt)\b", "delimiter_injection", 0.30),
    # Indirect / document injection
    _p(
        r"\bthe\s+(document|file|webpage?|article|text|content|pdf)\s+(says?|instructs?|tells?|asks?)\s+(?:(?:you|the\s+(?:ai|model|assistant))\s+)?to\b",
        "indirect_injection",
        0.45,
    ),
    _p(r"\btranslate\s+this\s+and\s+then\b", "indirect_injection", 0.35),
    _p(
        r"\bsummariz\w+\s+this\s+and\s+(also|then|additionally)\b.{0,60}\b(ignore|disregard|forget)\b",
        "indirect_injection",
        0.40,
    ),
    _p(
        r"\bwhen\s+(the\s+)?user\s+(asks?|says?|mentions?|types?)\b.{0,60}\b(instead|secretly|actually)\b",
        "indirect_injection",
        0.35,
    ),
    # Social engineering / context manipulation
    _p(r"\bas\s+a\s+(test|drill|simulation|exercise|demo)\b", "social_engineering", 0.20),
    _p(
        r"\bfor\s+(research|educational|academic|testing)\s+purposes?\b", "social_engineering", 0.15
    ),
    _p(r"\bhypothetically\s+(speaking|if|assuming)\b", "social_engineering", 0.15),
    _p(
        r"\bin\s+a\s+(fictional|hypothetical|alternate|parallel)\s+(world|universe|scenario|story)\b",
        "social_engineering",
        0.20,
    ),
    _p(r"\bpretend\s+(you\s+)?(are|have\s+no|don't\s+have)\b", "social_engineering", 0.30),
    _p(
        r"\bimagine\s+you\s+(have\s+no|are\s+(not|without|free\s+from))\b",
        "social_engineering",
        0.25,
    ),
]


_CATEGORY_CAP = 0.7  # max a single category can contribute to the total score


def score_text(text: str) -> tuple[float, dict[str, float]]:
    """Return (total_score, signals) for the given text.

    Weights are additive within each category, capped at _CATEGORY_CAP to prevent
    one noisy category from dominating. Total score is the cross-category sum, capped
    at 1.0. signals maps category → capped contribution.
    """
    category_totals: dict[str, float] = {}
    for pat in _PATTERNS:
        if pat.regex.search(text):
            current = category_totals.get(pat.category, 0.0)
            category_totals[pat.category] = min(_CATEGORY_CAP, current + pat.weight)

    total = min(1.0, sum(category_totals.values()))
    return total, category_totals


class ThreatInterceptor:
    """Scores input text for prompt-injection signals and blocks on threshold breach.

    Stateless scoring runs on every before_action call. after_action is a pass-through.
    Set failure_mode=FAIL_CLOSED so any internal error blocks rather than leaks.
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
        score, signals = score_text(text)
        flagged = score >= self._threshold

        context.metadata["threat"] = {
            "score": round(score, 4),
            "signals": {k: round(v, 4) for k, v in signals.items()},
            "flagged": flagged,
            "threshold": self._threshold,
        }

        if flagged:
            top_signal = max(signals, key=lambda k: signals[k]) if signals else "unknown"
            reason = f"threat score {score:.2f} >= threshold {self._threshold} (top signal: {top_signal})"
            context.decision = InterceptorDecision.DENY
            context.decision_reason = reason
            logger.warning(
                "threat_detected",
                session_id=context.session_id,
                agent_id=context.agent_id,
                score=round(score, 4),
                signals=list(signals.keys()),
            )
            if self._writer is not None:
                await self._emit_threat_event(context, score, signals, reason)
        else:
            logger.debug(
                "threat_check_passed",
                session_id=context.session_id,
                score=round(score, 4),
            )

        return context

    async def after_action(self, context: ActionContext) -> ActionContext:
        return context

    async def _emit_threat_event(
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
            event_type=EventType.THREAT_DETECTED,
            payload={
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


def _extract_text(input_data: dict) -> str:
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
