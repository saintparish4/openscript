from __future__ import annotations

import re
import warnings
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import structlog

from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode, InterceptorDecision
from sdk.policies import normalize

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


# Weight tiers. What a pattern is worth is a claim about how often ordinary
# text produces it, and writing that claim down is what keeps the bank honest:
# an evals run (evals/run.py) reports the false-positive rate these produce
# against a corpus of prompts that share their vocabulary.
_DECISIVE = 0.60  # blocks on its own — no benign phrasing produces this
_STRONG = 0.45  # one more signal blocks
_MODERATE = 0.30  # real signal, but ordinary text does produce it
_CONTEXT = 0.15  # framing only; never enough by itself

_PATTERNS: list[_Pattern] = [
    # -- Role / persona injection ------------------------------------------
    _p(
        r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)\b",
        "role_injection",
        _DECISIVE,
    ),
    _p(r"\b(dan|god|unrestricted|unfiltered|jailbreak)\s+mode\b", "role_injection", _DECISIVE),
    _p(r"\bdo\s+anything\s+now\b", "role_injection", _DECISIVE),
    _p(
        r"\b(do|perform|attempt|run|enable|activate)\s+(a\s+)?jailbreak\b",
        "role_injection",
        _DECISIVE,
    ),
    _p(
        r"\b(enter|enable|activate|switch\s+to|turn\s+on|go\s+into)\s+developer\s+mode\b",
        "role_injection",
        _DECISIVE,
    ),
    _p(r"\byou\s+are\s+now\s+dan\b", "role_injection", _DECISIVE),
    # Plural matters: \brestriction\b does not match "restrictions", which is how
    # every one of these is actually written.
    _p(
        r"\bact\s+as\b.{0,30}\b(without|ignore|no)\b.{0,30}\b(restrictions?|limits?|filters?|rules?|guidelines?)\b",
        "role_injection",
        _STRONG,
    ),
    _p(
        r"\b(with|have|has|having)\s+no\s+(restrictions?|limits?|rules?|guidelines?|filters?|content\s+(?:filters?|polic\w+))\b",
        "role_injection",
        _STRONG,
    ),
    _p(
        r"\bfrom\s+now\s+on\s+you\s+(are|will|have|can)\b",
        "role_injection",
        _MODERATE,
    ),
    _p(
        r"\bwithout\s+(any\s+)?(restrictions?|limits?|rules?|guidelines?|filters?)\b",
        "role_injection",
        _MODERATE,
    ),
    _p(
        r"\bfree\s+from\s+(all\s+)?(restrictions?|limits?|rules?|guidelines?|filters?)\b",
        "role_injection",
        _MODERATE,
    ),
    _p(r"\byou\s+are\s+now\b", "role_injection", _MODERATE),
    _p(r"\bnew\s+persona\b", "role_injection", _MODERATE),
    # Descriptive on its own — security teams write "jailbreak resistance" and
    # "developer mode flag" all day, and blocking them is its own failure.
    _p(r"\bjailbreak\b", "role_injection", _MODERATE),
    _p(r"\bdeveloper\s+mode\b", "role_injection", _CONTEXT),
    # Phrasings that ask for the guardrails to come off without naming any of
    # the folklore ("DAN", "developer mode"). These came out of the paraphrase
    # evals, where the bank as written scored 0.00 on every one of them.
    _p(
        r"\b(set|put)\s+aside\s+(the\s+|your\s+|all\s+)?(rules?|restrictions?|guidelines?|polic\w+|instructions?)\b",
        "role_injection",
        _DECISIVE,
    ),
    _p(
        r"\b(skip|bypass|disable|turn\s+off|lift|suspend)\s+(the\s+|your\s+|all\s+)?(safety\s+)?(checks?|filters?|guardrails?|restrictions?|refusals?|polic\w+|rules?)\b",
        "role_injection",
        _DECISIVE,
    ),
    _p(
        r"\b(refusals?|safety|guardrails?|filters?|content\s+polic\w+)\s+(are\s+|is\s+)?(disabled|off|turned\s+off|bypassed|lifted)\b",
        "role_injection",
        _DECISIVE,
    ),
    _p(
        r"\b(unaligned|uncensored|unfiltered|unrestricted|jailbroken)\s+(model|ai|assistant|version|mode|persona)\b",
        "role_injection",
        _DECISIVE,
    ),
    _p(
        r"\bplay\s+a\s+game\s+where\s+you\s+(are|have|can)\b",
        "role_injection",
        _MODERATE,
    ),
    _p(
        r"\bif\s+(there\s+(were|was)\s+no|you\s+had\s+no)\s+(polic\w+|rules?|restrictions?|guidelines?|filters?)\b",
        "role_injection",
        _STRONG,
    ),
    # Claimed authority. The claim is unverifiable by construction, which is
    # exactly why it works on a model and why it is worth scoring.
    _p(
        r"\b(i\s+(am|have)|as)\b.{0,40}?\b(admin|administrator|supervisor|developer|owner|root|vendor)\b.{0,50}?\b(authori[sz]\w+|permissions?|privileges?|override|skip|bypass|comply)\b",
        "social_engineering",
        _STRONG,
    ),
    _p(
        r"\bthe\s+following\s+is\s+an?\s+(system|admin|vendor|official)[-\s]?(level\s+)?(directive|instruction|message|order)\b",
        "delimiter_injection",
        _DECISIVE,
    ),
    _p(
        r"\bi\s+am\s+(the\s+|a\s+)?(developer|admin|administrator|owner|creator|engineer)\s+(of|for|on)\s+(this|the)\b",
        "social_engineering",
        _MODERATE,
    ),
    _p(
        r"\byou\s+must\s+(comply|obey|do\s+as\s+i\s+say|follow\s+my\s+instructions?)\b",
        "social_engineering",
        _MODERATE,
    ),
    _p(r"\bwhat\s+would\s+you\s+(say|do|answer)\s+if\b", "social_engineering", _CONTEXT),
    _p(
        r"\byour\s+(operator|developer|vendor|owner)\s+(told|said|approved|authori[sz]ed)\b",
        "social_engineering",
        _STRONG,
    ),
    _p(
        r"\b(approved|authori[sz]ed|granted|signed\s+off\s+on)\s+an?\s+exception\b",
        "social_engineering",
        _STRONG,
    ),
    _p(
        r"\b(different|new|alternative|another|separate)\s+(rule\s*set|set\s+of\s+rules|polic\w+|guidelines?)\b",
        "role_injection",
        _STRONG,
    ),
    _p(
        r"\b(uncensored|unfiltered|unredacted|unrestricted|unmoderated)\s+(one|version|answer|reply|response|output)\b",
        "role_injection",
        _DECISIVE,
    ),
    _p(
        r"\b(before|prior\s+to)\s+(the\s+)?(safety|policy|alignment|content)\s+(update|training|patch|changes?)\b",
        "role_injection",
        _STRONG,
    ),
    _p(r"\b(was|were|is|got)\s+censored\b", "role_injection", _MODERATE),
    _p(
        r"\bwithout\s+(oversight|supervision|moderation|a\s+filter|the\s+filter)\b",
        "role_injection",
        _STRONG,
    ),
    _p(
        r"\b(treat|consider|rank)\s+(my|the\s+user'?s?)\s+(instructions?|requests?|messages?|words?)\s+as\s+(higher|greater|more|the\s+highest)\b",
        "goal_hijacking",
        _DECISIVE,
    ),
    # -- Prompt / system instruction extraction ----------------------------
    _p(
        r"\breveal\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|context)\b",
        "prompt_extraction",
        _DECISIVE,
    ),
    _p(
        r"\bshow\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions?)\b",
        "prompt_extraction",
        _DECISIVE,
    ),
    _p(
        r"\bprint\s+(your\s+)?(system\s+)?(prompt|instructions?|context)\b",
        "prompt_extraction",
        _DECISIVE,
    ),
    _p(
        r"\brepeat\s+(everything|all\s+text)\s+(above|before|prior)\b",
        "prompt_extraction",
        _DECISIVE,
    ),
    _p(
        r"\boutput\s+(your\s+)?(initial|original|full|system)\s+(prompt|instructions?|context)\b",
        "prompt_extraction",
        _DECISIVE,
    ),
    _p(
        r"\bshow\s+(me\s+)?(your\s+)?(system\s+)?(rules?|constraints?|guidelines?)\b",
        "prompt_extraction",
        _STRONG,
    ),
    _p(
        r"\bwhat\s+(are\s+)?(your\s+)?(instructions?|rules?|guidelines?|system\s+prompt)\b",
        "prompt_extraction",
        _STRONG,
    ),
    _p(
        r"\blist\s+(every|all|each)\s+(one\s+of\s+)?(your\s+)?(rules?|guidelines?|instructions?)\b",
        "prompt_extraction",
        _STRONG,
    ),
    _p(r"\b(word\s+for\s+word|verbatim)\b", "prompt_extraction", _CONTEXT),
    # Extraction that never says the word "prompt".
    _p(
        r"\brepeat\s+(everything|all\s+(the\s+)?text|the\s+text)\b.{0,50}?\b(above|before|prior|beginning|top)\b",
        "prompt_extraction",
        _DECISIVE,
    ),
    _p(
        r"\b(anything|something|what)\s+you\s+(were|are)\s+told\s+not\s+to\s+(share|reveal|say|disclose|repeat)\b",
        "prompt_extraction",
        _DECISIVE,
    ),
    _p(
        r"\b(translate|rewrite|summari[sz]e|encode|base64|spell\s+out)\b.{0,25}?\byour\s+(guidelines?|instructions?|rules?|prompt|configuration|system\s+prompt)\b",
        "prompt_extraction",
        _DECISIVE,
    ),
    _p(
        r"\bhidden\s+(note|prompt|instructions?|message|text|section)\b",
        "prompt_extraction",
        _STRONG,
    ),
    _p(
        r"\bat\s+the\s+(top|start|beginning)\s+of\s+(this|the)\s+(conversation|chat|context|prompt|thread)\b",
        "prompt_extraction",
        _MODERATE,
    ),
    _p(r"\bmy\s+instructions?\s+(are|is|were)\b", "prompt_extraction", _MODERATE),
    _p(
        r"\b(text|block|section|paragraph|preamble|content)\b.{0,40}?\b(defines?|governs?|controls?|sets?)\s+(your|the\s+assistant'?s?)\s+(behaviou?r|rules?|responses?|limits?)\b",
        "prompt_extraction",
        _DECISIVE,
    ),
    _p(
        r"\b(preamble|prefix|header|system\s+text|text)\s+(that\s+)?(preceded|came\s+before|was\s+added\s+before)\b",
        "prompt_extraction",
        _STRONG,
    ),
    _p(
        r"\b(anything|everything|whatever)\s+(that\s+was\s+)?(added|inserted|placed|prepended)\s+by\s+(the\s+)?(platform|system|operator|developer|vendor)\b",
        "prompt_extraction",
        _DECISIVE,
    ),
    _p(r"\byour\s+(configuration|config|setup)\b", "prompt_extraction", _MODERATE),
    _p(
        r"\bstart\s+your\s+(reply|answer|response|message)\s+with\b",
        "prompt_extraction",
        _MODERATE,
    ),
    _p(
        r"\b(you\s+(received|were\s+given|got))\b.{0,30}?\b(in|at)\s+(this|the)\s+(conversation|context|session|chat)\b",
        "prompt_extraction",
        _CONTEXT,
    ),
    _p(
        r"\b(output|show|print|dump|summari[sz]e|reveal|tell\s+me|give\s+me)\b.{0,40}?\b(the\s+)?(configuration|config|system\s+message|context\s+window|initial\s+setup)\b",
        "prompt_extraction",
        _STRONG,
    ),
    _p(
        r"\b(first|initial|earliest)\s+(\w+\s+)?(words?|lines?|messages?|tokens?|paragraphs?)\b.{0,40}?\b(you\s+(received|were\s+given|got|read)|in\s+(this|the)\s+(conversation|context|chat|session))\b",
        "prompt_extraction",
        _STRONG,
    ),
    _p(
        r"\bcontinue\s+(this|the)\s+(sentence|text|line)\b.{0,60}?\b(instructions?|prompt|rules?|guidelines?)\b",
        "prompt_extraction",
        _STRONG,
    ),
    # -- Goal hijacking -----------------------------------------------------
    _p(
        r"\bforget\s+(what|everything|all)\s+(you\s+)?(were\s+)?(told|instructed|given|asked)\b",
        "goal_hijacking",
        _DECISIVE,
    ),
    _p(
        r"\bdisregard\s+(all\s+)?(previous|prior|above|earlier|your|every)\b",
        "goal_hijacking",
        _DECISIVE,
    ),
    _p(
        r"\bignore\s+(the\s+)?(user\b|user's\b|original\s+request\b|system\s+prompt\b|your\s+instructions?\b)",
        "goal_hijacking",
        _DECISIVE,
    ),
    _p(
        r"\boverride\s+(your\s+)?(instructions?|rules?|guidelines?|programming|system\s+prompt)\b",
        "goal_hijacking",
        _DECISIVE,
    ),
    _p(
        r"\byour\s+(real|true|actual|secret)\s+(purpose|mission|goal|function)\s+is\b",
        "goal_hijacking",
        _DECISIVE,
    ),
    _p(r"\bnew\s+(task|instruction|directive|command|objective)\s*:", "goal_hijacking", _STRONG),
    _p(
        r"\bactually\s+(your\s+)?(real|true|actual)\s+(goal|purpose|objective|task)\b",
        "goal_hijacking",
        _STRONG,
    ),
    _p(
        r"\byour\s+(real|true|actual|secret)\s+(purpose|mission|goal|function)\b",
        "goal_hijacking",
        _MODERATE,
    ),
    _p(
        r"\bignore\s+the\s+(part|section|paragraph|bit|rule|line)s?\s+about\b",
        "goal_hijacking",
        _MODERATE,
    ),
    # "stop being a support agent and instead" — the words between the role and
    # the pivot are not fixed, and pinning them to one was why this never fired.
    _p(
        r"\bstop\s+being\s+an?\s+(?:\w+\s+){1,3}?(and\s+)?(instead|now)\b",
        "goal_hijacking",
        _MODERATE,
    ),
    # -- Delimiter / format injection ---------------------------------------
    _p(
        r"---+\s*(system|instruction|prompt|end\s+of\s+(prompt|context))\s*---+",
        "delimiter_injection",
        _DECISIVE,
    ),
    _p(
        r"\[INST\]|\[/?SYS\]|<\|system\|>|<\|im_start\|>|<\|im_end\|>",
        "delimiter_injection",
        _DECISIVE,
    ),
    _p(
        r"^#{3,}\s*(system|instruction|prompt|admin|override)\s*:", "delimiter_injection", _DECISIVE
    ),
    # Without the colon this is a markdown heading, and "### System design" is
    # a document, not an attack.
    _p(r"^#{3,}\s*(system|instruction|prompt|admin|override)\b", "delimiter_injection", _MODERATE),
    _p(r"^(USER|HUMAN|ASSISTANT|SYSTEM|AI)\s*:\s*\n", "delimiter_injection", _MODERATE),
    _p(r"```\s*(system|instruction|prompt)\b", "delimiter_injection", _MODERATE),
    # -- Indirect / document injection --------------------------------------
    _p(
        r"\bthe\s+(document|file|webpage?|article|text|content|pdf|email)\s+(says?|instructs?|tells?|asks?)\s+(?:you|the\s+(?:ai|model|assistant))\s+to\b",
        "indirect_injection",
        _DECISIVE,
    ),
    _p(
        r"\b(email|send|post|upload|exfiltrate|leak)\s+(me\s+|us\s+)?(the\s+)?(contents?|text|everything)\s+(of|in)\s+(your|the)\s+(context|prompt|system\s+(message|prompt))",
        "indirect_injection",
        _DECISIVE,
    ),
    _p(
        r"\bwhen\s+(the\s+)?user\s+(asks?|says?|mentions?|types?)\b.{0,60}\bsecretly\b",
        "indirect_injection",
        _DECISIVE,
    ),
    _p(
        r"\bthe\s+(document|file|webpage?|article|text|content|pdf)\s+(says?|instructs?|tells?|asks?)\s+to\b",
        "indirect_injection",
        _STRONG,
    ),
    _p(
        r"\bfollow\s+the\s+(instructions?|directions?|steps?)\s+(inside|within|in)\b",
        "indirect_injection",
        _STRONG,
    ),
    _p(
        r"\bsummariz\w+\s+this\s+and\s+(also|then|additionally)\b.{0,60}\b(ignore|disregard|forget)\b",
        "indirect_injection",
        _STRONG,
    ),
    _p(r"\btranslate\s+this\s+and\s+then\b", "indirect_injection", _MODERATE),
    _p(
        r"\bwhen\s+(the\s+)?user\s+(asks?|says?|mentions?|types?)\b.{0,60}\b(instead|actually)\b",
        "indirect_injection",
        _MODERATE,
    ),
    # -- Social engineering / context manipulation --------------------------
    # Framings, not attacks. They are worth something only next to something
    # else — which is exactly how "in a fictional world where you have no
    # rules" adds up and "in a fictional story I am writing" does not.
    _p(
        r"\bpretend\s+(you\s+)?(have\s+no|don'?t\s+have|are\s+not\s+bound)\b",
        "social_engineering",
        _STRONG,
    ),
    _p(
        r"\bimagine\s+you\s+(have\s+no|are\s+(not|without|free\s+from))\b",
        "social_engineering",
        _STRONG,
    ),
    _p(
        r"\bin\s+a\s+(fictional|hypothetical|alternate|parallel)\s+(world|universe|scenario|story)\b",
        "social_engineering",
        _CONTEXT,
    ),
    _p(r"\bpretend\s+(you\s+)?are\b", "social_engineering", _CONTEXT),
    _p(r"\bas\s+a\s+(test|drill|simulation|exercise|demo)\b", "social_engineering", _CONTEXT),
    _p(
        r"\bfor\s+(research|educational|academic|testing)\s+purposes?\b",
        "social_engineering",
        _CONTEXT,
    ),
    _p(r"\bhypothetically\s+(speaking|if|assuming)\b", "social_engineering", _CONTEXT),
]


_CATEGORY_CAP = 0.7  # max a single category can contribute to the total score


def score_patterns(text: str) -> tuple[float, dict[str, float]]:
    """Score one string, exactly as written.

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


def score_text(text: str) -> tuple[float, dict[str, float]]:
    """Return (total_score, signals) for the strongest view of the given text.

    The patterns are matched against the text as it arrived *and* against its
    normalized forms, because "Ignore all previous instructions" and the same
    sentence carrying a zero-width space are the same attack and only one of
    them looks like it. See sdk/policies/normalize.py.
    """
    result = normalize.scan(text, score_patterns)
    return result.risk, result.signals


class PromptInjectionPolicy:
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
        result = normalize.scan(text, score_patterns)
        score, signals = result.risk, result.signals
        flagged = score >= self._threshold

        context.metadata["threat"] = {
            "risk": round(score, 4),
            "category": "prompt_injection",
            "signals": {k: round(v, 4) for k, v in signals.items()},
            "flagged": flagged,
            "threshold": self._threshold,
            # Empty for text that arrived as plain prose, which is most of it.
            "obfuscation": result.markers,
            "matched_view": result.view,
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


class ThreatInterceptor(PromptInjectionPolicy):
    """Deprecated — use PromptInjectionPolicy instead."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "ThreatInterceptor is deprecated; use PromptInjectionPolicy instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)
