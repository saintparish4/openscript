from __future__ import annotations

import re
import warnings
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode, InterceptorDecision

if TYPE_CHECKING:
    from events.writer import EventWriter

logger = structlog.get_logger(__name__)


class PIIMode(str, Enum):
    REDACT = "redact"
    DENY = "deny"


@dataclass(frozen=True)
class _PIIPattern:
    regex: re.Pattern[str]
    label: str


def _p(pattern: str, label: str) -> _PIIPattern:
    return _PIIPattern(re.compile(pattern, re.IGNORECASE), label)


_PII_PATTERNS: list[_PIIPattern] = [
    _p(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "email"),
    _p(r"\b(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b", "phone"),
    _p(r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
    # API / bearer tokens — must appear before generic patterns
    _p(r"\b(sk-|Bearer\s+|token[=:\s]+|api[_\-]?key[=:\s]+)[A-Za-z0-9\-_]{20,}\b", "api_key"),
    # IPv4 addresses
    _p(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", "ip_address"
    ),
]

# Credit card: 13-16 digits optionally separated by spaces or dashes.
# Validated with Luhn check to reduce false positives.
_CC_RE = re.compile(r"\b(?:\d[ \-]?){13,16}\b")


def _luhn(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    digits.reverse()
    total = sum(
        d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2) for i, d in enumerate(digits)
    )
    return total % 10 == 0


def _find_pii(text: str) -> list[tuple[str, str]]:
    """Return list of (matched_text, label) pairs found in text."""
    found: list[tuple[str, str]] = []
    for pat in _PII_PATTERNS:
        for m in pat.regex.finditer(text):
            found.append((m.group(), pat.label))
    for m in _CC_RE.finditer(text):
        raw = m.group()
        digits_only = re.sub(r"[ \-]", "", raw)
        if len(digits_only) >= 13 and _luhn(digits_only):
            found.append((raw, "credit_card"))
    return found


def _redact_text(text: str) -> tuple[str, list[str]]:
    """Replace PII matches with [REDACTED:<label>] tokens.

    Returns (redacted_text, list_of_found_labels).
    """
    found_labels: list[str] = []

    # Credit cards first (before phone regex can partially match)
    def _cc_replace(m: re.Match[str]) -> str:
        raw = m.group()
        digits_only = re.sub(r"[ \-]", "", raw)
        if len(digits_only) >= 13 and _luhn(digits_only):
            found_labels.append("credit_card")
            return "[REDACTED:credit_card]"
        return raw

    text = _CC_RE.sub(_cc_replace, text)

    for pat in _PII_PATTERNS:

        def _replace(m: re.Match[str], label: str = pat.label) -> str:
            found_labels.append(label)
            return f"[REDACTED:{label}]"

        text = pat.regex.sub(_replace, text)

    return text, list(dict.fromkeys(found_labels))  # deduplicate, preserve order


def _walk_redact(obj: Any) -> tuple[Any, list[str]]:
    """Recursively redact PII from strings inside dicts/lists."""
    all_labels: list[str] = []
    if isinstance(obj, str):
        redacted, labels = _redact_text(obj)
        all_labels.extend(labels)
        return redacted, all_labels
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            result[k], labels = _walk_redact(v)
            all_labels.extend(labels)
        return result, all_labels
    if isinstance(obj, list):
        result_list = []
        for item in obj:
            redacted_item, labels = _walk_redact(item)
            all_labels.extend(labels)
            result_list.append(redacted_item)
        return result_list, all_labels
    return obj, []


class PIIPolicy:
    """Scans agent output for PII and either redacts or blocks.

    Runs in after_action. before_action is a pass-through.
    Default mode is REDACT so observability is preserved; use DENY for
    strict environments.
    """

    failure_mode: FailureMode = FailureMode.FAIL_OPEN

    def __init__(
        self,
        mode: PIIMode = PIIMode.REDACT,
        writer: EventWriter | None = None,
    ) -> None:
        self._mode = mode
        self._writer = writer
        self._sequence_counters: dict[str, int] = {}

    async def before_action(self, context: ActionContext) -> ActionContext:
        return context

    async def after_action(self, context: ActionContext) -> ActionContext:
        redacted_output, found_labels = _walk_redact(context.output_data)

        if not found_labels:
            context.metadata["pii"] = {"found": [], "redacted": False}
            return context

        logger.warning(
            "pii_detected",
            session_id=context.session_id,
            agent_id=context.agent_id,
            types=found_labels,
            mode=self._mode.value,
        )

        if self._mode == PIIMode.DENY:
            context.metadata["pii"] = {"found": found_labels, "redacted": False}
            context.decision = InterceptorDecision.DENY
            context.decision_reason = f"PII detected in output: {', '.join(set(found_labels))}"
        else:
            context.output_data = redacted_output
            context.metadata["pii"] = {"found": found_labels, "redacted": True}

        if self._writer is not None:
            await self._emit_pii_event(context, found_labels)

        return context

    async def _emit_pii_event(self, context: ActionContext, found_labels: list[str]) -> None:
        seq = self._next_sequence(context.session_id)
        event = Event(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.POLICY_EVALUATED,
            payload={
                "policy": "pii_check",
                "pii_types": list(set(found_labels)),
                "mode": self._mode.value,
                "decision": context.decision.value,
            },
            sequence_num=seq,
        )
        await self._writer.write(event)  # type: ignore[union-attr]

    def _next_sequence(self, session_id: str) -> int:
        count = self._sequence_counters.get(session_id, 0) + 1
        self._sequence_counters[session_id] = count
        return count


class PIIInterceptor(PIIPolicy):
    """Deprecated — use PIIPolicy instead."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "PIIInterceptor is deprecated; use PIIPolicy instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)
