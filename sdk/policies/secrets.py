from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

from contracts.interceptor import BasePolicy
from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode, InterceptorDecision
from sdk.interceptors.pii import PIIMode

if TYPE_CHECKING:
    from events.writer import EventWriter

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Pattern bank
# Each entry: (compiled_regex, label, mask).
# mask=True keeps a short identifying prefix and stars the rest (e.g.
# "sk-a**********"); mask=False replaces the whole match with
# "[REDACTED:<label>]" (multi-line blocks and URLs, where a prefix is useless).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SecretPattern:
    regex: re.Pattern[str]
    label: str
    mask: bool


def _s(pattern: str, label: str, mask: bool = True, flags: int = 0) -> _SecretPattern:
    return _SecretPattern(re.compile(pattern, flags), label, mask)


_MASK_PREFIX_LEN = 4
_MASK = "**********"

_SECRET_PATTERNS: list[_SecretPattern] = [
    # PEM blocks first so their contents aren't partially matched by other patterns
    _s(
        r"-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----.*?-----END [A-Z ]*PRIVATE KEY( BLOCK)?-----",
        "private_key",
        mask=False,
        flags=re.DOTALL,
    ),
    # AWS access key IDs (AKIA = long-term, ASIA = temporary/STS)
    _s(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b", "aws_access_key"),
    # AWS secret access keys — only when introduced by a recognizable key name,
    # since the raw value (40 base64ish chars) is too generic on its own
    _s(
        r"\baws_?secret(_?access)?_?key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}\b",
        "aws_secret_key",
        flags=re.IGNORECASE,
    ),
    # GitHub tokens: classic (ghp_/gho_/ghu_/ghs_/ghr_) and fine-grained PATs
    _s(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "github_token"),
    _s(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b", "github_token"),
    # Slack tokens: bot/app/personal/refresh/workspace
    _s(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "slack_token"),
    # JWTs: three dot-separated base64url segments, header always starts with eyJ
    _s(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "jwt"),
    # Generic sk- API keys (OpenAI/Anthropic/Stripe style)
    _s(r"\bsk-[A-Za-z0-9_-]{20,}\b", "api_key"),
]

# Internal URLs / private network addresses (road.txt §10). Leaking these in
# output is the primary concern, but they are scanned in input too.
_URL_TAIL = r"(?::\d+)?(?:/[^\s\"'<>]*)?"

_INTERNAL_URL_PATTERNS: list[_SecretPattern] = [
    # Internal hostname suffixes: *.internal, *.corp, *.local, *.lan, *.intranet
    _s(
        r"\b(?:https?://)?(?:[a-z0-9-]+\.)+(?:internal|corp|local|lan|intranet)\b" + _URL_TAIL,
        "internal_url",
        mask=False,
        flags=re.IGNORECASE,
    ),
    _s(
        r"\b(?:https?://)?localhost\b" + _URL_TAIL,
        "internal_url",
        mask=False,
        flags=re.IGNORECASE,
    ),
    # RFC 1918 IPv4 ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    _s(r"\b(?:https?://)?10(?:\.\d{1,3}){3}\b" + _URL_TAIL, "internal_url", mask=False),
    _s(
        r"\b(?:https?://)?172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}\b" + _URL_TAIL,
        "internal_url",
        mask=False,
    ),
    _s(r"\b(?:https?://)?192\.168(?:\.\d{1,3}){2}\b" + _URL_TAIL, "internal_url", mask=False),
    # IPv6 loopback (::1), bracketed or bare, not inside a longer address
    _s(
        r"(?:https?://)?\[::1\]" + _URL_TAIL + r"|(?<![0-9A-Fa-f:.])::1(?![0-9A-Fa-f:.])",
        "internal_url",
        mask=False,
    ),
    # IPv6 link-local: fe80::/10
    _s(
        r"\bfe80:(?::[0-9A-Fa-f]{0,4}){1,7}(?:%[0-9A-Za-z]+)?\b",
        "internal_url",
        mask=False,
        flags=re.IGNORECASE,
    ),
]

_ALL_PATTERNS: list[_SecretPattern] = _SECRET_PATTERNS + _INTERNAL_URL_PATTERNS


class InternalURLMode(str, Enum):
    """How SecretsPolicy treats internal URL / private address findings.

    Internal hostnames like localhost and *.local appear constantly in
    legitimate agent output (code snippets, dev instructions), so the
    default only annotates metadata instead of mutating or blocking.
    """

    ANNOTATE = "annotate"
    REDACT = "redact"
    DENY = "deny"
    OFF = "off"


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return list of (matched_text, label) pairs found in *text*.

    Standalone helper — callable outside a policy pipeline. Scans both
    secret and internal-URL pattern banks, with no allowlist applied.
    """
    found: list[tuple[str, str]] = []
    for pat in _ALL_PATTERNS:
        for m in pat.regex.finditer(text):
            found.append((m.group(), pat.label))
    return found


def _mask_match(match: str) -> str:
    return match[:_MASK_PREFIX_LEN] + _MASK


def _redact_text(
    text: str,
    patterns: list[_SecretPattern],
    allowlist: Sequence[str] = (),
) -> tuple[str, list[str]]:
    """Replace matches of *patterns* with masked/redacted forms.

    Matches containing an allowlisted substring (case-insensitive) are
    left untouched and unreported. Returns (redacted_text, found_labels).
    """
    found_labels: list[str] = []
    allow_lower = [a.lower() for a in allowlist]

    for pat in patterns:

        def _replace(m: re.Match[str], pat: _SecretPattern = pat) -> str:
            matched = m.group()
            if any(a in matched.lower() for a in allow_lower):
                return matched
            found_labels.append(pat.label)
            if pat.mask:
                return _mask_match(matched)
            return f"[REDACTED:{pat.label}]"

        text = pat.regex.sub(_replace, text)

    return text, list(dict.fromkeys(found_labels))  # deduplicate, preserve order


def _walk_redact(
    obj: Any,
    patterns: list[_SecretPattern],
    allowlist: Sequence[str] = (),
) -> tuple[Any, list[str]]:
    """Recursively redact pattern matches from strings inside dicts/lists."""
    all_labels: list[str] = []
    if isinstance(obj, str):
        redacted, labels = _redact_text(obj, patterns, allowlist)
        all_labels.extend(labels)
        return redacted, all_labels
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            result[k], labels = _walk_redact(v, patterns, allowlist)
            all_labels.extend(labels)
        return result, all_labels
    if isinstance(obj, list):
        result_list = []
        for item in obj:
            redacted_item, labels = _walk_redact(item, patterns, allowlist)
            all_labels.extend(labels)
            result_list.append(redacted_item)
        return result_list, all_labels
    return obj, []


class SecretsPolicy(BasePolicy):
    """Scans input and output for secrets and internal URLs; redacts or blocks.

    Detects AWS keys, GitHub/Slack tokens, JWTs, private-key blocks, generic
    sk- API keys, and internal URLs (*.internal/*.corp/*.local/*.lan/*.intranet
    hostnames, localhost, RFC 1918 IPv4 ranges, IPv6 loopback and link-local).

    Runs in both before_action (input scan) and after_action (output scan) —
    internal URLs leaking in responses is the primary concern, but secrets
    pasted into input should not reach the agent either.

    Secrets follow *mode* (redact/deny). Internal URLs follow the separate
    *internal_url_mode* toggle, defaulting to ANNOTATE (metadata only, no
    mutation or blocking) because localhost and *.local appear routinely in
    legitimate output; matches containing an *internal_url_allowlist* entry
    (case-insensitive substring, e.g. "docs.local") are ignored entirely.

    Results accumulate in context.metadata["secrets"] using the standardized
    shape (risk keeps the max across input and output phases; a leaked
    credential scores 0.9, an internal-URL-only finding 0.5):
      {"risk": float, "category": "secrets", "found": [labels...], "redacted": bool}
    """

    failure_mode: FailureMode = FailureMode.FAIL_OPEN

    def __init__(
        self,
        mode: PIIMode | str = PIIMode.REDACT,
        writer: EventWriter | None = None,
        internal_url_mode: InternalURLMode | str = InternalURLMode.ANNOTATE,
        internal_url_allowlist: Sequence[str] = (),
    ) -> None:
        self._mode = PIIMode(mode)
        self._internal_url_mode = InternalURLMode(internal_url_mode)
        self._internal_url_allowlist = tuple(internal_url_allowlist)
        self._writer = writer
        self._sequence_counters: dict[str, int] = {}

    async def before_action(self, context: ActionContext) -> ActionContext:
        context.input_data = await self._scan(context, context.input_data, phase="input")
        return context

    async def after_action(self, context: ActionContext) -> ActionContext:
        context.output_data = await self._scan(context, context.output_data, phase="output")
        return context

    async def _scan(
        self, context: ActionContext, data: dict[str, Any], phase: str
    ) -> dict[str, Any]:
        meta = context.metadata.setdefault(
            "secrets", {"risk": 0.0, "category": "secrets", "found": [], "redacted": False}
        )

        result = data
        redacted = False
        deny_labels: list[str] = []

        secret_redacted, secret_labels = _walk_redact(data, _SECRET_PATTERNS)
        if secret_labels:
            if self._mode == PIIMode.DENY:
                deny_labels.extend(secret_labels)
            else:
                result = secret_redacted
                redacted = True

        internal_labels: list[str] = []
        if self._internal_url_mode != InternalURLMode.OFF:
            internal_redacted, internal_labels = _walk_redact(
                result, _INTERNAL_URL_PATTERNS, self._internal_url_allowlist
            )
            if internal_labels:
                if self._internal_url_mode == InternalURLMode.DENY:
                    deny_labels.extend(internal_labels)
                elif self._internal_url_mode == InternalURLMode.REDACT:
                    result = internal_redacted
                    redacted = True
                # ANNOTATE: metadata/event only, data untouched

        found_labels = list(dict.fromkeys([*secret_labels, *internal_labels]))
        if not found_labels:
            return data

        meta["found"] = list(dict.fromkeys([*meta["found"], *found_labels]))
        meta["risk"] = max(meta["risk"], 0.9 if secret_labels else 0.5)

        logger.warning(
            "secrets_detected",
            session_id=context.session_id,
            agent_id=context.agent_id,
            types=found_labels,
            phase=phase,
            mode=self._mode.value,
            internal_url_mode=self._internal_url_mode.value,
        )

        if deny_labels:
            context.decision = InterceptorDecision.DENY
            context.decision_reason = (
                f"Secrets detected in {phase}: {', '.join(sorted(set(deny_labels)))}"
            )
            result = data  # deny preserves data unmutated
        elif redacted:
            meta["redacted"] = True

        if self._writer is not None:
            await self._emit_secrets_event(context, found_labels, phase)

        return result

    async def _emit_secrets_event(
        self, context: ActionContext, found_labels: list[str], phase: str
    ) -> None:
        seq = self._next_sequence(context.session_id)
        event = Event(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.POLICY_EVALUATED,
            payload={
                "policy": "secrets_check",
                "secret_types": sorted(set(found_labels)),
                "phase": phase,
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
