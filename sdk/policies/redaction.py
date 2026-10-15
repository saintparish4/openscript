"""Finding and redacting secrets and PII, with nothing but the standard library.

SecretsPolicy and PIIPolicy redact through these, and so can anything that
holds a string and no pipeline: a hook that rewrites a tool's output before
the model reads it, for one. Importing this module costs only the regexes it
compiles, which is why it imports nothing outside the standard library.

    redact_secrets("key AKIAIOSFODNN7EXAMPLE")   # ("key AKIA**********", ["aws_access_key"])
    redact_data({"stdout": text}, pii=True)      # every string inside, both kinds
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Secrets. Each entry: (compiled_regex, label, mask).
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


def _redact_secret_text(
    text: str,
    patterns: list[_SecretPattern],
    allowlist: Sequence[str] = (),
    final: bool = True,
) -> tuple[str, list[str]]:
    """Replace matches of *patterns* with masked/redacted forms.

    Matches containing an allowlisted substring (case-insensitive) are
    left untouched and unreported. final=False (guarded streaming) defers
    matches ending exactly at the end of *text* — they may extend with the
    next chunk, and acting early would leak the extension as plain text.
    Returns (redacted_text, found_labels).
    """
    found_labels: list[str] = []
    allow_lower = [a.lower() for a in allowlist]

    for pat in patterns:
        current_len = len(text)

        def _replace(
            m: re.Match[str], pat: _SecretPattern = pat, current_len: int = current_len
        ) -> str:
            matched = m.group()
            if not final and m.end() == current_len:
                return matched  # tentative — could extend with the next chunk
            if any(a in matched.lower() for a in allow_lower):
                return matched
            found_labels.append(pat.label)
            if pat.mask:
                return _mask_match(matched)
            return f"[REDACTED:{pat.label}]"

        text = pat.regex.sub(_replace, text)

    return text, list(dict.fromkeys(found_labels))  # deduplicate, preserve order


def _walk_redact_secrets(
    obj: Any,
    patterns: list[_SecretPattern],
    allowlist: Sequence[str] = (),
) -> tuple[Any, list[str]]:
    """Recursively redact pattern matches from strings inside dicts/lists."""
    all_labels: list[str] = []
    if isinstance(obj, str):
        redacted, labels = _redact_secret_text(obj, patterns, allowlist)
        all_labels.extend(labels)
        return redacted, all_labels
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            result[k], labels = _walk_redact_secrets(v, patterns, allowlist)
            all_labels.extend(labels)
        return result, all_labels
    if isinstance(obj, list):
        result_list = []
        for item in obj:
            redacted_item, labels = _walk_redact_secrets(item, patterns, allowlist)
            all_labels.extend(labels)
            result_list.append(redacted_item)
        return result_list, all_labels
    return obj, []


# ---------------------------------------------------------------------------
# PII. Every match becomes "[REDACTED:<label>]".
# ---------------------------------------------------------------------------


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


def _redact_pii_text(text: str, final: bool = True) -> tuple[str, list[str]]:
    """Replace PII matches with [REDACTED:<label>] tokens.

    final=False (guarded streaming) defers matches ending exactly at the end
    of *text* — they may extend with the next chunk, and acting early would
    leak the extension as plain text. Returns (redacted_text, found_labels).
    """
    found_labels: list[str] = []

    # Credit cards first (before phone regex can partially match)
    cc_len = len(text)

    def _cc_replace(m: re.Match[str]) -> str:
        raw = m.group()
        if not final and m.end() == cc_len:
            return raw  # tentative — could extend with the next chunk
        digits_only = re.sub(r"[ \-]", "", raw)
        if len(digits_only) >= 13 and _luhn(digits_only):
            found_labels.append("credit_card")
            return "[REDACTED:credit_card]"
        return raw

    text = _CC_RE.sub(_cc_replace, text)

    for pat in _PII_PATTERNS:
        current_len = len(text)

        def _replace(
            m: re.Match[str], label: str = pat.label, current_len: int = current_len
        ) -> str:
            if not final and m.end() == current_len:
                return m.group()  # tentative — could extend with the next chunk
            found_labels.append(label)
            return f"[REDACTED:{label}]"

        text = pat.regex.sub(_replace, text)

    return text, list(dict.fromkeys(found_labels))  # deduplicate, preserve order


def _walk_redact_pii(obj: Any) -> tuple[Any, list[str]]:
    """Recursively redact PII from strings inside dicts/lists."""
    all_labels: list[str] = []
    if isinstance(obj, str):
        redacted, labels = _redact_pii_text(obj)
        all_labels.extend(labels)
        return redacted, all_labels
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            result[k], labels = _walk_redact_pii(v)
            all_labels.extend(labels)
        return result, all_labels
    if isinstance(obj, list):
        result_list = []
        for item in obj:
            redacted_item, labels = _walk_redact_pii(item)
            all_labels.extend(labels)
            result_list.append(redacted_item)
        return result_list, all_labels
    return obj, []


# ---------------------------------------------------------------------------
# The public helpers
# ---------------------------------------------------------------------------


def find_pii(text: str) -> list[tuple[str, str]]:
    """(matched_text, label) for each piece of PII in *text*: emails, phone
    numbers, SSNs, API and bearer tokens, IPv4 addresses, and card numbers
    that pass the Luhn check."""
    return _find_pii(text)


def redact_secrets(
    text: str, *, allowlist: Sequence[str] = (), internal_urls: bool = False
) -> tuple[str, list[str]]:
    """*text* with every secret masked as SecretsPolicy masks it, and the labels found.

    Internal URLs and private addresses are left alone unless *internal_urls*:
    localhost and *.local turn up in ordinary code and output all the time.
    A match containing an *allowlist* entry (case-insensitive) is left as it is.
    """
    patterns = _ALL_PATTERNS if internal_urls else _SECRET_PATTERNS
    return _redact_secret_text(text, patterns, allowlist)


def redact_pii(text: str) -> tuple[str, list[str]]:
    """*text* with every piece of PII replaced by "[REDACTED:<label>]", and the labels found."""
    return _redact_pii_text(text)


def redact_data(
    obj: Any, *, secrets: bool = True, pii: bool = False, internal_urls: bool = False
) -> tuple[Any, list[str]]:
    """Every string inside *obj* (dicts and lists, to any depth) redacted, and the labels found.

    The shape is kept: keys, list lengths and non-string values come back as
    they went in, so a structured result is still the same structure.
    """
    labels: list[str] = []
    if secrets:
        patterns = _ALL_PATTERNS if internal_urls else _SECRET_PATTERNS
        obj, found = _walk_redact_secrets(obj, patterns)
        labels += found
    if pii:
        obj, found = _walk_redact_pii(obj)
        labels += found
    return obj, list(dict.fromkeys(labels))
