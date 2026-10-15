from __future__ import annotations

import re
from collections.abc import Sequence
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import structlog

from contracts.interceptor import BasePolicy, GuardScan, StreamGuard
from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode, InterceptorDecision
from sdk.interceptors.pii import PIIMode
from sdk.policies.redaction import _INTERNAL_URL_PATTERNS, _SECRET_PATTERNS
from sdk.policies.redaction import _redact_secret_text as _redact_text
from sdk.policies.redaction import _walk_redact_secrets as _walk_redact
from sdk.policies.redaction import find_secrets as find_secrets

if TYPE_CHECKING:
    from events.writer import EventWriter

logger = structlog.get_logger(__name__)

# Guarded streaming: longest realistic bounded secret (fat JWTs run long;
# everything else is well under 100 chars). PEM blocks are unbounded and are
# handled by their header instead.
_GUARD_MAX_MATCH_LEN = 512
_PEM_HEADER_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----")


class InternalURLMode(StrEnum):
    """How SecretsPolicy treats internal URL / private address findings.

    Internal hostnames like localhost and *.local appear constantly in
    legitimate agent output (code snippets, dev instructions), so the
    default only annotates metadata instead of mutating or blocking.
    """

    ANNOTATE = "annotate"
    REDACT = "redact"
    DENY = "deny"
    OFF = "off"


class _SecretsStreamGuard:
    """Incremental scanner backing SecretsPolicy in guarded streams."""

    name = "SecretsPolicy"
    max_match_len = _GUARD_MAX_MATCH_LEN

    def __init__(
        self,
        mode: PIIMode,
        internal_url_mode: InternalURLMode,
        allowlist: Sequence[str],
    ) -> None:
        self._mode = mode
        self._internal_url_mode = internal_url_mode
        self._allowlist = allowlist

    def scan(self, text: str, final: bool = False) -> GuardScan:
        # A private-key header aborts outright, even in redact mode: the
        # block is unbounded, so chunkwise redaction can't contain it.
        if _PEM_HEADER_RE.search(text):
            return GuardScan(
                text=text,
                labels=["private_key"],
                risk=0.9,
                deny=True,
                reason="private key block in streamed output",
            )

        labels: list[str] = []
        risk = 0.0
        deny = False

        redacted, secret_labels = _redact_text(text, _SECRET_PATTERNS, final=final)
        if secret_labels:
            labels.extend(secret_labels)
            risk = 0.9
            if self._mode == PIIMode.DENY:
                deny = True
            else:
                text = redacted

        if self._internal_url_mode != InternalURLMode.OFF:
            redacted, internal_labels = _redact_text(
                text, _INTERNAL_URL_PATTERNS, self._allowlist, final=final
            )
            if internal_labels:
                labels.extend(internal_labels)
                risk = max(risk, 0.5)
                if self._internal_url_mode == InternalURLMode.DENY:
                    deny = True
                elif self._internal_url_mode == InternalURLMode.REDACT:
                    text = redacted

        labels = list(dict.fromkeys(labels))
        reason = f"Secrets detected in stream: {', '.join(sorted(set(labels)))}" if deny else ""
        return GuardScan(text=text, labels=labels, risk=risk, deny=deny, reason=reason)


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

    def stream_guard(self) -> StreamGuard:
        return _SecretsStreamGuard(
            self._mode, self._internal_url_mode, self._internal_url_allowlist
        )

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
