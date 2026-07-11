from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

from contracts.interceptor import BasePolicy
from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode, InterceptorDecision
from sdk.policies.secrets import find_secrets

if TYPE_CHECKING:
    from events.writer import EventWriter

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# PHI pattern bank
# Structural patterns for protected-health-information categories a regex can
# honestly detect: coded identifiers and identifier-labelled values, not
# free-text medical meaning.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _PHIPattern:
    regex: re.Pattern[str]
    label: str


def _p(pattern: str, label: str) -> _PHIPattern:
    return _PHIPattern(re.compile(pattern, re.IGNORECASE), label)


_PHI_PATTERNS: list[_PHIPattern] = [
    # ICD-10 diagnosis codes — dotted form only (E11.9), the undotted form
    # collides with too many product/part numbers
    _PHIPattern(re.compile(r"\b[A-TV-Z]\d{2}\.\d{1,4}\b"), "icd10_code"),
    # Medical record numbers introduced by their label
    _p(r"\b(?:mrn|medical\s+record\s+(?:number|no\.?))\s*[:#]?\s*\d{5,}\b", "mrn"),
    # Insurance / member identifiers introduced by their label
    _p(
        r"\b(?:member|policy|subscriber|insurance)\s+(?:id|number|no\.?)\s*[:#]?\s*[A-Z0-9-]{5,}\b",
        "insurance_id",
    ),
    # Medication name (common drug-class suffixes) followed by a dosage
    _p(
        r"\b[a-z]+(?:cillin|mycin|statin|prazole|sartan|olol|pril|formin|azepam|oxetine|codone)\b"
        r"\s+\d+\s*(?:mg|mcg|ml)\b",
        "medication_dosage",
    ),
    # Explicit diagnosis statements
    _p(r"\b(?:diagnosed\s+with|diagnosis\s+of)\s+[a-z]", "diagnosis_mention"),
]

_CREDENTIAL_RISK = 0.9
_PHI_RISK = 0.6

# Preset name -> description; the public contract of CompliancePolicy(rules=...)
KNOWN_RULES: dict[str, str] = {
    "phi_detection": "detect PHI identifiers (ICD-10 codes, MRNs, insurance IDs, "
    "medication dosages, diagnosis statements) in input and output",
    "credential_output_guard": "deny any output containing raw credential material "
    "(reuses the secrets pattern bank)",
    "data_access_audit": "emit an audit event for every tool call",
}


class PHIMode(str, Enum):
    ANNOTATE = "annotate"
    DENY = "deny"


def find_phi(text: str) -> list[tuple[str, str]]:
    """Return list of (matched_text, label) pairs of PHI found in *text*.

    Standalone helper — callable outside a policy pipeline.
    """
    found: list[tuple[str, str]] = []
    for pat in _PHI_PATTERNS:
        for m in pat.regex.finditer(text):
            found.append((m.group(), pat.label))
    return found


def _flatten_text(obj: Any) -> str:
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten_text(v) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_flatten_text(item) for item in obj)
    return ""


class CompliancePolicy(BasePolicy):
    """Concrete, honestly-scoped checks that assist compliance programs.

    This policy ASSISTS compliance work (its checks map onto common
    GDPR/HIPAA/SOC2 controls); it does not confer or certify compliance
    with any regulation. Presets are named after what they check:

    - "phi_detection": scan input (before_action) and output (after_action)
      for PHI identifiers — ICD-10 codes, MRNs, insurance IDs, medication
      dosages, diagnosis statements. Follows *phi_mode*: ANNOTATE (default)
      records findings only; DENY blocks. Pair with PIIPolicy/SecretsPolicy
      for redaction.
    - "credential_output_guard": deny any output containing raw credential
      material (secrets pattern bank, internal URLs excluded). Always
      blocks — it is a guard, not a detector.
    - "data_access_audit": emit a POLICY_EVALUATED audit event for every
      tool call (requires a writer; annotates metadata either way).

    Results accumulate in context.metadata["compliance"] using the
    standardized shape (risk keeps the max across phases; credentials in
    output score 0.9, PHI findings 0.6):
      {"risk": float, "category": "compliance", "rules": [...],
       "phi": [labels...], "credentials": [labels...], "audited": bool}
    """

    failure_mode: FailureMode = FailureMode.FAIL_OPEN

    def __init__(
        self,
        rules: list[str],
        phi_mode: PHIMode | str = PHIMode.ANNOTATE,
        writer: EventWriter | None = None,
    ) -> None:
        unknown = set(rules) - set(KNOWN_RULES)
        if unknown:
            raise ValueError(
                f"unknown compliance rule(s): {sorted(unknown)}; known rules: {sorted(KNOWN_RULES)}"
            )
        if not rules:
            raise ValueError(f"rules must name at least one preset: {sorted(KNOWN_RULES)}")
        self._rules = list(dict.fromkeys(rules))
        self._phi_mode = PHIMode(phi_mode)
        self._writer = writer
        self._sequence_counters: dict[str, int] = {}

    async def before_action(self, context: ActionContext) -> ActionContext:
        meta = self._meta(context)

        if "data_access_audit" in self._rules and context.action == "tool_call":
            meta["audited"] = True
            if self._writer is not None:
                await self._emit_event(
                    context,
                    policy="data_access_audit",
                    payload={
                        "tool": context.input_data.get("name", ""),
                        "arg_keys": sorted(context.input_data.get("args", {})),
                    },
                )

        if "phi_detection" in self._rules:
            await self._check_phi(context, context.input_data, phase="input")

        return context

    async def after_action(self, context: ActionContext) -> ActionContext:
        meta = self._meta(context)

        if "phi_detection" in self._rules:
            await self._check_phi(context, context.output_data, phase="output")

        if "credential_output_guard" in self._rules:
            text = _flatten_text(context.output_data)
            credentials = sorted(
                {label for _, label in find_secrets(text) if label != "internal_url"}
            )
            if credentials:
                meta["credentials"] = list(dict.fromkeys([*meta["credentials"], *credentials]))
                meta["risk"] = max(meta["risk"], _CREDENTIAL_RISK)
                context.decision = InterceptorDecision.DENY
                context.decision_reason = f"Credential material in output: {', '.join(credentials)}"
                logger.warning(
                    "credential_output_blocked",
                    session_id=context.session_id,
                    agent_id=context.agent_id,
                    types=credentials,
                )
                if self._writer is not None:
                    await self._emit_event(
                        context,
                        policy="credential_output_guard",
                        payload={"credential_types": credentials},
                    )

        return context

    async def _check_phi(self, context: ActionContext, data: dict[str, Any], phase: str) -> None:
        meta = self._meta(context)
        text = _flatten_text(data)
        found = sorted({label for _, label in find_phi(text)})
        if not found:
            return

        meta["phi"] = list(dict.fromkeys([*meta["phi"], *found]))
        meta["risk"] = max(meta["risk"], _PHI_RISK)

        logger.warning(
            "phi_detected",
            session_id=context.session_id,
            agent_id=context.agent_id,
            types=found,
            phase=phase,
            mode=self._phi_mode.value,
        )

        if self._phi_mode == PHIMode.DENY:
            context.decision = InterceptorDecision.DENY
            context.decision_reason = f"PHI detected in {phase}: {', '.join(found)}"

        if self._writer is not None:
            await self._emit_event(
                context,
                policy="phi_detection",
                payload={"phi_types": found, "phase": phase, "mode": self._phi_mode.value},
            )

    def _meta(self, context: ActionContext) -> dict[str, Any]:
        return context.metadata.setdefault(
            "compliance",
            {
                "risk": 0.0,
                "category": "compliance",
                "rules": self._rules,
                "phi": [],
                "credentials": [],
                "audited": False,
            },
        )

    async def _emit_event(
        self, context: ActionContext, policy: str, payload: dict[str, Any]
    ) -> None:
        seq = self._next_sequence(context.session_id)
        event = Event(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.POLICY_EVALUATED,
            payload={
                "policy": policy,
                **payload,
                "decision": context.decision.value,
            },
            sequence_num=seq,
        )
        await self._writer.write(event)  # type: ignore[union-attr]

    def _next_sequence(self, session_id: str) -> int:
        count = self._sequence_counters.get(session_id, 0) + 1
        self._sequence_counters[session_id] = count
        return count
