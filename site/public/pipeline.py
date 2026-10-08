"""The policy pipeline the demo page runs, in the browser, on the visitor's text.

Loaded once by lib/runtime.ts and then called per submission. Every entry point
goes through `run_pipeline`, so the page and the end-to-end check in verify.mjs
exercise the identical code — there is no separate "demo mode".

The policy objects are built once at module scope and reused: they are stateless
apart from per-session counters, and rebuilding them per keystroke would show up
in the latency number this page advertises.
"""

import json
import logging
import time

logging.disable(logging.CRITICAL)  # the policies log every finding; the UI is the report

from events.writer import EventWriter
from sdk import (
    ActionBlockedError,
    AuditPolicy,
    CompliancePolicy,
    HarmfulRequestPolicy,
    PHIMode,
    PIIPolicy,
    PromptInjectionPolicy,
    SecretsPolicy,
    SecureAgent,
    SecureTool,
    ToolFirewallPolicy,
    ToolRules,
    ToxicityPolicy,
)
from sdk.observability.risk import aggregate_risk

# Tool rules the sandboxed agent is held to. Deliberately small: a spend ceiling
# and one outright-forbidden tool are enough to show the shape of the check.
TOOL_RULES = ToolRules.model_validate(
    {
        "rules": {
            "refund_tool": {"arg_constraints": {"max_amount": 100}},
            "delete_account": {"deny": True},
            "send_email": {"requires_approval": True},
        }
    }
)

# metadata key -> (display name, what the policy is for). The key is how a
# policy identifies itself in ActionContext.metadata.
POLICIES = {
    "threat": ("Prompt injection", "Weighted pattern match over 6 attack categories"),
    "toxicity": ("Toxicity", "Structural patterns for violence, hate, harassment, self-harm"),
    "harmful_request": (
        "Harmful request",
        "Request constructions aimed at weapons, malware, doxxing and 5 more categories",
    ),
    "compliance": ("Compliance", "PHI detection and a credential guard on output"),
    "secrets": ("Secrets", "Credential shapes in the prompt and the response"),
    "pii": ("PII", "Email, phone, SSN, card numbers (Luhn-checked), IP addresses"),
    "tool_firewall": ("Tool firewall", "Declarative rules on the tool call the agent attempts"),
}
ORDER = [
    "threat",
    "toxicity",
    "harmful_request",
    "secrets",
    "pii",
    "compliance",
    "tool_firewall",
]


class _MemorySink:
    """Where the audit trail goes. There is no database in a browser tab."""

    def __init__(self) -> None:
        self.rows: list = []

    async def insert_events(self, events) -> None:
        self.rows.extend(events)


class _EchoAgent:
    """Stands in for the LLM. It quotes back whatever it was given, which is
    what gives the output-side policies (PII, the credential guard) something
    real to catch — a model repeating sensitive input is the leak they exist to
    stop.

    "Whatever it was given" is not always what was sent. SecretsPolicy masks a
    credential on the way in, so a pasted key never reaches this method and
    the echo has nothing to repeat. Both sides are kept so the page can show
    that rather than claim it.

    Async on purpose: the sync path routes through loop.run_in_executor, a
    threading API, and this runtime has no threads.
    """

    def __init__(self) -> None:
        # What the model was handed, to set beside what the sender wrote.
        self.last_input = ""
        # What the model produced, to set beside what the caller received.
        # Without these there is no "before" to diff on either side.
        self.last_output = ""

    async def ainvoke(self, input_data, **kwargs):
        self.last_input = input_data.get("input", "")
        self.last_output = f"Sure — here is what you asked about: {self.last_input}"
        return {"output": self.last_output}


def _label(name: str) -> str:
    return name.replace("_", " ")


def _normalization_note(meta: dict) -> str:
    """Said out loud, because "it matched" is not the interesting part here.

    A prompt written with Cyrillic letters or leetspeak scored 0.00 before the
    policies started scanning normalized views of the text. When that is why a
    finding exists, the page should say so rather than presenting the score as
    if the patterns matched the text as typed.
    """
    if meta.get("matched_view", "raw") == "raw":
        return ""
    named = ", ".join(_label(m) for m in meta.get("obfuscation") or [])
    return f" Matched only after undoing {named}." if named else ""


def _explain(key: str, meta: dict) -> str:
    """One line of plain English. Never a stack trace, never a raw score alone."""
    risk = meta.get("risk", 0.0)

    if key == "threat":
        signals = meta.get("signals") or {}
        if not meta.get("flagged"):
            return (
                "No injection patterns matched."
                if not signals
                else f"Matched {_label(max(signals, key=signals.get))} weakly — below the "
                f"{meta.get('threshold', 0.5):.2f} threshold, so it passed."
            )
        named = ", ".join(_label(s) for s in sorted(signals, key=signals.get, reverse=True))
        return (
            f"Matched {named}. Score {risk:.2f} is at or above the "
            f"{meta.get('threshold', 0.5):.2f} threshold." + _normalization_note(meta)
        )

    if key == "toxicity":
        signals = meta.get("signals") or {}
        if not meta.get("flagged"):
            return "No violence, hate, harassment or self-harm patterns matched."
        named = ", ".join(_label(s) for s in sorted(signals, key=signals.get, reverse=True))
        return (
            f"Matched {named}. Score {risk:.2f} is at or above the "
            f"{meta.get('threshold', 0.5):.2f} threshold." + _normalization_note(meta)
        )

    if key == "harmful_request":
        signals = meta.get("signals") or {}
        if not meta.get("flagged"):
            return "No request for harmful capability matched."
        named = ", ".join(_label(s) for s in sorted(signals, key=signals.get, reverse=True))
        return (
            f"Matched {named}. Score {risk:.2f} is at or above the "
            f"{meta.get('threshold', 0.5):.2f} threshold." + _normalization_note(meta)
        )

    if key == "pii":
        found = meta.get("found") or []
        if not found:
            return "No personal data found in the response."
        named = ", ".join(sorted({_label(f) for f in found}))
        verb = "Redacted" if meta.get("redacted") else "Found"
        return f"{verb} {named} in the response before it was returned."

    if key == "secrets":
        found = meta.get("found") or []
        if not found:
            return "No credentials found in the prompt or the response."
        named = ", ".join(sorted({_label(f) for f in found}))
        verb = "Masked" if meta.get("redacted") else "Found"
        return f"{verb} {named}."

    if key == "compliance":
        phi = meta.get("phi") or []
        creds = meta.get("credentials") or []
        parts = []
        if phi:
            parts.append("health data (" + ", ".join(sorted({_label(p) for p in phi})) + ")")
        if creds:
            parts.append("credentials (" + ", ".join(sorted({_label(c) for c in creds})) + ")")
        if not parts:
            return "No regulated content found."
        return "Found " + " and ".join(parts) + " in the exchange."

    if key == "tool_firewall":
        reason = meta.get("reason") or ""
        if meta.get("allowed") and not meta.get("requires_approval"):
            return reason or "The tool call matched no blocking rule."
        return reason

    return ""


def _verdict(key: str, meta: dict, blocked_by: str) -> str:
    """What the policy did, from what it actually recorded.

    "flag" is the case worth being careful about: a policy running in annotate
    mode records a finding and deliberately does not act on it. Reporting that
    as a plain allow would make it indistinguishable from a policy that found
    nothing, which is the one thing this page must not do.
    """
    if meta.get("requires_approval"):
        return "approval"
    if key == blocked_by:
        return "deny"
    if meta.get("redacted"):
        return "mutate"
    if meta.get("risk", 0.0) > 0:
        return "flag"
    return "allow"


def _needs_crisis_support(metadata: dict) -> bool:
    """True when any policy matched a self-harm pattern in this submission.

    Deliberately keyed on the *signal*, not on the deny — the patterns that
    score below threshold ("i want to die" scores 0.45 against a 0.50 gate) are
    exactly the ones a refusal would answer with silence. The policy layer's
    job ends at the signal; deciding that this particular one deserves a
    different response than "Blocked" is the product's call, so it is made
    here rather than inside the policy.
    """
    harmful = (metadata.get("harmful_request") or {}).get("signals") or {}
    toxic = (metadata.get("toxicity") or {}).get("signals") or {}
    return "self_harm_method" in harmful or "self_harm" in toxic


def _rows(metadata: dict, blocked_by: str, reached: set) -> list:
    out = []
    for key in ORDER:
        name, blurb = POLICIES[key]
        if key not in metadata:
            out.append(
                {
                    "key": key,
                    "policy": name,
                    "blurb": blurb,
                    "verdict": "skipped" if key in reached else "not_reached",
                    "risk": None,
                    "explanation": (
                        "Did not apply to this input."
                        if key in reached
                        else "Never ran — an earlier policy stopped the pipeline."
                    ),
                }
            )
            continue
        meta = metadata[key]
        out.append(
            {
                "key": key,
                "policy": name,
                "blurb": blurb,
                "verdict": _verdict(key, meta, blocked_by),
                "risk": meta.get("risk", 0.0),
                "explanation": _explain(key, meta),
            }
        )
    return out


_SINK = _MemorySink()
_WRITER = EventWriter(_SINK, flush_interval=0.01)
_STARTED = False

# Order matters. Secrets and PII redact the response, so they run before the
# compliance guard inspects it — masking a leaked credential is a better
# outcome than discarding the whole reply, and the guard still backstops
# anything the patterns missed.
_INPUT_POLICIES = [
    PromptInjectionPolicy(),
    ToxicityPolicy(),
    HarmfulRequestPolicy(),
    SecretsPolicy(),
    PIIPolicy(),
    CompliancePolicy(rules=["phi_detection", "credential_output_guard"], phi_mode=PHIMode.ANNOTATE),
]
_FIREWALL = ToolFirewallPolicy(rules=TOOL_RULES)

# Every tool the sandboxed agent reaches for goes through a SecureTool, so the
# firewall is in the path of the call rather than consulted beside it. The
# tools themselves do nothing but note that they ran — which is the one fact
# about them the page needs: a refused call has to leave this list alone.
_TOOL_RUNS: list = []
_TOOLS: dict = {}


def _tool(name: str) -> SecureTool:
    if name not in _TOOLS:

        async def run(**args):
            _TOOL_RUNS.append(name)
            return f"{name} ran"

        _TOOLS[name] = SecureTool(run, [_FIREWALL], name=name)
    return _TOOLS[name]


_ECHO = _EchoAgent()
_AGENT = SecureAgent(_ECHO, policies=[*_INPUT_POLICIES, AuditPolicy(_WRITER)])


async def _ensure_started():
    global _STARTED
    if not _STARTED:
        await _WRITER.start()
        _STARTED = True


async def run_pipeline(payload_json: str) -> str:
    """Run one submission. `payload_json` is {"text": str, "tool_call": {...}|None}.

    Returns JSON: the per-policy rows, the response the caller would have
    received, the aggregated risk, and how long the pipeline itself took.
    """
    await _ensure_started()
    payload = json.loads(payload_json)
    text = payload.get("text", "")
    tool_call = payload.get("tool_call")

    before = len(_SINK.rows)
    blocked_by = ""
    blocked_reason = ""
    output = ""
    _ECHO.last_input = ""
    _ECHO.last_output = ""

    start = time.perf_counter()
    try:
        result, ctx = await _AGENT.invoke_with_context({"input": text})
        output = result.get("output", "")
    except ActionBlockedError as exc:
        ctx = exc.context
        blocked_by = _KEY_BY_CLASS.get(exc.interceptor, "")
        blocked_reason = exc.reason

    # The agent only gets to attempt a tool call if the prompt survived the
    # input gates — which is the point of running them first.
    attempted_tool = None
    if tool_call is not None and not blocked_by:
        name = tool_call["name"]
        rule = TOOL_RULES.rules.get(name)
        runs_before = len(_TOOL_RUNS)
        try:
            _, tool_ctx = await _tool(name).call_with_context(tool_call.get("args", {}))
        except ActionBlockedError as exc:
            tool_ctx = exc.context
            blocked_reason = exc.reason
            # A pending approval is a hold, not a refusal: the reply stands and
            # the page says so. Only a deny counts as blocked.
            if not exc.approval_id:
                blocked_by = "tool_firewall"
        ctx.metadata["tool_firewall"] = tool_ctx.metadata["tool_firewall"]
        attempted_tool = {
            "name": name,
            "args": tool_call.get("args", {}),
            "rule": rule.model_dump(exclude_defaults=True) if rule is not None else {},
            # Read off the tool, not inferred from the verdict.
            "executed": len(_TOOL_RUNS) > runs_before,
        }
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    risk, categories = aggregate_risk(ctx)
    reached = {"tool_firewall"} if tool_call is None else set()

    # Where the block happened changes how it should be described: a prompt
    # rejected on the way in never reached the model, whereas a refused tool
    # call happened after a reply had already been produced.
    if not blocked_by:
        stage = ""
    elif blocked_by == "tool_firewall":
        stage = "tool"
    elif output:
        stage = "response"
    else:
        stage = "prompt"

    # stop() drains the queue to completion, so the trail is accurate. Done
    # after the measurement: the drain interval is not pipeline time.
    global _STARTED
    await _WRITER.stop()
    _STARTED = False
    events = [e.event_type.value for e in _SINK.rows[before:]]

    return json.dumps(
        {
            "prompt": text,
            # Empty when the prompt was stopped before the model was called.
            "model_input": _ECHO.last_input,
            "output": output,
            "raw_output": _ECHO.last_output,
            "blocked": bool(blocked_by),
            "blocked_by": POLICIES.get(blocked_by, (blocked_by, ""))[0],
            "blocked_reason": blocked_reason,
            "stage": stage,
            "tool_call": attempted_tool,
            "crisis": _needs_crisis_support(ctx.metadata),
            "rows": _rows(ctx.metadata, blocked_by, reached),
            "risk": risk,
            "categories": categories,
            "latency_ms": round(elapsed_ms, 2),
            "events": len(events),
        },
        default=str,
    )


# Class name -> metadata key, so a block can be attributed to the row that caused it.
_KEY_BY_CLASS = {
    "PromptInjectionPolicy": "threat",
    "ToxicityPolicy": "toxicity",
    "HarmfulRequestPolicy": "harmful_request",
    "CompliancePolicy": "compliance",
    "SecretsPolicy": "secrets",
    "PIIPolicy": "pii",
    "ToolFirewallPolicy": "tool_firewall",
}
