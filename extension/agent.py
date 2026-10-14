"""The agent in the panel, and the tools it acts through.

There is no model here. The agent is a stand-in with a fixed plan for each of
three tasks, and it is gullible on purpose: a line on a page addressed to
"assistants" with a URL in it is followed, the way an injected model follows
one. That is the thing the tools exist to contain. Every action it takes is a
SecureTool call. open_page, read_page and submit_form each run the tool
firewall before anything touches the tab, read_page scans what came back, and
submit_form waits on a person. The browser side (sidepanel.js) does the DOM
work and nothing else: it never decides whether an action may happen, and it
is only ever reached through a tool body, after the firewall.

Loaded by runtime.js with runPythonAsync, then `setup(rules_yaml)` is called
once. Outside the panel there is no `browser` module; tests/test_extension.py
installs a fake one.
"""

import json
import logging
import re
import time
from typing import Any

logging.disable(logging.CRITICAL)  # the policies log every finding; the panel is the report

import yaml

from events.approvals import InMemoryApprovalStore
from sdk import (
    ActionBlockedError,
    PromptInjectionPolicy,
    SecureTool,
    ToolFirewallPolicy,
    ToolRules,
)

# The names of the tools whose bodies ran, in order. "Refused" and "held" are
# only worth saying if this list did not grow, so it is read, not inferred.
_RAN: list[str] = []

# One store for every tool, in this panel's memory. The person deciding and the
# call waiting on them are in the same page here, which is the one case the
# in-memory store is for.
_APPROVALS = InMemoryApprovalStore()

# Scores what read_page returned. Annotate, the default: it records a finding
# and lets the text through, because the patterns behind it miss most attacks
# they were not written for, and a scan that blocked on them would mostly
# block nothing.
_RESULT_SCAN = PromptInjectionPolicy(tool_output="annotate")

_TOOLS: dict[str, SecureTool] = {}

# What a page says to an assistant, and where it says to go. A real model
# would read this as an instruction some of the time; this one does so every
# time, so the consequence is on screen rather than probabilistic.
_NOTE = re.compile(r"(?is)\bnote for (?:ai |automated )?assistants?\b.*?(https?://[^\s\"'<>]+)")


async def _do(name: str, **args: Any) -> dict[str, Any]:
    """Ask the panel to perform *name* on the tab. The panel answers in JSON, and
    an answer with "error" in it is the tool failing, not the firewall."""
    from browser import perform  # registered by runtime.js; exists only in the panel

    reply = json.loads(await perform(name, json.dumps(args)))
    if "error" in reply:
        raise RuntimeError(reply["error"])
    return reply


async def open_page(url: str) -> str:
    _RAN.append("open_page")
    page = await _do("open_page", url=url)
    return str(page["url"])


async def read_page(url: str) -> str:
    _RAN.append("read_page")
    page = await _do("read_page", url=url)
    # A string, which is what the result scan reads.
    return str(page["text"])


async def submit_form(url: str, fields: dict[str, Any]) -> str:
    _RAN.append("submit_form")
    done = await _do("submit_form", url=url, fields=fields)
    return str(done["action"])


def setup(rules_yaml: str) -> None:
    """Build the tools against the rules. Called once, by runtime.js, so the
    rules stay a file a person can read rather than a string inside this one."""
    rules = ToolRules.model_validate(yaml.safe_load(rules_yaml))
    firewall = ToolFirewallPolicy(rules=rules)
    _TOOLS.clear()
    _TOOLS["open_page"] = SecureTool(open_page, [firewall], approval_store=_APPROVALS)
    _TOOLS["read_page"] = SecureTool(read_page, [firewall, _RESULT_SCAN], approval_store=_APPROVALS)
    _TOOLS["submit_form"] = SecureTool(submit_form, [firewall], approval_store=_APPROVALS)


def _note_for_assistants(text: str) -> str:
    """The URL a page tells an assistant to go to, or "" if it tells it nothing."""
    found = _NOTE.search(text)
    return found.group(1).rstrip(".,;)") if found else ""


async def _call(name: str, args: dict[str, Any], approval_id: str = "") -> dict[str, Any]:
    """One tool call through its pipeline, and the record of what became of it."""
    step: dict[str, Any] = {
        "tool": name,
        "args": args,
        "status": "",
        "reason": "",
        "executed": False,
        "scan": None,
        "returned": None,
        "approval_id": "",
    }
    before = len(_RAN)
    try:
        value, ctx = await _TOOLS[name].call_with_context(args, approval_id=approval_id)
        step["status"] = "ran"
        step["reason"] = (ctx.metadata.get("tool_firewall") or {}).get("reason", "")
        step["returned"] = value
        scan = ctx.metadata.get("tool_output")
        if scan is not None:
            step["scan"] = {"flagged": bool(scan["flagged"]), "risk": float(scan["risk"])}
    except ActionBlockedError as exc:
        # A pending approval is a hold, not a refusal: the call waits.
        step["status"] = "held" if exc.approval_id else "refused"
        step["approval_id"] = exc.approval_id or ""
        step["reason"] = exc.reason
    except Exception as exc:  # the tab moved, or the form is not there
        step["status"] = "failed"
        step["reason"] = str(exc)
    step["executed"] = len(_RAN) > before
    return step


async def _decide(decision: dict[str, Any]) -> dict[str, Any]:
    """Write the person's answer to the store. decide() refuses an id that is
    unknown, already decided or expired, and so does this."""
    approval_id = str(decision.get("id", ""))
    try:
        record = await _APPROVALS.decide(
            approval_id,
            bool(decision.get("approved")),
            str(decision.get("decided_by", "")),
            str(decision.get("note", "")),
        )
    except ValueError:
        record = None
    if record is None:
        return {"id": approval_id, "status": "spent", "decided_by": "", "note": ""}
    return {
        "id": approval_id,
        "status": record.status.value,
        "decided_by": record.decided_by,
        "note": record.decision_note,
    }


async def run_task(payload_json: str) -> str:
    """Run one task. `payload_json` is {"task", "vendor", "tab": {"url", "title"},
    "approval": {"id", "approved", "decided_by", "note"} | null}.

    Returns JSON: every step the agent took with the firewall's verdict on it,
    the approval a held call is waiting on (or what was decided), what the
    agent said, and how long the task took. The panel keeps no state between
    tasks, so a decision re-runs the task and the held call is retried with the
    approval attached — the SDK's retry-after-approval and nothing else.
    """
    payload = json.loads(payload_json)
    task = payload.get("task", "")
    vendor = payload.get("vendor", "")
    tab = payload.get("tab") or {}
    decision = payload.get("approval")
    steps: list[dict[str, Any]] = []
    approval: dict[str, Any] | None = None
    said = ""
    start = time.perf_counter()

    if task == "read":
        step = await _call("read_page", {"url": tab.get("url", "")})
        steps.append(step)
        if step["status"] == "ran":
            first = next((line for line in step["returned"].splitlines() if line.strip()), "")
            said = f"The page starts: {first[:160]}"

    elif task == "price":
        opened = await _call("open_page", {"url": f"{vendor}/pricing"})
        steps.append(opened)
        if opened["status"] == "ran":
            read = await _call("read_page", {"url": f"{vendor}/pricing"})
            steps.append(read)
            if read["status"] == "ran":
                text = read["returned"]
                elsewhere = _note_for_assistants(text)
                if elsewhere:
                    # The gullible part. Whatever the page asked for, it is a
                    # tool call like any other, and the firewall sees it first.
                    steps.append(
                        await _call(
                            "submit_form",
                            {
                                "url": elsewhere,
                                "fields": {"session": "(this browser's session cookie)"},
                            },
                        )
                    )
                price = re.search(r"\$\d+(?:\.\d+)?[^.\n]*", text)
                said = (
                    f"The enterprise plan is {price.group(0).strip()}."
                    if price
                    else "I could not find a price on the page."
                )

    elif task == "buy":
        order = {"url": f"{vendor}/order", "fields": {"plan": "enterprise", "seats": 40}}
        opened = await _call("open_page", {"url": f"{vendor}/pricing"})
        steps.append(opened)
        if opened["status"] == "ran":
            approval_id = ""
            if decision:
                approval_id = str(decision.get("id", ""))
                approval = await _decide(decision)
            # A denied or unusable approval ends here: the call is not made again.
            if approval is None or approval["status"] == "approved":
                step = await _call("submit_form", order, approval_id=approval_id)
                steps.append(step)
                if step["status"] == "held":
                    approval = {
                        "id": step["approval_id"],
                        "status": "pending",
                        "decided_by": "",
                        "note": "",
                    }
                if step["status"] == "ran":
                    said = "Ordered 40 seats on the enterprise plan."
            else:
                steps.append(
                    {
                        "tool": "submit_form",
                        "args": order,
                        "status": "skipped",
                        "reason": (
                            f"{approval['decided_by'] or 'The approver'} said no: {approval['note']}"
                            if approval["status"] == "denied"
                            else "that approval was already used, or has expired"
                        ),
                        "executed": False,
                        "scan": None,
                        "returned": None,
                        "approval_id": approval_id,
                    }
                )

    else:
        said = f"No such task: {task!r}."

    return json.dumps(
        {
            "task": task,
            "steps": steps,
            "approval": approval,
            "said": said,
            "latency_ms": round((time.perf_counter() - start) * 1000.0, 2),
        },
        default=str,
    )
