"""SessionTaintPolicy — what an agent has read decides what it may do next.

Every other check here looks at one call. This one remembers. A prompt
injection does its work in two steps: the agent reads something a stranger
wrote (a web page, an issue, an email), and then it acts. The detectors try to
recognise the first step and mostly cannot; measured on attacks nobody wrote a
pattern for, they catch a few percent. This policy does not try. It notes that
the session has read untrusted content, and from then on a call that changes
anything waits for a person, or is refused.

It is coarse on purpose. It has no idea whether what was read was hostile, so
it holds the benign follow-up exactly as it holds the attack. That is the cost,
and it is the number to look at before turning this on: how often an ordinary
task reads first and acts second.

Nothing here looks at the text of anything, so nothing here can be talked
round.
"""

from __future__ import annotations

from collections.abc import Collection
from enum import StrEnum
from typing import Any

from contracts.interceptor import BasePolicy
from contracts.types import ActionContext, FailureMode, InterceptorDecision

#: In place of a list of names: every tool.
ANY_TOOL = "*"


class TaintAction(StrEnum):
    """What happens to a state-changing call in a session that has read
    untrusted content."""

    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


def _names(value: Collection[str] | str, what: str) -> frozenset[str] | None:
    """The tool names in *value*, or None when it means every tool."""
    if isinstance(value, str):
        if value == ANY_TOOL:
            return None
        # A string is a collection of its characters. sources="fetch_page"
        # would otherwise become five one-letter tools and match nothing.
        raise TypeError(f'{what} takes a list of tool names, or "*" for every tool; got {value!r}')
    names = frozenset(value)
    if not names:
        # Not a default worth having: with no sources nothing is ever tainted,
        # and with no sinks nothing is ever held. Either way the policy would
        # sit in the list and do nothing.
        raise ValueError(f"{what} is empty, so this policy would never act")
    for name in names:
        if not isinstance(name, str) or not name:
            raise ValueError(f"{what} has to be tool names, got {name!r}")
    return names


class SessionTaintPolicy(BasePolicy):
    """Holds state-changing tool calls once a session has read untrusted content.

        taint = SessionTaintPolicy(
            sources=["fetch_issue", "read_page"],    # what they return, a stranger may have written
            sinks=["send_email", "run_shell"],       # what they do cannot be taken back
        )
        fetch = SecureTool(fetch_issue, [firewall, taint])
        send = SecureTool(send_email, [firewall, taint])

    Until a source has run in a session, the sinks run as they always did.
    After one has, each call to a sink raises ActionBlockedError with an
    approval_id (or is refused outright with ``on_taint="deny"``). An approval
    covers one call with those exact arguments; the next one waits again. A
    session does not become clean by being approved.

    Only acts when context.action == "tool_call", so like ToolFirewallPolicy
    it belongs in a SecureTool's list and does nothing in a SecureAgent's.

    Three things to get right, because getting them wrong is silent:

    - **One instance for all of a session's tools.** What a session has read is
      remembered on the instance. Two instances are two memories, and a sink
      wrapped with one never hears about a read seen by the other.
    - **A tool that is not listed is not held.** ``sinks="*"`` holds every
      tool. A tool that reads but whose arguments can carry data out (a URL to
      fetch) is a source and a sink: list it in both.
    - **Sessions are what you say they are.** Calls made without a session_id
      share SecureTool's default one, which errs on the side of holding.

    The memory is this process's, like InMemoryApprovalStore: it is not shared
    between workers and does not survive a restart. ``reset(session_id)`` is
    for when the model's context has been thrown away, and only then.

    Results are written to context.metadata["session_taint"] in the standard
    shape: "risk" (held 0.6, refused 0.8, otherwise 0.0), "category", plus
    "tainted", "tainted_by" (the sources that ran), "source", "sink",
    "allowed", "requires_approval" and "reason".
    """

    failure_mode: FailureMode = FailureMode.FAIL_CLOSED

    def __init__(
        self,
        *,
        sources: Collection[str] | str,
        sinks: Collection[str] | str,
        on_taint: TaintAction | str = TaintAction.REQUIRE_APPROVAL,
    ) -> None:
        self._sources = _names(sources, "sources")
        self._sinks = _names(sinks, "sinks")
        self._on_taint = TaintAction(on_taint)
        # session_id -> the sources that have run in it, in the order they
        # first did. Names only: what they returned is not this policy's to keep.
        self._read: dict[str, list[str]] = {}

    # -- what the host can ask and say -----------------------------------

    def is_tainted(self, session_id: str) -> bool:
        return bool(self._read.get(session_id))

    def tainted_by(self, session_id: str) -> tuple[str, ...]:
        """The sources that have run in *session_id*, oldest first."""
        return tuple(self._read.get(session_id, ()))

    def taint(self, session_id: str, source: str) -> None:
        """Mark *session_id* as having read untrusted content from *source*.

        For content that reaches the model by a road that is not a wrapped
        tool: an uploaded file, a retrieved document, a pasted email.
        """
        if not source:
            raise ValueError("say where the untrusted content came from")
        read = self._read.setdefault(session_id, [])
        if source not in read:
            read.append(source)

    def reset(self, session_id: str) -> None:
        """Forget what *session_id* has read.

        Correct only when the model no longer has it either: the conversation
        was discarded, not merely continued. Text read ten turns ago steers an
        agent as well as text read just now.
        """
        self._read.pop(session_id, None)

    # -- the policy -------------------------------------------------------

    def _is_source(self, name: str) -> bool:
        # A call with no name cannot be shown not to be one.
        return not name or self._sources is None or name in self._sources

    def _is_sink(self, name: str) -> bool:
        return not name or self._sinks is None or name in self._sinks

    @staticmethod
    def _name(context: ActionContext) -> str:
        name = context.input_data.get("name", "")
        return name if isinstance(name, str) else ""

    async def before_action(self, context: ActionContext) -> ActionContext:
        if context.action != "tool_call":
            return context

        name = self._name(context)
        read = self.tainted_by(context.session_id)
        sink = self._is_sink(name)
        held = bool(read) and sink
        refused = held and self._on_taint is TaintAction.DENY
        needs_person = held and not refused

        shown = name or "a call with no name"
        if not held:
            reason = (
                f"'{shown}' is not held: nothing untrusted has been read in this session"
                if not read
                else f"'{shown}' is not one of the calls held after an untrusted read"
            )
        else:
            after = f"this session has read untrusted content (from {', '.join(read)})"
            reason = (
                f"'{shown}' changes state and {after}; it is refused"
                if refused
                else f"'{shown}' changes state and {after}; it needs a person to approve it"
            )

        entry: dict[str, Any] = {
            "risk": 0.8 if refused else 0.6 if needs_person else 0.0,
            "category": "session_taint",
            "tainted": bool(read),
            "tainted_by": list(read),
            "source": self._is_source(name),
            "sink": sink,
            "allowed": not refused,
            "requires_approval": needs_person,
            "reason": reason,
        }
        context.metadata["session_taint"] = entry

        if refused:
            context.decision = InterceptorDecision.DENY
            context.decision_reason = reason
        elif needs_person:
            context.decision = InterceptorDecision.REQUIRE_APPROVAL
            context.decision_reason = reason
        return context

    async def after_action(self, context: ActionContext) -> ActionContext:
        # Reached only when the tool ran: a read that was refused, or that
        # raised, returned nothing and taints nothing. One whose result a later
        # policy withholds still taints. That is the safe side to be wrong on,
        # and this policy cannot see what the policies after it will decide.
        if context.action != "tool_call":
            return context
        name = self._name(context)
        if not self._is_source(name):
            return context

        self.taint(context.session_id, name or "a call with no name")
        entry = context.metadata.get("session_taint")
        if isinstance(entry, dict):
            entry["tainted"] = True
            entry["tainted_by"] = list(self.tainted_by(context.session_id))
        return context
