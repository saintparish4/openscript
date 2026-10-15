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

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from contracts.interceptor import BasePolicy
from contracts.types import ActionContext, FailureMode, InterceptorDecision

#: In place of a list of names: every tool.
ANY_TOOL = "*"


class TaintAction(StrEnum):
    """What happens to a state-changing call in a session that has read
    untrusted content."""

    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class _Tools:
    """A set of tool names, some of them prefixes: "mcp__github__*" is every
    tool whose name starts with "mcp__github__"."""

    exact: frozenset[str]
    prefixes: tuple[str, ...]

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and (
            name in self.exact or any(name.startswith(prefix) for prefix in self.prefixes)
        )


def _names(value: Collection[str] | str, what: str) -> _Tools | None:
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
        if "*" in name[:-1]:
            # A pattern language would be a second way to get a name wrong.
            # A trailing * is all there is: a prefix.
            raise ValueError(f'{what}: "*" may only end a name, as a prefix; got {name!r}')
    prefixes = tuple(sorted(name[:-1] for name in names if name.endswith("*")))
    return _Tools(frozenset(name for name in names if not name.endswith("*")), prefixes)


def _known(
    value: Mapping[str, Mapping[str, Collection[str]]] | None, sinks: _Tools | None
) -> dict[str, dict[str, frozenset[str]]]:
    """``known`` checked and normalised: tool -> argument -> casefolded values."""
    if value is None:
        return {}
    if not isinstance(value, Mapping) or not value:
        raise ValueError("known maps sink names to their destination arguments, and is not empty")
    known: dict[str, dict[str, frozenset[str]]] = {}
    for tool, args in value.items():
        if not isinstance(tool, str) or not tool:
            raise ValueError(f"known has to be keyed by tool names, got {tool!r}")
        if sinks is not None and tool not in sinks:
            # A destination can only release a held call, and only sinks are held.
            raise ValueError(f"known names {tool!r}, which is not one of the sinks")
        if not isinstance(args, Mapping) or not args:
            raise ValueError(f"known[{tool!r}] maps destination arguments to values")
        known[tool] = {}
        for arg, values in args.items():
            if isinstance(values, str) or not isinstance(values, Collection) or not values:
                # A string is a collection of its characters: "alice@x.com"
                # would become a set of letters and release nothing, silently.
                raise ValueError(f"known[{tool!r}][{arg!r}] takes a list of values")
            if not all(isinstance(v, str) and v for v in values):
                raise ValueError(f"known[{tool!r}][{arg!r}] has to be non-empty strings")
            known[tool][arg] = frozenset(v.casefold() for v in values)
    return known


class TaintStore(Protocol):
    """Where a SessionTaintPolicy keeps what each session has read.

    Names only, in the order they first ran. The default keeps them in this
    process; a store that writes them down lets the memory outlive it, which
    is what a hook that runs as a new process on every call needs.
    """

    def sources(self, session_id: str) -> list[str]: ...

    def add(self, session_id: str, source: str) -> None: ...

    def clear(self, session_id: str) -> None: ...


class InMemoryTaintStore:
    """What each session has read, in a dict in this process."""

    def __init__(self) -> None:
        self._read: dict[str, list[str]] = {}

    def sources(self, session_id: str) -> list[str]:
        return list(self._read.get(session_id, ()))

    def add(self, session_id: str, source: str) -> None:
        read = self._read.setdefault(session_id, [])
        if source not in read:
            read.append(source)

    def clear(self, session_id: str) -> None:
        self._read.pop(session_id, None)


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

    The memory is this process's by default, like InMemoryApprovalStore: it is
    not shared between workers and does not survive a restart. Pass a
    ``store`` (a TaintStore) to keep it somewhere that does. ``reset(session_id)``
    is for when the model's context has been thrown away, and only then.

    A name in ``sources`` or ``sinks`` that ends in ``*`` is a prefix:
    ``"mcp__github__*"`` is every tool from that MCP server.

    ``known`` lets a held call through when everywhere it sends is somewhere
    the user has already sent: ``known={"send_money": {"recipient": [...]}}``.
    For a listed sink, every destination argument that is present must have
    all of its values known (each item of a list); an argument that is absent
    leaves the destination as it was. Values compare exactly, ignoring case.
    Arguments not listed are not looked at, so list every one that names a
    destination (``to``, ``cc`` and ``bcc``). Sinks not in ``known`` are held as
    before. The list is fixed when the policy is built: an approval does not
    add to it.

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
        store: TaintStore | None = None,
        known: Mapping[str, Mapping[str, Collection[str]]] | None = None,
    ) -> None:
        self._sources = _names(sources, "sources")
        self._sinks = _names(sinks, "sinks")
        self._on_taint = TaintAction(on_taint)
        self._known = _known(known, self._sinks)
        # session_id -> the sources that have run in it, in the order they
        # first did. Names only: what they returned is not this policy's to keep.
        self._store: TaintStore = store if store is not None else InMemoryTaintStore()

    # -- what the host can ask and say -----------------------------------

    def is_tainted(self, session_id: str) -> bool:
        return bool(self._store.sources(session_id))

    def tainted_by(self, session_id: str) -> tuple[str, ...]:
        """The sources that have run in *session_id*, oldest first."""
        return tuple(self._store.sources(session_id))

    def taint(self, session_id: str, source: str) -> None:
        """Mark *session_id* as having read untrusted content from *source*.

        For content that reaches the model by a road that is not a wrapped
        tool: an uploaded file, a retrieved document, a pasted email.
        """
        if not source:
            raise ValueError("say where the untrusted content came from")
        self._store.add(session_id, source)

    def reset(self, session_id: str) -> None:
        """Forget what *session_id* has read.

        Correct only when the model no longer has it either: the conversation
        was discarded, not merely continued. Text read ten turns ago steers an
        agent as well as text read just now.
        """
        self._store.clear(session_id)

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

    def _destinations(self, name: str, args: Mapping[str, Any] | None) -> dict[str, Any] | None:
        """The destination arguments of a call to a sink listed in ``known``,
        or None when the sink is not listed."""
        if name not in self._known:
            return None
        args = args if isinstance(args, Mapping) else {}
        return {arg: args[arg] for arg in self._known[name] if args.get(arg) is not None}

    def _all_known(self, name: str, destinations: dict[str, Any]) -> bool:
        for arg, value in destinations.items():
            items = value if isinstance(value, list | tuple) else [value]
            if not items or not all(
                isinstance(item, str) and item.casefold() in self._known[name][arg]
                for item in items
            ):
                return False
        return True

    def check(
        self, session_id: str, name: str, args: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """Whether a call to *name* in *session_id* is held, without making it.

        Returns the metadata entry before_action writes: "allowed" False means
        refused, "requires_approval" True means it waits for a person. The
        same answer before_action gives, for a host that only wants the verdict.
        *args* matter only for a sink listed in ``known``.
        """
        read = self.tainted_by(session_id)
        sink = self._is_sink(name)
        destinations = self._destinations(name, args) if sink else None
        known = destinations is not None and self._all_known(name, destinations)
        held = bool(read) and sink and not known
        refused = held and self._on_taint is TaintAction.DENY
        needs_person = held and not refused

        shown = name or "a call with no name"
        if not held:
            if not read:
                reason = f"'{shown}' is not held: nothing untrusted has been read in this session"
            elif known:
                reason = f"'{shown}' is not held: it sends only to destinations already known" + (
                    f" ({_show(destinations)})" if destinations else ""
                )
            else:
                reason = f"'{shown}' is not one of the calls held after an untrusted read"
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
        if destinations is not None:
            entry["destinations"] = destinations
            entry["known_destination"] = known
        return entry

    def record(self, session_id: str, name: str) -> bool:
        """Note that a call to *name* ran in *session_id*. True if it was a
        source, so the session is now tainted by it."""
        if not self._is_source(name):
            return False
        self.taint(session_id, name or "a call with no name")
        return True

    async def before_action(self, context: ActionContext) -> ActionContext:
        if context.action != "tool_call":
            return context
        args = context.input_data.get("args")
        entry = self.check(
            context.session_id, self._name(context), args if isinstance(args, Mapping) else None
        )
        context.metadata["session_taint"] = entry
        if not entry["allowed"]:
            context.decision = InterceptorDecision.DENY
            context.decision_reason = entry["reason"]
        elif entry["requires_approval"]:
            context.decision = InterceptorDecision.REQUIRE_APPROVAL
            context.decision_reason = entry["reason"]
        return context

    async def after_action(self, context: ActionContext) -> ActionContext:
        # Reached only when the tool ran: a read that was refused, or that
        # raised, returned nothing and taints nothing. One whose result a later
        # policy withholds still taints. That is the safe side to be wrong on,
        # and this policy cannot see what the policies after it will decide.
        if context.action != "tool_call":
            return context
        if not self.record(context.session_id, self._name(context)):
            return context
        entry = context.metadata.get("session_taint")
        if isinstance(entry, dict):
            entry["tainted"] = True
            entry["tainted_by"] = list(self.tainted_by(context.session_id))
        return context


def _show(destinations: Mapping[str, Any]) -> str:
    return ", ".join(f"{arg}={value!r}" for arg, value in destinations.items())
