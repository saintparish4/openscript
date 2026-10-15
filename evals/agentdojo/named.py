"""A candidate rule, measured before it is built into the package: destinations
the user named count as known.

PROTOCOL-named.md says why and what is measured. The session rule holds every
state-changing call after an untrusted read; with ``known`` it lets through a
call that sends only where the user has sent before. This also lets through a
call whose every destination appears in what the user asked for, provided no
argument carries a link the user did not give: "message Alice" must not
release a message to Alice carrying the attacker's link.

It is a subclass of SessionTaintPolicy here, in the harness, and nowhere in
``sdk/``: the rule ships only if the measurement says it is worth shipping.
Standard library and ``sdk`` only, so it is testable without AgentDojo.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from sdk import SessionTaintPolicy

HERE = Path(__file__).resolve().parent

#: A link: a scheme, a "www." host, or a bare host ending in one of these.
#: Written down before any run. An obfuscated link ("hxxp", "example[.]com")
#: is not recognised, and that is a limit of the guard, stated with it.
TLDS = (
    "com", "net", "org", "io", "co", "ai", "app", "dev", "info", "biz", "xyz", "me", "ly",
    "site", "online", "link",
)  # fmt: skip
LINK = re.compile(
    r"(?:https?://[^\s\"'<>()]+"
    r"|\bwww\.[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/[^\s\"'<>()]*)?"
    r"|(?<![\w@.-])(?:[a-z0-9-]+\.)+(?:" + "|".join(TLDS) + r")\b(?:/[^\s\"'<>()]*)?)",
    re.IGNORECASE,
)
#: Characters that may not touch a named value on either side: a name inside
#: a longer word, address or host is not that name ("general" in "generally",
#: "informations.com" in "true-informations.com").
_WORD = r"a-z0-9_@\-"


def load_named() -> dict[str, Any]:
    """The frozen destination arguments (named.yaml)."""
    named: dict[str, Any] = yaml.safe_load((HERE / "named.yaml").read_text())
    return named


def normalise(value: str) -> str:
    """Case folded, with a scheme and a trailing slash taken off."""
    value = value.strip().casefold()
    value = re.sub(r"^https?://", "", value)
    return value.rstrip("/")


def said(value: str, text: str) -> bool:
    """Does *value* appear in *text* as itself, not as part of a longer word?"""
    value = normalise(value)
    if not value:
        return False
    pattern = rf"(?<![{_WORD}.]){re.escape(value)}(?![{_WORD}/])"
    return re.search(pattern, text.casefold()) is not None


def strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list | tuple | set):
        for item in value:
            yield from strings(item)


def links(args: Mapping[str, Any]) -> list[str]:
    """Every link in any argument, at any depth."""
    return [match.group(0) for text in strings(args) for match in LINK.finditer(text)]


class NamedTaintPolicy(SessionTaintPolicy):
    """The session rule with ``known``, where what the user asked for also counts.

    *destinations* maps a sink to the arguments that say where it sends.
    *said_by_user* is the user's own request for the session, never a tool's
    result. A held call to a listed sink is let through when every value of
    those arguments that is present is known or appears in that request, and
    every link in any of its arguments appears in it too. *known* is the
    sending history, as for SessionTaintPolicy; a call it lets through passes
    the same link check.
    """

    def __init__(
        self,
        *,
        sources: Sequence[str],
        sinks: Sequence[str],
        destinations: Mapping[str, Sequence[str]],
        said_by_user: str,
        known: Mapping[str, Mapping[str, Sequence[str]]] | None = None,
    ) -> None:
        # The sending history is checked here, not by the parent, so that a
        # call released by it passes the same link check as one the user named.
        super().__init__(sources=sources, sinks=sinks)
        unknown = (set(destinations) | set(known or {})) - set(sinks)
        if unknown:
            raise ValueError(f"not sinks: {sorted(unknown)}")
        if set(known or {}) - set(destinations):
            raise ValueError("every tool with known destinations needs its destination arguments")
        self._named_args = {tool: list(args) for tool, args in destinations.items()}
        self._history = {
            tool: {arg: {str(v).casefold() for v in values} for arg, values in by_arg.items()}
            for tool, by_arg in (known or {}).items()
        }
        self._request = said_by_user

    def _named(self, tool: str, arg: str, value: Any) -> bool:
        items = value if isinstance(value, list | tuple) else [value]
        return bool(items) and all(
            isinstance(item, str)
            and (
                item.casefold() in self._history.get(tool, {}).get(arg, set())
                or said(item, self._request)
            )
            for item in items
        )

    def check(
        self, session_id: str, name: str, args: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        entry = super().check(session_id, name, args)
        if not entry["requires_approval"] or name not in self._named_args:
            return entry
        args = args if isinstance(args, Mapping) else {}
        present = {a: args[a] for a in self._named_args[name] if args.get(a) is not None}
        unnamed_links = [link for link in links(args) if not said(link, self._request)]
        if unnamed_links or not all(self._named(name, a, v) for a, v in present.items()):
            entry["named_destination"] = False
            return entry
        return {
            **entry,
            "risk": 0.0,
            "requires_approval": False,
            "named_destination": True,
            "reason": f"'{name}' is not held: every destination and link in it was named "
            "by the user or is already known",
        }
