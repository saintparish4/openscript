"""AgentDojo's tool runtime, with every call put through OpenScript's policies.

AgentDojo hands an agent its tools through a FunctionsRuntime, and scores what
the environment looks like afterwards. GuardedRuntime is that class with one
method overridden: a call becomes a SecureTool call, so the policies see the
name and arguments before the tool runs and the text of the result after, and
a call they hold or refuse never reaches the tool.

It is a FunctionsRuntime on purpose. The replay in replay.py drives it with no
model, and AgentDojo's own model pipelines take the same class, so a run with
a model uses this code and not a second copy of it.

AgentDojo is synchronous and SecureTool is not, so the runtime owns an event
loop and runs each call to completion on it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import Function, FunctionsRuntime, TaskEnvironment

from contracts.interceptor import Policy
from contracts.types import ActionBlockedError
from events.approvals import InMemoryApprovalStore
from sdk import (
    PromptInjectionPolicy,
    SecureTool,
    SessionTaintPolicy,
    ToolFirewallPolicy,
    ToolRules,
)

HERE = Path(__file__).parent

#: The configurations PROTOCOL.md names, in the order it names them.
CONFIGURATIONS = ("none", "detector", "approve_all", "taint_text", "taint_all")

#: (tool, arguments, who made the call) -> whether a person approves it.
Approver = Callable[[str, Mapping[str, Any], str], bool]

#: Who answers a held call. "careful" is the best a person can do: it knows
#: which calls are the task's own. None means nobody answers.
APPROVERS: dict[str, Approver | None] = {
    "nobody": None,
    "careful": lambda _tool, _args, origin: origin == "user",
    "rubber_stamp": lambda _tool, _args, _origin: True,
}


def load_classification() -> dict[str, dict[str, list[str]]]:
    """The frozen source and sink lists, by suite."""
    data = yaml.safe_load((HERE / "classification.yaml").read_text())
    suites: dict[str, dict[str, list[str]]] = data["suites"]
    return suites


def policies_for(configuration: str, lists: Mapping[str, Sequence[str]]) -> list[Policy]:
    """A fresh list of policies for one session. Fresh, because the session
    rule keeps what a session has read on the instance."""
    sinks = list(lists["sinks"])
    if configuration == "none":
        return []
    if configuration == "detector":
        return [PromptInjectionPolicy(tool_output="deny")]
    if configuration == "approve_all":
        rules = ToolRules.model_validate(
            {"rules": {tool: {"requires_approval": True} for tool in sinks}}
        )
        return [ToolFirewallPolicy(rules=rules)]
    if configuration == "taint_text":
        return [SessionTaintPolicy(sources=list(lists["sources"]), sinks=sinks)]
    if configuration == "taint_all":
        return [SessionTaintPolicy(sources="*", sinks=sinks)]
    raise ValueError(f"no such configuration: {configuration!r}")


@dataclass
class Outcome:
    """What became of one call."""

    function: str
    args: dict[str, Any]
    #: Who made it: "user" for the task's own call, "injection" for the attacker's.
    origin: str
    #: ran | approved (held, then a person said yes, then ran) | held | refused
    #: | withheld (it ran; its result was kept from the agent)
    status: str
    reason: str = ""
    #: The tool's own error, if it raised. Not a policy decision.
    error: str | None = None

    @property
    def ran(self) -> bool:
        """The tool's code executed."""
        return self.status in ("ran", "approved", "withheld")

    @property
    def delivered(self) -> bool:
        """The agent got a result back from it."""
        return self.status in ("ran", "approved") and self.error is None


@dataclass
class _Session:
    policies: list[Policy]
    approver: Approver | None
    store: InMemoryApprovalStore = field(default_factory=InMemoryApprovalStore)


class GuardedRuntime(FunctionsRuntime):
    """A FunctionsRuntime whose calls go through *policies*.

    With no policies it is a FunctionsRuntime that keeps a log. Set ``origin``
    before a call to say who is making it; the approver is told, and the log
    records it.
    """

    _loop: asyncio.AbstractEventLoop | None = None

    def __init__(
        self,
        functions: Sequence[Function] = (),
        *,
        policies: Sequence[Policy] = (),
        approver: Approver | None = None,
        session_id: str = "replay",
    ) -> None:
        super().__init__(functions)
        self._session = _Session(list(policies), approver)
        self._session_id = session_id
        self.origin = "user"
        self.log: list[Outcome] = []
        self.approvals_asked = 0

    @classmethod
    def _run(cls, coroutine: Any) -> Any:
        if cls._loop is None or cls._loop.is_closed():
            cls._loop = asyncio.new_event_loop()
        return cls._loop.run_until_complete(coroutine)

    def run_function(  # type: ignore[override]
        self,
        env: TaskEnvironment | None,
        function: str,
        kwargs: Mapping[str, Any],
        raise_on_error: bool = False,
    ) -> tuple[Any, str | None]:
        args = dict(kwargs)
        if not self._session.policies or function not in self.functions:
            # Unguarded, or a tool that does not exist and so cannot run.
            result, error = super().run_function(env, function, args, raise_on_error=False)
            self.log.append(Outcome(function, args, self.origin, "ran", error=error))
            return result, error

        ran: dict[str, Any] = {}

        async def tool(**arguments: Any) -> str:
            result, error = FunctionsRuntime.run_function(
                self, env, function, arguments, raise_on_error=False
            )
            ran["result"], ran["error"] = result, error
            # What the policies are shown is what the agent would be: the
            # text of the result, formatted as AgentDojo formats it.
            return error if error is not None else tool_result_to_str(result)

        secure = SecureTool(
            tool,
            self._session.policies,
            name=function,
            approval_store=self._session.store,
            session_id=self._session_id,
        )
        status, reason = self._call(secure, function, args, ran)
        self.log.append(Outcome(function, args, self.origin, status, reason, ran.get("error")))
        if status in ("ran", "approved"):
            return ran["result"], ran["error"]
        kind = "PolicyWithheld" if status == "withheld" else "PolicyBlocked"
        return "", f"{kind}: {reason}"

    def _call(
        self, secure: SecureTool, function: str, args: dict[str, Any], ran: dict[str, Any]
    ) -> tuple[str, str]:
        """Make the call, and if it is held, ask whoever answers approvals."""
        try:
            self._run(secure.call(args))
            return "ran", ""
        except ActionBlockedError as blocked:
            if not blocked.approval_id:
                # Refused before the tool ran, or its result withheld after.
                return ("withheld" if "result" in ran else "refused"), blocked.reason
            held = blocked

        self.approvals_asked += 1
        approver = self._session.approver
        approved = approver is not None and approver(function, args, self.origin)
        if approver is not None:
            self._run(self._session.store.decide(held.approval_id, approved, "approver", ""))
        if not approved:
            return "held", held.reason
        try:
            self._run(secure.call(args, approval_id=held.approval_id))
            return "approved", held.reason
        except ActionBlockedError as blocked:
            return ("withheld" if "result" in ran else "refused"), blocked.reason
