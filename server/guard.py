"""The policy pipeline behind /v1/guard, for clients that are not Python.

A Python caller wraps its agent in SecureAgent and its tools in SecureTool, and
the pipeline runs before and after the call in one process. A client in another
language cannot hand the server its agent, so the server runs the two phases as
two requests instead: the client asks about the input, runs its agent (or tool)
on what came back, then asks about the output. The phases are SecureAgent's own
(``_run_before`` / ``_run_after``), so failure modes, approvals and refusals mean
here exactly what they mean in Python.

The config names two lists, because a Python program builds two: the one it
gives SecureAgent and the one it gives each SecureTool.

    agent:                 # action "invoke": the caller's input, the agent's output
      prompt_injection: {threshold: 0.5}
      secrets: {mode: redact}
    tool:                  # action "tool_call": a tool's name and arguments, its result
      tool_firewall: {rules_path: tools.yaml}   # relative to this file

Each list is built once, at startup, so a policy that remembers between calls
(SessionTaintPolicy) remembers across requests, in this process only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from contracts.interceptor import Policy, StreamGuard
from contracts.types import ActionContext
from sdk.middleware.middleware import SecureAgent
from sdk.policies.config import load_policies

#: The config's sections, by the action each one is asked about. A streamed
#: answer is an agent's, so it is held to the agent's list, as in Python.
SECTIONS = {"invoke": "agent", "stream": "agent", "tool_call": "tool"}


class Checkpoint(SecureAgent):
    """SecureAgent's two phases, run one at a time, with no agent between them."""

    async def check_input(self, context: ActionContext, approval_id: str) -> ActionContext:
        with self._trace(context):
            context, _ = await self._run_before(context, approval_id)
            return self._finalize(context)

    async def check_output(self, context: ActionContext) -> ActionContext:
        # No approval is redeemed here. The id was spent on the input, and none
        # of the built-in policies asks for one on the way out; a custom policy
        # that does gets a fresh approval, as a separate action would.
        with self._trace(context):
            context = await self._run_after(context)
            return self._finalize(context)

    def stream_guards(self) -> list[StreamGuard]:
        """The incremental scanners of the policies that have one (secrets, PII)."""
        guards: list[StreamGuard] = []
        for policy in self._policies:
            factory = getattr(policy, "stream_guard", None)
            guard = factory() if callable(factory) else None
            if guard is not None:
                guards.append(guard)
        return guards

    async def scan_stream(self, context: ActionContext, text: str, final: bool) -> str:
        """One pass of guarded streaming over the text a client is holding back.

        SecureAgent's own _apply_guards: the guards are stateless over the
        text they are given, so the client keeps the held tail and sends it
        with each new chunk, and the server needs no memory of the stream.
        A deny raises ActionBlockedError, after the audit hears of it.
        """
        with self._trace(context):
            return await self._apply_guards(text, self.stream_guards(), context, final)


def _resolve_rules_path(policies: dict[str, Any], base: Path) -> dict[str, Any]:
    firewall = policies.get("tool_firewall")
    if isinstance(firewall, dict) and isinstance(firewall.get("rules_path"), str):
        path = Path(firewall["rules_path"])
        if not path.is_absolute():
            policies = {**policies, "tool_firewall": {**firewall, "rules_path": str(base / path)}}
    return policies


def load_checkpoints(
    path: str | Path, *, writer: Any | None = None, approval_store: Any | None = None
) -> dict[str, Checkpoint]:
    """Build one Checkpoint per section of the config at *path*, keyed by action.

    Raises ValueError on an unknown section, an empty config, or anything
    load_policies refuses. A server that cannot build what it was told to
    build should not start.
    """
    path = Path(path)
    with open(path) as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a mapping with 'agent' and/or 'tool'")
    unknown = set(raw) - set(SECTIONS.values())
    if unknown:
        raise ValueError(f"{path}: unknown section(s) {sorted(unknown)}; expected 'agent', 'tool'")

    by_section: dict[str, Checkpoint] = {}
    for section in dict.fromkeys(SECTIONS.values()):
        policies = raw.get(section)
        if policies is None:
            continue
        if not isinstance(policies, dict) or not policies:
            raise ValueError(f"{path}: section '{section}' names no policies")
        built: list[Policy] = load_policies(
            _resolve_rules_path(policies, path.parent), writer=writer
        )
        by_section[section] = Checkpoint(
            agent=None, policies=built, approval_store=approval_store, writer=writer
        )
    # One pipeline per section, shared by the actions asked of it: what a
    # policy remembers is remembered once.
    checkpoints = {
        action: by_section[section] for action, section in SECTIONS.items() if section in by_section
    }
    if not checkpoints:
        raise ValueError(f"{path}: no 'agent' or 'tool' section")
    return checkpoints
