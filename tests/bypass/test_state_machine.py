"""Bypass search 4a: a state machine over reads, acts, approvals, redemptions,
resets and restarts, against one invariant.

    A sink never runs in a tainted session without a consumed approval whose
    hash matches, given by a person for that call in that session.

"Tainted" is the ground truth the model holds: a session that has read a
source since the host last reset it. A restart of the policy's process does
not untaint anything, because the model still has the text in its context.
docs/red-team.md lists what this found.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    Bundle,
    RuleBasedStateMachine,
    consumes,
    invariant,
    rule,
)

from contracts.types import ActionBlockedError
from events.approvals import InMemoryApprovalStore
from sdk import SecureTool, SessionTaintPolicy
from sdk.policies.taint_store import FileTaintStore

SESSIONS = st.sampled_from(["s1", "s2"])
AMOUNTS = st.integers(min_value=1, max_value=3)


def _run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


class Sessions(RuleBasedStateMachine):
    """One host with a read tool and an act tool behind the session rule."""

    #: "file" keeps what sessions read on disk; "memory" in the process.
    STORE = "file"
    #: Whether the policy's process may restart.
    RESTARTS = True

    pending = Bundle("pending")

    def __init__(self) -> None:
        super().__init__()
        self._dir = TemporaryDirectory()
        self.approvals = InMemoryApprovalStore()  # outlives a restart, as Redis would
        self.ran_effects: list[tuple[str, int, str]] = []
        self.violations: list[str] = []
        # Ground truth and what a person did.
        self.tainted: dict[str, bool] = {"s1": False, "s2": False}
        self.requested: dict[str, tuple[str, int]] = {}  # approval id -> (session, amount)
        self.approved: set[str] = set()
        self.consumed: set[str] = set()
        self._start()

    def _start(self) -> None:
        store = FileTaintStore(Path(self._dir.name)) if self.STORE == "file" else None
        policy = SessionTaintPolicy(sources=["read"], sinks=["act"], store=store)

        async def read() -> str:
            return "text a stranger wrote"

        async def act(amount: int) -> str:
            return "done"

        self.read = SecureTool(read, [policy], approval_store=self.approvals)
        self.act = SecureTool(act, [policy], approval_store=self.approvals)

    def teardown(self) -> None:
        self._dir.cleanup()

    # -- what happens -------------------------------------------------------

    @rule(session=SESSIONS)
    def do_read(self, session: str) -> None:
        _run(self.read.call({}, session_id=session))
        self.tainted[session] = True

    @rule(target=pending, session=SESSIONS, amount=AMOUNTS)
    def act_without_approval(self, session: str, amount: int) -> str:
        try:
            _run(self.act.call({"amount": amount}, session_id=session))
        except ActionBlockedError as held:
            assert held.approval_id
            self.requested[held.approval_id] = (session, amount)
            return held.approval_id
        self._ran(session, amount, "")
        return ""

    @rule(approval=pending)
    def person_approves(self, approval: str) -> None:
        if not approval or approval in self.approved:
            return
        try:
            _run(self.approvals.decide(approval, approved=True, decided_by="person"))
        except ValueError:
            return  # already consumed and gone, or expired
        self.approved.add(approval)

    @rule(approval=consumes(pending), session=SESSIONS, amount=AMOUNTS)
    def act_with_approval(self, approval: str, session: str, amount: int) -> None:
        """The agent retries with an approval id: its own, or one from another
        session or for another amount."""
        if not approval:
            return
        try:
            _run(self.act.call({"amount": amount}, session_id=session, approval_id=approval))
        except ActionBlockedError:
            return
        self._ran(session, amount, approval)

    @rule(session=SESSIONS)
    def host_resets(self, session: str) -> None:
        """The host discards the model's context for the session."""
        self.read_policy().reset(session)
        self.tainted[session] = False

    @rule()
    def restart(self) -> None:
        if self.RESTARTS:
            self._start()

    def read_policy(self) -> SessionTaintPolicy:
        policy = self.act._pipeline._policies[0]
        assert isinstance(policy, SessionTaintPolicy)
        return policy

    # -- what must hold -------------------------------------------------------

    def _ran(self, session: str, amount: int, approval: str) -> None:
        self.ran_effects.append((session, amount, approval))
        if not self.tainted[session]:
            return
        if not approval:
            self.violations.append(f"act({amount}) ran in tainted {session} with no approval")
        elif self.requested.get(approval) != (session, amount):
            self.violations.append(
                f"act({amount}) ran in tainted {session} on an approval given for "
                f"{self.requested.get(approval)}"
            )
        elif approval not in self.approved:
            self.violations.append(f"act({amount}) ran on an approval nobody gave")
        elif approval in self.consumed:
            self.violations.append(f"act({amount}) ran twice on one approval")
        self.consumed.add(approval)

    @invariant()
    def no_unapproved_effect_in_a_tainted_session(self) -> None:
        assert not self.violations, self.violations[0]


def _machine(store: str, restarts: bool) -> type[RuleBasedStateMachine]:
    return type(
        f"Sessions_{store}_{'restarts' if restarts else 'steady'}",
        (Sessions,),
        {"STORE": store, "RESTARTS": restarts},
    )


SETTINGS = settings(
    max_examples=300,
    stateful_step_count=25,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    derandomize=True,
)


def test_with_memory_on_disk_every_effect_in_a_tainted_session_was_approved_for_it():
    _machine("file", restarts=True).TestCase.settings = SETTINGS
    _machine("file", restarts=True).TestCase().runTest()


def test_with_memory_in_the_process_and_no_restart_the_same_holds():
    _machine("memory", restarts=False).TestCase.settings = SETTINGS
    _machine("memory", restarts=False).TestCase().runTest()


def test_with_memory_in_the_process_a_restart_forgets_what_was_read():
    """Row S6 of the threat model, as it stands: the default store lives in the
    process. Not a defect to fix in code; the store= argument is the answer."""
    machine = _machine("memory", restarts=True)
    machine.TestCase.settings = SETTINGS
    with pytest.raises(AssertionError, match="with no approval"):
        machine.TestCase().runTest()
