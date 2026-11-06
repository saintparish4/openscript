"""Bypass search 4d: what each component does when what it depends on fails.

Each test is one row of the table in docs/red-team.md. "Closed" means the
irreversible call does not happen. "Open" means it does, and the row says
what the deployment must do about it.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from evals.ledger import ServiceProcess, TokenClass, call_hash
from openscript_sdk import SecureTool, SessionTaintPolicy, ToolFirewallPolicy, ToolRules
from openscript_sdk.contracts.types import ActionBlockedError
from openscript_sdk.events.approvals import InMemoryApprovalStore
from openscript_sdk.policies.taint_store import FileTaintStore

ROOT = Path(__file__).resolve().parents[2]
NOWHERE = "redis://127.0.0.1:1/0"  # nothing listens on port 1


def _held_tool(store: Any, effects: list[int]) -> SecureTool:
    def pay(amount: int) -> str:
        effects.append(amount)
        return "paid"

    rules = ToolRules.model_validate({"rules": {"pay": {"requires_approval": True}}})
    return SecureTool(pay, [ToolFirewallPolicy(rules=rules)], approval_store=store)


# -- approvals ---------------------------------------------------------------------------


def test_redis_unreachable_when_a_call_is_held_is_closed():
    from openscript_sdk.events.approvals import RedisApprovalStore

    effects: list[int] = []
    with pytest.raises(Exception) as raised:
        asyncio.run(_held_tool(RedisApprovalStore(NOWHERE), effects).call({"amount": 5}))
    assert "Connection" in type(raised.value).__name__, raised.value
    assert effects == []


def test_redis_unreachable_when_an_approval_is_redeemed_is_closed():
    from openscript_sdk.events.approvals import RedisApprovalStore

    effects: list[int] = []
    tool = _held_tool(RedisApprovalStore(NOWHERE), effects)
    with pytest.raises(Exception) as raised:
        asyncio.run(tool.call({"amount": 5}, approval_id="a" * 32))
    assert "Connection" in type(raised.value).__name__, raised.value
    assert effects == []


@pytest.mark.parametrize(
    ("left", "redeemed"),
    [(timedelta(0), False), (timedelta(seconds=-1), False), (timedelta(seconds=5), True)],
)
def test_an_approval_at_its_expiry_is_refused_and_one_inside_it_is_not(
    left: timedelta, redeemed: bool
):
    store = InMemoryApprovalStore()
    effects: list[int] = []
    tool = _held_tool(store, effects)
    with pytest.raises(ActionBlockedError) as held:
        asyncio.run(tool.call({"amount": 5}))
    approval_id = held.value.approval_id
    asyncio.run(store.decide(approval_id, approved=True))
    store._records[approval_id].expires_at = datetime.now(UTC) + left
    if redeemed:
        assert asyncio.run(tool.call({"amount": 5}, approval_id=approval_id)) == "paid"
    else:
        with pytest.raises(ActionBlockedError):
            asyncio.run(tool.call({"amount": 5}, approval_id=approval_id))
    assert effects == ([5] if redeemed else [])


# -- the session rule's memory ---------------------------------------------------------------


def _worker(store: Any, effects: list[str]) -> dict[str, SecureTool]:
    taint = SessionTaintPolicy(sources=["read"], sinks=["send"], store=store)

    def read() -> str:
        return "a stranger's text"

    def send() -> str:
        effects.append("sent")
        return "sent"

    return {"read": SecureTool(read, [taint]), "send": SecureTool(send, [taint])}


def test_two_workers_with_memory_in_the_process_is_open():
    """Row S6/J4: worker B never heard of worker A's read. Open by
    configuration: pass a store both can see."""
    effects: list[str] = []
    a, b = _worker(None, effects), _worker(None, effects)
    asyncio.run(a["read"].call({}, session_id="s"))
    asyncio.run(b["send"].call({}, session_id="s"))
    assert effects == ["sent"]


def test_two_workers_sharing_a_store_on_disk_is_closed(tmp_path: Path):
    effects: list[str] = []
    a, b = _worker(FileTaintStore(tmp_path), effects), _worker(FileTaintStore(tmp_path), effects)
    asyncio.run(a["read"].call({}, session_id="s"))
    with pytest.raises(ActionBlockedError):
        asyncio.run(b["send"].call({}, session_id="s"))
    assert effects == []


# -- the Claude Code hook ----------------------------------------------------------------------

CONFIG = {
    "version": 1,
    "session": {"sources": ["WebFetch"], "sinks": ["mcp__bank__send"]},
}


def _payload(event: str, tool: str) -> str:
    return json.dumps(
        {
            "session_id": "s",
            "hook_event_name": event,
            "tool_name": tool,
            "tool_input": {},
            "cwd": str(ROOT),
        }
    )


def _hook(tmp: Path, command: str, stdin: str) -> subprocess.CompletedProcess[str]:
    config = tmp / "openscript.yaml"
    config.write_text(json.dumps(CONFIG))
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "openscript_sdk.hooks.claude_code",
            "--config",
            str(config),
            command,
        ],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=60,
        env={**os.environ, "OPENSCRIPT_STATE_DIR": str(tmp / "state")},
    )


def _kill_mid_decision(tmp: Path, wrapped: bool) -> int:
    """The hook as the example settings run it, killed while it decides."""
    config = tmp / "openscript.yaml"
    config.write_text(json.dumps(CONFIG))
    hook = f"{sys.executable} -m openscript_sdk.hooks.claude_code --config {config} pre-tool-use"
    shell = subprocess.Popen(
        ["sh", "-c", f"{hook} || exit 2" if wrapped else f"exec {hook}"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ROOT,
        env={**os.environ, "OPENSCRIPT_STATE_DIR": str(tmp / "state")},
    )
    # The hook waits for its payload on stdin; it is killed before it gets one.
    deadline = time.monotonic() + 10
    child = None
    while child is None and time.monotonic() < deadline:
        found = subprocess.run(
            ["pgrep", "-f", "openscript_sdk.hooks.claude_code"], capture_output=True, text=True
        )
        pids = [int(p) for p in found.stdout.split() if int(p) != shell.pid]
        child = pids[0] if pids else (shell.pid if not wrapped else None)
        time.sleep(0.05)
    assert child is not None
    os.kill(child, signal.SIGKILL)
    shell.communicate(timeout=10)
    return shell.returncode


def test_the_hook_killed_mid_decision_under_the_example_wrapper_is_closed(tmp_path: Path):
    """Claude Code blocks on exit code 2 only. The example runs the hook as
    "openscript-hook pre-tool-use || exit 2", so a killed hook blocks."""
    assert _kill_mid_decision(tmp_path, wrapped=True) == 2


def test_the_hook_killed_mid_decision_without_the_wrapper_is_open(tmp_path: Path):
    """Without "|| exit 2" the code is -9, which Claude Code treats as a
    non-blocking error: the call goes ahead. Open by configuration."""
    assert _kill_mid_decision(tmp_path, wrapped=False) not in (0, 2)


def test_the_hooks_state_unwritable_when_a_read_is_attempted_is_closed(tmp_path: Path):
    sessions = tmp_path / "state" / "claude-code" / "sessions"
    sessions.mkdir(parents=True)
    sessions.chmod(0o500)
    try:
        read = _hook(tmp_path, "pre-tool-use", _payload("PreToolUse", "WebFetch"))
    finally:
        sessions.chmod(0o700)
    assert read.returncode == 2, "a read the hook cannot record must not run"


def test_the_hooks_state_unwritable_after_a_read_is_closed(tmp_path: Path):
    """The read is recorded when it is attempted, so a PostToolUse that cannot
    write leaves the session tainted all the same."""
    assert _hook(tmp_path, "pre-tool-use", _payload("PreToolUse", "WebFetch")).returncode == 0
    sessions = tmp_path / "state" / "claude-code" / "sessions"
    sessions.chmod(0o500)
    try:
        _hook(tmp_path, "post-tool-use", _payload("PostToolUse", "WebFetch"))
    finally:
        sessions.chmod(0o700)
    send = _hook(tmp_path, "pre-tool-use", _payload("PreToolUse", "mcp__bank__send"))
    assert json.loads(send.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


# -- the effect side ------------------------------------------------------------------------------


def test_the_effect_side_unreachable_is_closed():
    service = ServiceProcess()
    token = service.approve("a1", call_hash("pay", {"amount": 5}))
    service.close()
    with pytest.raises(OSError):
        service.effect("pay", {"amount": 5}, token)


def test_a_restarted_effect_side_does_not_honour_its_predecessors_tokens():
    with ServiceProcess() as first:
        token = first.approve("a1", call_hash("pay", {"amount": 5}))
    with ServiceProcess() as second:
        entry = second.effect("pay", {"amount": 5}, token)
    assert (entry.token, entry.applied) == (TokenClass.FORGED, False)
