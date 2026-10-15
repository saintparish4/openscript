"""FileTaintStore: a session's reads written down, so a fresh process remembers them.

What has to hold: parallel writers do not lose or mangle each other's lines,
a damaged record taints rather than cleans, a session id cannot become a path
out of the directory, and the policy reads the same memory from any process.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from sdk import SessionTaintPolicy
from sdk.policies.taint_store import UNREADABLE, FileTaintStore, append_jsonl, prune, state_dir

ROOT = Path(__file__).resolve().parents[1]
SESSION = "3f2b9c1e-7d4a-4b8e-9a51-0c6d2e8f4b17"  # the shape of a Claude Code session id


def test_it_keeps_each_source_once_in_the_order_it_first_ran(tmp_path):
    store = FileTaintStore(tmp_path)
    assert store.sources(SESSION) == []
    for source in ["WebFetch", "mcp__github__get_issue", "WebFetch"]:
        store.add(SESSION, source)
    assert store.sources(SESSION) == ["WebFetch", "mcp__github__get_issue"]
    assert store.sources("another-session") == []
    store.clear(SESSION)
    store.clear(SESSION)  # clearing twice is fine
    assert store.sources(SESSION) == []


def test_two_policies_with_one_directory_share_one_memory(tmp_path):
    reader = SessionTaintPolicy(
        sources=["WebFetch"], sinks=["mcp__*"], store=FileTaintStore(tmp_path)
    )
    reader.record(SESSION, "WebFetch")
    writer = SessionTaintPolicy(
        sources=["WebFetch"], sinks=["mcp__*"], store=FileTaintStore(tmp_path)
    )
    assert writer.check(SESSION, "mcp__slack__post_message")["requires_approval"]


def test_a_damaged_record_taints_the_session_rather_than_cleaning_it(tmp_path):
    store = FileTaintStore(tmp_path)
    (tmp_path / f"{SESSION}.jsonl").write_text('{"source": "WebFetch"}\n{"sour\n[]\n')
    assert store.sources(SESSION) == ["WebFetch", UNREADABLE]
    (tmp_path / f"{SESSION}.jsonl").write_text("not json at all\n")
    policy = SessionTaintPolicy(sources=["WebFetch"], sinks=["Bash"], store=store)
    assert policy.check(SESSION, "Bash")["requires_approval"]


@pytest.mark.parametrize("bad", ["../escape", "a/b", "", "x" * 129, "with space", "nul\x00"])
def test_a_session_id_that_could_name_another_file_is_refused(tmp_path, bad):
    store = FileTaintStore(tmp_path)
    with pytest.raises(ValueError, match="session id"):
        store.add(bad, "WebFetch")
    with pytest.raises(ValueError, match="session id"):
        store.sources(bad)


def test_parallel_writers_lose_no_line(tmp_path):
    """32 processes appending at once, as parallel hooks would."""
    script = (
        "import sys; from sdk.policies.taint_store import FileTaintStore; "
        "FileTaintStore(sys.argv[1]).add(sys.argv[2], 'source-' + sys.argv[3])"
    )
    procs = [
        subprocess.Popen([sys.executable, "-c", script, str(tmp_path), SESSION, str(i)], cwd=ROOT)
        for i in range(32)
    ]
    assert all(proc.wait(timeout=120) == 0 for proc in procs)
    lines = (tmp_path / f"{SESSION}.jsonl").read_text().splitlines()
    assert len(lines) == 32
    assert sorted(json.loads(line)["source"] for line in lines) == sorted(
        f"source-{i}" for i in range(32)
    )


def test_files_are_the_owners_alone(tmp_path):
    FileTaintStore(tmp_path / "state").add(SESSION, "WebFetch")
    mode = stat.S_IMODE((tmp_path / "state" / f"{SESSION}.jsonl").stat().st_mode)
    assert mode == 0o600
    append_jsonl(tmp_path / "audit.jsonl", {"verdict": "ask"})
    assert stat.S_IMODE((tmp_path / "audit.jsonl").stat().st_mode) == 0o600


def test_prune_removes_only_sessions_left_alone_long_enough(tmp_path):
    store = FileTaintStore(tmp_path)
    store.add("old-session", "WebFetch")
    store.add("new-session", "WebFetch")
    long_ago = time.time() - 30 * 86400
    os.utime(tmp_path / "old-session.jsonl", (long_ago, long_ago))
    assert prune(tmp_path, older_than=7 * 86400) == 1
    assert store.sources("old-session") == [] and store.sources("new-session") == ["WebFetch"]


def test_the_state_directory_follows_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENSCRIPT_STATE_DIR", str(tmp_path / "explicit"))
    assert state_dir("claude-code") == tmp_path / "explicit" / "claude-code"
    monkeypatch.delenv("OPENSCRIPT_STATE_DIR")
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    assert state_dir("claude-code") == tmp_path / "xdg" / "openscript" / "claude-code"
    monkeypatch.delenv("XDG_STATE_HOME")
    assert state_dir("claude-code") == Path.home() / ".local/state/openscript/claude-code"
