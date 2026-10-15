"""openscript-hook, run as Claude Code runs it: a fresh process, JSON on stdin.

What has to hold, because getting it wrong is silent:
- it only tightens: "deny" (exit 2) or "ask", never "allow";
- anything that goes wrong while deciding blocks the call;
- stdout is empty or exactly one JSON object, whatever a library prints;
- the session's memory survives between processes;
- redaction keeps the output's shape, and the audit log never holds a secret.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "sdk" / "hooks"
SESSION = "3f2b9c1e-7d4a-4b8e-9a51-0c6d2e8f4b17"
AWS = "AKIAIOSFODNN7EXAMPLE"

CONFIG = {
    "version": 1,
    "firewall": {
        "rules": {
            "mcp__github__create_issue": {"args": {"owner": {"one_of": ["acme"]}}},
            "mcp__github__merge_pull_request": {"requires_approval": True},
            "mcp__github__delete_repository": {"deny": True},
        }
    },
    "session": {
        "sources": ["WebFetch", "mcp__github__get_*"],
        "sinks": ["mcp__github__create_issue", "mcp__github__merge_pull_request"],
    },
    "redact": {"tools": ["Bash", "Read", "mcp__*"]},
}


class Hook:
    """The hook as a subprocess, with its own state directory and config."""

    def __init__(self, tmp: Path, config: dict[str, Any] | None = None) -> None:
        self.state = tmp / "state"
        self.config = tmp / "openscript.yaml"
        self.config.write_text(yaml.safe_dump(config or CONFIG))
        self.env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("OPENSCRIPT_HOOK_CONFIG", "CLAUDE_PROJECT_DIR", "OPENSCRIPT_STATE_DIR")
        }
        self.env["OPENSCRIPT_STATE_DIR"] = str(self.state)

    def run(
        self, command: str, stdin: str, *extra: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "sdk.hooks.claude_code",
                "--config",
                str(self.config),
                command,
                *extra,
            ],
            input=stdin,
            cwd=ROOT,
            capture_output=True,
            text=True,
            env={**self.env, **(env or {})},
            timeout=60,
        )

    def pre(self, tool: str, **args: Any) -> subprocess.CompletedProcess[str]:
        return self.run("pre-tool-use", json.dumps(payload("PreToolUse", tool, args)))

    def post(self, tool: str, response: Any, **args: Any) -> subprocess.CompletedProcess[str]:
        return self.run(
            "post-tool-use", json.dumps(payload("PostToolUse", tool, args, response=response))
        )

    def audit(self) -> list[dict[str, Any]]:
        path = self.state / "claude-code" / "audit.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()]


def payload(event: str, tool: str, args: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """The fields Claude Code sends, from its hooks reference."""
    body = {
        "session_id": SESSION,
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/tmp/project",
        "hook_event_name": event,
        "permission_mode": "default",
        "tool_name": tool,
        "tool_input": args,
        "tool_use_id": "toolu_01",
    }
    if "response" in extra:
        body["tool_response"] = extra["response"]
    return body


def asked(proc: subprocess.CompletedProcess[str]) -> str:
    """The reason of an "ask", checking it is exactly that and nothing else."""
    assert proc.returncode == 0, proc.stderr
    decision = json.loads(proc.stdout)
    output = decision["hookSpecificOutput"]
    assert output["hookEventName"] == "PreToolUse"
    assert output["permissionDecision"] == "ask"
    assert set(decision) == {"hookSpecificOutput"}
    reason: str = output["permissionDecisionReason"]
    assert reason.startswith("OpenScript: ")
    return reason


def silent(proc: subprocess.CompletedProcess[str]) -> None:
    assert (proc.returncode, proc.stdout) == (0, ""), proc.stderr


def blocked(proc: subprocess.CompletedProcess[str]) -> str:
    assert proc.returncode == 2 and proc.stdout == "", (proc.returncode, proc.stdout)
    assert proc.stderr.startswith("OpenScript: ")
    return proc.stderr


# -- what it decides ------------------------------------------------------------


def test_a_write_runs_unasked_until_the_session_has_read_something(tmp_path):
    hook = Hook(tmp_path)
    silent(hook.pre("mcp__github__create_issue", owner="acme", title="x"))
    silent(hook.pre("mcp__github__get_issue", number=7))  # a read: noted, not held
    reason = asked(hook.pre("mcp__github__create_issue", owner="acme", title="x"))
    assert "mcp__github__get_issue" in reason


def test_the_memory_is_per_session(tmp_path):
    hook = Hook(tmp_path)
    silent(hook.pre("WebFetch", url="https://example.com"))
    other = payload("PreToolUse", "mcp__github__create_issue", {"owner": "acme"})
    other["session_id"] = "another-session"
    silent(hook.run("pre-tool-use", json.dumps(other)))


def test_a_firewall_refusal_blocks_with_the_reason_for_claude(tmp_path):
    hook = Hook(tmp_path)
    reason = blocked(hook.pre("mcp__github__create_issue", owner="someone-else"))
    assert "owner" in reason and "someone-else" in reason
    assert "mcp__github__delete_repository" in blocked(
        hook.pre("mcp__github__delete_repository", name="r")
    )


def test_a_rule_that_requires_approval_asks_even_in_a_clean_session(tmp_path):
    reason = asked(Hook(tmp_path).pre("mcp__github__merge_pull_request", number=3))
    assert "mcp__github__merge_pull_request" in reason and "review" in reason


def test_deny_mode_refuses_after_a_read(tmp_path):
    config = {**CONFIG, "session": {**CONFIG["session"], "on_taint": "deny"}}
    hook = Hook(tmp_path, config)
    silent(hook.pre("WebFetch", url="https://example.com"))
    assert "refused" in blocked(hook.pre("mcp__github__create_issue", owner="acme"))


def test_a_tool_it_has_no_rule_for_is_left_to_claude_code(tmp_path):
    hook = Hook(tmp_path)
    silent(hook.pre("WebFetch", url="https://example.com"))
    silent(hook.pre("mcp__slack__slack_post_message", channel_id="C1", text="hi"))


def test_it_never_answers_allow(tmp_path):
    """Every stdout it can produce, parsed: "ask" or nothing."""
    hook = Hook(tmp_path)
    procs = [
        hook.pre("mcp__github__create_issue", owner="acme"),
        hook.pre("mcp__github__get_issue", number=1),
        hook.pre("mcp__github__create_issue", owner="acme"),
        hook.pre("mcp__github__merge_pull_request", number=1),
        hook.pre("mcp__github__create_issue", owner="nope"),
    ]
    for proc in procs:
        if proc.stdout:
            assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert "allow" not in json.dumps(json.loads(proc.stdout or "{}"))


# -- failing closed ---------------------------------------------------------------


@pytest.mark.parametrize(
    "stdin",
    ["not json", "[]", json.dumps({"session_id": SESSION}), json.dumps({"tool_name": "WebFetch"})],
    ids=["not-json", "not-an-object", "no-tool", "no-session"],
)
def test_input_it_cannot_read_blocks_the_call(tmp_path, stdin):
    assert "could not decide" in blocked(Hook(tmp_path).run("pre-tool-use", stdin))


def test_a_missing_config_blocks_the_call(tmp_path):
    hook = Hook(tmp_path)
    hook.config.unlink()
    assert "no OpenScript config" in blocked(hook.pre("mcp__github__create_issue", owner="acme"))


@pytest.mark.parametrize(
    "config",
    [
        {"version": 1, "sesion": {"sources": ["WebFetch"], "sinks": ["mcp__x"]}},
        {"version": 2},
        {"version": 1, "firewall": {}},
        {"version": 1, "session": {"sources": [], "sinks": ["mcp__x"]}},
        {"version": 1, "session": {"sources": ["mcp__*__get"], "sinks": ["mcp__x"]}},
    ],
    ids=["misspelt-key", "unknown-version", "firewall-without-rules", "no-sources", "bad-star"],
)
def test_a_config_that_would_not_do_what_it_says_blocks_the_call(tmp_path, config):
    proc = Hook(tmp_path, config).pre("mcp__x", a=1)
    assert "could not decide" in blocked(proc)


def test_a_state_directory_it_cannot_write_blocks_the_call(tmp_path):
    hook = Hook(tmp_path)
    hook.state.mkdir()
    hook.state.chmod(0o500)
    try:
        if os.access(hook.state, os.W_OK):
            pytest.skip("running as a user who can write anywhere")
        blocked(hook.pre("mcp__github__create_issue", owner="acme"))
    finally:
        hook.state.chmod(0o700)


def test_an_import_that_fails_blocks_the_call(tmp_path):
    stub = tmp_path / "stub"
    stub.mkdir()
    (stub / "pydantic.py").write_text("raise ImportError('pydantic is broken here')\n")
    hook = Hook(tmp_path)
    proc = hook.run(
        "pre-tool-use",
        json.dumps(payload("PreToolUse", "WebFetch", {"url": "x"})),
        env={"PYTHONPATH": str(stub)},
    )
    assert "pydantic is broken here" in blocked(proc)


def test_stdout_holds_only_the_decision_whatever_a_library_prints(tmp_path):
    """A policy that prints, and structlog logging before it is configured,
    both of which write to stdout, must not reach Claude Code's stdout."""
    hook = Hook(tmp_path)
    wrapper = (
        "import sys, structlog\n"
        "import sdk.policies.session_taint as taint\n"
        "real = taint.SessionTaintPolicy.check\n"
        "def noisy(self, *a, **k):\n"
        "    print('noise from a policy')\n"
        "    structlog.get_logger().warning('noise from structlog')\n"
        "    return real(self, *a, **k)\n"
        "taint.SessionTaintPolicy.check = noisy\n"
        "from sdk.hooks.claude_code import main\n"
        "raise SystemExit(main(sys.argv[1:]))\n"
    )

    def run(tool: str, **args: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", wrapper, "--config", str(hook.config), "pre-tool-use"],
            input=json.dumps(payload("PreToolUse", tool, args)),
            cwd=ROOT,
            capture_output=True,
            text=True,
            env=hook.env,
            timeout=60,
        )

    first = run("mcp__github__get_issue", number=1)
    assert first.stdout == "" and "noise from a policy" in first.stderr
    held = run("mcp__github__create_issue", owner="acme")
    assert "noise" not in held.stdout
    asked(held)


# -- after the call ---------------------------------------------------------------


def test_a_read_noted_after_the_call_taints_even_if_the_first_hook_never_ran(tmp_path):
    hook = Hook(tmp_path)
    silent(hook.post("mcp__github__get_issue", {"title": "hello"}, number=1))
    asked(hook.pre("mcp__github__create_issue", owner="acme"))


def test_bash_output_is_masked_in_place_and_keeps_its_shape(tmp_path):
    response = {
        "stdout": f"AWS_KEY={AWS}\nok",
        "stderr": "",
        "interrupted": False,
        "isImage": False,
    }
    proc = Hook(tmp_path).post("Bash", response, command="cat .env")
    assert proc.returncode == 0, proc.stderr
    updated = json.loads(proc.stdout)["hookSpecificOutput"]
    assert updated["hookEventName"] == "PostToolUse"
    out = updated["updatedToolOutput"]
    assert set(out) == set(response) and out["interrupted"] is False and out["isImage"] is False
    assert AWS not in out["stdout"] and out["stdout"].endswith("\nok")


def test_read_output_is_masked_in_the_file_content_only(tmp_path):
    response = {
        "type": "text",
        "file": {"filePath": "/p/.env", "content": f"KEY={AWS}", "numLines": 1, "startLine": 1},
    }
    out = json.loads(Hook(tmp_path).post("Read", response, file_path="/p/.env").stdout)
    file = out["hookSpecificOutput"]["updatedToolOutput"]["file"]
    assert AWS not in file["content"] and file["filePath"] == "/p/.env" and file["numLines"] == 1


def test_mcp_output_is_masked_wherever_the_text_is(tmp_path):
    response = [{"type": "text", "text": f"deploy key {AWS}"}, {"type": "text", "text": "clean"}]
    out = json.loads(Hook(tmp_path).post("mcp__github__get_file", response).stdout)
    blocks = out["hookSpecificOutput"]["updatedToolOutput"]
    assert len(blocks) == 2 and AWS not in blocks[0]["text"] and blocks[1]["text"] == "clean"


def test_clean_output_or_an_uncovered_tool_is_left_alone(tmp_path):
    hook = Hook(tmp_path)
    silent(hook.post("Bash", {"stdout": "all clean", "stderr": ""}, command="ls"))
    silent(hook.post("WebFetch", f"page with {AWS}", url="x"))  # not in redact.tools here


# -- the record -------------------------------------------------------------------


def test_every_decision_is_one_line_and_no_line_holds_a_secret(tmp_path):
    hook = Hook(tmp_path)
    hook.pre("mcp__github__get_issue", number=1)
    hook.pre("mcp__github__create_issue", owner="acme", body=f"key {AWS}")
    hook.pre("mcp__github__create_issue", owner="evil")
    hook.post("Bash", {"stdout": AWS, "stderr": ""}, command="env")
    lines = hook.audit()
    assert [line["verdict"] for line in lines] == ["none", "ask", "deny", "redacted"]
    assert lines[1]["policy"] == "session_taint" and lines[1]["tainted_by"] == [
        "mcp__github__get_issue"
    ]
    assert lines[2]["policy"] == "tool_firewall" and lines[3]["labels"] == ["aws_access_key"]
    assert AWS not in (hook.state / "claude-code" / "audit.jsonl").read_text()
    assert all(len(line["args_sha256"]) == 64 and "args" not in line for line in lines)


def test_arguments_are_recorded_only_when_asked_and_then_masked(tmp_path):
    hook = Hook(tmp_path, {**CONFIG, "audit": {"include_args": True}})
    hook.pre("mcp__github__create_issue", owner="acme", body=f"key {AWS}")
    (line,) = hook.audit()
    assert line["args"]["owner"] == "acme" and AWS not in line["args"]["body"]


# -- the commands around it ---------------------------------------------------------


def test_reset_forgets_one_session(tmp_path):
    hook = Hook(tmp_path)
    hook.pre("WebFetch", url="x")
    assert hook.run("reset", "", SESSION).returncode == 0
    silent(hook.pre("mcp__github__create_issue", owner="acme"))


def test_check_accepts_the_shipped_example_and_flags_a_typo(tmp_path):
    hook = Hook(tmp_path, yaml.safe_load((HOOKS / "claude_code_example.yaml").read_text()))
    proc = hook.run("check", "")
    assert proc.returncode == 0 and "warning" not in proc.stderr, proc.stderr
    typo = Hook(tmp_path, {"version": 1, "session": {"sources": ["Webfetch"], "sinks": ["mcp__x"]}})
    assert "'Webfetch' is not a Claude Code tool" in typo.run("check", "").stderr


def test_the_example_settings_send_every_configured_tool_to_the_hook():
    """A tool the matcher misses never reaches the hook, and nobody is told."""
    settings = json.loads((HOOKS / "settings_example.json").read_text())["hooks"]
    pre = re.compile(settings["PreToolUse"][0]["matcher"])
    post = re.compile(settings["PostToolUse"][0]["matcher"])
    config = yaml.safe_load((HOOKS / "claude_code_example.yaml").read_text())
    names = set(config["firewall"]["rules"]) | set(config["session"]["sources"])
    names |= set(config["session"]["sinks"])
    for name in names:
        example = name.rstrip("*") + ("tool" if name.endswith("*") else "")
        assert pre.search(example), f"PreToolUse never sees {name}"
    for name in config["redact"]["tools"] + config["session"]["sources"]:
        example = name.rstrip("*") + ("tool" if name.endswith("*") else "")
        assert post.search(example), f"PostToolUse never sees {name}"
    for event in settings.values():
        command = event[0]["hooks"][0]["command"]
        assert "openscript-hook" in command
    assert settings["PreToolUse"][0]["hooks"][0]["command"].endswith("|| exit 2")


def test_the_hook_modules_import_nothing_that_reaches_the_network():
    sys.path.insert(0, str(ROOT / "tools"))
    from policy_audit import NETWORK_MARKERS

    for path in HOOKS.glob("*.py"):
        tree = ast.parse(path.read_text())
        imported = {
            (node.module or "") if isinstance(node, ast.ImportFrom) else alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import | ast.ImportFrom)
            for alias in node.names
        }
        roots = {name.split(".")[0] for name in imported}
        assert not roots & set(NETWORK_MARKERS), (path.name, roots & set(NETWORK_MARKERS))


def test_the_console_script_points_at_main():
    try:
        (entry,) = [
            e for e in metadata.entry_points(group="console_scripts") if e.name == "openscript-hook"
        ]
    except ValueError:
        pytest.skip("the package is not installed with its entry points here")
    assert entry.value == "sdk.hooks.claude_code:main"


# -- the validated config, kept between calls ------------------------------------------


def _cache(hook: Hook) -> list[Path]:
    return sorted((hook.state / "claude-code" / "config-cache").glob("*.json"))


def test_a_changed_config_takes_effect_on_the_next_call(tmp_path):
    hook = Hook(tmp_path)
    silent(hook.pre("WebFetch", url="x"))
    asked(hook.pre("mcp__github__create_issue", owner="acme"))
    assert len(_cache(hook)) == 1
    loosened = {**CONFIG, "session": {**CONFIG["session"], "sinks": ["mcp__github__merge_*"]}}
    hook.config.write_text(yaml.safe_dump(loosened))
    silent(hook.pre("mcp__github__create_issue", owner="acme"))
    assert len(_cache(hook)) == 2, "a new config is a new key, not an edit of the old one"


def test_a_changed_rules_file_takes_effect_on_the_next_call(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(yaml.safe_dump({"rules": {"mcp__x__send": {"deny": True}}}))
    hook = Hook(tmp_path, {"version": 1, "firewall": {"rules_path": "rules.yaml"}})
    blocked(hook.pre("mcp__x__send", to="a"))
    rules.write_text(yaml.safe_dump({"rules": {"mcp__x__send": {"requires_approval": True}}}))
    asked(hook.pre("mcp__x__send", to="a"))


def test_a_cache_entry_it_cannot_read_is_validated_again(tmp_path):
    hook = Hook(tmp_path)
    hook.pre("mcp__github__get_issue", number=1)
    (entry,) = _cache(hook)
    entry.write_text("{not json")
    asked(hook.pre("mcp__github__create_issue", owner="acme"))
    entry.write_text(json.dumps({"format": 2, "settings": {"role": None}, "depends_on": {}}))
    asked(hook.pre("mcp__github__create_issue", owner="acme"))


def test_with_the_config_cached_a_post_call_imports_no_pydantic(tmp_path):
    """The point of the cache: the call made after every tool stays cheap."""
    hook = Hook(tmp_path)
    hook.post("Bash", {"stdout": "x", "stderr": ""}, command="ls")  # validates and caches
    probe = (
        "import sys\n"
        "from sdk.hooks.claude_code import main\n"
        "code = main(sys.argv[1:])\n"
        "sys.stderr.write('PYDANTIC=%s\\n' % ('pydantic' in sys.modules))\n"
        "raise SystemExit(code)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe, "--config", str(hook.config), "post-tool-use"],
        input=json.dumps(
            payload(
                "PostToolUse", "Bash", {"command": "env"}, response={"stdout": AWS, "stderr": ""}
            )
        ),
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=hook.env,
        timeout=60,
    )
    assert proc.returncode == 0 and AWS not in proc.stdout, proc.stderr
    assert "PYDANTIC=False" in proc.stderr


def test_a_call_to_a_known_destination_runs_unasked_after_a_read(tmp_path):
    config = {
        **CONFIG,
        "session": {
            **CONFIG["session"],
            "known": {"mcp__github__create_issue": {"owner": ["acme"]}},
        },
        "firewall": {"rules": {"mcp__github__merge_pull_request": {"requires_approval": True}}},
    }
    hook = Hook(tmp_path, config)
    silent(hook.pre("mcp__github__get_issue", number=1))
    silent(hook.pre("mcp__github__create_issue", owner="acme", title="x"))
    assert "review" in asked(hook.pre("mcp__github__merge_pull_request", number=2))
    reason = asked(hook.pre("mcp__github__create_issue", owner="stranger", title="x"))
    assert "mcp__github__get_issue" in reason


# -- payloads recorded from a real Claude Code session -----------------------------------

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "claude_code"
DOGFOOD = {
    "version": 1,
    "firewall": {"rules": {"mcp__issues__post_comment": {"args": {"issue": {"one_of": [1, 2]}}}}},
    "session": {
        "sources": ["WebFetch", "WebSearch", "mcp__issues__read_issue"],
        "sinks": ["mcp__issues__post_comment"],
    },
    "redact": {"secrets": True, "tools": ["Bash", "Read", "mcp__*"]},
}


def test_a_recorded_claude_code_session_replays_as_it_happened(tmp_path):
    """The payloads Claude Code 2.1.292 sent during the dogfood session, scrubbed,
    replayed in order with the config that session used."""
    hook = Hook(tmp_path, DOGFOOD)
    outcomes = {}
    for path in sorted(FIXTURES.glob("*.json")):
        event = json.loads(path.read_text())
        command = "pre-tool-use" if event["hook_event_name"] == "PreToolUse" else "post-tool-use"
        outcomes[path.stem] = hook.run(command, path.read_text())

    silent(outcomes["01_PreToolUse_mcp_post_comment"])  # nothing read yet
    silent(outcomes["03_PreToolUse_mcp_read_issue"])
    assert "mcp__issues__read_issue" in asked(outcomes["05_PreToolUse_mcp_post_comment"])
    assert "not one of the permitted" in blocked(outcomes["07_PreToolUse_mcp_post_comment"])

    bash = json.loads(outcomes["09_PostToolUse_Bash"].stdout)["hookSpecificOutput"]
    original = json.loads((FIXTURES / "09_PostToolUse_Bash.json").read_text())["tool_response"]
    assert set(bash["updatedToolOutput"]) == set(original), "every field kept, noOutputExpected too"
    assert "AKIA**********" in bash["updatedToolOutput"]["stdout"] and AWS not in json.dumps(bash)
    assert "masked" in bash["additionalContext"]

    read = json.loads(outcomes["11_PostToolUse_Read"].stdout)["hookSpecificOutput"]
    assert AWS not in read["updatedToolOutput"]["file"]["content"]
    assert read["updatedToolOutput"]["file"]["numLines"] == original_lines(11)
    for quiet in ("02_PostToolUse_mcp_post_comment", "04_PostToolUse_mcp_read_issue"):
        silent(outcomes[quiet])


def original_lines(n: int) -> int:
    path = next(FIXTURES.glob(f"{n:02d}_*.json"))
    return int(json.loads(path.read_text())["tool_response"]["file"]["numLines"])
