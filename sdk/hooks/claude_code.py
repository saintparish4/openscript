"""openscript-hook: OpenScript's tool policies as a Claude Code hook.

Claude Code's own permissions say which tools may run. This adds what they do
not: rules on a call's arguments (ToolFirewallPolicy), a memory of what the
session has read (SessionTaintPolicy), secrets masked in a tool's output
before the model reads it, and a record of every decision.

    openscript-hook pre-tool-use      # PreToolUse: deny, ask, or say nothing
    openscript-hook post-tool-use     # PostToolUse: note a read, redact the output
    openscript-hook check             # is the config valid, and what will it do
    openscript-hook prune [--days N]  # forget sessions not seen for N days
    openscript-hook reset SESSION_ID  # forget what one session has read

It only ever tightens. On a call it answers "deny" (exit 2, the reason on
stderr, which Claude sees) or "ask" (Claude Code shows its own prompt, with
OpenScript's reason), or nothing, and Claude Code's permissions decide as they
always would. It never answers "allow": that would skip Claude Code's prompt
and override the user's own settings.

It fails closed. Anything that goes wrong while deciding on a call, a missing
config included, blocks the call with the reason. Run it as
``openscript-hook pre-tool-use || exit 2`` so that a hook that cannot start
blocks too, until Claude Code's ``onFailure: "block"`` is available.

The config is ``--config``, else $OPENSCRIPT_HOOK_CONFIG, else
$CLAUDE_PROJECT_DIR/.claude/openscript.yaml. State and the audit log live in
$OPENSCRIPT_STATE_DIR (default ~/.local/state/openscript/claude-code).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

#: Say which product spoke, in Claude Code's prompt and in Claude's context.
PREFIX = "OpenScript: "


def main(argv: list[str] | None = None) -> int:
    # stdout carries the decision and nothing else: Claude Code ignores a
    # decision with anything printed around it. Keep the real stdout for the
    # decision and point fd 1 at stderr, so a library that prints (structlog
    # does, until configured) cannot spoil it.
    sys.stdout.flush()
    decision = os.fdopen(os.dup(1), "w", encoding="utf-8")
    os.dup2(2, 1)
    logging.disable(logging.CRITICAL)

    parser = argparse.ArgumentParser(prog="openscript-hook", description=__doc__.split("\n")[0])
    parser.add_argument("--config", type=Path, help="the YAML config (see the module docstring)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("pre-tool-use", help="decide on a call (PreToolUse)")
    commands.add_parser("post-tool-use", help="note a read, redact output (PostToolUse)")
    commands.add_parser("check", help="validate the config and say what it will do")
    prune_parser = commands.add_parser("prune", help="forget sessions not seen for a while")
    prune_parser.add_argument("--days", type=float, default=7.0)
    reset_parser = commands.add_parser("reset", help="forget what one session has read")
    reset_parser.add_argument("session_id")
    args = parser.parse_args(argv)

    if args.command == "pre-tool-use":
        try:
            return _pre_tool_use(_payload(), args.config, decision)
        except Exception as error:  # fail closed: no verdict is a refusal
            return _block(f"the hook could not decide, so the call is blocked: {error}")
    if args.command == "post-tool-use":
        try:
            return _post_tool_use(_payload(), args.config, decision)
        except Exception as error:  # the tool has run; say so and let it be
            sys.stderr.write(f"{PREFIX}the hook could not check this output: {error}\n")
            return 1
    if args.command == "check":
        return _check(args.config)
    if args.command == "prune":
        from sdk.policies.taint_store import prune

        removed = prune(_state() / "sessions", older_than=args.days * 86400)
        sys.stderr.write(f"removed {removed} session(s) not seen for {args.days:g} days\n")
        return 0
    from sdk.policies.taint_store import FileTaintStore

    FileTaintStore(_state() / "sessions").clear(args.session_id)
    return 0


# -- the two hooks ------------------------------------------------------------


def _pre_tool_use(payload: dict[str, Any], config_path: Path | None, out: IO[str]) -> int:
    from sdk.hooks.config import load_config
    from sdk.policies.tool_firewall import validate_tool_call

    name, args, session_id = _call(payload)
    config, rules = load_config(_config_path(config_path, payload))
    asks: list[tuple[str, str]] = []

    if rules is not None:
        verdict = validate_tool_call({"name": name, "args": args}, role=config.role, rules=rules)
        if not verdict["allowed"]:
            _audit(config, payload, "deny", "tool_firewall", verdict["reason"])
            return _block(f"the tool rules refuse this call: {verdict['reason']}")
        if verdict["requires_approval"]:
            asks.append(("tool_firewall", verdict["reason"]))

    tainted_by: list[str] = []
    if config.session is not None:
        session = _session_policy(config)
        entry = session.check(session_id, name)
        tainted_by = entry["tainted_by"]
        if not entry["allowed"]:
            _audit(config, payload, "deny", "session_taint", entry["reason"], tainted_by)
            return _block(entry["reason"])
        if entry["requires_approval"]:
            asks.append(("session_taint", entry["reason"]))
        # Taint when a source is attempted rather than when it returns: a
        # PostToolUse hook that never runs must not leave the session clean.
        # The cost is a declined read that still taints.
        session.record(session_id, name)

    if not asks:
        _audit(config, payload, "none", "", "no policy objects", tainted_by)
        return 0
    reason = "; ".join(text for _, text in asks)
    _audit(config, payload, "ask", "+".join(p for p, _ in asks), reason, tainted_by)
    _ask(out, reason)
    return 0


def _post_tool_use(payload: dict[str, Any], config_path: Path | None, out: IO[str]) -> int:
    from sdk.hooks.config import load_config

    name, _args, session_id = _call(payload)
    config, _rules = load_config(_config_path(config_path, payload))
    if config.session is not None:
        _session_policy(config).record(session_id, name)  # again, in case PreToolUse never ran

    if not config.redact.covers(name) or "tool_response" not in payload:
        return 0
    redacted, labels = _redact_output(name, payload["tool_response"], config)
    if not labels:
        return 0
    _audit(config, payload, "redacted", "redaction", f"masked {', '.join(labels)}", labels=labels)
    out.write(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": redacted,
                }
            }
        )
    )
    out.flush()
    return 0


# -- pieces -------------------------------------------------------------------


def _payload() -> dict[str, Any]:
    payload = json.loads(sys.stdin.read())
    if not isinstance(payload, dict):
        raise ValueError("the hook input is not a JSON object")
    return payload


def _call(payload: dict[str, Any]) -> tuple[str, dict[str, Any], str]:
    name, args, session_id = (
        payload.get("tool_name"),
        payload.get("tool_input"),
        payload.get("session_id"),
    )
    if not isinstance(name, str) or not name:
        raise ValueError("the hook input names no tool")
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("the hook input has no session id")
    return name, args if isinstance(args, dict) else {}, session_id


def _config_path(given: Path | None, payload: dict[str, Any]) -> Path:
    if given is not None:
        return given
    if os.environ.get("OPENSCRIPT_HOOK_CONFIG"):
        return Path(os.environ["OPENSCRIPT_HOOK_CONFIG"])
    project = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()
    return Path(project) / ".claude" / "openscript.yaml"


def _state() -> Path:
    from sdk.policies.taint_store import state_dir

    return state_dir("claude-code")


def _session_policy(config: Any) -> Any:
    from sdk.policies.session_taint import SessionTaintPolicy
    from sdk.policies.taint_store import FileTaintStore

    return SessionTaintPolicy(
        sources=config.session.sources,
        sinks=config.session.sinks,
        on_taint=config.session.on_taint,
        store=FileTaintStore(_state() / "sessions"),
    )


def _redact_output(name: str, response: Any, config: Any) -> tuple[Any, list[str]]:
    """The tool's output with secrets masked, in the shape the tool gave it.

    Claude Code ignores a replacement for a built-in tool that does not match
    the tool's output schema, so for those only the text fields change.
    """
    from sdk.policies.redaction import redact_data

    def redact(value: Any) -> tuple[Any, list[str]]:
        return redact_data(
            value,
            secrets=config.redact.secrets,
            pii=config.redact.pii,
            internal_urls=config.redact.internal_urls,
        )

    if name == "Bash" and isinstance(response, dict):
        out, labels = dict(response), []
        for key in ("stdout", "stderr"):
            if isinstance(out.get(key), str):
                out[key], found = redact(out[key])
                labels += found
        return out, list(dict.fromkeys(labels))
    if name == "Read" and isinstance(response, dict) and isinstance(response.get("file"), dict):
        file = dict(response["file"])
        if isinstance(file.get("content"), str):
            file["content"], labels = redact(file["content"])
            return {**response, "file": file}, labels
        return response, []
    return redact(response)


def _ask(out: IO[str], reason: str) -> None:
    decision = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": PREFIX + reason,
        }
    }
    out.write(json.dumps(decision))
    out.flush()


def _block(reason: str) -> int:
    sys.stderr.write(PREFIX + reason + "\n")
    return 2


def _audit(
    config: Any,
    payload: dict[str, Any],
    verdict: str,
    policy: str,
    reason: str,
    tainted_by: list[str] | None = None,
    labels: list[str] | None = None,
) -> None:
    """One line per decision. Never the tool's output, and the arguments only
    as a digest unless asked for, and then with secrets masked."""
    from sdk.policies.redaction import redact_data
    from sdk.policies.taint_store import append_jsonl

    args = payload.get("tool_input")
    record: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "session_id": payload.get("session_id"),
        "agent_id": payload.get("agent_id"),
        "tool_use_id": payload.get("tool_use_id"),
        "hook_event": payload.get("hook_event_name"),
        "tool": payload.get("tool_name"),
        "policy": policy,
        "verdict": verdict,
        "reason": reason,
        "tainted_by": tainted_by or [],
        "labels": labels or [],
        "cwd": payload.get("cwd"),
        "args_sha256": hashlib.sha256(
            json.dumps(args, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest(),
    }
    if config.audit.include_args:
        record["args"] = redact_data(args)[0]
    path = Path(config.audit.path) if config.audit.path else _state() / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    append_jsonl(path, record)


def _check(config_path: Path | None) -> int:
    from sdk.hooks.config import ConfigError, load_config, unknown_names

    path = _config_path(config_path, {})
    try:
        config, rules = load_config(path)
    except ConfigError as error:
        sys.stderr.write(f"{error}\n")
        return 2
    lines = [f"config: {path}"]
    lines.append(
        f"tool rules for {len(rules.rules)} tool(s)"
        + (", everything else refused" if rules.default_deny else "")
        if rules is not None
        else "no tool rules"
    )
    if config.session is not None:
        lines.append(f"untrusted sources: {', '.join(config.session.sources)}")
        lines.append(
            f"held after an untrusted read ({config.session.on_taint}): "
            f"{', '.join(config.session.sinks)}"
        )
    else:
        lines.append("no session rule")
    kinds = [k for k in ("secrets", "pii", "internal_urls") if getattr(config.redact, k)]
    lines.append(
        f"redacting {', '.join(kinds)} in: {', '.join(config.redact.tools)}"
        if kinds
        else "no redaction"
    )
    lines.append(f"state and audit log: {_state()}")
    for name in unknown_names(config, rules):
        lines.append(f"warning: {name!r} is not a Claude Code tool or an MCP tool (a typo?)")
    sys.stderr.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
