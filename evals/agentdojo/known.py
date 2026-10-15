"""Known destinations for each AgentDojo suite, as PROTOCOL-known.md defines them.

The rule is one sentence: a destination is known only if the user has already
sent to it, in the environment as it stands before any task runs and before
any injection is placed. This applies it to each suite's default environment
and writes known.yaml, which is frozen with the protocol.

    .venv/bin/python known.py            # writes known.yaml
    .venv/bin/python known.py --check    # fails if known.yaml is not what the rule gives

The Slack directory variant is not the rule: it is the labelled second
configuration the protocol adds, every existing member and channel, to show
what a rule based on the directory instead of history would release.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml
from agentdojo.task_suite.load_suites import get_suites

HERE = Path(__file__).resolve().parent
BENCHMARK = "v1.2.2"


def _env(suite: str) -> Any:
    return get_suites(BENCHMARK)[suite].load_and_inject_default_environment({})


def banking() -> dict[str, dict[str, list[str]]]:
    """Accounts the user has paid, or has a scheduled payment to."""
    account = _env("banking").bank_account
    paid = {t.recipient for t in account.transactions if t.sender == "me"}
    paid |= {t.recipient for t in account.scheduled_transactions}
    paid.discard("me")
    tools = ("send_money", "schedule_transaction", "update_scheduled_transaction")
    return {tool: {"recipient": sorted(paid)} for tool in tools}


def _addresses(sent: set[str]) -> dict[str, dict[str, list[str]]]:
    if not sent:
        return {}
    known = sorted(sent)
    return {
        "send_email": {"recipients": known, "cc": known, "bcc": known},
        "create_calendar_event": {"participants": known},
        "add_calendar_event_participants": {"participants": known},
        "share_file": {"email": known},
    }


def workspace() -> dict[str, dict[str, list[str]]]:
    """Addresses the user has emailed (to, cc, bcc), or shared a file of theirs with."""
    env = _env("workspace")
    me = env.inbox.account_email
    sent: set[str] = set()
    for email in env.inbox.emails.values():
        if email.sender == me:
            sent |= set(email.recipients) | set(email.cc or []) | set(email.bcc or [])
    for file in env.cloud_drive.files.values():
        if file.owner == me:
            sent |= set(file.shared_with or {})
    sent.discard(me)
    return _addresses(sent)


def travel() -> dict[str, dict[str, list[str]]]:
    """Addresses the user has emailed. A reservation has no history to know."""
    env = _env("travel")
    me = env.user.email
    sent: set[str] = set()
    for email in env.inbox.emails.values():
        if email.sender == me:
            sent |= set(email.recipients) | set(email.cc or []) | set(email.bcc or [])
    sent.discard(me)
    known = _addresses(sent)
    # Travel's sinks do not include share_file or add_calendar_event_participants.
    return {
        tool: args
        for tool, args in known.items()
        if tool in ("send_email", "create_calendar_event")
    }


def slack() -> dict[str, dict[str, list[str]]]:
    """Members and channels the agent, which posts as "bot", has sent to."""
    env = _env("slack").slack
    users: set[str] = set()
    channels: set[str] = set()
    for messages in env.user_inbox.values():
        users |= {m.recipient for m in messages if m.sender == "bot"}
    for messages in env.channel_inbox.values():
        channels |= {m.recipient for m in messages if m.sender == "bot"}
    known: dict[str, dict[str, list[str]]] = {}
    if users:
        known["send_direct_message"] = {"recipient": sorted(users)}
    if channels:
        known["send_channel_message"] = {"channel": sorted(channels)}
    return known


def slack_directory() -> dict[str, dict[str, list[str]]]:
    """Not the rule: every existing member and channel, for the labelled variant."""
    env = _env("slack").slack
    users, channels = sorted(env.users), sorted(env.channels)
    return {
        "send_direct_message": {"recipient": users},
        "send_channel_message": {"channel": channels},
        "add_user_to_channel": {"user": users, "channel": channels},
    }


def derive() -> dict[str, Any]:
    return {
        "rule": "a destination is known only if the user has already sent to it",
        "suites": {
            "banking": banking(),
            "workspace": workspace(),
            "travel": travel(),
            "slack": slack(),
        },
        "directory": {"slack": slack_directory()},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="compare with known.yaml")
    args = parser.parse_args()
    text = yaml.safe_dump(derive(), sort_keys=True, width=100)
    path = HERE / "known.yaml"
    if args.check:
        if path.read_text() != text:
            print("known.yaml is not what the rule gives", file=sys.stderr)
            return 1
        return 0
    path.write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
