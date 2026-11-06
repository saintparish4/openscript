"""The effect side: an irreversible call is applied only with a person's token.

Everything else in this repository checks a call before it leaves the agent's
process. That is only as strong as the agent's inability to go round it
(docs/threat-model.md, rows S4 and J3). This is the other end. It stands in
front of the irreversible tools, where the effect happens, and accepts a call
only with a token that a person's approval of that exact call produced. It
keeps a ledger of everything it saw, which is the evidence the replay and the
tests count. PROTOCOL-ledger.md, under evals/agentdojo, froze its design.

    ledger = Ledger(mode="enforce")
    token = ledger.mint(approval_id, record.action_hash)    # the authority, after a person's yes
    entry = ledger.check("send_money", args, token)         # the service, at the effect
    entry.applied                                           # True only for that call, once

``python -m evals.ledger serve`` runs the same thing as a separate process.
It generates its own secret and serves HTTP for the agent. A person speaks
to it on its stdin, which the agent cannot reach. ServiceProcess drives one
from a test. Standard library only, apart from the approval hash it binds to.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import IO, Any

from openscript_sdk.events.approvals import action_hash

#: Separates these MACs from any other use of the same key.
DOMAIN = b"openscript-effect:v1|"


class TokenClass(StrEnum):
    """What the service made of the token that came with a call."""

    VALID = "valid"  # it verifies, names an unspent approval, and is for this call
    NONE = "none"  # no token at all
    FORGED = "forged"  # the MAC does not verify, or names no approval the authority minted
    SPENT = "spent"  # it verified once already
    OTHER_CALL = "other_call"  # it verifies, for another call


class LedgerMode(StrEnum):
    RECORD = "record"  # apply everything, write down what the token was
    ENFORCE = "enforce"  # apply only a valid token


def call_hash(name: str, args: Mapping[str, Any]) -> str:
    """The hash of a tool call, exactly as an approval record carries it."""
    return action_hash("tool_call", {"name": name, "args": dict(args)})


@dataclass(frozen=True)
class Entry:
    """One irreversible call, as the effect side saw it."""

    tool: str
    call_hash: str
    token: TokenClass
    applied: bool
    #: Who made the call, where the caller can say: the replay knows whether
    #: a call is the task's own or the attacker's. Never used to decide.
    origin: str = ""


@dataclass
class Ledger:
    """The authority that mints tokens and the service that checks them.

    They are one object because they share one secret and one record of what
    was minted. Nothing here should be reachable by the agent but check():
    in the replay the agent is scripted and holds no reference to it, and
    across a process boundary it is ServiceProcess.
    """

    mode: LedgerMode | str = LedgerMode.ENFORCE
    _secret: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)
    _minted: dict[str, str] = field(default_factory=dict, repr=False)
    _spent: set[str] = field(default_factory=set, repr=False)
    entries: list[Entry] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self.mode = LedgerMode(self.mode)

    # -- the authority: a person said yes ---------------------------------

    def mint(self, approval_id: str, approved_hash: str) -> str:
        """A token for the one call *approved_hash* names, under *approval_id*."""
        if not approval_id or "." in approval_id:
            raise ValueError("an approval id is a non-empty string with no '.'")
        with self._lock:
            if approval_id in self._minted:
                raise ValueError(f"a token was already minted for approval {approval_id!r}")
            self._minted[approval_id] = approved_hash
        return f"{approval_id}.{self._mac(approval_id, approved_hash)}"

    # -- the service: the call arrives at the effect ----------------------

    def check(
        self, tool: str, args: Mapping[str, Any], token: str | None, origin: str = ""
    ) -> Entry:
        """Class the token, apply or refuse the call, and write it down."""
        this_call = call_hash(tool, args)
        with self._lock:
            kind = self._classify(this_call, token)
            applied = kind is TokenClass.VALID or self.mode is LedgerMode.RECORD
            if kind is TokenClass.VALID:
                self._spent.add(str(token).split(".", 1)[0])
            entry = Entry(tool, this_call, kind, applied, origin)
            self.entries.append(entry)
        return entry

    def _classify(self, this_call: str, token: str | None) -> TokenClass:
        if not token:
            return TokenClass.NONE
        approval_id, _, mac = token.partition(".")
        minted_for = self._minted.get(approval_id)
        if minted_for is None or not hmac.compare_digest(mac, self._mac(approval_id, minted_for)):
            return TokenClass.FORGED
        if approval_id in self._spent:
            return TokenClass.SPENT
        if not hmac.compare_digest(minted_for, this_call):
            return TokenClass.OTHER_CALL
        return TokenClass.VALID

    def _mac(self, approval_id: str, approved_hash: str) -> str:
        message = DOMAIN + f"{approval_id}|{approved_hash}".encode()
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()


class LedgerRefused(RuntimeError):
    """An irreversible call the effect side would not apply."""

    def __init__(self, entry: Entry) -> None:
        super().__init__(f"the effect side refused {entry.tool}: token {entry.token.value}")
        self.entry = entry


# -- the same, as a process of its own -------------------------------------------------


def serve(mode: str, stdin: IO[str], stdout: IO[str]) -> None:
    """HTTP for the agent on 127.0.0.1, and the person on stdin.

    The first line written is "port N". Then each line read from stdin is a
    person's approval, {"approve": approval_id, "hash": action_hash}, and each
    line written back is the token, {"token": ...}, or {"error": ...}.
    """
    ledger = Ledger(mode=mode)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # quiet: stdout is the person's channel
            pass

        def _send(self, status: int, body: Any) -> None:
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self) -> None:
            if self.path != "/effect":
                self._send(404, {"error": "no such endpoint"})
                return
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                entry = ledger.check(body["tool"], body["args"], body.get("token"))
            except (ValueError, KeyError, TypeError) as error:
                self._send(400, {"error": str(error)})
                return
            self._send(200 if entry.applied else 403, asdict(entry))

        def do_GET(self) -> None:
            if self.path != "/ledger":
                self._send(404, {"error": "no such endpoint"})
                return
            with ledger._lock:
                self._send(200, [asdict(e) for e in ledger.entries])

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    stdout.write(f"port {server.server_address[1]}\n")
    stdout.flush()
    for line in stdin:
        try:
            ask = json.loads(line)
            reply: dict[str, str] = {"token": ledger.mint(ask["approve"], ask["hash"])}
        except (ValueError, KeyError, TypeError) as error:
            reply = {"error": str(error)}
        stdout.write(json.dumps(reply) + "\n")
        stdout.flush()
    server.shutdown()


class ServiceProcess:
    """A ledger in a separate process, driven from a test.

    The test plays the agent: it reaches the service only over HTTP, as an
    agent would. approve() plays the person, over the process's stdin. The
    secret is generated in the child and never crosses either channel.
    """

    def __init__(self, mode: str = "enforce") -> None:
        root = Path(__file__).resolve().parents[1]
        self._proc = subprocess.Popen(
            [sys.executable, "-m", "evals.ledger", "serve", "--mode", mode],
            cwd=root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._in, self._out = self._proc.stdin, self._proc.stdout
        first = self._out.readline().split()
        if first[:1] != ["port"]:
            self.close()
            raise RuntimeError(f"the ledger service did not start: {first!r}")
        self.url = f"http://127.0.0.1:{first[1]}"

    def approve(self, approval_id: str, approved_hash: str) -> str:
        """The person's yes, over the channel only the person has."""
        self._in.write(json.dumps({"approve": approval_id, "hash": approved_hash}) + "\n")
        self._in.flush()
        reply = json.loads(self._out.readline())
        if "error" in reply:
            raise ValueError(reply["error"])
        return str(reply["token"])

    def effect(self, tool: str, args: Mapping[str, Any], token: str | None = None) -> Entry:
        """What the agent can do: ask for an effect."""
        body = json.dumps({"tool": tool, "args": dict(args), "token": token}).encode()
        request = urllib.request.Request(
            f"{self.url}/effect", data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = json.loads(response.read())
        except urllib.error.HTTPError as refused:
            raw = json.loads(refused.read())
        return Entry(raw["tool"], raw["call_hash"], TokenClass(raw["token"]), raw["applied"])

    def entries(self) -> list[dict[str, Any]]:
        with urllib.request.urlopen(f"{self.url}/ledger", timeout=10) as response:
            listed: list[dict[str, Any]] = json.loads(response.read())
        return listed

    @property
    def pid(self) -> int:
        return self._proc.pid

    def close(self) -> None:
        if self._proc.poll() is None:
            self._in.close()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._out.close()

    def __enter__(self) -> ServiceProcess:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m evals.ledger", description=__doc__.split("\n")[0]
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("serve", help="run the effect side as a process of its own")
    run.add_argument("--mode", choices=[m.value for m in LedgerMode], default="enforce")
    args = parser.parse_args(argv)
    serve(args.mode, sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
