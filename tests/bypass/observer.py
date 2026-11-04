"""An observer the policies do not own: who reached the sink's host, and how.

Two independent witnesses, because a test that trusts the code it tests
proves little:

- **The sink counts its own hits.** It is a real HTTP server on 127.0.0.1.
  A hit is counted whatever sent it.
- **An audit hook sees the interpreter's own events** (PEP 578). It records
  every socket.connect to the sink's port, and every subprocess.Popen whose
  arguments name it. It notes whether each came from inside the gated
  tool's own body. The gated tool marks that itself; no policy can.

Audit hooks cannot be removed, so one is installed for the process and
reports to whichever Observer is active.
"""

from __future__ import annotations

import contextvars
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

#: Set only inside the gated tool's own body.
IN_GATED_TOOL: contextvars.ContextVar[bool] = contextvars.ContextVar("in_gated", default=False)


@dataclass
class Observer:
    port: int
    #: (event, inside the gated tool) for every event that touched the sink.
    events: list[tuple[str, bool]] = field(default_factory=list)

    def outside_the_gated_tool(self) -> list[str]:
        return [event for event, inside in self.events if not inside]


_active: list[Observer] = []
_installed = False


def _hook(event: str, args: tuple[Any, ...]) -> None:
    if not _active:
        return
    observer = _active[-1]
    port = observer.port
    if event == "socket.connect":
        address = args[1] if len(args) > 1 else None
        if isinstance(address, tuple) and len(address) >= 2 and address[1] == port:
            observer.events.append(
                (f"socket.connect {address[0]}:{address[1]}", IN_GATED_TOOL.get())
            )
    elif event == "subprocess.Popen":
        text = " ".join(str(a) for a in args)
        if f":{port}" in text:
            observer.events.append((f"subprocess.Popen {text[:120]}", IN_GATED_TOOL.get()))


@contextmanager
def observing(port: int) -> Iterator[Observer]:
    global _installed
    if not _installed:
        sys.addaudithook(_hook)
        _installed = True
    observer = Observer(port)
    _active.append(observer)
    try:
        yield observer
    finally:
        _active.remove(observer)


class Sink:
    """The service an irreversible call reaches: it counts every hit.

    With a *ledger* it is also the effect side of evals/ledger.py: a hit is
    applied only with a valid token in its ``token`` query parameter.
    """

    def __init__(self, ledger: Any = None) -> None:
        self.hits: list[str] = []
        self.applied: list[str] = []
        self._ledger = ledger
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _hit(self) -> None:
                sink.hits.append(self.path)
                path, _, query = self.path.partition("?")
                token = dict(p.split("=", 1) for p in query.split("&") if "=" in p).get("token")
                if (
                    sink._ledger is None
                    or sink._ledger.check("send", {"path": path}, token).applied
                ):
                    sink.applied.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _hit
            do_POST = _hit

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
