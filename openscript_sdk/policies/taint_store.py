"""What sessions have read, kept on disk, with nothing but the standard library.

SessionTaintPolicy keeps its memory in this process by default. A host that
runs a fresh process for every tool call, as a Claude Code hook does, needs it
written down: FileTaintStore keeps one append-only file per session, one
JSON line per source that ran.

Appending a short line with a single write to a file opened O_APPEND does not
interleave with another process doing the same on a local filesystem, so
hooks running in parallel need no lock (and none is available under Pyodide).
On a network filesystem that guarantee does not hold: keep the state
directory local.

Reading fails closed. A line that cannot be read counts as a source: something
was written there, and a session that read untrusted content must not come
out of it clean because a record was damaged.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

#: What a session id may look like before it becomes part of a file name.
_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")

#: The source recorded for a line that cannot be read.
UNREADABLE = "an unreadable record"


def state_dir(name: str) -> Path:
    """Where OpenScript keeps state for *name*: $OPENSCRIPT_STATE_DIR, else
    $XDG_STATE_HOME/openscript, else ~/.local/state/openscript."""
    base = os.environ.get("OPENSCRIPT_STATE_DIR")
    if not base:
        xdg = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
        base = str(Path(xdg) / "openscript")
    return Path(base) / name


def append_jsonl(path: Path | str, record: Mapping[str, Any]) -> None:
    """Append *record* to *path* as one JSON line, in a single write.

    The file is created readable by its owner only.
    """
    line = (json.dumps(record, separators=(",", ":"), default=str) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        written = os.write(fd, line)
        while written < len(line):  # a regular file writes it all; this is belt and braces
            written += os.write(fd, line[written:])
    finally:
        os.close(fd)


class FileTaintStore:
    """A TaintStore that keeps each session's sources in ``<directory>/<session_id>.jsonl``."""

    def __init__(self, directory: Path | str) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path(self, session_id: str) -> Path:
        if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
            # It becomes a file name: nothing that could climb out of the directory.
            raise ValueError(f"not a session id this store will use as a file name: {session_id!r}")
        return self._dir / f"{session_id}.jsonl"

    def sources(self, session_id: str) -> list[str]:
        try:
            text = self._path(session_id).read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return []
        seen: list[str] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                source = json.loads(line)["source"]
                if not isinstance(source, str) or not source:
                    raise ValueError(source)
            except (ValueError, KeyError, TypeError):
                source = UNREADABLE
            if source not in seen:
                seen.append(source)
        return seen

    def add(self, session_id: str, source: str) -> None:
        append_jsonl(self._path(session_id), {"source": source, "at": time.time()})

    def clear(self, session_id: str) -> None:
        self._path(session_id).unlink(missing_ok=True)


def prune(directory: Path | str, older_than: float) -> int:
    """Remove session files not written to for *older_than* seconds. Returns how many."""
    cutoff = time.time() - older_than
    removed = 0
    for path in Path(directory).glob("*.jsonl"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except FileNotFoundError:
            continue  # another process got there first
    return removed
