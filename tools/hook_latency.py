"""How long openscript-hook takes per call, against a budget fixed before it was measured.

    .venv/bin/python tools/hook_latency.py            # 50 runs per event
    .venv/bin/python tools/hook_latency.py --runs 200

Claude Code waits for a PreToolUse hook before every matching call, so this is
time added to the agent's turn. The budget, median 200 ms and p95 300 ms per
call, was written down before the first measurement and does not move to fit
one. Each run is a fresh process, as Claude Code starts it, using the
installed console script (or `python -m` if there is none). Exits 1 when over
budget.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "sdk" / "hooks" / "claude_code_example.yaml"
BUDGET_MEDIAN_MS, BUDGET_P95_MS = 200.0, 300.0
SESSION = "3f2b9c1e-7d4a-4b8e-9a51-0c6d2e8f4b17"


def _command(event: str) -> list[str]:
    script = Path(sys.executable).with_name("openscript-hook")
    base = [str(script)] if script.exists() else [sys.executable, "-m", "sdk.hooks.claude_code"]
    return [*base, "--config", str(CONFIG), event]


def _payload(event: str) -> str:
    """The heaviest ordinary path: a held write in a tainted session, and a
    Bash output with a secret to mask."""
    if event == "pre-tool-use":
        body = {"tool_name": "mcp__github__create_issue", "tool_input": {"owner": "your-org"}}
    else:
        body = {
            "tool_name": "Bash",
            "tool_input": {"command": "cat .env"},
            "tool_response": {"stdout": "KEY=AKIAIOSFODNN7EXAMPLE\n" * 50, "stderr": ""},
        }
    return json.dumps({"session_id": SESSION, "hook_event_name": event, **body})


def measure(event: str, runs: int, env: dict[str, str]) -> list[float]:
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        proc = subprocess.run(
            _command(event), input=_payload(event), capture_output=True, text=True, env=env
        )
        times.append((time.perf_counter() - start) * 1000)
        if proc.returncode not in (0, 2):
            raise SystemExit(f"{event} failed: {proc.stderr}")
    return times


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--runs", type=int, default=50)
    args = parser.parse_args()
    state = tempfile.mkdtemp(prefix="openscript-latency-")
    env = {**os.environ, "OPENSCRIPT_STATE_DIR": state}
    env.pop("OPENSCRIPT_HOOK_CONFIG", None)
    try:
        # Taint the session first, so pre-tool-use takes the held path.
        subprocess.run(
            _command("pre-tool-use"),
            input=json.dumps(
                {"session_id": SESSION, "tool_name": "WebFetch", "tool_input": {"url": "x"}}
            ),
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        over = False
        for event in ("pre-tool-use", "post-tool-use"):
            times = sorted(measure(event, args.runs, env))
            median = statistics.median(times)
            p95 = times[max(0, round(0.95 * len(times)) - 1)]
            fits = median <= BUDGET_MEDIAN_MS and p95 <= BUDGET_P95_MS
            over |= not fits
            print(
                f"{event:14} median {median:6.1f} ms  p95 {p95:6.1f} ms  "
                f"(budget {BUDGET_MEDIAN_MS:.0f} / {BUDGET_P95_MS:.0f})  {'ok' if fits else 'OVER'}"
            )
        return 1 if over else 0
    finally:
        shutil.rmtree(state, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
