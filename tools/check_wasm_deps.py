"""Step 1: does anything OpenScript imports contain a C extension that
Pyodide cannot supply?

Downloads the package's runtime dependencies, inspects every wheel for
.so/.pyd/.dll/.dylib members, and cross-references each one against the Pyodide
distribution's own package list. A dependency with a C extension is fine *only*
if Pyodide ships a prebuilt WASM wheel for it.

    python tools/check_wasm_deps.py
    python tools/check_wasm_deps.py --pyodide 0.28.3

Exit 0 = every dependency is either pure-Python or covered by Pyodide.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

PYODIDE_VERSION = "0.28.3"
LOCK_URL = "https://cdn.jsdelivr.net/pyodide/v{v}/full/pyodide-lock.json"
BINARY_SUFFIXES = (".so", ".pyd", ".dll", ".dylib")

# Runtime deps of `import sdk` — must match [project].dependencies in pyproject.toml.
RUNTIME_DEPS = ["pydantic", "structlog", "pyyaml"]


def fetch_lock(version: str) -> dict:
    with urllib.request.urlopen(LOCK_URL.format(v=version), timeout=60) as fh:
        return json.load(fh)


def pip_python() -> str:
    """An interpreter that actually has pip. uv-created venvs do not ship one."""
    for candidate in (sys.executable, "/usr/bin/python3", "python3"):
        exe = shutil.which(candidate) if not Path(candidate).is_absolute() else candidate
        if not exe or not Path(exe).exists():
            continue
        probe = subprocess.run([exe, "-m", "pip", "--version"], capture_output=True, text=True)
        if probe.returncode == 0:
            return exe
    raise SystemExit(
        f"no pip available. Install one into {sys.executable} "
        "(python -m ensurepip) or onto PATH."
    )


def download(deps: list[str], dest: Path) -> list[Path]:
    subprocess.run(
        [pip_python(), "-m", "pip", "download", "--quiet", "--dest", str(dest), *deps],
        check=True,
    )
    return sorted(dest.glob("*.whl"))


def binary_members(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as zf:
        return [n for n in zf.namelist() if n.endswith(BINARY_SUFFIXES)]


def normalize(name: str) -> str:
    return name.lower().replace("_", "-")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pyodide", default=PYODIDE_VERSION)
    args = ap.parse_args()

    lock = fetch_lock(args.pyodide)
    info, shipped = lock["info"], lock["packages"]
    print(f"Pyodide {args.pyodide} — Python {info['python']}, abi {info['abi_version']}\n")

    tmp = Path(tempfile.mkdtemp(prefix="wasm-audit-"))
    try:
        wheels = download(RUNTIME_DEPS, tmp)
        print(f"{'wheel':<52} {'C ext':<7} {'Pyodide has':<22} verdict")
        print("-" * 100)
        failures = []
        for wheel in wheels:
            dist = normalize(wheel.name.split("-")[0])
            bins = binary_members(wheel)
            entry = shipped.get(dist)
            have = entry["version"] if entry else "—"
            if not bins:
                verdict = "OK (pure python)"
            elif entry:
                verdict = "OK (pyodide wheel)"
            else:
                verdict = "BLOCKER"
                failures.append(dist)
            print(f"{wheel.name[:51]:<52} {('yes' if bins else 'no'):<7} {have:<22} {verdict}")

        print()
        if failures:
            print(f"BLOCKER: {failures} ship C extensions with no Pyodide wheel.")
            print("Swap for a pure-Python equivalent, or drop the policy that needs it.")
            return 1
        print("No C-extension blockers. Every runtime dependency runs under Pyodide.")

        # The version-floor trap: a pin Pyodide's bundled version cannot satisfy
        # sends micropip to PyPI, where no WASM wheel exists for most versions.
        print("\nVersion floors to keep compatible with this Pyodide:")
        for dep in RUNTIME_DEPS:
            entry = shipped.get(normalize(dep))
            if entry:
                print(f"  {dep:<12} pyodide ships {entry['version']} — your floor must be <= that")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
