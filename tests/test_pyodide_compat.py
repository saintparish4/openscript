"""The built wheel must be installable and importable under Pyodide.

These tests catch the two failures that broke the browser build the first time:

  1. `include = ["sdk", ...]` shipped a wheel containing only sdk/__init__.py and
     sdk/logging.py — every policy subpackage was missing. Invisible locally,
     because pytest runs from the repo root with pythonpath = ["."].
  2. `pydantic>=2.12` cannot be satisfied in the browser: Pyodide 0.28.3 bundles
     2.10.6, and no pydantic-core between 2.28 and 2.46 publishes a WASM wheel.
     micropip fails the install outright.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # py3.10
    tomllib = None

REPO_ROOT = Path(__file__).resolve().parent.parent
PYODIDE_VERSION = "0.28.3"
LOCK_URL = f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE_VERSION}/full/pyodide-lock.json"

# Every module the browser demo imports, relative to the wheel root.
REQUIRED_WHEEL_MEMBERS = [
    "sdk/__init__.py",
    "sdk/logging.py",
    "sdk/interceptors/pii.py",
    "sdk/interceptors/threat.py",
    "sdk/interceptors/event_writer.py",
    "sdk/interceptors/base.py",
    "sdk/policies/secrets.py",
    "sdk/policies/toxicity.py",
    "sdk/policies/harmful_request.py",
    "sdk/policies/compliance.py",
    "sdk/policies/tool_firewall.py",
    "sdk/policies/output_schema.py",
    "sdk/policies/config.py",
    "sdk/middleware/middleware.py",
    "sdk/observability/risk.py",
    "sdk/integrations/langchain.py",
    "contracts/types.py",
    "contracts/interceptor.py",
    "contracts/server_types.py",
    "events/writer.py",
    "events/approvals.py",
]


# Generated trees that must not be copied into the isolated build. `build/` is
# the important one: setuptools reuses a stale build/lib, so building in place
# can produce a wheel that reflects a PREVIOUS pyproject.toml. That silently
# defeats test_wheel_contains_every_policy_module — verified.
_BUILD_EXCLUDES = shutil.ignore_patterns(
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "build",
    "dist",
    "*.egg-info",
    "__pycache__",
    ".pytest_cache",
    ".benchmarks",
    "wheels",
)


@pytest.fixture(scope="session")
def wheel(tmp_path_factory) -> Path:
    """Build the wheel from a pristine copy of the source tree.

    Building in REPO_ROOT would let a leftover build/lib/ satisfy these
    assertions with files the current pyproject.toml no longer ships.
    """
    src = tmp_path_factory.mktemp("src") / "openscript"
    shutil.copytree(REPO_ROOT, src, ignore=_BUILD_EXCLUDES)

    out = tmp_path_factory.mktemp("wheel")
    proc = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(out)],
        cwd=src,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"wheel build failed:\n{proc.stdout}\n{proc.stderr}"
    built = list(out.glob("*.whl"))
    assert len(built) == 1, built
    return built[0]


@pytest.fixture(scope="session")
def pyodide_lock() -> dict:
    try:
        with urllib.request.urlopen(LOCK_URL, timeout=60) as fh:
            return json.load(fh)
    except (urllib.error.URLError, TimeoutError) as exc:
        pytest.skip(f"cannot reach the Pyodide CDN: {exc}")


def test_wheel_contains_every_policy_module(wheel: Path):
    with zipfile.ZipFile(wheel) as zf:
        names = set(zf.namelist())
    missing = [m for m in REQUIRED_WHEEL_MEMBERS if m not in names]
    assert not missing, (
        f"{len(missing)} modules missing from {wheel.name}: {missing}\n"
        "Check [tool.setuptools.packages.find].include — bare 'sdk' does not "
        "match sdk.policies / sdk.interceptors / sdk.middleware. Use 'sdk*'."
    )


def test_wheel_is_pure_python(wheel: Path):
    with zipfile.ZipFile(wheel) as zf:
        binaries = [n for n in zf.namelist() if n.endswith((".so", ".pyd", ".dll", ".dylib"))]
    assert not binaries, f"wheel ships compiled artifacts Pyodide cannot load: {binaries}"
    assert wheel.name.endswith("-py3-none-any.whl"), f"not a universal wheel: {wheel.name}"


@pytest.mark.skipif(tomllib is None, reason="needs python>=3.11 for tomllib")
def test_dependency_floors_are_satisfiable_by_pyodide(pyodide_lock: dict):
    from packaging.requirements import Requirement

    deps = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    shipped = pyodide_lock["packages"]

    problems = []
    for raw in deps:
        req = Requirement(raw)
        entry = shipped.get(req.name.lower().replace("_", "-"))
        if entry is None:
            continue  # pure-python, micropip pulls it from PyPI
        if not req.specifier.contains(entry["version"], prereleases=True):
            problems.append(
                f"{raw!r} excludes the {entry['version']} that Pyodide {PYODIDE_VERSION} bundles"
            )
    assert (
        not problems
    ), "micropip will try to upgrade from PyPI and fail (no WASM wheel exists):\n  " + "\n  ".join(
        problems
    )


def test_no_runtime_dependency_needs_a_missing_wasm_wheel(wheel: Path, pyodide_lock: dict):
    """Any Requires-Dist with a C extension must be one Pyodide already ships."""
    from packaging.requirements import Requirement

    with zipfile.ZipFile(wheel) as zf:
        meta = next(n for n in zf.namelist() if n.endswith(".dist-info/METADATA"))
        lines = zf.read(meta).decode().splitlines()

    required = [
        Requirement(line.split(":", 1)[1].strip())
        for line in lines
        if line.startswith("Requires-Dist:")
    ]
    # extras are opt-in and never installed in the browser
    core = [r for r in required if not r.marker or "extra" not in str(r.marker)]

    known_pure = {"structlog"}
    unavailable = [
        r.name
        for r in core
        if r.name.lower().replace("_", "-") not in pyodide_lock["packages"]
        and r.name.lower() not in known_pure
    ]
    assert not unavailable, (
        f"{unavailable} are neither bundled by Pyodide nor known-pure; "
        "verify a py3-none-any wheel exists on PyPI before shipping"
    )
