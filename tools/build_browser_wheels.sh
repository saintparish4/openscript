#!/usr/bin/env bash
# Build the OpenScript wheel and vendor its one pure-Python runtime dependency
# into web/wheels/, so the demo page never touches PyPI at runtime.
#
# pydantic, pyyaml, annotated-types and typing-extensions are NOT vendored:
# Pyodide bundles them and micropip resolves them from the Pyodide distribution.
set -euo pipefail

PYTHON="${PYTHON:-.venv/bin/python}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/web/wheels"

rm -rf "$OUT"
mkdir -p "$OUT"

echo "==> building openscript wheel"
"$PYTHON" -m build --wheel --outdir "$OUT" "$ROOT" >/dev/null

echo "==> vendoring structlog"
# structlog is py3-none-any, so any interpreter's pip fetches the same wheel.
# uv-created venvs ship no pip, so fall back to a system one before bootstrapping.
PIP_PYTHON=""
for candidate in "$PYTHON" /usr/bin/python3 python3; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -m pip --version >/dev/null 2>&1; then
    PIP_PYTHON="$candidate"
    break
  fi
done
if [ -z "$PIP_PYTHON" ]; then
  echo "    no pip found; bootstrapping one into $PYTHON via ensurepip"
  "$PYTHON" -m ensurepip --default-pip >/dev/null
  PIP_PYTHON="$PYTHON"
fi
"$PIP_PYTHON" -m pip download --quiet --only-binary=:all: --no-deps --dest "$OUT" "structlog>=25.5.0"

echo "==> writing manifest"
"$PYTHON" - "$OUT" <<'PY'
import json, sys
from pathlib import Path

out = Path(sys.argv[1])
manifest = {}
for whl in out.glob("*.whl"):
    dist = whl.name.split("-")[0].replace("_", "-").lower()
    manifest[dist] = f"./wheels/{whl.name}"

missing = {"openscript", "structlog"} - set(manifest)
if missing:
    raise SystemExit(f"missing wheels: {sorted(missing)}")

(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest, indent=2))
PY
