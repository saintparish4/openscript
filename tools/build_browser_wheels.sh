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

# The demo app serves the same wheels from its own public/ directory. Mirroring
# rather than rebuilding keeps the probe and the page on identical bytes.
#
# site/public/wheels/ is committed, and a wheel is a zip: two builds of
# identical source differ in their member timestamps. Copying unconditionally
# would put a meaningless 80 KB diff in front of every commit, so a wheel whose
# modules already match is left where it is.
SITE_OUT="$ROOT/site/public/wheels"
if [ -d "$ROOT/site/public" ]; then
  echo "==> mirroring into site/public/wheels"
  mkdir -p "$SITE_OUT"
  "$PYTHON" - "$OUT" "$SITE_OUT" <<'MIRROR'
import shutil, sys, zipfile
from pathlib import Path

built, mirrored = Path(sys.argv[1]), Path(sys.argv[2])


def modules(path):
    with zipfile.ZipFile(path) as zf:
        return {n: zf.read(n) for n in sorted(zf.namelist()) if n.endswith(".py")}


names = {p.name for p in built.iterdir()}
for stale in mirrored.iterdir():
    if stale.name not in names:
        stale.unlink()

for source in built.iterdir():
    target = mirrored / source.name
    if source.suffix == ".whl" and target.exists() and modules(source) == modules(target):
        print(f"    {source.name} unchanged")
        continue
    shutil.copy2(source, target)
    print(f"    {source.name} updated")
MIRROR
fi
