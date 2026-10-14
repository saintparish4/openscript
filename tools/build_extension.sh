#!/usr/bin/env bash
# Assemble extension/vendor/: the Pyodide runtime and every wheel the panel
# installs. Nothing is downloaded. The runtime and its packages come from
# site/node_modules/pyodide — the same pinned 0.28.3 the demo site loads from
# jsDelivr — and the project wheels from web/wheels (make browser-wheels). An
# unpacked extension may not load remote code, and this one does not try.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYODIDE="$ROOT/site/node_modules/pyodide"
WHEELS="$ROOT/web/wheels"
OUT="$ROOT/extension/vendor"
PIN="0.28.3"

[ -f "$PYODIDE/pyodide.mjs" ] || { echo "no $PYODIDE — run \`make demo-install\` first"; exit 1; }
ls "$WHEELS"/openscript-*.whl >/dev/null 2>&1 || { echo "no $WHEELS — run \`make browser-wheels\` first"; exit 1; }

have="$(node -p "require('$PYODIDE/package.json').version")"
if [ "$have" != "$PIN" ]; then
  echo "site/node_modules/pyodide is $have; the pin is $PIN (see CLAUDE.md on bumping it)"
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"
echo "==> runtime ($PIN)"
cp "$PYODIDE"/{pyodide.mjs,pyodide.asm.js,pyodide.asm.wasm,python_stdlib.zip,pyodide-lock.json} "$OUT/"
echo "==> packages the runtime ships"
cp "$PYODIDE"/*.whl "$OUT/"
echo "==> project wheels"
cp "$WHEELS"/*.whl "$OUT/"

structlog="$(basename "$(ls "$WHEELS"/structlog-*.whl)")"
openscript="$(basename "$(ls "$WHEELS"/openscript-*.whl)")"
printf '{\n  "structlog": "%s",\n  "openscript": "%s"\n}\n' "$structlog" "$openscript" > "$OUT/manifest.json"
du -sh "$OUT"
