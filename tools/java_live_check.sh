#!/usr/bin/env bash
# Run the Java client's tests against the real Python policies: start the
# server with server/guard_example.yaml on a free port, run `mvn test` with
# OPENSCRIPT_SERVER_URL set (which enables LiveServerTest), stop the server.
#
# It needs the Postgres the server needs (`docker compose up -d postgres`, or
# DATABASE_URL pointing at another): deciding an approval writes its event
# there. Migrations are run first. Approvals stay in memory, in the one server
# process.
#
#   PYTHON=.venv/bin/python MVN=mvn bash tools/java_live_check.sh
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python}"
MVN="${MVN:-mvn}"

PORT="$("$PYTHON" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
export OPENSCRIPT_API_KEY="java-live-check"
export OPENSCRIPT_GUARD_CONFIG="server/guard_example.yaml"
export OPENSCRIPT_SERVER_URL="http://127.0.0.1:${PORT}"
export DATABASE_URL="${DATABASE_URL:-postgresql+asyncpg://openscript:openscript@localhost:5432/openscript}"
LOG="$(mktemp)"

"$PYTHON" -m alembic upgrade head

"$PYTHON" -m uvicorn server.app:app --host 127.0.0.1 --port "$PORT" >"$LOG" 2>&1 &
SERVER=$!
trap 'kill "$SERVER" 2>/dev/null || true; rm -f "$LOG"' EXIT

for _ in $(seq 1 100); do
  if curl -sf "${OPENSCRIPT_SERVER_URL}/health" >/dev/null; then
    break
  fi
  if ! kill -0 "$SERVER" 2>/dev/null; then
    echo "the server exited before it was ready:" >&2
    cat "$LOG" >&2
    exit 1
  fi
  sleep 0.2
done
curl -sf "${OPENSCRIPT_SERVER_URL}/health" >/dev/null || {
  echo "the server did not answer /health:" >&2
  cat "$LOG" >&2
  exit 1
}

cd clients/java
"$MVN" -B -q test
# Surefire reports skips quietly. A live run that skipped is not a live run.
if grep -q 'Skipped: [1-9]' target/surefire-reports/*LiveServerTest.txt; then
  echo "LiveServerTest was skipped" >&2
  exit 1
fi
grep -h 'Tests run' target/surefire-reports/*.txt
