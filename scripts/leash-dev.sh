#!/usr/bin/env bash
# leash-dev.sh — start the Leash dev stack.
#
# Runs the test agent with Python hot reload (watchdog/watchmedo) and the
# Vite dev server for the Leash UI in parallel. Ctrl-C tears both down.
#
# Usage:
#   scripts/leash-dev.sh
#
# Env vars:
#   LEASH_PORT             — port for the test agent (default: 8126)
#   LEASH_UI_PORT          — port for Vite dev server (default: 5280)
#   LEASH_TEST_AGENT_URL   — URL the UI proxies to (default: http://localhost:$LEASH_PORT)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LEASH_PORT="${LEASH_PORT:-8126}"
LEASH_UI_PORT="${LEASH_UI_PORT:-5280}"
export LEASH_TEST_AGENT_URL="${LEASH_TEST_AGENT_URL:-http://localhost:${LEASH_PORT}}"

if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  if [[ -f "$REPO_ROOT/.venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "$REPO_ROOT/.venv/bin/activate"
  else
    echo "No virtualenv active and .venv not found. Activate your venv first." >&2
    exit 1
  fi
fi

if [[ ! -d "$REPO_ROOT/leash-ui/node_modules" ]]; then
  echo "Installing leash-ui dependencies..."
  (cd "$REPO_ROOT/leash-ui" && npm install)
fi

pids=()
cleanup() {
  trap '' INT TERM
  for pid in "${pids[@]:-}"; do
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "[leash-dev] starting test agent on :$LEASH_PORT (hot reload via watchmedo)"
watchmedo auto-restart \
  --directory="$REPO_ROOT/ddapm_test_agent" \
  --pattern="*.py" \
  --recursive \
  --signal=SIGTERM \
  -- ddapm-test-agent --port="$LEASH_PORT" &
pids+=($!)

echo "[leash-dev] starting vite dev server on :$LEASH_UI_PORT (HMR)"
(cd "$REPO_ROOT/leash-ui" && npm run dev -- --port "$LEASH_UI_PORT") &
pids+=($!)

echo "[leash-dev] UI:     http://localhost:$LEASH_UI_PORT"
echo "[leash-dev] Agent:  http://localhost:$LEASH_PORT"
echo "[leash-dev] (Ctrl-C to stop)"

wait -n "${pids[@]}"
