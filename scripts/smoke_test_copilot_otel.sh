#!/usr/bin/env bash
set -euo pipefail

export PORT="${PORT:-${LAPDOG_PORT:-8126}}"
export LAPDOG_PORT="$PORT"

cleanup() {
    lapdog stop || true
}

trap cleanup EXIT

echo "[smoke] stopping existing lapdog if present"
lapdog stop || true

echo "[smoke] starting lapdog"
lapdog start

echo "[smoke] checking status"
lapdog status

echo "[smoke] verifying copilot exists"
command -v copilot

echo "[smoke] launching copilot through lapdog"
lapdog copilot --help

echo "[smoke] done"
