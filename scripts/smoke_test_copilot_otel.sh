#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON:-python}"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/lapdog-copilot-smoke.XXXXXX")
read -r auto_port auto_otlp_http_port auto_otlp_grpc_port < <(
    "$python_bin" - <<'PY'
import socket

sockets = []
ports = []
for _ in range(3):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
    ports.append(sock.getsockname()[1])
print(*ports)
for sock in sockets:
    sock.close()
PY
)

export PORT="${PORT:-${LAPDOG_PORT:-$auto_port}}"
export LAPDOG_PORT="$PORT"
export OTLP_HTTP_PORT="${OTLP_HTTP_PORT:-$auto_otlp_http_port}"
export OTLP_GRPC_PORT="${OTLP_GRPC_PORT:-$auto_otlp_grpc_port}"
export LAPDOG_PID_FILE="$tmpdir/lapdog.pid"
export LAPDOG_LOG_FILE="$tmpdir/lapdog.log"
smoke_session_id=$("$python_bin" -c 'import uuid; print(uuid.uuid4())')

cleanup() {
    lapdog stop || true
    rm -rf "$tmpdir"
}

trap cleanup EXIT

echo "[smoke] starting isolated lapdog"
lapdog start

echo "[smoke] checking status"
lapdog status

echo "[smoke] verifying copilot exists"
command -v copilot

echo "[smoke] running a time-bounded Copilot prompt through lapdog"
"$python_bin" - "$smoke_session_id" "$tmpdir/response.txt" <<'PY'
import subprocess
import sys


session_id, response_path = sys.argv[1:]
with open(response_path, "w") as response:
    subprocess.run(
        [
            "lapdog",
            "copilot",
            "-p",
            "Reply exactly LAPDOG_OTEL_SMOKE. Do not call tools.",
            "--session-id",
            session_id,
            "--no-custom-instructions",
            "--no-ask-user",
            "--silent",
        ],
        check=True,
        stdout=response,
        timeout=120,
    )
PY

grep -q "LAPDOG_OTEL_SMOKE" "$tmpdir/response.txt"

echo "[smoke] verifying the current invocation's exported span tree"
"$python_bin" - "$PORT" "$smoke_session_id" <<'PY'
import json
import sys
from urllib.request import Request
from urllib.request import urlopen


port = int(sys.argv[1])
session_id = sys.argv[2]
request = Request(
    f"http://127.0.0.1:{port}/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
    data=json.dumps({"list": {"search": {"query": ""}, "limit": 100}}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urlopen(request, timeout=20) as response:
    payload = json.load(response)

all_events = [item["event"]["custom"] for item in payload.get("result", {}).get("events", [])]
events = [event for event in all_events if event.get("session_id") == session_id]
names = {event.get("name") for event in events}
roots = [event for event in events if event.get("parent_id") == "undefined"]
if payload.get("status") != "done":
    raise SystemExit(f"Lapdog query did not complete: {payload!r}")
if len(roots) != 1:
    raise SystemExit(f"Expected one Copilot session root for {session_id}, got {len(roots)}")
if "invoke_agent" not in names:
    raise SystemExit(f"No invoke_agent span was exported for {session_id}: {sorted(str(name) for name in names)}")
if not any(str(name).startswith("chat ") for name in names):
    raise SystemExit(f"No Copilot chat span was exported for {session_id}: {sorted(str(name) for name in names)}")

print(f"[smoke] verified {len(events)} spans for session {session_id}")
PY

echo "[smoke] done"
