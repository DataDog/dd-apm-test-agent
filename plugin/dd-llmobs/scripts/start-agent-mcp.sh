#!/bin/bash
set -e

AGENT_PORT=8126
AGENT_SESSIONS_URL="http://localhost:${AGENT_PORT}/claude/hooks/sessions"
DOCKER_IMAGE="ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Check if a compatible dd-llmobs agent is already running (dev mode)
if curl -sf --max-time 2 "${AGENT_SESSIONS_URL}" >/dev/null 2>&1; then
    echo "[dd-llmobs] Agent already running on :${AGENT_PORT} (dev mode)" >&2
    exec python3 "${SCRIPT_DIR}/mcp_passthrough.py"
fi

# If some other process already owns the port, stay up in safe degraded mode.
if command -v lsof >/dev/null 2>&1 && lsof -iTCP:"${AGENT_PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "[dd-llmobs] WARNING: port ${AGENT_PORT} is occupied by a non-dd-llmobs service" >&2
    echo "[dd-llmobs] Running in degraded mode" >&2
    exec python3 "${SCRIPT_DIR}/mcp_passthrough.py"
fi

# Try Docker
if command -v docker >/dev/null 2>&1; then
    echo "[dd-llmobs] Starting agent via Docker" >&2
    exec docker run --rm -i \
        -p "${AGENT_PORT}:8126" \
        -e HOST_USER \
        -e DD_API_KEY \
        -e DD_SITE \
        "${DOCKER_IMAGE}" \
        ddapm-test-agent-mcp
fi

# Try local binary
if command -v ddapm-test-agent-mcp >/dev/null 2>&1; then
    echo "[dd-llmobs] Starting agent via local binary" >&2
    exec ddapm-test-agent-mcp
fi

echo "[dd-llmobs] ERROR: Cannot start agent. Install Docker or ddapm-test-agent." >&2
exit 1
