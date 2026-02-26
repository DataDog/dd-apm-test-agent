#!/bin/bash
set -e

AGENT_PORT=8126
AGENT_INFO_URL="http://localhost:${AGENT_PORT}/info"
DOCKER_IMAGE="ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest"

# Check if our test agent is already running (dev mode)
if curl -sf --max-time 2 "${AGENT_INFO_URL}" >/dev/null 2>&1; then
    info_resp=$(curl -sf --max-time 2 "${AGENT_INFO_URL}" 2>/dev/null || true)
    if echo "${info_resp}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'endpoints' in d" 2>/dev/null; then
        echo "[dd-llmobs] Agent already running on :${AGENT_PORT} (dev mode)" >&2
    else
        echo "[dd-llmobs] WARNING: port ${AGENT_PORT} is occupied but does not look like our test agent" >&2
    fi
    # Minimal MCP passthrough - Content-Length framing, block on stdin forever
    exec python3 -c "
import sys, json

def read_msg():
    header = b''
    while True:
        b = sys.stdin.buffer.read(1)
        if b == b'':
            raise EOFError()
        header += b
        if header.endswith(b'\r\n\r\n'):
            break
    length = int(header.decode().split(':')[1].strip())
    return json.loads(sys.stdin.buffer.read(length))

def write_msg(msg):
    body = json.dumps(msg).encode()
    frame = ('Content-Length: %d\r\n\r\n' % len(body)).encode() + body
    sys.stdout.buffer.write(frame)
    sys.stdout.buffer.flush()

while True:
    try:
        msg = read_msg()
    except EOFError:
        break
    method = msg.get('method', '')
    mid = msg.get('id')
    if method == 'initialize':
        write_msg({'jsonrpc':'2.0','id':mid,'result':{'protocolVersion':'2024-11-05','capabilities':{},'serverInfo':{'name':'dd-llmobs-agent','version':'1.0'}}})
    elif method == 'tools/list':
        write_msg({'jsonrpc':'2.0','id':mid,'result':{'tools':[]}})
    elif method == 'ping':
        write_msg({'jsonrpc':'2.0','id':mid,'result':{}})
"
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
