#!/bin/sh
# Claude Code hook script — forwards hook events to dd-apm-test-agent.
# Reads JSON from stdin, POSTs to the test agent's /claude/hooks endpoint.
# Designed to never block Claude Code (--max-time 2, || true).
AGENT_URL="${DD_TEST_AGENT_URL:-http://localhost:8126}"
curl -s --max-time 2 -X POST -H "Content-Type: application/json" \
  -d "$(cat)" "${AGENT_URL}/claude/hooks" >/dev/null 2>&1 || true
