---
description: Check LLM Observability agent health, proxy config, and session status
---

# LLM Observability Status

When the user invokes `llmobs-status`, check and report the health of the Datadog LLM Observability setup.

## Workflow

Run all checks, then present a summary.

### 1. Agent Health

```bash
curl -sf http://localhost:8126/info
```

If it responds with JSON containing `version` and `endpoints`, the agent is running. If it fails, the agent is down.

### 2. Session Count

Only if the agent is running:

```bash
curl -sf http://localhost:8126/claude/hooks/sessions
```

Report the number of sessions recorded.

### 3. Proxy Config

Read `~/.claude/settings.json` and check whether `env.ANTHROPIC_BASE_URL` is set to `http://localhost:8126/claude/proxy`.

### 4. Duplicate Hooks Check

While reading `~/.claude/settings.json`, check if there is also a `hooks` key containing curl commands that post to `:8126`. This is old manual config that should be removed to avoid double-counting events. Warn the user if found.

### 5. Docker Container

```bash
docker ps --filter ancestor=ghcr.io/datadog/dd-apm-test-agent --format '{{.ID}} {{.Status}} {{.Ports}}'
```

Report whether the agent container is running, or if Docker is not available.

## Output Format

Present results as a status report:

```
LLM Observability Status
========================

Agent:     running (v7.x.x)
Sessions:  3 recorded
Proxy:     configured (ANTHROPIC_BASE_URL set)
Docker:    container abc123 up 5 minutes
Hooks:     no duplicates detected

Status: Full observability
```

### Summary Line

Based on the checks, report exactly one of:

- **"Full observability"** - agent running AND proxy configured (ANTHROPIC_BASE_URL present in settings.json AND Claude Code was restarted after it was configured)
- **"Hooks-only mode (restart needed for full observability)"** - agent running, ANTHROPIC_BASE_URL was just configured this session by configure-proxy.sh
- **"Hooks-only mode (proxy not configured)"** - agent running but no ANTHROPIC_BASE_URL in settings.json
- **"Agent not running"** - nothing responding on :8126

To distinguish "full observability" from "restart needed": if the proxy is configured and LLM spans exist in `curl -sf http://localhost:8126/claude/hooks/spans`, the proxy is active. If only hook events exist but no LLM spans, a restart is still needed.

## Error Handling

- **Agent not responding**: Report "Agent not running" and suggest checking that the plugin MCP server started correctly or that Docker is running.
- **Docker not installed**: Skip the Docker check, note it was skipped.
- **settings.json missing**: Report proxy as not configured.
