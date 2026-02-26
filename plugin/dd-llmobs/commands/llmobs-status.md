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

### 3. Proxy Active

Only if the agent is running, check if LLM spans exist:

```bash
curl -sf http://localhost:8126/claude/hooks/spans
```

If there are spans with `meta.span.kind == "llm"`, the proxy is active and capturing LLM data. If only hook-based spans exist (agent, tool), the proxy is not active.

### 4. Duplicate Hooks Check

Read `~/.claude/settings.json` and check if there is a `hooks` key containing curl commands that post to `:8126`. This is old manual config that should be removed to avoid double-counting events. Warn the user if found.

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
Proxy:     active (22 LLM spans captured)
Docker:    container abc123 up 5 minutes
Hooks:     no duplicates detected

Status: Full observability
```

### Summary Line

Based on the checks, report exactly one of:

- **"Full observability"** - agent running AND LLM spans present (proxy is active)
- **"Hooks-only mode"** - agent running but no LLM spans (proxy not active - agent may not be reachable from configure-proxy.py)
- **"Agent not running"** - nothing responding on :8126

## Error Handling

- **Agent not responding**: Report "Agent not running" and suggest checking that the plugin MCP server started correctly or that Docker is running.
- **Docker not installed**: Skip the Docker check, note it was skipped.
