---
description: Check LLM Observability agent health, proxy config, and session status
---

# LLM Observability Status

When the user invokes `llmobs-status`, check and report the health of the Datadog LLM Observability setup.

## Workflow

Run all checks, then present a summary.

### 1. Agent Health and Sessions

```bash
curl -sf http://localhost:8126/claude/hooks/sessions
```

If it responds with JSON containing a `sessions` array, a compatible dd-llmobs agent is running. Report the number of sessions. If it fails or returns an unexpected shape, treat the agent as down/incompatible.

### 2. Proxy Active

Only if a compatible agent is running, check if LLM spans exist:

```bash
curl -sf http://localhost:8126/claude/hooks/spans
```

If there are spans with `meta.span.kind == "llm"`, the proxy is active and capturing LLM data. If only hook-based spans exist (agent, tool), the proxy is not active.

### 3. Duplicate Hooks Check

Read `~/.claude/settings.json` and check if there is a `hooks` key containing curl commands that post to `:8126`. This is old manual config that should be removed to avoid double-counting events. Warn the user if found.

### 4. Docker Container

```bash
docker ps --filter ancestor=ghcr.io/datadog/dd-apm-test-agent --format '{{.ID}} {{.Status}} {{.Ports}}'
```

Report whether the agent container is running, or if Docker is not available.

## Output Format

Present results as a status report:

```
LLM Observability Status
========================

Agent:     running (3 sessions recorded)
Proxy:     active (22 LLM spans captured)
Docker:    container abc123 up 5 minutes
Hooks:     no duplicates detected

Status: Full observability
```

### Summary Line

Based on the checks, report exactly one of:

- **"Full observability"** - agent running AND LLM spans present (proxy is active)
- **"Hooks-only mode"** - agent running but no LLM spans (proxy not active)
- **"Agent not running"** - no compatible dd-llmobs endpoint on :8126

## Error Handling

- **Agent not responding**: Report "Agent not running" and suggest checking that the plugin MCP server started correctly, that Docker is running, or that no unrelated service is bound to :8126.
- **Docker not installed**: Skip the Docker check, note it was skipped.
