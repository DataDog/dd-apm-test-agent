# Setting up Claude Code Hooks with dd-apm-test-agent

Follow these steps to configure Claude Code to send hook events to the dd-apm-test-agent. This enables LLM Observability traces for your Claude Code sessions — you can view tool calls, subagent spans, and LLM invocations.

## Prerequisites

- Docker installed and running
- `curl` available on the system

## Step 1: Start the test agent

### Check for port conflicts

Before starting the test agent, check if one is already running:

```bash
curl -s http://localhost:8126/info
```

If this returns a JSON response where the `version` field contains `"test"` (e.g. `"version": "test"`), the test agent is already running. **Skip ahead to Step 2** — no need to start another one.

Note: The regular Datadog Agent also listens on port 8126 and has an `/info` endpoint, but it returns a numeric version like `"7.45.0"`. Checking for `"test"` in the version field reliably distinguishes the test agent from the Datadog Agent.

If curl fails, returns nothing, or the version does not contain `"test"`, check whether another process is using port 8126:

```bash
lsof -i :8126 -sTCP:LISTEN
```

If the command produces no output, the port is free — proceed to the `docker run` command below.

If a process is listed, note its name and PID from the output. Inform the user:

> Port 8126 is currently in use by `<process name>` (PID `<pid>`). The test agent needs this port to receive traces and hook events.
>
> **Note:** If the conflicting process is the Datadog Agent, stopping it will prevent APM traces, metrics, and other telemetry from being submitted to datadoghq.com while it is stopped.
>
> Do you want to stop `<process name>` so the test agent can start?

**Wait for explicit user confirmation before proceeding.** Do not stop the process without a "Yes."

After the user confirms, stop the process and verify the port is free:

```bash
kill <pid>
```

Then re-check:

```bash
lsof -i :8126 -sTCP:LISTEN
```

If the process is still listening after a few seconds, inform the user and ask whether to force-kill it:

```bash
kill -9 <pid>
```

Once the port is free, proceed to start the test agent.

### Start the container

Run the test agent:

```bash
docker run --rm --pull always -p 8126:8126 -e HOST_USER="$USER" ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest
```

The `HOST_USER` env var passes your username into the container so spans are tagged with `user_name:<you>` instead of `root`.

Verify it's running:

```bash
curl -s http://localhost:8126/info | head -c 100
```

## Step 2: Configure Claude Code hooks

Add the following to `~/.claude/settings.json`. If the file already exists, merge the `hooks` key into the existing config. If an `env` key already exists, merge the `ANTHROPIC_BASE_URL` entry into it.

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://localhost:8126/claude/proxy"
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "curl -s --max-time 2 -X POST -H 'Content-Type: application/json' -d @- http://localhost:8126/claude/hooks >/dev/null 2>&1 || true",
            "async": true
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "curl -s --max-time 2 -X POST -H 'Content-Type: application/json' -d @- http://localhost:8126/claude/hooks >/dev/null 2>&1 || true",
            "async": true
          }
        ]
      }
    ],
    "Notification": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "curl -s --max-time 2 -X POST -H 'Content-Type: application/json' -d @- http://localhost:8126/claude/hooks >/dev/null 2>&1 || true",
            "async": true
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "curl -s --max-time 2 -X POST -H 'Content-Type: application/json' -d @- http://localhost:8126/claude/hooks >/dev/null 2>&1 || true",
            "async": true
          }
        ]
      }
    ],
    "SubagentStart": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "curl -s --max-time 2 -X POST -H 'Content-Type: application/json' -d @- http://localhost:8126/claude/hooks >/dev/null 2>&1 || true",
            "async": true
          }
        ]
      }
    ],
    "SubagentStop": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "curl -s --max-time 2 -X POST -H 'Content-Type: application/json' -d @- http://localhost:8126/claude/hooks >/dev/null 2>&1 || true",
            "async": true
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "curl -s --max-time 2 -X POST -H 'Content-Type: application/json' -d @- http://localhost:8126/claude/hooks >/dev/null 2>&1 || true",
            "async": true
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "curl -s --max-time 2 -X POST -H 'Content-Type: application/json' -d @- http://localhost:8126/claude/hooks >/dev/null 2>&1 || true",
            "async": true
          }
        ]
      }
    ],
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "curl -s --max-time 2 -X POST -H 'Content-Type: application/json' -d @- http://localhost:8126/claude/hooks >/dev/null 2>&1 || true",
            "async": true
          }
        ]
      }
    ]
  }
}
```

### What this does

- **`env.ANTHROPIC_BASE_URL`**: Routes all Claude API calls through the test agent's proxy, enabling LLM span capture (token counts, model info, input/output messages, and span linking between LLM calls and tool calls).
- **`hooks`**: Each hook fires a curl command that POSTs the hook event JSON (read from stdin via `-d @-`) to the test agent. The `--max-time 2` timeout and `|| true` ensure hooks never block Claude Code, even if the agent is down.

## Step 3: Forward traces to Datadog (optional)

Ask the user if they would like to forward traces to Datadog to persist them and get additional features like cost estimation. If they do, ask them for their `DD_API_KEY` and restart the test agent with the key:

```bash
docker run --rm -p 8126:8126 \
  -e HOST_USER="$USER" \
  -e DD_API_KEY=<their-api-key> \
  -e DD_SITE=datadoghq.com \
  ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest
```

If they don't have an API key, they can create one at https://app.datadoghq.com/organization-settings/api-keys. If they prefer local-only mode, skip this step.

## Step 4: View traces

Direct the user to open the local dev experience in their browser to view traces:

https://app-30bd13e67e6cba3b6c36f48da9908a7a.datadoghq.com/llm/traces?devLocal=true&enable-rum

This connects to the local test agent and displays traces as they arrive. The `enable-rum` query parameter enables RUM data collection on hash links (it's disabled by default). This only needs to be added once — it persists in localStorage for subsequent visits.

## Step 5: Use Claude Code

Start a new Claude Code session. Each user turn produces a trace with:
- A root agent span for the session turn
- LLM spans for each Anthropic API call (with token metrics)
- Tool spans for each tool invocation
- Subagent spans for Task tool delegations
- Span links connecting LLM outputs to tool inputs and vice versa

## Customization

### Different host or port

Replace `http://localhost:8126` in both the `ANTHROPIC_BASE_URL` env var and the hook curl commands with your test agent's URL.

### Forwarding to Datadog

To forward LLM Observability data to Datadog, start the agent with:

```bash
docker run --rm -p 8126:8126 \
  -e HOST_USER="$USER" \
  -e DD_API_KEY=<your-api-key> \
  -e DD_SITE=datadoghq.com \
  ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest
```

### Disabling the proxy

If you only want hook-based tracing without LLM span capture, remove the `env.ANTHROPIC_BASE_URL` entry. You will still get tool and agent spans but not LLM spans or span links.

## Diagnostic endpoints

- `GET http://localhost:8126/claude/hooks/sessions` — list tracked sessions
- `GET http://localhost:8126/claude/hooks/spans` — return all assembled spans
- `GET http://localhost:8126/claude/hooks/raw` — return all raw received hook events

## Troubleshooting

**Hooks not sending events**: Verify the agent is running with `curl http://localhost:8126/info`. Check that `~/.claude/settings.json` is valid JSON. Start a new Claude Code session after changing settings.

**No LLM spans**: Ensure `ANTHROPIC_BASE_URL` is set in the `env` section. The proxy must be reachable at that URL for LLM span capture to work.

**Missing spans**: Some events (like Stop) may arrive after the session ends. Check `GET /claude/hooks/raw` to see all received events.
