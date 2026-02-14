# Setting up Claude Code Hooks with dd-apm-test-agent

Follow these steps to configure Claude Code to send hook events to the dd-apm-test-agent. This enables LLM Observability traces for your Claude Code sessions — you can view tool calls, subagent spans, and LLM invocations in the web UI.

## Prerequisites

- Docker installed and running
- `curl` available on the system

## Step 1: Start the test agent

Run the test agent with the web UI and API proxy enabled:

```bash
docker run --rm -p 8126:8126 -p 8080:8080 ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest --web-ui-port=8080
```

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

## Step 3: Use Claude Code

Start a new Claude Code session. Each user turn produces a trace with:
- A root agent span for the session turn
- LLM spans for each Anthropic API call (with token metrics)
- Tool spans for each tool invocation
- Subagent spans for Task tool delegations
- Span links connecting LLM outputs to tool inputs and vice versa

View traces in the web UI at `http://localhost:8080`.

## Customization

### Different host or port

Replace `http://localhost:8126` in both the `ANTHROPIC_BASE_URL` env var and the hook curl commands with your test agent's URL.

### Forwarding to Datadog

To also forward LLM Observability data to Datadog, start the agent with:

```bash
docker run --rm -p 8126:8126 -p 8080:8080 \
  -e DD_API_KEY=<your-api-key> \
  -e DD_SITE=datadoghq.com \
  ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest --web-ui-port=8080
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
