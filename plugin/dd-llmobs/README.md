# dd-llmobs - Datadog LLM Observability for Claude Code

LLM Observability for Claude Code sessions. Captures tool calls, agent spans, user prompts, and LLM invocations with token metrics, model info, and cost data. Traces are viewable in Datadog or the local dev experience.

## Prerequisites

- Docker installed and running
- `DD_API_KEY` set in your shell environment (required for forwarding spans to Datadog; without it, spans are captured locally only)

## Installation

In Claude Code, first add the marketplace (one-time), then install the plugin:

```
/plugin marketplace add DataDog/dd-apm-test-agent
/plugin install dd-llmobs@dd-apm-test-agent
```

For local development:

```bash
claude --plugin-dir ./plugin/dd-llmobs
```

## First session behavior

On the first session after install:

1. The MCP server starts the agent (via Docker) automatically
2. Hooks fire immediately - tool calls, agent spans, and user prompts are captured
3. `configure-proxy.sh` adds `ANTHROPIC_BASE_URL` to `~/.claude/settings.json`
4. A message says: "Restart Claude Code once for full LLM span capture"

After one restart, full observability is active - including LLM spans with token metrics, model info, input/output messages, and span linking. This restart is a one-time event.

## Environment variables

These must be available in the shell that launches Claude Code. The plugin's MCP server and Docker container inherit them.

Set them in your shell profile (`~/.zshrc` or `~/.bashrc`):

```bash
export DD_API_KEY="your-api-key-here"
export DD_SITE="datadoghq.com"  # optional, defaults to datad0g.com
```

Or add them to `~/.claude/settings.json` under `env` (alongside `ANTHROPIC_BASE_URL`):

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://localhost:8126/claude/proxy",
    "DD_API_KEY": "your-api-key-here",
    "DD_SITE": "datadoghq.com"
  }
}
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DD_API_KEY` | For Datadog forwarding | none | Datadog API key for forwarding spans |
| `DD_SITE` | No | `datad0g.com` | Datadog site to forward spans to |
| `HOST_USER` | No | auto-detected | Tags spans with `user_name:<value>` |

## Dev mode

If you're developing the test agent locally, run it from source before starting Claude Code:

```bash
ddapm-test-agent --port 8126
```

The plugin detects that port 8126 is already occupied and becomes a passthrough MCP server. All hooks fire against your local agent. No Docker container is started.

## Slash commands

- `/llmobs-status` - Check agent health, proxy config, session count, and overall observability status

## Viewing traces

Open the local dev experience in your browser:

https://app-30bd13e67e6cba3b6c36f48da9908a7a.datadoghq.com/llm/traces?devLocal=true&enable-rum

## Troubleshooting

- **Agent not starting**: Check that Docker is installed and running. Run `docker ps` to verify.
- **Port conflict**: Run `lsof -i :8126` to check what's using the port. Port 8126 is also used by the Datadog agent.
- **No LLM spans after restart**: Verify `ANTHROPIC_BASE_URL` is set in `~/.claude/settings.json` with `cat ~/.claude/settings.json`.
- **Use `/llmobs-status`**: The status command checks agent health, proxy config, and reports the current observability mode.

## Uninstalling

Before uninstalling the plugin, remove `ANTHROPIC_BASE_URL` from settings:

```bash
python3 -c "
import json, os
path = os.path.expanduser('~/.claude/settings.json')
with open(path) as f:
    data = json.load(f)
env = data.get('env', {})
env.pop('ANTHROPIC_BASE_URL', None)
if not env:
    data.pop('env', None)
else:
    data['env'] = env
with open(path, 'w') as f:
    json.dump(data, f, indent=2)
    f.write('\n')
"
```

Then uninstall the plugin. If you skip this step, Claude Code will fail on next start (it will try to route API calls through a proxy that no longer exists).
