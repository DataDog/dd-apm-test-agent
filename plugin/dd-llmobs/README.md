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

That's it. Full observability is active immediately - no restart needed.

## Environment variables

These must be available in the shell that launches Claude Code. The plugin's MCP server and Docker container inherit them.

Set them in your shell profile (`~/.zshrc` or `~/.bashrc`):

```bash
export DD_API_KEY="your-api-key-here"
export DD_SITE="datadoghq.com"  # optional, defaults to datad0g.com
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

The plugin validates `GET /claude/hooks/sessions` before enabling passthrough and proxy mode. If your local
`ddapm-test-agent` is already running on 8126, the plugin becomes a passthrough MCP server and no Docker container is
started. If another service occupies 8126, the plugin stays in a safe degraded mode (Claude keeps working, observability
stays off) instead of sending traffic to the wrong endpoint.

## Slash commands

- `/dd-llmobs:llmobs-status` - Check agent health, proxy config, session count, and overall observability status

## Viewing traces

Open the local dev experience in your browser:

https://app-30bd13e67e6cba3b6c36f48da9908a7a.datadoghq.com/llm/traces?devLocal=true&enable-rum

## Troubleshooting

- **Agent not starting**: Check that Docker is installed and running. Run `docker ps` to verify.
- **Port conflict**: Run `lsof -i :8126` to check what's using the port. Port 8126 is also used by the Datadog agent.
  If a non-dd-llmobs service owns the port, the plugin will enter degraded mode and skip proxy setup.
- **No LLM spans**: Run `/dd-llmobs:llmobs-status` to diagnose. Check that the agent is reachable on :8126.
- **Use `/dd-llmobs:llmobs-status`**: The status command checks agent health, proxy config, and reports the current observability mode.

## Uninstalling

Just uninstall the plugin. The proxy is configured per-session via `CLAUDE_ENV_FILE` (not persisted to settings.json), so there is nothing to clean up.
