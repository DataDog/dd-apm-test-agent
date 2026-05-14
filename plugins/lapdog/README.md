# lapdog (Claude Code plugin)

Forwards every Claude Code hook event (`PreToolUse`, `PostToolUse`,
`UserPromptSubmit`, `SessionStart`, `PermissionRequest`, ...) to a locally
running [lapdog](https://github.com/DataDog/dd-apm-test-agent) /
[dd-apm-test-agent](https://github.com/DataDog/dd-apm-test-agent) on
`http://localhost:8126/claude/hooks`.

Pair this plugin with `lapdog start` (or `lapdog claude`) on the same machine.
While both are running, open <http://localhost:8126/leash/> to inspect traces,
sessions, costs, and permission friction in real time.

## Install

```bash
claude plugin marketplace add DataDog/dd-apm-test-agent
claude plugin install lapdog@lapdog
```

## What it does

For each Claude Code hook event the plugin runs a single non-blocking `curl`
that POSTs the event payload to the local lapdog agent. When the agent is not
running the `curl` fails silently (`|| true`), so the plugin is harmless to
leave installed.

The plugin does not write to `~/.claude/settings.json` and does not require
any further configuration.
