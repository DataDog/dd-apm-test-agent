# Lapdog

Local development tooling for LLM Observability. Lapdog wraps the
[Datadog APM test agent](https://github.com/DataDog/dd-apm-test-agent) and a
small CLI so you can run an LLM coding agent (Claude Code, Pi, or your own)
locally and see every span, prompt, tool call, and cost in a browser — no
Datadog account required.

The static dashboard at <https://lapdog.datadoghq.com> connects directly to a
test agent running on `localhost:8126`. This document is what that page links
out to when you need an install path other than the one-line Homebrew tap (for
example: Linux, Windows, CI containers, locked-down environments, or you just
want to know what `lapdog start` actually does).

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
  - [Homebrew (macOS)](#homebrew-macos)
  - [pip (Linux, macOS, Windows)](#pip-linux-macos-windows)
  - [Docker](#docker)
  - [From source](#from-source)
- [Claude Code plugin](#claude-code-plugin)
- [Quickstart](#quickstart)
- [What lapdog touches on your machine](#what-lapdog-touches-on-your-machine)
- [Uninstallation](#uninstallation)

---

## Requirements

- Python **3.11+** when installing via `pip` or from source. The Homebrew tap
  bundles its own interpreter, so the system Python version does not matter.
- Port **8126** free on `localhost`. If the port is taken, set `PORT=<other>`
  before running `lapdog start` and open the dashboard at
  `http://localhost:<port>/leash/`.
- For `lapdog claude` / `lapdog pi`: the `claude` / `pi` binary already on
  `PATH`.

---

## Installation

### Homebrew (macOS)

This is the path the static onboarding page uses. It installs the `lapdog` CLI
into your shell.

```bash
brew install datadog/lapdog/lapdog
lapdog claude     # or: lapdog pi
```

Upgrade later with `brew upgrade lapdog`.

### pip (Linux, macOS, Windows)

`lapdog` is shipped as a console script inside the `ddapm-test-agent`
distribution. Any environment with Python 3.11+ and `pip` works.

```bash
# Recommended: install into an isolated tool environment
pipx install ddapm-test-agent

# Or, into the current virtualenv / user site
pip install ddapm-test-agent
```

`pipx` is preferred because it keeps `lapdog` and its dependencies off your
project's Python path — important when you also want to instrument an
application that has its own `ddtrace` pin.

To verify:

```bash
lapdog start
# [lapdog] Lapdog running at http://127.0.0.1:8126/info (pid=…, logs: ~/.lapdog/lapdog.log)
```

### Docker

The container image bundles the test agent. Lapdog itself is a thin client
that talks to it, so for Docker workflows you typically run the *agent* in a
container and run your application (or coding agent) on the host pointing at
it.

```bash
docker run --rm \
    -p 8126:8126 \
    -p 4318:4318 \
    -p 4317:4317 \
    ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest \
    ddapm-test-agent --enable-claude-code-hooks --lapdog-mode
```

Then point your application at the host: `DD_TRACE_AGENT_URL=http://localhost:8126`.
Open the dashboard at <http://localhost:8126/leash/>.

To persist sessions across container restarts, mount a host directory at
`/snapshots`:

```bash
docker run --rm \
    -p 8126:8126 \
    -v "$PWD/.lapdog-data:/snapshots" \
    ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest \
    ddapm-test-agent --enable-claude-code-hooks --lapdog-mode
```

If you want the `lapdog claude` workflow (Claude Code hooks + intercept) the
CLI must run on the same machine as Claude Code, since it writes
`~/.claude/settings.json` and execs the local `claude` binary. Use the Docker
image for the *agent*, and `pip install ddapm-test-agent` for the CLI.

### From source

```bash
git clone https://github.com/DataDog/dd-apm-test-agent
cd dd-apm-test-agent
pip install -e .
lapdog --help
```

Or pin to a branch / commit:

```bash
pip install "git+https://github.com/DataDog/dd-apm-test-agent@<branch-or-sha>"
```

---

## Claude Code plugin

The recommended way to capture Claude Code sessions is the `lapdog` Claude
Code plugin, vended from a marketplace inside this same repository. The plugin
registers a non-blocking `curl` hook for every Claude Code event so the local
lapdog agent can record traces, prompts, tool calls, and permission requests.

```bash
# One-time: add this repo as a marketplace and install the plugin.
claude plugin marketplace add DataDog/dd-apm-test-agent
claude plugin install lapdog@lapdog

# Then in any session:
lapdog start                  # run the local agent
claude                        # plugin-installed hooks POST to localhost:8126
```

Open <http://localhost:8126/leash/> while a session is running.

The plugin lives entirely under `~/.claude/plugins/...` — it does **not**
modify `~/.claude/settings.json`. `claude plugin uninstall lapdog@lapdog`
fully removes it.

If you cannot or do not want to install the plugin, `lapdog claude --hooks`
writes the equivalent hook entries directly into `~/.claude/settings.json`.
This is opt-in: by default `lapdog claude` no longer touches your Claude Code
settings.

---

## Quickstart

```bash
# Start the local agent in the background.
lapdog start

# Launch Claude Code with hooks + intercept wired up.
lapdog claude

# Or launch Pi with the lapdog extension installed.
lapdog pi

# Run any other command with tracing instrumentation auto-injected.
lapdog python app.py

# Check status / stop.
lapdog status
lapdog stop
```

Open <http://localhost:8126/leash/> while a session is running to see traces,
sessions, costs, and permission friction in real time.

Useful flags:

- `--forward` — also forward LLMObs events to Datadog (requires `DD_API_KEY`).
- `--hooks` — opt-in: write Claude Code hook entries into
  `~/.claude/settings.json` so Claude Code posts events to the local agent.
  Prefer installing the [Claude Code plugin](#claude-code-plugin) instead.
- `-p <port>` / `--port <port>` — bind to a different port (default `8126`).

---

## What lapdog touches on your machine

Knowing this up front makes the uninstall list below easy to verify.

| Path | When written | What it is |
| --- | --- | --- |
| `~/.lapdog/lapdog.pid` | `lapdog start` / `lapdog claude` / `lapdog pi` | PID + port of the background agent |
| `~/.lapdog/lapdog.log` | same | stdout/stderr of the background agent |
| `~/.claude/settings.json` | only `lapdog claude --hooks` (opt-in) | adds a `curl` hook to `localhost:8126/claude/hooks` for each Claude Code event. The Claude Code plugin path leaves this file alone. |
| `~/.pi/agent/extensions/lapdog.ts` | `lapdog pi` | Pi extension that reports tool calls to the local agent |

No other state is created. There is no daemon installed at the OS level
(launchd / systemd) — the background process is a plain detached child.

---

## Uninstallation

### 1. Stop the running agent

```bash
lapdog stop
```

If `lapdog stop` reports no PID file but you still see something on port 8126,
find and kill it manually:

```bash
lsof -ti tcp:8126 | xargs kill
```

### 2. Remove the Claude Code plugin (if installed)

If you installed the plugin from the marketplace:

```bash
claude plugin uninstall lapdog@lapdog
claude plugin marketplace remove lapdog
```

### 3. Remove the Claude Code hooks (only if you used `lapdog claude --hooks`)

`lapdog claude --hooks` adds hook entries to `~/.claude/settings.json` so
Claude Code posts events to `localhost:8126/claude/hooks`. They look like:

```json
{
  "type": "command",
  "command": "curl -s --max-time 2 -X POST -H 'Content-Type: application/json' -d @- http://localhost:8126/claude/hooks >/dev/null 2>&1 || true",
  "async": true
}
```

You can either delete just the entries that POST to
`localhost:8126/claude/hooks` (leaving any other hooks you've configured
alone), or `jq` them out:

```bash
jq '
  .hooks |= with_entries(
    .value |= map(
      .hooks |= map(select(
        (.command // "") | contains("localhost:8126/claude/hooks") | not
      ))
    )
  )
' ~/.claude/settings.json > ~/.claude/settings.json.tmp \
  && mv ~/.claude/settings.json.tmp ~/.claude/settings.json
```

The hooks are harmless when the agent is not running (the `curl` returns
non-zero and the `|| true` swallows it), so removing them is optional unless
you want a fully clean Claude Code config.

### 4. Remove the Pi extension (only if you used `lapdog pi`)

```bash
rm -f ~/.pi/agent/extensions/lapdog.ts
```

### 5. Remove lapdog's working directory

```bash
rm -rf ~/.lapdog
```

### 6. Uninstall the package

Match the install method you used:

```bash
# Homebrew
brew uninstall lapdog
brew untap datadog/lapdog

# pipx
pipx uninstall ddapm-test-agent

# pip
pip uninstall ddapm-test-agent

# Docker
docker rmi ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest
```

After this nothing lapdog wrote remains on the system.
