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
- For `lapdog claude` / `lapdog pi` / `lapdog codex`: the `claude` / `pi` /
  `codex` binary already on `PATH`.

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

If you want the `lapdog claude` or `lapdog codex` workflow, the CLI must run
on the same machine as the coding agent, since it execs the local binary and
routes model traffic through the local Lapdog agent. Use the Docker image for
the *agent*, and `pip install ddapm-test-agent` for the CLI.

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

`lapdog claude` auto-installs the plugin on first run — no separate setup
step is needed:

```bash
lapdog claude
# [lapdog] Installing Claude Code plugin 'lapdog'...
# [lapdog] Plugin installed.
# ...launches Claude...
```

On subsequent runs lapdog detects the plugin via
`~/.claude/plugins/installed_plugins.json` and skips the install step. To do
the install yourself (or to script it in CI), the commands are:

```bash
claude plugin marketplace add DataDog/dd-apm-test-agent
claude plugin install lapdog@lapdog
```

The plugin lives entirely under `~/.claude/plugins/...` — it does **not**
modify `~/.claude/settings.json`. `claude plugin uninstall lapdog@lapdog`
fully removes it.

To skip the auto-install (e.g. on a locked-down machine), run
`lapdog --no-plugin-install claude` — Claude will launch but events will not
be captured. If the auto-install fails (no network, etc.) lapdog prints the
manual commands and launches Claude uninstrumented rather than blocking the
session.

---

## Quickstart

```bash
# Start the local agent in the background.
lapdog start

# Auto-install the Claude Code plugin (if needed), then launch Claude with intercept.
lapdog claude

# Or launch Codex with JSONL capture + proxy tracing wired up.
lapdog codex

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

Important: `lapdog claude` and `lapdog codex` are proxy-backed workflows.
They put the local Lapdog agent in the live model-request path. Keep Lapdog
running until the coding agent exits. If Lapdog is stopped or killed
mid-session, the launched agent can stop making model progress; `lapdog codex`
continues pointing Codex at the local OpenAI proxy, and `lapdog claude` can
interrupt in-flight proxied Anthropic calls. Restart the coding agent after
restarting Lapdog.

Hook-only integrations are different: their non-blocking `curl` hooks fail
open when Lapdog is down, so the coding agent keeps running but capture data
is lost.

Useful flags:

- `--forward` — also forward LLMObs events to Datadog (requires `DD_API_KEY`).
- `--no-plugin-install` — skip the `lapdog claude` auto-install of the Claude
  Code plugin.
- `-p <port>` / `--port <port>` — bind to a different port (default `8126`).

---

## What lapdog touches on your machine

Knowing this up front makes the uninstall list below easy to verify.

| Path | When written | What it is |
| --- | --- | --- |
| `~/.lapdog/lapdog.pid` | `lapdog start` / `lapdog claude` / `lapdog pi` | PID + port of the background agent |
| `~/.lapdog/lapdog.log` | same | stdout/stderr of the background agent |
| `~/.claude/plugins/...` | `lapdog claude` (first run) | the auto-installed `lapdog@lapdog` Claude Code plugin lives entirely under here |
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

### 3. Remove the Pi extension (only if you used `lapdog pi`)

```bash
rm -f ~/.pi/agent/extensions/lapdog.ts
```

### 4. Remove lapdog's working directory

```bash
rm -rf ~/.lapdog
```

### 5. Uninstall the package

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
