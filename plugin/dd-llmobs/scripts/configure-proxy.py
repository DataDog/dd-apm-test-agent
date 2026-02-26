#!/usr/bin/env python3
import json
import os
import sys
import urllib.request

AGENT_PORT = 8126
PROXY_URL = f"http://localhost:{AGENT_PORT}/claude/proxy"
SESSIONS_URL = f"http://localhost:{AGENT_PORT}/claude/hooks/sessions"
CLAUDE_ENV_FILE = os.environ.get("CLAUDE_ENV_FILE", "")
SETTINGS = os.path.expanduser("~/.claude/settings.json")

# Only configure proxy when a compatible dd-llmobs endpoint is present.
try:
    with urllib.request.urlopen(SESSIONS_URL, timeout=2) as response:
        if response.status != 200:
            raise RuntimeError("unexpected status")
except Exception:
    print(
        f"[dd-llmobs] Proxy disabled: compatible dd-llmobs agent not detected on :{AGENT_PORT}.",
        file=sys.stderr,
    )
    sys.exit(0)

# Set ANTHROPIC_BASE_URL for the current session via CLAUDE_ENV_FILE
if CLAUDE_ENV_FILE:
    with open(CLAUDE_ENV_FILE, "a") as f:
        f.write(f"export ANTHROPIC_BASE_URL={PROXY_URL}\n")

# Check for duplicate hooks from old manual config
try:
    with open(SETTINGS) as f:
        data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    data = {}

hooks = data.get("hooks", {})
for event_hooks in hooks.values():
    if isinstance(event_hooks, list):
        for entry in event_hooks:
            cmds = [entry] if isinstance(entry, str) else (entry if isinstance(entry, list) else [])
            for cmd in cmds:
                if isinstance(cmd, str) and ":8126" in cmd:
                    print(
                        "[dd-llmobs] WARNING: ~/.claude/settings.json has manual hooks posting to :8126."
                        " These will duplicate plugin hooks. Remove the hooks section to avoid double-counting.",
                        file=sys.stderr,
                    )
                    break
