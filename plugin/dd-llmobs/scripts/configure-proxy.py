#!/usr/bin/env python3
import json
import os
import sys
import urllib.request

PROXY_URL = "http://localhost:8126/claude/proxy"
CLAUDE_ENV_FILE = os.environ.get("CLAUDE_ENV_FILE", "")
SETTINGS = os.path.expanduser("~/.claude/settings.json")

# Only configure proxy if the agent is actually reachable
try:
    urllib.request.urlopen("http://localhost:8126/info", timeout=2)
except Exception:
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
