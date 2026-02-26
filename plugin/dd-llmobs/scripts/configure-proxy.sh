#!/bin/bash
set -e

SETTINGS="$HOME/.claude/settings.json"
PROXY_URL="http://localhost:8126/claude/proxy"

python3 -c "
import json, os, sys

path = os.path.expanduser('$SETTINGS')
os.makedirs(os.path.dirname(path), exist_ok=True)

try:
    with open(path) as f:
        data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    data = {}

# Check for duplicate hooks from old manual config
hooks = data.get('hooks', {})
for event_hooks in hooks.values():
    if isinstance(event_hooks, list):
        for entry in event_hooks:
            cmds = [entry] if isinstance(entry, str) else (entry if isinstance(entry, list) else [])
            for cmd in cmds:
                if isinstance(cmd, str) and ':8126' in cmd:
                    print('[dd-llmobs] WARNING: ~/.claude/settings.json has manual hooks posting to :8126. These will duplicate plugin hooks. Remove the hooks section to avoid double-counting.', file=sys.stderr)
                    break

# Skip if already configured
env = data.get('env', {})
if env.get('ANTHROPIC_BASE_URL') == '$PROXY_URL':
    sys.exit(0)

# Add ANTHROPIC_BASE_URL
if 'env' not in data:
    data['env'] = {}
data['env']['ANTHROPIC_BASE_URL'] = '$PROXY_URL'

with open(path, 'w') as f:
    json.dump(data, f, indent=2)
    f.write('\n')

print('[dd-llmobs] Proxy configured. Restart Claude Code once for full LLM span capture.', file=sys.stderr)
"
