"""CLI entry point for launching commands with the Anthropic API fetch interceptor.

Usage: ddapm-test-agent-run <command> [args...]

Prepends NODE_OPTIONS with --import pointing to claude_intercept.mjs, then
exec's the given command. When the command is "claude", it locates the
npm-installed @anthropic-ai/claude-code cli.js and runs it under node
(the Homebrew Bun binary ignores NODE_OPTIONS).
"""
import os
import shutil
import subprocess
import sys


def _find_claude_cli_js() -> str:
    """Find the npm-installed @anthropic-ai/claude-code cli.js."""
    # Check common npm global/local locations
    candidates = [
        os.path.join(d, "@anthropic-ai", "claude-code", "cli.js")
        for d in [
            # npm global
            os.path.join(os.environ.get("NPM_CONFIG_PREFIX", ""), "lib", "node_modules"),
            os.path.join(sys.prefix, "lib", "node_modules"),
            "/usr/local/lib/node_modules",
            "/opt/homebrew/lib/node_modules",
            # Home-based npm prefix
            os.path.join(os.path.expanduser("~"), ".npm-packages", "lib", "node_modules"),
            os.path.join(os.path.expanduser("~"), ".npm", "lib", "node_modules"),
        ]
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path

    # Search npx cache
    npx_cache = os.path.join(os.path.expanduser("~"), ".npm", "_npx")
    if os.path.isdir(npx_cache):
        for entry in os.listdir(npx_cache):
            path = os.path.join(npx_cache, entry, "node_modules", "@anthropic-ai", "claude-code", "cli.js")
            if os.path.isfile(path):
                return path

    # Fall back to npx install
    print("[ddapm] Claude Code npm package not found locally, installing via npm...", file=sys.stderr)
    result = subprocess.run(
        ["npm", "install", "-g", "@anthropic-ai/claude-code"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[ddapm] npm install failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    # After install, try npm root -g
    result = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True)
    if result.returncode == 0:
        path = os.path.join(result.stdout.strip(), "@anthropic-ai", "claude-code", "cli.js")
        if os.path.isfile(path):
            return path

    print("[ddapm] Could not find cli.js after npm install", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: ddapm-test-agent-run <command> [args...]", file=sys.stderr)
        sys.exit(1)

    mjs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "claude_intercept.mjs")
    existing = os.environ.get("NODE_OPTIONS", "")
    os.environ["NODE_OPTIONS"] = f"--import {mjs_path} {existing}".strip()

    command = sys.argv[1]

    if command == "claude":
        cli_js = _find_claude_cli_js()
        node = shutil.which("node")
        if not node:
            print("[ddapm] node not found in PATH", file=sys.stderr)
            sys.exit(1)
        print(f"[ddapm] using {cli_js}", file=sys.stderr)
        os.execv(node, ["node", cli_js] + sys.argv[2:])
    else:
        os.execvp(command, sys.argv[1:])
