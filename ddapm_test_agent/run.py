"""CLI entry point for launching commands with the Anthropic API fetch interceptor.

Usage: lapdog-run <command> [args...]

- For "claude": sets BUN_OPTIONS with --preload pointing to claude_intercept.mjs and
  exec's the claude binary from PATH (e.g. Homebrew Cask). Works with Bun-based Claude Code.
- For other commands: sets NODE_OPTIONS with --import pointing to claude_intercept.mjs
  and exec's the given command (for Node-based tools).
"""
import os
import shutil
import sys
from typing import List
from typing import Optional


def run_claude(args: Optional[List[str]] = None) -> None:
    """Set BUN_OPTIONS with claude_intercept.mjs and exec the claude binary. Never returns."""
    if args is None:
        args = sys.argv[1:]
    mjs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "claude_intercept.mjs")
    claude_bin = shutil.which("claude")
    if not claude_bin:
        print("[ddapm] 'claude' not found in PATH", file=sys.stderr)
        sys.exit(1)
    existing = os.environ.get("BUN_OPTIONS", "")
    os.environ["BUN_OPTIONS"] = f"--preload {mjs_path} {existing}".strip()
    os.execv(claude_bin, [claude_bin] + args)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: lapdog-run <command> [args...]", file=sys.stderr)
        sys.exit(1)

    mjs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "claude_intercept.mjs")
    command = sys.argv[1]

    if command == "claude":
        run_claude(sys.argv[2:])
    else:
        # to avoid unintended side effects from running with other commands that might take some JS options
        # TODO: expand upon this conditional tree with more support for other agent launchers
        print(f"""Unsupported command for lapdog-run: {command}
Supported commands are: claude""", file=sys.stderr)
        sys.exit(1)
