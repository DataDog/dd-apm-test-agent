"""Claude launcher and plugin management."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import List
from typing import Optional
import uuid

from lapdog import backfill_claude
from lapdog.cli.ascii_art import build_running_banner
from lapdog.cli.os_runner import run
from lapdog.cli.runtime import _PROXY_SESSION_WARNING_LINES
from lapdog.cli.runtime import ensure_lapdog_running


LAPDOG_PLUGIN_NAME = "lapdog@lapdog"
LAPDOG_MARKETPLACE_SOURCE = "DataDog/dd-apm-test-agent"


def _lapdog_claude_code_plugin_installed() -> bool:
    """Return True if the lapdog Claude Code plugin is installed for this user."""
    installed_path = Path.home() / ".claude" / "plugins" / "installed_plugins.json"
    if not installed_path.exists():
        return False
    try:
        with installed_path.open() as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False
    return bool(LAPDOG_PLUGIN_NAME in (data.get("plugins") or {}))


def _ensure_lapdog_claude_code_plugin_installed() -> None:
    """Install the lapdog Claude Code plugin if missing. Best-effort: failures warn and continue."""
    if _lapdog_claude_code_plugin_installed():
        return
    claude_bin = shutil.which("claude")
    if not claude_bin:
        # _run_claude will print a clearer error in a moment.
        return

    print("[lapdog] Installing Claude Code plugin 'lapdog'...", file=sys.stderr)
    commands = [
        [claude_bin, "plugin", "marketplace", "add", LAPDOG_MARKETPLACE_SOURCE],
        [claude_bin, "plugin", "install", LAPDOG_PLUGIN_NAME],
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            detail = (e.stderr or e.stdout or "").strip()
            print(
                f"[lapdog] '{' '.join(cmd[1:])}' failed (rc={e.returncode}): {detail}",
                file=sys.stderr,
            )
            print(
                "[lapdog] Continuing without plugin; LLM calls will still be captured "
                "but Claude Code hook events (tool calls, prompts, sessions, permissions) "
                "will not. Install manually:\n"
                f"          claude plugin marketplace add {LAPDOG_MARKETPLACE_SOURCE}\n"
                f"          claude plugin install {LAPDOG_PLUGIN_NAME}",
                file=sys.stderr,
            )
            return
    print("[lapdog] Plugin installed.", file=sys.stderr)


def _uninstall_lapdog_claude_code_plugin() -> None:
    if not _lapdog_claude_code_plugin_installed():
        return

    claude_bin = shutil.which("claude")
    if not claude_bin:
        return

    commands = [
        [claude_bin, "plugin", "uninstall", LAPDOG_PLUGIN_NAME],
        [claude_bin, "plugin", "marketplace", "remove", LAPDOG_MARKETPLACE_SOURCE],
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            detail = (e.stderr or e.stdout or "").strip()
            print(
                f"[lapdog] '{' '.join(cmd[1:])}' failed (rc={e.returncode}): {detail}",
                file=sys.stderr,
            )
            print(
                "[lapdog] Failed to uninstall 'lapdog' Claude Code plugin "
                "Uninstall manually:\n"
                f"          claude plugin uninstall {LAPDOG_PLUGIN_NAME}",
                file=sys.stderr,
            )
            return
    print("[lapdog] Claude Code plugin uninstalled", file=sys.stderr)


def _run_claude(
    args: Optional[List[str]] = None, port: Optional[int] = None, session_token: Optional[str] = None
) -> None:
    """Set BUN_OPTIONS with claude_intercept.mjs and exec the claude binary. Never returns."""
    if args is None:
        args = sys.argv[1:]
    mjs_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "claude_intercept.mjs")

    # BUN_OPTIONS is re-parsed by Bun as a shell-like arg string, so backslashes
    # in the path get treated as escape characters and stripped. Bun accepts
    # forward slashes on Windows, which is the most reliable fix.
    if sys.platform == "win32":
        mjs_path = mjs_path.replace("\\", "/")

    claude_bin = shutil.which("claude")
    if not claude_bin:
        print("[ddapm] 'claude' not found in PATH", file=sys.stderr)
        sys.exit(1)

    env = os.environ.copy()
    for variable in ("CODEX_THREAD_ID", "PI_SESSION_ID", "LAPDOG_SESSION_TOKEN"):
        env.pop(variable, None)
    existing = env.get("BUN_OPTIONS", "")
    env["BUN_OPTIONS"] = f"--preload {mjs_path} {existing}".strip()
    debug_log = env.setdefault("DDAPM_CLAUDE_DEBUG_LOG", os.path.expanduser("~/.lapdop/claude-code-debug.log"))
    if port is not None:
        lapdog_url = f"http://localhost:{port}"
        env["LAPDOG_URL"] = lapdog_url
        env["DDAPM_GATEWAY_URL"] = f"{lapdog_url}/claude/proxy"
        env["TEST_AGENT_URL"] = f"{lapdog_url}/info"
    if session_token:
        env["LAPDOG_SESSION_TOKEN"] = session_token
    try:
        os.makedirs(os.path.dirname(debug_log) or ".", mode=0o700, exist_ok=True)
        fd = os.open(debug_log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as log_file:
            log_file.write(
                f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
                f"pid={os.getpid()} launcher exec preload={mjs_path} claude={claude_bin}\n"
            )
    except OSError:
        # Diagnostics must not prevent Claude Code from starting.
        pass
    run(bin_path=claude_bin, argv=([claude_bin] + args), env=env)


def cmd_claude(
    sub_cmd_args: List[str],
    forward_data: bool,
    install_plugin: bool,
    backfill: bool = False,
) -> None:
    """Ensure lapdog is running in background, then launch Claude with intercept.

    When ``backfill`` is True: ensure lapdog is running, replay historical
    Claude Code transcripts from ``~/.claude/projects`` through
    ``/claude/hooks``, and exit without launching Claude. ``forward_data``
    is forced off and plugin installation is skipped during backfill.
    """
    if backfill:
        port = ensure_lapdog_running(forward_data=False, detached=True)
        if port is None:
            print("[lapdog] Could not determine lapdog port.", file=sys.stderr)
            sys.exit(1)
        backfill_claude.backfill(f"http://localhost:{port}")
        return

    if install_plugin:
        _ensure_lapdog_claude_code_plugin_installed()
    port = ensure_lapdog_running(forward_data, detached=True)
    if port is None:
        print("[lapdog] Could not determine lapdog port.", file=sys.stderr)
        sys.exit(1)
    print(build_running_banner(data_type="coding session", warning_lines=_PROXY_SESSION_WARNING_LINES))

    _run_claude(sub_cmd_args, port=port, session_token=uuid.uuid4().hex)
