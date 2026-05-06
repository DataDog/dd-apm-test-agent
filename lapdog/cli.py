"""CLI for lapdog subcommands"""

import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from typing import List
from typing import Optional
from typing import Tuple

from lapdog.lapdog_ascii_art import build_running_banner

import requests

from lapdog.hooks import write_claude_code_hooks
from lapdog.paths import LOG_FILE, PID_FILE
from lapdog import tracer_inject

LAPDOG_COMMANDS = ["start", "stop", "status", "claude", "pi"]
LAPDOG_USAGE = (
    "Usage: lapdog [OPTIONS] <command> [command-args...]\n"
    "Options must appear before <command>. Arguments after <command> are forwarded.\n"
    "  start   Start lapdog (background)\n"
    "  stop    Stop lapdog (started by 'lapdog start' or 'lapdog claude')\n"
    "  status  Show lapdog status (from /info)\n"
    "  claude  Start lapdog in background if needed, then launch Claude with intercept\n"
    "  pi      Start lapdog in background if needed, install extension, then launch pi\n"
    "\n"
    "Any other command is treated as an app to run with tracing instrumentation:\n"
    "  lapdog python app.py\n"
)


def _resolved_port(cli_args: Optional[List[str]] = None) -> int:
    """Infer port the same way lapdog does: -p/--port in args, else PORT env, else 8126."""
    if cli_args is not None:
        i = 0
        while i < len(cli_args):
            arg = cli_args[i]
            if arg in ("-p", "--port"):
                if i + 1 < len(cli_args):
                    return int(cli_args[i + 1])
                i += 1
            elif arg.startswith("--port="):
                return int(arg.split("=", 1)[1])
            i += 1
    return int(os.environ.get("PORT", "8126"))


def _pid_file_path() -> str:
    return os.environ.get("LAPDOG_PID_FILE", PID_FILE)


def _log_file_path() -> str:
    return os.environ.get("LAPDOG_LOG_FILE", LOG_FILE)


def _url_for_port(port: int) -> str:
    return f"http://127.0.0.1:{port}/info"


def _lapdog_alive(timeout: float = 2.0) -> bool:
    """Check if the lapdog we started is running (pid file + process exists + /info responds)."""
    pid, port = _read_pid_file()
    if pid is None or port is None:
        return False
    if not _process_exists(pid):
        return False
    try:
        r = requests.get(_url_for_port(port), timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


def _read_pid_file() -> Tuple[Optional[int], Optional[int]]:
    path = _pid_file_path()
    if not os.path.exists(path):
        return None, None
    try:
        with open(path) as f:
            lines = f.read().splitlines()
        pid = int(lines[0].strip()) if lines else None
        port = int(lines[1].strip()) if len(lines) > 1 else None
        return pid, port
    except (ValueError, OSError):
        return None, None


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _ensure_lapdog_running(forward_data: bool = False, detached: bool = False) -> Optional[int]:
    """Start lapdog in background if it is not already running. Exits if the port is taken."""
    if _lapdog_alive():
        _, port = _read_pid_file()
        return port
    port = _resolved_port()
    if _port_in_use(port):
        print(
            f"[lapdog] Port {port} is already in use. Stop the existing lapdog instance first (e.g. 'lapdog stop').",
            file=sys.stderr,
        )
        sys.exit(1)

    if detached:
        _start_lapdog_detached(port, forward_data=forward_data)
    else:
        _start_lapdog(port, forward_data=forward_data)

    return port


def _write_pid_file(pid: int, port: int) -> None:
    path = _pid_file_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(f"{pid}\n{port}\n")


def _remove_pid_file() -> None:
    path = _pid_file_path()
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def _maybe_write_claude_hooks(disable: bool) -> None:
    if disable:
        return
    claude_settings_path = Path.home() / ".claude" / "settings.json"
    write_claude_code_hooks(claude_settings_path)


def _start_lapdog(port: int, extra_args: Optional[List[str]] = None, forward_data: bool = False) -> Tuple[int, int, str]:
    """Start lapdog in background with logs to the log file; wait until ready or exit on timeout. Return (process, log_path)."""
    log_path = _log_file_path()
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    args = [sys.executable, "-m", "ddapm_test_agent.agent", "--enable-claude-code-hooks", "--lapdog-mode"]

    if not forward_data:
        args.append("--disable-llmobs-data-forwarding")

    if extra_args:
        args += extra_args
    with open(log_path, "w") as log_file:
        proc = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    _write_pid_file(proc.pid, port)
    _wait_for_lapdog(proc, log_path)

    return proc.pid, port, log_path


def _port_in_use(port: Optional[int] = None) -> bool:
    """Return True if something is already serving /info on the given port. If port is None, use _resolved_port()."""
    if port is None:
        port = _resolved_port()
    try:
        r = requests.get(_url_for_port(port), timeout=1)
        return r.status_code == 200
    except Exception:
        return False


def _wait_for_lapdog(proc: "subprocess.Popen[bytes]", log_path: Optional[str] = None) -> None:
    """Wait up to ~10s for lapdog to start, then exit(1) on timeout."""
    for _ in range(50):
        if _lapdog_alive():
            return
        time.sleep(0.2)
    msg = "[lapdog] Lapdog failed to start in time."
    if log_path:
        msg += f" Check logs: {log_path}"
    print(msg, file=sys.stderr)
    _remove_pid_file()
    try:
        proc.kill()
    except OSError:
        pass
    sys.exit(1)


def _run_claude(args: Optional[List[str]] = None) -> None:
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


def cmd_start(sub_cmd_args: List[str], forward_data: bool) -> None:
    """Start lapdog in background with Claude hooks enabled."""
    if _lapdog_alive():
        pid, port = _read_pid_file()
        url = _url_for_port(port) if port else None
        print(f"[lapdog] Lapdog already running at {url}" + (f" (PID {pid})" if pid else ""), file=sys.stderr)
        return
    port = _resolved_port(sys.argv[2:])
    if _port_in_use(port):
        print(
            f"[lapdog] Port {port} is already in use (something is serving /info). "
            "Stop it first (e.g. 'lapdog stop') or use a different port.",
            file=sys.stderr,
        )
        sys.exit(1)
    pid, port, log_path = _start_lapdog(port, sub_cmd_args, forward_data)

    print(f"[lapdog] Lapdog running at {_url_for_port(port)} (pid={pid}, logs: {log_path})")


def cmd_stop() -> None:
    """Stop lapdog (started by 'lapdog start' or 'lapdog claude')."""
    pid, _ = _read_pid_file()
    if pid is None:
        print("[lapdog] No lapdog PID file found; lapdog may not be running.", file=sys.stderr)
        sys.exit(1)
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as e:
        print(f"[lapdog] Failed to stop lapdog (PID {pid}): {e}", file=sys.stderr)
        sys.exit(1)
    _remove_pid_file()
    print("[lapdog] Lapdog stopped.")


def cmd_status() -> None:
    """Print lapdog status (from /info). Only works when lapdog was started by this CLI (pid file exists)."""
    pid, port = _read_pid_file()
    if port is None:
        print("[lapdog] No lapdog running (start with 'lapdog start' or 'lapdog claude').", file=sys.stderr)
        sys.exit(1)
    url = _url_for_port(port)
    try:
        requests.get(url, timeout=2).raise_for_status()
        print(f"[lapdog] Lapdog running at {url} (pid={pid}, logs: {_log_file_path()})", file=sys.stderr)
    except requests.RequestException as e:
        print(f"[lapdog] Lapdog not reachable at {url}: {e}", file=sys.stderr)
        sys.exit(1)


def _start_lapdog_detached(port: int, forward_data: bool) -> None:
    """Start lapdog in a forked child so it is not a child of the calling process.

    After os.execv replaces the current process with pi/claude, lapdog must not
    be a child of that process.  If it were, killing/restarting lapdog would
    send SIGCHLD to the agent which can crash the runtime.  By forking first
    and starting lapdog in the child, the child exits immediately after lapdog
    is ready and lapdog gets re-parented to init/launchd — fully independent of
    the process that will become pi/claude.
    """
    child_pid = os.fork()
    if child_pid == 0:
        # Child: start lapdog, wait for it to be ready, then exit.
        try:
            _start_lapdog(port, forward_data=forward_data)
        except SystemExit:
            # _start_lapdog may call sys.exit on failure
            os._exit(1)
        os._exit(0)

    # Parent: wait for the intermediate child to finish.
    _, status = os.waitpid(child_pid, 0)
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
        print("[lapdog] Failed to start lapdog in background.", file=sys.stderr)
        sys.exit(1)

    # The child already verified lapdog is alive via _wait_for_lapdog before
    # exiting, so we don't re-check here.  The forked child's exit can briefly
    # disrupt the listening socket (shared fd), causing a transient connection
    # refused that would make a re-check flaky.


def cmd_exec(app_cmd: List[str], forward_data: bool, disable_hooks: bool = False) -> None:
    """Auto-start lapdog if needed, inject tracer env vars, then exec the app command. Never returns."""
    _ensure_lapdog_running(forward_data)
    print(build_running_banner(data_type="application"))

    _, port = _read_pid_file()
    if port is None:
        print("[lapdog] Could not determine lapdog port.", file=sys.stderr)
        sys.exit(1)

    env = tracer_inject.build_instrumented_env(port=port)

    resolved = shutil.which(app_cmd[0])
    if not resolved:
        print(f"[lapdog] Command not found: {app_cmd[0]}", file=sys.stderr)
        sys.exit(1)

    os.execvpe(resolved, app_cmd, env)


def cmd_claude(sub_cmd_args: List[str], forward_data: bool, disable_hooks: bool) -> None:
    """Ensure lapdog is running in background, then launch Claude with intercept."""
    _maybe_write_claude_hooks(disable_hooks)
    _ensure_lapdog_running(forward_data, detached=True)
    print(build_running_banner(data_type="coding session"))

    _run_claude(sub_cmd_args)


# ---------------------------------------------------------------------------
# Pi extension management
# ---------------------------------------------------------------------------

_PI_GLOBAL_EXT_DIR = os.path.expanduser("~/.pi/agent/extensions")
_PI_EXT_DEST = os.path.join(_PI_GLOBAL_EXT_DIR, "lapdog.ts")
_PI_EXT_SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pi_lapdog_extension.ts")


def _install_pi_extension() -> None:
    """Copy the bundled lapdog extension into pi's global extensions directory.

    If the extension is already installed and identical, skip the copy.
    LAPDOG_URL is injected at runtime via environment variable when pi is launched.
    """
    if not os.path.isfile(_PI_EXT_SOURCE):
        print(f"[lapdog] Extension source not found: {_PI_EXT_SOURCE}", file=sys.stderr)
        sys.exit(1)

    with open(_PI_EXT_SOURCE, "r") as f:
        source = f.read()

    # Check if already installed and up-to-date.
    is_update = False
    if os.path.isfile(_PI_EXT_DEST):
        try:
            with open(_PI_EXT_DEST, "r") as f:
                existing = f.read()
            if existing == source:
                print(f"[lapdog] pi extension already installed at {_PI_EXT_DEST}")
                return
            is_update = True
        except OSError:
            pass

    os.makedirs(_PI_GLOBAL_EXT_DIR, exist_ok=True)
    with open(_PI_EXT_DEST, "w") as f:
        f.write(source)

    if is_update:
        print(f"[lapdog] Updated pi extension → {_PI_EXT_DEST}")
    else:
        print(f"[lapdog] Installed pi extension → {_PI_EXT_DEST}")


def _run_pi(args: Optional[List[str]] = None, port: Optional[int] = 8126) -> None:
    """Exec the pi binary, forwarding arguments.  Never returns."""
    if args is None:
        args = []
    pi_bin = shutil.which("pi")
    if not pi_bin:
        print("[lapdog] 'pi' not found in PATH", file=sys.stderr)
        sys.exit(1)
    env = {**os.environ, "LAPDOG_URL": f"http://localhost:{port}"}
    os.execve(pi_bin, [pi_bin] + args, env)


def cmd_pi(sub_cmd_args: List[str], forward_data: bool) -> None:
    """Ensure lapdog is running, install the pi extension, then launch pi."""
    port = _ensure_lapdog_running(forward_data, detached=True)
    _install_pi_extension()

    print(build_running_banner(data_type="coding session"))
    _run_pi(args=sub_cmd_args, port=port)


def _parse_command(cmd_args: List[str]) -> Tuple[List[str], List[str]]:
    lapdog_args: List[str] = []

    for arg_idx, arg in enumerate(cmd_args):
        if not arg.startswith('--'):
            return lapdog_args, cmd_args[arg_idx:]

        lapdog_args.append(arg)

    # no sub command found
    print(LAPDOG_USAGE, file=sys.stderr)
    sys.exit(1)


def _parse_lapdog_args(lapdog_args: List[str]) -> argparse.Namespace:
    """Parse lapdog-specific args"""
    parser = argparse.ArgumentParser(
        description="Lapdog CLI",
        prog="lapdog",
    )

    parser.add_argument(
        "--forward",
        action="store_true",
        default=False,
        help="Enable data forwarding to Datadog.",
    )

    parser.add_argument(
        "--disable-claude-code-hooks",
        action="store_true",
        default=False,
        help="Skip writing Claude Code hooks to ~/.claude/settings.json.",
    )

    return parser.parse_args(args=lapdog_args)


def main() -> None:
    args = sys.argv
    if len(args) < 2:
        print(LAPDOG_USAGE, file=sys.stderr)
        sys.exit(1)

    lapdog_args, remaining = _parse_command(args[1:])
    lapdog_parsed_args = _parse_lapdog_args(lapdog_args)

    sub_cmd = remaining[0].lower()
    sub_cmd_args = remaining[1:]

    if sub_cmd not in LAPDOG_COMMANDS:
        cmd_exec(
            app_cmd=remaining,
            forward_data=lapdog_parsed_args.forward,
        )

        return

    if sub_cmd == "start":
        cmd_start(sub_cmd_args=sub_cmd_args, forward_data=lapdog_parsed_args.forward)
    elif sub_cmd == "stop":
        cmd_stop()
    elif sub_cmd == "status":
        cmd_status()
    elif sub_cmd == "claude":
        cmd_claude(
            sub_cmd_args=sub_cmd_args,
            forward_data=lapdog_parsed_args.forward,
            disable_hooks=lapdog_parsed_args.disable_claude_code_hooks,
        )
    elif sub_cmd == "pi":
        cmd_pi(sub_cmd_args=sub_cmd_args, forward_data=lapdog_parsed_args.forward)
