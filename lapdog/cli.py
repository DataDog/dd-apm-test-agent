"""CLI for lapdog subcommands"""

import argparse
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import subprocess
import sys
import time
from typing import List
from typing import Optional
from typing import Tuple
import uuid

import requests

from lapdog import codex_args
from lapdog import tracer_inject
from lapdog.lapdog_ascii_art import build_running_banner
from lapdog.paths import CODEX_APP_CURSOR_FILE
from lapdog.paths import LAPDOG_DIR
from lapdog.paths import LOG_FILE
from lapdog.paths import PID_FILE


LAPDOG_COMMANDS = ["start", "stop", "status", "claude", "pi", "codex", "uninstall"]
LAPDOG_USAGE = (
    "Usage: lapdog [OPTIONS] <command> [command-args...]\n"
    "Options must appear before <command>. Arguments after <command> are forwarded.\n"
    "  start      Start lapdog (background)\n"
    "  stop       Stop lapdog (started by 'lapdog start' or 'lapdog claude')\n"
    "  status     Show lapdog status (from /info)\n"
    "  claude     Start lapdog in background if needed, then launch Claude with intercept\n"
    "  pi         Start lapdog in background if needed, install extension, then launch pi\n"
    "  codex      Start lapdog in background if needed, then launch Codex with tracing\n"
    "  uninstall  Stop lapdog and remove all state it wrote (~/.lapdog, Claude hooks, pi extension)\n"
    "\n"
    "Any other command is treated as an app to run with tracing instrumentation:\n"
    "  lapdog python app.py\n"
)

_PROXY_SESSION_WARNING_LINES = ["Keep Lapdog running; stopping it can break proxied model calls."]

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
        [claude_bin, "plugin", "marketplace", "remove", LAPDOG_MARKETPLACE_SOURCE]
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


def _read_pid_file(path: Optional[str] = None) -> Tuple[Optional[int], Optional[int]]:
    path = path or _pid_file_path()
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


def _start_lapdog(
    port: int, extra_args: Optional[List[str]] = None, forward_data: bool = False
) -> Tuple[int, int, str]:
    """Start lapdog in background with logs to the log file; wait until ready or exit on timeout. Return (process, log_path)."""
    log_path = _log_file_path()
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    args = [sys.executable, "-m", "ddapm_test_agent.agent", "--lapdog-mode"]

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


def cmd_stop(pid: Optional[int] = None) -> None:
    """Stop lapdog (started by 'lapdog start' or 'lapdog claude')."""
    if pid is None:
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


def cmd_exec(app_cmd: List[str], forward_data: bool) -> None:
    """Auto-start lapdog if needed, inject tracer env vars, then exec the app command. Never returns."""
    resolved = shutil.which(app_cmd[0])
    if not resolved:
        print(f"[lapdog] Command not found: {app_cmd[0]}", file=sys.stderr)
        sys.exit(1)

    _ensure_lapdog_running(forward_data)
    print(build_running_banner(data_type="application"))

    _, port = _read_pid_file()
    if port is None:
        print("[lapdog] Could not determine lapdog port.", file=sys.stderr)
        sys.exit(1)

    env = tracer_inject.build_instrumented_env(port=port)
    os.execvpe(resolved, app_cmd, env)


def cmd_claude(
    sub_cmd_args: List[str],
    forward_data: bool,
    install_plugin: bool,
) -> None:
    """Ensure lapdog is running in background, then launch Claude with intercept."""
    if install_plugin:
        _ensure_lapdog_claude_code_plugin_installed()
    _ensure_lapdog_running(forward_data, detached=True)
    print(build_running_banner(data_type="coding session", warning_lines=_PROXY_SESSION_WARNING_LINES))

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


def _codex_watcher_pid_file(log_dir: str, singleton_key: str) -> str:
    return os.path.join(log_dir, f"codex-watcher-{singleton_key}.pid")


def _codex_watcher_command(pid: int) -> Optional[str]:
    """Return the command line for a live watcher candidate, if it can be verified."""
    if os.name == "nt":
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            f'(Get-CimInstance Win32_Process -Filter "ProcessId = {int(pid)}").CommandLine',
        ]
    else:
        cmd = ["ps", "-p", str(pid), "-o", "command="]
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    command = result.stdout.strip()
    if result.returncode != 0 or not command:
        return None
    return command


def _arg_value(parts: List[str], flag: str) -> Optional[str]:
    try:
        idx = parts.index(flag)
    except ValueError:
        return None
    return parts[idx + 1] if idx + 1 < len(parts) else None


def _codex_watcher_matches(
    pid: int,
    parent_pid: Optional[int] = None,
    lapdog_url: Optional[str] = None,
    include_all_cwds: Optional[bool] = None,
) -> bool:
    """Return True when a live process matches the expected watcher metadata."""
    if not _process_exists(pid):
        return False
    command = _codex_watcher_command(pid)
    if not command:
        return False
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    if "lapdog.codex_watcher" not in parts:
        return False
    if parent_pid is not None and _arg_value(parts, "--parent-pid") != str(parent_pid):
        return False
    if lapdog_url is not None and _arg_value(parts, "--lapdog-url") != lapdog_url:
        return False
    if include_all_cwds is not None and ("--include-all-cwds" in parts) is not include_all_cwds:
        return False
    return True


def _codex_watcher_reusable(
    pid: int,
    parent_pid: int,
    lapdog_url: Optional[str] = None,
    include_all_cwds: Optional[bool] = None,
) -> bool:
    """Return True only when a pid file points at the expected watcher process.

    App watcher pid files can outlive the short `lapdog codex app` launcher, so
    PID existence alone is not enough: a recycled PID could point at an
    unrelated process. Validate the command line before reusing or terminating.
    """
    return _codex_watcher_matches(
        pid,
        parent_pid=parent_pid,
        lapdog_url=lapdog_url,
        include_all_cwds=include_all_cwds,
    )


def _terminate_codex_watcher(pid: int, pid_path: str, message: str) -> bool:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as exc:
        print(f"[lapdog] Failed to stop Codex watcher (PID {pid}): {exc}", file=sys.stderr)
        return False
    print(message, file=sys.stderr)
    try:
        os.remove(pid_path)
    except OSError:
        pass
    return True


def _stop_codex_watcher_pid_file(
    pid_path: str,
    parent_pid: int,
    lapdog_url: Optional[str] = None,
    include_all_cwds: Optional[bool] = None,
) -> None:
    """Terminate a verified watcher from a pid file and remove stale pid files."""
    existing_pid, _ = _read_pid_file(path=pid_path)
    if not existing_pid:
        return
    if not _process_exists(existing_pid):
        try:
            os.remove(pid_path)
        except OSError:
            pass
        return
    if not _codex_watcher_reusable(
        existing_pid,
        parent_pid,
        lapdog_url=lapdog_url,
        include_all_cwds=include_all_cwds,
    ):
        return
    _terminate_codex_watcher(
        existing_pid,
        pid_path,
        f"[lapdog] Replacing legacy Codex watcher for this app workspace (PID {existing_pid}).",
    )


def _stop_codex_watcher_singleton(
    singleton_key: str,
    parent_pid: int,
    lapdog_url: Optional[str] = None,
    include_all_cwds: Optional[bool] = None,
) -> None:
    """Stop one legacy app watcher identified by its singleton key."""
    log_dir = os.path.dirname(_log_file_path())
    pid_path = _codex_watcher_pid_file(log_dir, singleton_key)
    _stop_codex_watcher_pid_file(
        pid_path,
        parent_pid,
        lapdog_url=lapdog_url,
        include_all_cwds=include_all_cwds,
    )


def _stop_legacy_codex_app_watchers(port: int, parent_pid: int, keep_singleton_key: str) -> None:
    """Stop verified cwd-keyed app watchers after migrating to one all-cwd watcher."""
    log_dir = os.path.dirname(_log_file_path())
    try:
        filenames = os.listdir(log_dir)
    except OSError:
        return
    prefix = "codex-watcher-"
    suffix = ".pid"
    lapdog_url = f"http://localhost:{port}"
    for filename in filenames:
        if not filename.startswith(prefix) or not filename.endswith(suffix):
            continue
        singleton_key = filename[len(prefix) : -len(suffix)]
        if singleton_key == keep_singleton_key:
            continue
        _stop_codex_watcher_singleton(
            singleton_key,
            parent_pid,
            lapdog_url=lapdog_url,
            include_all_cwds=False,
        )


def _start_codex_watcher(
    port: int,
    proxy_session_key: Optional[str] = None,
    cwd: Optional[str] = None,
    parent_pid: Optional[int] = None,
    singleton_key: Optional[str] = None,
    include_all_cwds: bool = False,
) -> None:
    """Start the bundled Codex JSONL watcher for this working directory."""
    watcher_cwd = os.path.abspath(cwd or os.getcwd())
    watcher_parent_pid = parent_pid or os.getpid()
    log_path = _log_file_path()
    log_dir = os.path.dirname(log_path)
    os.makedirs(log_dir, exist_ok=True)
    lapdog_url = f"http://localhost:{port}"
    if singleton_key:
        pid_path = _codex_watcher_pid_file(log_dir, singleton_key)
        existing_pid, _ = _read_pid_file(path=pid_path)
        if existing_pid and _codex_watcher_reusable(
            existing_pid,
            watcher_parent_pid,
            lapdog_url=lapdog_url,
            include_all_cwds=include_all_cwds,
        ):
            print(
                f"[lapdog] Codex watcher already running for this app workspace (PID {existing_pid}).",
                flush=True,
            )
            return
        if existing_pid:
            if _codex_watcher_matches(existing_pid, lapdog_url=lapdog_url, include_all_cwds=include_all_cwds):
                _terminate_codex_watcher(
                    existing_pid,
                    pid_path,
                    f"[lapdog] Replacing stale Codex watcher for this app workspace (PID {existing_pid}).",
                )
            else:
                print(
                    f"[lapdog] Replacing stale Codex watcher for this app workspace (PID {existing_pid}).",
                    file=sys.stderr,
                )
    else:
        pid_path = None
    ready_path = os.path.join(log_dir, f"codex-watcher-{os.getpid()}.ready")
    try:
        os.unlink(ready_path)
    except OSError:
        pass
    args = [
        sys.executable,
        "-m",
        "lapdog.codex_watcher",
        "--lapdog-url",
        f"http://localhost:{port}",
        "--cwd",
        watcher_cwd,
        "--parent-pid",
        str(watcher_parent_pid),
        "--ready-file",
        ready_path,
    ]
    if proxy_session_key:
        args += ["--proxy-session-key", proxy_session_key]
    if include_all_cwds:
        args += ["--include-all-cwds", "--cursor-path", CODEX_APP_CURSOR_FILE]
    with open(log_path, "a") as log_file:
        process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    if pid_path:
        with open(pid_path, "w") as f:
            f.write(f"{process.pid}\n")
    deadline = time.time() + 2
    while time.time() < deadline:
        if os.path.exists(ready_path):
            return
        if process.poll() is not None:
            break
        time.sleep(0.05)
    print("[lapdog] Codex watcher did not confirm startup; continuing without startup confirmation.", file=sys.stderr)


def _run_codex(
    args: Optional[List[str]] = None, port: Optional[int] = None, proxy_session_key: Optional[str] = None
) -> None:
    """Exec the codex binary, forwarding arguments. Never returns."""
    if args is None:
        args = []
    codex_bin = shutil.which("codex")
    if not codex_bin:
        print("[lapdog] 'codex' not found in PATH", file=sys.stderr)
        sys.exit(1)
    env = os.environ.copy()
    proxy_args: List[str] = []
    if port is not None:
        proxy_path = f"/codex/proxy/{proxy_session_key}/v1" if proxy_session_key else "/codex/proxy/v1"
        base_url = f"http://localhost:{port}{proxy_path}"
        env["OPENAI_BASE_URL"] = base_url
        if env.get("OPENAI_API_KEY"):
            proxy_args = [
                "-c",
                'model_provider="openai-lapdog"',
                "-c",
                (
                    'model_providers.openai-lapdog={name="OpenAI via Lapdog",'
                    f' base_url="{base_url}", env_key="OPENAI_API_KEY", wire_api="responses"' + "}"
                ),
            ]
        else:
            print(
                "[lapdog] Codex proxy capture requires OPENAI_API_KEY; continuing with JSONL-only tracing.",
                file=sys.stderr,
            )
    os.execve(codex_bin, [codex_bin] + proxy_args + args, env)


def cmd_codex(sub_cmd_args: List[str], forward_data: bool) -> None:
    """Ensure lapdog is running, start the Codex JSONL watcher, then launch Codex."""
    port = _ensure_lapdog_running(forward_data, detached=True)
    if port is None:
        print("[lapdog] Could not determine lapdog port.", file=sys.stderr)
        sys.exit(1)
    app_mode = codex_args.is_app_command(sub_cmd_args)
    proxy_session_key = None if app_mode else uuid.uuid4().hex
    parent_pid = os.getpid()
    if app_mode:
        lapdog_pid, _ = _read_pid_file()
        parent_pid = lapdog_pid or parent_pid
    codex_cwd = codex_args.resolve_cwd(sub_cmd_args)
    if app_mode:
        _stop_legacy_codex_app_watchers(port, parent_pid, codex_args.app_watcher_key(port))
    _start_codex_watcher(
        port,
        proxy_session_key=proxy_session_key,
        cwd=codex_cwd,
        parent_pid=parent_pid,
        singleton_key=codex_args.app_watcher_key(port) if app_mode else None,
        include_all_cwds=app_mode,
    )

    print(build_running_banner(data_type="coding session", warning_lines=_PROXY_SESSION_WARNING_LINES))
    _run_codex(args=sub_cmd_args, port=port, proxy_session_key=proxy_session_key)


def cmd_uninstall() -> None:
    """Stops the lapdog server, removes ~/.lapdog directory, and uninstalls managed plugins"""

    # stop lapdog server
    pid, _ = _read_pid_file()
    if pid is not None:
        cmd_stop(pid=pid)

    # remove ~/.lapdog dir
    if os.path.isdir(LAPDOG_DIR):
        shutil.rmtree(LAPDOG_DIR, ignore_errors=True)
        print("[lapdog] Lapdog-related files under ~/.lapdog removed")

    # remove claude code plugin
    _uninstall_lapdog_claude_code_plugin()

    # remove pi extension
    if os.path.isfile(_PI_EXT_DEST):
        try:
            os.remove(_PI_EXT_DEST)
            print(f"[lapdog] Removed {_PI_EXT_DEST}.")
        except OSError as e:
            print(f"[lapdog] Failed to remove {_PI_EXT_DEST}: {e}", file=sys.stderr)

    print(
        "[lapdog] Lapdog cleanup complete. Now uninstall the package:\n"
        "[lapdog]   brew uninstall lapdog\n"
        "[lapdog]   pipx uninstall ddapm-test-agent\n"
        "[lapdog]   pip uninstall ddapm-test-agent"
    )

    


def _parse_command(cmd_args: List[str]) -> Tuple[List[str], List[str]]:
    lapdog_args: List[str] = []

    for arg_idx, arg in enumerate(cmd_args):
        if not arg.startswith("--"):
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
        "--no-plugin-install",
        dest="install_plugin",
        action="store_false",
        default=True,
        help=(
            "Skip auto-installing the 'lapdog' Claude Code plugin when running "
            f"'lapdog claude'. By default, lapdog runs 'claude plugin marketplace "
            f"add {LAPDOG_MARKETPLACE_SOURCE}' and 'claude plugin install "
            f"{LAPDOG_PLUGIN_NAME}' if the plugin is not already installed."
        ),
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
            install_plugin=lapdog_parsed_args.install_plugin,
        )
    elif sub_cmd == "pi":
        cmd_pi(sub_cmd_args=sub_cmd_args, forward_data=lapdog_parsed_args.forward)
    elif sub_cmd == "codex":
        cmd_codex(sub_cmd_args=sub_cmd_args, forward_data=lapdog_parsed_args.forward)
    elif sub_cmd == "uninstall":
        cmd_uninstall()


if __name__ == "__main__":
    main()
