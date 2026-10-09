"""Shared server startup and status helpers."""

import os
import subprocess
import sys
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
import urllib.request

from ddapm_test_agent import _get_version
from lapdog.model_pricing import refresh_price_file
from lapdog.paths import LOG_FILE
from lapdog.paths import PID_FILE


# Managed launchers can also be invoked through an explicit binary path.
_PATH_ROUTABLE_LAUNCHERS = ("claude", "pi", "codex")
_PROXY_SESSION_WARNING_LINES = ["Keep Lapdog running; stopping it can break proxied model calls."]


def resolved_port(cli_args: Optional[List[str]] = None) -> int:
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


def log_file_path() -> str:
    return os.environ.get("LAPDOG_LOG_FILE", LOG_FILE)


def url_for_port(port: int) -> str:
    return f"http://127.0.0.1:{port}/info"


def http_get_status(url: str, timeout: float) -> int:
    """GET url and return the HTTP status code.

    Uses an empty ProxyHandler so macOS _scproxy.get_proxy_settings is never
    called.  That call crashes inside a forked child on Python 3.13 / macOS
    because the parent process has internal threads at fork time, leaving
    CoreFoundation's logging lock state corrupt in the child.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as resp:
        return int(resp.status)


def lapdog_alive(timeout: float = 2.0) -> bool:
    """Check if the lapdog we started is running (pid file + process exists + /info responds)."""
    pid, port = read_pid_file()
    if pid is None or port is None:
        return False
    if not process_exists(pid):
        return False
    try:
        return http_get_status(url_for_port(port), timeout=timeout) == 200
    except Exception:
        return False


def read_pid_file(path: Optional[str] = None) -> Tuple[Optional[int], Optional[int]]:
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


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def ensure_lapdog_running(forward_data: bool = False, detached: bool = False) -> Optional[int]:
    """Start lapdog in background if it is not already running. Exits if the port is taken."""
    refresh_price_file()
    if lapdog_alive():
        _, port = read_pid_file()
        return port
    port = resolved_port()
    if port_in_use(port):
        print(
            f"[lapdog] Port {port} is already in use. Stop the existing lapdog instance first (e.g. 'lapdog stop').",
            file=sys.stderr,
        )
        sys.exit(1)

    if detached:
        _start_lapdog_detached(port, forward_data=forward_data)
    else:
        start_lapdog(port, forward_data=forward_data)

    return port


def _write_pid_file(pid: int, port: int) -> None:
    path = _pid_file_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(f"{pid}\n{port}\n")


def remove_pid_file() -> None:
    path = _pid_file_path()
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def start_lapdog(
    port: int, extra_args: Optional[List[str]] = None, forward_data: bool = False
) -> Tuple[int, int, str]:
    """Start lapdog in background with logs to the log file; wait until ready or exit on timeout. Return (process, log_path)."""
    log_path = log_file_path()
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    args = [sys.executable, "-m", "lapdog.server"]

    env = os.environ.copy()
    env["TEST_AGENT_VERSION"] = _get_version()

    if not forward_data:
        args.append("--disable-llmobs-data-forwarding")

    if extra_args:
        args += extra_args
    popen_kwargs: Dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stderr": subprocess.STDOUT,
    }
    if sys.platform == "win32":
        # On Windows, start_new_session is a no-op. Use creationflags to truly
        # detach the child so it survives after the launcher process exits.
        popen_kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True
    with open(log_path, "w") as log_file:
        proc = subprocess.Popen(args, stdout=log_file, env=env, **popen_kwargs)
    _write_pid_file(proc.pid, port)
    _wait_for_lapdog(proc, log_path)

    return proc.pid, port, log_path


def port_in_use(port: Optional[int] = None) -> bool:
    """Return True if something is already serving /info on the given port. If port is None, use resolved_port()."""
    if port is None:
        port = resolved_port()
    try:
        return http_get_status(url_for_port(port), timeout=1) == 200
    except Exception:
        return False


def _wait_for_lapdog(proc: "subprocess.Popen[bytes]", log_path: Optional[str] = None) -> None:
    """Wait up to ~10s for lapdog to start, then exit(1) on timeout."""
    for _ in range(50):
        if lapdog_alive():
            return
        time.sleep(0.2)
    msg = "[lapdog] Lapdog failed to start in time."
    if log_path:
        msg += f" Check logs: {log_path}"
    print(msg, file=sys.stderr)
    remove_pid_file()
    try:
        proc.kill()
    except OSError:
        pass
    sys.exit(1)


def _start_lapdog_detached(port: int, forward_data: bool) -> None:
    """Start lapdog in a forked child so it is not a child of the calling process.

    After os.execv replaces the current process with pi/claude, lapdog must not
    be a child of that process.  If it were, killing/restarting lapdog would
    send SIGCHLD to the agent which can crash the runtime.  By forking first
    and starting lapdog in the child, the child exits immediately after lapdog
    is ready and lapdog gets re-parented to init/launchd — fully independent of
    the process that will become pi/claude.

    On Windows there is no os.fork() and no SIGCHLD; the DETACHED_PROCESS /
    CREATE_NEW_PROCESS_GROUP creation flags passed inside start_lapdog already
    detach the child from the launcher, so we just call it directly.
    """
    if sys.platform == "win32":
        start_lapdog(port, forward_data=forward_data)
        return

    child_pid = os.fork()
    if child_pid == 0:
        # Child: start lapdog, wait for it to be ready, then exit.
        try:
            start_lapdog(port, forward_data=forward_data)
        except SystemExit:
            # start_lapdog may call sys.exit on failure
            os._exit(1)
        os._exit(0)

    # Parent: wait for the intermediate child to finish.
    _, status = os.waitpid(child_pid, 0)
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
        print("[lapdog] Failed to start lapdog in background.", file=sys.stderr)
        sys.exit(1)

    # The forked child's exit can briefly disrupt the listening socket. Wait
    # from the final parent too so immediate follow-up work, such as --backfill
    # preflight POSTs, does not race the re-parented server.
    for _ in range(50):
        if lapdog_alive(timeout=0.5):
            return
        time.sleep(0.2)
    print("[lapdog] Lapdog failed to become reachable after background start.", file=sys.stderr)
    sys.exit(1)
