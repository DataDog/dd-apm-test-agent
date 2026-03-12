"""CLI for lapdog subcommands: run, stop, status, claude."""
import os
import signal
import subprocess
import sys
import time
from typing import List
from typing import Optional
from typing import Tuple

import requests


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
    return os.environ.get("LAPDOG_PID_FILE", os.path.expanduser("~/.lapdog/lapdog.pid"))


def _log_file_path() -> str:
    return os.environ.get("LAPDOG_LOG_FILE", os.path.expanduser("~/.lapdog/lapdog.log"))


def _url_for_port(port: int) -> str:
    return f"http://127.0.0.1:{port}/info"


def _lapdog_url() -> Optional[str]:
    """URL for the lapdog we're managing (from pid file). Return None if no pid file or no port."""
    _, port = _read_pid_file()
    return _url_for_port(port) if port is not None else None


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
    except ProcessLookupError:
        return False
    except OSError:
        return False


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


def _port_in_use(port: Optional[int] = None) -> bool:
    """Return True if something is already serving /info on the given port. If port is None, use _resolved_port()."""
    if port is None:
        port = _resolved_port()
    try:
        r = requests.get(_url_for_port(port), timeout=1)
        return r.status_code == 200
    except Exception:
        return False


def cmd_run() -> None:
    """Start lapdog in background with Claude hooks enabled."""
    if _lapdog_alive():
        pid, _ = _read_pid_file()
        url = _lapdog_url()
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
    log_path = _log_file_path()
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w") as log_file:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "ddapm_test_agent.agent",
                "--enable-claude-code-hooks",
            ] + sys.argv[2:],
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    _write_pid_file(proc.pid, port)
    for _ in range(50):
        if _lapdog_alive():
            url = _lapdog_url()
            print(f"[lapdog] Lapdog running at {url} (pid={proc.pid}, logs: {_log_file_path()})")
            return
        time.sleep(0.2)
    print("[lapdog] Lapdog failed to start in time. Check logs:", log_path, file=sys.stderr)
    _remove_pid_file()
    try:
        proc.kill()
    except OSError:
        pass
    sys.exit(1)


def cmd_stop() -> None:
    """Stop lapdog (started by 'lapdog run' or 'lapdog claude')."""
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
        print("[lapdog] No lapdog running (start with 'lapdog run' or 'lapdog claude').", file=sys.stderr)
        sys.exit(1)
    try:
        r = requests.get(_url_for_port(port), timeout=2)
        r.raise_for_status()
        url = _url_for_port(port)
        print(f"[lapdog] Lapdog running at {url} (pid={pid}, logs: {_log_file_path()})", file=sys.stderr)
    except requests.RequestException as e:
        print(f"[lapdog] Lapdog not reachable at {_url_for_port(port)}: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_claude() -> None:
    """Ensure lapdog is running in background, then launch Claude with intercept."""
    if not _lapdog_alive():
        port = _resolved_port()
        if _port_in_use(port):
            print(
                f"[lapdog] Port {port} is already in use. Stop the existing lapdog instance first (e.g. 'lapdog stop').",
                file=sys.stderr,
            )
            sys.exit(1)
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "ddapm_test_agent.agent",
                "--enable-claude-code-hooks",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _write_pid_file(proc.pid, port)
        for _ in range(50):
            if _lapdog_alive():
                break
            time.sleep(0.2)
        else:
            print("[lapdog] Lapdog failed to start in time.", file=sys.stderr)
            _remove_pid_file()
            try:
                proc.kill()
            except OSError:
                pass
            sys.exit(1)
    from ddapm_test_agent.run import run_claude

    run_claude(sys.argv[2:])


def main() -> None:
    if len(sys.argv) < 2:
        print(
            "Usage: lapdog <command> [args...]\n"
            "  run     Start lapdog (background)\n"
            "  stop    Stop lapdog (started by 'lapdog run' or 'lapdog claude')\n"
            "  status  Show lapdog status (from /info)\n"
            "  claude  Start lapdog in background if needed, then launch Claude with intercept",
            file=sys.stderr,
        )
        sys.exit(0)
    sub = sys.argv[1].lower()
    if sub == "run":
        cmd_run()
    elif sub == "stop":
        cmd_stop()
    elif sub == "status":
        cmd_status()
    elif sub == "claude":
        cmd_claude()
    else:
        print(f"[lapdog] Unknown command: {sub}", file=sys.stderr)
        sys.exit(1)
