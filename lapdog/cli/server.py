"""Start, stop, and status commands."""

import os
import signal
import sys
from typing import List
from typing import Optional

from lapdog.cli.ascii_art import build_status_banner
from lapdog.cli.runtime import http_get_status
from lapdog.cli.runtime import lapdog_alive
from lapdog.cli.runtime import log_file_path
from lapdog.cli.runtime import port_in_use
from lapdog.cli.runtime import read_pid_file
from lapdog.cli.runtime import remove_pid_file
from lapdog.cli.runtime import resolved_port
from lapdog.cli.runtime import start_lapdog
from lapdog.cli.runtime import url_for_port
from lapdog.model_pricing import refresh_price_file


def cmd_start(sub_cmd_args: List[str], forward_data: bool) -> None:
    """Start lapdog in background with Claude hooks enabled."""
    refresh_price_file()
    if lapdog_alive():
        pid, port = read_pid_file()
        url = url_for_port(port) if port else None
        print(f"[lapdog] Lapdog already running at {url}" + (f" (PID {pid})" if pid else ""), file=sys.stderr)
        return
    port = resolved_port(sys.argv[2:])
    if port_in_use(port):
        print(
            f"[lapdog] Port {port} is already in use (something is serving /info). "
            "Stop it first (e.g. 'lapdog stop') or use a different port.",
            file=sys.stderr,
        )
        sys.exit(1)
    pid, port, log_path = start_lapdog(port, sub_cmd_args, forward_data)

    print(f"[lapdog] Lapdog running at {url_for_port(port)} (pid={pid}, logs: {log_path})")


def cmd_stop(pid: Optional[int] = None) -> None:
    """Stop lapdog (started by 'lapdog start' or 'lapdog claude')."""
    if pid is None:
        pid, _ = read_pid_file()

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
    remove_pid_file()
    print("[lapdog] Lapdog stopped.")


def cmd_status() -> None:
    """Print lapdog status (from /info). Only works when lapdog was started by this CLI (pid file exists)."""
    pid, port = read_pid_file()
    if port is None:
        print(build_status_banner(is_running=False))
        sys.exit(1)
    url = url_for_port(port)
    try:
        status = http_get_status(url, timeout=2)
        if status >= 400:
            raise OSError(f"HTTP {status}")
        print(build_status_banner(port=port, pid=pid, logs_path=log_file_path()))
    except Exception as e:
        print(f"[lapdog] Lapdog not reachable at {url}: {e}", file=sys.stderr)
        sys.exit(1)
