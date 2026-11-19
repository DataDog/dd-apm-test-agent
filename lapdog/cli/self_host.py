"""``lapdog server``: start, stop, status, and config for the ClickHouse-backed Self-hosted lapdog server."""

import argparse
import json
import os
import signal
import sys
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
import urllib.error

from lapdog.cli.runtime import abandon_start
from lapdog.cli.runtime import http_request
from lapdog.cli.runtime import process_exists
from lapdog.cli.runtime import read_pid_file
from lapdog.cli.runtime import remove_pid_file
from lapdog.cli.runtime import start_background
from lapdog.cli.runtime import wait_until_ready
from lapdog.cli.runtime import write_pid_file
from lapdog.paths import SERVER_DIR
from lapdog.self_host.clickhouse import ClickHouseError
from lapdog.self_host.clickhouse import ensure_binary
from lapdog.self_host.config import Settings
from lapdog.self_host.config import add_server_arguments
from lapdog.self_host.config import config_from_args
from lapdog.self_host.config import load_settings
from lapdog.self_host.config import parse_settings_update
from lapdog.self_host.config import save_settings
from lapdog.self_host.config import settings_to_json
from lapdog.utils import format_bytes

SERVER_USAGE = (
    "Usage: lapdog server <start|stop|status|config> [options]\n"
    "\n"
    "  start [--foreground] [--host H] [--port P] [--retention 30d] [--max-disk 20GB] ...\n"
    "                       Start the Self-hosted server (ClickHouse-backed). 'lapdog server start --help' for all flags\n"
    "  stop                 Stop the Self-hosted server\n"
    "  status               Show disk usage, retention, and health\n"
    "  config get           Show retention and max disk\n"
    "  config set KEY VAL   Change 'retention' (e.g. 14d) or 'max-disk' (e.g. 50GB); applied live if running\n"
    "\n"
    "Every command takes --data-dir (default ~/.lapdog/server, or LAPDOG_SERVER_DATA_DIR).\n"
)

_STARTUP_TIMEOUT = 90.0


def _data_dir(value: str) -> str:
    return os.path.abspath(os.path.expanduser(value))


def _pid_path(data_dir: str) -> str:
    return os.path.join(data_dir, "server.pid")


def _log_path(data_dir: str) -> str:
    return os.path.join(data_dir, "server.log")


def _local_url(host: str, port: int) -> str:
    connect_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    if ":" in connect_host:
        connect_host = f"[{connect_host}]"
    return f"http://{connect_host}:{port}"


def _request(url: str, body: Optional[Dict[str, Any]] = None, timeout: float = 5) -> Any:
    """Return the parsed JSON response, or the plain text one (``/ping`` answers text)."""
    text = http_request(url, body, timeout)
    return json.loads(text) if text.startswith(("{", "[")) else text


def _answers_ping(url: str, timeout: float) -> bool:
    try:
        _request(f"{url}/ping", timeout=timeout)
    except (OSError, ValueError):
        return False
    return True


def _running(data_dir: str) -> Tuple[Optional[int], Optional[str]]:
    """Return the server's PID, and its base URL if it is answering ``/ping``."""
    pid_path = _pid_path(data_dir)
    pid, port = read_pid_file(pid_path)
    if pid is None or port is None or not process_exists(pid):
        return None, None
    host = "127.0.0.1"
    try:
        with open(pid_path) as f:
            lines = f.read().splitlines()
        if len(lines) > 2 and lines[2].strip():
            host = lines[2].strip()
    except OSError:
        pass
    url = _local_url(host, port)
    if not _answers_ping(url, timeout=2):
        return pid, None
    return pid, url


def _write_pid_file(data_dir: str, pid: int, port: int, host: str) -> None:
    write_pid_file(_pid_path(data_dir), pid, port, host)


def _remove_pid_file(data_dir: str, only_pid: Optional[int] = None) -> None:
    """Remove the PID file, if present; with ``only_pid``, only when it still names that process."""
    if only_pid is not None and read_pid_file(_pid_path(data_dir))[0] != only_pid:
        return
    remove_pid_file(_pid_path(data_dir))


def _print_started(url: str, pid: int, args: argparse.Namespace, data_dir: str) -> None:
    settings = load_settings(data_dir)
    public = args.host not in ("127.0.0.1", "localhost", "::1")
    server_url = f"http://<this-host>:{args.port}" if public else url
    print(f"[lapdog] Lapdog server running at {url} (pid={pid}, logs: {_log_path(data_dir)})")
    if settings:
        print(
            f"[lapdog] Data in {data_dir}, retention {settings.retention_days}d, "
            f"max disk {format_bytes(settings.max_disk_bytes)}"
        )
    print("[lapdog] Forward a laptop's lapdog here with:")
    print(f"  lapdog forward {server_url}")
    if public:
        print("[lapdog] The server has no auth: anyone who can reach it can read and send spans.")
        print("[lapdog] Put it behind your own auth proxy or firewall.")


def cmd_server_start(argv: List[str]) -> None:
    parser = argparse.ArgumentParser(prog="lapdog server start", description="Start the Self-hosted lapdog server")
    add_server_arguments(parser)
    parser.add_argument("--foreground", action="store_true", help="Run in the foreground (for Docker and services)")
    args = parser.parse_args(argv)

    data_dir = _data_dir(args.data_dir)
    pid, url = _running(data_dir)
    if url:
        print(f"[lapdog] Lapdog server already running at {url} (PID {pid})", file=sys.stderr)
        if args.foreground:
            sys.exit(1)
        return

    if args.foreground:
        from lapdog.self_host.__main__ import main as server_main

        # Record this process so 'lapdog server status|stop|config' find a foreground server too.
        os.makedirs(data_dir, exist_ok=True)
        _write_pid_file(data_dir, os.getpid(), args.port, args.host)
        try:
            code = server_main([a for a in argv if a != "--foreground"])
        finally:
            _remove_pid_file(data_dir, only_pid=os.getpid())
        sys.exit(code)
    try:
        config_from_args(args)  # validate flags and save settings before detaching
        binary = ensure_binary(args.clickhouse_binary)
    except (ValueError, ClickHouseError, OSError) as e:
        print(f"[lapdog] {e}", file=sys.stderr)
        sys.exit(1)

    child_args = [a for a in argv if a != "--foreground"]
    if not args.clickhouse_binary:
        child_args += ["--clickhouse-binary", binary]
    if "--data-dir" not in child_args:
        child_args += ["--data-dir", data_dir]
    proc = start_background(
        [sys.executable, "-m", "lapdog.self_host", *child_args], _log_path(data_dir), append_log=True
    )
    _write_pid_file(data_dir, proc.pid, args.port, args.host)

    url = _local_url(args.host, args.port)
    if wait_until_ready(proc, lambda: _answers_ping(url, timeout=1), _STARTUP_TIMEOUT, interval=0.3):
        _print_started(url, proc.pid, args, data_dir)
        return
    if proc.poll() is not None:
        message = f"[lapdog] Lapdog server exited (code {proc.returncode}); see {_log_path(data_dir)}"
        abandon_start(proc, message, pid_path=_pid_path(data_dir))
    # SIGTERM, so the server stops its ClickHouse on the way out.
    message = f"[lapdog] Lapdog server did not start within {_STARTUP_TIMEOUT:.0f}s; see {_log_path(data_dir)}"
    abandon_start(proc, message, force=False)


def cmd_server_stop(data_dir: str) -> None:
    pid, _ = read_pid_file(_pid_path(data_dir))
    if pid is None or not process_exists(pid):
        print("[lapdog] Lapdog server is not running.", file=sys.stderr)
        _remove_pid_file(data_dir)
        sys.exit(1)
    os.kill(pid, signal.SIGTERM)
    # The server stops ClickHouse on the way out; wait so a restart doesn't race it for the data directory.
    deadline = time.monotonic() + 30
    while process_exists(pid) and time.monotonic() < deadline:
        time.sleep(0.2)
    if process_exists(pid):
        os.kill(pid, signal.SIGKILL)
    # A foreground server removes its own PID file on the way out.
    _remove_pid_file(data_dir)
    print("[lapdog] Lapdog server stopped.")


def cmd_server_status(data_dir: str) -> None:
    pid, url = _running(data_dir)
    if not url:
        print("[lapdog] Lapdog server is not running." if pid is None else f"[lapdog] PID {pid} is not answering.")
        sys.exit(1)
    try:
        status = _request(f"{url}/api/lapdog/server/status")
    except urllib.error.HTTPError as e:
        print(f"[lapdog] Status request failed: HTTP {e.code}", file=sys.stderr)
        sys.exit(1)
    disk = status["disk"]
    settings = status["settings"]
    print(f"Lapdog server  {url}  (pid {pid})")
    print(f"  Data dir     {data_dir}")
    print(f"  Retention    {settings['retention']}  (stored days: {status['oldest_day']} to {status['newest_day']})")
    print(
        f"  Disk         {format_bytes(disk['used_bytes'])} used of {settings['max_disk']} cap"
        f"  ({format_bytes(disk['free_bytes'])} free on disk)"
    )
    print(f"  Span rows    {status['span_rows']}")
    print(f"  Ingest       {'PAUSED (' + str(status['pause_reason']) + ')' if status['ingest_paused'] else 'ok'}")
    ch = status["clickhouse"]
    print(f"  ClickHouse   {ch['version']}  pid {ch['pid']}  {'healthy' if ch['healthy'] else 'UNHEALTHY'}")
    action = status.get("last_action")
    if action:
        dropped = ", ".join(f"{d['partition']} ({d['reason']})" for d in action["dropped_partitions"])
        print(f"  Last cleanup {action['at']}: dropped {dropped}")


def cmd_server_config(argv: List[str], data_dir: str) -> None:
    if not argv or argv[0] not in ("get", "set") or (argv[0] == "set" and len(argv) != 3):
        print(SERVER_USAGE, file=sys.stderr)
        sys.exit(2)
    _, url = _running(data_dir)
    if argv[0] == "get":
        settings_json = _request(f"{url}/api/lapdog/server/settings") if url else None
        if settings_json is None:
            saved = load_settings(data_dir)
            if saved is None:
                print("[lapdog] No lapdog server settings yet; run 'lapdog server start' first.", file=sys.stderr)
                sys.exit(1)
            settings_json = settings_to_json(saved)
        print(f"retention  {settings_json['retention']}\nmax-disk   {settings_json['max_disk']}")
        return

    key = {"retention": "retention", "max-disk": "max_disk", "max_disk": "max_disk"}.get(argv[1])
    if key is None:
        print(f"[lapdog] Unknown setting {argv[1]!r}; expected 'retention' or 'max-disk'.", file=sys.stderr)
        sys.exit(2)
    if url:
        try:
            result = _request(f"{url}/api/lapdog/server/settings", body={key: argv[2]})
        except urllib.error.HTTPError as e:
            print(f"[lapdog] {json.loads(e.read().decode()).get('error', e)}", file=sys.stderr)
            sys.exit(1)
        dropped = result["enforcement"]["dropped_partitions"]
        print(
            f"[lapdog] Updated: retention {result['settings']['retention']}, max disk {result['settings']['max_disk']}"
        )
        if dropped:
            print(f"[lapdog] Dropped {len(dropped)} day(s) of spans to apply it.")
        return
    current = load_settings(data_dir) or Settings(30, 20 * 1024**3)
    try:
        settings = parse_settings_update({key: argv[2]}, current)
    except ValueError as e:
        print(f"[lapdog] {e}", file=sys.stderr)
        sys.exit(1)
    save_settings(data_dir, settings)
    applied = settings_to_json(settings)
    print(f"[lapdog] Saved: retention {applied['retention']}, max disk {applied['max_disk']} (applies on next start)")


def cmd_server(sub_cmd_args: List[str]) -> None:
    if not sub_cmd_args or sub_cmd_args[0] in ("-h", "--help", "help"):
        print(SERVER_USAGE)
        sys.exit(0 if sub_cmd_args else 1)
    action, rest = sub_cmd_args[0], sub_cmd_args[1:]
    if action == "start":
        cmd_server_start(rest)
        return

    parser = argparse.ArgumentParser(prog=f"lapdog server {action}", add_help=False)
    parser.add_argument("--data-dir", default=os.environ.get("LAPDOG_SERVER_DATA_DIR") or SERVER_DIR)
    known, extra = parser.parse_known_args(rest)
    data_dir = _data_dir(known.data_dir)
    if action == "stop":
        cmd_server_stop(data_dir)
    elif action == "status":
        cmd_server_status(data_dir)
    elif action == "config":
        cmd_server_config(extra, data_dir)
    else:
        print(SERVER_USAGE, file=sys.stderr)
        sys.exit(2)
