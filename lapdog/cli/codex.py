"""Codex launcher and cleanup of watchers from previous installations."""

import os
import shlex
import shutil
import signal
import subprocess
import sys
from typing import List
from typing import Optional
import uuid

from lapdog import backfill_codex
from lapdog import codex_args
from lapdog.cli.ascii_art import build_running_banner
from lapdog.cli.codex_setup import install as install_codex_hooks
from lapdog.cli.os_runner import run
from lapdog.cli.runtime import _PROXY_SESSION_WARNING_LINES
from lapdog.cli.runtime import ensure_lapdog_running
from lapdog.cli.runtime import log_file_path
from lapdog.cli.runtime import process_exists
from lapdog.cli.runtime import read_pid_file


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


def _codex_watcher_matches(pid: int, lapdog_url: Optional[str] = None) -> bool:
    """Verify an old watcher before migration cleanup can terminate it."""
    if not process_exists(pid):
        return False
    command = _codex_watcher_command(pid)
    if not command:
        return False
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    return "lapdog.codex_watcher" in parts and (lapdog_url is None or _arg_value(parts, "--lapdog-url") == lapdog_url)


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


def _stop_all_codex_watchers(lapdog_url: Optional[str] = None) -> None:
    """Stop all running codex watcher processes found in the log directory."""
    log_dir = os.path.dirname(log_file_path())
    try:
        filenames = os.listdir(log_dir)
    except OSError:
        return
    prefix = "codex-watcher-"
    suffix = ".pid"
    for filename in filenames:
        if not filename.startswith(prefix) or not filename.endswith(suffix):
            continue
        pid_path = os.path.join(log_dir, filename)
        existing_pid, _ = read_pid_file(path=pid_path)
        if not existing_pid:
            continue
        if not _codex_watcher_matches(existing_pid):
            try:
                os.remove(pid_path)
            except OSError:
                pass
            continue
        if lapdog_url and not _codex_watcher_matches(existing_pid, lapdog_url=lapdog_url):
            continue
        _terminate_codex_watcher(
            existing_pid,
            pid_path,
            f"[lapdog] Stopped Codex watcher (PID {existing_pid}).",
        )


def _run_codex(
    args: Optional[List[str]] = None,
    port: Optional[int] = None,
    proxy_session_key: Optional[str] = None,
    session_token: Optional[str] = None,
    launch_bin: Optional[str] = None,
    capture_proxy: bool = True,
) -> None:
    """Exec the codex binary, forwarding arguments. Never returns."""
    if args is None:
        args = []

    launch_bin = launch_bin or shutil.which("codex")
    if not launch_bin:
        print("[lapdog] 'codex' not found in PATH", file=sys.stderr)
        sys.exit(1)
    env = os.environ.copy()
    for variable in ("CODEX_THREAD_ID", "PI_SESSION_ID", "LAPDOG_SESSION_TOKEN"):
        env.pop(variable, None)
    proxy_args: List[str] = []
    if port is not None:
        env["LAPDOG_URL"] = f"http://localhost:{port}"
    if capture_proxy and port is not None and launch_bin == shutil.which("codex"):
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
                "[lapdog] Codex proxy capture requires OPENAI_API_KEY; continuing with local session capture.",
                file=sys.stderr,
            )
    if session_token:
        env["LAPDOG_SESSION_TOKEN"] = session_token
    argv = [launch_bin] + proxy_args + args
    if port is not None and session_token:
        from lapdog.codex_launch import run as run_capture

        run_capture(argv, env, port, session_token)
    else:
        run(bin_path=launch_bin, argv=argv, env=env)


def cmd_codex(
    sub_cmd_args: List[str],
    forward_data: bool,
    backfill: bool = False,
    launch_bin: Optional[str] = None,
    capture_proxy: bool = True,
) -> None:
    """Ensure Lapdog is running, configure hook capture, then launch Codex.

    Set ``capture_proxy`` to False to preserve an externally configured provider.

    When ``backfill`` is True: ensure lapdog is running, replay historical
    rollouts from ``~/.codex/sessions`` through ``/codex/hooks``, and exit
    without launching Codex. ``forward_data`` is ignored (forced off) so a
    backfill never accidentally streams thousands of historical spans to
    Datadog.
    """
    if backfill:
        port = ensure_lapdog_running(forward_data=False, detached=True)
        if port is None:
            print("[lapdog] Could not determine lapdog port.", file=sys.stderr)
            sys.exit(1)
        backfill_codex.backfill(f"http://localhost:{port}", cwd=codex_args.resolve_cwd(sub_cmd_args))
        return

    port = ensure_lapdog_running(forward_data, detached=True)
    if port is None:
        print("[lapdog] Could not determine lapdog port.", file=sys.stderr)
        sys.exit(1)
    session_token = uuid.uuid4().hex
    if codex_args.is_app_command(sub_cmd_args):
        from lapdog.cli.codex_desktop import launch

        try:
            launch(codex_args.resolve_cwd(sub_cmd_args), port, session_token)
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            print(f"[lapdog] {exc}", file=sys.stderr)
            sys.exit(1)
        return
    proxy_session_key = session_token
    try:
        install_codex_hooks(port, launch_bin or "")
    except RuntimeError as exc:
        print(f"[lapdog] {exc}", file=sys.stderr)
        sys.exit(1)
    _stop_all_codex_watchers(lapdog_url=f"http://localhost:{port}")

    print(build_running_banner(data_type="coding session", warning_lines=_PROXY_SESSION_WARNING_LINES))
    _run_codex(
        args=sub_cmd_args,
        port=port,
        proxy_session_key=proxy_session_key,
        session_token=session_token,
        launch_bin=launch_bin,
        capture_proxy=capture_proxy,
    )
