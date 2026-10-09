"""Codex launcher and watcher management."""

import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
import uuid

from lapdog import backfill_codex
from lapdog import codex_args
from lapdog.cli.ascii_art import build_running_banner
from lapdog.cli.os_runner import run
from lapdog.cli.runtime import _PROXY_SESSION_WARNING_LINES
from lapdog.cli.runtime import ensure_lapdog_running
from lapdog.cli.runtime import log_file_path
from lapdog.cli.runtime import process_exists
from lapdog.cli.runtime import read_pid_file
from lapdog.paths import CODEX_APP_CURSOR_FILE


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
    proxy_session_key: Optional[str] = None,
) -> bool:
    """Return True when a live process matches the expected watcher metadata."""
    if not process_exists(pid):
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
    if proxy_session_key is not None:
        actual_proxy_session_key = _arg_value(parts, "--proxy-session-key")
        if proxy_session_key:
            if actual_proxy_session_key != proxy_session_key:
                return False
        elif actual_proxy_session_key is not None:
            return False
    return True


def _codex_watcher_reusable(
    pid: int,
    parent_pid: int,
    lapdog_url: Optional[str] = None,
    include_all_cwds: Optional[bool] = None,
    proxy_session_key: Optional[str] = None,
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
        proxy_session_key=proxy_session_key,
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
    existing_pid, _ = read_pid_file(path=pid_path)
    if not existing_pid:
        return
    if not process_exists(existing_pid):
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
    log_dir = os.path.dirname(log_file_path())
    pid_path = _codex_watcher_pid_file(log_dir, singleton_key)
    _stop_codex_watcher_pid_file(
        pid_path,
        parent_pid,
        lapdog_url=lapdog_url,
        include_all_cwds=include_all_cwds,
    )


def _stop_all_codex_watchers() -> None:
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
        _terminate_codex_watcher(
            existing_pid,
            pid_path,
            f"[lapdog] Stopped Codex watcher (PID {existing_pid}).",
        )


def _stop_legacy_codex_app_watchers(port: int, parent_pid: int, keep_singleton_key: str) -> None:
    """Stop verified cwd-keyed app watchers after migrating to one all-cwd watcher."""
    log_dir = os.path.dirname(log_file_path())
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
    resume_mode: bool = False,
    resume_session_id: Optional[str] = None,
    resume_all_cwds: bool = False,
) -> None:
    """Start the bundled Codex JSONL watcher for this working directory."""
    watcher_cwd = os.path.abspath(cwd or os.getcwd())
    watcher_parent_pid = parent_pid or os.getpid()
    log_path = log_file_path()
    log_dir = os.path.dirname(log_path)
    os.makedirs(log_dir, exist_ok=True)
    lapdog_url = f"http://localhost:{port}"
    expected_proxy_session_key = "" if include_all_cwds and proxy_session_key is None else proxy_session_key
    if singleton_key:
        pid_path = _codex_watcher_pid_file(log_dir, singleton_key)
        existing_pid, _ = read_pid_file(path=pid_path)
        if existing_pid and _codex_watcher_reusable(
            existing_pid,
            watcher_parent_pid,
            lapdog_url=lapdog_url,
            include_all_cwds=include_all_cwds,
            proxy_session_key=expected_proxy_session_key,
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
    if resume_mode:
        args += ["--resume"]
        if resume_session_id:
            args += ["--resume-session-id", resume_session_id]
        if resume_all_cwds:
            args += ["--resume-all-cwds"]
    with open(log_path, "a") as log_file:
        popen_kwargs: Dict[str, Any] = {"stdin": subprocess.DEVNULL, "stdout": log_file, "stderr": subprocess.STDOUT}

        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True

        process = subprocess.Popen(args, **popen_kwargs)
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
    args: Optional[List[str]] = None,
    port: Optional[int] = None,
    proxy_session_key: Optional[str] = None,
    session_token: Optional[str] = None,
) -> None:
    """Exec the codex binary, forwarding arguments. Never returns."""
    if args is None:
        args = []
    codex_bin = shutil.which("codex")
    if not codex_bin:
        print("[lapdog] 'codex' not found in PATH", file=sys.stderr)
        sys.exit(1)
    env = os.environ.copy()
    for variable in ("CODEX_THREAD_ID", "PI_SESSION_ID", "LAPDOG_SESSION_TOKEN"):
        env.pop(variable, None)
    proxy_args: List[str] = []
    if port is not None:
        proxy_path = f"/codex/proxy/{proxy_session_key}/v1" if proxy_session_key else "/codex/proxy/v1"
        base_url = f"http://localhost:{port}{proxy_path}"
        env["OPENAI_BASE_URL"] = base_url
        env["LAPDOG_URL"] = f"http://localhost:{port}"
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
    if session_token:
        env["LAPDOG_SESSION_TOKEN"] = session_token
    run(bin_path=codex_bin, argv=([codex_bin] + proxy_args + args), env=env)


def cmd_codex(sub_cmd_args: List[str], forward_data: bool, backfill: bool = False) -> None:
    """Ensure lapdog is running, start the Codex JSONL watcher, then launch Codex.

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
    app_mode = codex_args.is_app_command(sub_cmd_args)
    resume_mode, resume_session_id, resume_all_cwds = codex_args.resume_options(sub_cmd_args)
    session_token = uuid.uuid4().hex
    proxy_session_key = None if app_mode else session_token
    parent_pid = os.getpid()
    if app_mode:
        lapdog_pid, _ = read_pid_file()
        parent_pid = lapdog_pid or parent_pid
    codex_cwd = codex_args.resolve_cwd(sub_cmd_args)
    if app_mode:
        _stop_legacy_codex_app_watchers(port, parent_pid, codex_args.app_watcher_key(port))
    watcher_kwargs: Dict[str, Any] = {
        "proxy_session_key": proxy_session_key,
        "cwd": codex_cwd,
        "parent_pid": parent_pid,
        "singleton_key": codex_args.app_watcher_key(port) if app_mode else None,
        "include_all_cwds": app_mode,
    }
    if resume_mode:
        watcher_kwargs.update(
            resume_mode=True,
            resume_session_id=resume_session_id,
            resume_all_cwds=resume_all_cwds,
        )
    _start_codex_watcher(port, **watcher_kwargs)

    print(build_running_banner(data_type="coding session", warning_lines=_PROXY_SESSION_WARNING_LINES))
    _run_codex(
        args=sub_cmd_args,
        port=port,
        proxy_session_key=proxy_session_key,
        session_token=session_token,
    )
