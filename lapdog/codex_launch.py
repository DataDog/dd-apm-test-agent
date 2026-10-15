"""Identify terminal-owned sessions without changing Codex's backend selection."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from typing import Any
from typing import Iterator

from lapdog.codex_registration import RegistrationClient


def owns_process(root_pid: int, pid: int) -> bool:
    """Check current ancestry; detached shared daemons are not launcher children."""
    try:
        if os.name == "nt":
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,CommandLine | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
                timeout=3,
                check=True,
            )
            processes = {
                int(p["ProcessId"]): (int(p["ParentProcessId"]), p.get("CommandLine") or "")
                for p in json.loads(result.stdout)
            }
        else:
            result = subprocess.run(
                ["ps", "-axo", "pid=,ppid=,args="],
                capture_output=True,
                text=True,
                timeout=3,
                check=True,
            )
            processes = {
                int(parts[0]): (int(parts[1]), parts[2])
                for line in result.stdout.splitlines()
                if len(parts := line.split(None, 2)) == 3
            }
        seen = set()
        while pid > 1 and pid not in seen:
            if pid == root_pid:
                return True
            seen.add(pid)
            parent, command = processes.get(pid, (0, ""))
            if "app-server" in command.split() or "--managed-daemon" in command.split():
                return False
            pid = parent
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        pass
    return False


def records(path: str) -> Iterator[dict[str, Any]]:
    """Read complete JSON records only; Codex can be appending concurrently."""
    try:
        with open(path, encoding="utf-8") as source:
            for line in source:
                if not line.endswith("\n"):
                    break
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if isinstance(value, dict):
                    yield value
    except (OSError, UnicodeError):
        return


def matches_terminal(log_path: str, transcript_path: str, turn_id: str, sid: str) -> bool:
    ids = set()
    for record in records(log_path):
        payload = record.get("payload", {})
        if isinstance(payload, dict):
            message = payload.get("UserTurn", {})
            if isinstance(message, dict) and isinstance(message.get("client_user_message_id"), str):
                ids.add(message["client_user_message_id"])
    if not ids or not turn_id:
        return False
    current_turn = ""
    for record in records(transcript_path):
        payload = record.get("payload", {})
        if not isinstance(payload, dict):
            continue
        if record.get("type") == "session_meta" and payload.get("id") != sid:
            return False
        if record.get("type") == "turn_context":
            current_turn = payload.get("turn_id", "")
        if payload.get("turn_id", current_turn) != turn_id:
            continue
        item = payload.get("item", {}) if payload.get("type") == "item_completed" else payload
        if (
            isinstance(item, dict)
            and item.get("type") in ("UserMessage", "user_message")
            and isinstance(item.get("client_id"), str)
            and item.get("client_id") in ids
        ):
            return True
    return False


def run(argv: list[str], env: dict[str, str], port: int, owner: str) -> None:
    """Keep a launch registration alive while Codex retains normal terminal I/O."""
    with tempfile.TemporaryDirectory(prefix="lapdog-codex-") as directory:
        log_path = str(Path(directory) / "terminal.jsonl")
        env = {**env, "CODEX_TUI_RECORD_SESSION": "1", "CODEX_TUI_SESSION_LOG_PATH": log_path}
        shell = sys.platform == "win32" and os.path.splitext(argv[0])[1].lower() in (".cmd", ".bat")
        child = subprocess.Popen(argv, env=env, shell=shell)
        registry = RegistrationClient(f"http://localhost:{port}", owner, pid=child.pid, log_path=log_path)
        previous = signal.signal(signal.SIGTERM, lambda *_: child.terminate())
        try:
            with registry.keepalive():
                while True:
                    try:
                        code = child.wait()
                        break
                    except KeyboardInterrupt:
                        # The foreground child receives Ctrl+C as well. Let Codex
                        # cancel the turn without terminating the capture launcher.
                        continue
        finally:
            signal.signal(signal.SIGTERM, previous)
        sys.exit(code if code >= 0 else 128 - code)
