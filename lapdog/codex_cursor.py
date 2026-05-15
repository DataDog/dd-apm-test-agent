"""Atomic on-disk offset cursor for the Codex rollout watcher.

Mirrors trajectory's ``codex/watcher/cursor.go``: tracks the next-unread byte
offset per rollout file so the watcher can resume after a mid-session restart
without dropping or duplicating records.
"""

from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Dict


@dataclass
class CursorState:
    files: Dict[str, int] = field(default_factory=dict)
    saved_at: str = ""


def load_cursor(path: Path) -> CursorState:
    try:
        data = path.read_text()
    except FileNotFoundError:
        return CursorState()
    except OSError:
        return CursorState()
    try:
        parsed = json.loads(data) if data.strip() else {}
    except json.JSONDecodeError:
        return CursorState()
    if not isinstance(parsed, dict):
        return CursorState()
    files_raw = parsed.get("files")
    files: Dict[str, int] = {}
    if isinstance(files_raw, dict):
        for key, value in files_raw.items():
            if isinstance(key, str) and isinstance(value, int) and value >= 0:
                files[key] = value
    saved_at = parsed.get("saved_at", "")
    if not isinstance(saved_at, str):
        saved_at = ""
    return CursorState(files=files, saved_at=saved_at)


def save_cursor_atomic(path: Path, state: CursorState, prune_missing: bool = False) -> None:
    state.saved_at = datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_file = lock_path.open("a")
    tmp_path = ""
    try:
        try:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass

        merged = load_cursor(path)
        merged.files.update(state.files)
        if prune_missing:
            merged.files = {file_path: offset for file_path, offset in merged.files.items() if Path(file_path).exists()}
        merged.saved_at = state.saved_at
        state.files = dict(merged.files)
        payload = {"files": merged.files, "saved_at": merged.saved_at}
        body = json.dumps(payload, indent=2, sort_keys=True)
        with tempfile.NamedTemporaryFile(
            "w",
            dir=str(path.parent),
            prefix=f"{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(body)
            tmp_path = tmp.name
        os.replace(tmp_path, path)
    finally:
        try:
            lock_file.close()
        except OSError:
            pass
        try:
            if tmp_path and Path(tmp_path).exists():
                Path(tmp_path).unlink()
        except OSError:
            pass
