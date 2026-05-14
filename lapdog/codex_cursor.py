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


def save_cursor_atomic(path: Path, state: CursorState) -> None:
    state.saved_at = datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {"files": state.files, "saved_at": state.saved_at}
    body = json.dumps(payload, indent=2, sort_keys=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(body)
        os.replace(tmp, path)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
