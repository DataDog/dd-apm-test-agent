import json
import os
from typing import Any
from typing import Dict


def set_hidden_metadata(span: Dict[str, Any], **fields: Any) -> None:
    """Merge fields into ``span.meta.metadata._dd`` without replacing existing values."""
    span["meta"].setdefault("metadata", {}).setdefault("_dd", {}).update(fields)


def process_exists(pid: int) -> bool:
    """Return whether a process with this PID exists (one owned by another user counts)."""
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def format_bytes(size: float) -> str:
    """Format a byte count for people, e.g. ``512B``, ``1.5GB``, ``2.0TB``."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024 or unit == "TB":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def write_json_atomic(path: str, data: Any) -> None:
    """Write ``data`` as indented JSON to ``path`` via a temp file, creating the directory first."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
