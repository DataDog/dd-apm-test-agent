"""Install and remove globally approved Codex capture hooks."""

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
from typing import Optional

from lapdog.codex_hook import EVENTS

MARKER = "Lapdog session capture"


def hooks_path() -> Path:
    return Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "hooks.json"


def supported(binary: str) -> bool:
    try:
        result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5, check=False)
        match = re.search(r"codex-cli (\d+)\.(\d+)\.(\d+)", result.stdout)
        return result.returncode == 0 and match is not None and tuple(map(int, match.groups())) >= (0, 124, 0)
    except (OSError, subprocess.SubprocessError):
        return False


def configure(port: Optional[int] = None) -> Path:
    """Replace or remove Lapdog handlers, preserving other registrations."""
    path = hooks_path()
    config = json.loads(path.read_text()) if path.exists() else {}
    original = json.dumps(config, sort_keys=True)
    hooks = config.get("hooks", {})
    for event, groups in list(hooks.items()):
        kept = []
        for group in groups:
            handlers = [handler for handler in group.get("hooks", []) if handler.get("statusMessage") != MARKER]
            if handlers:
                kept.append({**group, "hooks": handlers})
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
    if port is not None:
        argv = [sys.executable, "-m", "lapdog.codex_hook", "--url", f"http://localhost:{port}", "--capture"]
        command = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
        config["hooks"] = hooks
        for event in EVENTS:
            hooks.setdefault(event, []).append(
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": command,
                            "timeout": 3 if event in ("SessionEnd", "Interrupt") else 30,
                            "statusMessage": MARKER,
                        }
                    ]
                }
            )
    if json.dumps(config, sort_keys=True) != original:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.lapdog-tmp")
        temporary.write_text(json.dumps(config, indent=2) + "\n")
        temporary.replace(path)
    return path


def install(port: int, binary: str = "") -> None:
    """Install global hooks without changing backend selection."""
    binary = binary or shutil.which("codex") or "codex"
    if not supported(binary):
        raise RuntimeError("Lapdog requires Codex CLI 0.124.0 or later. Upgrade Codex to use hook capture.")
    try:
        configure(port)
    except (OSError, ValueError, TypeError, AttributeError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"Cannot configure global hooks in {hooks_path()}: {exc}") from exc
    print(
        "[lapdog] Global hook capture configured. Review and trust Lapdog hooks with /hooks in Codex.",
        file=sys.stderr,
    )


def uninstall() -> None:
    path = hooks_path()
    if path.exists():
        configure()
        print(f"[lapdog] Cleared Lapdog Codex hook registrations from {path}.")
    else:
        print(f"[lapdog] No Codex hooks file at {path}; nothing to remove.")
