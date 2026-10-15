"""Install only Lapdog's Codex hook handlers, preserving other registrations."""

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

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


def configure(command: str = "") -> Path:
    """Replace managed handlers; an empty command removes them."""
    path = hooks_path()
    config = json.loads(path.read_text()) if path.exists() else {}
    original = json.dumps(config, sort_keys=True)
    hooks = config.setdefault("hooks", {}) if command else config.get("hooks", {})
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
    if command:
        handler = {"type": "command", "command": command, "timeout": 30, "statusMessage": MARKER}
        for event in EVENTS:
            hooks.setdefault(event, []).append({"hooks": [handler]})
    if json.dumps(config, sort_keys=True) != original:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.lapdog-tmp")
        temporary.write_text(json.dumps(config, indent=2) + "\n")
        temporary.replace(path)
    return path


def install(port: int, binary: str = "") -> None:
    if not supported(binary or shutil.which("codex") or "codex"):
        raise RuntimeError("Lapdog requires Codex CLI 0.124.0 or later. Upgrade Codex to use hook capture.")
    try:
        argv = [sys.executable, "-m", "lapdog.codex_hook", "--url", f"http://localhost:{port}"]
        path = configure(subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv))
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        raise RuntimeError(f"Cannot install Codex hooks in {hooks_path()}: {exc}") from exc
    print(
        f"[lapdog] Hook capture configured in {path}. Review and trust Lapdog hooks with /hooks in Codex.",
        file=sys.stderr,
    )


def uninstall() -> None:
    path = hooks_path()
    if path.exists():
        configure()
        print(f"[lapdog] Cleared Lapdog Codex hook registrations from {path}.")
    else:
        print(f"[lapdog] No Codex hooks file at {path}; nothing to remove.")
