"""Pi launcher and extension management."""

import os
import shutil
import subprocess
import sys
from typing import List
from typing import Optional
from typing import Tuple
import uuid

from lapdog import backfill_pi
from lapdog.cli.ascii_art import build_running_banner
from lapdog.cli.os_runner import run
from lapdog.cli.runtime import ensure_lapdog_running
from lapdog.paths import LAPDOG_DIR


_PI_GLOBAL_EXT_DIR = os.path.expanduser("~/.pi/agent/extensions")
_PI_EXT_DEST = os.path.join(_PI_GLOBAL_EXT_DIR, "lapdog.ts")
_PI_EXT_SOURCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pi_lapdog_extension.ts")

# pi-context-inspector supplies the per-call context-window breakdown (see pi_lapdog_extension.ts).
_PI_CONTEXT_INSPECTOR_NAME = "pi-context-inspector"
_PI_CONTEXT_INSPECTOR_SOURCE = f"npm:{_PI_CONTEXT_INSPECTOR_NAME}@1.3.0"
_PI_CONTEXT_INSPECTOR_REMOVE_SOURCE = f"npm:{_PI_CONTEXT_INSPECTOR_NAME}"
_PI_CONTEXT_INSPECTOR_MODULE = os.path.join("src", "index.ts")
# Present only when lapdog installed the package, so uninstall leaves a user's own install alone.
_PI_CONTEXT_INSPECTOR_MARKER = os.path.join(LAPDOG_DIR, "pi-context-inspector-installed")
_PI_CONTEXT_INSPECTOR_INSTALL_TIMEOUT_S = 120
_PI_LIST_TIMEOUT_S = 30
_PI_PACKAGE_SOURCE_PREFIXES = ("npm:", "git:", "http://", "https://")


def _install_pi_extension() -> None:
    """Copy the bundled lapdog extension into pi's global extensions directory.

    If the extension is already installed and identical, skip the copy.
    Lapdog URL and session context are injected via environment variables when pi is launched.
    """
    if not os.path.isfile(_PI_EXT_SOURCE):
        print(f"[lapdog] Extension source not found: {_PI_EXT_SOURCE}", file=sys.stderr)
        sys.exit(1)

    with open(_PI_EXT_SOURCE, "r") as f:
        source = f.read()

    # Check if already installed and up-to-date.
    is_update = False
    if os.path.isfile(_PI_EXT_DEST):
        try:
            with open(_PI_EXT_DEST, "r") as f:
                existing = f.read()
            if existing == source:
                print(f"[lapdog] pi extension already installed at {_PI_EXT_DEST}")
                return
            is_update = True
        except OSError:
            pass

    os.makedirs(_PI_GLOBAL_EXT_DIR, exist_ok=True)
    with open(_PI_EXT_DEST, "w") as f:
        f.write(source)

    if is_update:
        print(f"[lapdog] Updated pi extension → {_PI_EXT_DEST}")
    else:
        print(f"[lapdog] Installed pi extension → {_PI_EXT_DEST}")


def _find_pi_context_inspector(pi_bin: str) -> Optional[Tuple[bool, Optional[str]]]:
    """Return (declared, module_path) for pi-context-inspector according to ``pi list``, or None if it can't run.

    ``pi list`` prints each declared package source followed by the directory Pi
    resolved it to, which may be the legacy global npm location rather than
    ~/.pi/agent/npm, so the path is taken from Pi instead of assumed.
    """
    try:
        result = subprocess.run([pi_bin, "list"], capture_output=True, text=True, timeout=_PI_LIST_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    for index, line in enumerate(lines):
        if not line.startswith(_PI_PACKAGE_SOURCE_PREFIXES) or _PI_CONTEXT_INSPECTOR_NAME not in line:
            continue
        install_dir = lines[index + 1] if index + 1 < len(lines) else ""
        module_path = os.path.join(install_dir, _PI_CONTEXT_INSPECTOR_MODULE) if os.path.isabs(install_dir) else None
        return True, module_path if module_path and os.path.isfile(module_path) else None
    return False, None


def _ensure_pi_context_inspector(launch_bin: Optional[str]) -> Optional[str]:
    """Return the pi-context-inspector module path, installing the pinned package with ``pi install`` if undeclared.

    A package the user already declared (any version, any install location) is
    used as-is and never reinstalled or claimed. Returns None when the package
    is unavailable; Pi tracing then reports usage without a section breakdown.
    """
    pi_bin = launch_bin or shutil.which("pi")
    if not pi_bin:
        return None
    found = _find_pi_context_inspector(pi_bin)
    if found is None:
        # Can't tell what is declared; installing could replace the user's declaration.
        return None
    declared, module_path = found
    if declared:
        return module_path

    print(f"[lapdog] Installing {_PI_CONTEXT_INSPECTOR_SOURCE} for context usage breakdowns...")
    try:
        result = subprocess.run(
            [pi_bin, "install", _PI_CONTEXT_INSPECTOR_SOURCE],
            capture_output=True,
            text=True,
            timeout=_PI_CONTEXT_INSPECTOR_INSTALL_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"[lapdog] Could not install pi-context-inspector ({e}); continuing without it.", file=sys.stderr)
        return None
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()[-1:] or ["unknown error"]
        print(f"[lapdog] Could not install pi-context-inspector ({detail[0]}); continuing without it.", file=sys.stderr)
        return None

    try:
        os.makedirs(LAPDOG_DIR, exist_ok=True)
        with open(_PI_CONTEXT_INSPECTOR_MARKER, "w") as f:
            f.write(f"{_PI_CONTEXT_INSPECTOR_SOURCE}\n")
    except OSError:
        pass
    found = _find_pi_context_inspector(pi_bin)
    return found[1] if found else None


def _uninstall_pi_context_inspector() -> None:
    """Remove pi-context-inspector if lapdog installed it. Must run before ~/.lapdog is deleted."""
    if not os.path.isfile(_PI_CONTEXT_INSPECTOR_MARKER):
        return
    pi_bin = shutil.which("pi")
    if not pi_bin:
        print(
            f"[lapdog] 'pi' not found; remove pi-context-inspector with: pi remove {_PI_CONTEXT_INSPECTOR_REMOVE_SOURCE}",
            file=sys.stderr,
        )
        return
    try:
        result = subprocess.run(
            [pi_bin, "remove", _PI_CONTEXT_INSPECTOR_REMOVE_SOURCE],
            capture_output=True,
            text=True,
            timeout=_PI_CONTEXT_INSPECTOR_INSTALL_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"[lapdog] Failed to remove pi-context-inspector: {e}", file=sys.stderr)
        return
    if result.returncode == 0:
        print("[lapdog] Removed pi-context-inspector.")
    else:
        print(f"[lapdog] Failed to remove pi-context-inspector: {result.stderr.strip()}", file=sys.stderr)


def _run_pi(
    args: Optional[List[str]] = None,
    port: Optional[int] = 8126,
    session_token: Optional[str] = None,
    launch_bin: Optional[str] = None,
    context_inspector_path: Optional[str] = None,
) -> None:
    """Exec the pi binary, forwarding arguments.  Never returns."""
    if args is None:
        args = []
    launch_bin = launch_bin or shutil.which("pi")
    if not launch_bin:
        print("[lapdog] 'pi' not found in PATH", file=sys.stderr)
        sys.exit(1)
    env = {**os.environ, "LAPDOG_URL": f"http://localhost:{port}"}
    for variable in ("CODEX_THREAD_ID", "PI_SESSION_ID", "LAPDOG_SESSION_TOKEN", "LAPDOG_PI_CONTEXT_INSPECTOR_PATH"):
        env.pop(variable, None)
    if session_token:
        env["LAPDOG_SESSION_TOKEN"] = session_token
    if context_inspector_path:
        env["LAPDOG_PI_CONTEXT_INSPECTOR_PATH"] = context_inspector_path
    run(bin_path=launch_bin, argv=([launch_bin] + args), env=env)


def cmd_pi(
    sub_cmd_args: List[str], forward_data: bool, backfill: bool = False, launch_bin: Optional[str] = None
) -> None:
    """Ensure lapdog is running, install the pi extension, then launch pi.

    When ``backfill`` is True: ensure lapdog is running, replay historical
    Pi/OMP sessions through ``/pi/hooks``, and exit without launching pi.
    The extension is not installed during backfill (no live capture to wire
    up); ``forward_data`` is forced off.
    """
    if backfill:
        port = ensure_lapdog_running(forward_data=False, detached=True)
        if port is None:
            print("[lapdog] Could not determine lapdog port.", file=sys.stderr)
            sys.exit(1)
        backfill_pi.backfill(f"http://localhost:{port}")
        return

    port = ensure_lapdog_running(forward_data, detached=True)
    _install_pi_extension()
    context_inspector_path = _ensure_pi_context_inspector(launch_bin)

    print(build_running_banner(data_type="coding session"))
    _run_pi(
        args=sub_cmd_args,
        port=port,
        session_token=uuid.uuid4().hex,
        launch_bin=launch_bin,
        context_inspector_path=context_inspector_path,
    )
