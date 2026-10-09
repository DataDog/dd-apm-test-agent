"""Pi launcher and extension management."""

import os
import shutil
import sys
from typing import List
from typing import Optional
import uuid

from lapdog import backfill_pi
from lapdog.cli.ascii_art import build_running_banner
from lapdog.cli.os_runner import run
from lapdog.cli.runtime import ensure_lapdog_running


_PI_GLOBAL_EXT_DIR = os.path.expanduser("~/.pi/agent/extensions")
_PI_EXT_DEST = os.path.join(_PI_GLOBAL_EXT_DIR, "lapdog.ts")
_PI_EXT_SOURCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pi_lapdog_extension.ts")


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


def _run_pi(
    args: Optional[List[str]] = None,
    port: Optional[int] = 8126,
    session_token: Optional[str] = None,
) -> None:
    """Exec the pi binary, forwarding arguments.  Never returns."""
    if args is None:
        args = []
    pi_bin = shutil.which("pi")
    if not pi_bin:
        print("[lapdog] 'pi' not found in PATH", file=sys.stderr)
        sys.exit(1)
    env = {**os.environ, "LAPDOG_URL": f"http://localhost:{port}"}
    for variable in ("CODEX_THREAD_ID", "PI_SESSION_ID", "LAPDOG_SESSION_TOKEN"):
        env.pop(variable, None)
    if session_token:
        env["LAPDOG_SESSION_TOKEN"] = session_token
    run(bin_path=pi_bin, argv=([pi_bin] + args), env=env)


def cmd_pi(sub_cmd_args: List[str], forward_data: bool, backfill: bool = False) -> None:
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

    print(build_running_banner(data_type="coding session"))
    _run_pi(args=sub_cmd_args, port=port, session_token=uuid.uuid4().hex)
