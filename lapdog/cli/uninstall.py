"""Cleanup across supported agents."""

import os
import shutil
import sys

from lapdog.cli.claude import _uninstall_lapdog_claude_code_plugin
from lapdog.cli.codex import _stop_all_codex_watchers
from lapdog.cli.pi import _PI_EXT_DEST
from lapdog.cli.runtime import read_pid_file
from lapdog.cli.server import cmd_stop
from lapdog.paths import LAPDOG_DIR


def cmd_uninstall() -> None:
    """Stop the lapdog server, removes ~/.lapdog directory, and uninstalls managed plugins"""

    # stop lapdog server
    pid, _ = read_pid_file()
    if pid is not None:
        cmd_stop(pid=pid)

    # remove ~/.lapdog dir
    if os.path.isdir(LAPDOG_DIR):
        shutil.rmtree(LAPDOG_DIR, ignore_errors=True)
        print("[lapdog] Lapdog-related files under ~/.lapdog removed")

    # remove claude code plugin
    _uninstall_lapdog_claude_code_plugin()

    # remove pi extension
    if os.path.isfile(_PI_EXT_DEST):
        try:
            os.remove(_PI_EXT_DEST)
            print(f"[lapdog] Removed {_PI_EXT_DEST}.")
        except OSError as e:
            print(f"[lapdog] Failed to remove {_PI_EXT_DEST}: {e}", file=sys.stderr)

    # stop codex watcher(s)
    _stop_all_codex_watchers()

    print(
        "[lapdog] Lapdog cleanup complete. Now uninstall the package:\n"
        "[lapdog]   brew uninstall lapdog\n"
        "[lapdog]   pipx uninstall ddapm-test-agent\n"
        "[lapdog]   pip uninstall ddapm-test-agent"
    )
