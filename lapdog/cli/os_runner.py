"""Platform-specific process execution."""

import os
import subprocess
import sys
from typing import Dict
from typing import List
from typing import Optional


def wait_for_exit(proc: "subprocess.Popen[bytes]") -> int:
    """On Windows, let the console child handle Ctrl+C before its parent exits."""
    while True:
        try:
            return proc.wait()
        except KeyboardInterrupt:
            if sys.platform != "win32":
                raise
            # Windows delivers console interrupts to the child as well. It may
            # cancel a turn and continue running, so keep waiting for its exit.


def run(
    bin_path: str,
    argv: List[str],
    env: Optional[Dict[str, str]] = None,
    search_path: bool = False,
) -> None:
    """Run the command with the platform-specific process API."""
    run_env = env if env is not None else os.environ

    if sys.platform == "win32":
        kwargs = {
            "env": run_env,
            "stdin": None,
            "stdout": None,
            "stderr": None,
        }

        if not search_path:
            kwargs["executable"] = bin_path

        proc = subprocess.Popen(argv, **kwargs)
        sys.exit(wait_for_exit(proc))
    else:
        os_exec = os.execvpe if search_path else os.execve
        os_exec(bin_path, argv, run_env)
