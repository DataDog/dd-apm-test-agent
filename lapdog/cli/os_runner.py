"""Platform-specific process execution."""

import os
import subprocess
import sys
from typing import Dict
from typing import List
from typing import Optional


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
        sys.exit(proc.wait())
    else:
        os_exec = os.execvpe if search_path else os.execve
        os_exec(bin_path, argv, run_env)
