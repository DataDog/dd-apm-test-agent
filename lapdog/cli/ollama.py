"""Ollama launch command."""

import shutil
import sys
from typing import List

from lapdog.cli.os_runner import run
from lapdog.ollama_launcher import run_launch


def cmd_ollama(
    sub_cmd_args: List[str],
    forward_data: bool,
    install_plugin: bool,
    backfill: bool = False,
) -> None:
    """Launch Ollama with process-local wrappers for supported coding agents."""
    ollama_bin = shutil.which("ollama")
    if not ollama_bin:
        print("[lapdog] ollama not found on PATH")
        sys.exit(1)

    if not sub_cmd_args or sub_cmd_args[0] != "launch":
        print("[lapdog] Cannot instrument non-`launch` Ollama session.")
        run(ollama_bin, argv=([ollama_bin] + sub_cmd_args))
        return

    if backfill:
        print("[lapdog] Backfill not supported for `ollama`, run it for individual coding agents instead")
        print("[lapdog]     lapdog --backfill claude")
        sys.exit(1)

    sys.exit(run_launch(ollama_bin, sub_cmd_args, forward_data, install_plugin))
