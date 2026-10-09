"""Process-local PATH wrappers for Ollama launches (POSIX prototype)."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import List


def run_launch(ollama_bin: str, args: List[str], forward_data: bool, install_plugin: bool) -> int:
    """Keep wrappers alive until Ollama exits, then remove them."""
    if os.name == "nt":
        print("[lapdog] Ollama instrumentation currently requires macOS or Linux.")
        return 1

    original_path = os.environ.get("PATH", os.defpath)
    binaries = {name: path for name in ("claude", "codex", "pi") if (path := shutil.which(name))}
    with tempfile.TemporaryDirectory(prefix="lapdog-ollama-") as directory:
        config_path = Path(directory) / "launch.json"
        config_path.write_text(
            json.dumps(
                {
                    "path": original_path,
                    "binaries": binaries,
                    "forward_data": forward_data,
                    "install_plugin": install_plugin,
                }
            )
        )
        for name in binaries:
            wrapper = Path(directory) / name
            command = shlex.join([sys.executable, "-m", "lapdog.ollama_launcher", str(config_path), name])
            wrapper.write_text(f'#!/bin/sh\nexec {command} "$@"\n')
            wrapper.chmod(0o700)
        env = {**os.environ, "PATH": directory + os.pathsep + original_path}
        try:
            result = subprocess.run([ollama_bin] + args, env=env)
        except KeyboardInterrupt:
            return 130
        return result.returncode if result.returncode >= 0 else 128 - result.returncode


def _maintenance_command(agent: str, args: List[str]) -> bool:
    """Avoid instrumenting Ollama's version checks and package operations."""
    if args and args[0] in ("--version", "-v", "--help", "-h", "help"):
        return True
    return agent == "pi" and bool(args) and args[0] in ("list", "install", "uninstall", "remove", "update", "config")


def main() -> None:
    config_path, agent, *args = sys.argv[1:]
    config = json.loads(Path(config_path).read_text())
    # Restore PATH before plugins, watchers, or the real agent can start children.
    os.environ["PATH"] = config["path"]
    binary = config["binaries"][agent]
    if _maintenance_command(agent, args):
        os.execve(binary, [binary] + args, os.environ)
        return

    from lapdog.cli import claude
    from lapdog.cli import codex
    from lapdog.cli import pi

    if agent == "claude":
        claude.cmd_claude(args, config["forward_data"], config["install_plugin"], launch_bin=binary)
    elif agent == "pi":
        pi.cmd_pi(args, config["forward_data"], launch_bin=binary)
    else:
        # Ollama has already configured the provider and model for this child.
        codex.cmd_codex(args, config["forward_data"], launch_bin=binary, capture_proxy=False)


if __name__ == "__main__":
    main()
