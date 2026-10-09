"""Process-local PATH wrappers for Ollama launches."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import List


def _write_wrappers(directory: Path, agents: List[str]) -> None:
    if sys.platform == "win32":
        # Use native console launchers: Ollama starts executables without a shell.
        from distlib.scripts import ScriptMaker
        from distlib.scripts import enquote_executable

        maker = ScriptMaker(None, str(directory))
        maker.executable = enquote_executable(sys.executable)
        maker.variants = {""}
        for agent in agents:
            maker.make(f"{agent} = lapdog.ollama_launcher:windows_main")
        return

    for agent in agents:
        wrapper = directory / agent
        command = shlex.join([sys.executable, "-m", "lapdog.ollama_launcher", str(directory / "launch.json"), agent])
        wrapper.write_text(f'#!/bin/sh\nexec {command} "$@"\n', encoding="utf-8")
        wrapper.chmod(0o700)


def run_launch(ollama_bin: str, args: List[str], forward_data: bool, install_plugin: bool) -> int:
    """Keep wrappers alive until Ollama exits, then remove them."""
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
            ),
            encoding="utf-8",
        )
        _write_wrappers(Path(directory), list(binaries))
        env = {**os.environ, "PATH": directory + os.pathsep + original_path}
        if sys.platform == "win32":
            from lapdog.cli.os_runner import wait_for_exit

            # Wait for Ollama and its agents to exit before deleting the .exe
            # wrappers. subprocess.run would kill Ollama on KeyboardInterrupt.
            with subprocess.Popen([ollama_bin] + args, env=env) as proc:
                return wait_for_exit(proc)
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


def _launch_agent(config_path: Path, agent: str, args: List[str]) -> None:
    from lapdog.cli.os_runner import run

    config = json.loads(config_path.read_text(encoding="utf-8"))
    # Restore PATH before plugins, watchers, or the real agent can start children.
    os.environ["PATH"] = config["path"]
    binary = config["binaries"][agent]
    if _maintenance_command(agent, args):
        run(binary, [binary] + args)
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


def windows_main() -> None:
    """Distlib entry point; the executable name identifies the selected agent."""
    wrapper = Path(sys.argv[0]).absolute()
    _launch_agent(wrapper.parent / "launch.json", wrapper.stem, sys.argv[1:])


def main() -> None:
    config_path, agent, *args = sys.argv[1:]
    _launch_agent(Path(config_path), agent, args)


if __name__ == "__main__":
    main()
