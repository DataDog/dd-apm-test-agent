"""Argument parsing and command dispatch."""

import argparse
import os
import shutil
import sys
from typing import List
from typing import Optional
from typing import Tuple

from ddapm_test_agent import _get_version
from lapdog import tracer_inject
from lapdog.cli.ascii_art import build_running_banner
from lapdog.cli.claude import LAPDOG_MARKETPLACE_SOURCE
from lapdog.cli.claude import LAPDOG_PLUGIN_NAME
from lapdog.cli.claude import cmd_claude
from lapdog.cli.codex import cmd_codex
from lapdog.cli.ollama import cmd_ollama
from lapdog.cli.os_runner import run
from lapdog.cli.pi import cmd_pi
from lapdog.cli.runtime import _PATH_ROUTABLE_LAUNCHERS
from lapdog.cli.runtime import ensure_lapdog_running
from lapdog.cli.runtime import read_pid_file
from lapdog.cli.server import cmd_start
from lapdog.cli.server import cmd_status
from lapdog.cli.server import cmd_stop
from lapdog.cli.tags import cmd_tags
from lapdog.cli.uninstall import cmd_uninstall


LAPDOG_COMMANDS = ["start", "stop", "status", "claude", "pi", "codex", "ollama", "tags", "uninstall"]
LAPDOG_USAGE = (
    "Usage: lapdog [OPTIONS] <command> [command-args...]\n"
    "Options must appear before <command>. Arguments after <command> are forwarded.\n"
    "  start      Start lapdog (background)\n"
    "  stop       Stop lapdog (started by 'lapdog start' or 'lapdog claude')\n"
    "  status     Show lapdog status (from /info)\n"
    "  claude     Start lapdog in background if needed, then launch Claude with intercept\n"
    "  pi         Start lapdog in background if needed, install extension, then launch pi\n"
    "  codex      Start lapdog in background if needed, then launch Codex with tracing\n"
    "  tags       Add tags to the current instrumented coding-agent session\n"
    "  uninstall  Stop lapdog and remove all state it wrote (~/.lapdog, Claude hooks, pi extension, Codex watchers)\n"
    "\n"
    "Any other command is treated as an app to run with tracing instrumentation:\n"
    "  lapdog python app.py\n"
)


def cmd_exec(app_cmd: List[str], forward_data: bool) -> None:
    """Auto-start lapdog if needed, inject tracer env vars, then exec the app command. Never returns."""
    resolved = shutil.which(app_cmd[0])
    if not resolved:
        print(f"[lapdog] Command not found: {app_cmd[0]}", file=sys.stderr)
        sys.exit(1)

    ensure_lapdog_running(forward_data)
    print(build_running_banner(data_type="application"))

    _, port = read_pid_file()
    if port is None:
        print("[lapdog] Could not determine lapdog port.", file=sys.stderr)
        sys.exit(1)

    env = tracer_inject.build_instrumented_env(port=port)
    run(bin_path=resolved, argv=app_cmd, env=env, search_path=True)


def _parse_command(cmd_args: List[str]) -> Tuple[List[str], Optional[List[str]]]:
    lapdog_args: List[str] = []

    for arg_idx, arg in enumerate(cmd_args):
        if not arg.startswith("--"):
            return lapdog_args, cmd_args[arg_idx:]

        lapdog_args.append(arg)

    return lapdog_args, None


def _parse_lapdog_args(lapdog_args: List[str]) -> argparse.Namespace:
    """Parse lapdog-specific args"""
    parser = argparse.ArgumentParser(description="Lapdog CLI", prog="lapdog", add_help=False)

    parser.add_argument(
        "--forward",
        action="store_true",
        default=False,
        help="Enable data forwarding to Datadog.",
    )

    parser.add_argument(
        "--no-plugin-install",
        dest="install_plugin",
        action="store_false",
        default=True,
        help=(
            "Skip auto-installing the 'lapdog' Claude Code plugin when running "
            f"'lapdog claude'. By default, lapdog runs 'claude plugin marketplace "
            f"add {LAPDOG_MARKETPLACE_SOURCE}' and 'claude plugin install "
            f"{LAPDOG_PLUGIN_NAME}' if the plugin is not already installed."
        ),
    )

    parser.add_argument(
        "--backfill",
        action="store_true",
        default=False,
        help=(
            "Ingest historical sessions from disk by replaying them through the local "
            "agent's /<source>/hooks endpoint, then exit without launching the underlying "
            "CLI. Sources: ~/.codex/sessions (codex), ~/.claude/projects (claude), "
            "~/.pi/agent/sessions + ~/.omp/agent/sessions (pi)."
        ),
    )

    parser.add_argument("--version", action="store_true", dest="version", help="Print version info and exit.")

    parser.add_argument("--help", action="store_true", dest="help", help="Print usage info and exit.")

    return parser.parse_args(args=lapdog_args)


def _consume_backfill_arg(args: List[str]) -> Tuple[List[str], bool]:
    """Remove a command-local ``--backfill`` flag before forwarding args.

    Arguments after ``--`` belong to the underlying command and are left alone.
    """
    cleaned: List[str] = []
    backfill = False
    passthrough = False
    for arg in args:
        if passthrough:
            cleaned.append(arg)
            continue
        if arg == "--":
            passthrough = True
            cleaned.append(arg)
            continue
        if arg == "--backfill":
            backfill = True
            continue
        cleaned.append(arg)
    return cleaned, backfill


def _canonical_launcher(target: str) -> Optional[str]:
    """Map an invocation target to a managed launcher name, or return None.

    A managed launcher may be invoked either by bare name (``claude``) or by an
    explicit path that resolves to the same binary (``~/.local/bin/claude``,
    i.e. what ``which claude`` returns). Both must route to the dedicated
    launcher (``cmd_claude``/``cmd_pi``/``cmd_codex``).

    A bare, unknown word (e.g. ``python``) returns None so it still falls
    through to ``cmd_exec`` unchanged.
    """
    if target.lower() in _PATH_ROUTABLE_LAUNCHERS:
        return target.lower()

    if not (target.startswith("~") or os.sep in target or (os.altsep and os.altsep in target)):
        return None

    invoked = os.path.realpath(os.path.expanduser(target))
    for launcher in _PATH_ROUTABLE_LAUNCHERS:
        on_path = shutil.which(launcher)
        if on_path and os.path.realpath(on_path) == invoked:
            return launcher
    return None


def main() -> None:
    # On Windows the default stdout/stderr encoding is the system ANSI codepage
    # (e.g. cp1252), which can't encode the banner's box-drawing glyphs. Force
    # UTF-8 with a replacement fallback so lapdog never crashes on its own
    # output. No-op on POSIX where the default is already UTF-8.
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            reconfigure = getattr(stream, "reconfigure", None)
            if reconfigure is not None:
                try:
                    reconfigure(encoding="utf-8", errors="replace")
                except OSError:
                    pass

    args = sys.argv
    if len(args) < 2:
        print(LAPDOG_USAGE, file=sys.stderr)
        sys.exit(1)

    lapdog_args, remaining = _parse_command(args[1:])
    lapdog_parsed_args = _parse_lapdog_args(lapdog_args)

    if lapdog_parsed_args.version:
        print(_get_version())
        sys.exit(0)

    if lapdog_parsed_args.help:
        print(LAPDOG_USAGE)
        sys.exit(0)

    if not remaining:
        print(LAPDOG_USAGE)
        sys.exit(1)

    sub_cmd = _canonical_launcher(remaining[0]) or remaining[0].lower()
    sub_cmd_args = remaining[1:]
    command_backfill = False
    if sub_cmd in _PATH_ROUTABLE_LAUNCHERS:
        sub_cmd_args, command_backfill = _consume_backfill_arg(sub_cmd_args)
    backfill = lapdog_parsed_args.backfill or command_backfill

    if sub_cmd not in LAPDOG_COMMANDS:
        cmd_exec(
            app_cmd=remaining,
            forward_data=lapdog_parsed_args.forward,
        )

        return

    if sub_cmd == "start":
        cmd_start(sub_cmd_args=sub_cmd_args, forward_data=lapdog_parsed_args.forward)
    elif sub_cmd == "stop":
        cmd_stop()
    elif sub_cmd == "status":
        cmd_status()
    elif sub_cmd == "claude":
        cmd_claude(
            sub_cmd_args=sub_cmd_args,
            forward_data=lapdog_parsed_args.forward,
            install_plugin=lapdog_parsed_args.install_plugin,
            backfill=backfill,
        )
    elif sub_cmd == "pi":
        cmd_pi(
            sub_cmd_args=sub_cmd_args,
            forward_data=lapdog_parsed_args.forward,
            backfill=backfill,
        )
    elif sub_cmd == "codex":
        cmd_codex(
            sub_cmd_args=sub_cmd_args,
            forward_data=lapdog_parsed_args.forward,
            backfill=backfill,
        )
    elif sub_cmd == "ollama":
        cmd_ollama(
            sub_cmd_args=sub_cmd_args,
            forward_data=lapdog_parsed_args.forward,
            install_plugin=lapdog_parsed_args.install_plugin,
            backfill=backfill,
        )
    elif sub_cmd == "tags":
        cmd_tags(sub_cmd_args)
    elif sub_cmd == "uninstall":
        cmd_uninstall()
