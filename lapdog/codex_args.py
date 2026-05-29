"""Codex CLI argument helpers for Lapdog launch wrappers."""

import hashlib
import os
from pathlib import Path
from typing import List
from typing import Optional

_CODEX_FLAGS_WITH_VALUES = {
    "-a",
    "--add-dir",
    "--ask-for-approval",
    "-c",
    "--config",
    "-C",
    "--cd",
    "--download-url",
    "--enable",
    "--disable",
    "--local-provider",
    "-m",
    "--model",
    "-p",
    "--profile",
    "--profile-v2",
    "--remote",
    "--remote-auth-token-env",
    "-s",
    "--sandbox",
}


def _abs_path_from_cwd(path: str, cwd: Optional[str] = None) -> str:
    resolved = str(Path(path).expanduser())
    if not os.path.isabs(resolved):
        resolved = os.path.join(cwd or os.getcwd(), resolved)
    return os.path.abspath(resolved)


def _resolve_cd_cwd(args: List[str]) -> str:
    cwd = os.getcwd()
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--":
            break
        next_idx = idx + 1
        cd_value: Optional[str] = None
        if arg in ("-C", "--cd"):
            if next_idx < len(args):
                cd_value = args[next_idx]
                next_idx += 1
        elif arg.startswith("--cd="):
            cd_value = arg.split("=", 1)[1]
        elif arg.startswith("-C") and arg != "-C":
            cd_value = arg[2:].lstrip("=")
        if cd_value:
            cwd = _abs_path_from_cwd(cd_value)
        idx = next_idx
    return os.path.abspath(cwd)


def _command_index(args: List[str]) -> Optional[int]:
    """Return the index of the first Codex subcommand, if one is present."""
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--":
            return idx + 1 if idx + 1 < len(args) else None
        if not arg.startswith("-"):
            return idx
        if arg in _CODEX_FLAGS_WITH_VALUES:
            idx += 2
            continue
        idx += 1
    return None


def is_app_command(args: List[str]) -> bool:
    command_idx = _command_index(args)
    return command_idx is not None and args[command_idx] == "app"


def _resolve_app_cwd(args: List[str]) -> Optional[str]:
    """Resolve the workspace path for `codex app [PATH]` commands."""
    command_idx = _command_index(args)
    if command_idx is None or args[command_idx] != "app":
        return None

    base_cwd = _resolve_cd_cwd(args[:command_idx])
    idx = command_idx + 1
    while idx < len(args):
        arg = args[idx]
        if arg == "--":
            if idx + 1 < len(args):
                return _abs_path_from_cwd(args[idx + 1], cwd=base_cwd)
            break
        if arg in _CODEX_FLAGS_WITH_VALUES:
            idx += 2
            continue
        if arg.startswith("-"):
            idx += 1
            continue
        return _abs_path_from_cwd(arg, cwd=base_cwd)

    return base_cwd


def resolve_cwd(args: List[str]) -> str:
    app_cwd = _resolve_app_cwd(args)
    if app_cwd is not None:
        return app_cwd

    return _resolve_cd_cwd(args)


def app_watcher_key(port: int, cwd: Optional[str] = None) -> str:
    key = f"{port}\0{os.path.realpath(cwd) if cwd else 'all-cwds'}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
