"""One-shot backfill of historical Claude Code sessions.

Walks ``~/.claude/projects/<encoded-cwd>/<session-id>.jsonl`` and POSTs each
session's entries as a single payload to the local agent's
``/claude/hooks/backfill_session`` endpoint, which builds full LLMObs spans
server-side (root agent + LLM + tool spans, with real timestamps and token
usage / cost).

A separate trace is created per user prompt — so a transcript with N user
turns produces N traces, matching the live behavior where every
``UserPromptSubmit`` opens a fresh trace.
"""

import json
from pathlib import Path
import sys
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional

from lapdog._backfill_common import LapdogDead
from lapdog._backfill_common import post_event
from lapdog._backfill_common import preflight_endpoint


def _default_projects_dir() -> Path:
    return Path.home() / ".claude" / "projects"


def _iter_session_files(projects_dir: Path) -> List[Path]:
    """Top-level session transcripts, newest last.

    Subagent transcripts (under ``<session-id>/subagents/``) are excluded here
    and bundled into their parent session's payload by ``_subagent_files`` —
    otherwise the walker would pick each one up as an independent session,
    exploding one logical session into many.
    """
    if not projects_dir.exists():
        return []
    files = [p for p in projects_dir.rglob("*.jsonl") if "subagents" not in p.parts]
    return sorted(files, key=lambda p: p.stat().st_mtime if p.exists() else 0)


def _subagent_files(session_path: Path) -> List[Path]:
    """Subagent transcripts Claude wrote for ``session_path``.

    Claude Code stores each subagent's (e.g. ``Explore``) conversation in
    ``<session-dir>/<session-id>/subagents/agent-<id>.jsonl`` rather than in the
    main transcript. ``rglob`` picks up nested subagents at any depth.
    """
    sub_dir = session_path.parent / session_path.stem
    if not sub_dir.is_dir():
        return []
    return sorted(sub_dir.rglob("*.jsonl"), key=lambda p: p.stat().st_mtime if p.exists() else 0)


def _load_entries(path: Path) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        print(f"lapdog backfill claude: cannot read {path}: {exc}", file=sys.stderr, flush=True)
    return entries


def _resolve_cwd(entries: Iterable[Dict[str, Any]]) -> str:
    """First ``cwd`` field on any entry. Empty string if none."""
    for entry in entries:
        cwd = entry.get("cwd")
        if isinstance(cwd, str) and cwd:
            return cwd
    return ""


def _backfill_one(lapdog_url: str, path: Path) -> bool:
    session_id = path.stem
    entries = _load_entries(path)
    if not entries:
        return False
    cwd = _resolve_cwd(entries)
    subagents: List[Dict[str, Any]] = []
    for sub_path in _subagent_files(path):
        sub_entries = _load_entries(sub_path)
        if sub_entries:
            subagents.append({"agent_id": sub_path.stem, "entries": sub_entries})
    body = {"session_id": session_id, "cwd": cwd, "entries": entries, "subagents": subagents}
    return post_event(lapdog_url, "/claude/hooks/backfill_session", body)


def backfill(
    lapdog_url: str,
    *,
    projects_dir: Optional[Path] = None,
) -> int:
    """Walk all historical Claude transcripts and POST them to the backfill endpoint.

    ``lapdog_url`` is the base URL of the local agent (e.g. ``http://localhost:8126``).
    ``projects_dir`` overrides the source directory and defaults to ``~/.claude/projects``.
    Returns the number of sessions for which the POST succeeded.
    """
    dir_path = projects_dir if projects_dir is not None else _default_projects_dir()
    files = _iter_session_files(dir_path)
    if not files:
        print(f"lapdog backfill claude: no sessions found under {dir_path}", file=sys.stderr, flush=True)
        return 0

    if not preflight_endpoint(lapdog_url, "/claude/hooks/backfill_session"):
        return 0

    posted_sessions = 0
    aborted = False
    for path in files:
        try:
            if _backfill_one(lapdog_url, path):
                posted_sessions += 1
        except LapdogDead:
            aborted = True
            break
    suffix = " (aborted: lapdog stopped responding)" if aborted else ""
    print(
        f"lapdog backfill claude: scanned {len(files)} file(s), forwarded {posted_sessions} session(s){suffix}",
        file=sys.stderr,
        flush=True,
    )
    return posted_sessions
