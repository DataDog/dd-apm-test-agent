"""One-shot backfill of historical Pi / OMP sessions.

Walks ``~/.pi/agent/sessions/<project>/*.jsonl`` and
``~/.omp/agent/sessions/<project>/*.jsonl`` and POSTs each session's entries
as a single payload to ``/pi/hooks/backfill_session``, which builds full
LLMObs spans server-side (root agent + LLM + tool spans, with real
timestamps and token usage / cost from each ``message.usage`` block).
"""

import json
from pathlib import Path
import sys
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from lapdog._backfill_common import LapdogDead
from lapdog._backfill_common import post_event
from lapdog._backfill_common import preflight_endpoint


def _default_pi_dir() -> Path:
    return Path.home() / ".pi" / "agent" / "sessions"


def _default_omp_dir() -> Path:
    return Path.home() / ".omp" / "agent" / "sessions"


def _iter_session_files(*dirs: Path) -> List[Path]:
    files: List[Path] = []
    for d in dirs:
        if d.exists():
            files.extend(d.rglob("*.jsonl"))
    files.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0)
    return files


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
        print(f"lapdog backfill pi: cannot read {path}: {exc}", file=sys.stderr, flush=True)
    return entries


def _session_metadata(entries: List[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    """Return ``{session_id, cwd}`` from the leading ``type=session`` entry.

    Returns None when the first entry isn't a session header — pi transcripts
    must start with one, so anything else is malformed.
    """
    if not entries:
        return None
    first = entries[0]
    if first.get("type") != "session":
        return None
    session_id = str(first.get("id") or "")
    cwd = str(first.get("cwd") or "")
    if not session_id:
        return None
    return {"session_id": session_id, "cwd": cwd}


def _backfill_one(lapdog_url: str, path: Path) -> bool:
    entries = _load_entries(path)
    meta = _session_metadata(entries)
    if meta is None:
        return False
    body = {"session_id": meta["session_id"], "cwd": meta["cwd"], "entries": entries}
    return post_event(lapdog_url, "/pi/hooks/backfill_session", body)


def backfill(
    lapdog_url: str,
    *,
    pi_dir: Optional[Path] = None,
    omp_dir: Optional[Path] = None,
) -> int:
    """Walk historical Pi/OMP sessions and POST them to the backfill endpoint.

    Returns the number of sessions for which the POST succeeded.
    """
    dirs: List[Path] = []
    dirs.append(pi_dir if pi_dir is not None else _default_pi_dir())
    dirs.append(omp_dir if omp_dir is not None else _default_omp_dir())

    files = _iter_session_files(*dirs)
    if not files:
        print(
            f"lapdog backfill pi: no sessions found under {dirs[0]} or {dirs[1]}",
            file=sys.stderr,
            flush=True,
        )
        return 0

    if not preflight_endpoint(lapdog_url, "/pi/hooks/backfill_session"):
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
        f"lapdog backfill pi: scanned {len(files)} file(s), forwarded {posted_sessions} session(s){suffix}",
        file=sys.stderr,
        flush=True,
    )
    return posted_sessions
