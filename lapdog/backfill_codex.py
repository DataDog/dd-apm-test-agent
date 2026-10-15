"""One-shot backfill of historical Codex rollout sessions.

Reads ``~/.codex/sessions/**/*.jsonl`` (or ``$CODEX_HOME/sessions`` /
``$LAPDOG_CODEX_SESSION_DIR``) and POSTs each record to the local agent's
``/codex/hooks`` endpoint.

By default only sessions whose recorded ``cwd`` is under the caller's
current working directory are forwarded. Pass ``cwd=None`` to disable filtering.
"""

import json
import os
from pathlib import Path
import sys
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import requests

from lapdog.codex_hook import read_session_names

_session = requests.Session()
_POST_TIMEOUT = (0.5, 2.0)


def _default_session_dir() -> Path:
    explicit_session_dir = os.environ.get("LAPDOG_CODEX_SESSION_DIR")
    if explicit_session_dir:
        return Path(explicit_session_dir).expanduser()
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home).expanduser() / "sessions"
    return Path.home() / ".codex" / "sessions"


def _is_under(cwd: str, root: str) -> bool:
    """Return True if `cwd` is `root` itself or any descendant directory.

    Uses ``os.path.realpath`` so symlinked roots (e.g. ``/tmp`` →
    ``/private/tmp`` on macOS) compare equal. Mirrors trajectory's
    ``isUnderProjectRoot`` (``trajectory/codex/watcher/watcher.go``).
    """
    if not cwd or not root:
        return False
    try:
        cwd_r = os.path.realpath(cwd)
        root_r = os.path.realpath(root)
    except OSError:
        return False
    if cwd_r == root_r:
        return True
    return cwd_r.startswith(root_r + os.sep)


def _post_record(
    lapdog_url: str,
    session_id: str,
    record: Dict[str, Any],
    source_path: Path,
) -> bool:
    body = {"session_id": session_id, "record": record, "source_path": str(source_path), "backfill": True}
    try:
        response = _session.post(
            f"{lapdog_url.rstrip('/')}/codex/hooks",
            json=body,
            timeout=_POST_TIMEOUT,
        )
        if response is not None and response.status_code >= 400:
            print(
                "lapdog backfill codex: hook post failed "
                f"status={response.status_code} session_id={session_id} source_path={source_path}",
                file=sys.stderr,
                flush=True,
            )
            return False
    except Exception as exc:
        print(
            f"lapdog backfill codex: hook post failed session_id={session_id} source_path={source_path}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        return False
    return True


def _shutdown_record() -> Dict[str, Any]:
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "type": "event_msg",
        "payload": {"type": "shutdown_complete"},
    }


def _record_cwd(record: Dict[str, Any]) -> str:
    payload = record.get("payload", {})
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("cwd", ""))


def _record_session_id(record: Dict[str, Any]) -> str:
    if record.get("type") != "session_meta":
        return ""
    payload = record.get("payload", {})
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("id", ""))


def _iter_jsonl_files(session_dir: Path) -> List[Path]:
    if not session_dir.exists():
        return []
    return sorted(session_dir.rglob("*.jsonl"), key=lambda p: p.stat().st_mtime if p.exists() else 0)


# Sentinel that distinguishes "default cwd (process getcwd)" from "explicit
# None means: skip the cwd filter entirely". A regular ``None`` default would
# force callers who want filtering to compute ``os.getcwd()`` themselves.
_DEFAULT_CWD: Any = object()


def _backfill_one(
    lapdog_url: str, path: Path, cwd_filter: Optional[str], session_names: Optional[Dict[str, str]] = None
) -> bool:
    """Read a single rollout file and post every record.

    When ``cwd_filter`` is set, records read before the first ``cwd`` is
    seen are buffered in memory and only flushed if the session's cwd is
    under ``cwd_filter``. Buffering preserves ``session_meta`` when the
    eventual ``turn_context`` matches.

    Returns True if any record was posted.
    """
    session_id = ""
    matches_cwd: Optional[bool] = None if cwd_filter else True
    pending: List[Dict[str, Any]] = []
    posted_any = False
    name_posted = False
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                rec_session = _record_session_id(record)
                if rec_session:
                    session_id = rec_session

                if cwd_filter and matches_cwd is None:
                    rec_cwd = _record_cwd(record)
                    if rec_cwd:
                        matches_cwd = _is_under(rec_cwd, cwd_filter)
                        if matches_cwd is False:
                            return False

                if matches_cwd is None:
                    # cwd disposition unknown — buffer the record and keep reading.
                    pending.append(record)
                    continue

                if not session_id:
                    # No session anchor yet (very early records); skip.
                    continue

                # Flush any buffered records first.
                if not name_posted and session_names and session_id in session_names:
                    name_posted = _post_record(
                        lapdog_url,
                        session_id,
                        {"type": "event_msg", "payload": {"type": "session_name", "name": session_names[session_id]}},
                        path,
                    )
                if pending:
                    for buffered in pending:
                        if _post_record(lapdog_url, session_id, buffered, path):
                            posted_any = True
                    pending.clear()

                if _post_record(lapdog_url, session_id, record, path):
                    posted_any = True
    except OSError as exc:
        print(f"lapdog backfill codex: cannot read {path}: {exc}", file=sys.stderr, flush=True)
        return posted_any

    if posted_any and session_id:
        _post_record(lapdog_url, session_id, _shutdown_record(), path)
    return posted_any


def backfill(
    lapdog_url: str,
    *,
    cwd: Any = _DEFAULT_CWD,
    session_dir: Optional[Path] = None,
) -> int:
    """Walk all historical Codex rollouts and POST them to ``/codex/hooks``.

    ``lapdog_url`` is the base URL of the local agent. ``cwd``: if a string,
    only sessions whose recorded cwd is under this path are forwarded;
    defaults to ``os.getcwd()``; pass ``cwd=None`` to disable the filter and
    backfill every session. ``session_dir`` overrides the source directory
    (defaults to ``~/.codex/sessions`` or ``$CODEX_HOME/sessions``).
    Returns the number of sessions for which at least one record was posted.
    """
    if cwd is _DEFAULT_CWD:
        cwd_filter: Optional[str] = os.getcwd()
    else:
        cwd_filter = cwd  # may be None to skip filtering, or an explicit string

    dir_path = session_dir if session_dir is not None else _default_session_dir()
    files = _iter_jsonl_files(dir_path)
    if not files:
        print(f"lapdog backfill codex: no sessions found under {dir_path}", file=sys.stderr, flush=True)
        return 0

    posted_sessions = 0
    session_names = read_session_names(dir_path.parent / "session_index.jsonl")
    for path in files:
        if _backfill_one(lapdog_url, path, cwd_filter, session_names):
            posted_sessions += 1
    print(
        f"lapdog backfill codex: scanned {len(files)} file(s), forwarded {posted_sessions} session(s)",
        file=sys.stderr,
        flush=True,
    )
    return posted_sessions
