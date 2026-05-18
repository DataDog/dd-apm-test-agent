"""One-shot backfill of historical Codex rollout sessions.

Reads ``~/.codex/sessions/**/*.jsonl`` (or ``$CODEX_HOME/sessions`` /
``$LAPDOG_CODEX_SESSION_DIR``) and POSTs each record to the local agent's
``/codex/hooks`` endpoint, the same way ``lapdog.codex_watcher`` does for
live sessions.

By default only sessions whose recorded ``cwd`` is under the caller's
current working directory are forwarded — matching ``lapdog codex``'s
live-mode behavior. Pass ``cwd=None`` to disable filtering.
"""

import json
import os
from pathlib import Path
import sys
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from lapdog.codex_watcher import _default_session_dir
from lapdog.codex_watcher import _is_under
from lapdog.codex_watcher import _iter_jsonl_files
from lapdog.codex_watcher import _post_record
from lapdog.codex_watcher import _post_shutdown_complete
from lapdog.codex_watcher import _record_cwd
from lapdog.codex_watcher import _record_session_id

# Sentinel that distinguishes "default cwd (process getcwd)" from "explicit
# None means: skip the cwd filter entirely". A regular ``None`` default would
# force callers who want filtering to compute ``os.getcwd()`` themselves.
_DEFAULT_CWD: Any = object()


def _backfill_one(lapdog_url: str, path: Path, cwd_filter: Optional[str]) -> bool:
    """Read a single rollout file and post every record.

    When ``cwd_filter`` is set, records read before the first ``cwd`` is
    seen are buffered in memory and only flushed if the session's cwd is
    under ``cwd_filter``. This mirrors ``codex_watcher._drain_file``'s
    buffer-then-flush behavior so ``session_meta`` (which carries no cwd)
    is preserved when the eventual ``turn_context`` matches.

    Returns True if any record was posted.
    """
    session_id = ""
    matches_cwd: Optional[bool] = None if cwd_filter else True
    pending: List[Dict[str, Any]] = []
    posted_any = False
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
        _post_shutdown_complete(lapdog_url, session_id, path)
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
    (defaults to ``~/.codex/sessions`` resolved by ``codex_watcher``).
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
    for path in files:
        if _backfill_one(lapdog_url, path, cwd_filter):
            posted_sessions += 1
    print(
        f"lapdog backfill codex: scanned {len(files)} file(s), forwarded {posted_sessions} session(s)",
        file=sys.stderr,
        flush=True,
    )
    return posted_sessions
