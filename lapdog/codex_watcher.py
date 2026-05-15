"""Tail Codex session JSONL files and post records to Lapdog."""

import argparse
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

from lapdog.codex_cursor import CursorState
from lapdog.codex_cursor import load_cursor
from lapdog.codex_cursor import save_cursor_atomic
from lapdog.paths import CODEX_CURSOR_FILE


class FileState:
    def __init__(self, offset: int = 0) -> None:
        # ``offset`` is the durable cursor — only advanced after a record is
        # delivered (or definitively discarded by cwd filter). On crash recovery
        # the watcher resumes from this offset.
        self.offset = offset
        # ``scan_offset`` tracks how far ``_drain_file`` has read on the current
        # pass. It can move ahead of ``offset`` while records sit in ``buffer``
        # waiting for cwd resolution; the durable cursor catches up only after
        # those records are flushed (or dropped).
        self.scan_offset = offset
        self.session_id = ""
        self.matches_cwd: Optional[bool] = None
        # Holds parsed records whose cwd disposition is still unknown. The
        # bytes for these records live between ``offset`` and ``scan_offset``.
        self.buffer: List[Dict[str, Any]] = []
        # Byte offsets immediately after each buffered record, in order. Used
        # to slide ``offset`` forward by exactly the right amount when the
        # buffer is flushed (or dropped on cwd mismatch).
        self.buffer_ends: List[int] = []
        self.ignored = False


RECENT_SESSION_REPLAY_SECONDS = 300.0


def _default_session_dir() -> Path:
    explicit_session_dir = os.environ.get("LAPDOG_CODEX_SESSION_DIR")
    if explicit_session_dir:
        return Path(explicit_session_dir).expanduser()
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home).expanduser() / "sessions"
    return Path.home() / ".codex" / "sessions"


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


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
    proxy_session_key: Optional[str] = None,
) -> bool:
    body = {"session_id": session_id, "record": record, "source_path": str(source_path)}
    if proxy_session_key:
        body["proxy_session_key"] = proxy_session_key
    try:
        response = requests.post(
            f"{lapdog_url.rstrip('/')}/codex/hooks",
            json=body,
            timeout=2,
        )
        if response is not None and response.status_code >= 400:
            print(
                "lapdog codex watcher: hook post failed "
                f"status={response.status_code} session_id={session_id} source_path={source_path}",
                file=sys.stderr,
                flush=True,
            )
            return False
    except Exception as exc:
        print(
            f"lapdog codex watcher: hook post failed session_id={session_id} source_path={source_path}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        return False
    return True


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


def _drain_file(
    path: Path,
    state: FileState,
    lapdog_url: str,
    cwd: str,
    proxy_session_key: Optional[str] = None,
) -> Optional[str]:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size < state.offset:
        # File was truncated or replaced; reset and replay from the beginning.
        print(
            f"lapdog codex watcher: truncation detected for {path} "
            f"(size={size} < offset={state.offset}); replaying from 0",
            file=sys.stderr,
            flush=True,
        )
        state.offset = 0
        state.scan_offset = 0
        state.session_id = ""
        state.matches_cwd = None
        state.buffer.clear()
        state.buffer_ends.clear()
    # Always resume scanning from where we left off in the previous pass —
    # which may be ahead of state.offset because buffered records have not
    # been delivered yet.
    if state.scan_offset < state.offset:
        state.scan_offset = state.offset
    try:
        with path.open("rb") as f:
            f.seek(state.scan_offset)
            data = f.read()
    except OSError:
        return None

    if not data:
        return None
    if data.endswith(b"\n"):
        complete_data = data
    else:
        complete_end = data.rfind(b"\n") + 1
        if complete_end <= 0:
            return None
        complete_data = data[:complete_end]

    posted_session_id: Optional[str] = None
    cursor = state.scan_offset
    # Split on b"\n" only — splitlines() also breaks on \r, NEL, etc., which
    # corrupts records whose JSON values contain those bytes.
    chunks = complete_data.split(b"\n")
    # split() yields one trailing "" because complete_data ends with \n.
    for chunk in chunks[:-1]:
        line_bytes = chunk + b"\n"
        line_end = cursor + len(line_bytes)
        cursor = line_end
        state.scan_offset = line_end
        line = chunk.strip()
        if not line:
            # Blank line — no record to deliver. If nothing is buffered, the
            # durable cursor can safely advance past the blank.
            if not state.buffer:
                state.offset = line_end
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # Malformed line is unrecoverable; only advance the durable cursor
            # if nothing is buffered (otherwise we'd lose buffered records on
            # a subsequent crash).
            if not state.buffer:
                state.offset = line_end
            continue

        session_id = _record_session_id(record)
        if session_id:
            state.session_id = session_id

        record_cwd = _record_cwd(record)
        if record_cwd and state.matches_cwd is None:
            state.matches_cwd = _is_under(record_cwd, cwd)

        if state.matches_cwd is None:
            # cwd disposition unknown — hold the record in memory. Do NOT
            # advance state.offset; if the watcher dies before disposition
            # resolves, those bytes must be re-read on restart.
            state.buffer.append(record)
            state.buffer_ends.append(line_end)
            continue

        if state.matches_cwd is False:
            # Session is in a non-matching cwd; drop buffered records and
            # advance the durable cursor past everything we scanned.
            state.buffer.clear()
            state.buffer_ends.clear()
            state.offset = line_end
            continue

        if state.session_id:
            if state.buffer:
                for buffered, buffered_end in zip(state.buffer, state.buffer_ends):
                    if not _post_record(
                        lapdog_url, state.session_id, buffered, path, proxy_session_key=proxy_session_key
                    ):
                        # Rewind the scan cursor so the unsent records are
                        # re-read (and the still-buffered ones are re-tried)
                        # on the next pass.
                        state.scan_offset = state.offset
                        state.buffer.clear()
                        state.buffer_ends.clear()
                        return posted_session_id
                    state.offset = buffered_end
                state.buffer.clear()
                state.buffer_ends.clear()
            if not _post_record(lapdog_url, state.session_id, record, path, proxy_session_key=proxy_session_key):
                # Roll scan back to the durable cursor so the failed record
                # is re-read on the next pass.
                state.scan_offset = state.offset
                return posted_session_id
            posted_session_id = state.session_id
            state.offset = line_end

    return posted_session_id


def _prime_file_state(path: Path, state: FileState, cwd: str, up_to: int) -> None:
    """Read old records only to learn session id and cwd; do not post them."""
    try:
        with path.open("r") as f:
            while True:
                if f.tell() >= up_to:
                    break
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                session_id = _record_session_id(record)
                if session_id:
                    state.session_id = session_id
                record_cwd = _record_cwd(record)
                if record_cwd and state.matches_cwd is None:
                    state.matches_cwd = _is_under(record_cwd, cwd)
    except OSError:
        return


def _iter_jsonl_files(session_dir: Path) -> List[Path]:
    if not session_dir.exists():
        return []
    return sorted(session_dir.rglob("*.jsonl"), key=lambda p: p.stat().st_mtime if p.exists() else 0)


def _initial_offset_for_file(stat_mtime: float, stat_size: int, started_at: float, replay_recent_seconds: float) -> int:
    if stat_mtime >= started_at - replay_recent_seconds:
        return 0
    return stat_size


CURSOR_SAVE_INTERVAL_SECONDS = 1.0


def _sync_cursor(cursor: CursorState, states: Dict[Path, FileState]) -> None:
    cursor.files = {str(path): state.offset for path, state in states.items()}


def _maybe_save_cursor(
    cursor_path: Optional[Path],
    cursor: CursorState,
    states: Dict[Path, FileState],
    last_save: float,
    now: float,
    force: bool = False,
) -> float:
    if cursor_path is None:
        return last_save
    if not force and (now - last_save) < CURSOR_SAVE_INTERVAL_SECONDS:
        return last_save
    _sync_cursor(cursor, states)
    try:
        save_cursor_atomic(cursor_path, cursor)
    except OSError as exc:
        print(f"lapdog codex watcher: cursor save failed: {exc}", file=sys.stderr, flush=True)
        return last_save
    return now


def watch_codex_sessions(
    lapdog_url: str,
    cwd: str,
    parent_pid: int,
    session_dir: Path,
    poll_interval: float = 0.25,
    flush_seconds: float = 2.0,
    replay_recent_seconds: float = RECENT_SESSION_REPLAY_SECONDS,
    ready_file: Optional[Path] = None,
    proxy_session_key: Optional[str] = None,
    cursor_path: Optional[Path] = None,
) -> None:
    states: Dict[Path, FileState] = {}
    started_at = time.time()
    initial_paths = set(_iter_jsonl_files(session_dir)) if proxy_session_key else set()
    parent_dead_at: Optional[float] = None
    cursor: CursorState = load_cursor(cursor_path) if cursor_path is not None else CursorState()
    last_cursor_save = 0.0
    if ready_file is not None:
        try:
            ready_file.parent.mkdir(parents=True, exist_ok=True)
            ready_file.write_text("ready\n")
        except OSError:
            pass
    print(
        "lapdog codex watcher: ready " f"cwd={cwd} parent_pid={parent_pid} session_dir={session_dir}",
        file=sys.stderr,
        flush=True,
    )

    while True:
        for path in _iter_jsonl_files(session_dir):
            if path not in states:
                try:
                    stat = path.stat()
                except OSError:
                    continue
                cursor_offset = cursor.files.get(str(path))
                if cursor_offset is not None and cursor_offset <= stat.st_size:
                    # Resume from the persisted offset (crash-safe).
                    initial_offset = cursor_offset
                elif proxy_session_key and path in initial_paths:
                    # With proxy correlation, files present before this watcher
                    # starts belong to earlier Codex sessions. Keep advancing
                    # their offsets without posting later appends.
                    initial_offset = stat.st_size
                else:
                    # First time seeing this file: replay recent rollouts to
                    # avoid missing the session_meta/turn_context records.
                    initial_offset = _initial_offset_for_file(
                        stat_mtime=stat.st_mtime,
                        stat_size=stat.st_size,
                        started_at=started_at,
                        replay_recent_seconds=replay_recent_seconds,
                    )
                states[path] = FileState(offset=initial_offset)
                if proxy_session_key and path in initial_paths:
                    states[path].ignored = True
                if initial_offset and not states[path].ignored:
                    _prime_file_state(path, states[path], cwd, initial_offset)
            if states[path].ignored:
                try:
                    stat = path.stat()
                except OSError:
                    continue
                if stat.st_size < states[path].offset:
                    states[path] = FileState(offset=0)
                else:
                    states[path].offset = stat.st_size
                    continue
            _drain_file(
                path,
                states[path],
                lapdog_url,
                cwd,
                proxy_session_key=proxy_session_key,
            )

        last_cursor_save = _maybe_save_cursor(cursor_path, cursor, states, last_cursor_save, time.time())

        if not _process_exists(parent_pid):
            if parent_dead_at is None:
                parent_dead_at = time.time()
            elif time.time() - parent_dead_at >= flush_seconds:
                break
        else:
            parent_dead_at = None

        time.sleep(poll_interval)

    for path, state in list(states.items()):
        _drain_file(
            path,
            state,
            lapdog_url,
            cwd,
            proxy_session_key=proxy_session_key,
        )
    _maybe_save_cursor(cursor_path, cursor, states, last_cursor_save, time.time(), force=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Tail Codex session JSONL files and post records to Lapdog.")
    parser.add_argument("--lapdog-url", required=True)
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--parent-pid", required=True, type=int)
    parser.add_argument("--session-dir", default=str(_default_session_dir()))
    parser.add_argument("--poll-interval", default=0.25, type=float)
    parser.add_argument("--flush-seconds", default=2.0, type=float)
    parser.add_argument("--replay-recent-seconds", default=RECENT_SESSION_REPLAY_SECONDS, type=float)
    parser.add_argument("--ready-file")
    parser.add_argument("--proxy-session-key")
    parser.add_argument("--cursor-path", default=CODEX_CURSOR_FILE)
    args = parser.parse_args()

    cursor_path = Path(args.cursor_path).expanduser() if args.cursor_path else None
    watch_codex_sessions(
        lapdog_url=args.lapdog_url,
        cwd=args.cwd,
        parent_pid=args.parent_pid,
        session_dir=Path(args.session_dir).expanduser(),
        poll_interval=args.poll_interval,
        flush_seconds=args.flush_seconds,
        replay_recent_seconds=args.replay_recent_seconds,
        ready_file=Path(args.ready_file).expanduser() if args.ready_file else None,
        proxy_session_key=args.proxy_session_key,
        cursor_path=cursor_path,
    )


if __name__ == "__main__":
    main()
