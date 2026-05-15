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
from typing import Set

import requests

from lapdog.codex_cursor import CursorState
from lapdog.codex_cursor import load_cursor
from lapdog.codex_cursor import save_cursor_atomic
from lapdog.paths import CODEX_CURSOR_FILE

# Module-level connection-pooled session — avoids reopening a TCP/SSL
# connection on every record post. Tests patch ``_session.post`` directly to
# intercept; production code calls ``_session.post(...)``.
_session = requests.Session()
# Timeout tuple: (connect_timeout, read_timeout). The hook handler runs in the
# same process and should respond within a few hundred ms, so 0.5s connect is
# plenty; reads can take longer when assembled spans are large.
_POST_TIMEOUT = (0.5, 2.0)


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

# Hard cap on per-line bytes. A single JSONL record larger than this is
# dropped with a stderr warning instead of being buffered in memory.
MAX_LINE_BYTES = 10 * 1024 * 1024  # 10MB

# Hard cap on records held in FileState.buffer while waiting for cwd
# disposition. Beyond this we treat the session as non-matching and discard
# the buffer — clearer signal than silently dropping records.
MAX_BUFFER_RECORDS = 1000


def _default_session_dir() -> Path:
    explicit_session_dir = os.environ.get("LAPDOG_CODEX_SESSION_DIR")
    if explicit_session_dir:
        return Path(explicit_session_dir).expanduser()
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home).expanduser() / "sessions"
    return Path.home() / ".codex" / "sessions"


def _process_exists(pid: int, expected_start: Optional[float] = None) -> bool:
    """Return True if `pid` is alive and (optionally) matches `expected_start`.

    Without psutil installed, falls back to ``os.kill(pid, 0)``; this catches
    no-such-process but does NOT detect PID reuse. When psutil is available
    and `expected_start` is supplied, also compares ``proc.create_time()`` so
    a recycled PID is treated as dead.
    """
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    try:
        proc = psutil.Process(pid)
        if expected_start is not None and abs(proc.create_time() - expected_start) > 0.1:
            return False
        return bool(proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE)
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
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
        response = _session.post(
            f"{lapdog_url.rstrip('/')}/codex/hooks",
            json=body,
            timeout=_POST_TIMEOUT,
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

    posted_session_id: Optional[str] = None
    try:
        f = path.open("rb")
    except OSError:
        return None
    try:
        f.seek(state.scan_offset)
        cursor = state.scan_offset
        # readline() with a size hint caps a single line at MAX_LINE_BYTES + 1
        # bytes; if the result is exactly MAX_LINE_BYTES + 1 and doesn't end
        # in \n, the line is over-cap and we discard it.
        while True:
            line_bytes = f.readline(MAX_LINE_BYTES + 1)
            if not line_bytes:
                break
            if not line_bytes.endswith(b"\n"):
                # Either an oversized line we read up to the cap with no
                # newline in sight, or an incomplete trailing line waiting
                # for more bytes to be flushed. Distinguish by length.
                if len(line_bytes) > MAX_LINE_BYTES:
                    # Skip past the rest of this oversized line and drop it.
                    cap_position = f.tell()
                    rest_skipped = 0
                    found_newline = False
                    while True:
                        chunk = f.read(64 * 1024)
                        if not chunk:
                            break
                        nl = chunk.find(b"\n")
                        if nl >= 0:
                            rest_skipped += nl + 1
                            # Rewind so the next readline starts right after \n.
                            f.seek(cap_position + rest_skipped)
                            found_newline = True
                            break
                        rest_skipped += len(chunk)
                    dropped_total = len(line_bytes) + rest_skipped
                    print(
                        f"lapdog codex watcher: dropping oversized line "
                        f"({dropped_total} bytes) in {path}",
                        file=sys.stderr,
                        flush=True,
                    )
                    cursor += dropped_total
                    state.scan_offset = cursor
                    # Only advance the durable cursor if nothing is buffered;
                    # otherwise wait for the buffer to flush first.
                    if not state.buffer:
                        state.offset = cursor
                    if not found_newline:
                        # Oversized line extends to EOF — give up this pass and
                        # try again next poll (newline may arrive).
                        break
                    continue
                # Partial trailing line — leave it for the next poll.
                break
            line_end = cursor + len(line_bytes)
            cursor = line_end
            state.scan_offset = line_end
            line = line_bytes.strip()
            if not line:
                # Blank line — no record to deliver. If nothing is buffered,
                # the durable cursor can safely advance past the blank.
                if not state.buffer:
                    state.offset = line_end
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # Malformed line is unrecoverable; only advance the durable
                # cursor if nothing is buffered (otherwise we'd lose buffered
                # records on a subsequent crash).
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
                if len(state.buffer) >= MAX_BUFFER_RECORDS:
                    # Buffer overflow — the session never identified its cwd
                    # within MAX_BUFFER_RECORDS records, so treat it as
                    # non-matching to avoid unbounded memory growth.
                    print(
                        f"lapdog codex watcher: buffer overflow ({MAX_BUFFER_RECORDS}+ records "
                        f"without cwd) for {path}; treating session as non-matching",
                        file=sys.stderr,
                        flush=True,
                    )
                    state.matches_cwd = False
                    state.buffer.clear()
                    state.buffer_ends.clear()
                    state.offset = line_end
                    continue
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
                    aborted = False
                    for buffered, buffered_end in zip(state.buffer, state.buffer_ends):
                        if not _post_record(
                            lapdog_url, state.session_id, buffered, path, proxy_session_key=proxy_session_key
                        ):
                            # Rewind scan so the unsent records are re-read on
                            # the next pass.
                            state.scan_offset = state.offset
                            state.buffer.clear()
                            state.buffer_ends.clear()
                            aborted = True
                            break
                        state.offset = buffered_end
                    if aborted:
                        return posted_session_id
                    state.buffer.clear()
                    state.buffer_ends.clear()
                if not _post_record(
                    lapdog_url, state.session_id, record, path, proxy_session_key=proxy_session_key
                ):
                    # Roll scan back to the durable cursor so the failed record
                    # is re-read on the next pass.
                    state.scan_offset = state.offset
                    return posted_session_id
                posted_session_id = state.session_id
                state.offset = line_end
    except OSError:
        return posted_session_id
    finally:
        f.close()

    return posted_session_id


def _prime_file_state(path: Path, state: FileState, cwd: str, up_to: int) -> None:
    """Read old records only to learn session id and cwd; do not post them.

    Reads in binary mode so byte offsets stay byte-accurate (text-mode
    ``tell()`` returns an opaque cookie on platforms where line endings or
    multi-byte decoding change the byte/character mapping). Each line is
    decoded with ``errors='replace'`` so multi-byte cwd values do not abort
    priming.
    """
    try:
        with path.open("rb") as f:
            read = 0
            while read < up_to:
                line_bytes = f.readline()
                if not line_bytes:
                    break
                read += len(line_bytes)
                line = line_bytes.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line.decode("utf-8", errors="replace"))
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
    """Merge live FileState offsets into ``cursor.files``.

    Uses merge semantics rather than replacement: entries in ``cursor.files``
    that don't appear in ``states`` (e.g. files glob-skipped on this pass, or
    rolled out of the watcher's view) are preserved. Stale phantoms are
    cleaned up by ``_prune_cursor`` at shutdown.
    """
    for path, state in states.items():
        cursor.files[str(path)] = state.offset


def _prune_cursor(cursor: CursorState) -> None:
    """Drop entries whose backing file no longer exists.

    Called only at force-save (shutdown) so a one-pass glob hiccup during
    normal operation cannot wipe out crash-recovery state for files that
    happen not to appear in this iteration's discovery results.
    """
    cursor.files = {path: offset for path, offset in cursor.files.items() if Path(path).exists()}


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
    if force:
        _prune_cursor(cursor)
    try:
        save_cursor_atomic(cursor_path, cursor)
    except OSError as exc:
        print(f"lapdog codex watcher: cursor save failed: {exc}", file=sys.stderr, flush=True)
        return last_save
    return now


def _discover_new_files(
    session_dir: Path,
    states: Dict[Path, FileState],
    cwd: str,
    cursor: CursorState,
    initial_paths: Set[Path],
    proxy_session_key: Optional[str],
    started_at: float,
    replay_recent_seconds: float,
) -> None:
    """Glob the session dir and seed FileState for any new rollouts."""
    for path in _iter_jsonl_files(session_dir):
        if path in states:
            continue
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
            # First time seeing this file: replay recent rollouts to avoid
            # missing the session_meta/turn_context records.
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
    discovery_interval: float = 1.0,
    parent_start_time: Optional[float] = None,
) -> None:
    states: Dict[Path, FileState] = {}
    started_at = time.time()
    initial_paths: Set[Path] = set(_iter_jsonl_files(session_dir)) if proxy_session_key else set()
    parent_dead_at: Optional[float] = None
    cursor: CursorState = load_cursor(cursor_path) if cursor_path is not None else CursorState()
    last_cursor_save = 0.0
    last_discovery = 0.0
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
        now = time.time()
        # Re-glob only periodically — file system enumeration is expensive
        # compared to the per-file readline drain.
        if now - last_discovery >= discovery_interval:
            _discover_new_files(
                session_dir=session_dir,
                states=states,
                cwd=cwd,
                cursor=cursor,
                initial_paths=initial_paths,
                proxy_session_key=proxy_session_key,
                started_at=started_at,
                replay_recent_seconds=replay_recent_seconds,
            )
            last_discovery = now

        for path, state in list(states.items()):
            try:
                if state.ignored:
                    try:
                        stat = path.stat()
                    except OSError:
                        continue
                    if stat.st_size < state.offset:
                        states[path] = FileState(offset=0)
                        states[path].ignored = True
                    else:
                        state.offset = stat.st_size
                        continue
                _drain_file(
                    path,
                    states[path],
                    lapdog_url,
                    cwd,
                    proxy_session_key=proxy_session_key,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                # Per-file failures (corrupt JSONL, decode errors, etc.) must
                # not kill the watcher — other rollouts may still need to be
                # captured. Log and move on.
                print(
                    f"lapdog codex watcher: per-file error for {path}: {exc!r}",
                    file=sys.stderr,
                    flush=True,
                )
                continue

        last_cursor_save = _maybe_save_cursor(cursor_path, cursor, states, last_cursor_save, time.time())

        if not _process_exists(parent_pid, expected_start=parent_start_time):
            if parent_dead_at is None:
                parent_dead_at = time.time()
            elif time.time() - parent_dead_at >= flush_seconds:
                break
        else:
            parent_dead_at = None

        time.sleep(poll_interval)

    # Final discovery + drain so any file written after the last discovery
    # tick (e.g. just before the parent died) is still captured.
    _discover_new_files(
        session_dir=session_dir,
        states=states,
        cwd=cwd,
        cursor=cursor,
        initial_paths=initial_paths,
        proxy_session_key=proxy_session_key,
        started_at=started_at,
        replay_recent_seconds=replay_recent_seconds,
    )
    for path, state in list(states.items()):
        try:
            _drain_file(
                path,
                state,
                lapdog_url,
                cwd,
                proxy_session_key=proxy_session_key,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            print(
                f"lapdog codex watcher: final drain error for {path}: {exc!r}",
                file=sys.stderr,
                flush=True,
            )
            continue
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
    parser.add_argument(
        "--discovery-interval",
        default=1.0,
        type=float,
        help="How often (seconds) to re-glob the session dir for new rollouts (default: 1.0).",
    )
    parser.add_argument(
        "--parent-start-time",
        default=None,
        type=float,
        help=(
            "Expected create_time() of the parent process (requires psutil). "
            "When set, treats the parent as dead if its start time differs, "
            "which guards against PID reuse after the parent exits."
        ),
    )
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
        discovery_interval=args.discovery_interval,
        parent_start_time=args.parent_start_time,
    )


if __name__ == "__main__":
    main()
