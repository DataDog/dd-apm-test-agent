"""Tail Codex session JSONL files and post records to Lapdog."""

import argparse
from dataclasses import dataclass
from dataclasses import field
import datetime
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from types import FrameType
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

import requests

from lapdog.paths import CODEX_CURSOR_FILE

# Module-level connection-pooled session — avoids reopening a TCP/SSL
# connection on every record post. Tests patch ``_session.post`` directly to
# intercept; production code calls ``_session.post(...)``.
_session = requests.Session()
# Timeout tuple: (connect_timeout, read_timeout). The hook handler runs in the
# same process and should respond within a few hundred ms, so 0.5s connect is
# plenty; reads can take longer when assembled spans are large.
_POST_TIMEOUT = (0.5, 2.0)


@dataclass
class CursorState:
    files: Dict[str, int] = field(default_factory=dict)
    saved_at: str = ""


def load_cursor(path: Path) -> CursorState:
    try:
        data = path.read_text()
    except FileNotFoundError:
        return CursorState()
    except OSError:
        return CursorState()
    try:
        parsed = json.loads(data) if data.strip() else {}
    except json.JSONDecodeError:
        return CursorState()
    if not isinstance(parsed, dict):
        return CursorState()
    files_raw = parsed.get("files")
    files: Dict[str, int] = {}
    if isinstance(files_raw, dict):
        for key, value in files_raw.items():
            if isinstance(key, str) and isinstance(value, int) and value >= 0:
                files[key] = value
    saved_at = parsed.get("saved_at", "")
    if not isinstance(saved_at, str):
        saved_at = ""
    return CursorState(files=files, saved_at=saved_at)


def save_cursor_atomic(path: Path, state: CursorState, prune_missing: bool = False) -> None:
    state.saved_at = datetime.datetime.now(tz=datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_file = lock_path.open("a")
    tmp_path = ""
    try:
        try:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass

        merged = load_cursor(path)
        merged.files.update(state.files)
        if prune_missing:
            merged.files = {file_path: offset for file_path, offset in merged.files.items() if Path(file_path).exists()}
        merged.saved_at = state.saved_at
        state.files = dict(merged.files)
        payload = {"files": merged.files, "saved_at": merged.saved_at}
        body = json.dumps(payload, indent=2, sort_keys=True)
        with tempfile.NamedTemporaryFile(
            "w",
            dir=str(path.parent),
            prefix=f"{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(body)
            tmp_path = tmp.name
        os.replace(tmp_path, path)
    finally:
        try:
            lock_file.close()
        except OSError:
            pass
        try:
            if tmp_path and Path(tmp_path).exists():
                Path(tmp_path).unlink()
        except OSError:
            pass


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
        self.session_meta: Optional[Dict[str, Any]] = None
        self.matches_cwd: Optional[bool] = None
        # Holds parsed records whose cwd disposition is still unknown. The
        # bytes for these records live between ``offset`` and ``scan_offset``.
        self.buffer: List[Tuple[int, Dict[str, Any]]] = []
        self.ignored = False
        self.resume_candidate = False
        self.resume_meta_posted = False
        self.session_name = ""

    def observe(self, record: Dict[str, Any], cwd: str, include_all_cwds: bool) -> None:
        session_id = _record_session_id(record)
        if session_id:
            self.session_id = session_id
            self.session_meta = record
        record_cwd = _record_cwd(record)
        if record_cwd and self.matches_cwd is None:
            self.matches_cwd = include_all_cwds or _is_under(record_cwd, cwd)

    def rewind(self) -> None:
        """Retry only records that have not been acknowledged."""
        self.scan_offset = self.offset
        self.buffer.clear()


class SessionNames:
    """Read Codex's append-only name index when it changes."""

    def __init__(self, session_dir: Path) -> None:
        self.path = session_dir.parent / "session_index.jsonl"
        self.names: Dict[str, str] = {}
        self._signature: Optional[Tuple[int, int]] = None

    def refresh(self) -> Dict[str, str]:
        try:
            stat = self.path.stat()
            signature = (stat.st_mtime_ns, stat.st_size)
            if signature == self._signature:
                return self.names
            names: Dict[str, str] = {}
            for _, entry in _read_records(self.path):
                if entry is not None:
                    session_id, name = entry.get("id"), entry.get("thread_name")
                    if isinstance(session_id, str) and isinstance(name, str) and name.strip():
                        names[session_id] = name.strip()
            self.names = names
            self._signature = signature
        except OSError:
            pass  # Names are optional; rollout capture must still work.
        return self.names


def _post_session_name(lapdog_url: str, session_id: str, name: str, path: Path, *, is_backfill: bool = False) -> bool:
    return _post_record(
        lapdog_url,
        session_id,
        {"type": "event_msg", "payload": {"type": "session_name", "name": name}},
        path,
        is_backfill=is_backfill,
    )


def _sync_session_name(lapdog_url: str, path: Path, state: FileState, names: Optional[Dict[str, str]]) -> None:
    if not names or state.ignored or state.matches_cwd is not True:
        return
    name = names.get(state.session_id)
    if name and name != state.session_name:
        if _post_session_name(lapdog_url, state.session_id, name, path):
            state.session_name = name


class SessionOwnership:
    """Track the rollout tree owned by one ``lapdog codex`` invocation."""

    def __init__(
        self,
        started_at: float,
        launch_token: str = "",
        parent_pid: Optional[int] = None,
        app: bool = False,
        client_log: Optional[Path] = None,
    ) -> None:
        self.started_at = started_at
        self.launch_token = launch_token
        self.parent_pid = parent_pid
        self.app = app
        self.open_paths: Set[str] = set()
        self.root_session_id = ""
        self.session_ids: Set[str] = set()
        self.client_log = client_log
        self.identity_offsets: Dict[Path, int] = {}
        self.client_ids: Dict[Path, Set[str]] = {}

    def _read_client_ids(self, path: Path, initial_offset: int = 0) -> Set[str]:
        """Read only correlation IDs; leave partial records for the next poll."""
        ids = self.client_ids.setdefault(path, set())
        try:
            offset = self.identity_offsets.get(path, initial_offset)
            if path.stat().st_size < offset:
                offset = initial_offset
                ids.clear()
            for end, record in _read_records(path, offset):
                self.identity_offsets[path] = end
                if record is None or not isinstance(record.get("payload"), dict):
                    continue
                payload = record["payload"]
                if path == self.client_log:
                    if record.get("dir") != "from_tui" or record.get("kind") != "op":
                        continue
                    item = payload.get("UserTurn", {})
                    client_id = item.get("client_user_message_id") if isinstance(item, dict) else None
                else:
                    item = payload.get("item", {})
                    if record.get("type") != "event_msg" or payload.get("type") != "item_completed":
                        continue
                    client_id = (
                        item.get("client_id") if isinstance(item, dict) and item.get("type") == "UserMessage" else None
                    )
                if isinstance(client_id, str) and client_id:
                    ids.add(client_id)
        except OSError:
            pass
        return ids

    def owns_path(self, path: Path, initial_offset: int = 0) -> bool:
        if str(path.resolve()) in self.open_paths:
            return True
        if self.client_log is None:
            return False
        # The same UUID is in the TUI's UserTurn and the daemon's UserMessage.
        # Do not infer ownership from cwd, timestamps, or the shared daemon PID.
        return bool(self._read_client_ids(self.client_log) & self._read_client_ids(path, initial_offset))

    def refresh(self) -> None:
        """Resolve picker/resume selection from files opened by the launched process.

        Failure leaves ownership unconfirmed. Never substitute the first file
        that happens to grow in the same working directory.
        """
        if self.parent_pid is None or self.app or self.root_session_id:
            return
        self.open_paths.clear()
        try:
            # npm launchers can keep the native Codex binary in a child process.
            processes = subprocess.run(["ps", "-axo", "pid=,ppid="], capture_output=True, text=True, timeout=2)
            parents: Dict[int, int] = {}
            for line in processes.stdout.splitlines():
                fields = line.split()
                if len(fields) == 2:
                    parents[int(fields[0])] = int(fields[1])
            pids = {self.parent_pid}
            while True:
                children = {pid for pid, parent in parents.items() if parent in pids} - pids
                if not children:
                    break
                pids.update(children)
            if Path("/proc/self/fd").is_dir():
                for pid in pids:
                    try:
                        self.open_paths.update(
                            str(path.resolve())
                            for path in Path(f"/proc/{pid}/fd").iterdir()
                            if str(path.resolve()).endswith(".jsonl")
                        )
                    except OSError:
                        continue
                return
            lsof = shutil.which("lsof")
            if lsof:
                result = subprocess.run(
                    [lsof, "-a", "-p", ",".join(map(str, sorted(pids))), "-Fn"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                self.open_paths.update(
                    line[1:] for line in result.stdout.splitlines() if line.startswith("n/") and line.endswith(".jsonl")
                )
        except (OSError, ValueError, subprocess.SubprocessError):
            pass

    def _started_before_watcher(self, payload: Dict[str, Any]) -> bool:
        timestamp = payload.get("timestamp")
        if not isinstance(timestamp, str) or not timestamp:
            return False
        try:
            started_at = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return False
        return started_at < self.started_at

    def accepts(self, record: Dict[str, Any], path: Optional[Path] = None) -> bool:
        payload = record.get("payload", {})
        if not isinstance(payload, dict):
            return False
        session_id = str(payload.get("id", ""))
        if not session_id:
            return False

        thread_source = str(payload.get("thread_source", ""))
        parent_session_id = str(payload.get("parent_thread_id", "") or payload.get("forked_from_id", ""))
        if session_id in self.session_ids:
            return True
        if parent_session_id in self.session_ids:
            self.session_ids.add(session_id)
            return True
        if self.app:
            # Shared-daemon CLI sessions also use source=vscode.
            originator = str(payload.get("originator", ""))
            if payload.get("source") in ("vscode", "app", "desktop") and not (
                originator in ("codex-tui", "codex_exec") or originator.startswith("lapdog_")
            ):
                self.session_ids.add(session_id)
                return True
            return False
        if not self.root_session_id:
            if (thread_source and thread_source != "user") or self._started_before_watcher(payload):
                return False
            marked = self.launch_token and payload.get("originator") == f"lapdog_{self.launch_token}"
            if not marked and (path is None or not self.owns_path(path)):
                return False
            self.root_session_id = session_id
            self.session_ids.add(session_id)
            return True

        return False

    def claim_resumed(self, session_id: str) -> bool:
        if not session_id or (self.root_session_id and self.root_session_id != session_id):
            return False
        self.root_session_id = session_id
        self.session_ids.add(session_id)
        return True


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

    Without psutil installed, falls back to a platform-specific existence
    probe; this catches no-such-process but does NOT detect PID reuse. When
    psutil is available and `expected_start` is supplied, also compares
    ``proc.create_time()`` so a recycled PID is treated as dead.
    """
    try:
        import psutil
    except ImportError:
        if os.name == "nt":
            return _windows_process_exists(pid)
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


def _windows_process_exists(pid: int) -> bool:
    """Return True if a Windows process can be opened or is access-denied."""
    import ctypes

    windll_name = "WinDLL"
    get_last_error_name = "get_last_error"
    try:
        windll_factory = getattr(ctypes, windll_name)
        get_last_error = getattr(ctypes, get_last_error_name)
    except AttributeError:
        return False

    kernel32 = windll_factory("kernel32", use_last_error=True)
    process_query_limited_information = 0x1000
    error_access_denied = 5
    handle = kernel32.OpenProcess(process_query_limited_information, False, int(pid))
    if handle:
        kernel32.CloseHandle(handle)
        return True
    return int(get_last_error()) == error_access_denied


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
    *,
    is_backfill: bool = False,
) -> bool:
    body: Dict[str, Any] = {"session_id": session_id, "record": record, "source_path": str(source_path)}
    if proxy_session_key:
        body["proxy_session_key"] = proxy_session_key
    if is_backfill:
        body["backfill"] = True
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


def _shutdown_record() -> Dict[str, Any]:
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "type": "event_msg",
        "payload": {"type": "shutdown_complete"},
    }


def _post_shutdown_complete(
    lapdog_url: str,
    session_id: str,
    source_path: Path,
    proxy_session_key: Optional[str] = None,
    *,
    is_backfill: bool = False,
) -> bool:
    return _post_record(
        lapdog_url,
        session_id,
        _shutdown_record(),
        source_path,
        proxy_session_key=proxy_session_key,
        is_backfill=is_backfill,
    )


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


def _read_records(
    path: Path, offset: int = 0, up_to: Optional[int] = None
) -> Iterator[Tuple[int, Optional[Dict[str, Any]]]]:
    """Yield complete records and byte offsets; None marks a discarded line.

    Partial lines, including oversized ones, stay before the cursor until
    their newline arrives. All readers use the same size and decoding rules.
    """
    with path.open("rb") as stream:
        stream.seek(offset)
        while up_to is None or stream.tell() < up_to:
            line = stream.readline(MAX_LINE_BYTES + 1)
            oversized = len(line) > MAX_LINE_BYTES
            if oversized:
                while line and not line.endswith(b"\n"):
                    line = stream.readline(MAX_LINE_BYTES + 1)
            if not line.endswith(b"\n"):
                return
            end = stream.tell()
            record = None
            if oversized:
                print(f"lapdog codex watcher: dropping oversized line in {path}", file=sys.stderr, flush=True)
            else:
                try:
                    parsed = json.loads(line.decode("utf-8", errors="replace"))
                    if isinstance(parsed, dict):
                        record = parsed
                except ValueError:
                    pass
            yield end, record


def _drain_file(
    path: Path,
    state: FileState,
    lapdog_url: str,
    cwd: str,
    proxy_session_key: Optional[str] = None,
    include_all_cwds: bool = False,
    session_ownership: Optional[SessionOwnership] = None,
    session_names: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    if state.ignored:
        return None
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size < state.scan_offset:
        # File was truncated or replaced; reset and replay from the beginning.
        print(
            f"lapdog codex watcher: truncation detected for {path} "
            f"(size={size} < scan_offset={state.scan_offset}); replaying from 0",
            file=sys.stderr,
            flush=True,
        )
        state.offset = 0
        state.scan_offset = 0
        state.session_id = ""
        state.session_meta = None
        state.matches_cwd = None
        state.rewind()
    if session_ownership is not None and state.session_meta is not None:
        if not session_ownership.accepts(state.session_meta, path):
            return None
    state.scan_offset = max(state.scan_offset, state.offset)

    posted_session_id: Optional[str] = None
    try:
        for line_end, record in _read_records(path, state.scan_offset):
            state.scan_offset = line_end
            if record is None:
                if not state.buffer:
                    state.offset = line_end
                continue
            state.observe(record, cwd, include_all_cwds)
            if _record_session_id(record) and session_ownership is not None:
                if not session_ownership.accepts(record, path):
                    # Retry discovery: a child may precede its parent, or a
                    # newly opened rollout may not yet be in the process scan.
                    state.rewind()
                    return posted_session_id
                state.matches_cwd = True
            if state.matches_cwd is None or (state.matches_cwd and not state.session_id):
                if len(state.buffer) >= MAX_BUFFER_RECORDS:
                    print(
                        f"lapdog codex watcher: buffer overflow ({MAX_BUFFER_RECORDS}+ records "
                        f"without session metadata) for {path}; treating session as non-matching",
                        file=sys.stderr,
                        flush=True,
                    )
                    state.matches_cwd = False
                else:
                    state.buffer.append((line_end, record))
                    continue
            if state.matches_cwd is False:
                state.buffer.clear()
                state.offset = line_end
                continue
            _sync_session_name(lapdog_url, path, state, session_names)
            state.buffer.append((line_end, record))
            for end, pending in state.buffer:
                if not _post_record(lapdog_url, state.session_id, pending, path, proxy_session_key=proxy_session_key):
                    state.rewind()
                    return posted_session_id
                posted_session_id = state.session_id
                state.offset = end
            state.buffer.clear()
    except OSError:
        return posted_session_id

    _sync_session_name(lapdog_url, path, state, session_names)
    return posted_session_id


def _prime_file_state(
    path: Path,
    state: FileState,
    cwd: str,
    up_to: int,
    include_all_cwds: bool = False,
    stop_after_meta: bool = False,
) -> None:
    """Read old records only to learn session id and cwd; do not post them."""
    try:
        for _, record in _read_records(path, up_to=up_to):
            if record is not None:
                state.observe(record, cwd, include_all_cwds)
            if stop_after_meta and state.session_id and state.matches_cwd is not None:
                break
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
    try:
        save_cursor_atomic(cursor_path, cursor, prune_missing=force)
    except OSError as exc:
        print(f"lapdog codex watcher: cursor save failed: {exc}", file=sys.stderr, flush=True)
        return last_save
    return now


def _discover_new_files(
    session_dir: Path,
    states: Dict[Path, FileState],
    cwd: str,
    cursor: CursorState,
    initial_offsets: Dict[Path, int],
    proxy_session_key: Optional[str],
    started_at: float,
    replay_recent_seconds: float,
    include_all_cwds: bool = False,
    resume_mode: bool = False,
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
        has_valid_cursor = cursor_offset is not None and cursor_offset <= stat.st_size
        has_truncated_cursor = cursor_offset is not None and cursor_offset > stat.st_size
        initial_path = bool(proxy_session_key and path in initial_offsets)
        ignore_initial_path = initial_path and not resume_mode
        if initial_path:
            # A proxy watcher belongs to the Codex process it was launched
            # with. For resume, keep the startup size so records written
            # before the first discovery pass are not lost or replayed.
            initial_offset = initial_offsets[path]
        elif has_valid_cursor:
            # Resume from the persisted offset (crash-safe).
            initial_offset = cursor_offset or 0
        elif has_truncated_cursor:
            # The rollout was truncated/replaced after the last cursor save.
            # Re-read it rather than treating it as an unrelated pre-existing
            # proxy-mode file.
            initial_offset = 0
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
        states[path].resume_candidate = bool(initial_path and resume_mode)
        if ignore_initial_path:
            states[path].ignored = True
        if initial_offset and not states[path].ignored:
            _prime_file_state(
                path,
                states[path],
                cwd,
                initial_offset,
                include_all_cwds=include_all_cwds,
                stop_after_meta=states[path].resume_candidate,
            )


def _prepare_resumed_file(
    path: Path,
    state: FileState,
    lapdog_url: str,
    session_ownership: Optional[SessionOwnership],
    proxy_session_key: Optional[str],
    resume_session_id: Optional[str],
    resume_all_cwds: bool,
) -> bool:
    """Claim one old rollout after it grows, then send only its metadata."""
    if not state.resume_candidate or state.ignored:
        return True
    if session_ownership is None:
        return False
    if state.resume_meta_posted:
        return True
    try:
        if path.stat().st_size <= state.offset:
            return False
    except OSError:
        return False
    if not state.session_meta:
        return False
    parent_id = state.session_meta.get("payload", {}).get("parent_thread_id")
    owned_child = parent_id in session_ownership.session_ids
    if owned_child:
        session_ownership.session_ids.add(state.session_id)
    else:
        if resume_session_id and state.session_id != resume_session_id:
            return False  # It may be a child whose parent has not been claimed yet.
        if not resume_session_id and not session_ownership.owns_path(path, state.offset):
            return False
        if not resume_session_id and not resume_all_cwds and state.matches_cwd is not True:
            return False
        if not session_ownership.claim_resumed(state.session_id):
            return False
    if owned_child or resume_session_id or resume_all_cwds:
        state.matches_cwd = True
    if not state.resume_meta_posted:
        if not _post_record(lapdog_url, state.session_id, state.session_meta, path, proxy_session_key):
            return False
        state.resume_meta_posted = True
    return True


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
    include_all_cwds: bool = False,
    resume_mode: bool = False,
    resume_session_id: Optional[str] = None,
    resume_all_cwds: bool = False,
    client_log: Optional[Path] = None,
) -> None:
    states: Dict[Path, FileState] = {}
    session_names = SessionNames(session_dir)
    started_at = time.time()
    initial_offsets: Dict[Path, int] = {}
    if proxy_session_key:
        for path in _iter_jsonl_files(session_dir):
            try:
                initial_offsets[path] = path.stat().st_size
            except OSError:
                continue
    parent_dead_at: Optional[float] = None
    cursor: CursorState = load_cursor(cursor_path) if cursor_path is not None else CursorState()
    session_ownership = SessionOwnership(
        started_at, proxy_session_key or "", parent_pid, app=include_all_cwds, client_log=client_log
    )
    last_cursor_save = 0.0
    last_discovery = 0.0
    final_pass = False
    shutdown_sessions: Dict[str, Path] = {}
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
        names = session_names.refresh()
        # Re-glob only periodically — file system enumeration is expensive
        # compared to the per-file readline drain.
        if final_pass or now - last_discovery >= discovery_interval:
            session_ownership.refresh()
            _discover_new_files(
                session_dir=session_dir,
                states=states,
                cwd=cwd,
                cursor=cursor,
                initial_offsets=initial_offsets,
                proxy_session_key=proxy_session_key,
                started_at=started_at,
                replay_recent_seconds=replay_recent_seconds,
                include_all_cwds=include_all_cwds,
                resume_mode=resume_mode,
            )
            last_discovery = now

        for path, state in list(states.items()):
            try:
                if state.ignored:
                    state.offset = path.stat().st_size
                    continue
                if not _prepare_resumed_file(
                    path,
                    state,
                    lapdog_url,
                    session_ownership,
                    proxy_session_key,
                    resume_session_id,
                    resume_all_cwds,
                ):
                    continue
                posted_session_id = _drain_file(
                    path,
                    state,
                    lapdog_url,
                    cwd,
                    proxy_session_key=proxy_session_key,
                    include_all_cwds=include_all_cwds,
                    session_ownership=session_ownership,
                    session_names=names,
                )
                session_id = posted_session_id or state.session_id
                if final_pass and session_id in session_ownership.session_ids and state.matches_cwd is not False:
                    shutdown_sessions[session_id] = path
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

        if final_pass:
            break
        last_cursor_save = _maybe_save_cursor(cursor_path, cursor, states, last_cursor_save, time.time())

        if not _process_exists(parent_pid, expected_start=parent_start_time):
            if parent_dead_at is None:
                parent_dead_at = time.time()
            elif time.time() - parent_dead_at >= flush_seconds:
                final_pass = True
        else:
            parent_dead_at = None

        if not final_pass:
            time.sleep(poll_interval)
    for session_id, path in shutdown_sessions.items():
        _post_shutdown_complete(lapdog_url, session_id, path, proxy_session_key=proxy_session_key)
    _maybe_save_cursor(cursor_path, cursor, states, last_cursor_save, time.time(), force=True)


def _terminate(signum: int, frame: Optional[FrameType]) -> None:
    raise SystemExit(0)


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
    parser.add_argument("--client-log", type=Path)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--resume-session-id")
    parser.add_argument("--resume-all-cwds", action="store_true")
    parser.add_argument(
        "--include-all-cwds",
        action="store_true",
        help="Capture Codex sessions regardless of session cwd. Used for Codex Desktop app launches.",
    )
    parser.add_argument("--cursor-path", default=CODEX_CURSOR_FILE)
    args = parser.parse_args()

    cursor_path = Path(args.cursor_path).expanduser() if args.cursor_path else None
    previous_sigterm = signal.signal(signal.SIGTERM, _terminate)
    try:
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
            include_all_cwds=args.include_all_cwds,
            resume_mode=args.resume,
            resume_session_id=args.resume_session_id,
            resume_all_cwds=args.resume_all_cwds,
            client_log=args.client_log,
        )
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        if args.client_log:
            args.client_log.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
