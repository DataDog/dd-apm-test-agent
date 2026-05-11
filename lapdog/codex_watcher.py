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


class FileState:
    def __init__(self, offset: int = 0) -> None:
        self.offset = offset
        self.session_id = ""
        self.matches_cwd: Optional[bool] = None
        self.buffer: List[Dict[str, Any]] = []


RECENT_SESSION_REPLAY_SECONDS = 300.0


def _default_session_dir() -> Path:
    return Path(os.environ.get("LAPDOG_CODEX_SESSION_DIR", Path.home() / ".codex" / "sessions")).expanduser()


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _post_record(lapdog_url: str, session_id: str, record: Dict[str, Any], source_path: Path) -> None:
    try:
        response = requests.post(
            f"{lapdog_url.rstrip('/')}/codex/hooks",
            json={"session_id": session_id, "record": record, "source_path": str(source_path)},
            timeout=2,
        )
        if response is not None and response.status_code >= 400:
            print(
                "lapdog codex watcher: hook post failed "
                f"status={response.status_code} session_id={session_id} source_path={source_path}",
                file=sys.stderr,
                flush=True,
            )
    except Exception as exc:
        print(
            f"lapdog codex watcher: hook post failed session_id={session_id} source_path={source_path}: {exc}",
            file=sys.stderr,
            flush=True,
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


def _drain_file(path: Path, state: FileState, lapdog_url: str, cwd: str) -> None:
    try:
        with path.open("r") as f:
            f.seek(state.offset)
            lines = f.readlines()
            state.offset = f.tell()
    except OSError:
        return

    for line in lines:
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
            state.matches_cwd = os.path.abspath(record_cwd) == os.path.abspath(cwd)

        if state.matches_cwd is None:
            state.buffer.append(record)
            continue

        if state.matches_cwd is False:
            state.buffer.clear()
            continue

        if state.session_id:
            if state.buffer:
                for buffered in state.buffer:
                    _post_record(lapdog_url, state.session_id, buffered, path)
                state.buffer.clear()
            _post_record(lapdog_url, state.session_id, record, path)


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
                    state.matches_cwd = os.path.abspath(record_cwd) == os.path.abspath(cwd)
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


def watch_codex_sessions(
    lapdog_url: str,
    cwd: str,
    parent_pid: int,
    session_dir: Path,
    poll_interval: float = 0.25,
    flush_seconds: float = 2.0,
    replay_recent_seconds: float = RECENT_SESSION_REPLAY_SECONDS,
    ready_file: Optional[Path] = None,
) -> None:
    states: Dict[Path, FileState] = {}
    started_at = time.time()
    parent_dead_at: Optional[float] = None
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
                # The watcher is a separate Python process, so Codex can create
                # and write the session file before this loop starts. Replay
                # recent files to avoid missing the session_meta/turn_context
                # records that make the session visible in Lapdog.
                initial_offset = _initial_offset_for_file(
                    stat_mtime=stat.st_mtime,
                    stat_size=stat.st_size,
                    started_at=started_at,
                    replay_recent_seconds=replay_recent_seconds,
                )
                states[path] = FileState(offset=initial_offset)
                if initial_offset:
                    _prime_file_state(path, states[path], cwd, initial_offset)
            _drain_file(path, states[path], lapdog_url, cwd)

        if not _process_exists(parent_pid):
            if parent_dead_at is None:
                parent_dead_at = time.time()
            elif time.time() - parent_dead_at >= flush_seconds:
                break
        else:
            parent_dead_at = None

        time.sleep(poll_interval)

    for path, state in list(states.items()):
        _drain_file(path, state, lapdog_url, cwd)


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
    args = parser.parse_args()

    watch_codex_sessions(
        lapdog_url=args.lapdog_url,
        cwd=args.cwd,
        parent_pid=args.parent_pid,
        session_dir=Path(args.session_dir).expanduser(),
        poll_interval=args.poll_interval,
        flush_seconds=args.flush_seconds,
        replay_recent_seconds=args.replay_recent_seconds,
        ready_file=Path(args.ready_file).expanduser() if args.ready_file else None,
    )


if __name__ == "__main__":
    main()
