import json
from pathlib import Path
from typing import Any

from lapdog.codex_watcher import FileState
from lapdog.codex_watcher import _drain_file
from lapdog.codex_watcher import _initial_offset_for_file
from lapdog.codex_watcher import _prime_file_state
from lapdog.codex_watcher import watch_codex_sessions


def _append(path: Path, record: Any) -> None:
    with path.open("a") as f:
        f.write(json.dumps(record) + "\n")


def test_drain_file_buffers_until_matching_cwd(monkeypatch, tmp_path):
    posts = []

    def fake_post(url, json, timeout):
        posts.append(json)

    monkeypatch.setattr("lapdog.codex_watcher.requests.post", fake_post)
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "event_msg", "payload": {"type": "task_started"}})
    _append(
        session_file,
        {
            "type": "session_meta",
            "payload": {
                "id": "sess-1",
                "cwd": str(tmp_path),
            },
        },
    )

    _drain_file(session_file, FileState(), "http://localhost:8126", str(tmp_path))

    assert [post["record"]["type"] for post in posts] == ["event_msg", "session_meta"]
    assert all(post["session_id"] == "sess-1" for post in posts)


def test_drain_file_includes_proxy_session_key(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher.requests.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-keyed", "cwd": str(tmp_path)}})

    _drain_file(session_file, FileState(), "http://localhost:8126", str(tmp_path), proxy_session_key="proxy-key")

    assert posts[0]["session_id"] == "sess-keyed"
    assert posts[0]["proxy_session_key"] == "proxy-key"


def test_drain_file_respects_allowed_session_id(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher.requests.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-other", "cwd": str(tmp_path)}})

    posted_session_id = _drain_file(
        session_file,
        FileState(),
        "http://localhost:8126",
        str(tmp_path),
        proxy_session_key="proxy-key",
        allowed_session_id="sess-claimed",
    )

    assert posted_session_id is None
    assert posts == []


def test_drain_file_drops_non_matching_cwd(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher.requests.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(
        session_file,
        {
            "type": "session_meta",
            "payload": {
                "id": "sess-2",
                "cwd": str(tmp_path / "other"),
            },
        },
    )
    _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "hello"}})

    _drain_file(session_file, FileState(), "http://localhost:8126", str(tmp_path))

    assert posts == []


def test_drain_file_preserves_partial_jsonl_record(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher.requests.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    partial = '{"type":"session_meta","payload":{"id":"sess-partial","cwd":'
    session_file.write_text(partial)

    state = FileState()
    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    assert posts == []
    assert state.offset == 0

    with session_file.open("a") as f:
        f.write(json.dumps(str(tmp_path)) + "}}\n")

    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    assert [post["record"]["type"] for post in posts] == ["session_meta"]
    assert posts[0]["session_id"] == "sess-partial"
    assert state.offset == session_file.stat().st_size


def test_prime_file_state_learns_old_session_metadata(tmp_path):
    session_file = tmp_path / "rollout.jsonl"
    _append(
        session_file,
        {
            "type": "session_meta",
            "payload": {
                "id": "sess-resume",
                "cwd": str(tmp_path),
            },
        },
    )
    offset = session_file.stat().st_size
    _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "new"}})

    state = FileState(offset=offset)
    _prime_file_state(session_file, state, str(tmp_path), offset)

    assert state.session_id == "sess-resume"
    assert state.matches_cwd is True


def test_recent_existing_files_are_replayed_from_start():
    assert (
        _initial_offset_for_file(
            stat_mtime=95.0,
            stat_size=1234,
            started_at=100.0,
            replay_recent_seconds=300.0,
        )
        == 0
    )


def test_old_existing_files_are_tailed_from_end():
    assert (
        _initial_offset_for_file(
            stat_mtime=1.0,
            stat_size=1234,
            started_at=1000.0,
            replay_recent_seconds=300.0,
        )
        == 1234
    )


def test_watch_codex_sessions_writes_ready_file(monkeypatch, tmp_path):
    ready_file = tmp_path / "watcher.ready"
    monkeypatch.setattr("lapdog.codex_watcher._iter_jsonl_files", lambda session_dir: [])

    watch_codex_sessions(
        lapdog_url="http://localhost:8126",
        cwd=str(tmp_path),
        parent_pid=999999,
        session_dir=tmp_path,
        poll_interval=0.01,
        flush_seconds=0.01,
        ready_file=ready_file,
    )

    assert ready_file.read_text() == "ready\n"
