import json
import os
from pathlib import Path
from typing import Any

from lapdog.codex_cursor import CursorState
from lapdog.codex_cursor import load_cursor
from lapdog.codex_cursor import save_cursor_atomic
from lapdog.codex_watcher import FileState
from lapdog.codex_watcher import _default_session_dir
from lapdog.codex_watcher import _drain_file
from lapdog.codex_watcher import _initial_offset_for_file
from lapdog.codex_watcher import _is_under
from lapdog.codex_watcher import _prime_file_state
from lapdog.codex_watcher import watch_codex_sessions


def _append(path: Path, record: Any) -> None:
    with path.open("a") as f:
        f.write(json.dumps(record) + "\n")


def test_default_session_dir_uses_codex_home(monkeypatch, tmp_path):
    codex_home = tmp_path / "custom-codex-home"
    monkeypatch.delenv("LAPDOG_CODEX_SESSION_DIR", raising=False)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    assert _default_session_dir() == codex_home / "sessions"


def test_default_session_dir_prefers_lapdog_override(monkeypatch, tmp_path):
    session_dir = tmp_path / "custom-sessions"
    monkeypatch.setenv("LAPDOG_CODEX_SESSION_DIR", str(session_dir))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "custom-codex-home"))

    assert _default_session_dir() == session_dir


def test_is_under_accepts_descendant_cwd(tmp_path):
    root = tmp_path
    sub = tmp_path / "sub" / "deeper"
    sub.mkdir(parents=True)
    assert _is_under(str(sub), str(root)) is True
    assert _is_under(str(root), str(root)) is True


def test_is_under_rejects_prefix_without_separator(tmp_path):
    root = tmp_path / "a"
    sibling = tmp_path / "abc"
    root.mkdir()
    sibling.mkdir()
    # /tmp/a vs /tmp/abc: textually a prefix, but not a child directory.
    assert _is_under(str(sibling), str(root)) is False


def test_is_under_resolves_symlinks(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        # Platforms without symlink permissions skip the symlink branch.
        return
    nested = real / "child"
    nested.mkdir()
    # Watcher launched at the realpath should still match records that say
    # their cwd is via the symlink.
    assert _is_under(str(link / "child"), str(real)) is True
    assert _is_under(str(nested), str(link)) is True


def test_is_under_returns_false_for_empty_inputs():
    assert _is_under("", "/tmp") is False
    assert _is_under("/tmp", "") is False


def test_drain_file_matches_descendant_cwd(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher.requests.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    sub = tmp_path / "sub"
    sub.mkdir()
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-sub", "cwd": str(sub)}})

    _drain_file(session_file, FileState(), "http://localhost:8126", str(tmp_path))

    # Launcher cwd is the parent; the record cwd is a descendant — must match.
    assert [post["session_id"] for post in posts] == ["sess-sub"]


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


def test_drain_file_keeps_offset_when_post_fails(monkeypatch, tmp_path):
    posts = []
    status_codes = [500, 200]

    class FakeResponse:
        def __init__(self, status_code):
            self.status_code = status_code

    def fake_post(url, json, timeout):
        posts.append(json)
        return FakeResponse(status_codes.pop(0))

    monkeypatch.setattr("lapdog.codex_watcher.requests.post", fake_post)
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-retry", "cwd": str(tmp_path)}})

    state = FileState()
    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    assert state.offset == 0

    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    assert [post["session_id"] for post in posts] == ["sess-retry", "sess-retry"]
    assert state.offset == session_file.stat().st_size


def test_drain_file_posts_multiple_sessions_with_same_proxy_key(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher.requests.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_a = tmp_path / "rollout-a.jsonl"
    session_b = tmp_path / "rollout-b.jsonl"
    _append(session_a, {"type": "session_meta", "payload": {"id": "sess-a", "cwd": str(tmp_path)}})
    _append(session_b, {"type": "session_meta", "payload": {"id": "sess-b", "cwd": str(tmp_path)}})

    _drain_file(session_a, FileState(), "http://localhost:8126", str(tmp_path), proxy_session_key="proxy-key")
    _drain_file(session_b, FileState(), "http://localhost:8126", str(tmp_path), proxy_session_key="proxy-key")

    assert [post["session_id"] for post in posts] == ["sess-a", "sess-b"]
    assert [post["proxy_session_key"] for post in posts] == ["proxy-key", "proxy-key"]


def test_drain_file_drops_non_matching_cwd(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher.requests.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    # Sibling directory (same parent, different name) — must not match the
    # launcher cwd under the prefix-based filter.
    sibling = tmp_path.parent / (tmp_path.name + "-other")
    _append(
        session_file,
        {
            "type": "session_meta",
            "payload": {
                "id": "sess-2",
                "cwd": str(sibling),
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


def test_load_cursor_missing_returns_empty(tmp_path):
    state = load_cursor(tmp_path / "absent.json")
    assert state.files == {}
    assert state.saved_at == ""


def test_load_cursor_corrupt_returns_empty(tmp_path):
    cursor_path = tmp_path / "cursor.json"
    cursor_path.write_text("not json {")
    state = load_cursor(cursor_path)
    assert state.files == {}


def test_save_cursor_atomic_roundtrip(tmp_path):
    cursor_path = tmp_path / "sub" / "cursor.json"
    state = CursorState(files={"/path/a": 100, "/path/b": 200})
    save_cursor_atomic(cursor_path, state)
    loaded = load_cursor(cursor_path)
    assert loaded.files == {"/path/a": 100, "/path/b": 200}
    assert loaded.saved_at != ""


def test_save_cursor_atomic_leaves_no_temp_file(tmp_path):
    cursor_path = tmp_path / "cursor.json"
    save_cursor_atomic(cursor_path, CursorState(files={"x": 1}))
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []


def test_drain_file_resets_offset_on_truncation(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher.requests.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-trunc", "cwd": str(tmp_path)}})
    # Pretend a previous run advanced the offset well past the current size.
    state = FileState(offset=10_000)
    state.session_id = "sess-trunc"
    state.matches_cwd = True

    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    # The drain noticed size < offset, reset to 0, and replayed the record.
    assert state.offset == session_file.stat().st_size
    assert state.session_id == "sess-trunc"
    assert state.matches_cwd is True
    assert [post["record"]["type"] for post in posts] == ["session_meta"]
    assert posts[0]["session_id"] == "sess-trunc"


def test_drain_file_resets_session_state_on_truncation(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher.requests.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-new", "cwd": str(tmp_path)}})
    state = FileState(offset=10_000)
    state.session_id = "sess-old"
    state.matches_cwd = False

    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    assert posts[0]["session_id"] == "sess-new"
    assert state.session_id == "sess-new"
    assert state.matches_cwd is True


def test_proxy_watcher_ignores_existing_files_after_start(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher.requests.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout-existing.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-old", "cwd": str(tmp_path)}})

    watched_once = False

    def fake_process_exists(pid):
        nonlocal watched_once
        if watched_once:
            return False
        watched_once = True
        _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "late"}})
        return True

    monkeypatch.setattr("lapdog.codex_watcher._process_exists", fake_process_exists)

    watch_codex_sessions(
        lapdog_url="http://localhost:8126",
        cwd=str(tmp_path),
        parent_pid=12345,
        session_dir=tmp_path,
        poll_interval=0.01,
        flush_seconds=0.01,
        ready_file=None,
        proxy_session_key="proxy-key",
        cursor_path=None,
    )

    assert posts == []


def test_watch_codex_sessions_resumes_from_cursor(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher.requests.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-c", "cwd": str(tmp_path)}})
    primed_offset = session_file.stat().st_size
    _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "after-restart"}})

    cursor_path = tmp_path / "codex-cursor.json"
    # Pre-load a cursor as if the watcher had previously processed the first
    # record and then crashed before the user_message arrived.
    save_cursor_atomic(cursor_path, CursorState(files={str(session_file): primed_offset}))

    watch_codex_sessions(
        lapdog_url="http://localhost:8126",
        cwd=str(tmp_path),
        parent_pid=999999,
        session_dir=tmp_path,
        poll_interval=0.01,
        flush_seconds=0.01,
        ready_file=None,
        cursor_path=cursor_path,
    )

    # Only the user_message after the cursor should have been posted; the
    # session_meta that the cursor already covered must not reappear.
    assert [post["record"]["type"] for post in posts] == ["event_msg"]
    # And the cursor file should have advanced to the file's full size.
    loaded = load_cursor(cursor_path)
    assert loaded.files.get(str(session_file)) == session_file.stat().st_size


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
