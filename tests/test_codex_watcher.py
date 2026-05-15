import json
import os
from pathlib import Path
from typing import Any

from lapdog.codex_cursor import CursorState
from lapdog.codex_cursor import load_cursor
from lapdog.codex_cursor import save_cursor_atomic
from lapdog.codex_watcher import MAX_BUFFER_RECORDS
from lapdog.codex_watcher import MAX_LINE_BYTES
from lapdog.codex_watcher import _maybe_save_cursor
from lapdog.codex_watcher import _prune_cursor
from lapdog.codex_watcher import _sync_cursor
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
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    sub = tmp_path / "sub"
    sub.mkdir()
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-sub", "cwd": str(sub)}})

    _drain_file(session_file, FileState(), "http://localhost:8126", str(tmp_path))

    # Launcher cwd is the parent; the record cwd is a descendant — must match.
    assert [post["session_id"] for post in posts] == ["sess-sub"]


def test_post_uses_session_with_split_timeout(monkeypatch, tmp_path):
    """``_post_record`` routes through the module-level Session with a
    (connect, read) timeout tuple instead of a single scalar."""
    calls = []

    def fake_post(url, json, timeout):
        calls.append({"url": url, "json": json, "timeout": timeout})

    monkeypatch.setattr("lapdog.codex_watcher._session.post", fake_post)
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-timeout", "cwd": str(tmp_path)}})

    _drain_file(session_file, FileState(), "http://localhost:8126", str(tmp_path))

    assert len(calls) == 1
    # Timeout must be a (connect, read) tuple — not a scalar.
    assert isinstance(calls[0]["timeout"], tuple)
    assert len(calls[0]["timeout"]) == 2
    connect_timeout, read_timeout = calls[0]["timeout"]
    assert connect_timeout < read_timeout


def test_drain_file_buffers_until_matching_cwd(monkeypatch, tmp_path):
    posts = []

    def fake_post(url, json, timeout):
        posts.append(json)

    monkeypatch.setattr("lapdog.codex_watcher._session.post", fake_post)
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
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
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

    monkeypatch.setattr("lapdog.codex_watcher._session.post", fake_post)
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
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
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
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
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


def test_drain_file_does_not_advance_durable_offset_past_buffered_records(monkeypatch, tmp_path):
    """When cwd is undetermined, buffered records stay un-acknowledged so a
    mid-drain crash safely resumes from the same offset."""
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    # Three records without cwd, no session_meta — disposition stays None
    # and all three sit in the buffer.
    _append(session_file, {"type": "event_msg", "payload": {"type": "task_started"}})
    _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "hi"}})
    _append(session_file, {"type": "event_msg", "payload": {"type": "agent_message", "message": "ok"}})

    state = FileState()
    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    # Nothing posted because matches_cwd never resolved.
    assert posts == []
    # The durable cursor must NOT have advanced past the buffered records —
    # on restart we need to re-read them.
    assert state.offset == 0
    # But the scan offset has moved forward so the next pass picks up new bytes.
    assert state.scan_offset == session_file.stat().st_size
    # The records are still in memory.
    assert len(state.buffer) == 3


def test_drain_file_flushes_buffer_after_late_session_meta(monkeypatch, tmp_path):
    """Three pre-meta records get flushed once session_meta arrives, and the
    durable cursor advances all the way to the file's end."""
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "event_msg", "payload": {"type": "task_started"}})
    _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "hi"}})
    _append(session_file, {"type": "event_msg", "payload": {"type": "agent_message", "message": "thinking"}})
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-late", "cwd": str(tmp_path)}})
    _append(session_file, {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "done"}})

    state = FileState()
    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    # All five records delivered in order.
    assert [post["record"]["type"] for post in posts] == [
        "event_msg", "event_msg", "event_msg", "session_meta", "event_msg",
    ]
    assert all(post["session_id"] == "sess-late" for post in posts)
    # Durable cursor caught up to end-of-file once buffer was flushed.
    assert state.offset == session_file.stat().st_size
    assert state.buffer == []


def test_drain_file_splits_only_on_newline(monkeypatch, tmp_path):
    """Records whose payloads contain \\r, NEL, etc. must round-trip intact."""
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    # session_meta first to establish the cwd match.
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-crlf", "cwd": str(tmp_path)}})
    # Payload contains \r\n, \v, and NEL bytes — splitlines() would have split
    # on them; the watcher must not.
    record = {"type": "event_msg", "payload": {"type": "user_message", "message": "line1\r\nline2\x0bline3\x85line4"}}
    _append(session_file, record)

    _drain_file(session_file, FileState(), "http://localhost:8126", str(tmp_path))

    assert [post["record"]["type"] for post in posts] == ["session_meta", "event_msg"]
    # The event_msg payload must be intact — embedded \r and other separators
    # must not have been treated as line boundaries.
    assert posts[1]["record"]["payload"]["message"] == "line1\r\nline2\x0bline3\x85line4"


def test_drain_file_preserves_partial_jsonl_record(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
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


def test_prime_file_state_handles_utf8_multibyte_cwd(tmp_path):
    """A cwd field with non-ASCII characters must not abort priming."""
    session_file = tmp_path / "rollout.jsonl"
    multibyte_cwd = str(tmp_path / "résumé")
    (tmp_path / "résumé").mkdir()
    _append(
        session_file,
        {
            "type": "session_meta",
            "payload": {"id": "sess-utf8", "cwd": multibyte_cwd},
        },
    )
    state = FileState(offset=session_file.stat().st_size)
    _prime_file_state(session_file, state, multibyte_cwd, session_file.stat().st_size)

    assert state.session_id == "sess-utf8"
    assert state.matches_cwd is True


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


def test_sync_cursor_merges_rather_than_replaces():
    """Entries for files not in the live states dict must survive a sync."""
    cursor = CursorState(files={"/path/a": 100, "/path/b": 200})
    states = {Path("/path/a"): FileState(offset=150)}
    _sync_cursor(cursor, states)
    assert cursor.files == {"/path/a": 150, "/path/b": 200}


def test_prune_cursor_drops_missing_files(tmp_path):
    real = tmp_path / "real.jsonl"
    real.write_text("{}\n")
    cursor = CursorState(files={str(real): 5, "/does/not/exist.jsonl": 12345})
    _prune_cursor(cursor)
    assert str(real) in cursor.files
    assert "/does/not/exist.jsonl" not in cursor.files


def test_maybe_save_cursor_does_not_prune_on_throttled_save(tmp_path):
    """A normal periodic save preserves phantom entries; only force=True prunes."""
    cursor_path = tmp_path / "cursor.json"
    cursor = CursorState(files={"/phantom.jsonl": 99})
    # Force-save first so the next call is throttled into a save anyway.
    _maybe_save_cursor(cursor_path, cursor, {}, last_save=0.0, now=10.0, force=True)
    # After force-save, phantom should have been pruned.
    loaded = load_cursor(cursor_path)
    assert "/phantom.jsonl" not in loaded.files

    # Now re-seed a phantom and do a non-force save.
    cursor.files["/phantom2.jsonl"] = 77
    _maybe_save_cursor(cursor_path, cursor, {}, last_save=0.0, now=10.0 + 10.0, force=False)
    loaded = load_cursor(cursor_path)
    # Non-force save preserved the phantom because we didn't prune.
    assert loaded.files.get("/phantom2.jsonl") == 77


def test_save_cursor_atomic_leaves_no_temp_file(tmp_path):
    cursor_path = tmp_path / "cursor.json"
    save_cursor_atomic(cursor_path, CursorState(files={"x": 1}))
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []


def test_drain_file_drops_oversized_line(monkeypatch, capsys, tmp_path):
    """Lines larger than MAX_LINE_BYTES are dropped and the cursor advances."""
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    # First a normal session_meta so cwd resolves.
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-big", "cwd": str(tmp_path)}})
    # Then an oversized JSONL line (slightly above MAX_LINE_BYTES).
    huge_payload = "x" * (MAX_LINE_BYTES + 100)
    with session_file.open("a") as f:
        f.write(json.dumps({"type": "event_msg", "payload": {"data": huge_payload}}) + "\n")
    # Then a normal record after the over-cap line.
    _append(session_file, {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "ok"}})

    state = FileState()
    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    types_posted = [post["record"]["type"] for post in posts]
    # session_meta delivered, oversized line skipped, last event_msg delivered.
    assert types_posted == ["session_meta", "event_msg"]
    assert posts[1]["record"]["payload"]["type"] == "task_complete"
    captured = capsys.readouterr()
    assert "dropping oversized line" in captured.err
    # Cursor must now be at end-of-file so a re-drain finds nothing new.
    assert state.offset == session_file.stat().st_size


def test_drain_file_processes_large_but_within_cap_line(monkeypatch, tmp_path):
    """A line just under the 10MB cap is processed normally."""
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-5mb", "cwd": str(tmp_path)}})
    # 5MB payload — well under the cap.
    large_payload = "y" * (5 * 1024 * 1024)
    with session_file.open("a") as f:
        f.write(json.dumps({"type": "event_msg", "payload": {"data": large_payload}}) + "\n")

    state = FileState()
    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    types_posted = [post["record"]["type"] for post in posts]
    assert types_posted == ["session_meta", "event_msg"]
    assert len(posts[1]["record"]["payload"]["data"]) == len(large_payload)


def test_drain_file_caps_buffer_when_cwd_never_resolves(monkeypatch, capsys, tmp_path):
    """Beyond MAX_BUFFER_RECORDS records without cwd, the session is treated as
    non-matching and the buffer is discarded."""
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    overflow_count = MAX_BUFFER_RECORDS + 500
    with session_file.open("a") as f:
        for i in range(overflow_count):
            f.write(json.dumps({"type": "event_msg", "payload": {"type": "tick", "i": i}}) + "\n")

    state = FileState()
    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    captured = capsys.readouterr()
    # Nothing should have been posted — cwd never resolved.
    assert posts == []
    # Buffer should be cleared and matches_cwd set to False.
    assert state.buffer == []
    assert state.matches_cwd is False
    # Overflow warning fired.
    assert "buffer overflow" in captured.err


def test_drain_file_resets_offset_on_truncation(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
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
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-new", "cwd": str(tmp_path)}})
    state = FileState(offset=10_000)
    state.session_id = "sess-old"
    state.matches_cwd = False

    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    assert posts[0]["session_id"] == "sess-new"
    assert state.session_id == "sess-new"
    assert state.matches_cwd is True


def test_ignored_file_remains_ignored_after_truncation(monkeypatch, tmp_path):
    """An ignored proxy-mode file that gets truncated must stay ignored after
    the reset; otherwise its first post-truncate record would be replayed."""
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout-existing.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-ignored", "cwd": str(tmp_path)}})

    poll_count = {"n": 0}

    def fake_process_exists(pid, expected_start=None):
        poll_count["n"] += 1
        if poll_count["n"] == 1:
            # Truncate and re-append after the watcher has registered the file.
            session_file.write_text("")
            _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "after-trunc"}})
            return True
        return False

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

    # File was ignored from the start (existed before watcher came up); even
    # after truncation it must stay ignored so its records are NOT posted.
    assert posts == []


def test_proxy_watcher_ignores_existing_files_after_start(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout-existing.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-old", "cwd": str(tmp_path)}})

    watched_once = False

    def fake_process_exists(pid, expected_start=None):
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
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
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


def test_watch_codex_sessions_exits_when_parent_start_time_stale(monkeypatch, tmp_path):
    """A stale --parent-start-time causes the watcher to treat the parent as
    dead even though the PID still exists."""
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs.get("json")))

    seen_expected_start = []

    def fake_process_exists(pid, expected_start=None):
        seen_expected_start.append(expected_start)
        # Stale start time: always treat parent as dead.
        if expected_start is not None:
            return False
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
        cursor_path=None,
        parent_start_time=999999.0,  # impossible-to-match start time
    )

    # The fake was invoked at least once with our supplied expected_start —
    # confirming the kwarg was threaded through.
    assert any(start == 999999.0 for start in seen_expected_start)


def test_process_exists_falls_back_when_psutil_missing(monkeypatch):
    """When psutil is unavailable, _process_exists uses os.kill(pid, 0)."""
    import builtins
    import importlib

    # Force ImportError for psutil even if it happens to be installed.
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "psutil":
            raise ImportError("forced for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    from lapdog import codex_watcher
    importlib.reload(codex_watcher)
    try:
        # Our own PID must be alive.
        assert codex_watcher._process_exists(os.getpid()) is True
        # A clearly bogus PID is not.
        assert codex_watcher._process_exists(999999) is False
    finally:
        # Restore the real psutil binding for other tests by reloading without
        # the fake import hook in effect.
        monkeypatch.undo()
        importlib.reload(codex_watcher)


def test_process_exists_with_mismatched_start_time(monkeypatch):
    """With a stale --parent-start-time, the parent is treated as dead even
    though the PID exists."""
    # Build a fake psutil module so this works without installing the real one.
    import sys
    import types

    class _NoSuchProcess(Exception):
        pass

    class _AccessDenied(Exception):
        pass

    class FakeProcess:
        def __init__(self, pid, create_time_value, status_value="running", running=True):
            self.pid = pid
            self._create_time = create_time_value
            self._status = status_value
            self._running = running

        def create_time(self):
            return self._create_time

        def status(self):
            return self._status

        def is_running(self):
            return self._running

    fake_psutil = types.ModuleType("psutil")
    fake_psutil.Process = lambda pid: FakeProcess(pid, create_time_value=1000.0)
    fake_psutil.NoSuchProcess = _NoSuchProcess
    fake_psutil.AccessDenied = _AccessDenied
    fake_psutil.STATUS_ZOMBIE = "zombie"
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil)

    from lapdog import codex_watcher

    # Real start time matches → alive.
    assert codex_watcher._process_exists(12345, expected_start=1000.0) is True
    # Stale start time → treated as dead (PID was reused).
    assert codex_watcher._process_exists(12345, expected_start=500.0) is False
    # No expected_start → alive (matches existing fallback semantics).
    assert codex_watcher._process_exists(12345) is True


def test_watch_codex_sessions_respects_discovery_interval(monkeypatch, tmp_path):
    """When --discovery-interval is set, new files are picked up within ~2 cycles."""
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))

    poll_count = {"n": 0}
    session_file = tmp_path / "rollout.jsonl"

    def fake_process_exists(pid, expected_start=None):
        poll_count["n"] += 1
        if poll_count["n"] == 1:
            # File doesn't exist yet on first poll.
            return True
        if poll_count["n"] == 2:
            # Write the file just before second poll; with discovery_interval
            # of 0 it should be picked up immediately.
            _append(session_file, {"type": "session_meta", "payload": {"id": "sess-disc", "cwd": str(tmp_path)}})
            return True
        # After a few more polls, signal parent died so watcher exits.
        return False

    monkeypatch.setattr("lapdog.codex_watcher._process_exists", fake_process_exists)

    watch_codex_sessions(
        lapdog_url="http://localhost:8126",
        cwd=str(tmp_path),
        parent_pid=12345,
        session_dir=tmp_path,
        poll_interval=0.01,
        flush_seconds=0.01,
        ready_file=None,
        cursor_path=None,
        discovery_interval=0.0,  # rediscover every loop iteration
    )

    assert [post["session_id"] for post in posts] == ["sess-disc"]


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
