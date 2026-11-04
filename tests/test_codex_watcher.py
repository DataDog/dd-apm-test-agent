import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from lapdog.cli import codex as codex_args
from lapdog.codex_watcher import CursorState
from lapdog.codex_watcher import FileState
from lapdog.codex_watcher import MAX_BUFFER_RECORDS
from lapdog.codex_watcher import MAX_LINE_BYTES
from lapdog.codex_watcher import SessionOwnership
from lapdog.codex_watcher import _default_session_dir
from lapdog.codex_watcher import _drain_file
from lapdog.codex_watcher import _initial_offset_for_file
from lapdog.codex_watcher import _is_under
from lapdog.codex_watcher import _maybe_save_cursor
from lapdog.codex_watcher import _prime_file_state
from lapdog.codex_watcher import _prune_cursor
from lapdog.codex_watcher import _sync_cursor
from lapdog.codex_watcher import load_cursor
from lapdog.codex_watcher import save_cursor_atomic
from lapdog.codex_watcher import watch_codex_sessions


@pytest.fixture(autouse=True)
def isolate_process_inventory(monkeypatch):
    monkeypatch.setattr("lapdog.codex_watcher.subprocess.run", lambda *a, **kw: SimpleNamespace(stdout=""))


def _append(path: Path, record: Any) -> None:
    with path.open("a") as f:
        f.write(json.dumps(record) + "\n")


def test_cli_ownership_rejects_unrelated_session_before_marked_session(tmp_path):
    owner = SessionOwnership(0, "launch")
    unrelated = {"type": "session_meta", "payload": {"id": "other", "source": "cli", "originator": "codex-tui"}}
    assert not owner.accepts(unrelated)
    marked = {"type": "session_meta", "payload": {"id": "owned", "source": "cli", "originator": "lapdog_launch"}}
    assert owner.accepts(marked)
    assert not owner.accepts(unrelated)
    child = {"type": "session_meta", "payload": {"id": "child", "parent_thread_id": "owned", "cwd": "/different"}}
    assert owner.accepts(child)


@pytest.mark.parametrize("resume", [False, True])
@pytest.mark.parametrize("log_first", [False, True])
def test_shared_daemon_capture_uses_client_id_and_preserves_resume_boundary(monkeypatch, tmp_path, resume, log_first):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *a, **kw: posts.append(kw["json"]))
    # Neither CLI owns an open rollout: one independent daemon writes both files.
    monkeypatch.setattr(SessionOwnership, "refresh", lambda self: None)
    session_dir = tmp_path / "sessions"
    session_dir.mkdir()
    client_log = tmp_path / "client.jsonl"
    files = [(session_dir / "other.jsonl", "other"), (session_dir / "owned.jsonl", "owned")]

    def metadata(sid):
        return {
            "type": "session_meta",
            "payload": {
                "id": sid,
                "source": "vscode",
                "originator": "codex-tui",
                "cwd": str(tmp_path),
                "thread_source": "user",
            },
        }

    def message(client_id):
        return {
            "type": "event_msg",
            "payload": {
                "type": "item_completed",
                "item": {
                    "type": "UserMessage",
                    "client_id": client_id,
                    "content": [],
                },
            },
        }

    if resume:
        for path, sid in files:
            _append(path, metadata(sid))
            # An old matching ID must not establish ownership of the other file.
            _append(path, message("owned"))

    def write_log():
        _append(
            client_log,
            {
                "dir": "from_tui",
                "kind": "op",
                "payload": {
                    "UserTurn": {"client_user_message_id": "owned"},
                },
            },
        )

    def write_rollouts():
        for path, sid in files:
            if not resume:
                _append(path, metadata(sid))
            _append(path, {"type": "event_msg", "payload": {"type": "task_started", "turn_id": "new-turn"}})
            _append(path, message(sid))

    polls = 0

    def alive(*args, **kwargs):
        nonlocal polls
        polls += 1
        if polls == 1:
            (write_log if log_first else write_rollouts)()
        elif polls == 2:
            (write_rollouts if log_first else write_log)()
        return polls < 3

    monkeypatch.setattr("lapdog.codex_watcher._process_exists", alive)
    watch_codex_sessions(
        "http://localhost:8126",
        str(tmp_path),
        123,
        session_dir,
        poll_interval=0,
        flush_seconds=0,
        discovery_interval=0,
        proxy_session_key="launch",
        resume_mode=resume,
        client_log=client_log,
    )
    assert {post["session_id"] for post in posts} == {"owned"}
    records = [post["record"] for post in posts]
    assert [record["type"] for record in records].count("session_meta") == 1
    assert sum(record.get("payload", {}).get("type") == "task_started" for record in records) == 1
    assert sum(record.get("payload", {}).get("type") == "item_completed" for record in records) == 1


def test_client_identity_waits_for_complete_jsonl_and_ignores_other_item_ids(tmp_path):
    log = tmp_path / "client.jsonl"
    rollout = tmp_path / "rollout.jsonl"
    owner = SessionOwnership(0, client_log=log)
    log.write_text(
        'null\n[]\ninvalid\n{"dir":"from_tui","kind":"op","payload":{"UserTurn":{"client_user_message_id":"id"}}}'
    )
    _append(
        rollout,
        {
            "type": "event_msg",
            "payload": {
                "type": "item_completed",
                "item": {
                    "type": "UserMessage",
                    "client_id": "id",
                },
            },
        },
    )
    assert not owner.owns_path(rollout)
    with log.open("a") as stream:
        stream.write("\n")
    assert owner.owns_path(rollout)
    other = tmp_path / "other.jsonl"
    _append(
        other,
        {
            "type": "event_msg",
            "payload": {
                "type": "item_completed",
                "item": {
                    "type": "AgentMessage",
                    "client_id": "id",
                },
            },
        },
    )
    assert not owner.owns_path(other)


@pytest.mark.parametrize("fails", [False, True])
def test_watcher_removes_its_temporary_client_recording(monkeypatch, tmp_path, fails):
    from lapdog import codex_watcher

    log = tmp_path / "client.jsonl"
    log.write_text("temporary recording\n")
    monkeypatch.setattr(
        "sys.argv",
        [
            "watcher",
            "--lapdog-url",
            "http://localhost:8126",
            "--cwd",
            str(tmp_path),
            "--parent-pid",
            "123",
            "--client-log",
            str(log),
        ],
    )

    def watch(**kwargs):
        assert kwargs["client_log"] == log
        if fails:
            raise RuntimeError("watcher failed")

    monkeypatch.setattr(codex_watcher, "watch_codex_sessions", watch)
    if fails:
        with pytest.raises(RuntimeError, match="watcher failed"):
            codex_watcher.main()
    else:
        codex_watcher.main()
    assert not log.exists()


@pytest.mark.parametrize("offset", [0, 1])
def test_app_capture_excludes_cli_even_with_saved_cursor(monkeypatch, tmp_path, offset):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *a, **kw: posts.append(kw["json"]))
    for sid, source, originator in (
        ("desktop", "vscode", "Codex Desktop"),
        ("cli", "cli", "codex-tui"),
        ("exec", "exec", "codex_exec"),
        ("daemon-cli", "vscode", "codex-tui"),
        ("wrapped-cli", "vscode", "lapdog_launch"),
    ):
        path = tmp_path / f"{sid}.jsonl"
        _append(
            path,
            {
                "type": "session_meta",
                "payload": {
                    "id": sid,
                    "source": source,
                    "originator": originator,
                    "cwd": str(tmp_path),
                },
            },
        )
        after_meta = path.stat().st_size
        _append(path, {"type": "event_msg", "payload": {"type": "user_message", "message": source}})
        state = FileState(after_meta if offset else 0)
        if offset:
            _prime_file_state(path, state, str(tmp_path), after_meta, include_all_cwds=True)
        _drain_file(
            path,
            state,
            "http://localhost:8126",
            str(tmp_path),
            include_all_cwds=True,
            session_ownership=SessionOwnership(0, app=True),
        )
    assert {post["session_id"] for post in posts} == {"desktop"}


def test_app_ownership_includes_multiple_workspaces_and_children():
    owner = SessionOwnership(0, app=True)
    for sid in ("one", "two"):
        assert owner.accepts({"payload": {"id": sid, "source": "vscode", "cwd": "/" + sid}})
    assert owner.accepts({"payload": {"id": "child", "source": "cli", "parent_thread_id": "one"}})
    assert not owner.accepts({"payload": {"id": "unrelated", "source": "cli"}})


def test_resume_selection_reads_open_files_from_codex_process_tree(monkeypatch):
    from types import SimpleNamespace

    commands = []

    def run(command, **kwargs):
        commands.append(command)
        if command[0] == "ps":
            return SimpleNamespace(stdout="10 1\n11 10\n12 11\n99 1\n")
        return SimpleNamespace(stdout="p12\nn/tmp/selected.jsonl\nn/tmp/other.txt\n")

    monkeypatch.setattr("lapdog.codex_watcher.subprocess.run", run)
    monkeypatch.setattr("lapdog.codex_watcher.shutil.which", lambda name: "/usr/sbin/lsof")
    monkeypatch.setattr("lapdog.codex_watcher.Path.is_dir", lambda path: False)
    owner = SessionOwnership(0, "launch", parent_pid=10)
    owner.open_paths.add("/tmp/stale.jsonl")
    owner.refresh()
    assert owner.open_paths == {"/tmp/selected.jsonl"}
    assert commands[-1] == ["/usr/sbin/lsof", "-a", "-p", "10,11,12", "-Fn"]
    assert owner.claim_resumed("root")
    commands.clear()
    owner.refresh()
    assert commands == []
    assert not owner.claim_resumed("different-root")


def test_linux_resume_selection_handles_inaccessible_child(monkeypatch):
    monkeypatch.setattr("lapdog.codex_watcher.subprocess.run", lambda *a, **kw: SimpleNamespace(stdout="10 1\n11 10\n"))
    monkeypatch.setattr(Path, "is_dir", lambda path: str(path) == "/proc/self/fd")

    def entries(path):
        if str(path) == "/proc/10/fd":
            return iter([Path("/tmp/owned.jsonl"), Path("/tmp/unrelated.txt")])
        raise PermissionError("child exited")

    monkeypatch.setattr(Path, "iterdir", entries)
    monkeypatch.setattr(Path, "resolve", lambda path: path)
    owner = SessionOwnership(0, parent_pid=10)
    owner.refresh()
    assert owner.open_paths == {"/tmp/owned.jsonl"}


def test_client_identity_skips_oversized_lines_and_resets_after_truncation(monkeypatch, tmp_path):
    monkeypatch.setattr("lapdog.codex_watcher.MAX_LINE_BYTES", 200)
    path = tmp_path / "client.jsonl"
    path.write_text("x" * 300 + "\n")
    _append(path, {"dir": "from_tui", "kind": "op", "payload": {"UserTurn": {"client_user_message_id": "old"}}})
    owner = SessionOwnership(0, client_log=path)
    assert owner._read_client_ids(path) == {"old"}
    path.write_text("")
    _append(path, {"dir": "from_tui", "kind": "op", "payload": {"UserTurn": {"client_user_message_id": "new"}}})
    assert owner._read_client_ids(path) == {"new"}


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX SIGTERM cleanup")
def test_sigterm_removes_client_recording(tmp_path):
    log = tmp_path / "client.jsonl"
    log.write_text("private prompt\n")
    script = """
import time
from lapdog import codex_watcher
def watch(**kwargs):
    print('ready', flush=True)
    while True:
        time.sleep(0.1)
codex_watcher.watch_codex_sessions = watch
codex_watcher.main()
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            "--lapdog-url",
            "http://unused",
            "--cwd",
            str(tmp_path),
            "--parent-pid",
            str(os.getpid()),
            "--client-log",
            str(log),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout.readline().strip() == "ready"
        process.send_signal(signal.SIGTERM)
        _, errors = process.communicate(timeout=5)
        assert process.returncode == 0, errors
        assert not log.exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


def test_resume_keeps_existing_child_reviews_from_launch_offset(monkeypatch, tmp_path):
    from lapdog.codex_watcher import _prepare_resumed_file

    path = tmp_path / "child.jsonl"
    meta = {
        "type": "session_meta",
        "payload": {"id": "child", "parent_thread_id": "parent", "thread_source": "guardian_review"},
    }
    _append(path, meta)
    _append(path, {"type": "event_msg", "payload": {"type": "task_complete", "turn_id": "old"}})
    state = FileState(path.stat().st_size)
    state.session_meta, state.session_id, state.resume_candidate = meta, "child", True
    _append(path, {"type": "event_msg", "payload": {"type": "task_started", "turn_id": "new"}})
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *a, **kw: posts.append(kw["json"]))
    owner = SessionOwnership(0)
    assert not _prepare_resumed_file(path, state, "http://unused", owner, "launch", "parent", False)
    assert not state.ignored
    owner.claim_resumed("parent")
    assert _prepare_resumed_file(path, state, "http://unused", owner, "launch", "parent", False)
    _drain_file(path, state, "http://unused", str(tmp_path), session_ownership=owner)
    assert [post["record"] for post in posts] == [
        meta,
        {"type": "event_msg", "payload": {"type": "task_started", "turn_id": "new"}},
    ]


def test_failed_buffer_flush_retries_only_unacknowledged_records(monkeypatch, tmp_path):
    path = tmp_path / "buffered.jsonl"
    records = [
        {"type": "session_meta", "payload": {"id": "s"}},
        {"type": "event_msg", "payload": {"type": "task_started"}},
        {"type": "turn_context", "payload": {"cwd": str(tmp_path)}},
    ]
    for record in records:
        _append(path, record)
    attempts = []

    def post(*args, **kwargs):
        attempts.append(kwargs["json"]["record"])
        return SimpleNamespace(status_code=500 if len(attempts) == 2 else 200)

    monkeypatch.setattr("lapdog.codex_watcher._session.post", post)
    state = FileState()
    _drain_file(path, state, "http://unused", str(tmp_path))
    assert state.offset == state.scan_offset < path.stat().st_size
    _drain_file(path, state, "http://unused", str(tmp_path))
    assert attempts == [records[0], records[1], records[1], records[2]]
    assert state.offset == path.stat().st_size


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
    (connect, read) timeout tuple instead of a single scalar.
    """
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


def test_drain_file_include_all_cwds_posts_non_matching_cwd(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    outside = tmp_path.parent / (tmp_path.name + "-other")
    _append(
        session_file,
        {
            "type": "session_meta",
            "payload": {
                "id": "sess-app",
                "cwd": str(outside),
            },
        },
    )
    _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "hello"}})

    _drain_file(session_file, FileState(), "http://localhost:8126", str(tmp_path), include_all_cwds=True)

    assert [post["session_id"] for post in posts] == ["sess-app", "sess-app"]


def test_drain_file_does_not_advance_durable_offset_past_buffered_records(monkeypatch, tmp_path):
    """When cwd is undetermined, buffered records stay un-acknowledged so a
    mid-drain crash safely resumes from the same offset.
    """
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


@pytest.mark.parametrize("early_cwd", [False, True])
def test_drain_file_flushes_buffer_after_late_session_meta(monkeypatch, tmp_path, early_cwd):
    """Three pre-meta records get flushed once session_meta arrives, and the
    durable cursor advances all the way to the file's end.
    """
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(
        session_file,
        {"type": "event_msg", "payload": {"type": "task_started", **({"cwd": str(tmp_path)} if early_cwd else {})}},
    )
    _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "hi"}})
    _append(session_file, {"type": "event_msg", "payload": {"type": "agent_message", "message": "thinking"}})
    state = FileState()
    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))
    assert posts == []
    assert state.offset == 0
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-late", "cwd": str(tmp_path)}})
    _append(session_file, {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "done"}})

    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    # All five records delivered in order.
    assert [post["record"]["type"] for post in posts] == [
        "event_msg",
        "event_msg",
        "event_msg",
        "session_meta",
        "event_msg",
    ]
    assert all(post["session_id"] == "sess-late" for post in posts)
    # Durable cursor caught up to end-of-file once buffer was flushed.
    assert state.offset == session_file.stat().st_size
    assert state.buffer == []


def test_drain_file_splits_only_on_newline(monkeypatch, tmp_path):
    r"""Records whose payloads contain \r, NEL, etc. must round-trip intact."""
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


def test_save_cursor_atomic_merges_existing_entries(tmp_path):
    cursor_path = tmp_path / "cursor.json"
    save_cursor_atomic(cursor_path, CursorState(files={"/path/a": 100}))
    save_cursor_atomic(cursor_path, CursorState(files={"/path/b": 200}))

    loaded = load_cursor(cursor_path)
    assert loaded.files == {"/path/a": 100, "/path/b": 200}


def test_sync_cursor_merges_rather_than_replaces():
    """Entries for files not in the live states dict must survive a sync."""
    path_a = Path("/path/a")
    path_b = Path("/path/b")
    cursor = CursorState(files={str(path_a): 100, str(path_b): 200})
    states = {path_a: FileState(offset=150)}
    _sync_cursor(cursor, states)
    assert cursor.files == {str(path_a): 150, str(path_b): 200}


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


@pytest.mark.parametrize("partial", [False, True])
def test_drain_file_drops_oversized_line(monkeypatch, capsys, tmp_path, partial):
    """Lines larger than MAX_LINE_BYTES are dropped and the cursor advances."""
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    # First a normal session_meta so cwd resolves.
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-big", "cwd": str(tmp_path)}})
    after_meta = session_file.stat().st_size
    state = FileState()
    # Then an oversized JSONL line (slightly above MAX_LINE_BYTES).
    huge_payload = "x" * (MAX_LINE_BYTES + 100)
    with session_file.open("a") as f:
        f.write(json.dumps({"type": "event_msg", "payload": {"data": huge_payload}}))
        if not partial:
            f.write("\n")
    if partial:
        _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))
        assert state.offset == state.scan_offset == after_meta
        # This valid JSON is still part of the oversized line, not a record.
        _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "discard"}})
    # Then a normal record after the over-cap line.
    _append(session_file, {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "ok"}})

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
    non-matching and the buffer is discarded.
    """
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


@pytest.mark.parametrize("acknowledged_offset", [0, 10_000])
def test_drain_file_resets_session_state_on_truncation(monkeypatch, tmp_path, acknowledged_offset):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-new", "cwd": str(tmp_path)}})
    state = FileState(offset=acknowledged_offset)
    state.scan_offset = 10_000
    state.buffer.append((10_000, {"type": "event_msg", "payload": {"type": "user_message", "message": "old"}}))
    state.session_id = "sess-old"
    state.matches_cwd = False

    _drain_file(session_file, state, "http://localhost:8126", str(tmp_path))

    assert posts[0]["session_id"] == "sess-new"
    assert state.session_id == "sess-new"
    assert state.matches_cwd is True
    assert len(posts) == 1
    assert state.buffer == []


def test_ignored_file_remains_ignored_after_truncation(monkeypatch, tmp_path):
    """An ignored proxy-mode file that gets truncated must stay ignored after
    the reset; otherwise its first post-truncate record would be replayed.
    """
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


@pytest.mark.parametrize("command", [["resume"], ["exec", "resume"]])
@pytest.mark.parametrize("selected_id", [None, "123e4567-e89b-12d3-a456-426614174000"])
def test_resume_watcher_captures_new_records_without_replaying_old_turns(monkeypatch, tmp_path, selected_id, command):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    resumed_file = tmp_path / "rollout-resumed.jsonl"
    unrelated_file = tmp_path / "rollout-unrelated.jsonl"
    resumed_id = "123e4567-e89b-12d3-a456-426614174000"
    for path, session_id in ((resumed_file, resumed_id), (unrelated_file, "sess-unrelated")):
        _append(path, {"type": "session_meta", "payload": {"id": session_id, "cwd": str(tmp_path)}})
        _append(path, {"type": "event_msg", "payload": {"type": "user_message", "message": "old"}})

    polls = {"count": 0}

    def fake_process_exists(pid, expected_start=None):
        polls["count"] += 1
        if polls["count"] == 1:
            _append(resumed_file, {"type": "event_msg", "payload": {"type": "thread_settings_applied"}})
            _append(resumed_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "new"}})
            return True
        if polls["count"] == 2:
            _append(unrelated_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "unrelated"}})
            return True
        return False

    monkeypatch.setattr("lapdog.codex_watcher._process_exists", fake_process_exists)
    resume_mode, resume_session_id, resume_all_cwds = codex_args.resume_options(
        command + ([selected_id] if selected_id else ["--last"])
    )
    monkeypatch.setattr(
        "lapdog.codex_watcher.SessionOwnership.refresh", lambda owner: owner.open_paths.add(str(resumed_file.resolve()))
    )
    watch_codex_sessions(
        lapdog_url="http://localhost:8126",
        cwd=str(tmp_path),
        parent_pid=12345,
        session_dir=tmp_path,
        poll_interval=0.01,
        flush_seconds=0.01,
        proxy_session_key="proxy-key",
        cursor_path=None,
        discovery_interval=0,
        resume_mode=resume_mode,
        resume_session_id=resume_session_id,
        resume_all_cwds=resume_all_cwds,
    )

    assert {post["session_id"] for post in posts} == {resumed_id}
    assert [post["record"]["type"] for post in posts].count("session_meta") == 1
    messages = [
        post["record"]["payload"]["message"]
        for post in posts
        if post["record"]["type"] == "event_msg" and post["record"]["payload"].get("type") == "user_message"
    ]
    assert messages == ["new"]


def test_resume_watcher_skips_other_old_file_even_if_it_changes_first(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    unrelated_file = tmp_path / "rollout-unrelated.jsonl"
    resumed_file = tmp_path / "rollout-resumed.jsonl"
    for path, session_id in ((unrelated_file, "sess-unrelated"), (resumed_file, "sess-resumed")):
        _append(path, {"type": "session_meta", "payload": {"id": session_id, "cwd": str(tmp_path)}})

    polls = {"count": 0}

    def fake_process_exists(pid, expected_start=None):
        polls["count"] += 1
        if polls["count"] == 1:
            _append(unrelated_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "other"}})
            return True
        if polls["count"] == 2:
            _append(resumed_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "selected"}})
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
        proxy_session_key="proxy-key",
        cursor_path=None,
        discovery_interval=0,
        resume_mode=True,
        resume_session_id="sess-resumed",
    )

    assert {post["session_id"] for post in posts} == {"sess-resumed"}


def test_resume_picker_ignores_unrelated_old_file_that_grows_first(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    unrelated_file = tmp_path / "rollout-unrelated.jsonl"
    selected_file = tmp_path / "rollout-selected.jsonl"
    for path, session_id in ((unrelated_file, "sess-unrelated"), (selected_file, "sess-selected")):
        _append(path, {"type": "session_meta", "payload": {"id": session_id, "cwd": str(tmp_path)}})

    polls = {"count": 0}

    def fake_process_exists(pid, expected_start=None):
        polls["count"] += 1
        if polls["count"] == 1:
            _append(unrelated_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "other"}})
            return True
        if polls["count"] == 2:
            _append(selected_file, {"type": "event_msg", "payload": {"type": "thread_settings_applied"}})
            _append(selected_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "selected"}})
            return True
        return False

    monkeypatch.setattr("lapdog.codex_watcher._process_exists", fake_process_exists)
    monkeypatch.setattr(
        "lapdog.codex_watcher.SessionOwnership.refresh",
        lambda owner: owner.open_paths.add(str(selected_file.resolve())),
    )
    watch_codex_sessions(
        lapdog_url="http://localhost:8126",
        cwd=str(tmp_path),
        parent_pid=12345,
        session_dir=tmp_path,
        poll_interval=0.01,
        flush_seconds=0.01,
        proxy_session_key="proxy-key",
        cursor_path=None,
        discovery_interval=0,
        resume_mode=True,
    )

    assert {post["session_id"] for post in posts} == {"sess-selected"}


def test_resume_watcher_keeps_startup_offset_when_file_grows_before_discovery(monkeypatch, tmp_path):
    from lapdog import codex_watcher

    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout-resumed.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-resumed", "cwd": str(tmp_path)}})
    _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "old"}})
    real_iter = codex_watcher._iter_jsonl_files
    calls = {"count": 0}

    def files_with_early_append(session_dir):
        calls["count"] += 1
        if calls["count"] == 2:
            _append(session_file, {"type": "event_msg", "payload": {"type": "thread_settings_applied"}})
            _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "new"}})
        return real_iter(session_dir)

    monkeypatch.setattr(codex_watcher, "_iter_jsonl_files", files_with_early_append)
    monkeypatch.setattr(codex_watcher, "_process_exists", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        "lapdog.codex_watcher.SessionOwnership.refresh", lambda owner: owner.open_paths.add(str(session_file.resolve()))
    )
    watch_codex_sessions(
        lapdog_url="http://localhost:8126",
        cwd=str(tmp_path),
        parent_pid=12345,
        session_dir=tmp_path,
        poll_interval=0.01,
        flush_seconds=0.01,
        proxy_session_key="proxy-key",
        cursor_path=None,
        resume_mode=True,
    )

    messages = [
        post["record"]["payload"]["message"]
        for post in posts
        if post["record"]["type"] == "event_msg" and post["record"]["payload"].get("type") == "user_message"
    ]
    assert messages == ["new"]


def test_proxy_watcher_captures_only_its_first_new_top_level_session(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    owned_file = tmp_path / "rollout-owned.jsonl"
    unrelated_file = tmp_path / "rollout-unrelated.jsonl"
    poll_count = {"n": 0}

    def fake_process_exists(pid, expected_start=None):
        poll_count["n"] += 1
        if poll_count["n"] == 1:
            _append(
                owned_file,
                {
                    "type": "session_meta",
                    "payload": {
                        "id": "sess-owned",
                        "cwd": str(tmp_path),
                        "thread_source": "user",
                        "originator": "lapdog_proxy-key",
                    },
                },
            )
            return True
        if poll_count["n"] == 2:
            _append(
                unrelated_file,
                {
                    "type": "session_meta",
                    "payload": {"id": "sess-unrelated", "cwd": str(tmp_path), "thread_source": "user"},
                },
            )
            _append(
                unrelated_file,
                {"type": "event_msg", "payload": {"type": "user_message", "message": "unrelated"}},
            )
            _append(
                unrelated_file,
                {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "done"}},
            )
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
        discovery_interval=0.0,
    )

    assert {post["session_id"] for post in posts} == {"sess-owned"}


def test_proxy_watcher_rejects_delayed_file_for_session_started_before_watcher(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    stale_file = tmp_path / "rollout-stale.jsonl"
    owned_file = tmp_path / "rollout-owned.jsonl"
    poll_count = {"n": 0}

    def fake_process_exists(pid, expected_start=None):
        poll_count["n"] += 1
        if poll_count["n"] == 1:
            _append(
                stale_file,
                {
                    "type": "session_meta",
                    "payload": {
                        "id": "sess-stale",
                        "cwd": str(tmp_path),
                        "thread_source": "user",
                        "timestamp": "2000-01-01T00:00:00.000Z",
                    },
                },
            )
            return True
        if poll_count["n"] == 2:
            _append(
                owned_file,
                {
                    "type": "session_meta",
                    "payload": {
                        "id": "sess-owned",
                        "cwd": str(tmp_path),
                        "thread_source": "user",
                        "originator": "lapdog_proxy-key",
                    },
                },
            )
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
        discovery_interval=0.0,
    )

    assert {post["session_id"] for post in posts} == {"sess-owned"}


def test_proxy_watcher_captures_subagent_of_owned_session(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    owned_file = tmp_path / "rollout-owned.jsonl"
    child_file = tmp_path / "rollout-child.jsonl"
    poll_count = {"n": 0}

    def fake_process_exists(pid, expected_start=None):
        poll_count["n"] += 1
        if poll_count["n"] == 1:
            _append(
                owned_file,
                {
                    "type": "session_meta",
                    "payload": {
                        "id": "sess-owned",
                        "cwd": str(tmp_path),
                        "thread_source": "user",
                        "originator": "lapdog_proxy-key",
                    },
                },
            )
            return True
        if poll_count["n"] == 2:
            _append(
                child_file,
                {
                    "type": "session_meta",
                    "payload": {
                        "id": "sess-child",
                        "cwd": str(tmp_path),
                        "thread_source": "subagent",
                        "parent_thread_id": "sess-owned",
                    },
                },
            )
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
        discovery_interval=0.0,
    )

    assert {post["session_id"] for post in posts} == {"sess-owned", "sess-child"}


def test_watch_codex_sessions_resumes_from_cursor(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(
        session_file, {"type": "session_meta", "payload": {"source": "vscode", "id": "sess-c", "cwd": str(tmp_path)}}
    )
    primed_offset = session_file.stat().st_size
    _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "after-restart"}})

    cursor_path = tmp_path / "codex-cursor.json"
    # Pre-load a cursor as if the watcher had previously processed the first
    # record and then crashed before the user_message arrived.
    save_cursor_atomic(cursor_path, CursorState(files={str(session_file): primed_offset}))

    watch_codex_sessions(
        include_all_cwds=True,
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
    posted_types = [post["record"]["payload"]["type"] for post in posts if post["record"]["type"] == "event_msg"]
    assert posted_types == ["user_message", "shutdown_complete"]
    # And the cursor file should have advanced to the file's full size.
    loaded = load_cursor(cursor_path)
    assert loaded.files.get(str(session_file)) == session_file.stat().st_size


def test_proxy_watch_codex_sessions_ignores_initial_file_when_cursor_exists(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout.jsonl"
    _append(session_file, {"type": "session_meta", "payload": {"id": "sess-proxy-c", "cwd": str(tmp_path)}})
    primed_offset = session_file.stat().st_size
    _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "after-proxy-restart"}})

    cursor_path = tmp_path / "codex-cursor.json"
    save_cursor_atomic(cursor_path, CursorState(files={str(session_file): primed_offset}))

    watch_codex_sessions(
        lapdog_url="http://localhost:8126",
        cwd=str(tmp_path),
        parent_pid=999999,
        session_dir=tmp_path,
        poll_interval=0.01,
        flush_seconds=0.01,
        ready_file=None,
        proxy_session_key="proxy-key",
        cursor_path=cursor_path,
    )

    assert posts == []


def test_app_watch_codex_sessions_replays_recent_nonmatching_file(monkeypatch, tmp_path):
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    session_file = tmp_path / "rollout-app.jsonl"
    outside = tmp_path.parent / (tmp_path.name + "-app-workspace")
    _append(
        session_file,
        {"type": "session_meta", "payload": {"source": "vscode", "id": "sess-app-recent", "cwd": str(outside)}},
    )
    _append(session_file, {"type": "event_msg", "payload": {"type": "user_message", "message": "hello world"}})

    watch_codex_sessions(
        lapdog_url="http://localhost:8126",
        cwd=str(tmp_path),
        parent_pid=999999,
        session_dir=tmp_path,
        poll_interval=0.01,
        flush_seconds=0.01,
        ready_file=None,
        cursor_path=tmp_path / "codex-app-cursor.json",
        include_all_cwds=True,
    )

    posted_messages = [
        post["record"]["payload"]["message"]
        for post in posts
        if post["record"]["type"] == "event_msg" and post["record"]["payload"].get("type") == "user_message"
    ]
    assert posted_messages == ["hello world"]


def test_watch_codex_sessions_exits_when_parent_start_time_stale(monkeypatch, tmp_path):
    """A stale --parent-start-time causes the watcher to treat the parent as
    dead even though the PID still exists.
    """
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


def test_watch_codex_sessions_continues_after_per_file_error(monkeypatch, capsys, tmp_path):
    """A drain failure on one file must not stop other files from being processed."""
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))

    bad_file = tmp_path / "rollout-bad.jsonl"
    good_file = tmp_path / "rollout-good.jsonl"
    _append(bad_file, {"type": "session_meta", "payload": {"source": "vscode", "id": "sess-bad", "cwd": str(tmp_path)}})
    _append(
        good_file, {"type": "session_meta", "payload": {"source": "vscode", "id": "sess-good", "cwd": str(tmp_path)}}
    )

    real_drain = __import__("lapdog.codex_watcher", fromlist=["_drain_file"])._drain_file

    def fake_drain(path, *args, **kwargs):
        if path == bad_file:
            raise UnicodeDecodeError("utf-8", b"\x80", 0, 1, "synthetic")
        return real_drain(path, *args, **kwargs)

    monkeypatch.setattr("lapdog.codex_watcher._drain_file", fake_drain)

    poll_count = {"n": 0}

    def fake_process_exists(pid, expected_start=None):
        poll_count["n"] += 1
        return poll_count["n"] < 2

    monkeypatch.setattr("lapdog.codex_watcher._process_exists", fake_process_exists)

    watch_codex_sessions(
        include_all_cwds=True,
        lapdog_url="http://localhost:8126",
        cwd=str(tmp_path),
        parent_pid=12345,
        session_dir=tmp_path,
        poll_interval=0.01,
        flush_seconds=0.01,
        ready_file=None,
        cursor_path=None,
    )

    # The good file's record was delivered even though the bad file raised.
    assert any(post["session_id"] == "sess-good" for post in posts)
    # The error landed on stderr.
    captured = capsys.readouterr()
    assert "per-file error" in captured.err


def test_process_exists_falls_back_when_psutil_missing(monkeypatch):
    """When psutil is unavailable, _process_exists uses a safe fallback."""
    import builtins

    from lapdog import codex_watcher

    # Force ImportError for psutil even if it happens to be installed.
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "psutil":
            raise ImportError("forced for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    # Our own PID must be alive.
    assert codex_watcher._process_exists(os.getpid()) is True
    # A clearly bogus PID is not.
    assert codex_watcher._process_exists(999999) is False


def test_process_exists_uses_windows_probe_when_psutil_missing(monkeypatch):
    import builtins

    from lapdog import codex_watcher

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "psutil":
            raise ImportError("forced for test")
        return real_import(name, *args, **kwargs)

    seen = []

    def fake_windows_process_exists(pid):
        seen.append(pid)
        return pid == 123

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(codex_watcher.os, "name", "nt")
    monkeypatch.setattr(codex_watcher, "_windows_process_exists", fake_windows_process_exists)

    assert codex_watcher._process_exists(123) is True
    assert codex_watcher._process_exists(456) is False
    assert seen == [123, 456]


def test_process_exists_with_mismatched_start_time(monkeypatch):
    """With a stale --parent-start-time, the parent is treated as dead even
    though the PID exists.
    """
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
            _append(
                session_file,
                {"type": "session_meta", "payload": {"source": "vscode", "id": "sess-disc", "cwd": str(tmp_path)}},
            )
            return True
        # After a few more polls, signal parent died so watcher exits.
        return False

    monkeypatch.setattr("lapdog.codex_watcher._process_exists", fake_process_exists)

    watch_codex_sessions(
        include_all_cwds=True,
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

    assert [post["session_id"] for post in posts] == ["sess-disc", "sess-disc"]
    assert posts[-1]["record"]["payload"]["type"] == "shutdown_complete"


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
