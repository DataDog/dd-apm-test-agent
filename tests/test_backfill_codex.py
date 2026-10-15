from lapdog.backfill_codex import _default_session_dir
from lapdog.backfill_codex import _is_under

import json
import os
from pathlib import Path
from typing import Any
from typing import List
from unittest import mock

from lapdog import backfill_codex


def _write_session(path: Path, session_id: str, cwd: str, extra_events: List[Any]) -> None:
    lines: List[Any] = [{"type": "session_meta", "payload": {"id": session_id, "cwd": cwd}}]
    lines.append({"type": "turn_context", "payload": {"cwd": cwd}})
    lines.extend(extra_events)
    with path.open("w") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")


def test_backfill_posts_records_and_shutdown(monkeypatch, tmp_path):
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    rollout = sessions_dir / "rollout-2026-05-01.jsonl"
    _write_session(
        rollout,
        "sess-abc",
        str(project),
        [
            {"type": "event_msg", "payload": {"type": "user_message", "text": "hi"}},
            {"type": "event_msg", "payload": {"type": "agent_message", "text": "hello"}},
        ],
    )

    posts: List[Any] = []
    monkeypatch.setattr(
        "lapdog.backfill_codex._session.post",
        lambda *args, **kwargs: posts.append(kwargs["json"]) or mock.Mock(status_code=200),
    )

    result = backfill_codex.backfill("http://localhost:8126", cwd=str(project), session_dir=sessions_dir)

    assert result == 1
    # Expect session_meta, turn_context, two event_msg, shutdown_complete = 5 records.
    assert len(posts) == 5
    assert all(post["backfill"] is True for post in posts)
    assert posts[0]["session_id"] == "sess-abc"
    assert posts[0]["record"]["type"] == "session_meta"
    assert posts[-1]["record"]["payload"]["type"] == "shutdown_complete"


def test_backfill_skips_sessions_under_different_cwd(monkeypatch, tmp_path):
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir()
    project_a = tmp_path / "a"
    project_b = tmp_path / "b"
    project_a.mkdir()
    project_b.mkdir()
    rollout_a = sessions_dir / "a.jsonl"
    rollout_b = sessions_dir / "b.jsonl"
    _write_session(rollout_a, "sess-a", str(project_a), [])
    _write_session(rollout_b, "sess-b", str(project_b), [])

    posts: List[Any] = []
    monkeypatch.setattr(
        "lapdog.backfill_codex._session.post",
        lambda *args, **kwargs: posts.append(kwargs["json"]) or mock.Mock(status_code=200),
    )

    result = backfill_codex.backfill("http://localhost:8126", cwd=str(project_a), session_dir=sessions_dir)

    assert result == 1
    session_ids = {p["session_id"] for p in posts}
    assert session_ids == {"sess-a"}


def test_backfill_cwd_none_disables_filtering(monkeypatch, tmp_path):
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir()
    project_a = tmp_path / "a"
    project_b = tmp_path / "b"
    project_a.mkdir()
    project_b.mkdir()
    _write_session(sessions_dir / "a.jsonl", "sess-a", str(project_a), [])
    _write_session(sessions_dir / "b.jsonl", "sess-b", str(project_b), [])

    posts: List[Any] = []
    monkeypatch.setattr(
        "lapdog.backfill_codex._session.post",
        lambda *args, **kwargs: posts.append(kwargs["json"]) or mock.Mock(status_code=200),
    )

    result = backfill_codex.backfill("http://localhost:8126", cwd=None, session_dir=sessions_dir)

    assert result == 2
    session_ids = {p["session_id"] for p in posts}
    assert session_ids == {"sess-a", "sess-b"}


def test_backfill_no_sessions_returns_zero(monkeypatch, tmp_path, capsys):
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir()

    posts: List[Any] = []
    monkeypatch.setattr(
        "lapdog.backfill_codex._session.post",
        lambda *args, **kwargs: posts.append(kwargs["json"]) or mock.Mock(status_code=200),
    )

    result = backfill_codex.backfill("http://localhost:8126", cwd=None, session_dir=sessions_dir)

    assert result == 0
    assert posts == []
    captured = capsys.readouterr()
    assert "no sessions found" in captured.err


def test_backfill_session_meta_preserved_when_cwd_matches_in_later_record(monkeypatch, tmp_path):
    """session_meta is buffered until cwd is known, then flushed if cwd matches."""
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir()
    project = tmp_path / "p"
    project.mkdir()
    rollout = sessions_dir / "r.jsonl"
    # session_meta has no cwd here — cwd only arrives on turn_context.
    with rollout.open("w") as f:
        f.write(json.dumps({"type": "session_meta", "payload": {"id": "sess-x"}}) + "\n")
        f.write(json.dumps({"type": "turn_context", "payload": {"cwd": str(project)}}) + "\n")
        f.write(json.dumps({"type": "event_msg", "payload": {"type": "user_message"}}) + "\n")

    posts: List[Any] = []
    monkeypatch.setattr(
        "lapdog.backfill_codex._session.post",
        lambda *args, **kwargs: posts.append(kwargs["json"]) or mock.Mock(status_code=200),
    )

    backfill_codex.backfill("http://localhost:8126", cwd=str(project), session_dir=sessions_dir)

    types = [p["record"]["type"] for p in posts]
    assert types == ["session_meta", "turn_context", "event_msg", "event_msg"]
    # The final event_msg is shutdown_complete.
    assert posts[-1]["record"]["payload"]["type"] == "shutdown_complete"


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
