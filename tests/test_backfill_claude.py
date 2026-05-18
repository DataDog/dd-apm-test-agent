import json
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from unittest import mock

from ddapm_test_agent import claude_backfill
from lapdog import backfill_claude


def _write_transcript(path: Path, entries: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def _ts(s: str) -> Dict[str, Any]:
    return {"timestamp": s}


def test_session_to_spans_one_user_one_turn():
    entries = [
        {
            "type": "user",
            "cwd": "/p",
            "timestamp": "2026-05-11T12:00:00.000Z",
            "message": {"role": "user", "content": "do thing"},
        },
        {
            "type": "assistant",
            "cwd": "/p",
            "timestamp": "2026-05-11T12:00:01.000Z",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4-7-20250101",
                "usage": {"input_tokens": 100, "output_tokens": 50, "cache_read_input_tokens": 10},
                "content": [
                    {"type": "text", "text": "ok"},
                    {"type": "tool_use", "id": "tu1", "name": "Bash", "input": {"command": "ls"}},
                ],
            },
        },
        {
            "type": "user",
            "cwd": "/p",
            "timestamp": "2026-05-11T12:00:02.000Z",
            "message": {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "tu1", "content": "file.txt"}],
            },
        },
    ]
    spans = claude_backfill.session_to_spans("sess-1", "/p", entries)
    by_kind = {s["meta"]["span"]["kind"]: s for s in spans}
    assert set(by_kind) == {"agent", "llm", "tool"}
    agent = by_kind["agent"]
    llm = by_kind["llm"]
    tool = by_kind["tool"]
    # All in the same trace
    assert agent["trace_id"] == llm["trace_id"] == tool["trace_id"]
    # Tool parented to LLM, LLM to agent
    assert llm["parent_id"] == agent["span_id"]
    assert tool["parent_id"] == llm["span_id"]
    # Real timestamps (May 11 2026 ~= 1778932800 epoch seconds)
    assert agent["start_ns"] >= 1_778_000_000_000_000_000
    assert agent["start_ns"] <= 1_779_000_000_000_000_000
    # Token + cost
    assert llm["metrics"]["input_tokens"] == 110  # 100 + 10 cache_read
    assert llm["metrics"]["output_tokens"] == 50
    assert llm["metrics"]["estimated_total_cost"] > 0
    assert agent["metrics"]["total_tokens"] == llm["metrics"]["total_tokens"]
    # Tool span input is JSON-encoded
    assert tool["meta"]["input"]["value"] == '{"command": "ls"}'
    assert tool["meta"]["output"]["value"] == "file.txt"


def test_session_to_spans_multiple_user_prompts_create_multiple_traces():
    entries = [
        {"type": "user", "timestamp": "2026-05-11T12:00:00.000Z", "message": {"role": "user", "content": "first"}},
        {
            "type": "assistant",
            "timestamp": "2026-05-11T12:00:01.000Z",
            "message": {"role": "assistant", "model": "claude-opus-4-7", "content": [{"type": "text", "text": "ok1"}]},
        },
        {"type": "user", "timestamp": "2026-05-11T12:00:10.000Z", "message": {"role": "user", "content": "second"}},
        {
            "type": "assistant",
            "timestamp": "2026-05-11T12:00:11.000Z",
            "message": {"role": "assistant", "model": "claude-opus-4-7", "content": [{"type": "text", "text": "ok2"}]},
        },
    ]
    spans = claude_backfill.session_to_spans("sess-1", "/p", entries)
    traces = {s["trace_id"] for s in spans}
    assert len(traces) == 2
    agents = [s for s in spans if s["meta"]["span"]["kind"] == "agent"]
    assert len(agents) == 2
    assert agents[0]["meta"]["input"]["value"] == "first"
    assert agents[1]["meta"]["input"]["value"] == "second"


def test_session_to_spans_skips_entries_without_timestamps():
    entries = [
        {"type": "user", "message": {"role": "user", "content": "no ts"}},
        {"type": "user", "timestamp": "2026-05-11T12:00:00.000Z", "message": {"role": "user", "content": "ok"}},
    ]
    spans = claude_backfill.session_to_spans("s", "", entries)
    agents = [s for s in spans if s["meta"]["span"]["kind"] == "agent"]
    assert len(agents) == 1
    assert agents[0]["meta"]["input"]["value"] == "ok"


def test_backfill_posts_one_payload_per_session(monkeypatch, tmp_path):
    projects = tmp_path / "projects"
    _write_transcript(
        projects / "-Users-x" / "sess-a.jsonl",
        [
            {
                "type": "user",
                "timestamp": "2026-05-11T12:00:00.000Z",
                "cwd": "/Users/x",
                "message": {"role": "user", "content": "hi"},
            }
        ],
    )
    _write_transcript(
        projects / "-Users-y" / "sess-b.jsonl",
        [
            {
                "type": "user",
                "timestamp": "2026-05-11T12:01:00.000Z",
                "cwd": "/Users/y",
                "message": {"role": "user", "content": "hi"},
            }
        ],
    )

    posts: List[Dict[str, Any]] = []

    def fake_post(url, **kw):
        body = kw.get("json") or {}
        posts.append((url, body))
        # The preflight POST sends an empty body — the handler responds 400.
        if not body.get("entries"):
            return mock.Mock(status_code=400)
        return mock.Mock(status_code=200)

    monkeypatch.setattr("lapdog._backfill_common._session.post", fake_post)

    n = backfill_claude.backfill("http://localhost:8126", projects_dir=projects)
    assert n == 2
    # 1 preflight + 1 POST per session = 3 total.
    assert len(posts) == 3
    urls = {url for url, _ in posts}
    assert urls == {"http://localhost:8126/claude/hooks/backfill_session"}
    # Filter to actual session POSTs (those with entries).
    session_bodies = [body for _, body in posts if body.get("entries")]
    sessions = {body["session_id"] for body in session_bodies}
    assert sessions == {"sess-a", "sess-b"}


def test_backfill_no_sessions_returns_zero(monkeypatch, tmp_path, capsys):
    projects = tmp_path / "projects"
    projects.mkdir()
    monkeypatch.setattr(
        "lapdog._backfill_common._session.post",
        lambda *a, **kw: mock.Mock(status_code=200),
    )
    assert backfill_claude.backfill("http://localhost:8126", projects_dir=projects) == 0
    assert "no sessions found" in capsys.readouterr().err
