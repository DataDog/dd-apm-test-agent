import json
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from unittest import mock

from ddapm_test_agent import pi_backfill
from lapdog import _backfill_common
from lapdog import backfill_pi


def _write_session(path: Path, entries: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def test_session_to_spans_full_turn():
    entries = [
        {"type": "session", "id": "sess-1", "cwd": "/p", "timestamp": "2026-05-11T12:00:00.000Z"},
        {
            "type": "message",
            "message": {
                "role": "user",
                "timestamp": 1778932800000,  # 2026-05-11 12:00:00 UTC, ms
                "content": [{"type": "text", "text": "hi"}],
            },
        },
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "timestamp": 1778932801000,
                "model": "claude-opus-4-6",
                "provider": "anthropic",
                "usage": {
                    "input": 5,
                    "output": 20,
                    "cacheRead": 0,
                    "cacheWrite": 100,
                    "totalTokens": 125,
                    "cost": {"input": 0.0, "output": 0.001, "cacheRead": 0, "cacheWrite": 0.005, "total": 0.006},
                },
                "content": [
                    {"type": "text", "text": "ok"},
                    {"type": "toolCall", "id": "tc1", "name": "bash", "arguments": {"command": "ls"}},
                ],
            },
        },
        {
            "type": "message",
            "message": {
                "role": "toolResult",
                "timestamp": 1778932803000,
                "toolCallId": "tc1",
                "toolName": "bash",
                "isError": False,
                "content": [{"type": "text", "text": "file.txt"}],
            },
        },
    ]
    spans = pi_backfill.session_to_spans("sess-1", "/p", entries)
    by_kind = {s["meta"]["span"]["kind"]: s for s in spans}
    assert set(by_kind) == {"agent", "step", "llm", "tool"}
    agent, step, llm, tool = by_kind["agent"], by_kind["step"], by_kind["llm"], by_kind["tool"]
    assert agent["trace_id"] == step["trace_id"] == llm["trace_id"] == tool["trace_id"]
    assert step["parent_id"] == agent["span_id"]
    assert llm["parent_id"] == step["span_id"]
    assert tool["parent_id"] == step["span_id"]
    # Real timestamps in ns
    assert agent["start_ns"] == 1778932800000 * 1_000_000
    assert llm["start_ns"] == 1778932800000 * 1_000_000
    assert step["duration"] == 3_000 * 1_000_000
    # Tool duration = (toolResult ts - toolCall ts) in ns
    assert tool["duration"] == 2_000 * 1_000_000
    # Cost converted to nanodollars (0.006 USD * 1e9)
    assert llm["metrics"]["estimated_total_cost"] == 6_000_000
    assert llm["metrics"]["total_tokens"] == 125


def test_session_to_spans_multiple_user_prompts_create_multiple_traces():
    entries = [
        {"type": "session", "id": "s", "cwd": "/p"},
        {
            "type": "message",
            "message": {"role": "user", "timestamp": 1778932800000, "content": [{"type": "text", "text": "first"}]},
        },
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "timestamp": 1778932801000,
                "model": "claude-opus-4-6",
                "content": [{"type": "text", "text": "a"}],
            },
        },
        {
            "type": "message",
            "message": {"role": "user", "timestamp": 1778932810000, "content": [{"type": "text", "text": "second"}]},
        },
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "timestamp": 1778932811000,
                "model": "claude-opus-4-6",
                "content": [{"type": "text", "text": "b"}],
            },
        },
    ]
    spans = pi_backfill.session_to_spans("s", "/p", entries)
    traces = {s["trace_id"] for s in spans}
    assert len(traces) == 2


def test_session_to_spans_closes_zero_duration_turns():
    entries = [
        {"type": "session", "id": "s", "cwd": "/p"},
        {
            "type": "message",
            "message": {"role": "user", "timestamp": 1778932800000, "content": [{"type": "text", "text": "only"}]},
        },
    ]

    spans = pi_backfill.session_to_spans("s", "/p", entries)

    agent = next(s for s in spans if s["meta"]["span"]["kind"] == "agent")
    assert agent["duration"] == 1
    assert agent["status"] == "ok"


def test_backfill_walks_pi_and_omp_one_post_per_session(monkeypatch, tmp_path):
    pi_dir = tmp_path / "pi"
    omp_dir = tmp_path / "omp"
    _write_session(
        pi_dir / "proj1" / "a.jsonl",
        [
            {"type": "session", "id": "sess-pi", "cwd": "/p1"},
            {
                "type": "message",
                "message": {"role": "user", "timestamp": 1778932800000, "content": [{"type": "text", "text": "hi"}]},
            },
        ],
    )
    _write_session(
        omp_dir / "proj2" / "b.jsonl",
        [
            {"type": "session", "id": "sess-omp", "cwd": "/p2"},
            {
                "type": "message",
                "message": {"role": "user", "timestamp": 1778932810000, "content": [{"type": "text", "text": "hi"}]},
            },
        ],
    )

    posts: List[Any] = []

    def fake_post(url, **kw):
        body = kw.get("json") or {}
        posts.append((url, body))
        if not body.get("entries"):
            return mock.Mock(status_code=400)
        return mock.Mock(status_code=200)

    monkeypatch.setattr("lapdog._backfill_common._session.post", fake_post)
    monkeypatch.setattr(_backfill_common, "_lapdog_dead", False)

    assert backfill_pi.backfill("http://localhost:8126", pi_dir=pi_dir, omp_dir=omp_dir) == 2
    # 1 preflight + 2 per-session = 3 total
    assert len(posts) == 3
    assert {url for url, _ in posts} == {"http://localhost:8126/pi/hooks/backfill_session"}
    session_bodies = [body for _, body in posts if body.get("entries")]
    assert {body["session_id"] for body in session_bodies} == {"sess-pi", "sess-omp"}


def test_backfill_skips_malformed_first_entry(monkeypatch, tmp_path):
    pi_dir = tmp_path / "pi"
    _write_session(pi_dir / "proj" / "bad.jsonl", [{"type": "message"}])
    posts: List[Any] = []

    def fake_post(*a, **kw):
        body = kw.get("json") or {}
        posts.append(body)
        if not body.get("entries"):
            return mock.Mock(status_code=400)
        return mock.Mock(status_code=200)

    monkeypatch.setattr("lapdog._backfill_common._session.post", fake_post)
    monkeypatch.setattr(_backfill_common, "_lapdog_dead", False)
    assert backfill_pi.backfill("http://localhost:8126", pi_dir=pi_dir, omp_dir=tmp_path / "x") == 0
    # Only the preflight POST should fire; no per-session attempts because
    # the lone file has no session header.
    session_posts = [b for b in posts if b.get("entries")]
    assert session_posts == []


def test_backfill_no_sessions_returns_zero(monkeypatch, tmp_path, capsys):
    pi_dir = tmp_path / "pi"
    pi_dir.mkdir()
    monkeypatch.setattr(
        "lapdog._backfill_common._session.post",
        lambda *a, **kw: mock.Mock(status_code=200),
    )
    assert backfill_pi.backfill("http://localhost:8126", pi_dir=pi_dir, omp_dir=tmp_path / "absent") == 0
    assert "no sessions found" in capsys.readouterr().err


def test_backfill_bails_when_endpoint_missing(monkeypatch, tmp_path, capsys):
    pi_dir = tmp_path / "pi"
    _write_session(
        pi_dir / "p" / "x.jsonl",
        [
            {"type": "session", "id": "s", "cwd": "/p"},
            {
                "type": "message",
                "message": {"role": "user", "timestamp": 1, "content": [{"type": "text", "text": "hi"}]},
            },
        ],
    )
    monkeypatch.setattr(_backfill_common, "_lapdog_dead", False)
    # First call (preflight) returns 404 → backfill should bail with 0
    # without attempting per-session POSTs.
    calls: List[Any] = []

    def fake_post(url, **kw):
        calls.append(url)
        return mock.Mock(status_code=404)

    monkeypatch.setattr("lapdog._backfill_common._session.post", fake_post)

    assert backfill_pi.backfill("http://localhost:8126", pi_dir=pi_dir, omp_dir=tmp_path / "absent") == 0
    # Exactly one POST (the preflight); no per-session attempts.
    assert len(calls) == 1
    err = capsys.readouterr().err
    assert "older than the --backfill feature" in err


def test_backfill_aborts_on_lapdog_death(monkeypatch, tmp_path, capsys):
    pi_dir = tmp_path / "pi"
    _write_session(
        pi_dir / "p" / "a.jsonl",
        [
            {"type": "session", "id": "sa", "cwd": "/p"},
            {
                "type": "message",
                "message": {"role": "user", "timestamp": 1, "content": [{"type": "text", "text": "hi"}]},
            },
        ],
    )
    _write_session(
        pi_dir / "p" / "b.jsonl",
        [
            {"type": "session", "id": "sb", "cwd": "/p"},
            {
                "type": "message",
                "message": {"role": "user", "timestamp": 2, "content": [{"type": "text", "text": "hi"}]},
            },
        ],
    )
    # Reset the latched dead flag from any earlier test.
    monkeypatch.setattr(_backfill_common, "_lapdog_dead", False)

    from requests.exceptions import ConnectionError as RCE

    post_calls = {"count": 0}

    def fake_post(url, **kw):
        # First call = preflight to backfill_session: return 400 to indicate
        # the route is wired up.
        post_calls["count"] += 1
        if post_calls["count"] == 1:
            return mock.Mock(status_code=400)
        # Subsequent POSTs simulate a dead server.
        raise RCE("Connection refused")

    def fake_get(url, **kw):
        # /info probe — also dead.
        raise RCE("Connection refused")

    monkeypatch.setattr("lapdog._backfill_common._session.post", fake_post)
    monkeypatch.setattr("lapdog._backfill_common._session.get", fake_get)

    n = backfill_pi.backfill("http://localhost:8126", pi_dir=pi_dir, omp_dir=tmp_path / "absent")
    # 0 sessions forwarded; aborted message in stderr.
    assert n == 0
    err = capsys.readouterr().err
    assert "aborted" in err and "stopped responding" in err
