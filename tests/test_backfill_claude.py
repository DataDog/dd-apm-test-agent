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
    assert set(by_kind) == {"agent", "step", "llm", "tool"}
    agent = by_kind["agent"]
    step = by_kind["step"]
    llm = by_kind["llm"]
    tool = by_kind["tool"]
    # All in the same trace
    assert agent["trace_id"] == step["trace_id"] == llm["trace_id"] == tool["trace_id"]
    # Step sits between the root agent and its LLM/tool children.
    assert step["parent_id"] == agent["span_id"]
    assert llm["parent_id"] == step["span_id"]
    assert tool["parent_id"] == step["span_id"]
    assert step["duration"] == 2_000_000_000
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


def test_session_to_spans_sets_model_from_first_assistant_in_each_turn():
    entries = [
        {
            "type": "assistant",
            "timestamp": "2026-05-11T11:59:59.000Z",
            "message": {"role": "assistant", "model": "title-model", "content": [{"type": "text", "text": "title"}]},
        },
        {"type": "user", "timestamp": "2026-05-11T12:00:00.000Z", "message": {"role": "user", "content": "first"}},
        {
            "type": "assistant",
            "timestamp": "2026-05-11T12:00:01.000Z",
            "message": {"role": "assistant", "model": "turn-one-model", "content": [{"type": "text", "text": "ok1"}]},
        },
        {"type": "user", "timestamp": "2026-05-11T12:00:10.000Z", "message": {"role": "user", "content": "second"}},
        {
            "type": "assistant",
            "timestamp": "2026-05-11T12:00:11.000Z",
            "message": {"role": "assistant", "model": "turn-two-model", "content": [{"type": "text", "text": "ok2"}]},
        },
    ]

    spans = claude_backfill.session_to_spans("sess-1", "/p", entries)

    agents = [s for s in spans if s["meta"]["span"]["kind"] == "agent"]
    assert [s["meta"]["model_name"] for s in agents] == ["turn-one-model", "turn-two-model"]
    assert [s["meta"]["metadata"]["_dd"]["agent_manifest"]["model"] for s in agents] == [
        "turn-one-model",
        "turn-two-model",
    ]


def test_session_to_spans_renders_task_tool_as_subagent_span():
    entries = [
        {"type": "user", "timestamp": "2026-05-11T12:00:00.000Z", "message": {"role": "user", "content": "first"}},
        {
            "type": "assistant",
            "timestamp": "2026-05-11T12:00:01.000Z",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4-7",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "task-1",
                        "name": "Task",
                        "input": {"description": "Explore", "prompt": "inspect the code"},
                    }
                ],
            },
        },
        {
            "type": "user",
            "timestamp": "2026-05-11T12:00:03.000Z",
            "message": {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "task-1", "content": "found it"}],
            },
        },
    ]

    spans = claude_backfill.session_to_spans("sess-1", "/p", entries)

    agents = [s for s in spans if s["meta"]["span"]["kind"] == "agent"]
    llm = next(s for s in spans if s["meta"]["span"]["kind"] == "llm")
    step = next(s for s in spans if s["meta"]["span"]["kind"] == "step")
    subagent = next(s for s in agents if s["parent_id"] != "undefined")
    assert subagent["name"] == "Task - Explore"
    assert llm["parent_id"] == step["span_id"]
    assert subagent["parent_id"] == step["span_id"]
    assert subagent["meta"]["output"]["value"] == "found it"
    assert subagent["meta"]["metadata"]["subagent"]["prompt"] == "inspect the code"


def _subagent_transcript(
    prompt: str, *, agent_id: str = "agent-x", model: str = "claude-haiku-4-5"
) -> List[Dict[str, Any]]:
    """Build a subagent (sidechain) transcript like Claude writes to
    ``<session>/subagents/agent-<id>.jsonl``: a string-content launch prompt
    followed by the subagent's own assistant turn + tool call.
    """
    return [
        {
            "type": "user",
            "isSidechain": True,
            "agentId": agent_id,
            "sessionId": "sess-1",
            "timestamp": "2026-05-11T12:00:01.500Z",
            "message": {"role": "user", "content": prompt},
        },
        {
            "type": "assistant",
            "isSidechain": True,
            "agentId": agent_id,
            "timestamp": "2026-05-11T12:00:02.000Z",
            "message": {
                "role": "assistant",
                "model": model,
                "usage": {"input_tokens": 30, "output_tokens": 20},
                "content": [
                    {"type": "text", "text": "looking"},
                    {"type": "tool_use", "id": "sub-tool-1", "name": "Read", "input": {"file": "a.py"}},
                ],
            },
        },
        {
            "type": "user",
            "isSidechain": True,
            "agentId": agent_id,
            "timestamp": "2026-05-11T12:00:02.500Z",
            "message": {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "sub-tool-1", "content": "contents"}],
            },
        },
    ]


def test_session_to_spans_nests_subagent_transcript_under_task_span():
    entries = [
        {"type": "user", "timestamp": "2026-05-11T12:00:00.000Z", "message": {"role": "user", "content": "first"}},
        {
            "type": "assistant",
            "timestamp": "2026-05-11T12:00:01.000Z",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4-7",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "task-1",
                        "name": "Task",
                        "input": {"description": "Explore", "subagent_type": "Explore", "prompt": "go look"},
                    }
                ],
            },
        },
        {
            "type": "user",
            "timestamp": "2026-05-11T12:00:03.000Z",
            "message": {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "task-1", "content": "done"}],
            },
        },
    ]
    subagents = [{"agent_id": "agent-x", "entries": _subagent_transcript("go look", agent_id="agent-x")}]

    spans = claude_backfill.session_to_spans("sess-1", "/p", entries, subagents=subagents)

    # Everything is one trace and one session — the subagent does NOT split off.
    assert len({s["trace_id"] for s in spans}) == 1
    assert {s["session_id"] for s in spans} == {"sess-1"}

    task_agent = next(s for s in spans if s["meta"]["span"]["kind"] == "agent" and s["parent_id"] != "undefined")
    assert task_agent["name"] == "Task - Explore"
    assert task_agent["meta"]["metadata"]["subagent"]["agent_id"] == "agent-x"

    # The Task agent matches live traces: it is a sibling of the LLM under the step that spawned it,
    # then the subagent's own spans are nested under that Task agent span.
    parent_step = next(s for s in spans if s["span_id"] == task_agent["parent_id"])
    parent_llm = next(
        s for s in spans if s["meta"]["span"]["kind"] == "llm" and s["parent_id"] == parent_step["span_id"]
    )
    assert parent_step["meta"]["span"]["kind"] == "step"
    assert parent_llm["parent_id"] == parent_step["span_id"]
    assert task_agent["parent_id"] == parent_step["span_id"]
    sub_steps = [s for s in spans if s["meta"]["span"]["kind"] == "step" and s["parent_id"] == task_agent["span_id"]]
    assert len(sub_steps) == 1
    sub_llm = next(s for s in spans if s["meta"]["span"]["kind"] == "llm" and s["parent_id"] == sub_steps[0]["span_id"])
    sub_tool = next(s for s in spans if s["meta"]["span"]["kind"] == "tool" and s["name"] == "Read")
    assert sub_llm["trace_id"] == task_agent["trace_id"]
    assert sub_tool["parent_id"] == sub_steps[0]["span_id"]
    assert sub_tool["meta"]["output"]["value"] == "contents"
    # The subagent's token usage rolls up onto its Task agent span.
    assert task_agent["metrics"]["total_tokens"] == sub_llm["metrics"]["total_tokens"]


def test_session_to_spans_nests_subagent_when_tool_not_named_task():
    # The orchestration harness names the tool "Agent" rather than "Task"; the
    # link is the prompt string, not the tool name, so it must still nest.
    entries = [
        {"type": "user", "timestamp": "2026-05-11T12:00:00.000Z", "message": {"role": "user", "content": "first"}},
        {
            "type": "assistant",
            "timestamp": "2026-05-11T12:00:01.000Z",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4-7",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "a1",
                        "name": "Agent",
                        "input": {"description": "Dig", "prompt": "go look"},
                    }
                ],
            },
        },
        {
            "type": "user",
            "timestamp": "2026-05-11T12:00:03.000Z",
            "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a1", "content": "done"}]},
        },
    ]
    subagents = [{"agent_id": "agent-y", "entries": _subagent_transcript("go look", agent_id="agent-y")}]

    spans = claude_backfill.session_to_spans("sess-1", "/p", entries, subagents=subagents)

    assert len({s["trace_id"] for s in spans}) == 1
    agent = next(s for s in spans if s["meta"]["span"]["kind"] == "agent" and s["parent_id"] != "undefined")
    parent_step = next(s for s in spans if s["span_id"] == agent["parent_id"])
    parent_llm = next(
        s for s in spans if s["meta"]["span"]["kind"] == "llm" and s["parent_id"] == parent_step["span_id"]
    )
    assert parent_step["meta"]["span"]["kind"] == "step"
    assert parent_llm["parent_id"] == parent_step["span_id"]
    assert agent["name"] == "Agent - Dig"
    assert agent["parent_id"] == parent_step["span_id"]
    assert any(s["meta"]["span"]["kind"] == "step" and s["parent_id"] == agent["span_id"] for s in spans)


def test_session_to_spans_orphan_subagent_stays_in_same_session():
    # A subagent transcript whose Task call isn't in the main transcript still
    # belongs to this session — it must not become a separate session_id.
    entries = [
        {"type": "user", "timestamp": "2026-05-11T12:00:00.000Z", "message": {"role": "user", "content": "first"}},
        {
            "type": "assistant",
            "timestamp": "2026-05-11T12:00:01.000Z",
            "message": {"role": "assistant", "model": "claude-opus-4-7", "content": [{"type": "text", "text": "ok"}]},
        },
    ]
    subagents = [{"agent_id": "agent-orphan", "entries": _subagent_transcript("unmatched prompt")}]

    spans = claude_backfill.session_to_spans("sess-1", "/p", entries, subagents=subagents)

    assert {s["session_id"] for s in spans} == {"sess-1"}
    # The orphan gets its own root agent span (a new trace) but same session.
    roots = [s for s in spans if s["parent_id"] == "undefined"]
    assert len(roots) == 2
    orphan_root = next(r for r in roots if r["meta"]["input"]["value"] == "unmatched prompt")
    assert orphan_root["meta"]["metadata"]["_dd"]["agent_id"] == "agent-orphan"
    # The orphan's own tool span is nested under it, in the orphan's trace.
    orphan_tool = next(s for s in spans if s["meta"]["span"]["kind"] == "tool" and s["name"] == "Read")
    assert orphan_tool["trace_id"] == orphan_root["trace_id"]
    assert orphan_tool["trace_id"] != roots[0]["trace_id"] or roots[0] is orphan_root


def test_session_to_spans_closes_zero_duration_turns():
    entries = [
        {"type": "user", "timestamp": "2026-05-11T12:00:00.000Z", "message": {"role": "user", "content": "only"}},
    ]

    spans = claude_backfill.session_to_spans("sess-1", "/p", entries)

    agent = next(s for s in spans if s["meta"]["span"]["kind"] == "agent")
    assert agent["duration"] == 1
    assert agent["status"] == "ok"


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


def test_iter_session_files_excludes_subagent_transcripts(tmp_path):
    projects = tmp_path / "projects"
    _write_transcript(projects / "-Users-x" / "sess-a.jsonl", [{"type": "user", "message": {"content": "hi"}}])
    # A subagent transcript living under <session>/subagents/ must be skipped.
    _write_transcript(
        projects / "-Users-x" / "sess-a" / "subagents" / "agent-1.jsonl",
        [{"type": "user", "isSidechain": True, "message": {"content": "sub"}}],
    )

    files = backfill_claude._iter_session_files(projects)

    assert [p.name for p in files] == ["sess-a.jsonl"]
    assert all("subagents" not in p.parts for p in files)


def test_backfill_bundles_subagent_transcripts(monkeypatch, tmp_path):
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
        projects / "-Users-x" / "sess-a" / "subagents" / "agent-abc.jsonl",
        _subagent_transcript("go look", agent_id="agent-abc"),
    )

    posts: List[Dict[str, Any]] = []

    def fake_post(url, **kw):
        body = kw.get("json") or {}
        posts.append(body)
        return mock.Mock(status_code=400 if not body.get("entries") else 200)

    monkeypatch.setattr("lapdog._backfill_common._session.post", fake_post)

    n = backfill_claude.backfill("http://localhost:8126", projects_dir=projects)
    assert n == 1  # one session, not two — the subagent isn't its own session.

    session_bodies = [b for b in posts if b.get("entries")]
    assert len(session_bodies) == 1
    body = session_bodies[0]
    assert body["session_id"] == "sess-a"
    assert len(body["subagents"]) == 1
    assert body["subagents"][0]["agent_id"] == "agent-abc"
    assert len(body["subagents"][0]["entries"]) == 3


def test_backfill_no_sessions_returns_zero(monkeypatch, tmp_path, capsys):
    projects = tmp_path / "projects"
    projects.mkdir()
    monkeypatch.setattr(
        "lapdog._backfill_common._session.post",
        lambda *a, **kw: mock.Mock(status_code=200),
    )
    assert backfill_claude.backfill("http://localhost:8126", projects_dir=projects) == 0
    assert "no sessions found" in capsys.readouterr().err
