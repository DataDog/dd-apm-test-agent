"""Tests for Codex JSONL hooks."""

import gzip
import json

import msgpack
import pytest

from ddapm_test_agent.claude_hooks import ClaudeHooksAPI


@pytest.fixture
def dd_api_key():
    return ""


@pytest.fixture
def codex_env_overrides(monkeypatch):
    monkeypatch.setenv("DD_CLAUDE_CODE_ML_APP", "lapdog")
    monkeypatch.setenv("DD_CODEX_ML_APP", "codex-custom")
    monkeypatch.setenv("DD_USER_HANDLE", "shared-user")


async def _post(agent, session_id, record):
    return await agent.post(
        "/codex/hooks",
        headers={"Content-Type": "application/json"},
        data=json.dumps({"session_id": session_id, "record": record}),
    )


def _spans(body):
    return body["spans"]


def _by_kind(spans, kind):
    return [s for s in spans if s.get("meta", {}).get("span", {}).get("kind") == kind]


def _span_index(spans, span):
    return next(index for index, candidate in enumerate(spans) if candidate["span_id"] == span["span_id"])


def _session_meta(session_id="codex-sess"):
    return {
        "timestamp": "2026-05-11T17:00:00.000Z",
        "type": "session_meta",
        "payload": {
            "id": session_id,
            "cwd": "/repo",
            "originator": "codex-tui",
            "cli_version": "0.130.0",
            "model_provider": "openai",
        },
    }


def _turn_context(turn_id="turn-1"):
    return {
        "timestamp": "2026-05-11T17:00:01.000Z",
        "type": "turn_context",
        "payload": {
            "turn_id": turn_id,
            "cwd": "/repo",
            "model": "gpt-5.5",
            "effort": "medium",
        },
    }


def _event(event_type, timestamp="2026-05-11T17:00:02.000Z", **kwargs):
    return {
        "timestamp": timestamp,
        "type": "event_msg",
        "payload": {
            "type": event_type,
            **kwargs,
        },
    }


def _response_item(item_type, timestamp="2026-05-11T17:00:03.000Z", **kwargs):
    return {
        "timestamp": timestamp,
        "type": "response_item",
        "payload": {
            "type": item_type,
            **kwargs,
        },
    }


async def test_codex_turn_llm_and_tool_spans(agent):
    sid = "codex-basic"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="inspect this repo"))
    await _post(
        agent,
        sid,
        _response_item(
            "function_call",
            name="exec_command",
            call_id="call-1",
            arguments='{"cmd": "rg codex"}',
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            info={
                "last_token_usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 20,
                    "output_tokens": 30,
                    "reasoning_output_tokens": 5,
                    "total_tokens": 130,
                }
            },
        ),
    )
    await _post(
        agent,
        sid,
        _response_item("function_call_output", call_id="call-1", output="matches"),
    )
    await _post(agent, sid, _event("agent_message", message="found it"))

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]

    roots = [s for s in session_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 1
    root = roots[0]
    assert root["name"] == "codex-request"
    assert root["meta"]["input"]["value"] == "inspect this repo"
    assert root["meta"]["output"]["value"] == "found it"
    assert "source:codex-jsonl" in root["tags"]
    assert "trajectory.semantic_type:turn" in root["tags"]

    steps = _by_kind(session_spans, "step")
    llms = _by_kind(session_spans, "llm")
    tools = _by_kind(session_spans, "tool")
    assert len(steps) == 1
    assert len(llms) == 1
    assert len(tools) == 1
    assert steps[0]["parent_id"] == root["span_id"]
    assert llms[0]["parent_id"] == steps[0]["span_id"]
    assert tools[0]["parent_id"] == steps[0]["span_id"]
    assert tools[0]["name"] == "exec_command"
    assert tools[0]["meta"]["input"]["value"] == '{"cmd": "rg codex"}'
    assert tools[0]["meta"]["output"]["value"] == "matches"
    assert llms[0]["metrics"]["input_tokens"] == 100
    assert llms[0]["metrics"]["output_tokens"] == 30
    assert llms[0]["metrics"]["reasoning_output_tokens"] == 5
    assert llms[0]["metrics"]["cache_read_input_tokens"] == 20
    assert llms[0]["metrics"]["non_cached_input_tokens"] == 80
    assert llms[0]["metrics"]["estimated_input_cost"] == 410_000
    assert llms[0]["metrics"]["estimated_output_cost"] == 900_000
    assert llms[0]["metrics"]["estimated_total_cost"] == 1_310_000


async def test_codex_populates_step_and_late_llm_output(agent):
    sid = "codex-late-output"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="hello"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:04.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 10,
                    "cached_input_tokens": 0,
                    "output_tokens": 2,
                    "total_tokens": 12,
                }
            },
        ),
    )
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:05.000Z", message="Hello."))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    step = _by_kind(session_spans, "step")[0]
    llm = _by_kind(session_spans, "llm")[0]

    assert step["meta"]["input"]["value"] == "hello"
    assert step["meta"]["output"]["value"] == "Hello."
    assert llm["meta"]["input"]["messages"] == [{"role": "user", "content": "hello"}]
    assert llm["meta"]["output"]["messages"] == [{"role": "assistant", "content": "Hello."}]


async def test_codex_ignores_token_usage_without_model_output(agent):
    sid = "codex-empty-usage"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="hello"))
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:03.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 10,
                    "cached_input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 10,
                }
            },
        ),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    llms = _by_kind(session_spans, "llm")

    assert llms == []
    assert all(span["name"] != "codex-model" for span in session_spans)


async def test_codex_duplicate_usage_does_not_create_second_llm_in_step(agent):
    sid = "codex-duplicate-usage"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="hello"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    await _post(
        agent,
        sid,
        _response_item(
            "message",
            timestamp="2026-05-11T17:00:04.000Z",
            role="assistant",
            content=[{"type": "output_text", "text": "Hello."}],
        ),
    )
    usage_event = _event(
        "token_count",
        timestamp="2026-05-11T17:00:05.000Z",
        info={
            "last_token_usage": {
                "input_tokens": 10,
                "cached_input_tokens": 0,
                "output_tokens": 2,
                "total_tokens": 12,
            }
        },
    )
    await _post(agent, sid, usage_event)
    await _post(agent, sid, {**usage_event, "timestamp": "2026-05-11T17:00:06.000Z"})

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    steps = _by_kind(session_spans, "step")
    llms = _by_kind(session_spans, "llm")

    assert len(steps) == 1
    assert len(llms) == 1
    assert llms[0]["parent_id"] == steps[0]["span_id"]


async def test_codex_creates_step_and_llm_span_per_model_call(agent):
    sid = "codex-multi-llm"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="use a tool"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    await _post(
        agent,
        sid,
        _response_item(
            "function_call",
            timestamp="2026-05-11T17:00:04.000Z",
            name="exec_command",
            call_id="call-1",
            arguments='{"cmd": "pwd"}',
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:05.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 20,
                    "output_tokens": 10,
                    "reasoning_output_tokens": 4,
                    "total_tokens": 110,
                }
            },
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "function_call_output",
            timestamp="2026-05-11T17:00:07.000Z",
            call_id="call-1",
            output="/repo",
        ),
    )
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:08.000Z", info=None))
    await _post(
        agent,
        sid,
        _response_item(
            "message",
            timestamp="2026-05-11T17:00:10.000Z",
            role="assistant",
            content=[{"type": "output_text", "text": "done"}],
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:11.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 120,
                    "cached_input_tokens": 30,
                    "output_tokens": 20,
                    "reasoning_output_tokens": 5,
                    "total_tokens": 140,
                }
            },
        ),
    )
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:12.000Z", message="done"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    steps = sorted(_by_kind(session_spans, "step"), key=lambda s: s["name"])
    llms = sorted(_by_kind(session_spans, "llm"), key=lambda s: s["start_ns"])
    tools = _by_kind(session_spans, "tool")

    assert [s["name"] for s in steps] == ["inference-0", "inference-1"]
    assert len(llms) == 2
    assert len(tools) == 1
    assert llms[0]["parent_id"] == steps[0]["span_id"]
    assert tools[0]["parent_id"] == steps[0]["span_id"]
    assert llms[1]["parent_id"] == steps[1]["span_id"]
    assert llms[0]["duration"] == 2_000_000_000
    assert llms[1]["duration"] == 3_000_000_000
    assert steps[0]["duration"] == 4_000_000_000
    assert steps[1]["duration"] == 3_000_000_000
    assert llms[0]["metrics"]["output_tokens"] == 10
    assert llms[1]["metrics"]["output_tokens"] == 20
    assert llms[1]["meta"]["output"]["messages"] == [{"role": "assistant", "content": "done"}]
    assert steps[0]["meta"]["input"]["value"] == "use a tool"
    assert json.loads(steps[1]["meta"]["input"]["value"]) == [
        {"role": "user", "content": "use a tool"},
        {"role": "tool", "tool_call_id": "call-1", "content": "/repo"},
    ]
    assert steps[0]["meta"]["output"]["value"] == '{"cmd": "pwd"}'
    assert llms[0]["meta"]["output"]["messages"] == [
        {
            "role": "assistant",
            "content": '{"cmd": "pwd"}',
            "tool_calls": [{"id": "call-1", "name": "exec_command", "arguments": {"cmd": "pwd"}}],
        }
    ]
    assert llms[1]["meta"]["input"]["messages"][-2:] == [
        {
            "role": "assistant",
            "content": '{"cmd": "pwd"}',
            "tool_calls": [{"id": "call-1", "name": "exec_command", "arguments": {"cmd": "pwd"}}],
        },
        {"role": "tool", "tool_call_id": "call-1", "content": "/repo"},
    ]


async def test_codex_orders_tool_call_llm_before_tool_when_usage_arrives_late(agent):
    sid = "codex-late-usage-tool"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="list files"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    await _post(
        agent,
        sid,
        _response_item(
            "function_call",
            timestamp="2026-05-11T17:00:04.000Z",
            name="exec_command",
            call_id="call-1",
            arguments='{"cmd": "rg --files"}',
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "function_call_output",
            timestamp="2026-05-11T17:00:04.300Z",
            call_id="call-1",
            output="README.md",
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:05.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 0,
                    "output_tokens": 10,
                    "total_tokens": 110,
                }
            },
        ),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    llm = _by_kind(session_spans, "llm")[0]
    tool = _by_kind(session_spans, "tool")[0]

    assert _span_index(session_spans, llm) < _span_index(session_spans, tool)
    assert llm["meta"]["input"]["messages"] == [{"role": "user", "content": "list files"}]
    assert llm["meta"]["output"]["messages"] == [
        {
            "role": "assistant",
            "content": '{"cmd": "rg --files"}',
            "tool_calls": [{"id": "call-1", "name": "exec_command", "arguments": {"cmd": "rg --files"}}],
        }
    ]


async def test_codex_late_tool_call_stays_in_completed_llm_step(agent):
    sid = "codex-late-tool-call"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="list files"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:04.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 0,
                    "output_tokens": 10,
                    "total_tokens": 110,
                }
            },
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "function_call",
            timestamp="2026-05-11T17:00:05.000Z",
            name="exec_command",
            call_id="call-1",
            arguments='{"cmd": "rg --files"}',
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "function_call_output",
            timestamp="2026-05-11T17:00:06.000Z",
            call_id="call-1",
            output="README.md",
        ),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    steps = _by_kind(session_spans, "step")
    llm = _by_kind(session_spans, "llm")[0]
    tool = _by_kind(session_spans, "tool")[0]

    assert len(steps) == 1
    assert llm["parent_id"] == steps[0]["span_id"]
    assert tool["parent_id"] == steps[0]["span_id"]
    assert llm["meta"]["output"]["messages"] == [
        {
            "role": "assistant",
            "content": '{"cmd": "rg --files"}',
            "tool_calls": [{"id": "call-1", "name": "exec_command", "arguments": {"cmd": "rg --files"}}],
        }
    ]


async def test_codex_new_turn_finalizes_previous_turn(agent):
    sid = "codex-two-turns"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context("turn-a"))
    await _post(agent, sid, _event("user_message", message="first"))
    await _post(agent, sid, _event("agent_message", message="done first"))
    await _post(agent, sid, _turn_context("turn-b"))
    await _post(agent, sid, _event("user_message", message="second"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 2
    first = next(s for s in roots if s["meta"]["metadata"]["turn_id"] == "turn-a")
    second = next(s for s in roots if s["meta"]["metadata"]["turn_id"] == "turn-b")
    assert first["duration"] > 0
    assert first["meta"]["output"]["value"] == "done first"
    assert second["meta"]["input"]["value"] == "second"


async def test_codex_new_turn_forwards_completed_trace_before_repointing_session(agent, monkeypatch):
    forwarded_payloads = []

    def fake_resolve_backend_target(self, *args, **kwargs):
        return "http://backend.example", {}

    async def fake_post_to_backend(self, url, headers, data, description):
        forwarded_payloads.append(msgpack.unpackb(gzip.decompress(data), raw=False))

    monkeypatch.setattr(ClaudeHooksAPI, "_resolve_backend_target", fake_resolve_backend_target)
    monkeypatch.setattr(ClaudeHooksAPI, "_post_to_backend", fake_post_to_backend)

    sid = "codex-forward-two-turns"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context("turn-a"))
    await _post(agent, sid, _event("user_message", message="first"))
    await _post(agent, sid, _event("agent_message", message="done first"))
    await _post(agent, sid, _turn_context("turn-b"))

    assert len(forwarded_payloads) == 1
    forwarded_spans = forwarded_payloads[0]["spans"]
    forwarded_turn_ids = {span["meta"]["metadata"].get("turn_id") for span in forwarded_spans}
    assert forwarded_turn_ids == {"turn-a"}


async def test_codex_accepts_raw_jsonl_records_like_curl(agent):
    sid = "codex-raw-curl"
    await agent.post("/codex/hooks", json=_session_meta(sid))
    await agent.post("/codex/hooks", json=_turn_context())
    await agent.post("/codex/hooks", json=_event("user_message", message="raw curl input"))
    await agent.post("/codex/hooks", json=_event("agent_message", message="raw curl output"))

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 1
    assert roots[0]["meta"]["input"]["value"] == "raw curl input"
    assert roots[0]["meta"]["output"]["value"] == "raw curl output"
    assert roots[0]["duration"] > 0


async def test_codex_list_rewriter_returns_posted_message_spans(agent):
    sid = "codex-list-rewriter"
    await agent.post("/codex/hooks", json=_session_meta(sid))
    await agent.post("/codex/hooks", json=_turn_context())
    await agent.post("/codex/hooks", json=_event("user_message", message="list rewriter input"))
    await agent.post("/codex/hooks", json=_event("agent_message", message="list rewriter output"))

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": f"@session_id:{sid}"}, "limit": 10}},
    )
    assert resp.status == 200
    data = await resp.json()
    root = next(
        event["event"]["custom"] for event in data["result"]["events"] if event["event"]["custom"]["kind"] == "agent"
    )

    assert root["name"] == "codex-request"
    assert root["session_id"] == sid
    assert root["meta"]["input"]["value"] == "list rewriter input"
    assert root["meta"]["output"]["value"] == "list rewriter output"


async def test_codex_tui_task_complete_finalizes_single_turn(agent):
    sid = "codex-tui-hello"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="hello"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    await _post(
        agent,
        sid,
        _event("agent_message", timestamp="2026-05-11T17:00:04.000Z", message="Hello. How can I help?"),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "message",
            timestamp="2026-05-11T17:00:04.100Z",
            role="assistant",
            content=[{"type": "output_text", "text": "Hello. How can I help?"}],
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:05.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 14784,
                    "cached_input_tokens": 6528,
                    "output_tokens": 11,
                    "reasoning_output_tokens": 0,
                    "total_tokens": 14795,
                }
            },
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "task_complete",
            timestamp="2026-05-11T17:00:05.100Z",
            last_agent_message="Hello. How can I help?",
        ),
    )

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": f"@session_id:{sid}"}, "limit": 10}},
    )
    assert resp.status == 200
    data = await resp.json()
    session_events = [event["event"]["custom"] for event in data["result"]["events"]]
    roots = [event for event in session_events if event["kind"] == "agent"]
    steps = [event for event in session_events if event["kind"] == "step"]
    llms = [event for event in session_events if event["kind"] == "llm"]

    assert len(roots) == 1
    assert len(steps) == 1
    assert len(llms) == 1
    assert roots[0]["meta"]["input"]["value"] == "hello"
    assert roots[0]["meta"]["output"]["value"] == "Hello. How can I help?"
    assert roots[0]["duration"] == 4_100_000_000
    assert llms[0]["duration"] == 2_000_000_000
    assert llms[0]["meta"]["output"]["messages"] == [{"role": "assistant", "content": "Hello. How can I help?"}]
    assert llms[0]["metrics"]["input_tokens"] == 14784
    assert llms[0]["metrics"]["estimated_total_cost"] > 0


async def test_codex_ignores_duplicate_replayed_records(agent):
    sid = "codex-replay"
    records = [
        _session_meta(sid),
        _turn_context(),
        _event("user_message", message="replayed input"),
        _event("agent_message", message="replayed output"),
    ]
    for record in records:
        await _post(agent, sid, record)
    for record in records:
        await _post(agent, sid, record)

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 1
    assert roots[0]["meta"]["input"]["value"] == "replayed input"
    assert roots[0]["meta"]["output"]["value"] == "replayed output"


async def test_codex_only_uses_own_ml_app_override(codex_env_overrides, agent):
    sid = "codex-env"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="env input"))
    await _post(agent, sid, _response_item("function_call", name="exec_command", call_id="call-env"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = next(s for s in session_spans if s["parent_id"] == "undefined")

    assert root["ml_app"] == "codex-custom"
    assert root["service"] == "codex-custom"
    assert root["env"] == "local"
    assert "ml_app:codex-custom" in root["tags"]
    assert "service:codex-custom" in root["tags"]
    assert "env:local" in root["tags"]
    assert "user_handle:shared-user" in root["tags"]
    assert "ml_app:lapdog" not in root["tags"]

    manifest = root["meta"]["metadata"]["_dd"]["agent_manifest"]
    assert manifest["name"] == "codex-custom"
    assert manifest["model"] == "gpt-5.5"
    assert manifest["model_provider"] == "openai"
    assert manifest["model_settings"]["reasoning_effort"] == "medium"
    assert manifest["tools"] == [{"name": "exec_command"}]


async def test_codex_hook_requires_session_id(agent):
    resp = await agent.post("/codex/hooks", json={"type": "event_msg", "payload": {"type": "user_message"}})
    assert resp.status == 400
    body = await resp.json()
    assert "session_id" in body["error"]
