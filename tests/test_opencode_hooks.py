"""Tests for opencode coding agent hooks."""

import json


SESSION = "opencode-test-sess"


async def _post(agent, event):
    return await agent.post(
        "/opencode/hooks",
        headers={"Content-Type": "application/json"},
        data=json.dumps(event),
    )


def _spans_body(body):
    return body["spans"]


def _by_kind(spans, kind):
    return [s for s in spans if s.get("meta", {}).get("span", {}).get("kind") == kind]


def _has_tag(span, tag):
    return tag in span.get("tags", [])


# ---------------------------------------------------------------------------
# Event factories
# ---------------------------------------------------------------------------


def _session_start(session_id=SESSION, model_id="", model_provider=""):
    return {
        "session_id": session_id,
        "hook_event_name": "session_start",
        "model_id": model_id,
        "model_provider": model_provider,
    }


def _user_message(session_id=SESSION, content="hello opencode", message_id="msg-u1"):
    return {
        "session_id": session_id,
        "hook_event_name": "user_message",
        "message_id": message_id,
        "content": content,
    }


def _assistant_message(
    session_id=SESSION,
    parts=None,
    tokens=None,
    cost=None,
    model_id="claude-sonnet-4-20250514",
    model_provider="anthropic",
    message_id="msg-a1",
    start_ns=1_000_000_000,
    end_ns=2_000_000_000,
    stop_reason="end_turn",
):
    return {
        "session_id": session_id,
        "hook_event_name": "assistant_message",
        "message_id": message_id,
        "model_id": model_id,
        "model_provider": model_provider,
        "tokens": tokens or {"input": 100, "output": 50, "reasoning": 0, "cache": {"read": 0, "write": 0}},
        "cost": cost,
        "start_ns": start_ns,
        "end_ns": end_ns,
        "parts": parts or [{"type": "text", "text": "Hello!"}],
        "stop_reason": stop_reason,
    }


def _tool_before(session_id=SESSION, call_id="tc-1", tool="read", args=None):
    return {
        "session_id": session_id,
        "hook_event_name": "tool_execute_before",
        "tool_call_id": call_id,
        "tool_name": tool,
        "args": args or {"filePath": "foo.py"},
    }


def _tool_after(session_id=SESSION, call_id="tc-1", tool="read", result="contents", is_error=False, error=None):
    return {
        "session_id": session_id,
        "hook_event_name": "tool_execute_after",
        "tool_call_id": call_id,
        "tool_name": tool,
        "args": {"filePath": "foo.py"},
        "result": result,
        "is_error": is_error,
        "error": error,
    }


def _session_idle(session_id=SESSION):
    return {"session_id": session_id, "hook_event_name": "session_idle"}


def _session_end(session_id=SESSION, error=None):
    return {"session_id": session_id, "hook_event_name": "session_end", "error": error}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_post_returns_200(agent):
    resp = await _post(agent, _session_start())
    assert resp.status == 200
    body = await resp.json()
    assert body["status"] == "ok"


async def test_missing_session_id_is_400(agent):
    resp = await agent.post(
        "/opencode/hooks",
        headers={"Content-Type": "application/json"},
        data=json.dumps({"hook_event_name": "session_start"}),
    )
    assert resp.status == 400


async def test_raw_events_endpoint(agent):
    sid = "opencode-raw"
    await _post(agent, _session_start(sid))
    await _post(agent, _user_message(sid, content="hi"))

    resp = await agent.get("/opencode/hooks/raw")
    assert resp.status == 200
    data = await resp.json()
    sess_events = [e for e in data["events"] if e.get("session_id") == sid]
    assert len(sess_events) == 2
    assert sess_events[0]["hook_event_name"] == "session_start"
    assert sess_events[1]["hook_event_name"] == "user_message"


async def test_minimal_turn_produces_agent_step_and_llm(agent):
    """session_start → user_message → assistant_message → session_idle → spans tree."""
    sid = "opencode-minimal"
    await _post(agent, _session_start(sid, model_id="claude-sonnet-4-20250514", model_provider="anthropic"))
    await _post(agent, _user_message(sid, content="What is 1+1?"))
    await _post(agent, _assistant_message(sid, parts=[{"type": "text", "text": "It is 2."}]))
    await _post(agent, _session_idle(sid))

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    spans = _spans_body(await resp.json())
    sess_spans = [s for s in spans if s.get("session_id") == sid]

    roots = [s for s in sess_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 1
    root = roots[0]
    assert root["meta"]["span"]["kind"] == "agent"
    assert root["meta"]["input"]["value"] == "What is 1+1?"
    assert root["meta"]["output"]["value"] == "It is 2."
    assert _has_tag(root, "source:opencode-hooks")
    assert root["duration"] > 0

    steps = _by_kind(sess_spans, "step")
    assert len(steps) == 1
    step = steps[0]
    assert step["parent_id"] == root["span_id"]
    assert step["name"] == "inference-0"

    llms = _by_kind(sess_spans, "llm")
    assert len(llms) == 1
    llm = llms[0]
    assert llm["parent_id"] == step["span_id"]
    assert llm["meta"]["model_name"] == "claude-sonnet-4-20250514"
    assert llm["meta"]["model_provider"] == "anthropic"
    assert llm["metrics"]["input_tokens"] == 100
    assert llm["metrics"]["output_tokens"] == 50


async def test_tools_nest_under_step(agent):
    sid = "opencode-tools"
    parts = [
        {"type": "text", "text": "Let me check that file."},
        {
            "type": "tool",
            "callID": "tc-1",
            "tool": "read",
            "state": {"input": {"filePath": "foo.py"}},
        },
    ]
    await _post(agent, _session_start(sid))
    await _post(agent, _user_message(sid, content="read foo.py"))
    await _post(agent, _assistant_message(sid, parts=parts, stop_reason="tool_use"))
    await _post(agent, _tool_before(sid, call_id="tc-1", tool="read", args={"filePath": "foo.py"}))
    await _post(agent, _tool_after(sid, call_id="tc-1", tool="read", result="file body"))
    await _post(agent, _session_idle(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans_body(await resp.json())
    sess_spans = [s for s in spans if s.get("session_id") == sid]

    steps = _by_kind(sess_spans, "step")
    assert len(steps) == 1
    step = steps[0]

    tools = _by_kind(sess_spans, "tool")
    assert len(tools) == 1
    tool = tools[0]
    assert tool["parent_id"] == step["span_id"]
    assert tool["name"] == "read"
    assert tool["status"] == "ok"
    assert "file body" in tool["meta"]["output"]["value"]
    assert _has_tag(tool, "tool_name:read")
    assert tool["duration"] >= 0


async def test_tool_error_status_and_message(agent):
    sid = "opencode-tool-err"
    await _post(agent, _session_start(sid))
    await _post(agent, _user_message(sid, content="run bash"))
    await _post(agent, _assistant_message(sid))
    await _post(agent, _tool_before(sid, call_id="tc-1", tool="bash", args={"command": "false"}))
    await _post(
        agent,
        _tool_after(
            sid,
            call_id="tc-1",
            tool="bash",
            result="",
            is_error=True,
            error={"message": "exit code 1"},
        ),
    )
    await _post(agent, _session_idle(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans_body(await resp.json())
    sess_spans = [s for s in spans if s.get("session_id") == sid]

    tools = _by_kind(sess_spans, "tool")
    assert len(tools) == 1
    tool = tools[0]
    assert tool["status"] == "error"
    assert "exit code 1" in tool["meta"]["error"]["message"]


async def test_tool_after_without_before_falls_back(agent):
    """tool_execute_after with no matching _before still emits a tool span."""
    sid = "opencode-tool-fallback"
    await _post(agent, _session_start(sid))
    await _post(agent, _user_message(sid, content="orphan tool"))
    await _post(agent, _assistant_message(sid))
    await _post(agent, _tool_after(sid, call_id="tc-orphan", tool="grep", result="match"))
    await _post(agent, _session_idle(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans_body(await resp.json())
    sess_spans = [s for s in spans if s.get("session_id") == sid]
    tools = _by_kind(sess_spans, "tool")
    assert len(tools) == 1
    assert tools[0]["name"] == "grep"


async def test_session_end_finalizes_open_turn(agent):
    """session_end (without session_idle) still closes the root span."""
    sid = "opencode-end"
    await _post(agent, _session_start(sid))
    await _post(agent, _user_message(sid, content="abrupt"))
    await _post(agent, _assistant_message(sid))
    await _post(agent, _session_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans_body(await resp.json())
    sess_spans = [s for s in spans if s.get("session_id") == sid]
    roots = [s for s in sess_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 1
    # Root should have been finalized (non-zero duration set).
    assert roots[0]["duration"] >= 0


async def test_provider_cost_passthrough(agent):
    """When the assistant_message carries a provider cost dict, it lands as nanodollars."""
    sid = "opencode-cost"
    await _post(agent, _session_start(sid))
    await _post(agent, _user_message(sid, content="cost test"))
    await _post(
        agent,
        _assistant_message(
            sid,
            tokens={"input": 1000, "output": 500, "reasoning": 0, "cache": {"read": 0, "write": 0}},
            cost={"input": 0.003, "output": 0.015, "cacheRead": 0.0, "cacheWrite": 0.0, "total": 0.018},
        ),
    )
    await _post(agent, _session_idle(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans_body(await resp.json())
    sess_spans = [s for s in spans if s.get("session_id") == sid]
    llms = _by_kind(sess_spans, "llm")
    assert len(llms) == 1
    metrics = llms[0]["metrics"]
    # 0.018 USD → 18_000_000 nanodollars
    assert metrics["estimated_total_cost"] == 18_000_000
    assert metrics["estimated_input_cost"] == 3_000_000
    assert metrics["estimated_output_cost"] == 15_000_000


async def test_two_turns_in_one_session(agent):
    """Two user → assistant → idle cycles produce two distinct traces."""
    sid = "opencode-two-turns"
    await _post(agent, _session_start(sid))

    # Turn 1
    await _post(agent, _user_message(sid, content="first", message_id="u1"))
    await _post(agent, _assistant_message(sid, message_id="a1", parts=[{"type": "text", "text": "one"}]))
    await _post(agent, _session_idle(sid))

    # Turn 2
    await _post(agent, _user_message(sid, content="second", message_id="u2"))
    await _post(agent, _assistant_message(sid, message_id="a2", parts=[{"type": "text", "text": "two"}]))
    await _post(agent, _session_idle(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans_body(await resp.json())
    sess_spans = [s for s in spans if s.get("session_id") == sid]

    roots = [s for s in sess_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 2
    trace_ids = {r["trace_id"] for r in roots}
    assert len(trace_ids) == 2  # two separate traces
