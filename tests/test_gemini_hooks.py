"""Tests for Gemini CLI hook ingestion."""

import json
from pathlib import Path


_FIXTURES_DIR = Path(__file__).parent / "fixtures"


async def _post(agent, event_type, payload):
    return await agent.post(
        f"/gemini/hooks/{event_type}",
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
    )


def _spans(body):
    return body["spans"]


def _by_kind(spans, kind):
    return [s for s in spans if s.get("meta", {}).get("span", {}).get("kind") == kind]


def _load_fixture(name):
    return json.loads((_FIXTURES_DIR / name).read_text())


def _read_tool_semantics(events, before_name, after_name, tool_names):
    before = next(
        event
        for event in events
        if event["hook_event_name"] == before_name and event.get("tool_name") in tool_names
    )
    after = next(
        event
        for event in events
        if event["hook_event_name"] == after_name and event.get("tool_name") in tool_names
    )
    return {
        "phase_before": "pre_tool_use",
        "phase_after": "post_tool_use",
        "tool_family": "read_file",
        "path": before["tool_input"]["file_path"],
        "has_output": bool(after.get("tool_response")),
    }


def _session_start(session_id):
    return {"session_id": session_id, "source": "startup", "cwd": "/tmp/project"}


def _before_agent(session_id, prompt="Explain the repo"):
    return {"session_id": session_id, "prompt": prompt}


def _after_model(
    session_id,
    *,
    model="gemini-2.5-pro",
    output_text="",
    tool_call=None,
    prompt_tokens=150,
    output_tokens=75,
    thought_tokens=25,
    finish_reason="STOP",
):
    parts = []
    if output_text:
        parts.append({"text": output_text})
    if tool_call:
        parts.append({"functionCall": tool_call})
    return {
        "session_id": session_id,
        "llm_request": {
            "model": model,
            "contents": [{"role": "user", "parts": [{"text": "Explain the repo"}]}],
        },
        "llm_response": {
            "candidates": [
                {
                    "finishReason": finish_reason,
                    "content": {"role": "model", "parts": parts},
                }
            ],
            "usageMetadata": {
                "promptTokenCount": prompt_tokens,
                "candidatesTokenCount": output_tokens,
                "thoughtsTokenCount": thought_tokens,
                "cachedContentTokenCount": 10,
            },
        },
    }


def _before_tool(session_id, tool_use_id="tool-1", tool_name="read_file"):
    return {
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_input": {"file_path": "README.md"},
        "mcp_context": {"tool_use_id": tool_use_id},
    }


def _after_tool(session_id, tool_use_id="tool-1", tool_name="read_file", response="contents", error=""):
    body = {
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_response": response,
        "mcp_context": {"tool_use_id": tool_use_id},
    }
    if error:
        body["tool_error"] = error
    return body


def _after_agent(session_id, response="Done"):
    return {"session_id": session_id, "prompt_response": response}


async def test_gemini_full_turn_with_tool(agent):
    sid = "gemini-full-turn"
    await _post(agent, "SessionStart", _session_start(sid))
    await _post(agent, "BeforeAgent", _before_agent(sid))
    await _post(
        agent,
        "AfterModel",
        _after_model(
            sid,
            tool_call={"id": "tool-1", "name": "read_file", "args": {"file_path": "README.md"}},
            finish_reason="TOOL_CALL",
        ),
    )
    await _post(agent, "BeforeTool", _before_tool(sid))
    await _post(
        agent,
        "Notification",
        {"session_id": sid, "notification_type": "tool_permission_requested", "message": "Allow read_file?"},
    )
    await _post(agent, "AfterTool", _after_tool(sid))
    await _post(agent, "AfterAgent", _after_agent(sid, "The repo is a test agent."))

    resp = await agent.get("/gemini/hooks/spans")
    assert resp.status == 200
    spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]

    roots = [s for s in spans if s["parent_id"] == "undefined"]
    steps = _by_kind(spans, "step")
    llms = _by_kind(spans, "llm")
    tools = _by_kind(spans, "tool")

    assert len(roots) == 1
    assert len(steps) == 1
    assert len(llms) == 1
    assert len(tools) == 1

    root = roots[0]
    step = steps[0]
    llm = llms[0]
    tool = tools[0]

    assert root["name"] == "gemini-request"
    assert "source:gemini-hooks" in root["tags"]
    assert "trajectory.semantic_type:turn" in root["tags"]
    assert root["meta"]["input"]["value"] == "Explain the repo"
    assert root["meta"]["output"]["value"] == "The repo is a test agent."
    assert root["meta"]["model_provider"] == "google"

    assert step["parent_id"] == root["span_id"]
    assert llm["parent_id"] == step["span_id"]
    assert tool["parent_id"] == step["span_id"]
    assert step["meta"]["metadata"]["tool_use_ids"] == ["tool-1"]
    assert step["meta"]["metadata"]["has_thinking"] is True

    assert llm["name"] == "gemini-2.5-pro"
    assert llm["meta"]["model_provider"] == "google"
    assert llm["metrics"]["input_tokens"] == 150
    assert llm["metrics"]["output_tokens"] == 75
    assert llm["metrics"]["reasoning_tokens"] == 25
    assert llm["metrics"]["cache_read_input_tokens"] == 10
    assert llm["meta"]["output"]["messages"][0]["tool_calls"][0]["tool_id"] == "tool-1"

    assert tool["name"] == "read_file"
    assert tool["status"] == "ok"
    assert tool["meta"]["metadata"]["tool_id"] == "tool-1"
    assert tool["meta"]["metadata"]["_dd"]["estimated_permission_wait_ms"] >= 0


async def test_gemini_active_turn_keeps_root_duration_zero_for_live_badge(agent, monkeypatch):
    now = {"ns": 1_000_000_000}
    monkeypatch.setattr("ddapm_test_agent.claude_hooks.monotonic_wall_ns", lambda: now["ns"])
    monkeypatch.setattr("ddapm_test_agent.gemini_hooks.monotonic_wall_ns", lambda: now["ns"])

    sid = "gemini-live-root-duration"
    await _post(agent, "SessionStart", _session_start(sid))
    await _post(agent, "BeforeAgent", _before_agent(sid, "Keep the trace live"))

    resp = await agent.get("/gemini/hooks/spans")
    assert resp.status == 200
    spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = [s for s in spans if s["parent_id"] == "undefined"][0]
    assert root["duration"] == 0
    trace_id = root["trace_id"]

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": f"@trace_id:{trace_id} @parent_id:undefined"}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["result"]["events"][0]["event"]["custom"]["duration"] == 0

    resp = await agent.get(f"/api/ui/llm-obs/v1/trace/{trace_id}")
    assert resp.status == 200
    data = await resp.json()
    attrs = data["data"]["attributes"]
    assert attrs["spans"][attrs["root_id"]]["duration"] == 0

    now["ns"] = 5_000_000_000
    await _post(agent, "AfterAgent", _after_agent(sid, "done"))

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": f"@trace_id:{trace_id} @parent_id:undefined"}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["result"]["events"][0]["event"]["custom"]["duration"] == 4_000_000_000


async def test_gemini_same_tick_finalization_exits_live_badge(agent, monkeypatch):
    now = {"ns": 1_000_000_000}
    monkeypatch.setattr("ddapm_test_agent.claude_hooks.monotonic_wall_ns", lambda: now["ns"])
    monkeypatch.setattr("ddapm_test_agent.gemini_hooks.monotonic_wall_ns", lambda: now["ns"])

    sid = "gemini-same-tick-finalized"
    await _post(agent, "SessionStart", _session_start(sid))
    await _post(agent, "BeforeAgent", _before_agent(sid, "finish immediately"))
    await _post(agent, "AfterModel", _after_model(sid, output_text="done"))

    resp = await agent.get("/gemini/hooks/spans")
    assert resp.status == 200
    spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = [s for s in spans if s["parent_id"] == "undefined"][0]
    assert root["duration"] == 0
    trace_id = root["trace_id"]

    await _post(agent, "AfterAgent", _after_agent(sid, "done"))

    resp = await agent.get("/gemini/hooks/spans")
    assert resp.status == 200
    spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = [s for s in spans if s["parent_id"] == "undefined"][0]
    step = _by_kind(spans, "step")[0]
    assert root["duration"] == 1
    assert step["duration"] == 1

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": f"@trace_id:{trace_id} @parent_id:undefined"}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["result"]["events"][0]["event"]["custom"]["duration"] == 1


def test_gemini_real_tool_fixture_matches_current_cli_shape():
    fixture = _load_fixture("gemini_real_tool_session.json")
    events = fixture["events"]

    assert [event["hook_event_name"] for event in events] == [
        "SessionStart",
        "BeforeAgent",
        "PreCompress",
        "AfterModel",
        "AfterModel",
        "AfterModel",
        "AfterModel",
        "AfterModel",
        "BeforeTool",
        "BeforeTool",
        "AfterTool",
        "AfterTool",
        "PreCompress",
        "AfterModel",
        "AfterModel",
        "AfterAgent",
        "SessionEnd",
    ]

    tool_events = [event for event in events if event["hook_event_name"] in ("BeforeTool", "AfterTool")]
    assert [event["tool_name"] for event in tool_events] == [
        "read_file",
        "run_shell_command",
        "read_file",
        "run_shell_command",
    ]
    assert all("tool_use_id" not in event and "mcp_context" not in event for event in tool_events)

    after_model = next(event for event in events if event["hook_event_name"] == "AfterModel")
    assert "messages" in after_model["llm_request"]
    assert isinstance(after_model["llm_response"]["candidates"][0]["content"]["parts"][0], str)


async def test_gemini_real_tool_fixture_pairs_tools_and_matches_claude_read_semantics(agent):
    gemini_fixture = _load_fixture("gemini_real_tool_session.json")
    claude_fixture = _load_fixture("claude_minimal_tool_session.json")
    gemini_events = gemini_fixture["events"]

    for event in gemini_events:
        await _post(agent, event["hook_event_name"], event)

    resp = await agent.get("/gemini/hooks/spans")
    assert resp.status == 200
    spans = [s for s in _spans(await resp.json()) if s.get("session_id") == "gemini-real-tool-session"]

    llms = _by_kind(spans, "llm")
    tools = _by_kind(spans, "tool")
    tools_by_name = {tool["name"]: tool for tool in tools}

    assert {"read_file", "run_shell_command"} <= set(tools_by_name)
    read_tool = tools_by_name["read_file"]
    shell_tool = tools_by_name["run_shell_command"]

    assert "README.md" in read_tool["meta"]["input"]["value"]
    assert "Lapdog Gemini real tool fixture" in read_tool["meta"]["output"]["value"]
    assert "pwd" in shell_tool["meta"]["input"]["value"]
    assert "/private/tmp/lapdog-gemini-real-fixture" in shell_tool["meta"]["output"]["value"]

    assert any(llm["meta"]["input"]["messages"] for llm in llms)
    assert any(
        message.get("content") == "real-fixture-done"
        for llm in llms
        for message in llm["meta"]["output"]["messages"]
    )

    assert _read_tool_semantics(gemini_events, "BeforeTool", "AfterTool", {"read_file"}) == _read_tool_semantics(
        claude_fixture["events"], "PreToolUse", "PostToolUse", {"Read"}
    )


async def test_gemini_multiple_after_model_calls_create_steps(agent):
    sid = "gemini-multi-step"
    await _post(agent, "SessionStart", _session_start(sid))
    await _post(agent, "BeforeAgent", _before_agent(sid))
    await _post(
        agent,
        "AfterModel",
        _after_model(
            sid,
            tool_call={"id": "tool-1", "name": "read_file", "args": {"file_path": "README.md"}},
            finish_reason="TOOL_CALL",
        ),
    )
    await _post(agent, "BeforeTool", _before_tool(sid))
    await _post(agent, "AfterTool", _after_tool(sid))
    await _post(agent, "AfterModel", _after_model(sid, output_text="README contents summarized."))
    await _post(agent, "AfterAgent", _after_agent(sid, "README contents summarized."))

    resp = await agent.get("/gemini/hooks/spans")
    spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]

    root = [s for s in spans if s["parent_id"] == "undefined"][0]
    steps = sorted(_by_kind(spans, "step"), key=lambda s: s["name"])
    llms = _by_kind(spans, "llm")
    tools = _by_kind(spans, "tool")

    assert [s["name"] for s in steps] == ["inference-0", "inference-1"]
    assert all(step["parent_id"] == root["span_id"] for step in steps)
    assert {llm["parent_id"] for llm in llms} == {step["span_id"] for step in steps}
    assert tools[0]["parent_id"] == steps[0]["span_id"]
    assert steps[1]["meta"]["output"]["value"] == "README contents summarized."


async def test_gemini_endpoint_alias_and_raw_events(agent):
    sid = "gemini-alias"
    resp = await agent.post("/capture/gemini/SessionStart", json=_session_start(sid))
    assert resp.status == 200

    raw = await agent.get("/gemini/hooks/raw")
    assert raw.status == 200
    events = (await raw.json())["events"]
    assert any(event["session_id"] == sid and event["hook_event_name"] == "SessionStart" for event in events)


async def test_gemini_rejects_bad_payloads(agent):
    resp = await agent.post("/gemini/hooks/SessionStart", data="{")
    assert resp.status == 400

    resp = await agent.post("/gemini/hooks/SessionStart", json={"source": "startup"})
    assert resp.status == 400

    resp = await agent.post("/gemini/hooks/NoSuchEvent", json={"session_id": "gemini-bad"})
    assert resp.status == 400


async def test_gemini_tool_error_span(agent):
    sid = "gemini-tool-error"
    await _post(agent, "SessionStart", _session_start(sid))
    await _post(agent, "BeforeAgent", _before_agent(sid))
    await _post(agent, "BeforeTool", _before_tool(sid, tool_use_id="bad-tool", tool_name="run_shell_command"))
    await _post(
        agent,
        "AfterTool",
        _after_tool(sid, tool_use_id="bad-tool", tool_name="run_shell_command", response="", error="permission denied"),
    )
    await _post(agent, "AfterAgent", _after_agent(sid, "Could not run it."))

    resp = await agent.get("/gemini/hooks/spans")
    spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    tools = _by_kind(spans, "tool")

    assert len(tools) == 1
    assert tools[0]["status"] == "error"
    assert tools[0]["meta"]["error"]["message"] == "permission denied"
