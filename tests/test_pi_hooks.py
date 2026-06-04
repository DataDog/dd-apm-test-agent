"""Tests for pi coding agent hooks — step span kind emission."""

import json
import subprocess


async def _post(agent, event):
    return await agent.post(
        "/pi/hooks",
        headers={"Content-Type": "application/json"},
        data=json.dumps(event),
    )


def _spans(body):
    """Return spans from /claude/hooks/spans response body."""
    return body["spans"]


def _by_kind(spans, kind):
    return [s for s in spans if s.get("meta", {}).get("span", {}).get("kind") == kind]


def _has_tag(span, tag):
    return tag in span.get("tags", [])


SESSION = "pi-test-sess"


def _session_start(
    session_id=SESSION,
    model_id="claude-sonnet-4-20250514",
    model_provider="anthropic",
    cwd=None,
):
    event = {
        "session_id": session_id,
        "hook_event_name": "session_start",
        "model_id": model_id,
        "model_provider": model_provider,
    }
    if cwd:
        event["cwd"] = cwd
    return event


def _agent_start(
    session_id=SESSION,
    prompt="hello",
    model_id="claude-sonnet-4-20250514",
    model_provider="anthropic",
    cwd=None,
    is_continuation=False,
):
    event = {
        "session_id": session_id,
        "hook_event_name": "agent_start",
        "user_prompt": prompt,
        "model_id": model_id,
        "model_provider": model_provider,
        "is_continuation": is_continuation,
    }
    if cwd:
        event["cwd"] = cwd
    return event


def _agent_end(session_id=SESSION, messages=None):
    return {"session_id": session_id, "hook_event_name": "agent_end", "messages": messages or []}


def _turn_start(session_id=SESSION, turn_index=0):
    return {"session_id": session_id, "hook_event_name": "turn_start", "turn_index": turn_index}


def _turn_end(session_id=SESSION, turn_index=0):
    return {"session_id": session_id, "hook_event_name": "turn_end", "turn_index": turn_index}


def _message_start(session_id=SESSION, system_prompt="", messages=None):
    return {
        "session_id": session_id,
        "hook_event_name": "message_start",
        "message_role": "assistant",
        "system_prompt": system_prompt,
        "messages": messages or [],
    }


def _message_end(
    session_id=SESSION,
    content=None,
    usage=None,
    stop_reason="end_turn",
    model_id="claude-sonnet-4-20250514",
    model_provider="anthropic",
    error_message="",
):
    return {
        "session_id": session_id,
        "hook_event_name": "message_end",
        "message_role": "assistant",
        "model_id": model_id,
        "model_provider": model_provider,
        "content": content if content is not None else [{"type": "text", "text": "Hello!"}],
        "usage": usage or {"input": 100, "output": 50, "cacheRead": 0, "cacheWrite": 0, "totalTokens": 150},
        "stop_reason": stop_reason,
        "error_message": error_message,
    }


def _tool_start(
    session_id=SESSION,
    tool_call_id="tool-1",
    tool_name="read",
    args="{}",
):
    return {
        "session_id": session_id,
        "hook_event_name": "tool_execution_start",
        "tool_call_id": tool_call_id,
        "tool_name": tool_name,
        "args": args,
    }


def _tool_end(
    session_id=SESSION,
    tool_call_id="tool-1",
    tool_name="read",
    result="ok",
    is_error=False,
):
    return {
        "session_id": session_id,
        "hook_event_name": "tool_execution_end",
        "tool_call_id": tool_call_id,
        "tool_name": tool_name,
        "result": result,
        "is_error": is_error,
    }


def _session_shutdown(session_id=SESSION):
    return {"session_id": session_id, "hook_event_name": "session_shutdown"}


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------


async def test_single_step_with_llm_no_tools(agent):
    """One turn_start/turn_end cycle produces: agent → step → llm."""
    sid = "pi-single-step"
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid, turn_index=0))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid, turn_index=0))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    roots = [s for s in session_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 1
    root = roots[0]

    steps = _by_kind(session_spans, "step")
    assert len(steps) == 1
    step = steps[0]

    llms = _by_kind(session_spans, "llm")
    assert len(llms) == 1
    llm = llms[0]

    # Parenting: root → step → llm
    assert step["parent_id"] == root["span_id"]
    assert llm["parent_id"] == step["span_id"]

    # Kinds
    assert root["meta"]["span"]["kind"] == "agent"
    assert step["meta"]["span"]["kind"] == "step"
    assert llm["meta"]["span"]["kind"] == "llm"

    # Step has non-zero duration (covers turn_start → turn_end)
    assert step["duration"] > 0

    # Step name
    assert step["name"] == "inference-0"


async def test_pi_project_metadata_from_extension_cwd(agent, tmp_path, monkeypatch):
    from ddapm_test_agent.coding_agent_metadata import _local_git_metadata

    monkeypatch.delenv("DD_GIT_REPOSITORY_URL", raising=False)
    _local_git_metadata.cache_clear()
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "git@github.com:DataDog/pi-project.git"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    sid = "pi-project-metadata"
    cwd = str(tmp_path)
    await _post(agent, _session_start(sid, cwd=cwd))
    await _post(agent, _agent_start(sid, cwd=cwd))
    await _post(agent, {**_turn_start(sid), "cwd": cwd})
    await _post(agent, {**_message_start(sid), "cwd": cwd})
    await _post(agent, {**_message_end(sid), "cwd": cwd})
    await _post(agent, {**_turn_end(sid), "cwd": cwd})
    await _post(agent, {**_agent_end(sid), "cwd": cwd})

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = next(s for s in spans if s["parent_id"] == "undefined")
    llm = next(s for s in spans if s["meta"]["span"]["kind"] == "llm")

    for span in (root, llm):
        assert "project_name:pi-project" in span["tags"]
        assert "git.repository_url:github.com/DataDog/pi-project" in span["tags"]
        assert not any("commit" in tag for tag in span["tags"])
    assert root["meta"]["metadata"]["project_name"] == "pi-project"
    assert root["meta"]["metadata"]["git_repository_url"] == "github.com/DataDog/pi-project"


async def test_ai_gateway_anthropic_model_id_gets_estimated_cost(agent):
    """AI Gateway-style Anthropic model IDs still get local estimated costs."""
    sid = "pi-ai-gateway-anthropic-cost"
    model_id = "anthropic/claude-opus-4-7"
    usage = {"input": 100, "output": 50, "cacheRead": 20, "cacheWrite": 10, "totalTokens": 180}
    await _post(agent, _session_start(sid, model_id=model_id, model_provider="ai-gateway"))
    await _post(agent, _agent_start(sid, model_id=model_id, model_provider="ai-gateway"))
    await _post(agent, _turn_start(sid, turn_index=0))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid, usage=usage, model_id=model_id, model_provider="ai-gateway"))
    await _post(agent, _turn_end(sid, turn_index=0))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    llm = _by_kind([s for s in spans if s.get("session_id") == sid], "llm")[0]

    metrics = llm["metrics"]
    expected_input = 100 * 5_000 + 10 * 6_250 + 20 * 500
    expected_output = 50 * 25_000
    assert llm["meta"]["model_name"] == model_id
    assert metrics["estimated_non_cached_input_cost"] == 100 * 5_000
    assert metrics["estimated_cache_write_input_cost"] == 10 * 6_250
    assert metrics["estimated_cache_read_input_cost"] == 20 * 500
    assert metrics["estimated_output_cost"] == expected_output
    assert metrics["estimated_total_cost"] == expected_input + expected_output


async def test_ai_gateway_openai_model_id_gets_estimated_cost(agent):
    """AI Gateway-style OpenAI model IDs are priced with the OpenAI cost table."""
    sid = "pi-ai-gateway-openai-cost"
    model_id = "openai/gpt-5.5"
    usage = {"input": 80, "output": 30, "cacheRead": 20, "cacheWrite": 0, "totalTokens": 130}
    await _post(agent, _session_start(sid, model_id=model_id, model_provider="ai-gateway"))
    await _post(agent, _agent_start(sid, model_id=model_id, model_provider="ai-gateway"))
    await _post(agent, _turn_start(sid, turn_index=0))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid, usage=usage, model_id=model_id, model_provider="ai-gateway"))
    await _post(agent, _turn_end(sid, turn_index=0))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    llm = _by_kind([s for s in spans if s.get("session_id") == sid], "llm")[0]

    metrics = llm["metrics"]
    assert llm["meta"]["model_name"] == model_id
    assert metrics["estimated_input_cost"] == 410_000
    assert metrics["estimated_output_cost"] == 900_000
    assert metrics["estimated_total_cost"] == 1_310_000


async def test_provider_reported_cost_is_preferred_over_model_estimate(agent):
    """Use cost sent by pi hooks when present, even if model-based pricing is also known."""
    sid = "pi-provider-cost-preferred"
    model_id = "openai/gpt-5.5"
    usage = {
        "input": 80,
        "output": 30,
        "cacheRead": 20,
        "cacheWrite": 0,
        "totalTokens": 130,
        "cost": {
            "input": 0.000001,
            "output": 0.000002,
            "cacheRead": 0.000003,
            "cacheWrite": 0.000004,
        },
    }
    await _post(agent, _session_start(sid, model_id=model_id, model_provider="ai-gateway"))
    await _post(agent, _agent_start(sid, model_id=model_id, model_provider="ai-gateway"))
    await _post(agent, _turn_start(sid, turn_index=0))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid, usage=usage, model_id=model_id, model_provider="ai-gateway"))
    await _post(agent, _turn_end(sid, turn_index=0))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    llm = _by_kind([s for s in spans if s.get("session_id") == sid], "llm")[0]

    metrics = llm["metrics"]
    assert metrics["estimated_non_cached_input_cost"] == 1_000
    assert metrics["estimated_output_cost"] == 2_000
    assert metrics["estimated_cache_read_input_cost"] == 3_000
    assert metrics["estimated_cache_write_input_cost"] == 4_000
    assert metrics["estimated_total_cost"] == 10_000


async def test_tools_parent_under_step(agent):
    """Tool spans should be children of the step, not the root agent."""
    sid = "pi-tools-step"
    content = [
        {"type": "text", "text": "Let me read that file."},
        {"type": "toolCall", "id": "tc-1", "name": "read", "arguments": {"path": "foo.py"}},
        {"type": "toolCall", "id": "tc-2", "name": "bash", "arguments": {"command": "ls"}},
    ]
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid, turn_index=0))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid, content=content, stop_reason="tool_use"))
    await _post(agent, _tool_start(sid, "tc-1", "read", '{"path": "foo.py"}'))
    await _post(agent, _tool_end(sid, "tc-1", "read", "contents"))
    await _post(agent, _tool_start(sid, "tc-2", "bash", '{"command": "ls"}'))
    await _post(agent, _tool_end(sid, "tc-2", "bash", "file1\nfile2"))
    await _post(agent, _turn_end(sid, turn_index=0))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    steps = _by_kind(session_spans, "step")
    assert len(steps) == 1
    step = steps[0]

    tools = _by_kind(session_spans, "tool")
    assert len(tools) == 2

    # Both tools parent to the step
    for tool in tools:
        assert tool["parent_id"] == step["span_id"]

    # LLM also parents to the step
    llms = _by_kind(session_spans, "llm")
    assert len(llms) == 1
    assert llms[0]["parent_id"] == step["span_id"]

    # Step metadata includes tool_use_ids
    step_meta = step["meta"].get("metadata", {})
    assert "tc-1" in step_meta.get("tool_use_ids", [])
    assert "tc-2" in step_meta.get("tool_use_ids", [])
    assert step_meta.get("stop_reason") == "tool_use"


async def test_multiple_steps(agent):
    """Two turn_start/turn_end cycles produce two sibling step spans."""
    sid = "pi-multi-step"
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))

    # First step: model calls a tool
    content1 = [
        {"type": "text", "text": "Reading file..."},
        {"type": "toolCall", "id": "tc-a", "name": "read", "arguments": {}},
    ]
    await _post(agent, _turn_start(sid, turn_index=0))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid, content=content1, stop_reason="tool_use"))
    await _post(agent, _tool_start(sid, "tc-a", "read"))
    await _post(agent, _tool_end(sid, "tc-a", "read", "file contents"))
    await _post(agent, _turn_end(sid, turn_index=0))

    # Second step: model responds with text only
    content2 = [{"type": "text", "text": "Done!"}]
    await _post(agent, _turn_start(sid, turn_index=1))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid, content=content2, stop_reason="end_turn"))
    await _post(agent, _turn_end(sid, turn_index=1))

    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    root = [s for s in session_spans if s["parent_id"] == "undefined"][0]
    steps = _by_kind(session_spans, "step")
    llms = _by_kind(session_spans, "llm")
    tools = _by_kind(session_spans, "tool")

    assert len(steps) == 2
    assert len(llms) == 2
    assert len(tools) == 1

    # Both steps parent to root
    for step in steps:
        assert step["parent_id"] == root["span_id"]

    # Steps are named sequentially
    step_names = sorted(s["name"] for s in steps)
    assert step_names == ["inference-0", "inference-1"]

    # Each LLM parents to its own step
    llm_parents = {llm["parent_id"] for llm in llms}
    step_ids = {s["span_id"] for s in steps}
    assert llm_parents == step_ids

    # Tool parents to the first step (the one that called it)
    step0 = next(s for s in steps if s["name"] == "inference-0")
    assert tools[0]["parent_id"] == step0["span_id"]


async def test_stale_turn_end_does_not_finalize_next_step(agent):
    """Out-of-order turn_end for the previous turn must not emit an empty step."""
    sid = "pi-stale-turn-end"
    tool_call_id = "tc-a"
    content1 = [
        {"type": "toolCall", "id": tool_call_id, "name": "read", "arguments": {"path": "foo.py"}},
    ]
    content2 = [{"type": "text", "text": "Done!"}]

    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid, turn_index=0))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid, content=content1, stop_reason="toolUse"))
    await _post(agent, _tool_start(sid, tool_call_id, "read"))
    await _post(agent, _tool_end(sid, tool_call_id, "read", "file contents"))

    # Pi can emit the next turn_start before the previous turn_end. The stale
    # turn_end(0) should not close turn 1 before its message_start/message_end.
    await _post(agent, _turn_start(sid, turn_index=1))
    await _post(agent, _turn_end(sid, turn_index=0))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid, content=content2, stop_reason="stop"))
    await _post(agent, _turn_end(sid, turn_index=1))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    root = [s for s in session_spans if s["parent_id"] == "undefined"][0]
    steps = sorted(_by_kind(session_spans, "step"), key=lambda s: s["name"])
    llms = _by_kind(session_spans, "llm")
    tools = _by_kind(session_spans, "tool")

    assert [s["name"] for s in steps] == ["inference-0", "inference-1"]
    assert [s["parent_id"] for s in steps] == [root["span_id"], root["span_id"]]
    assert len(llms) == 2
    assert len(tools) == 1

    step1 = steps[1]
    assert step1["meta"]["output"]["value"] == "Done!"
    assert step1["meta"]["metadata"]["turn_index"] == 1
    assert any(llm["parent_id"] == step1["span_id"] for llm in llms)
    assert all(any(child.get("parent_id") == step["span_id"] for child in session_spans) for step in steps)


async def test_trajectory_tags(agent):
    """Root has trajectory.semantic_type:turn, step has trajectory.semantic_type:agent_message."""
    sid = "pi-tags"
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    root = [s for s in session_spans if s["parent_id"] == "undefined"][0]
    step = _by_kind(session_spans, "step")[0]

    assert _has_tag(root, "trajectory.semantic_type:turn")
    assert _has_tag(step, "trajectory.semantic_type:agent_message")


async def test_list_api_filters_step_kind(agent):
    """The LLMObs list API can filter spans by @meta.span.kind:step."""
    sid = "pi-list-step"
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": f"@meta.span.kind:step session_id:{sid}"}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["hitCount"] == 1
    assert data["result"]["events"][0]["event"]["custom"]["meta"]["span"]["kind"] == "step"


async def test_step_finalized_on_agent_end_without_turn_end(agent):
    """If turn_end is missed, agent_end still finalizes the active step."""
    sid = "pi-no-turn-end"
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid))
    # No turn_end — go straight to agent_end
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    steps = _by_kind(session_spans, "step")
    assert len(steps) == 1
    assert steps[0]["duration"] > 0

    # LLM still parents under step
    llms = _by_kind(session_spans, "llm")
    assert len(llms) == 1
    assert llms[0]["parent_id"] == steps[0]["span_id"]


async def test_message_start_without_turn_start_creates_fallback_step(agent):
    """If message_start arrives without turn_start, a fallback step is created."""
    sid = "pi-no-turn-start"
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    # No turn_start — message_start directly
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    steps = _by_kind(session_spans, "step")
    assert len(steps) == 1

    llms = _by_kind(session_spans, "llm")
    assert len(llms) == 1
    assert llms[0]["parent_id"] == steps[0]["span_id"]


async def test_step_finalized_on_session_shutdown(agent):
    """session_shutdown finalizes any open step."""
    sid = "pi-shutdown"
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid))
    # No turn_end, no agent_end — session_shutdown
    await _post(agent, _session_shutdown(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    steps = _by_kind(session_spans, "step")
    assert len(steps) == 1
    assert steps[0]["duration"] > 0


async def test_step_metadata_fields(agent):
    """Step span metadata includes message_index, output text, and turn_index."""
    sid = "pi-step-meta"
    content = [
        {"type": "text", "text": "I'll help with that."},
        {"type": "toolCall", "id": "tc-x", "name": "edit", "arguments": {"path": "a.py"}},
    ]
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid, turn_index=3))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid, content=content, stop_reason="tool_use"))
    await _post(agent, _turn_end(sid, turn_index=3))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    step = _by_kind(session_spans, "step")[0]
    meta = step["meta"]

    assert meta["output"]["value"] == "I'll help with that."
    md = meta["metadata"]
    assert md["message_index"] == 0
    assert md["turn_index"] == 3
    assert md["tool_use_ids"] == ["tc-x"]
    assert md["stop_reason"] == "tool_use"


async def test_cancelled_turn_no_message(agent):
    """turn_start followed by turn_end with no message is a no-op step."""
    sid = "pi-cancelled-turn"
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    # No message_start/end
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    # Step still emitted (empty) — this is fine
    steps = _by_kind(session_spans, "step")
    assert len(steps) == 1
    # No LLM or tool spans
    assert len(_by_kind(session_spans, "llm")) == 0
    assert len(_by_kind(session_spans, "tool")) == 0


async def test_second_agent_cycle_resets_step_index(agent):
    """Step index resets on each agent_start so the second turn starts at inference-0."""
    sid = "pi-reset-idx"
    await _post(agent, _session_start(sid))

    # First agent cycle — one step
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    # Second agent cycle — step index should reset
    await _post(agent, _agent_start(sid, prompt="second"))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]
    steps = _by_kind(session_spans, "step")

    # Both cycles should have inference-0
    assert len(steps) == 2
    assert all(s["name"] == "inference-0" for s in steps)


async def test_llm_input_messages_include_system_and_user(agent):
    """LLM span input.messages includes the system prompt and user messages."""
    sid = "pi-llm-input"
    system_prompt = "You are a helpful assistant."
    convo = [
        {"role": "user", "content": "What is 2 + 2?"},
    ]

    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid, turn_index=0))
    await _post(agent, _message_start(sid, system_prompt=system_prompt, messages=convo))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid, turn_index=0))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    llms = _by_kind(session_spans, "llm")
    assert len(llms) == 1
    input_messages = llms[0]["meta"]["input"]["messages"]

    assert input_messages[0] == {"role": "system", "content": system_prompt}
    assert input_messages[1] == {"role": "user", "content": "What is 2 + 2?"}


async def test_llm_input_messages_handle_user_content_blocks(agent):
    """User messages with TextContent[] are flattened to a single string."""
    sid = "pi-llm-input-blocks"
    convo = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Look at this:"},
                {"type": "image", "data": "...", "mimeType": "image/png"},
                {"type": "text", "text": "What do you see?"},
            ],
        },
    ]

    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid, system_prompt="sys", messages=convo))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    llm = _by_kind(session_spans, "llm")[0]
    user_msg = llm["meta"]["input"]["messages"][1]
    assert user_msg["role"] == "user"
    assert "Look at this:" in user_msg["content"]
    assert "[image]" in user_msg["content"]
    assert "What do you see?" in user_msg["content"]


async def test_llm_input_messages_include_assistant_and_tool_results(agent):
    """Assistant tool_calls and toolResult messages are mapped to LLMObs format."""
    sid = "pi-llm-input-tools"
    # Second LLM call in a turn — conversation now contains the previous
    # assistant tool call and its toolResult.
    convo = [
        {"role": "user", "content": "read foo.py"},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Reading..."},
                {"type": "toolCall", "id": "tc-1", "name": "read", "arguments": {"path": "foo.py"}},
            ],
        },
        {
            "role": "toolResult",
            "toolCallId": "tc-1",
            "toolName": "read",
            "content": [{"type": "text", "text": "print('hi')"}],
            "isError": False,
        },
    ]

    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid, system_prompt="sys", messages=convo))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    llm = _by_kind(session_spans, "llm")[0]
    msgs = llm["meta"]["input"]["messages"]
    # [system, user, assistant, tool]
    assert [m["role"] for m in msgs] == ["system", "user", "assistant", "tool"]
    assistant_msg = msgs[2]
    assert assistant_msg["content"] == "Reading..."
    assert assistant_msg["tool_calls"] == [
        {
            "name": "read",
            "arguments": {"path": "foo.py"},
            "tool_id": "tc-1",
            "type": "tool_use",
        }
    ]
    tool_msg = msgs[3]
    assert tool_msg == {"role": "tool", "content": "print('hi')", "tool_id": "tc-1"}


async def test_llm_input_messages_omit_system_when_empty(agent):
    """No system message is emitted when system_prompt is empty."""
    sid = "pi-llm-no-sys"
    convo = [{"role": "user", "content": "hi"}]

    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid, system_prompt="", messages=convo))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    llm = _by_kind(session_spans, "llm")[0]
    msgs = llm["meta"]["input"]["messages"]
    assert [m["role"] for m in msgs] == ["user"]


async def test_thinking_block_sets_has_thinking(agent):
    """Content blocks with type 'thinking' set has_thinking on the step."""
    sid = "pi-thinking"
    content = [
        {"type": "thinking", "text": "Let me think..."},
        {"type": "text", "text": "Here's my answer."},
    ]
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid, content=content))
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    session_spans = [s for s in spans if s.get("session_id") == sid]

    step = _by_kind(session_spans, "step")[0]
    assert step["meta"]["metadata"].get("has_thinking") is True
    # Thinking text should NOT appear in output (only text blocks)
    assert step["meta"]["output"]["value"] == "Here's my answer."


async def test_llm_error_emits_error_span(agent):
    """A message_end with stop_reason=error yields an error LLM span + error step."""
    sid = "pi-llm-error"
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    # Errored assistant message: empty content, stop_reason error, errorMessage set.
    await _post(
        agent,
        _message_end(sid, content=[], stop_reason="error", error_message="rate limit exceeded"),
    )
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]

    llms = _by_kind(session_spans, "llm")
    assert len(llms) == 1
    llm = llms[0]
    assert llm["status"] == "error"
    assert llm["meta"]["error"]["message"] == "rate limit exceeded"
    assert llm["meta"]["metadata"]["stop_reason"] == "error"

    # The enclosing step reflects the failure (not silently empty/ok).
    step = _by_kind(session_spans, "step")[0]
    assert step["status"] == "error"
    assert step["meta"]["error"]["message"] == "rate limit exceeded"


async def test_orphaned_llm_call_emits_error_span_on_agent_end(agent):
    """message_start with no message_end (thrown error) still yields an error LLM span."""
    sid = "pi-llm-orphan"
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    # No message_end — the LLM call raised and pi unwound without finalizing.
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]

    llms = _by_kind(session_spans, "llm")
    assert len(llms) == 1, "orphaned pending LLM should still produce a span"
    llm = llms[0]
    assert llm["status"] == "error"
    assert "did not complete" in llm["meta"]["error"]["message"]

    step = _by_kind(session_spans, "step")[0]
    assert step["status"] == "error"


async def test_orphaned_llm_call_emits_error_span_on_session_shutdown(agent):
    """Orphaned pending LLM is flushed as an error span on session_shutdown too."""
    sid = "pi-llm-orphan-shutdown"
    await _post(agent, _session_start(sid))
    await _post(agent, _agent_start(sid))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    await _post(agent, _session_shutdown(sid))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    llms = _by_kind(session_spans, "llm")
    assert len(llms) == 1
    assert llms[0]["status"] == "error"


async def test_continuation_agent_start_extends_trace(agent):
    """A continuation agent_start (no user input) reuses the existing trace."""
    sid = "pi-continuation"
    await _post(agent, _session_start(sid))

    # First (real) user turn.
    await _post(agent, _agent_start(sid, prompt="do the thing"))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root_before = next(s for s in session_spans if s["parent_id"] == "undefined")
    trace_id = root_before["trace_id"]
    root_span_id = root_before["span_id"]

    # Continuation (e.g. after auto-compaction): no fresh user input.
    await _post(agent, _agent_start(sid, prompt="", is_continuation=True))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]

    # Exactly one trace and one root span — the continuation did NOT spawn a new one.
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 1
    root = roots[0]
    assert root["span_id"] == root_span_id
    assert root["trace_id"] == trace_id
    assert all(s["trace_id"] == trace_id for s in session_spans)

    # User input is preserved on the single trace.
    assert root["meta"]["input"]["value"] == "do the thing"
    assert root["meta"]["metadata"].get("missing_user_input") is None

    # Both inference cycles' steps live under the same trace/root.
    steps = _by_kind(session_spans, "step")
    assert len(steps) == 2
    assert all(s["parent_id"] == root_span_id for s in steps)


async def test_second_real_turn_still_rotates_trace(agent):
    """A genuine second user turn (is_continuation=False) still starts a new trace."""
    sid = "pi-two-real-turns"
    await _post(agent, _session_start(sid))

    await _post(agent, _agent_start(sid, prompt="first"))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    first_trace = next(s for s in session_spans if s["parent_id"] == "undefined")["trace_id"]

    await _post(agent, _agent_start(sid, prompt="second"))
    await _post(agent, _turn_start(sid))
    await _post(agent, _message_start(sid))
    await _post(agent, _message_end(sid))
    await _post(agent, _turn_end(sid))
    await _post(agent, _agent_end(sid))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 2
    trace_ids = {r["trace_id"] for r in roots}
    assert len(trace_ids) == 2
    assert first_trace in trace_ids
    inputs = sorted(r["meta"]["input"]["value"] for r in roots)
    assert inputs == ["first", "second"]
