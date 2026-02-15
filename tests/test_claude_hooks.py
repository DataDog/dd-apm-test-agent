import json
import os
import tempfile


async def _post_hook(agent, event):
    return await agent.post(
        "/claude/hooks",
        headers={"Content-Type": "application/json"},
        data=json.dumps(event),
    )


async def test_hook_endpoint_returns_ok(agent):
    resp = await _post_hook(
        agent,
        {
            "session_id": "sess-1",
            "hook_event_name": "Notification",
            "message": "hello",
        },
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["status"] == "ok"


async def test_hook_missing_session_id(agent):
    resp = await _post_hook(agent, {"hook_event_name": "Notification"})
    assert resp.status == 400
    body = await resp.json()
    assert "session_id" in body["error"]


async def test_hook_session_creates_agent_span(agent):
    session_id = "sess-agent-span"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    body = await resp.json()
    spans = body["spans"]

    root_spans = [s for s in spans if s["parent_id"] == "undefined"]
    assert len(root_spans) == 1

    root = root_spans[0]
    assert root["name"] == "claude-code-request"
    assert root["meta"]["span"]["kind"] == "agent"
    assert root["duration"] >= 0
    assert root["trace_id"]

    # Verify span appears in LLMObs query API
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"limit": 100, "search": {"query": ""}}},
    )
    assert resp.status == 200
    data = await resp.json()
    events = data["result"]["events"]
    trace_ids = {e["event"]["trace_id"] for e in events}
    assert root["trace_id"] in trace_ids


async def test_hook_tool_use_creates_tool_span(agent):
    session_id = "sess-tool-span"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-1",
            "tool_input": {"command": "ls"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-1",
            "tool_response": "file1.txt\nfile2.txt",
        },
    )
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    body = await resp.json()
    spans = body["spans"]

    tool_spans = [s for s in spans if s["meta"]["span"]["kind"] == "tool"]
    assert len(tool_spans) == 1

    tool = tool_spans[0]
    assert tool["name"] == "Bash"
    assert tool["duration"] >= 0
    assert "ls" in tool["meta"]["input"]["value"]
    assert "file1.txt" in tool["meta"]["output"]["value"]

    # Root agent span output comes from transcript (no transcript in tests, so empty)
    root_spans = [s for s in spans if s["parent_id"] == "undefined"]
    assert len(root_spans) == 1


async def test_hook_subagent_creates_nested_agent(agent):
    session_id = "sess-subagent"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})

    # Start a subagent
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "SubagentStart",
            "agent_type": "explore-agent",
        },
    )

    # Tool use inside subagent
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "tool-sub-1",
            "tool_input": {"file_path": "/foo/bar.py"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_use_id": "tool-sub-1",
            "tool_response": "contents",
        },
    )

    # Stop subagent
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SubagentStop"})

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    body = await resp.json()
    spans = body["spans"]

    # Should have: tool (Read), agent (explore-agent), root agent
    tool_spans = [s for s in spans if s["meta"]["span"]["kind"] == "tool"]
    agent_spans = [s for s in spans if s["meta"]["span"]["kind"] == "agent"]

    assert len(tool_spans) == 1
    assert len(agent_spans) == 2  # subagent + root

    tool = tool_spans[0]
    subagent = [s for s in agent_spans if s["name"] == "explore-agent"][0]
    root = [s for s in agent_spans if s["parent_id"] == "undefined"][0]

    # Tool's parent should be the subagent, not the root
    assert tool["parent_id"] == subagent["span_id"]
    # Subagent's parent should be the root
    assert subagent["parent_id"] == root["span_id"]


async def test_hook_trace_endpoint(agent):
    session_id = "sess-trace-ep"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Grep",
            "tool_use_id": "tool-t-1",
            "tool_input": {},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Grep",
            "tool_use_id": "tool-t-1",
            "tool_response": "match",
        },
    )
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    # Get sessions to find the trace_id
    resp = await agent.get("/claude/hooks/sessions")
    body = await resp.json()
    session_info = [s for s in body["sessions"] if s["session_id"] == session_id][0]
    trace_id = session_info["trace_id"]

    # Query the trace endpoint
    resp = await agent.get(f"/api/ui/llm-obs/v1/trace/{trace_id}")
    assert resp.status == 200
    data = await resp.json()

    assert "data" in data
    attrs = data["data"]["attributes"]
    assert attrs["root_id"] is not None
    assert len(attrs["spans"]) >= 2  # root + tool


async def test_hook_user_prompt_annotates_session(agent):
    session_id = "sess-prompt"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "UserPromptSubmit",
            "user_prompt": "Fix the bug in auth.py",
        },
    )
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    body = await resp.json()
    spans = body["spans"]

    root_spans = [s for s in spans if s["parent_id"] == "undefined"]
    assert len(root_spans) == 1

    root = root_spans[0]
    assert "Fix the bug in auth.py" in root["meta"]["input"]["value"]


async def test_hook_agent_manifest(agent):
    session_id = "sess-manifest"

    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "SessionStart",
            "model": "claude-sonnet-4-5-20250929",
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-m-1",
            "tool_input": {"command": "echo hi"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-m-1",
            "tool_response": "hi",
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "tool-m-2",
            "tool_input": {"file_path": "/tmp/x"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_use_id": "tool-m-2",
            "tool_response": "contents",
        },
    )
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    body = await resp.json()
    spans = body["spans"]

    root = [s for s in spans if s["parent_id"] == "undefined"][0]
    manifest = root["meta"]["metadata"]["agent_manifest"]

    assert manifest["name"] == "claude-code"
    assert manifest["model"] == "claude-sonnet-4-5-20250929"
    assert manifest["model_provider"] == "anthropic"

    tool_names = [t["name"] for t in manifest["tools"]]
    assert "Bash" in tool_names
    assert "Read" in tool_names

    assert root["meta"]["model_name"] == "claude-sonnet-4-5-20250929"
    assert root["meta"]["model_provider"] == "anthropic"


async def test_hook_console_output_on_agent_span(agent):
    session_id = "sess-console"

    # Create a fake transcript with a previous turn and a current turn
    transcript = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    try:
        # Previous turn (should NOT appear in output)
        transcript.write(
            json.dumps({"type": "user", "message": {"content": [{"type": "text", "text": "hello"}]}}) + "\n"
        )
        transcript.write(
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [{"type": "text", "text": "Hi there! How can I help?"}],
                    },
                }
            )
            + "\n"
        )
        # Tool result (type=user but NOT a prompt — should not reset the boundary)
        transcript.write(
            json.dumps(
                {
                    "type": "user",
                    "message": {
                        "content": [{"type": "tool_result", "tool_use_id": "x", "content": "ok"}],
                    },
                }
            )
            + "\n"
        )
        # Current turn — last user prompt
        transcript.write(
            json.dumps({"type": "user", "message": {"content": [{"type": "text", "text": "fix the bug"}]}}) + "\n"
        )
        transcript.write(
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "text", "text": "Let me read that file for you."},
                            {"type": "tool_use", "name": "Read", "input": {}},
                        ],
                    },
                }
            )
            + "\n"
        )
        transcript.write(
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [{"type": "text", "text": "Done! The bug is fixed."}],
                    },
                }
            )
            + "\n"
        )
        transcript.flush()
        transcript_path = transcript.name
        transcript.close()

        await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
        await _post_hook(
            agent, {"session_id": session_id, "hook_event_name": "Stop", "transcript_path": transcript_path}
        )

        resp = await agent.get("/claude/hooks/spans")
        body = await resp.json()
        spans = body["spans"]

        root = [s for s in spans if s["parent_id"] == "undefined" and s["trace_id"]][0]
        output = root["meta"]["output"]["value"]

        # Only output after the last prompt should appear
        assert "Let me read that file for you." in output
        assert "Done! The bug is fixed." in output
        # Previous turn's output should NOT appear
        assert "Hi there! How can I help?" not in output
    finally:
        os.unlink(transcript_path)


async def test_hook_sessions_endpoint(agent):
    session_id = "sess-list-test"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})

    resp = await agent.get("/claude/hooks/sessions")
    assert resp.status == 200
    body = await resp.json()
    session_ids = [s["session_id"] for s in body["sessions"]]
    assert session_id in session_ids
