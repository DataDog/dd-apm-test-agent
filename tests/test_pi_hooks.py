import json


async def _post_pi_hook(agent, event):
    return await agent.post(
        "/pi/hooks",
        headers={"Content-Type": "application/json"},
        data=json.dumps(event),
    )


async def test_pi_hook_endpoint_returns_ok(agent):
    resp = await _post_pi_hook(
        agent,
        {
            "session_id": "pi-sess-1",
            "hook_event_name": "session_start",
            "model_id": "gpt-4.1",
            "model_provider": "openai",
        },
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["status"] == "ok"


async def test_pi_hook_missing_session_id(agent):
    resp = await _post_pi_hook(agent, {"hook_event_name": "session_start"})
    assert resp.status == 400
    body = await resp.json()
    assert "session_id" in body["error"]


async def test_pi_llm_span_gets_context_breakdown_and_root_gets_context_delta(agent):
    session_id = "pi-context-single-turn"

    await _post_pi_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "session_start",
            "model_id": "gpt-4.1",
            "model_provider": "openai",
        },
    )
    await _post_pi_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "agent_start",
            "user_prompt": "Summarize this project",
            "model_id": "gpt-4.1",
            "model_provider": "openai",
        },
    )
    await _post_pi_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "provider_request_context",
            "model_id": "gpt-4.1",
            "model_provider": "openai",
            "context_window_size": 128000,
            "estimated_input_tokens": 700,
            "sections": [
                {"name": "system", "bytes": 100},
                {"name": "tools", "bytes": 200},
                {"name": "user_messages", "bytes": 400},
                {"name": "other", "bytes": 300},
            ],
        },
    )
    await _post_pi_hook(agent, {"session_id": session_id, "hook_event_name": "message_start"})
    await _post_pi_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "message_end",
            "model_id": "gpt-4.1",
            "model_provider": "openai",
            "usage": {
                "input": 500,
                "output": 80,
                "cacheRead": 100,
                "cacheWrite": 20,
                "totalTokens": 700,
            },
            "output_text": "Here is the summary.",
        },
    )
    await _post_pi_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "agent_end",
            "output": "Here is the summary.",
            "model_provider": "openai",
        },
    )

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    body = await resp.json()
    spans = [span for span in body["spans"] if span.get("session_id") == session_id]

    llm_spans = [span for span in spans if span["meta"]["span"]["kind"] == "llm"]
    assert len(llm_spans) == 1
    llm_span = llm_spans[0]
    context_breakdown = llm_span["meta"]["metadata"]["_dd"]["context_breakdown"]
    assert context_breakdown["context_window_size"] == 128000
    assert context_breakdown["total_input_tokens"] == 620
    assert context_breakdown["model_name"] == "gpt-4.1"
    assert [section["name"] for section in context_breakdown["sections"]] == ["system", "tools", "user_messages", "other"]
    other_section = next(section for section in context_breakdown["sections"] if section["name"] == "other")
    assert other_section["tokens"] > 0

    root_spans = [span for span in spans if span["meta"]["span"]["kind"] == "agent"]
    assert len(root_spans) == 1
    root_span = root_spans[0]
    assert root_span["meta"]["model_provider"] == "openai"
    context_delta = root_span["meta"]["metadata"]["_dd"]["context_delta"]
    assert context_delta["first_input_tokens"] == 0
    assert context_delta["last_input_tokens"] == 620
    assert context_delta["delta_tokens"] == 620
    assert context_delta["context_window_size"] == 128000
    assert context_delta["last_sections"] == context_breakdown["sections"]


async def test_pi_context_delta_persists_across_turns(agent):
    session_id = "pi-context-two-turns"

    await _post_pi_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "session_start",
            "model_id": "gpt-4.1",
            "model_provider": "openai",
        },
    )

    async def run_turn(input_tokens, output_text):
        await _post_pi_hook(
            agent,
            {
                "session_id": session_id,
                "hook_event_name": "agent_start",
                "user_prompt": "continue",
                "model_id": "gpt-4.1",
                "model_provider": "openai",
            },
        )
        await _post_pi_hook(
            agent,
            {
                "session_id": session_id,
                "hook_event_name": "provider_request_context",
                "model_id": "gpt-4.1",
                "model_provider": "openai",
                "context_window_size": 128000,
                "estimated_input_tokens": input_tokens,
                "sections": [
                    {"name": "system", "bytes": 100},
                    {"name": "user_messages", "bytes": 300},
                    {"name": "assistant_messages", "bytes": 200},
                ],
            },
        )
        await _post_pi_hook(agent, {"session_id": session_id, "hook_event_name": "message_start"})
        await _post_pi_hook(
            agent,
            {
                "session_id": session_id,
                "hook_event_name": "message_end",
                "model_id": "gpt-4.1",
                "model_provider": "openai",
                "usage": {
                    "input": input_tokens,
                    "output": 50,
                    "cacheRead": 0,
                    "cacheWrite": 0,
                    "totalTokens": input_tokens + 50,
                },
                "output_text": output_text,
            },
        )
        await _post_pi_hook(
            agent,
            {
                "session_id": session_id,
                "hook_event_name": "agent_end",
                "output": output_text,
                "model_provider": "openai",
            },
        )

    await run_turn(620, "turn one")
    await run_turn(900, "turn two")

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    body = await resp.json()
    root_spans = [
        span
        for span in body["spans"]
        if span.get("session_id") == session_id and span["meta"]["span"]["kind"] == "agent"
    ]
    assert len(root_spans) == 2

    root_spans.sort(key=lambda span: span["start_ns"])
    first_delta = root_spans[0]["meta"]["metadata"]["_dd"]["context_delta"]
    second_delta = root_spans[1]["meta"]["metadata"]["_dd"]["context_delta"]

    assert first_delta["first_input_tokens"] == 0
    assert first_delta["last_input_tokens"] == 620
    assert first_delta["delta_tokens"] == 620

    assert second_delta["first_input_tokens"] == 620
    assert second_delta["last_input_tokens"] == 900
    assert second_delta["delta_tokens"] == 280


async def test_pi_compaction_metadata_is_preserved(agent):
    session_id = "pi-compaction"

    await _post_pi_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "session_start",
            "model_id": "gpt-4.1",
            "model_provider": "openai",
        },
    )
    await _post_pi_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "agent_start",
            "user_prompt": "compact now",
            "model_id": "gpt-4.1",
            "model_provider": "openai",
        },
    )
    await _post_pi_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "session_compact",
            "from_extension": True,
        },
    )
    await _post_pi_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "agent_end",
            "output": "done",
            "model_provider": "openai",
        },
    )

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    body = await resp.json()
    root_span = next(
        span
        for span in body["spans"]
        if span.get("session_id") == session_id and span["meta"]["span"]["kind"] == "agent"
    )
    compactions = root_span["meta"]["metadata"]["_dd"]["compactions"]
    assert compactions == [{"trigger": "auto"}]
