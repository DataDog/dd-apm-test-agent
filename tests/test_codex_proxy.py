import json

from aiohttp import web

from ddapm_test_agent.codex_proxy import _is_client_disconnect_error


def test_codex_proxy_identifies_closing_transport_as_client_disconnect():
    assert _is_client_disconnect_error(RuntimeError("Cannot write to closing transport"))
    assert not _is_client_disconnect_error(RuntimeError("upstream failed"))


async def _post_codex(agent, session_id, record, proxy_session_key=None):
    body = {"session_id": session_id, "record": record}
    if proxy_session_key:
        body["proxy_session_key"] = proxy_session_key
    return await agent.post(
        "/codex/hooks",
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
    )


def _session_meta(session_id="codex-proxy-sess"):
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


def _responses_request(stream=False, text="hello"):
    return {
        "model": "gpt-5.5",
        "stream": stream,
        "input": [{"role": "user", "content": [{"type": "input_text", "text": text}]}],
    }


def _responses_body(text="hi"):
    return {
        "id": "resp_123",
        "object": "response",
        "status": "completed",
        "model": "gpt-5.5",
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": text}],
            }
        ],
        "usage": {
            "input_tokens": 100,
            "input_tokens_details": {"cached_tokens": 20},
            "output_tokens": 30,
            "output_tokens_details": {"reasoning_tokens": 5},
            "total_tokens": 130,
        },
    }


def _responses_tool_call_body():
    body = _responses_body()
    body["output"] = [
        {
            "type": "function_call",
            "id": "fc_123",
            "call_id": "call-1",
            "name": "exec_command",
            "arguments": '{"cmd": "pwd"}',
        }
    ]
    return body


def _empty_response_body():
    return {
        "id": "resp_empty",
        "object": "response",
        "status": "completed",
        "output": [],
        "usage": {},
    }


async def _spans(agent, session_id=None):
    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    spans = (await resp.json())["spans"]
    if session_id is None:
        return spans
    return [span for span in spans if span.get("session_id") == session_id]


def _by_kind(spans, kind):
    return [span for span in spans if span.get("meta", {}).get("span", {}).get("kind") == kind]


async def test_codex_proxy_non_streaming_forwards_and_creates_orphan_span(agent, aiohttp_server):
    seen = {}

    async def handle(request):
        seen["path"] = request.path
        seen["authorization"] = request.headers.get("Authorization")
        seen["body"] = await request.json()
        return web.json_response(_responses_body())

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    resp = await agent.post(
        "/codex/proxy/v1/responses",
        headers={
            "Authorization": "Bearer test-key",
            "X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/"),
        },
        json=_responses_request(),
    )

    assert resp.status == 200
    assert await resp.json() == _responses_body()
    assert seen["path"] == "/v1/responses"
    assert seen["authorization"] == "Bearer test-key"
    assert seen["body"]["input"][0]["content"][0]["text"] == "hello"

    llms = _by_kind(await _spans(agent), "llm")
    assert len(llms) == 1
    llm = llms[0]
    assert llm["parent_id"] == "undefined"
    assert "source:codex-proxy" in llm["tags"]
    assert llm["meta"]["input"]["messages"] == [{"role": "user", "content": "hello"}]
    assert llm["meta"]["output"]["messages"] == [{"role": "assistant", "content": "hi"}]
    assert llm["metrics"]["input_tokens"] == 100
    assert llm["metrics"]["cache_read_input_tokens"] == 20
    assert llm["metrics"]["reasoning_output_tokens"] == 5


async def test_codex_proxy_streaming_reconstructs_response(agent, aiohttp_server):
    async def handle(request):
        response = web.StreamResponse(status=200, headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        completed = _responses_body(text="streamed")
        await response.write(
            (
                "event: response.completed\n"
                f"data: {json.dumps({'type': 'response.completed', 'response': completed})}\n\n"
            ).encode()
        )
        await response.write_eof()
        return response

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    resp = await agent.post(
        "/codex/proxy/v1/responses",
        headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
        json=_responses_request(stream=True),
    )

    assert resp.status == 200
    assert "response.completed" in await resp.text()
    llms = _by_kind(await _spans(agent), "llm")
    assert len(llms) == 1
    assert llms[0]["meta"]["output"]["messages"] == [{"role": "assistant", "content": "streamed"}]
    assert llms[0]["metrics"]["total_tokens"] == 130


async def test_codex_proxy_does_not_create_empty_codex_model_span(agent, aiohttp_server):
    async def handle(request):
        return web.json_response(_empty_response_body())

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    resp = await agent.post(
        "/codex/proxy/v1/responses",
        headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
        json={"input": "hello"},
    )

    assert resp.status == 200
    assert await resp.json() == _empty_response_body()
    llms = _by_kind(await _spans(agent), "llm")
    assert llms == []


async def test_codex_proxy_span_parents_to_jsonl_turn_and_dedupes_token_count(agent, aiohttp_server):
    sid = "codex-proxy-hybrid"
    await _post_codex(agent, sid, _session_meta(sid))
    await _post_codex(agent, sid, _turn_context())
    await _post_codex(agent, sid, _event("user_message", message="hello"))

    async def handle(request):
        return web.json_response(_responses_body())

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    resp = await agent.post(
        "/codex/proxy/v1/responses",
        headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
        json=_responses_request(),
    )
    assert resp.status == 200

    await _post_codex(
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

    spans = await _spans(agent, sid)
    roots = [span for span in spans if span["parent_id"] == "undefined"]
    steps = _by_kind(spans, "step")
    llms = _by_kind(spans, "llm")
    assert len(roots) == 1
    assert len(steps) == 1
    assert len(llms) == 1
    assert llms[0]["parent_id"] == steps[0]["span_id"]
    assert steps[0]["parent_id"] == roots[0]["span_id"]
    assert "source:codex-proxy" in llms[0]["tags"]


async def test_codex_proxy_late_jsonl_tool_call_stays_in_llm_step(agent, aiohttp_server):
    sid = "codex-proxy-tool-step"
    await _post_codex(agent, sid, _session_meta(sid))
    await _post_codex(agent, sid, _turn_context())
    await _post_codex(agent, sid, _event("user_message", message="run pwd"))

    async def handle(request):
        return web.json_response(_responses_tool_call_body())

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    resp = await agent.post(
        "/codex/proxy/v1/responses",
        headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
        json=_responses_request(),
    )
    assert resp.status == 200
    await _post_codex(
        agent,
        sid,
        {
            "timestamp": "2026-05-13T17:00:04.000Z",
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "exec_command",
                "call_id": "call-1",
                "arguments": '{"cmd": "pwd"}',
            },
        },
    )
    await _post_codex(
        agent,
        sid,
        {
            "timestamp": "2026-05-13T17:00:05.000Z",
            "type": "response_item",
            "payload": {"type": "function_call_output", "call_id": "call-1", "output": "/repo"},
        },
    )

    spans = await _spans(agent, sid)
    steps = _by_kind(spans, "step")
    llms = _by_kind(spans, "llm")
    tools = _by_kind(spans, "tool")

    assert len(steps) == 1
    assert len(llms) == 1
    assert len(tools) == 1
    assert llms[0]["parent_id"] == steps[0]["span_id"]
    assert tools[0]["parent_id"] == steps[0]["span_id"]
    assert llms[0]["meta"]["output"]["messages"] == [
        {
            "role": "assistant",
            "content": '{"cmd": "pwd"}',
            "tool_calls": [{"id": "call-1", "name": "exec_command", "arguments": {"cmd": "pwd"}}],
        }
    ]


async def test_codex_proxy_orphan_is_reparented_when_turn_arrives(agent, aiohttp_server):
    sid = "codex-proxy-orphan"

    async def handle(request):
        return web.json_response(_responses_body())

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    resp = await agent.post(
        "/codex/proxy/v1/responses",
        headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
        json=_responses_request(),
    )
    assert resp.status == 200

    await _post_codex(agent, sid, _session_meta(sid))
    await _post_codex(agent, sid, _turn_context())

    spans = await _spans(agent, sid)
    steps = _by_kind(spans, "step")
    llms = _by_kind(spans, "llm")
    assert len(steps) == 1
    assert len(llms) == 1
    assert llms[0]["parent_id"] == steps[0]["span_id"]


async def test_codex_proxy_session_key_routes_to_matching_active_session(agent, aiohttp_server):
    sid_a = "codex-proxy-a"
    sid_b = "codex-proxy-b"
    await _post_codex(agent, sid_a, _session_meta(sid_a), proxy_session_key="proxy-a")
    await _post_codex(agent, sid_a, _turn_context("turn-a"), proxy_session_key="proxy-a")
    await _post_codex(agent, sid_a, _event("user_message", message="prompt a"), proxy_session_key="proxy-a")
    await _post_codex(agent, sid_b, _session_meta(sid_b), proxy_session_key="proxy-b")
    await _post_codex(agent, sid_b, _turn_context("turn-b"), proxy_session_key="proxy-b")
    await _post_codex(agent, sid_b, _event("user_message", message="prompt b"), proxy_session_key="proxy-b")

    async def handle(request):
        return web.json_response(_responses_body(text="answer a"))

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    resp = await agent.post(
        "/codex/proxy/proxy-a/v1/responses",
        headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
        json=_responses_request(text="prompt a"),
    )
    assert resp.status == 200

    spans_a = await _spans(agent, sid_a)
    spans_b = await _spans(agent, sid_b)
    llms_a = _by_kind(spans_a, "llm")
    llms_b = _by_kind(spans_b, "llm")
    assert len(llms_a) == 1
    assert llms_b == []
    assert llms_a[0]["meta"]["input"]["messages"] == [{"role": "user", "content": "prompt a"}]


async def test_codex_proxy_keyed_orphan_waits_for_matching_session(agent, aiohttp_server):
    async def handle(request):
        return web.json_response(_responses_body(text="keyed orphan"))

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    resp = await agent.post(
        "/codex/proxy/proxy-a/v1/responses",
        headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
        json=_responses_request(text="prompt a"),
    )
    assert resp.status == 200

    sid_b = "codex-proxy-unrelated"
    await _post_codex(agent, sid_b, _session_meta(sid_b), proxy_session_key="proxy-b")
    await _post_codex(agent, sid_b, _turn_context("turn-b"), proxy_session_key="proxy-b")
    assert _by_kind(await _spans(agent, sid_b), "llm") == []

    sid_a = "codex-proxy-matching"
    await _post_codex(agent, sid_a, _session_meta(sid_a), proxy_session_key="proxy-a")
    await _post_codex(agent, sid_a, _turn_context("turn-a"), proxy_session_key="proxy-a")

    llms_a = _by_kind(await _spans(agent, sid_a), "llm")
    assert len(llms_a) == 1
    assert llms_a[0]["parent_id"] != "undefined"
