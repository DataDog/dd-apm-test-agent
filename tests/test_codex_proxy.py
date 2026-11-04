import asyncio
import json

from aiohttp import web
import pytest

from lapdog import codex_proxy as codex_proxy_module
from lapdog.codex_proxy import _is_client_disconnect_error


@pytest.fixture
def agent(lapdog_agent):
    return lapdog_agent


@pytest.fixture
def dd_api_key():
    return ""


@pytest.fixture(autouse=True)
def allow_codex_upstream_override(monkeypatch):
    monkeypatch.setenv("DD_CODEX_ALLOW_UPSTREAM_OVERRIDE", "1")


def test_codex_proxy_identifies_closing_transport_as_client_disconnect():
    assert _is_client_disconnect_error(RuntimeError("Cannot write to closing transport"))
    assert not _is_client_disconnect_error(RuntimeError("upstream failed"))


async def test_codex_proxy_stream_disconnect_stops_upstream_and_skips_span(monkeypatch):
    class FakeConfig:
        ml_app = "codex"
        service = "codex"
        env = "local"
        hostname = "host"
        user_handle = ""

    class FakeHooks:
        _config = FakeConfig()

        def __init__(self):
            self.registered = []

        def register_proxy_llm_span(self, maybe_session_id, span, start_ns, end_ns):
            self.registered.append((maybe_session_id, span, start_ns, end_ns))

    class FakeContent:
        def __init__(self):
            self.iterations = 0

        async def iter_any(self):
            for chunk in [b"data: one\n\n", b"data: two\n\n"]:
                self.iterations += 1
                yield chunk

    class FakeUpstreamResponse:
        status = 200
        headers = {}

        def __init__(self):
            self.content = FakeContent()
            self.closed = False

        def close(self):
            self.closed = True

    class FakeStreamResponse:
        def __init__(self, status):
            self.status = status
            self.headers = {}

        async def prepare(self, request):
            return None

        async def write(self, chunk):
            raise RuntimeError("Cannot write to closing transport")

        async def write_eof(self):
            raise AssertionError("write_eof should not be called after disconnect")

    hooks = FakeHooks()
    proxy = codex_proxy_module.CodexProxyAPI(hooks)
    upstream_resp = FakeUpstreamResponse()
    monkeypatch.setattr(codex_proxy_module.web, "StreamResponse", FakeStreamResponse)

    await proxy._handle_streaming(object(), upstream_resp, _responses_request(stream=True), "proxy-key", 1)

    assert upstream_resp.closed is True
    assert upstream_resp.content.iterations == 1
    assert hooks.registered == []


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


def _response_item(item_type, timestamp="2026-05-11T17:00:03.000Z", **kwargs):
    return {
        "timestamp": timestamp,
        "type": "response_item",
        "payload": {
            "type": item_type,
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


async def test_codex_subagent_spawn_parents_to_active_step(agent):
    sid = "codex-subagent-parent-step"

    await _post_codex(agent, sid, _session_meta(sid))
    await _post_codex(agent, sid, _turn_context())
    await _post_codex(agent, sid, _event("user_message", message="delegate"))
    await _post_codex(
        agent,
        sid,
        _event(
            "collab_agent_spawn_begin",
            timestamp="2026-05-11T17:00:02.500Z",
            call_id="spawn-1",
            sender_thread_id=sid,
            prompt="inspect the repo",
            new_agent_nickname="worker",
        ),
    )

    spans = await _spans(agent, sid)
    roots = [span for span in spans if span["parent_id"] == "undefined"]
    steps = _by_kind(spans, "step")
    subagents = [
        span
        for span in _by_kind(spans, "agent")
        if span["parent_id"] != "undefined" and span["meta"].get("metadata", {}).get("subagent", {})
    ]

    assert len(roots) == 1
    assert len(steps) == 1
    assert len(subagents) == 1
    assert steps[0]["parent_id"] == roots[0]["span_id"]
    assert subagents[0]["name"] == "worker"
    assert subagents[0]["parent_id"] == steps[0]["span_id"]


@pytest.mark.parametrize("call_type", ["function_call", "custom_tool_call"])
def test_codex_proxy_caps_messages_and_links_reasoning_to_tool_calls(monkeypatch, call_type):
    monkeypatch.setattr("lapdog.codex_hooks.MAX_LLM_MESSAGE_CHARS", 8192)

    class FakeConfig:
        ml_app = "codex"
        service = "codex"
        env = "local"
        hostname = "host"

    class FakeHooks:
        _config = FakeConfig()

    proxy = codex_proxy_module.CodexProxyAPI(FakeHooks())
    large_value = "x" * 9000
    response_body = _responses_body()
    response_body["output"] = [
        {
            "type": "reasoning",
            "id": "rs_1",
            "status": "completed",
            "summary": [{"type": "summary_text", "text": "Need to inspect files"}],
        },
        {
            "type": call_type,
            "call_id": "call-1",
            "name": "exec_command",
            "input" if call_type == "custom_tool_call" else "arguments": json.dumps({"cmd": large_value}),
            "status": "in_progress",
        },
    ]
    request_body = {
        "model": "gpt-5.5",
        "input": [
            {
                "type": f"{call_type}_output",
                "call_id": "call-0",
                "output": large_value,
            }
        ],
    }

    span = proxy._create_llm_span(request_body, response_body, start_ns=1, duration_ns=2)

    assert span is not None
    input_message = span["meta"]["input"]["messages"][0]
    tool_call = span["meta"]["output"]["messages"][0]["tool_calls"][0]
    assert "[truncated " in input_message["content"]
    assert input_message["role"] == "tool"
    assert input_message["tool_call_id"] == "call-0"
    assert "[truncated " in tool_call["arguments"]
    assert tool_call["status"] == "in_progress"
    assert tool_call["reasoning"][0]["text"] == "Need to inspect files"


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

    assert _by_kind(await _spans(agent), "llm") == []
    llms = (await (await agent.get("/codex/hooks/raw-proxy")).json())["spans"]
    assert len(llms) == 1
    llm = llms[0]
    assert llm["parent_id"] == "undefined"
    assert "source:codex-proxy" in llm["tags"]
    assert llm["meta"]["input"]["messages"] == [{"role": "user", "content": "hello"}]
    assert llm["meta"]["output"]["messages"] == [{"role": "assistant", "content": "hi"}]
    assert llm["metrics"]["input_tokens"] == 100
    assert llm["metrics"]["cache_read_input_tokens"] == 20
    assert llm["metrics"]["reasoning_output_tokens"] == 5


async def test_codex_proxy_forwards_guardian_review_without_llm_span(agent, aiohttp_server):
    async def handle(request):
        return web.json_response(_responses_body())

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)
    request_body = _responses_request()
    request_body["input"][0]["content"][0][
        "text"
    ] = "Reviewed Codex session id: parent\nAPPROVAL REQUEST START\nPlanned action JSON: {}"
    resp = await agent.post(
        "/codex/proxy/v1/responses",
        headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
        json=request_body,
    )
    assert resp.status == 200
    assert await resp.json() == _responses_body()
    assert _by_kind(await _spans(agent), "llm") == []


async def test_codex_proxy_rejects_upstream_override_when_disabled(agent, aiohttp_server, monkeypatch):
    monkeypatch.delenv("DD_CODEX_ALLOW_UPSTREAM_OVERRIDE", raising=False)

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

    assert resp.status == 403


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
    assert _by_kind(await _spans(agent), "llm") == []
    llms = (await (await agent.get("/codex/hooks/raw-proxy")).json())["spans"]
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


@pytest.mark.parametrize("stream", [False, True])
async def test_custom_tool_only_proxy_response_survives_auxiliary_title_request(agent, aiohttp_server, stream):
    sid = "codex-custom-and-title"
    await _post_codex(agent, sid, _session_meta(sid))
    await _post_codex(agent, sid, _turn_context())
    await _post_codex(agent, sid, _event("user_message", message="inspect files"))
    script = 'await tools.exec_command({cmd:"pwd"});'

    async def handle(request):
        body = await request.json()
        result = _responses_body()
        if body["input"][0]["content"][0]["text"].startswith("Generate a concise"):
            result["id"] = "resp_title"
        else:
            result["output"] = [{"type": "custom_tool_call", "name": "exec", "call_id": "call-1", "input": script}]
        if stream:
            return web.Response(
                body=("data: " + json.dumps({"type": "response.completed", "response": result}) + "\n\n").encode(),
                content_type="text/event-stream",
            )
        return web.json_response(result)

    app = web.Application()
    app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(app)
    for text in [
        "Generate a concise, single-line task title of at most 36 characters.\n\nUser prompt:\ninspect files",
        "inspect files",
    ]:
        response = await agent.post(
            "/codex/proxy/v1/responses",
            headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
            json=_responses_request(stream=stream, text=text),
        )
        assert response.status == 200
        await response.read()
    await _post_codex(agent, sid, _response_item("custom_tool_call", name="exec", call_id="call-1", input=script))
    await _post_codex(
        agent,
        sid,
        {
            "type": "token_usage_record",
            "timestamp": "2026-05-11T17:00:04.000Z",
            "payload": {"response_id": "resp_123", "usage": {"input_tokens": 100, "output_tokens": 30}},
        },
    )
    await _post_codex(agent, sid, _response_item("custom_tool_call_output", call_id="call-1", output="done"))
    spans = await _spans(agent, sid)
    llms = _by_kind(spans, "llm")
    steps = _by_kind(spans, "step")
    tools = _by_kind(spans, "tool")
    assert len(llms) == len(steps) == 1
    assert tools == []  # The wrapper does not report a structured tool execution.
    assert llms[0]["meta"]["metadata"]["response_id"] == "resp_123"
    assert llms[0]["meta"]["output"]["messages"][0]["tool_calls"][0]["arguments"] == script
    assert llms[0]["parent_id"] == steps[0]["span_id"]
    pending = (await (await agent.get("/codex/hooks/raw-proxy")).json())["spans"]
    assert [s["meta"]["metadata"]["response_id"] for s in pending] == ["resp_title"]


async def test_codex_proxy_inflight_jsonl_usage_does_not_split_tool_call_step(agent, aiohttp_server):
    sid = "codex-proxy-inflight-tool"
    await _post_codex(agent, sid, _session_meta(sid))
    await _post_codex(agent, sid, _turn_context())
    await _post_codex(agent, sid, _event("user_message", message="run pwd"))

    request_started = asyncio.Event()
    release_response = asyncio.Event()

    async def handle(request):
        request_started.set()
        await release_response.wait()
        return web.json_response(_responses_tool_call_body())

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    proxied = asyncio.create_task(
        agent.post(
            "/codex/proxy/v1/responses",
            headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
            json=_responses_request(),
        )
    )
    await request_started.wait()

    await _post_codex(
        agent,
        sid,
        _response_item(
            "function_call",
            timestamp="2026-05-13T17:00:04.000Z",
            name="exec_command",
            call_id="call-1",
            arguments='{"cmd": "pwd"}',
        ),
    )
    await _post_codex(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-13T17:00:04.010Z",
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

    release_response.set()
    assert (await proxied).status == 200
    await _post_codex(
        agent,
        sid,
        _response_item(
            "function_call_output",
            timestamp="2026-05-13T17:00:05.000Z",
            call_id="call-1",
            output="/repo",
        ),
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
    assert llms[0]["duration"] > 0


async def test_codex_proxy_failed_response_does_not_suppress_jsonl_token_fallback(agent, aiohttp_server):
    sid = "codex-proxy-failed-fallback"
    await _post_codex(agent, sid, _session_meta(sid), proxy_session_key="proxy-failed")
    await _post_codex(agent, sid, _turn_context("turn-failed"), proxy_session_key="proxy-failed")
    await _post_codex(agent, sid, _event("user_message", message="prompt failed"), proxy_session_key="proxy-failed")

    async def handle(request):
        return web.json_response({"error": "upstream failed"}, status=500)

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    resp = await agent.post(
        "/codex/proxy/proxy-failed/v1/responses",
        headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
        json=_responses_request(text="prompt failed"),
    )
    assert resp.status == 500

    await _post_codex(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:03.000Z",
            info={"last_token_usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}},
        ),
        proxy_session_key="proxy-failed",
    )
    await _post_codex(
        agent,
        sid,
        _response_item(
            "message",
            timestamp="2026-05-11T17:00:04.000Z",
            role="assistant",
            content=[{"type": "output_text", "text": "fallback answer"}],
        ),
        proxy_session_key="proxy-failed",
    )

    llms = _by_kind(await _spans(agent, sid), "llm")
    assert len(llms) == 1
    assert llms[0]["metrics"]["input_tokens"] == 10
    assert llms[0]["meta"]["output"]["messages"] == [{"role": "assistant", "content": "fallback answer"}]


@pytest.mark.parametrize("arrival", ["before_session", "before_usage", "after_usage", "after_close"])
@pytest.mark.parametrize("shared_key", [False, True])
async def test_proxy_correlates_only_by_response_id(agent, aiohttp_server, arrival, shared_key):
    async def handle(request):
        return web.json_response(_responses_body())

    app = web.Application()
    app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(app)

    async def proxy_call():
        response = await agent.post(
            "/codex/proxy/shared/v1/responses",
            headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
            json=_responses_request(text="same prompt"),
        )
        assert response.status == 200
        await response.read()

    if arrival == "before_session":
        await proxy_call()
    for sid in ("a", "b"):
        key = "shared" if shared_key or sid == "a" else "different"
        await _post_codex(agent, sid, _session_meta(sid), proxy_session_key=key)
        await _post_codex(agent, sid, _turn_context("turn-" + sid))
        await _post_codex(agent, sid, _event("user_message", message="same prompt"))
        await _post_codex(
            agent,
            sid,
            _response_item("message", role="assistant", content=[{"type": "output_text", "text": "fallback"}]),
        )
    if arrival == "before_usage":
        await proxy_call()
    for sid, rid in (("a", "resp_123"), ("b", "resp_other")):
        await _post_codex(
            agent,
            sid,
            {
                "type": "token_usage_record",
                "timestamp": "2026-05-11T17:00:04.000Z",
                "payload": {"response_id": rid, "usage": {"input_tokens": 10, "output_tokens": 2}},
            },
        )
        await _post_codex(
            agent, sid, _event("token_count", info={"last_token_usage": {"input_tokens": 10, "output_tokens": 2}})
        )
    original = {s["session_id"]: s["span_id"] for s in _by_kind(await _spans(agent), "llm")}
    if arrival == "after_usage":
        await proxy_call()
    for sid in ("a", "b"):
        await _post_codex(agent, sid, _event("task_complete"))
    if arrival == "after_close":
        await proxy_call()
    llms = _by_kind(await _spans(agent), "llm")
    assert len(llms) == 2
    by_session = {s["session_id"]: s for s in llms}
    assert {sid: s["span_id"] for sid, s in by_session.items()} == original
    assert by_session["a"]["metrics"]["input_tokens"] == 100
    assert "source:codex-proxy" in by_session["a"]["tags"]
    assert by_session["b"]["metrics"]["input_tokens"] == 10
    assert "source:codex-jsonl" in by_session["b"]["tags"]
    assert (await (await agent.get("/codex/hooks/raw-proxy")).json())["spans"] == []
