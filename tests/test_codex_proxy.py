import asyncio
import json

from aiohttp import web
import pytest

from ddapm_test_agent import codex_proxy as codex_proxy_module
from ddapm_test_agent.codex_proxy import _is_client_disconnect_error


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

        def begin_proxy_llm_call(self, maybe_session_id, start_ns):
            return maybe_session_id

        def register_proxy_llm_span(self, maybe_session_id, span, start_ns, end_ns):
            self.registered.append((maybe_session_id, span, start_ns, end_ns))

        def finish_proxy_llm_call(self, maybe_session_id, succeeded):
            self.finished = (maybe_session_id, succeeded)

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
    assert hooks.finished == ("proxy-key", False)


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


def test_codex_proxy_caps_messages_and_links_reasoning_to_tool_calls():
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
            "type": "function_call",
            "call_id": "call-1",
            "name": "exec_command",
            "arguments": json.dumps({"cmd": large_value}),
            "status": "in_progress",
        },
    ]
    request_body = {
        "model": "gpt-5.5",
        "input": [
            {
                "type": "function_call_output",
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
    session_meta = _session_meta(sid)
    session_meta["git"] = {"repository_url": "https://github.com/DataDog/codex-proxy-project.git"}
    await _post_codex(agent, sid, session_meta)
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
    assert "project_name:codex-proxy-project" in llms[0]["tags"]
    assert "git.repository_url:github.com/DataDog/codex-proxy-project" in llms[0]["tags"]


async def test_codex_proxy_overlapping_llm_spans_split_into_steps(agent, aiohttp_server):
    sid = "codex-proxy-overlap"
    await _post_codex(agent, sid, _session_meta(sid))
    await _post_codex(agent, sid, _turn_context())
    await _post_codex(agent, sid, _event("user_message", message="run two calls"))

    requests_started = 0
    first_started = asyncio.Event()
    second_started = asyncio.Event()
    release_first = asyncio.Event()
    release_second = asyncio.Event()

    async def handle(request):
        nonlocal requests_started
        requests_started += 1
        if requests_started == 1:
            first_started.set()
            await release_first.wait()
            return web.json_response(_responses_body(text="first"))
        second_started.set()
        await release_second.wait()
        return web.json_response(_responses_body(text="second"))

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    first = asyncio.create_task(
        agent.post(
            "/codex/proxy/v1/responses",
            headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
            json=_responses_request(text="first prompt"),
        )
    )
    await first_started.wait()
    second = asyncio.create_task(
        agent.post(
            "/codex/proxy/v1/responses",
            headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
            json=_responses_request(text="second prompt"),
        )
    )
    await second_started.wait()

    release_first.set()
    assert (await first).status == 200
    release_second.set()
    assert (await second).status == 200

    spans = await _spans(agent, sid)
    steps = sorted(_by_kind(spans, "step"), key=lambda span: span["name"])
    llms = sorted(_by_kind(spans, "llm"), key=lambda span: span["start_ns"])

    assert [step["name"] for step in steps] == ["inference-0", "inference-1"]
    assert len(llms) == 2
    assert llms[0]["parent_id"] == steps[0]["span_id"]
    assert llms[1]["parent_id"] == steps[1]["span_id"]


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
            "tool_calls": [
                {
                    "id": "call-1",
                    "name": "exec_command",
                    "arguments": {"cmd": "pwd"},
                    "status": "completed",
                }
            ],
        }
    ]
    assert tools[0]["meta"]["metadata"]["status"] == "completed"


async def test_codex_proxy_reasoning_after_llm_does_not_split_tool_step(agent, aiohttp_server):
    sid = "codex-proxy-reasoning-tool-step"
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

    await _post_codex(agent, sid, _response_item("reasoning", timestamp="2026-05-13T17:00:03.500Z"))
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
    assert steps[0]["meta"]["metadata"]["tool_use_ids"] == ["call-1"]


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


async def test_codex_proxy_session_key_disambiguates_same_prompt_sessions(agent, aiohttp_server):
    sid_a = "codex-proxy-same-prompt-a"
    sid_b = "codex-proxy-same-prompt-b"
    await _post_codex(agent, sid_a, _session_meta(sid_a), proxy_session_key="proxy-a")
    await _post_codex(agent, sid_a, _turn_context("turn-a"), proxy_session_key="proxy-a")
    await _post_codex(agent, sid_a, _event("user_message", message="same prompt"), proxy_session_key="proxy-a")
    await _post_codex(agent, sid_b, _session_meta(sid_b), proxy_session_key="proxy-b")
    await _post_codex(agent, sid_b, _turn_context("turn-b"), proxy_session_key="proxy-b")
    await _post_codex(agent, sid_b, _event("user_message", message="same prompt"), proxy_session_key="proxy-b")

    async def handle(request):
        return web.json_response(_responses_body(text="answer a"))

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    resp = await agent.post(
        "/codex/proxy/proxy-a/v1/responses",
        headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
        json=_responses_request(text="same prompt"),
    )
    assert resp.status == 200

    assert len(_by_kind(await _spans(agent, sid_a), "llm")) == 1
    assert _by_kind(await _spans(agent, sid_b), "llm") == []


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
    await _post_codex(agent, sid_b, _event("user_message", message="prompt a"), proxy_session_key="proxy-b")
    assert _by_kind(await _spans(agent, sid_b), "llm") == []

    sid_a = "codex-proxy-matching"
    await _post_codex(agent, sid_a, _session_meta(sid_a), proxy_session_key="proxy-a")
    await _post_codex(agent, sid_a, _turn_context("turn-a"), proxy_session_key="proxy-a")
    await _post_codex(agent, sid_a, _event("user_message", message="prompt a"), proxy_session_key="proxy-a")

    llms_a = _by_kind(await _spans(agent, sid_a), "llm")
    assert len(llms_a) == 1
    assert llms_a[0]["parent_id"] != "undefined"


async def test_codex_proxy_keyed_orphan_ignores_same_key_non_matching_session(agent, aiohttp_server):
    async def handle(request):
        return web.json_response(_responses_body(text="second answer"))

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    resp = await agent.post(
        "/codex/proxy/proxy-shared/v1/responses",
        headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
        json=_responses_request(text="prompt b"),
    )
    assert resp.status == 200

    sid_a = "codex-proxy-first-file"
    await _post_codex(agent, sid_a, _session_meta(sid_a), proxy_session_key="proxy-shared")
    await _post_codex(agent, sid_a, _turn_context("turn-a"), proxy_session_key="proxy-shared")
    await _post_codex(agent, sid_a, _event("user_message", message="prompt a"), proxy_session_key="proxy-shared")
    assert _by_kind(await _spans(agent, sid_a), "llm") == []

    sid_b = "codex-proxy-second-file"
    await _post_codex(agent, sid_b, _session_meta(sid_b), proxy_session_key="proxy-shared")
    await _post_codex(agent, sid_b, _turn_context("turn-b"), proxy_session_key="proxy-shared")
    await _post_codex(agent, sid_b, _event("user_message", message="prompt b"), proxy_session_key="proxy-shared")

    llms_b = _by_kind(await _spans(agent, sid_b), "llm")
    assert len(llms_b) == 1
    assert llms_b[0]["parent_id"] != "undefined"


async def test_codex_proxy_shared_key_child_session_attaches_to_child_turn(agent, aiohttp_server):
    parent_sid = "codex-proxy-parent"
    child_sid = "codex-proxy-child"
    proxy_key = "proxy-shared-child"

    await _post_codex(agent, parent_sid, _session_meta(parent_sid), proxy_session_key=proxy_key)
    await _post_codex(agent, parent_sid, _turn_context("parent-turn"), proxy_session_key=proxy_key)
    await _post_codex(agent, parent_sid, _event("user_message", message="delegate"), proxy_session_key=proxy_key)
    await _post_codex(
        agent,
        parent_sid,
        _event(
            "collab_agent_spawn_begin",
            timestamp="2026-05-11T17:00:02.500Z",
            call_id="spawn-child",
            sender_thread_id=parent_sid,
            prompt="child work",
        ),
        proxy_session_key=proxy_key,
    )
    await _post_codex(agent, child_sid, _session_meta(child_sid), proxy_session_key=proxy_key)
    await _post_codex(agent, child_sid, _turn_context("child-turn"), proxy_session_key=proxy_key)
    await _post_codex(
        agent,
        parent_sid,
        _event(
            "collab_agent_spawn_end",
            timestamp="2026-05-11T17:00:03.000Z",
            call_id="spawn-child",
            new_thread_id=child_sid,
            new_agent_nickname="worker",
            status="ok",
        ),
        proxy_session_key=proxy_key,
    )
    await _post_codex(
        agent,
        child_sid,
        _event("user_message", timestamp="2026-05-11T17:00:04.000Z", message="child prompt"),
        proxy_session_key=proxy_key,
    )

    async def handle(request):
        return web.json_response(_responses_body(text="child answer"))

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", handle)
    upstream = await aiohttp_server(upstream_app)

    resp = await agent.post(
        f"/codex/proxy/{proxy_key}/v1/responses",
        headers={"X-DDAPM-Upstream": str(upstream.make_url("")).rstrip("/")},
        json=_responses_request(text="child prompt"),
    )
    assert resp.status == 200

    spans = await _spans(agent)
    child_root = next(span for span in spans if span.get("meta", {}).get("metadata", {}).get("turn_id") == "child-turn")
    child_steps = [
        span
        for span in _by_kind(spans, "step")
        if span["trace_id"] == child_root["trace_id"] and span["parent_id"] == child_root["span_id"]
    ]
    child_llms = [
        span
        for span in _by_kind(spans, "llm")
        if span["trace_id"] == child_root["trace_id"] and span["parent_id"] == child_steps[0]["span_id"]
    ]

    assert child_root["session_id"] == parent_sid
    assert len(child_steps) == 1
    assert len(child_llms) == 1
    assert child_llms[0]["meta"]["input"]["messages"] == [{"role": "user", "content": "child prompt"}]
