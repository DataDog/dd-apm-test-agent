"""Tests for the boundary between the base test agent and the Lapdog server."""

from unittest import mock

from aiohttp import web
import msgpack
import pytest

from ddapm_test_agent import agent as test_agent
from lapdog import server as lapdog_server

LAPDOG_ROUTE_PATHS = {
    "/lapdog/coding_agent/send",
    "/lapdog/pi/connect",
    "/claude/hooks",
    "/lapdog/session/tags",
    "/claude/hooks/session/tags",
    "/claude/hooks/backfill_session",
    "/claude/hooks/sessions",
    "/claude/hooks/spans",
    "/claude/hooks/raw",
    "/claude/proxy/{path}",
    "/pi/hooks",
    "/pi/hooks/backfill_session",
    "/pi/hooks/raw",
    "/codex/hooks",
    "/codex/hooks/raw",
    "/codex/proxy/{proxy_session_key}/v1/{path}",
    "/codex/proxy/v1/{path}",
    "/api/unstable/llm-obs-query-rewriter/list",
    "/api/unstable/llm-obs-query-rewriter/list/{request_id}",
    "/api/unstable/llm-obs-query-rewriter/aggregate",
    "/api/unstable/llm-obs-query-rewriter/fetch_one",
    "/api/unstable/llm-obs-query-rewriter/facet_info",
    "/api/unstable/llm-obs-query-rewriter/facet_range_info",
    "/api/ui/event-platform/llmobs/facets",
    "/api/v1/logs-analytics/list",
    "/api/v1/logs-analytics/list/{request_id}",
    "/api/v1/logs-analytics/aggregate",
    "/api/v1/logs-analytics/fetch_one",
    "/api/ui/llm-obs/v1/trace/{trace_id}",
    "/api/ui/query/scalar",
}


def _route_paths(client):
    return {route.resource.canonical for route in client.app.router.routes()}


@pytest.fixture
def agent_authentication(monkeypatch, request):
    monkeypatch.setattr(test_agent, "_is_agent_authenticated", lambda url: request.param)
    return request.param


@pytest.mark.parametrize("agent_authentication", [False, True], indirect=True)
@pytest.mark.parametrize("agent_url", ["http://127.0.0.1:9876"])
@pytest.mark.parametrize("disable_llmobs_data_forwarding", [False])
async def test_agent_validation_controls_forwarding(agent_authentication, agent, lapdog_agent):
    for client in (agent, lapdog_agent):
        app = client.app
        assert app["authenticated"] is agent_authentication
        assert app["disable_llmobs_data_forwarding"] is (not agent_authentication)
        assert app["agent_url"] == "http://127.0.0.1:9876"
    response = await lapdog_agent.get("/info")
    assert response.status == 200
    assert (await response.json())["authenticated"] is agent_authentication


@pytest.mark.parametrize("agent_url", ["http://127.0.0.1:9876"])
async def test_request_proxy_override_takes_precedence(agent, lapdog_agent):
    for client, default_forwarding in ((agent, True), (lapdog_agent, False)):
        assert client.app["proxy_to_agent"] is default_forwarding
        for override in (None, "true", "false"):
            headers = {} if override is None else {"X-Datadog-Agent-Proxy-Disabled": override}
            with mock.patch.object(test_agent, "_prepare_and_send_request", new_callable=mock.AsyncMock) as forward:
                forward.return_value = web.Response()
                response = await client.get("/info", headers=headers)
                assert response.status == 200
                should_forward = default_forwarding if override is None else override == "false"
                assert forward.await_count == int(should_forward)


async def test_base_agent_does_not_expose_lapdog_routes(agent):
    assert LAPDOG_ROUTE_PATHS.isdisjoint(_route_paths(agent))


@pytest.mark.parametrize("agent_authentication", [True], indirect=True)
@pytest.mark.parametrize("disable_llmobs_data_forwarding", [False])
class TestLapdogLLMObsForwarding:
    @pytest.fixture
    def forwarded_payloads(self):
        return []

    @pytest.fixture
    async def agent_url(self, aiohttp_server, forwarded_payloads):
        async def receive(request):
            forwarded_payloads.append(await request.read())
            return web.json_response({})

        upstream = web.Application()
        upstream.router.add_post("/evp_proxy/v2/api/v2/llmobs", receive)
        server = await aiohttp_server(upstream)
        return str(server.make_url("")).rstrip("/")

    async def test_llmobs_still_forwards(self, agent_authentication, lapdog_agent, forwarded_payloads):
        assert lapdog_agent.app["proxy_to_agent"] is False
        payload = msgpack.packb({"ml_obs": {"spans": []}}, use_bin_type=True)
        response = await lapdog_agent.post("/evp_proxy/v2/api/v2/llmobs", data=payload)
        assert response.status == 200
        assert forwarded_payloads == [payload]


async def test_lapdog_server_adds_all_lapdog_routes(lapdog_agent):
    assert LAPDOG_ROUTE_PATHS <= _route_paths(lapdog_agent)


@pytest.mark.parametrize("origin", ["https://app.datadoghq.com", "http://localhost:3000", "https://example.com"])
async def test_coding_agent_cors_preflight(lapdog_agent, origin):
    with mock.patch("lapdog.headless_coding_agent_interactions.asyncio.create_subprocess_exec") as spawn:
        response = await lapdog_agent.options(
            "/lapdog/coding_agent/send",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
    assert response.status == 200
    expected_origin = None if origin == "https://example.com" else origin
    assert response.headers.get("Access-Control-Allow-Origin") == expected_origin
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "content-type" in response.headers["Access-Control-Allow-Headers"].lower()
    spawn.assert_not_called()


@pytest.mark.parametrize("exit_code", [0, 1])
async def test_coding_agent_cors_response(lapdog_agent, exit_code):
    process = mock.Mock(returncode=exit_code)
    process.communicate = mock.AsyncMock(return_value=(b"output", b""))
    with (
        mock.patch("lapdog.headless_coding_agent_interactions.shutil.which", return_value="/bin/lapdog"),
        mock.patch("lapdog.headless_coding_agent_interactions.asyncio.create_subprocess_exec", return_value=process),
    ):
        response = await lapdog_agent.post(
            "/lapdog/coding_agent/send",
            json={"coding_agent": "claude-code", "session_id": "session", "message": "hello"},
            headers={"Origin": "https://app.datadoghq.com"},
        )
    assert response.status == (200 if exit_code == 0 else 502)
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.datadoghq.com"


async def test_coding_agent_cors_validation_error(lapdog_agent):
    response = await lapdog_agent.post(
        "/lapdog/coding_agent/send",
        json={},
        headers={"Origin": "https://app.datadoghq.com"},
    )
    assert response.status == 400
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.datadoghq.com"


async def test_lapdog_and_base_apps_use_different_forwarding_extensions(agent, lapdog_agent):
    base_agent = agent.app["agent"]
    extended_agent = lapdog_agent.app["agent"]
    assert base_agent.llmobs_payload_transform is not extended_agent.llmobs_payload_transform
    assert base_agent.llmobs_span_update_listener is None
    assert extended_agent.llmobs_span_update_listener is not None


async def test_lapdog_does_not_price_forwarded_llmobs_spans(agent, lapdog_agent):
    span = {
        "span_id": "1",
        "meta": {"span": {"kind": "llm"}, "model_name": "gpt-5.5", "model_provider": "openai"},
        "metrics": {"input_tokens": 100, "cache_read_input_tokens": 20, "output_tokens": 30},
    }
    raw = msgpack.packb({"ml_obs": {"spans": [span]}}, use_bin_type=True)
    base = agent.app["agent"].llmobs_payload_transform(raw, "")
    lapdog = lapdog_agent.app["agent"].llmobs_payload_transform(raw, "")
    assert base == raw
    forwarded = msgpack.unpackb(lapdog, raw=False)["ml_obs"]["spans"][0]
    assert forwarded["metrics"] == span["metrics"]
    assert "lapdog_forwarded:true" in forwarded["tags"]


def test_deprecated_lapdog_mode_reenters_main_once_without_recurring(monkeypatch, capsys):
    main_spy = mock.Mock(wraps=test_agent.main)
    monkeypatch.setattr(test_agent, "main", main_spy)

    with pytest.raises(SystemExit) as exc_info:
        test_agent.main(["--lapdog-mode", "--version"])

    assert exc_info.value.code == 0
    assert main_spy.call_args_list == [
        mock.call(["--lapdog-mode", "--version"]),
        mock.call(args=["--version"], app_factory=lapdog_server.make_app),
    ]
    captured = capsys.readouterr()
    assert "--lapdog-mode is deprecated" in captured.err
    assert captured.out.strip()
