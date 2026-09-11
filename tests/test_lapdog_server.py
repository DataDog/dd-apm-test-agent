"""Tests for the boundary between the base test agent and the Lapdog server."""

from unittest import mock

from lapdog import auth
from lapdog import server

LAPDOG_ROUTE_PATHS = {
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
    "/lapdog/oauth/token",
}


def _route_paths(client):
    return {route.resource.canonical for route in client.app.router.routes()}


async def test_base_agent_does_not_expose_lapdog_routes(agent):
    assert LAPDOG_ROUTE_PATHS.isdisjoint(_route_paths(agent))


async def test_lapdog_server_adds_all_lapdog_routes(lapdog_agent):
    assert LAPDOG_ROUTE_PATHS <= _route_paths(lapdog_agent)


async def test_lapdog_and_base_apps_use_different_forwarding_extensions(agent, lapdog_agent):
    base_agent = agent.app["agent"]
    extended_agent = lapdog_agent.app["agent"]
    assert base_agent.llmobs_payload_transform is not extended_agent.llmobs_payload_transform
    assert base_agent.llmobs_span_update_listener is None
    assert extended_agent.llmobs_span_update_listener is not None


async def test_oauth_token_creates_and_persists_api_key(lapdog_agent, monkeypatch):
    create_api_key = mock.AsyncMock(return_value=("created-key", "key-id"))
    set_api_key = mock.Mock()
    save_config = mock.Mock()
    monkeypatch.setattr(auth, "_create_api_key", create_api_key)
    monkeypatch.setattr(auth.config, "set_api_key", set_api_key)
    monkeypatch.setattr(auth.config, "save_config", save_config)

    response = await lapdog_agent.post(
        "/lapdog/oauth/token",
        json={"access_token": "oauth-token", "site": "us5.datadoghq.com"},
        headers={"Origin": "https://lapdog.datadoghq.com"},
    )

    assert response.status == 201
    assert await response.json() == {"configured": True}
    assert response.headers["Access-Control-Allow-Origin"] == "https://lapdog.datadoghq.com"
    create_api_key.assert_awaited_once_with("oauth-token", "us5.datadoghq.com")
    set_api_key.assert_called_once_with("created-key")
    save_config.assert_called_once_with(dd_site="us5.datadoghq.com", data_forwarding=True)
    assert lapdog_agent.app["dd_api_key"] == "created-key"
    assert lapdog_agent.app["dd_site"] == "us5.datadoghq.com"
    assert lapdog_agent.app["disable_llmobs_data_forwarding"] is False
    assert lapdog_agent.app["authenticated"] is True


async def test_oauth_token_does_not_replace_inline_runtime_configuration(lapdog_agent, monkeypatch):
    monkeypatch.setattr(auth, "_create_api_key", mock.AsyncMock(return_value=("created-key", "key-id")))
    monkeypatch.setattr(auth.config, "set_api_key", mock.Mock())
    monkeypatch.setattr(auth.config, "save_config", mock.Mock())
    lapdog_agent.app["lapdog_auth_overrides"] = {
        "dd_api_key": True,
        "dd_site": True,
        "forward": True,
    }
    lapdog_agent.app["dd_api_key"] = "inline-key"
    lapdog_agent.app["dd_site"] = "datadoghq.eu"
    lapdog_agent.app["disable_llmobs_data_forwarding"] = False

    response = await lapdog_agent.post(
        "/lapdog/oauth/token",
        json={"access_token": "oauth-token", "site": "us5.datadoghq.com"},
        headers={"Origin": "https://lapdog.datadoghq.com"},
    )

    assert response.status == 201
    assert lapdog_agent.app["dd_api_key"] == "inline-key"
    assert lapdog_agent.app["dd_site"] == "datadoghq.eu"
    assert lapdog_agent.app["disable_llmobs_data_forwarding"] is False


async def test_oauth_token_rejects_site_not_offered_by_web_ui(lapdog_agent, monkeypatch):
    create_api_key = mock.AsyncMock()
    monkeypatch.setattr(auth, "_create_api_key", create_api_key)

    response = await lapdog_agent.post(
        "/lapdog/oauth/token",
        json={"access_token": "oauth-token", "site": "attacker.example"},
        headers={"Origin": "https://lapdog.datadoghq.com"},
    )

    assert response.status == 400
    create_api_key.assert_not_awaited()


async def test_oauth_token_rejects_unexpected_origin(lapdog_agent, monkeypatch):
    create_api_key = mock.AsyncMock()
    monkeypatch.setattr(auth, "_create_api_key", create_api_key)

    response = await lapdog_agent.post(
        "/lapdog/oauth/token",
        json={"access_token": "oauth-token", "site": "datadoghq.com"},
        headers={"Origin": "https://attacker.example"},
    )

    assert response.status == 403
    create_api_key.assert_not_awaited()


async def test_oauth_token_rejects_non_json_content_type(lapdog_agent, monkeypatch):
    create_api_key = mock.AsyncMock()
    monkeypatch.setattr(auth, "_create_api_key", create_api_key)

    response = await lapdog_agent.post(
        "/lapdog/oauth/token",
        data='{"access_token":"oauth-token","site":"datadoghq.com"}',
        headers={
            "Content-Type": "text/plain",
            "Origin": "https://lapdog.datadoghq.com",
        },
    )

    assert response.status == 415
    create_api_key.assert_not_awaited()


def test_oauth_origin_allows_https_localhost_on_any_port():
    assert auth._is_allowed_oauth_origin("https://localhost:12345")


async def test_create_api_key_uses_oauth_bearer_and_requested_name(monkeypatch):
    calls = []

    class FakeResponse:
        status = 201

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def json(self):
            return {"data": {"id": "key-id", "attributes": {"key": "created-key"}}}

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        def post(self, url, **kwargs):
            calls.append((url, kwargs))
            return FakeResponse()

    monkeypatch.setattr(auth, "ClientSession", FakeSession)
    monkeypatch.setattr(auth, "_api_key_name", lambda: "Lapdog API Key created by sam on timestamp")

    result = await auth._create_api_key("oauth-token", "datadoghq.com")

    assert result == ("created-key", "key-id")
    assert calls == [
        (
            "https://api.datadoghq.com/api/v2/api_keys",
            {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Bearer oauth-token",
                    "Content-Type": "application/json",
                },
                "json": {
                    "data": {
                        "type": "api_keys",
                        "attributes": {"name": "Lapdog API Key created by sam on timestamp"},
                    }
                },
                "allow_redirects": False,
            },
        )
    ]


def test_persisted_auth_and_forwarding_are_startup_defaults(monkeypatch):
    monkeypatch.delenv("DD_API_KEY", raising=False)
    monkeypatch.delenv("DD_SITE", raising=False)
    monkeypatch.delenv("DISABLE_LLMOBS_DATA_FORWARDING", raising=False)
    monkeypatch.setattr(
        server.config,
        "load_config",
        lambda: {"dd_site": "datadoghq.eu", "data_forwarding": True},
    )
    monkeypatch.setattr(server.config, "get_api_key", lambda: "stored-key")

    args, overrides, environment = server._prepare_startup([])

    assert args == []
    assert overrides == {"dd_api_key": False, "dd_site": False, "forward": False}
    assert environment == {"DD_API_KEY": "stored-key", "DD_SITE": "datadoghq.eu"}


def test_inline_auth_and_forwarding_take_precedence(monkeypatch):
    monkeypatch.setenv("DD_API_KEY", "inline-key")
    monkeypatch.setenv("DD_SITE", "us3.datadoghq.com")
    monkeypatch.delenv("DISABLE_LLMOBS_DATA_FORWARDING", raising=False)
    monkeypatch.setattr(
        server.config,
        "load_config",
        lambda: {"dd_site": "datadoghq.eu", "data_forwarding": False},
    )
    get_api_key = mock.Mock(return_value="stored-key")
    monkeypatch.setattr(server.config, "get_api_key", get_api_key)

    args, overrides, environment = server._prepare_startup(["--forward"])

    assert args == []
    assert overrides == {"dd_api_key": True, "dd_site": True, "forward": True}
    assert environment == {}
    get_api_key.assert_not_called()


def test_forwarding_defaults_to_disabled_without_persisted_opt_in(monkeypatch):
    monkeypatch.delenv("DD_API_KEY", raising=False)
    monkeypatch.delenv("DD_SITE", raising=False)
    monkeypatch.delenv("DISABLE_LLMOBS_DATA_FORWARDING", raising=False)
    monkeypatch.setattr(server.config, "load_config", lambda: {})
    monkeypatch.setattr(server.config, "get_api_key", lambda: "")

    args, _, _ = server._prepare_startup([])

    assert args == ["--disable-llmobs-data-forwarding"]
