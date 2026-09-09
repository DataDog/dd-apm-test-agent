"""Tests for the boundary between the base test agent and the Lapdog server."""

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
