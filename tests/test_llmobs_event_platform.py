"""Tests for LLM Observability Event Platform API endpoints."""


async def test_llmobs_logs_analytics_list(agent):
    resp = await agent.post(
        "/api/v1/logs-analytics/list",
        json={"query": "*"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert "data" in data
    assert data["data"] == []
    assert "meta" in data
    assert data["meta"]["status"] == "done"


async def test_llmobs_logs_analytics_list_cors_headers(agent):
    resp = await agent.post(
        "/api/v1/logs-analytics/list",
        json={"query": "*"},
    )
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"


async def test_llmobs_logs_analytics_list_options(agent):
    resp = await agent.options("/api/v1/logs-analytics/list")
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"
    assert "POST" in resp.headers.get("Access-Control-Allow-Methods", "")
    # Verify x-csrf-token is allowed (required by Datadog UI)
    allowed_headers = resp.headers.get("Access-Control-Allow-Headers", "")
    assert "x-csrf-token" in allowed_headers.lower()


async def test_llmobs_logs_analytics_get(agent):
    resp = await agent.get("/api/v1/logs-analytics/list/test-request-id")
    assert resp.status == 200
    data = await resp.json()
    assert "data" in data
    assert data["data"] == []
    assert data["meta"]["status"] == "done"
    assert data["meta"]["request_id"] == "test-request-id"


async def test_llmobs_aggregate(agent):
    resp = await agent.post(
        "/api/v1/logs-analytics/aggregate",
        json={"query": "*"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "done"
    assert data["result"]["buckets"] == []
    assert data["result"]["count"] == 0


async def test_llmobs_aggregate_options(agent):
    resp = await agent.options("/api/v1/logs-analytics/aggregate")
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"


async def test_llmobs_fetch_one(agent):
    resp = await agent.post(
        "/api/v1/logs-analytics/fetch_one",
        json={"id": "test-span-id"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["data"] is None
    assert data["meta"]["status"] == "done"


async def test_llmobs_facets_list(agent):
    resp = await agent.get("/api/ui/event-platform/llmobs/facets")
    assert resp.status == 200
    data = await resp.json()
    assert "data" in data
    assert data["data"] == []


async def test_llmobs_facets_list_options(agent):
    resp = await agent.options("/api/ui/event-platform/llmobs/facets")
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"


async def test_llmobs_trace(agent):
    resp = await agent.get("/api/ui/llm-obs/v1/trace/test-trace-id")
    assert resp.status == 200
    data = await resp.json()
    assert "data" in data
    assert data["data"]["trace_id"] == "test-trace-id"
    assert data["data"]["spans"] == []


async def test_llmobs_trace_options(agent):
    resp = await agent.options("/api/ui/llm-obs/v1/trace/test-trace-id")
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"


async def test_llmobs_query_rewriter_list(agent):
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list",
        json={"query": "*"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["data"] == []
    assert data["meta"]["status"] == "done"


async def test_llmobs_query_rewriter_aggregate(agent):
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/aggregate",
        json={"query": "*"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "done"
    assert data["result"]["buckets"] == []


async def test_llmobs_query_rewriter_facet_info(agent):
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/facet_info",
        json={"facet": "ml_app"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert "data" in data
    assert data["data"] == []


async def test_llmobs_query_rewriter_facet_range_info(agent):
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/facet_range_info",
        json={"facet_range_info": {"path": "@duration"}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "done"
    assert data["result"]["min"] == 0
    assert data["result"]["max"] == 0


async def test_llmobs_query_rewriter_fetch_one(agent):
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/fetch_one",
        json={"id": "test-span-id"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["data"] is None


async def test_query_scalar(agent):
    resp = await agent.post(
        "/api/ui/query/scalar",
        json={"data": []},
    )
    assert resp.status == 200
    data = await resp.json()
    assert "data" in data
    assert len(data["data"]) == 1
    assert data["data"][0]["type"] == "scalar_response"
    assert data["data"][0]["attributes"]["columns"] == []


async def test_query_scalar_options(agent):
    resp = await agent.options("/api/ui/query/scalar")
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"


async def test_info_cors_headers(agent):
    resp = await agent.get("/info")
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"


async def test_info_options(agent):
    resp = await agent.options("/info")
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"
