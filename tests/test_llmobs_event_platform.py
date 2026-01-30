import gzip
import time

import msgpack
import pytest


@pytest.fixture
def llmobs_payload():
    return {
        "ml_app": "test-app",
        "tags": ["env:test", "service:test-service"],
        "spans": [
            {
                "name": "agent-workflow",
                "span_id": "span-root",
                "trace_id": "trace-123",
                "parent_id": "undefined",
                "status": "ok",
                "duration": 5_000_000_000,
                "start_ns": int(time.time() * 1_000_000_000),
                "meta": {
                    "span": {"kind": "agent"},
                    "input": {"value": "What is the weather?"},
                    "output": {"value": "The weather is sunny."},
                },
                "metrics": {"input_tokens": 10, "output_tokens": 20, "total_tokens": 30},
                "tags": [],
            },
            {
                "name": "llm-call",
                "span_id": "span-child",
                "trace_id": "trace-123",
                "parent_id": "span-root",
                "status": "ok",
                "duration": 2_000_000_000,
                "start_ns": int(time.time() * 1_000_000_000),
                "meta": {
                    "span": {"kind": "llm"},
                    "input": {"value": "Generate response"},
                    "output": {"value": "The weather is sunny."},
                    "model_name": "gpt-4",
                    "model_provider": "openai",
                },
                "metrics": {"input_tokens": 5, "output_tokens": 10, "total_tokens": 15},
                "tags": [],
            },
        ],
    }


async def _submit_llmobs_payload(agent, payload):
    data = gzip.compress(msgpack.packb(payload))
    return await agent.post(
        "/evp_proxy/v2/api/v2/llmobs",
        headers={"Content-Type": "application/msgpack", "Content-Encoding": "gzip"},
        data=data,
    )


# Tests from master branch (testing empty/stub responses)


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
    allowed_headers = resp.headers.get("Access-Control-Allow-Headers", "")
    assert "x-csrf-token" in allowed_headers.lower()


async def test_llmobs_aggregate_options(agent):
    resp = await agent.options("/api/v1/logs-analytics/aggregate")
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"


async def test_llmobs_facets_list(agent):
    resp = await agent.get("/api/ui/event-platform/llmobs/facets")
    assert resp.status == 200
    data = await resp.json()
    assert "facets" in data


async def test_llmobs_facets_list_options(agent):
    resp = await agent.options("/api/ui/event-platform/llmobs/facets")
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"


async def test_llmobs_trace_options(agent):
    resp = await agent.options("/api/ui/llm-obs/v1/trace/test-trace-id")
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"


async def test_llmobs_query_rewriter_facet_info(agent):
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/facet_info",
        json={"facet": "ml_app"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "done"


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


# Functional tests (testing actual span data flow)


async def test_llmobs_submit_spans(agent, llmobs_payload):
    resp = await _submit_llmobs_payload(agent, llmobs_payload)
    assert resp.status == 200


async def test_llmobs_list_empty(agent):
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": ""}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "done"
    assert data["hitCount"] == 0


async def test_llmobs_list_returns_spans(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": ""}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "done"
    assert data["hitCount"] == 2


async def test_llmobs_list_filter_by_span_kind(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": "@meta.span.kind:llm"}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["hitCount"] == 1
    assert data["result"]["events"][0]["event"]["custom"]["meta"]["span"]["kind"] == "llm"


async def test_llmobs_list_filter_root_spans(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": "@parent_id:undefined"}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["hitCount"] == 1
    assert data["result"]["events"][0]["event"]["custom"]["parent_id"] == "undefined"


async def test_llmobs_list_filter_by_duration(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": "@duration:>=3s"}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["hitCount"] == 1
    assert data["result"]["events"][0]["event"]["custom"]["duration"] == 5_000_000_000


async def test_llmobs_fetch_one(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/fetch_one?type=llmobs",
        json={"eventId": "span-root"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "done"


async def test_llmobs_trace(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.get("/api/ui/llm-obs/v1/trace/trace-123")
    assert resp.status == 200
    data = await resp.json()
    assert "data" in data
    assert data["data"]["attributes"]["root_id"] is not None


async def test_llmobs_aggregate(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/aggregate?type=llmobs",
        json={},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "done"


async def test_llmobs_cors_headers(agent):
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={},
    )
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"


async def test_llmobs_options(agent):
    resp = await agent.options("/api/unstable/llm-obs-query-rewriter/list")
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"
    assert "POST" in resp.headers.get("Access-Control-Allow-Methods", "")


# Facet filter query tests


def _create_span_for_facet_test(
    span_id: int,
    trace_id: int,
    ml_app: str = "test-app",
    span_kind: str = "llm",
    duration: int = 1000000000,
):
    """Create a span for facet testing."""
    return {
        "span_id": str(span_id),
        "trace_id": str(trace_id),
        "parent_id": "0",
        "name": "test-span",
        "status": "ok",
        "start_ns": int(time.time() * 1_000_000_000),
        "duration": duration,
        "tags": [f"ml_app:{ml_app}", "service:test", "env:test"],
        "meta": {
            "span": {"kind": span_kind},
            "input": {"value": "test"},
            "output": {"value": "test"},
        },
        "metrics": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
    }


async def _submit_spans_for_facet_test(agent, spans):
    """Submit spans for facet testing."""
    payload = {"_dd.stage": "raw", "event_type": "span", "spans": spans}
    data = gzip.compress(msgpack.packb(payload))
    resp = await agent.post(
        "/evp_proxy/v2/api/v2/llmobs",
        headers={"Content-Type": "application/msgpack", "Content-Encoding": "gzip"},
        data=data,
    )
    assert resp.status == 200
    return resp


async def test_facet_info_with_filter_query(agent):
    """Test facet_info respects filter query when computing values."""
    spans = [
        _create_span_for_facet_test(1, 100, ml_app="app-1", span_kind="llm"),
        _create_span_for_facet_test(2, 100, ml_app="app-1", span_kind="chain"),
        _create_span_for_facet_test(3, 101, ml_app="app-2", span_kind="llm"),
    ]
    await _submit_spans_for_facet_test(agent, spans)

    # Request facet info for ml_app, filtered by span_kind=llm
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/facet_info",
        json={
            "facet_info": {
                "path": "@ml_app",
                "limit": 10,
                "search": {"query": "@meta.span.kind:llm"},
            }
        },
    )
    assert resp.status == 200

    data = await resp.json()
    fields = data["result"]["fields"]

    # Should only count spans with kind=llm
    field_map = {f["field"]: f["value"] for f in fields}
    assert field_map.get("app-1") == 1  # Only 1 llm span in app-1
    assert field_map.get("app-2") == 1  # 1 llm span in app-2


async def test_facet_range_info_with_filter_query(agent):
    """Test facet_range_info respects filter query."""
    spans = [
        _create_span_for_facet_test(1, 100, ml_app="app-1", duration=1000000000),
        _create_span_for_facet_test(2, 100, ml_app="app-1", duration=2000000000),
        _create_span_for_facet_test(3, 101, ml_app="app-2", duration=10000000000),
    ]
    await _submit_spans_for_facet_test(agent, spans)

    # Request range for app-1 only
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/facet_range_info",
        json={
            "facet_range_info": {
                "path": "@duration",
                "search": {"query": "@ml_app:app-1"},
            }
        },
    )
    assert resp.status == 200

    data = await resp.json()
    # Should only include app-1 spans (1s and 2s)
    assert data["result"]["min"] == 1000000000
    assert data["result"]["max"] == 2000000000
