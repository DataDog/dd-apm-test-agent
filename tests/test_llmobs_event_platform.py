"""Tests for LLM Observability Event Platform API endpoints."""

import gzip
import time

import msgpack
import pytest


@pytest.fixture
def llmobs_payload():
    """A sample LLMObs payload matching the SDK format."""
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
    """Submit an LLMObs payload to the test agent (same format as SDK)."""
    data = gzip.compress(msgpack.packb(payload))
    return await agent.post(
        "/evp_proxy/v2/api/v2/llmobs",
        headers={"Content-Type": "application/msgpack", "Content-Encoding": "gzip"},
        data=data,
    )


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


async def test_llmobs_facets(agent):
    resp = await agent.get("/api/ui/event-platform/llmobs/facets")
    assert resp.status == 200
    data = await resp.json()
    assert "facets" in data
    assert "llmobs" in data["facets"]


async def test_llmobs_facet_info(agent):
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/facet_info?type=llmobs",
        json={"facet_info": {"path": "@ml_app", "limit": 10}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "done"


async def test_llmobs_facet_range_info(agent):
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/facet_range_info?type=llmobs",
        json={"facet_range_info": {"path": "@duration"}},
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
