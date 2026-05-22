import gzip
import time

import msgpack
import pytest

from ddapm_test_agent.llmobs_event_platform import _build_trace_aggregates
from ddapm_test_agent.llmobs_event_platform import extract_copilot_spans_from_otlp_traces


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


async def _submit_llmobs_payload(agent, payload, path="/evp_proxy/v2/api/v2/llmobs"):
    data = gzip.compress(msgpack.packb(payload))
    return await agent.post(
        path,
        headers={"Content-Type": "application/msgpack", "Content-Encoding": "gzip"},
        data=data,
    )


# Tests from master branch (testing empty/stub responses)

_TEST_ORIGIN = "https://app.datadoghq.com"
_TEST_ORIGIN_HEADERS = {"Origin": _TEST_ORIGIN}


async def test_llmobs_logs_analytics_list_cors_headers(agent):
    resp = await agent.post(
        "/api/v1/logs-analytics/list",
        json={"query": "*"},
        headers=_TEST_ORIGIN_HEADERS,
    )
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == _TEST_ORIGIN


async def test_llmobs_logs_analytics_list_cors_rejects_unknown_origin(agent):
    resp = await agent.post(
        "/api/v1/logs-analytics/list",
        json={"query": "*"},
        headers={"Origin": "https://evil.example.com"},
    )
    assert resp.status == 200
    assert "Access-Control-Allow-Origin" not in resp.headers


async def test_llmobs_logs_analytics_list_options(agent):
    resp = await agent.options("/api/v1/logs-analytics/list", headers=_TEST_ORIGIN_HEADERS)
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == _TEST_ORIGIN
    assert "POST" in resp.headers.get("Access-Control-Allow-Methods", "")
    allowed_headers = resp.headers.get("Access-Control-Allow-Headers", "")
    assert "x-csrf-token" in allowed_headers.lower()


async def test_llmobs_aggregate_options(agent):
    resp = await agent.options("/api/v1/logs-analytics/aggregate", headers=_TEST_ORIGIN_HEADERS)
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == _TEST_ORIGIN


async def test_llmobs_facets_list(agent):
    resp = await agent.get("/api/ui/event-platform/llmobs/facets")
    assert resp.status == 200
    data = await resp.json()
    assert "facets" in data


async def test_llmobs_facets_list_options(agent):
    resp = await agent.options("/api/ui/event-platform/llmobs/facets", headers=_TEST_ORIGIN_HEADERS)
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == _TEST_ORIGIN


async def test_llmobs_trace_options(agent):
    resp = await agent.options("/api/ui/llm-obs/v1/trace/test-trace-id", headers=_TEST_ORIGIN_HEADERS)
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == _TEST_ORIGIN


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
    resp = await agent.options("/api/ui/query/scalar", headers=_TEST_ORIGIN_HEADERS)
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == _TEST_ORIGIN


def _scalar_request(queries, from_ms=None, to_ms=None, formulas=None):
    attrs = {"queries": queries}
    if from_ms is not None:
        attrs["from"] = from_ms
    if to_ms is not None:
        attrs["to"] = to_ms
    if formulas is not None:
        attrs["formulas"] = formulas
    return {"data": [{"type": "scalar_request", "attributes": attrs}]}


async def test_query_scalar_count_no_groupby(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/ui/query/scalar",
        json=_scalar_request(
            [
                {
                    "name": "query1",
                    "data_source": "llm_observability",
                    "indexes": ["llmobs"],
                    "search": {"query": ""},
                    "compute": {"aggregation": "count"},
                }
            ]
        ),
    )
    assert resp.status == 200
    data = await resp.json()
    assert len(data["data"]) == 1
    cols = data["data"][0]["attributes"]["columns"]
    assert len(cols) == 1
    assert cols[0]["type"] == "number"
    assert cols[0]["values"] == [2.0]


async def test_query_scalar_group_by_kind(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/ui/query/scalar",
        json=_scalar_request(
            [
                {
                    "name": "query1",
                    "data_source": "llm_observability",
                    "indexes": ["llmobs"],
                    "search": {"query": ""},
                    "compute": {"aggregation": "count"},
                    "group_by": [{"facet": "@meta.span.kind", "limit": 10, "sort": {"order": "desc"}}],
                }
            ]
        ),
    )
    assert resp.status == 200
    data = await resp.json()
    cols = data["data"][0]["attributes"]["columns"]
    assert len(cols) == 2
    group_col, num_col = cols
    assert group_col["type"] == "group"
    assert group_col["name"] == "@meta.span.kind"
    # Two kinds present in fixture: agent and llm, one span each.
    assert sorted([v[0] for v in group_col["values"]]) == ["agent", "llm"]
    assert num_col["type"] == "number"
    assert num_col["values"] == [1.0, 1.0]


async def test_query_scalar_avg_duration(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/ui/query/scalar",
        json=_scalar_request(
            [
                {
                    "name": "query1",
                    "data_source": "llm_observability",
                    "indexes": ["llmobs"],
                    "compute": {"aggregation": "avg", "metric": "@duration"},
                }
            ]
        ),
    )
    assert resp.status == 200
    data = await resp.json()
    cols = data["data"][0]["attributes"]["columns"]
    assert len(cols) == 1
    # Fixture durations: 5e9 + 2e9 averaged = 3.5e9.
    assert cols[0]["values"] == [3_500_000_000.0]


async def test_query_scalar_ignores_time_window(agent, llmobs_payload):
    # The sibling list/aggregate endpoints return spans regardless of the
    # UI's time window, so the scalar endpoint must do the same — otherwise
    # the LLMObs Sessions table renders rows with blank cost / token columns
    # for any session older than the UI's (short) timeframe.
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/ui/query/scalar",
        json=_scalar_request(
            [
                {
                    "name": "query1",
                    "data_source": "llm_observability",
                    "indexes": ["llmobs"],
                    "compute": {"aggregation": "count"},
                }
            ],
            from_ms=1,
            to_ms=1000,
        ),
    )
    data = await resp.json()
    assert data["data"][0]["attributes"]["columns"][0]["values"] == [2.0]


async def test_query_scalar_search_query_filters(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/ui/query/scalar",
        json=_scalar_request(
            [
                {
                    "name": "query1",
                    "data_source": "llm_observability",
                    "indexes": ["llmobs"],
                    "search": {"query": "@meta.span.kind:llm"},
                    "compute": {"aggregation": "count"},
                }
            ]
        ),
    )
    data = await resp.json()
    assert data["data"][0]["attributes"]["columns"][0]["values"] == [1.0]


async def test_query_scalar_unknown_data_source(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/ui/query/scalar",
        json=_scalar_request(
            [
                {
                    "name": "query1",
                    "data_source": "metrics",
                    "query": "sum:foo{*}",
                    "aggregator": "sum",
                }
            ]
        ),
    )
    assert resp.status == 200
    data = await resp.json()
    cols = data["data"][0]["attributes"]["columns"]
    assert len(cols) == 1
    assert cols[0]["type"] == "number"
    assert cols[0]["values"] == [0.0]


async def test_query_scalar_multi_request(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    body = {
        "data": [
            {
                "type": "scalar_request",
                "attributes": {
                    "queries": [
                        {
                            "name": "query1",
                            "data_source": "llm_observability",
                            "indexes": ["llmobs"],
                            "compute": {"aggregation": "count"},
                        }
                    ]
                },
            },
            {
                "type": "scalar_request",
                "attributes": {
                    "queries": [
                        {
                            "name": "query1",
                            "data_source": "llm_observability",
                            "indexes": ["llmobs"],
                            "compute": {"aggregation": "sum", "metric": "@metrics.total_tokens"},
                        }
                    ]
                },
            },
        ]
    }
    resp = await agent.post("/api/ui/query/scalar", json=body)
    data = await resp.json()
    assert len(data["data"]) == 2
    assert data["data"][0]["attributes"]["columns"][0]["values"] == [2.0]
    # Fixture total_tokens: 30 + 15 = 45.
    assert data["data"][1]["attributes"]["columns"][0]["values"] == [45.0]


async def test_query_scalar_trace_rollup_metric(agent, llmobs_payload):
    # Fixture has 2 spans on the same trace with token counts 30 and 15.
    # @trace.total_tokens rolls up per-trace: sum across spans = 45, but
    # because both spans share trace-123, sum(@trace.total_tokens) over all
    # spans must dedupe to 45 (not 90).
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/ui/query/scalar",
        json=_scalar_request(
            [
                {
                    "name": "query1",
                    "data_source": "llm_observability",
                    "indexes": ["llmobs"],
                    "compute": {"aggregation": "sum", "metric": "@trace.total_tokens"},
                }
            ]
        ),
    )
    data = await resp.json()
    cols = data["data"][0]["attributes"]["columns"]
    assert cols[0]["values"] == [45.0]


async def test_query_scalar_formulas_reference_query(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload)
    resp = await agent.post(
        "/api/ui/query/scalar",
        json=_scalar_request(
            [
                {
                    "name": "q1",
                    "data_source": "llm_observability",
                    "indexes": ["llmobs"],
                    "compute": {"aggregation": "count"},
                }
            ],
            formulas=[{"formula": "q1", "alias": "span_count"}],
        ),
    )
    data = await resp.json()
    cols = data["data"][0]["attributes"]["columns"]
    assert len(cols) == 1
    assert cols[0]["name"] == "span_count"
    assert cols[0]["values"] == [2.0]


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


async def test_llmobs_list_returns_spans_v4(agent, llmobs_payload):
    await _submit_llmobs_payload(agent, llmobs_payload, path="/evp_proxy/v4/api/v2/llmobs")
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


async def test_llmobs_aggregate_group_by_session_id(agent):
    now = int(time.time() * 1_000_000_000)
    session_a_early = {
        "ml_app": "test-app",
        "tags": [],
        "spans": [
            {
                "name": "root-a-early",
                "span_id": "span-a1",
                "trace_id": "trace-a1",
                "parent_id": "undefined",
                "session_id": "session-a",
                "status": "ok",
                "start_ns": now - 2000,
                "duration": 1_000_000,
                "meta": {"span": {"kind": "agent"}},
                "metrics": {},
                "tags": [],
            }
        ],
    }
    session_a_late = {
        "ml_app": "test-app",
        "tags": [],
        "spans": [
            {
                "name": "root-a-late",
                "span_id": "span-a2",
                "trace_id": "trace-a2",
                "parent_id": "undefined",
                "session_id": "session-a",
                "status": "ok",
                "start_ns": now - 1000,
                "duration": 1_000_000,
                "meta": {"span": {"kind": "agent"}},
                "metrics": {},
                "tags": [],
            }
        ],
    }
    session_b = {
        "ml_app": "test-app",
        "tags": [],
        "spans": [
            {
                "name": "root-b",
                "span_id": "span-b1",
                "trace_id": "trace-b1",
                "parent_id": "undefined",
                "session_id": "session-b",
                "status": "ok",
                "start_ns": now,
                "duration": 1_000_000,
                "meta": {"span": {"kind": "agent"}},
                "metrics": {},
                "tags": [],
            }
        ],
    }
    for payload in [session_a_early, session_a_late, session_b]:
        await _submit_llmobs_payload(agent, payload)

    aggregate_query = {
        "aggregate": {
            "groupBy": [
                {
                    "field": {
                        "id": "@session_id",
                        "output": "@session_id",
                        "limit": 50,
                        "sort": {"metric": {"order": "desc", "id": "timestamp:min"}},
                    }
                }
            ],
            "compute": [
                {"total": {"metric": "@trace_id", "output": "@trace_id:earliest", "aggregation": "earliest"}},
                {"total": {"metric": "@trace_id", "output": "@trace_id:latest", "aggregation": "latest"}},
                {"total": {"metric": "count", "output": "count:count", "aggregation": "count"}},
                {
                    "list": {
                        "columns": ["@session_id"],
                        "output": "@session_id:latest",
                        "sort": {"time": {"order": "desc"}},
                    }
                },
            ],
            "search": {"query": "@parent_id:undefined @session_id:*"},
            "indexes": ["llmobs"],
        }
    }
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/aggregate?type=llmobs",
        json=aggregate_query,
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "done"
    assert data["type"] == "aggregate"

    values = data["result"]["values"]
    assert len(values) == 2

    # Groups are sorted desc by latest start_ns; session-b has the most recent span
    session_b_entry = values[0]
    session_a_entry = values[1]

    assert session_b_entry["by"]["@session_id"] == "session-b"
    assert session_b_entry["metrics"]["count:count"] == 1
    assert session_b_entry["metrics"]["@trace_id:earliest"] == "trace-b1"
    assert session_b_entry["metrics"]["@trace_id:latest"] == "trace-b1"
    assert session_b_entry["metrics"]["@session_id:latest"] == [["session-b"]]

    assert session_a_entry["by"]["@session_id"] == "session-a"
    assert session_a_entry["metrics"]["count:count"] == 2
    # earliest = span with the smallest start_ns
    assert session_a_entry["metrics"]["@trace_id:earliest"] == "trace-a1"
    # latest = span with the largest start_ns
    assert session_a_entry["metrics"]["@trace_id:latest"] == "trace-a2"

    paging_sessions = data["result"]["paging"]["after"]["@session_id"]
    assert set(paging_sessions) == {"session-a", "session-b"}


async def test_llmobs_aggregate_includes_copilot_otlp_session(testagent, testagent_url, otlp_http_url):
    now = int(time.time() * 1_000_000_000)
    payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "github-copilot-cli"}},
                        {"key": "service.version", "value": {"stringValue": "1.0.51"}},
                        {"key": "agent.framework", "value": {"stringValue": "github-copilot"}},
                        {"key": "agent.runtime", "value": {"stringValue": "cli"}},
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "github.copilot", "version": "1.0.51"},
                        "spans": [
                            {
                                "traceId": "7aa56cab037f78e3c8b38b628fd67288",
                                "spanId": "027c6f9675520315",
                                "name": "invoke_agent",
                                "kind": 3,
                                "startTimeUnixNano": str(now),
                                "endTimeUnixNano": str(now + 3_700_000_000),
                                "attributes": [
                                    {"key": "gen_ai.operation.name", "value": {"stringValue": "invoke_agent"}},
                                    {"key": "gen_ai.provider.name", "value": {"stringValue": "github"}},
                                    {
                                        "key": "gen_ai.request.model",
                                        "value": {"stringValue": "claude-opus-4.7-1m-internal"},
                                    },
                                    {
                                        "key": "gen_ai.conversation.id",
                                        "value": {"stringValue": "conversation-123"},
                                    },
                                    {"key": "gen_ai.usage.input_tokens", "value": {"intValue": "41531"}},
                                    {"key": "gen_ai.usage.output_tokens", "value": {"intValue": "27"}},
                                    {
                                        "key": "gen_ai.usage.cache_creation.input_tokens",
                                        "value": {"intValue": "41525"},
                                    },
                                    {"key": "github.copilot.cost", "value": {"intValue": "1"}},
                                    {
                                        "key": "github.copilot.interaction_id",
                                        "value": {"stringValue": "interaction-123"},
                                    },
                                ],
                            },
                            {
                                "traceId": "7aa56cab037f78e3c8b38b628fd67288",
                                "spanId": "d9e1aded59245440",
                                "parentSpanId": "027c6f9675520315",
                                "name": "chat claude-opus-4.7-1m-internal",
                                "kind": 3,
                                "startTimeUnixNano": str(now),
                                "endTimeUnixNano": str(now + 3_500_000_000),
                                "attributes": [
                                    {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                                    {"key": "gen_ai.provider.name", "value": {"stringValue": "github"}},
                                    {
                                        "key": "gen_ai.request.model",
                                        "value": {"stringValue": "claude-opus-4.7-1m-internal"},
                                    },
                                    {
                                        "key": "gen_ai.conversation.id",
                                        "value": {"stringValue": "conversation-123"},
                                    },
                                    {"key": "gen_ai.usage.input_tokens", "value": {"intValue": "41531"}},
                                    {"key": "gen_ai.usage.output_tokens", "value": {"intValue": "27"}},
                                    {
                                        "key": "gen_ai.usage.cache_creation.input_tokens",
                                        "value": {"intValue": "41525"},
                                    },
                                    {"key": "github.copilot.cost", "value": {"intValue": "1"}},
                                    {
                                        "key": "github.copilot.interaction_id",
                                        "value": {"stringValue": "interaction-123"},
                                    },
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    resp = await testagent.post(f"{otlp_http_url}/v1/traces", json=payload)
    assert resp.status == 200

    aggregate_query = {
        "aggregate": {
            "groupBy": [
                {
                    "field": {
                        "id": "@session_id",
                        "output": "@session_id",
                        "limit": 50,
                        "sort": {"metric": {"order": "desc", "id": "timestamp:min"}},
                    }
                }
            ],
            "compute": [
                {"total": {"metric": "count", "output": "count:count", "aggregation": "count"}},
                {"total": {"metric": "@trace.input_tokens", "output": "@trace.input_tokens:sum", "aggregation": "sum"}},
                {"total": {"metric": "@trace.output_tokens", "output": "@trace.output_tokens:sum", "aggregation": "sum"}},
                {"total": {"metric": "@trace.total_tokens", "output": "@trace.total_tokens:sum", "aggregation": "sum"}},
                {
                    "total": {
                        "metric": "@trace.estimated_total_cost",
                        "output": "@trace.estimated_total_cost:sum",
                        "aggregation": "sum",
                    }
                },
            ],
            "search": {"query": "@parent_id:undefined @session_id:*"},
            "indexes": ["llmobs"],
        }
    }
    resp = await testagent.post(
        f"{testagent_url}/api/unstable/llm-obs-query-rewriter/aggregate?type=llmobs",
        json=aggregate_query,
    )
    assert resp.status == 200
    data = await resp.json()
    values = data["result"]["values"]
    assert len(values) == 1
    assert values[0]["by"]["@session_id"] == "conversation-123"
    assert values[0]["metrics"]["count:count"] == 1
    assert values[0]["metrics"]["@trace.input_tokens:sum"] == 41531
    assert values[0]["metrics"]["@trace.output_tokens:sum"] == 27
    assert values[0]["metrics"]["@trace.total_tokens:sum"] == 41558
    assert values[0]["metrics"]["@trace.estimated_total_cost:sum"] == 1


def test_copilot_otlp_session_with_multiple_trace_ids_rolls_up_each_trace():
    payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [{"key": "service.name", "value": {"stringValue": "github-copilot-cli"}}]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "traceId": "trace-a",
                                "spanId": "span-a",
                                "name": "chat",
                                "startTimeUnixNano": "100",
                                "endTimeUnixNano": "200",
                                "attributes": [
                                    {"key": "gen_ai.conversation.id", "value": {"stringValue": "conversation-123"}},
                                    {"key": "gen_ai.usage.input_tokens", "value": {"intValue": "10"}},
                                ],
                            },
                            {
                                "traceId": "trace-b",
                                "spanId": "span-b",
                                "name": "chat",
                                "startTimeUnixNano": "300",
                                "endTimeUnixNano": "400",
                                "attributes": [
                                    {"key": "gen_ai.conversation.id", "value": {"stringValue": "conversation-123"}},
                                    {"key": "gen_ai.usage.input_tokens", "value": {"intValue": "20"}},
                                ],
                            },
                        ]
                    }
                ],
            }
        ]
    }

    spans = extract_copilot_spans_from_otlp_traces(payload)
    roots = [span for span in spans if span["parent_id"] == "undefined"]
    trace_aggregates = _build_trace_aggregates(spans)

    assert len(roots) == 2
    assert {root["trace_id"] for root in roots} == {"trace-a", "trace-b"}
    assert {span["parent_id"] for span in spans if span["span_id"] == "span-a"} == {"copilot-session-trace-a"}
    assert {span["parent_id"] for span in spans if span["span_id"] == "span-b"} == {"copilot-session-trace-b"}
    assert sum(trace_aggregates[root["trace_id"]]["input_tokens"] for root in roots) == 30


async def test_llmobs_cors_headers(agent):
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={},
        headers=_TEST_ORIGIN_HEADERS,
    )
    assert resp.headers.get("Access-Control-Allow-Origin") == _TEST_ORIGIN


async def test_llmobs_options(agent):
    resp = await agent.options("/api/unstable/llm-obs-query-rewriter/list", headers=_TEST_ORIGIN_HEADERS)
    assert resp.status == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == _TEST_ORIGIN
    assert "POST" in resp.headers.get("Access-Control-Allow-Methods", "")


# Facet filter query tests


def _create_span_for_facet_test(
    span_id: int,
    trace_id: int,
    ml_app: str = "test-app",
    span_kind: str = "llm",
    duration: int = 1000000000,
) -> dict:  # type: ignore[type-arg]
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


async def test_span_cost_metrics_surfaced_in_list(agent):
    """Span-level estimated cost metrics are passed through to the list response."""
    span = _create_span_for_facet_test(1, 200)
    span["metrics"].update(
        {
            "estimated_input_cost": 3_000_000,
            "estimated_output_cost": 15_000_000,
            "estimated_total_cost": 18_000_000,
        }
    )
    await _submit_spans_for_facet_test(agent, [span])

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": ""}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["hitCount"] == 1

    metrics = data["result"]["events"][0]["event"]["custom"]["metrics"]
    assert metrics["estimated_input_cost"] == 3_000_000
    assert metrics["estimated_output_cost"] == 15_000_000
    assert metrics["estimated_total_cost"] == 18_000_000


async def test_trace_estimated_total_cost_aggregated_across_spans(agent):
    """@trace.estimated_total_cost is the sum of estimated_total_cost across all spans in the trace."""
    span_a = _create_span_for_facet_test(1, 300)
    span_a["metrics"]["estimated_total_cost"] = 10_000_000
    span_b = _create_span_for_facet_test(2, 300)
    span_b["metrics"]["estimated_total_cost"] = 5_000_000
    await _submit_spans_for_facet_test(agent, [span_a, span_b])

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": ""}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()

    # Both spans share trace 300; each should report the aggregated trace total
    for event in data["result"]["events"]:
        assert event["event"]["custom"]["trace"]["estimated_total_cost"] == 15_000_000


async def test_trace_token_metrics_aggregated_across_spans(agent):
    """@trace.input_tokens, output_tokens, and total_tokens are summed across all spans in the trace."""
    span_a = _create_span_for_facet_test(1, 400)
    span_a["metrics"] = {"input_tokens": 10, "output_tokens": 20, "total_tokens": 30}
    span_b = _create_span_for_facet_test(2, 400)
    span_b["metrics"] = {"input_tokens": 5, "output_tokens": 10, "total_tokens": 15}
    await _submit_spans_for_facet_test(agent, [span_a, span_b])

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": ""}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()

    for event in data["result"]["events"]:
        trace = event["event"]["custom"]["trace"]
        assert trace["input_tokens"] == 15
        assert trace["output_tokens"] == 30
        assert trace["total_tokens"] == 45


async def test_trace_level_fields_populated_for_session_query(agent):
    """Trace-level token and cost fields are present for session-id-filtered queries (non-static app path)."""
    now = int(time.time() * 1_000_000_000)
    root_span = {
        "span_id": "span-sess-root",
        "trace_id": "trace-sess-1",
        "parent_id": "undefined",
        "name": "root",
        "status": "ok",
        "start_ns": now,
        "duration": 1_000_000_000,
        "session_id": "session-xyz",
        "tags": ["session_id:session-xyz"],
        "meta": {"span": {"kind": "agent"}},
        "metrics": {
            "input_tokens": 8,
            "output_tokens": 12,
            "total_tokens": 20,
            "estimated_total_cost": 7_000_000,
        },
    }
    child_span = {
        "span_id": "span-sess-child",
        "trace_id": "trace-sess-1",
        "parent_id": "span-sess-root",
        "name": "llm-call",
        "status": "ok",
        "start_ns": now,
        "duration": 500_000_000,
        "session_id": "session-xyz",
        "tags": ["session_id:session-xyz"],
        "meta": {"span": {"kind": "llm"}},
        "metrics": {
            "input_tokens": 4,
            "output_tokens": 6,
            "total_tokens": 10,
            "estimated_total_cost": 3_000_000,
        },
    }
    await _submit_spans_for_facet_test(agent, [root_span, child_span])

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": "@parent_id:undefined @session_id:session-xyz"}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["hitCount"] == 1

    trace = data["result"]["events"][0]["event"]["custom"]["trace"]
    assert trace["input_tokens"] == 12
    assert trace["output_tokens"] == 18
    assert trace["total_tokens"] == 30
    assert trace["estimated_total_cost"] == 10_000_000


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
