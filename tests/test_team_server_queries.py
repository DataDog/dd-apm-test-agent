"""Differential tests: ClickHouse SQL search must match the in-memory query evaluator.

Every query runs through ``apply_filters`` on the remapped spans and through
``lapdog server``'s list endpoint; the matched span IDs must be the same.
"""

import copy
import json
import time

import pytest

from lapdog.llmobs_event_platform import apply_filters
from lapdog.llmobs_event_platform import extract_spans_from_events
from lapdog.llmobs_event_platform import get_span_field_value
from lapdog.llmobs_event_platform import parse_filter_query
from lapdog.team_server.sql import like_pattern

NOW_NS = time.time_ns()

SPANS = [
    {
        "name": "llm-call-1",
        "span_id": "span-1",
        "status": "ok",
        "duration": 1_500_000_000,
        "meta": {
            "model_name": "gpt-4",
            "model_provider": "openai",
            "span": {"kind": "llm"},
            "input": {"value": "What is the Weather?"},
            "output": {"messages": [{"content": "Sunny with a chance of meatballs"}]},
        },
        "metrics": {"tokens": 1000, "input_tokens": 10},
        "tags": ["env:prod", "service:api", "version:1.0", "user:alice", "user:bob"],
    },
    {
        "name": "llm-call-2",
        "span_id": "span-2",
        "status": "error",
        "duration": 500_000_000,
        "meta": {
            "model_name": "gpt-3.5-turbo",
            "model_provider": "openai",
            "span": {"kind": "llm"},
            "error": {"message": "rate limited"},
        },
        "metrics": {"tokens": 500, "input_tokens": 0},
        "tags": ["env:staging", "service:web", "version:1.0"],
        "session_id": "sess-a",
    },
    {
        "name": "agent-workflow",
        "span_id": "span-3",
        "parent_id": "0",
        "status": "ok",
        "duration": 3_000_000_000,
        "meta": {"span": {"kind": "agent"}, "metadata": {"model_name": "claude-x", "team": "core"}},
        "metrics": {"tokens": 2000},
        "tags": ["env:prod", "service:api", "version:2.0", "session_id:sess-b"],
    },
    {
        "name": "embedding-call",
        "span_id": "span-4",
        "parent_id": "span-3",
        "status": "ok",
        "duration": 200_000_000,
        "meta": {
            "model_name": "text-embedding-ada-002",
            "model_provider": "openai",
            "span": {"kind": "embedding"},
        },
        "metrics": {"tokens": 100.5},
        "tags": ["env:dev", "service:api", "path:a_b%c"],
    },
    {
        "name": "tool 100%",
        "span_id": "span-5",
        "parent_id": "span-3",
        "duration": 7,
        "meta": {"span.kind": "tool", "input": {"value": {"query": "AND or not"}}},
        "tags": ["env:dev", "ml_app:tagged-app"],
    },
]

QUERIES = [
    # From test_llmobs_query_parser.py
    "@meta.model_name:gpt-4",
    "env:prod",
    "env:prod service:api",
    "@meta.model_name:gpt*",
    "@meta.model_name:gpt-?",
    "env:prod AND service:api",
    "env:prod OR env:staging",
    "-env:dev",
    "NOT env:dev",
    "env:prod AND -service:web",
    "(env:prod OR env:staging) AND service:api",
    "(env:prod OR env:staging) AND (@status:error OR version:2.0)",
    "((env:prod OR env:staging) AND service:api) OR env:dev",
    "@duration:>1000000000",
    "@metrics.tokens:<=1000",
    "@duration:[500000000 TO 2000000000]",
    "_exists_:@meta.model_name",
    "_missing_:@meta.model_name",
    "@status IN [error, warning]",
    "env:prod AND @status:error AND -service:web",
    "(service:api OR service:web) AND @duration:>1000000000",
    "(@meta.model_name:gpt-3* OR @meta.model_name:text*) AND (env:prod OR env:staging)",
    "(env:prod OR env:staging) AND @metrics.tokens:>500",
    "",
    "env:production",
    "env:prod OR env:staging OR env:dev OR env:test",
    "env:prod AND env:staging",
    "@meta.model_name:GPT-4",
    "@meta.model_name:GPT*",
    "agent",
    "staging",
    "nonexistent",
    '"llm-call"',
    "llm-call @status:error",
    "AGENT",
    "@model_name",
    "@model_name gpt-4",
    # Fields, defaults, and edge cases
    "@meta.span.kind:llm",
    "@meta.span.kind:tool",
    "@parent_id:undefined",
    "@parent_id:span-3",
    "@status:ok",
    "@ml_app:tagged-app",
    "ml_app:tagged-app",
    "@session_id:sess-a",
    "@session_id:sess-b",
    "@session_id:*",
    "_exists_:session_id",
    "@duration:>=3s",
    "@duration:[100ms TO 1s]",
    "@duration:[* TO 1s]",
    "@metrics.tokens:[* TO 600]",
    "@metrics.tokens:100.5",
    "@metrics.input_tokens:0",
    "@metrics.input_tokens:>=0",
    "_exists_:@metrics.input_tokens",
    "@meta.metadata.team:core",
    "@meta.model_name:claude-x",
    "@meta.error.message:rate*",
    "user:alice",
    "user:bob",
    "path:a_b%c",
    "path:a?b*",
    "@name:*100%",
    "weather",
    "meatballs",
    "chance",
    "@event_type:span",
    "version:1.0 -user:alice",
    "service IN [web, api]",
    "@timestamp:>0",
    "@bogus env:prod",
    "env:prod @bogus",
]


def _ids(spans):
    return sorted(span["span_id"] for span in spans)


@pytest.fixture
def remapped_spans():
    events = [{"ml_app": "test-app", "spans": copy.deepcopy(SPANS)}]
    spans = extract_spans_from_events(events)
    for i, span in enumerate(spans):
        span["start_ns"] = NOW_NS - i * 1_000_000
        span["trace_id"] = "trace-1" if i < 3 else "trace-2"
    return spans


@pytest.fixture
async def server(team_server, remapped_spans):
    payload = {"ml_app": "test-app", "spans": copy.deepcopy(remapped_spans)}
    resp = await team_server.post(
        "/api/v2/llmobs", data=json.dumps(payload), headers={"Content-Type": "application/json"}
    )
    assert resp.status == 200, await resp.text()
    return team_server


async def _list_ids(server, query):
    resp = await server.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"limit": 100, "search": {"query": query}}},
    )
    assert resp.status == 200, await resp.text()
    return sorted(event["id"] for event in (await resp.json())["result"]["events"])


@pytest.mark.parametrize("query", QUERIES)
async def test_search_matches_in_memory(server, remapped_spans, query):
    expected = _ids(apply_filters(remapped_spans, parse_filter_query(query)))
    if query in ("user:bob",):
        # In memory only the first ``user:`` tag is compared; SQL does the same.
        assert expected == []
    assert await _list_ids(server, query) == expected


@pytest.mark.parametrize(
    "field",
    [
        "env",
        "service",
        "@meta.span.kind",
        "@status",
        "@ml_app",
        "@session_id",
        "@meta.model_name",
        "user",
        "@parent_id",
    ],
)
async def test_facet_values_match_in_memory(server, remapped_spans, field):
    counts = {}
    for span in remapped_spans:
        value = get_span_field_value(span, field.lstrip("@"))
        if value is not None:
            counts[str(value)] = counts.get(str(value), 0) + 1
    resp = await server.post(
        "/api/unstable/llm-obs-query-rewriter/facet_info", json={"facet_info": {"path": field, "limit": 50}}
    )
    fields = (await resp.json())["result"]["fields"]
    assert {f["field"]: f["value"] for f in fields} == counts


@pytest.mark.parametrize(
    "aggregation,metric",
    [
        ("count", None),
        ("sum", "@duration"),
        ("avg", "@metrics.tokens"),
        ("max", "@duration"),
        ("min", "@duration"),
        ("median", "@duration"),
        ("pc90", "@duration"),
        ("cardinality", "@meta.model_name"),
        ("latest", "@duration"),
        ("earliest", "@duration"),
        ("sum", "@trace.total_tokens"),
    ],
)
async def test_scalar_matches_in_memory(server, remapped_spans, aggregation, metric):
    from lapdog.llmobs_event_platform import _build_scalar_columns
    from lapdog.llmobs_event_platform import _build_trace_aggregates

    query = {"data_source": "llm_observability", "compute": {"aggregation": aggregation, "metric": metric}}
    ordered = sorted(remapped_spans, key=lambda s: s["start_ns"], reverse=True)
    expected = _build_scalar_columns(ordered, [query], [], trace_aggregates=_build_trace_aggregates(ordered))
    resp = await server.post(
        "/api/ui/query/scalar", json={"data": [{"type": "scalar_request", "attributes": {"queries": [query]}}]}
    )
    columns = (await resp.json())["data"][0]["attributes"]["columns"]
    assert columns[0]["values"] == pytest.approx(expected[0]["values"])


async def test_scalar_group_by_matches_in_memory(server, remapped_spans):
    from lapdog.llmobs_event_platform import _build_scalar_columns
    from lapdog.llmobs_event_platform import _build_trace_aggregates

    queries = [
        {
            "name": "a",
            "data_source": "llm_observability",
            "compute": {"aggregation": "sum", "metric": "@duration"},
            "group_by": [{"facet": "@meta.span.kind", "limit": 10, "sort": {"order": "desc"}}],
        },
        {"name": "b", "data_source": "llm_observability", "compute": {"aggregation": "count"}},
    ]
    ordered = sorted(remapped_spans, key=lambda s: s["start_ns"], reverse=True)
    expected = _build_scalar_columns(ordered, queries, [], trace_aggregates=_build_trace_aggregates(ordered))
    resp = await server.post(
        "/api/ui/query/scalar", json={"data": [{"type": "scalar_request", "attributes": {"queries": queries}}]}
    )
    assert (await resp.json())["data"][0]["attributes"]["columns"] == expected


@pytest.mark.parametrize(
    "pattern,like",
    [("gpt*", "gpt%"), ("a?b", "a_b"), ("100%", "100\\%"), ("a_b", "a\\_b"), ("back\\slash", "back\\\\slash")],
)
def test_like_pattern(pattern, like):
    assert like_pattern(pattern) == like
