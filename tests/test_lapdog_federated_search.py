"""Searches through a local lapdog that forwards to a real Self-hosted server cover both, without duplicates."""

import asyncio
import json
import time

import msgpack
import pytest

LIST = "/api/unstable/llm-obs-query-rewriter/list?type=llmobs"


def _span(span_id, start_ns, trace_id=None, ml_app="app"):
    return {
        "span_id": span_id,
        "trace_id": trace_id or f"trace-{span_id}",
        "parent_id": "undefined",
        "name": span_id,
        "start_ns": start_ns,
        "duration": 1_000,
        "meta": {"span": {"kind": "llm"}},
        "metrics": {"input_tokens": 10},
        "tags": [f"ml_app:{ml_app}"],
    }


async def _post_to_laptop(lapdog_agent, *spans):
    body = msgpack.packb({"_dd.stage": "raw", "event_type": "span", "spans": list(spans)})
    resp = await lapdog_agent.post(
        "/evp_proxy/v2/api/v2/llmobs", headers={"Content-Type": "application/msgpack"}, data=body
    )
    assert resp.status == 200


async def _wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not await predicate():
        assert time.monotonic() < deadline, "timed out waiting"
        await asyncio.sleep(0.05)


@pytest.fixture
async def federated(lapdog_agent, self_hosted_server):
    """Return a local lapdog with spans in three places.

    - ``local-*``: received before Self-hosted forwarding was on, so only in memory;
    - ``fwd-*``: received after, so forwarded (and read from the Self-hosted server);
    - ``mate-*``: sent straight to the Self-hosted server by a teammate.
    """
    now = time.time_ns()
    await _post_to_laptop(lapdog_agent, _span("local-1", now - 5_000, ml_app="mine"), _span("local-2", now - 3_000))
    url = str(self_hosted_server.make_url("")).rstrip("/")
    resp = await lapdog_agent.post("/lapdog/forwarding", json={"self_hosted": url})
    assert resp.status == 200
    await _post_to_laptop(lapdog_agent, _span("fwd-1", now - 4_000, ml_app="mine"), _span("fwd-2", now - 1_000))
    mate = {"ml_app": "team", "spans": [_span("mate-1", now - 2_000, ml_app="team")]}
    resp = await self_hosted_server.post("/api/v2/llmobs", data=json.dumps(mate), headers={"Content-Type": "application/json"})
    assert resp.status == 200

    async def stored_on_server():
        resp = await self_hosted_server.post(LIST, json={"list": {"limit": 10}})
        return len((await resp.json())["result"]["events"]) == 3

    await _wait_for(stored_on_server)
    return lapdog_agent


async def _list(client, **list_params):
    resp = await client.post(LIST, json={"list": {"limit": 50, **list_params}})
    assert resp.status == 200, await resp.text()
    return await resp.json()


def _ids(response):
    return [e["event"]["custom"]["span_id"] for e in response["result"]["events"]]


async def test_list_merges_memory_and_self_hosted(federated):
    response = await _list(federated)
    assert _ids(response) == ["fwd-2", "mate-1", "local-2", "fwd-1", "local-1"]
    assert response["hitCount"] == 5


async def test_list_pages_across_both_sides(federated):
    seen = []
    paging = None
    for _ in range(10):
        params = {"limit": 2, **({"paging": paging} if paging else {})}
        response = await _list(federated, **params)
        seen += _ids(response)
        paging = response["result"].get("paging")
        if not paging:
            break
    assert seen == ["fwd-2", "mate-1", "local-2", "fwd-1", "local-1"]


async def test_stored_list_result_can_be_fetched_again(federated):
    response = await _list(federated)
    again = await federated.get(f"/api/unstable/llm-obs-query-rewriter/list/{response['requestId']}")
    assert _ids(await again.json()) == _ids(response)


async def test_aggregate_and_facets_add_up(federated):
    resp = await federated.post(
        "/api/v1/logs-analytics/aggregate?type=llmobs",
        json={
            "aggregate": {
                "search": {"query": ""},
                "groupBy": [{"field": {"id": "@ml_app", "output": "ml_app", "limit": 10}}],
                "compute": [{"total": {"aggregation": "count", "output": "c"}}],
            }
        },
    )
    values = (await resp.json())["result"]["values"]
    assert {v["by"]["ml_app"]: v["metrics"]["c"] for v in values} == {"mine": 2, "app": 2, "team": 1}

    resp = await federated.post(
        "/api/unstable/llm-obs-query-rewriter/facet_info",
        json={"facet_info": {"path": "@ml_app", "limit": 10, "search": {"query": ""}}},
    )
    fields = (await resp.json())["result"]["fields"]
    assert {f["field"]: f["value"] for f in fields} == {"mine": 2, "app": 2, "team": 1}


async def test_scalar_counts_add_up(federated):
    query = {
        "name": "query1",
        "data_source": "llm_observability",
        "search": {"query": ""},
        "compute": {"aggregation": "count"},
    }
    resp = await federated.post("/api/ui/query/scalar", json={"data": [{"attributes": {"queries": [query]}}]})
    columns = (await resp.json())["data"][0]["attributes"]["columns"]
    assert columns[0]["values"] == [5]


async def test_traces_come_from_whichever_side_has_them(federated):
    for trace_id, span_id in (("trace-local-1", "local-1"), ("trace-mate-1", "mate-1"), ("trace-fwd-1", "fwd-1")):
        resp = await federated.get(f"/api/ui/llm-obs/v1/trace/{trace_id}")
        assert resp.status == 200, trace_id
        spans = (await resp.json())["data"]["attributes"]["spans"]
        assert [s["span_id"] for s in spans.values()] == [span_id]


async def test_unreachable_self_hosted_falls_back_to_memory(federated):
    resp = await federated.post("/lapdog/forwarding", json={"self_hosted": "http://127.0.0.1:9"})
    assert resp.status == 200
    response = await _list(federated)
    # Memory still has everything this lapdog received, including what it forwarded.
    assert sorted(_ids(response)) == ["fwd-1", "fwd-2", "local-1", "local-2"]


def _sources(response):
    return {e["event"]["custom"]["span_id"]: e["event"]["custom"]["lapdog"] for e in response["result"]["events"]}


async def test_list_labels_where_each_span_was_read_from(federated):
    sources = _sources(await _list(federated))
    assert sources == {
        "fwd-2": {"source": "self-hosted"},
        "mate-1": {"source": "self-hosted"},
        "local-2": {"source": "laptop"},
        "fwd-1": {"source": "self-hosted"},
        "local-1": {"source": "laptop"},
    }


async def test_list_is_labelled_without_self_hosted(lapdog_agent):
    now = time.time_ns()
    await _post_to_laptop(lapdog_agent, _span("a", now - 2_000), _span("b", now - 1_000))
    first = await _list(lapdog_agent, limit=1)
    assert _sources(first) == {"b": {"source": "laptop"}}
    second = await _list(lapdog_agent, limit=1, paging=first["result"]["paging"])
    assert _sources(second) == {"a": {"source": "laptop"}}
    assert "paging" not in second["result"]
