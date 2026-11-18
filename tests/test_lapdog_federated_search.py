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


async def _post_to_server(self_hosted_server, *spans):
    body = {"ml_app": "team", "spans": list(spans)}
    resp = await self_hosted_server.post("/api/v2/llmobs", data=json.dumps(body), headers={"Content-Type": "application/json"})
    assert resp.status == 200


async def _server_has(self_hosted_server, count):
    async def check():
        resp = await self_hosted_server.post(LIST, json={"list": {"limit": 50}})
        return len((await resp.json())["result"]["events"]) == count

    await _wait_for(check)


async def test_aggregate_completes_groups_cut_off_on_one_side(federated, self_hosted_server):
    # Self-hosted's newest group is "mine", but memory's newest is "app", so with one group per side
    # memory's "mine" span (local-1) only counts if it's asked for separately.
    await _post_to_server(self_hosted_server, _span("mate-2", time.time_ns() - 500, ml_app="mine"))
    await _server_has(self_hosted_server, 4)
    resp = await federated.post(
        "/api/v1/logs-analytics/aggregate?type=llmobs",
        json={
            "aggregate": {
                "search": {"query": ""},
                "groupBy": [{"field": {"id": "@ml_app", "output": "ml_app", "limit": 1}}],
                "compute": [
                    {"total": {"aggregation": "count", "output": "c"}},
                    {"total": {"aggregation": "earliest", "metric": "@name", "output": "first"}},
                    {"total": {"aggregation": "latest", "metric": "@name", "output": "last"}},
                ],
            }
        },
    )
    values = (await resp.json())["result"]["values"]
    assert [(v["by"]["ml_app"], v["metrics"]) for v in values] == [
        ("mine", {"c": 3, "first": "local-1", "last": "mate-2"})
    ]


async def test_scalar_max_takes_the_larger_side():
    from lapdog.federated_search import _merge_scalar_columns
    from lapdog.federated_search import _scalar_aggregations

    attributes = {"queries": [{"name": "q", "compute": {"aggregation": "max", "metric": "@duration"}}]}
    column = {"name": "q", "type": "number", "meta": None}
    merged = _merge_scalar_columns(
        [{**column, "values": [5]}], [{**column, "values": [7]}], _scalar_aggregations(attributes)
    )
    assert merged[0]["values"] == [7]


async def test_trace_split_across_both_sides_is_combined(federated, self_hosted_server):
    child = {**_span("remote-child", time.time_ns(), trace_id="trace-local-1"), "parent_id": "local-1"}
    await _post_to_server(self_hosted_server, child)
    await _server_has(self_hosted_server, 4)
    resp = await federated.get("/api/ui/llm-obs/v1/trace/trace-local-1")
    attributes = (await resp.json())["data"]["attributes"]
    assert sorted(attributes["spans"]) == ["local-1", "remote-child"]
    assert attributes["spans"]["local-1"]["children_ids"] == ["remote-child"]
    assert attributes["root_id"] == "local-1"


async def test_paging_continues_from_memory_when_self_hosted_goes_away(federated):
    first = await _list(federated, limit=2)
    assert _ids(first) == ["fwd-2", "mate-1"]
    resp = await federated.post("/lapdog/forwarding", json={"self_hosted": "http://127.0.0.1:9"})
    assert resp.status == 200
    second = await _list(federated, limit=2, paging=first["result"]["paging"])
    assert _ids(second) == ["local-2", "fwd-1"]


async def test_list_accepts_an_inclusive_from_cursor(federated):
    first = await _list(federated, limit=2)
    again = await _list(federated, limit=2, paging={"from": first["result"]["paging"]["after"]})
    assert _ids(again) == ["mate-1", "local-2"]


async def test_paging_keeps_repeated_copies_of_a_span(lapdog_agent, self_hosted_server):
    now = time.time_ns()
    for _ in range(3):
        await _post_to_laptop(lapdog_agent, _span("dup", now - 3_000))
    url = str(self_hosted_server.make_url("")).rstrip("/")
    assert (await lapdog_agent.post("/lapdog/forwarding", json={"self_hosted": url})).status == 200
    await _post_to_laptop(lapdog_agent, _span("new", now - 1_000))
    await _server_has(self_hosted_server, 1)

    seen = []
    paging = None
    for _ in range(10):
        response = await _list(lapdog_agent, limit=2, **({"paging": paging} if paging else {}))
        seen += _ids(response)
        paging = response["result"].get("paging")
        if not paging:
            break
    assert seen == ["new", "dup", "dup", "dup"]
