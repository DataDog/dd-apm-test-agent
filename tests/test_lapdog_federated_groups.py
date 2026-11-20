"""Exercise group discovery over HTTP without requiring a ClickHouse binary."""

import time
from types import SimpleNamespace

from aiohttp import web
import pytest

from ddapm_test_agent.agent import Agent
from lapdog.llmobs_event_platform import LLMObsEventPlatformAPI

from .test_lapdog_federated_search import _span


@pytest.fixture
async def grouped_search(lapdog_agent, aiohttp_server, monkeypatch):
    local_spans, remote_spans, requests = [], [], []
    state = SimpleNamespace(fail_after=None)
    local_api = lapdog_agent.app["llmobs_event_platform_api"]
    remote_api = LLMObsEventPlatformAPI(Agent())
    monkeypatch.setattr(local_api._memory, "get_llmobs_spans", lambda token=None: local_spans)
    monkeypatch.setattr(remote_api._memory, "get_llmobs_spans", lambda token=None: remote_spans)

    @web.middleware
    async def record(request, handler):
        if request.method == "POST":
            body = await request.json()
            requests.append(body)
            if "facet_info" in body:
                limit = body["facet_info"]["limit"]
            else:
                limit = body["data"][0]["attributes"]["queries"][0]["group_by"][0]["limit"]
            if state.fail_after is not None and limit > state.fail_after:
                return web.json_response({}, status=503)
        return await handler(request)

    async def info(request):
        return web.json_response({"mode": "server"})

    app = web.Application(middlewares=[record])
    app.add_routes(remote_api.get_routes())
    app.router.add_get("/info", info)
    server = await aiohttp_server(app)
    lapdog_agent.app["lapdog_forwarding"].configure_self_hosted(str(server.make_url("")).rstrip("/"), False)
    return SimpleNamespace(client=lapdog_agent, local=local_spans, remote=remote_spans, requests=requests, state=state)


def _group(prefix, name, count, duration=1000):
    now = time.time_ns()
    return [
        {**_span(f"{prefix}-{i}", now - i, ml_app=name), "ml_app": name, "duration": duration} for i in range(count)
    ]


async def _groups(client, endpoint, limit, term="", aggregation="count", order="desc", formulas=False):
    if endpoint == "facet":
        path = "/api/unstable/llm-obs-query-rewriter/facet_info"
        body = {"facet_info": {"path": "@ml_app", "limit": limit, "termSearch": {"query": term}}}
    else:
        path = "/api/ui/query/scalar"
        query = {
            "name": "q",
            "data_source": "llm_observability",
            "compute": {"aggregation": aggregation, "metric": "@duration"},
            "group_by": [{"facet": "@ml_app", "limit": limit, "sort": {"order": order}}],
        }
        attributes = {"queries": [query]}
        if formulas:
            attributes["queries"].append({**query, "name": "count", "compute": {"aggregation": "count"}})
            attributes["formulas"] = [{"formula": "count"}, {"formula": "q"}]
        body = {"data": [{"attributes": attributes}]}
    response = await client.post(path, json=body)
    assert response.status == 200, await response.text()
    data = await response.json()
    if endpoint == "facet":
        return [(field["field"], field["value"]) for field in data["result"]["fields"]]
    columns = data["data"][0]["attributes"]["columns"]
    groups = next(column for column in columns if column["type"] == "group")
    numbers = next(column for column in columns if column["name"] == "q")
    assert all(not column["name"].startswith("__lapdog_") for column in columns)
    return list(zip((value[0] for value in groups["values"]), numbers["values"]))


@pytest.mark.parametrize("endpoint", ["facet", "scalar"])
@pytest.mark.parametrize("winner", ["winner", 'quoted"value\\', ""])
@pytest.mark.parametrize("competitors", [21, 85])
async def test_winner_outside_both_candidate_windows(grouped_search, endpoint, winner, competitors):
    fixture = grouped_search
    for i in range(competitors):
        fixture.local.extend(_group(f"local-{i}", f"local-{i}", 6))
        fixture.remote.extend(_group(f"remote-{i}", f"remote-{i}", 6))
    fixture.local.extend(_group("local-winner", winner, 5))
    fixture.remote.extend(_group("remote-winner", winner, 5))

    for limit in (1, 2):
        groups = await _groups(fixture.client, endpoint, limit)
        assert groups[0] == (winner, 10)
        assert len(groups) == limit


@pytest.mark.parametrize("order,winner_duration", [("desc", 6), ("asc", 4)])
@pytest.mark.parametrize("formulas", [False, True])
async def test_scalar_ranking_uses_complete_averages(grouped_search, order, winner_duration, formulas):
    fixture = grouped_search
    for i in range(21):
        for prefix, local_duration, remote_duration in (("a", 10, 0), ("b", 0, 10)):
            name = f"{prefix}-{i}"
            fixture.local.extend(_group(f"local-{name}", name, 1, local_duration))
            fixture.remote.extend(_group(f"remote-{name}", name, 1, remote_duration))
    fixture.local.extend(_group("local-winner", "winner", 1, winner_duration))
    fixture.remote.extend(_group("remote-winner", "winner", 1, winner_duration))

    groups = await _groups(fixture.client, "scalar", 1, aggregation="avg", order=order, formulas=formulas)
    assert groups == [("winner", winner_duration)]


async def test_facet_term_does_not_hide_truncated_candidates(grouped_search):
    fixture = grouped_search
    for i in range(21):
        fixture.local.extend(_group(f"local-{i}", f"other-local-{i}", 6))
        fixture.remote.extend(_group(f"remote-{i}", f"other-remote-{i}", 6))
    fixture.local.extend(_group("local-winner", "match-winner", 5))
    fixture.remote.extend(_group("remote-winner", "match-winner", 5))

    assert await _groups(fixture.client, "facet", 1, term="MATCH") == [("match-winner", 10)]


@pytest.mark.parametrize("endpoint", ["facet", "scalar"])
async def test_remote_only_search_does_not_expand_all_groups(grouped_search, endpoint):
    fixture = grouped_search
    for i in range(85):
        fixture.remote.extend(_group(f"remote-{i}", f"remote-{i}", 1))
    fixture.remote.extend(_group("remote-winner", "winner", 3))

    assert await _groups(fixture.client, endpoint, 1) == [("winner", 3)]
    assert len(fixture.requests) == 1


async def test_group_expansion_preserves_other_scalar_requests(grouped_search):
    fixture = grouped_search
    for i in range(21):
        fixture.local.extend(_group(f"local-{i}", f"local-{i}", 6))
        fixture.remote.extend(_group(f"remote-{i}", f"remote-{i}", 6))
    fixture.local.extend(_group("local-winner", "winner", 5))
    fixture.remote.extend(_group("remote-winner", "winner", 5))
    query = {"name": "q", "data_source": "llm_observability", "compute": {"aggregation": "count"}}
    body = {
        "data": [
            {"attributes": {"queries": [{**query, "group_by": [{"facet": "@ml_app", "limit": 1}]}]}},
            {"attributes": {"queries": [query]}},
            None,
        ]
    }

    response = await fixture.client.post("/api/ui/query/scalar", json=body)
    assert response.status == 200, await response.text()
    data = (await response.json())["data"]
    columns = data[0]["attributes"]["columns"]
    assert [(column["name"], column["values"]) for column in columns] == [("@ml_app", [["winner"]]), ("q", [10])]
    assert data[1]["attributes"]["columns"][0]["values"] == [262]
    assert all(item["attributes"]["columns"] == [] for item in data[2:])


@pytest.mark.parametrize("endpoint", ["facet", "scalar"])
async def test_failure_during_group_expansion_falls_back_to_memory(grouped_search, endpoint):
    fixture = grouped_search
    for i in range(22):
        fixture.local.extend(_group(f"local-{i}", f"local-{i}", 1))
        fixture.remote.extend(_group(f"remote-{i}", f"remote-{i}", 1))
    fixture.local.extend(_group("local-winner", "local-winner", 3))
    fixture.state.fail_after = 21

    assert await _groups(fixture.client, endpoint, 1) == [("local-winner", 3)]
    assert len(fixture.requests) == 2
