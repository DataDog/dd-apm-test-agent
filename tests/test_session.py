import base64

import msgpack
import pytest


@pytest.mark.parametrize(
    "params,headers,trace_token",
    [
        ({}, {}, None),
        ({"test_session_token": "test_case"}, {}, None),
        ({"test_session_token": "test_case"}, {}, "test_case"),
        ({}, {"X-Datadog-Test-Session-Token": "test_case"}, None),
        ({}, {"X-Datadog-Test-Session-Token": "test_case"}, "test_case"),
    ],
)
async def test_synchronous_session_single_trace(
    agent,
    params,
    headers,
    trace_token,
    v04_reference_http_trace_payload_data_raw,
    do_reference_v04_http_trace,
):
    resp = await agent.get("/test/session/start", params=params, headers=headers)
    assert resp.status == 200, await resp.text()

    resp = await do_reference_v04_http_trace(token=trace_token)
    assert resp.status == 200

    resp = await agent.get("/test/session/traces", params=params, headers=headers)
    assert resp.status == 200
    expected = v04_reference_http_trace_payload_data_raw if trace_token is not None or not (params or headers) else []
    assert await resp.json() == expected

    # Clear the traces and make sure there aren't any still stored
    resp = await agent.get("/test/session/clear", params=params, headers=headers)
    assert resp.status == 200
    resp = await agent.get("/test/session/traces", params=params, headers=headers)
    assert resp.status == 200
    assert await resp.json() == []


async def test_concurrent_session(
    agent,
    v04_reference_http_trace_payload_data_raw,
    do_reference_v04_http_trace,
):
    resp = await agent.get("/test/session/start", params={"test_session_token": "test_case"})
    assert resp.status == 200, await resp.text()
    resp = await agent.get("/test/session/start", params={"test_session_token": "test_case2"})
    assert resp.status == 200, await resp.text()

    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200, await resp.text()

    resp = await do_reference_v04_http_trace(token="test_case2")
    assert resp.status == 200, await resp.text()

    for token in ["test_case", "test_case2"]:
        resp = await agent.get("/test/session/traces", params={"test_session_token": token})
        assert resp.status == 200
        result = await resp.json()
        assert result == v04_reference_http_trace_payload_data_raw, result

    resp = await agent.get("/test/session/requests")
    assert resp.status == 200
    assert len(await resp.json()) == 2

    resp = await agent.get("/test/session/clear")
    assert resp.status == 200
    for token in ["test_case", "test_case2"]:
        resp = await agent.get("/test/session/traces", params={"test_session_token": token})
        assert resp.status == 404


async def test_two_sessions(
    agent,
    v04_reference_http_trace_payload_data_raw,
    do_reference_v04_http_trace,
):
    """
    When sessions are run again
        Only the traces for the latest session should be returned.
    """
    resp = await agent.get("/test/session/start", params={"test_session_token": "test_case"})
    assert resp.status == 200, await resp.text()

    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/session/start", params={"test_session_token": "test_case"})
    assert resp.status == 200, await resp.text()

    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/session/traces", params={"test_session_token": "test_case"})
    assert resp.status == 200
    assert await resp.json() == v04_reference_http_trace_payload_data_raw


async def test_session_requests(
    agent,
    do_reference_v04_http_trace,
    do_reference_v06_http_stats,
    do_reference_v2_http_apmtelemetry,
):
    resp = await agent.get("/test/session/start", params={"test_session_token": "test_case"})
    assert resp.status == 200, await resp.text()
    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200, await resp.text()
    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200, await resp.text()
    resp = await do_reference_v06_http_stats(token="test_case")
    assert resp.status == 200, await resp.text()
    resp = await do_reference_v2_http_apmtelemetry(token="test_case")
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/session/requests", params={"test_session_token": "test_case"})
    requests = await resp.json()
    assert resp.status == 200
    assert len(requests) == 4
    assert "X-Datadog-Trace-Count" in requests[0]["headers"]
    body = requests[0]["body"]
    traces = msgpack.unpackb(base64.b64decode(body))
    assert len(traces) == 1
    assert traces[0][0]["name"] == "http.request"
    assert requests[0]["method"] == "PUT"
    assert requests[0]["url"].endswith("/v0.4/traces?test_session_token=test_case")
    assert requests[1]["url"].endswith("/v0.4/traces?test_session_token=test_case")
    assert requests[2]["url"].endswith("/v0.6/stats?test_session_token=test_case")
    assert requests[3]["method"] == "POST"
    assert requests[3]["url"].endswith("/telemetry/proxy/api/v2/apmtelemetry?test_session_token=test_case")


async def test_404_when_session_doesnt_exist(agent):
    """When a session that doesn't exist is requested, we should get an error."""
    resp = await agent.get("/test/session/traces", params={"test_session_token": "nonexistent"})
    assert resp.status == 404


async def test_empty_session_ok(agent):
    """When a session exists but has no traces, we should get an OK with an empty list returned"""
    resp = await agent.get("/test/session/start", params={"test_session_token": "emptysession"})
    assert resp.status == 200
    resp = await agent.get("/test/session/traces", params={"test_session_token": "emptysession"})
    assert resp.status == 200
    assert await resp.json() == []


async def test_session_untagged_requests_use_latest_session(agent, do_reference_v04_http_trace):
    resp = await do_reference_v04_http_trace()
    assert resp.status == 200
    resp = await agent.get("/test/session/start")
    assert resp.status == 200
    resp = await agent.get("/test/session/traces")
    assert await resp.json() == []
    resp = await do_reference_v04_http_trace()
    assert resp.status == 200
    resp = await agent.get("/test/session/traces")
    assert resp.status == 200
    assert len(await resp.json()) == 1


async def test_session_results_with_token_but_no_session_start(
    agent, do_reference_v04_http_trace, v04_reference_http_trace_payload_data_raw
):
    await do_reference_v04_http_trace(token="nosessionstart")
    resp = await agent.get("/test/session/traces", params={"test_session_token": "nosessionstart"})
    assert resp.status == 200
    assert await resp.json() == v04_reference_http_trace_payload_data_raw


async def test_session_token_isolates_reads_and_clear(agent, do_reference_v04_http_trace):
    for token in ("other", "target"):
        resp = await agent.get("/test/session/start", params={"test_session_token": token})
        assert resp.status == 200
    for token in ("target", "other", None):
        resp = await do_reference_v04_http_trace(token=token)
        assert resp.status == 200

    for token in ("target", "other", None):
        params = {"test_session_token": token} if token is not None else {}
        resp = await agent.get("/test/session/requests", params=params)
        assert resp.status == 200
        assert len(await resp.json()) == (3 if token is None else 1)

    resp = await agent.get("/test/session/clear", params={"test_session_token": "target"})
    assert resp.status == 200
    for token, count in (("target", 0), ("other", 1), (None, 2)):
        params = {"test_session_token": token} if token is not None else {}
        resp = await agent.get("/test/session/requests", params=params)
        assert resp.status == 200
        assert len(await resp.json()) == count
