import base64
from typing import cast

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
    assert await resp.json() == v04_reference_http_trace_payload_data_raw

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

    resp = await agent.get("/test/session/traces")
    assert resp.status == 200
    assert await resp.json() == []

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


async def test_session_association_of_untokenized_traces(
    agent, do_reference_v04_http_trace, v04_reference_http_trace_payload_data_raw
):
    """Requests sent without a session token are associated with the session that proceeds it"""
    # Create session A, trace (no token), then create session B => assert the trace belong to A and not B
    resp = await agent.get("/test/session/start", params={"test_session_token": "sessiona"})
    assert resp.status == 200
    await do_reference_v04_http_trace()
    resp = await agent.get("/test/session/start", params={"test_session_token": "sessionb"})
    assert resp.status == 200
    resp_a = await agent.get("/test/session/traces", params={"test_session_token": "sessiona"})
    assert resp_a.status == 200
    a_results = await resp_a.json()
    first_a_trace_id = a_results[0][0]["trace_id"]
    resp_b = await agent.get("/test/session/traces", params={"test_session_token": "sessionb"})
    assert resp_b.status == 200
    b_results = await resp_b.json()
    assert len(a_results) == 1
    assert b_results == []

    #  Create a new trace (no token) and assert that sessions A and B now have a trace
    await do_reference_v04_http_trace()
    resp_a = await agent.get("/test/session/traces", params={"test_session_token": "sessiona"})
    resp_a_results = await resp_a.json()
    assert resp_a.status == 200
    resp_b = await agent.get("/test/session/traces", params={"test_session_token": "sessionb"})
    resp_b_results = await resp_b.json()
    assert resp_b.status == 200
    assert len(resp_a_results) == 1
    assert len(resp_b_results) == 1

    # Recreate session A, generate a "new" trace, and show that the trace for A is new
    resp = await agent.get("/test/session/start", params={"test_session_token": "sessiona"})
    assert resp.status == 200
    v04_reference_http_trace_payload_data_raw[0][0]["trace_id"] = 2
    v04_modified_payload_bytes = cast(bytes, msgpack.packb(v04_reference_http_trace_payload_data_raw))
    await do_reference_v04_http_trace(payload_override=v04_modified_payload_bytes)
    second_resp_a = await agent.get("/test/session/traces", params={"test_session_token": "sessiona"})
    assert second_resp_a.status == 200
    new_a_results = await second_resp_a.json()
    assert len(new_a_results) == 1
    second_a_trace_id = new_a_results[0][0]["trace_id"]
    assert second_a_trace_id == 2
    assert first_a_trace_id != second_a_trace_id


async def test_session_results_with_token_but_no_session_start(
    agent, do_reference_v04_http_trace, v04_reference_http_trace_payload_data_raw
):
    """Requests sent without a session token are associated with the session that proceeds it"""
    await do_reference_v04_http_trace(token="nosessionstart")
    resp = await agent.get("/test/session/traces", params={"test_session_token": "nosessionstart"})
    assert resp.status == 200
    assert await resp.json() == v04_reference_http_trace_payload_data_raw
