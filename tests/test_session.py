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


async def test_multi_session(
    agent,
    v04_reference_http_trace_payload_data_raw,
    do_reference_v04_http_trace,
):
    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200, await resp.text()

    resp = await do_reference_v04_http_trace(token="test_case2")
    assert resp.status == 200, await resp.text()

    for token in ["test_case", "test_case2"]:
        resp = await agent.get(
            "/test/session/traces", params={"test_session_token": token}
        )
        assert resp.status == 200
        assert await resp.json() == v04_reference_http_trace_payload_data_raw

    resp = await agent.get("/test/session/traces")
    assert resp.status == 200
    assert await resp.json() == []

    resp = await agent.get("/test/session/clear")
    assert resp.status == 200
    for token in ["test_case", "test_case2"]:
        resp = await agent.get(
            "/test/session/traces", params={"test_session_token": token}
        )
        assert resp.status == 200
        assert await resp.json() == []
