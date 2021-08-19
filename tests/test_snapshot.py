import pytest


@pytest.mark.parametrize(
    "params,headers",
    [
        ({"test_session_token": "1234"}, {}),
        ({}, {"X-Datadog-Test-Session-Token": "1234"}),
    ],
)
async def test_snapshot_single_trace_headers(
    agent,
    headers,
    params,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
):
    resp = await agent.get("/test/session-start", params=params, headers=headers)
    assert resp.status == 200, await resp.text()

    v04_reference_http_trace_payload_headers["X-Datadog-Test-Session-Token"] = "1234"
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 200

    resp = await agent.get("/test/session-snapshot", params=params, headers=headers)
    assert resp.status == 200, await resp.text()
