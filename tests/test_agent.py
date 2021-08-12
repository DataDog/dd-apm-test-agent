import json


async def test_sync_snapshot_single_trace(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
):
    resp = await agent.get(
        "/test/start",
        headers={
            "X-Datadog-Test-Token": "mytoken",
        },
    )
    assert resp.status == 200, await resp.text()

    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/session-snapshot", params={"token": "mytoken"})
    assert resp.status == 200, await resp.text()


async def test_trace(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
    v04_reference_http_trace_payload_data_raw,
):
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/traces", params={"trace_ids": "1234"})
    assert resp.status == 200
    assert json.loads(await resp.text()) == v04_reference_http_trace_payload_data_raw
