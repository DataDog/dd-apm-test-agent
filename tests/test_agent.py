import json

from ddapm_test_agent.trace import trace_id


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

    tid = trace_id(v04_reference_http_trace_payload_data_raw[0])
    resp = await agent.get("/test/traces", params={"trace_ids": str(tid)})
    assert resp.status == 200
    assert json.loads(await resp.text()) == v04_reference_http_trace_payload_data_raw
    resp = await agent.get("/test/traces")
    assert resp.status == 200
    assert json.loads(await resp.text()) == v04_reference_http_trace_payload_data_raw

    resp = await agent.get("/test/session/clear")
    assert resp.status == 200

    resp = await agent.get("/test/traces", params={"trace_ids": "123456"})
    assert resp.status == 200
    assert await resp.text() == "[[]]"


async def test_trace_clear_token(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
):
    resp = await agent.put(
        "/v0.4/traces",
        params={"test_session_token": "1"},
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/session/clear", params={"test_session_token": "1"})
    assert resp.status == 200

    resp = await agent.get("/test/traces", params={"trace_ids": "123456"})
    assert resp.status == 200
    assert await resp.text() == "[[]]"


async def test_info(agent):
    resp = await agent.get("/info")
    assert resp.status == 200
    assert await resp.json() == {
        "version": "test",
        "endpoints": [
            "/v0.4/traces",
            "/v0.5/traces",
            "/v0.6/stats",
            "/telemetry/proxy/",
            "/v0.7/config",
        ],
        "feature_flags": [],
        "config": {},
        "client_drop_p0s": True,
    }


async def test_apmtelemetry(
    agent,
    v2_reference_http_apmtelemetry_payload_headers,
    v2_reference_http_apmtelemetry_payload_data_raw,
    v2_reference_http_apmtelemetry_payload_data,
):
    resp = await agent.post(
        "/telemetry/proxy/api/v2/apmtelemetry",
        headers=v2_reference_http_apmtelemetry_payload_headers,
        data=v2_reference_http_apmtelemetry_payload_data,
    )
    assert resp.status == 200, await resp.text()

    rid = v2_reference_http_apmtelemetry_payload_data_raw["runtime_id"]
    resp = await agent.get("/test/apmtelemetry", params={"runtime_ids": rid})
    assert resp.status == 200
    assert json.loads(await resp.text()) == [v2_reference_http_apmtelemetry_payload_data_raw]

    resp = await agent.get("/test/apmtelemetry")
    assert resp.status == 200
    assert json.loads(await resp.text()) == [v2_reference_http_apmtelemetry_payload_data_raw]

    resp = await agent.get("/test/session/clear")
    assert resp.status == 200

    resp = await agent.get(
        "/test/apmtelemetry",
        params={"runtime_ids": "e81ece6d-7813-47f2-8337-d342f69626bb"},
    )
    assert resp.status == 200
    assert await resp.text() == "[]"
