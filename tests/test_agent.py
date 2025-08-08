import msgpack
import json
import os
import signal
import subprocess
import time

from ddapm_test_agent.trace import decode_v1, trace_id


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


async def test_trace_agent_sample_rate(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
):
    agent_rates = {"service:test,env:staging": 0.5}
    resp = await agent.get(
        "/test/session/start",
        params={"test_session_token": "1", "agent_sample_rate_by_service": json.dumps(agent_rates)},
    )
    assert resp.status == 200, await resp.text()
    resp = await agent.put(
        "/v0.4/traces",
        params={"test_session_token": "1"},
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 200, await resp.text()
    assert await resp.json() == {"rate_by_service": {"service:test,env:staging": 0.5}}


async def test_info(agent):
    resp = await agent.get("/info")
    assert resp.status == 200
    assert await resp.json() == {
        "version": "test",
        "endpoints": [
            "/v0.4/traces",
            "/v0.5/traces",
            "/v0.7/traces",
            "/v0.6/stats",
            "/telemetry/proxy/",
            "/v0.7/config",
            "/tracer_flare/v1",
            "/evp_proxy/v2/",
        ],
        "peer_tags": [
            "db.name",
            "mongodb.db",
            "messaging.system",
        ],
        "feature_flags": [],
        "config": {},
        "client_drop_p0s": True,
        "span_events": True,
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


async def test_get_trace_check_summary_full_results_and_clear(
    agent, v04_reference_http_trace_payload_data, v04_reference_http_trace_payload_headers
):
    expected_output = {
        "trace_stall": {"Passed_Checks": 3, "Failed_Checks": 0, "Skipped_Checks": 0},
        "meta_tracer_version_header": {"Passed_Checks": 3, "Failed_Checks": 0, "Skipped_Checks": 0},
        "trace_content_length": {"Passed_Checks": 3, "Failed_Checks": 0, "Skipped_Checks": 0},
        "trace_count_header": {"Passed_Checks": 3, "Failed_Checks": 0, "Skipped_Checks": 0},
    }
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    v04_reference_http_trace_payload_headers["X-Datadog-Test-Session-Token"] = "other"
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )

    response = await agent.get("/test/trace_check/summary?return_all=true")
    assert response.status == 200
    assert await response.json() == expected_output


async def test_get_trace_check_summary_partial_results(
    agent, v04_reference_http_trace_payload_data, v04_reference_http_trace_payload_headers
):
    expected_output = {
        "trace_stall": {"Passed_Checks": 1, "Failed_Checks": 0, "Skipped_Checks": 0},
        "meta_tracer_version_header": {"Passed_Checks": 1, "Failed_Checks": 0, "Skipped_Checks": 0},
        "trace_content_length": {"Passed_Checks": 1, "Failed_Checks": 0, "Skipped_Checks": 0},
        "trace_count_header": {"Passed_Checks": 1, "Failed_Checks": 0, "Skipped_Checks": 0},
    }
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    v04_reference_http_trace_payload_headers["X-Datadog-Test-Session-Token"] = "token123"
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    response = await agent.get("/test/trace_check/summary", headers={"X-Datadog-Test-Session-Token": "token123"})
    assert response.status == 200
    assert await response.json() == expected_output


async def test_get_trace_check_summary_no_results(
    agent, v04_reference_http_trace_payload_data, v04_reference_http_trace_payload_headers
):
    expected_output = {}
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    response = await agent.get(
        "/test/trace_check/summary?return_all=false", headers={"X-Datadog-Test-Session-Token": "token123"}
    )
    assert response.status == 200
    assert await response.json() == expected_output


async def test_get_trace_check_results_and_clear(
    agent, v04_reference_http_trace_payload_data, v04_reference_http_trace_payload_headers
):
    expected_output = {
        "trace_stall": {"Passed_Checks": 4, "Failed_Checks": 0, "Skipped_Checks": 0},
        "meta_tracer_version_header": {"Passed_Checks": 4, "Failed_Checks": 0, "Skipped_Checks": 0},
        "trace_content_length": {"Passed_Checks": 4, "Failed_Checks": 0, "Skipped_Checks": 0},
        "trace_count_header": {"Passed_Checks": 0, "Failed_Checks": 4, "Skipped_Checks": 0},
    }
    v04_reference_http_trace_payload_headers["X-Datadog-Trace-Count"] = "2"
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    v04_reference_http_trace_payload_headers["X-Datadog-Test-Session-Token"] = "other"
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    v04_reference_http_trace_payload_headers["X-Datadog-Test-Session-Token"] = "other2"
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )

    response = await agent.get("/test/trace_check/summary?return_all=true")
    assert response.status == 200
    assert await response.json() == expected_output

    response = await agent.get("/test/trace_check/summary?return_all=true")
    assert response.status == 200
    assert await response.json() == expected_output

    response = await agent.get("/test/trace_check/clear?test_session_token=other")
    assert response.status == 200

    response = await agent.get("/test/trace_check/summary?return_all=true")
    assert response.status == 200
    response_json = await response.json()
    assert response_json["trace_count_header"]["Failed_Checks"] == 2

    response = await agent.get("/test/trace_check/clear?clear_all=true")
    assert response.status == 200

    response = await agent.get("/test/trace_check/summary?return_all=true")
    assert response.status == 200
    response_json = await response.json()
    assert response_json == {}


async def test_get_trace_failures_and_clear_json(
    agent, v04_reference_http_trace_payload_data, v04_reference_http_trace_payload_headers
):
    results = {
        "trace_count_header": [
            "At request <Request PUT /v0.4/traces >:\n   At headers:\n    - {'Accept': '*/*',\n     'Accept-Encoding': 'gzip, deflate',\n     'Content-Length': '371',\n     'Content-Type': 'application/msgpack',\n     'Datadog-Meta-Tracer-Version': 'v0.1',\n     'Host': '127.0.0.1:.*',\n     'User-Agent': 'Python/3.11 aiohttp/3.8.4',\n     'X-Datadog-Trace-Count': '2'}\n    At payload (1 traces):\n    ❌ Check 'trace_count_header' failed: X-Datadog-Trace-Count value (2) does not match actual number of traces (1)\n",
            "At request <Request PUT /v0.4/traces >:\n   At headers:\n    - {'Accept': '*/*',\n     'Accept-Encoding': 'gzip, deflate',\n     'Content-Length': '371',\n     'Content-Type': 'application/msgpack',\n     'Datadog-Meta-Tracer-Version': 'v0.1',\n     'Host': '127.0.0.1:.*',\n     'User-Agent': 'Python/3.11 aiohttp/3.8.4',\n     'X-Datadog-Test-Session-Token': 'other',\n     'X-Datadog-Trace-Count': '2'}\n    At payload (1 traces):\n    ❌ Check 'trace_count_header' failed: X-Datadog-Trace-Count value (2) does not match actual number of traces (1)\n",
            "At request <Request PUT /v0.4/traces >:\n   At headers:\n    - {'Accept': '*/*',\n     'Accept-Encoding': 'gzip, deflate',\n     'Content-Length': '371',\n     'Content-Type': 'application/msgpack',\n     'Datadog-Meta-Tracer-Version': 'v0.1',\n     'Host': '127.0.0.1:.*',\n     'User-Agent': 'Python/3.11 aiohttp/3.8.4',\n     'X-Datadog-Test-Session-Token': 'other',\n     'X-Datadog-Trace-Count': '2'}\n    At payload (1 traces):\n    ❌ Check 'trace_count_header' failed: X-Datadog-Trace-Count value (2) does not match actual number of traces (1)\n",
            "At request <Request PUT /v0.4/traces >:\n   At headers:\n    - {'Accept': '*/*',\n     'Accept-Encoding': 'gzip, deflate',\n     'Content-Length': '371',\n     'Content-Type': 'application/msgpack',\n     'Datadog-Meta-Tracer-Version': 'v0.1',\n     'Host': '127.0.0.1:.*',\n     'User-Agent': 'Python/3.11 aiohttp/3.8.4',\n     'X-Datadog-Test-Session-Token': 'other2',\n     'X-Datadog-Trace-Count': '2'}\n    At payload (1 traces):\n    ❌ Check 'trace_count_header' failed: X-Datadog-Trace-Count value (2) does not match actual number of traces (1)\n",
        ]
    }
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    v04_reference_http_trace_payload_headers["X-Datadog-Trace-Count"] = "2"
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    v04_reference_http_trace_payload_headers["X-Datadog-Test-Session-Token"] = "other"
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    v04_reference_http_trace_payload_headers["X-Datadog-Test-Session-Token"] = "other2"
    await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )

    response = await agent.get("/test/trace_check/failures?return_all=true&use_json=true")
    assert response.status == 400
    resp = await response.json()
    assert resp.keys() == results.keys()
    assert len(resp["trace_count_header"]) == 4

    response = await agent.get("/test/trace_check/clear?test_session_token=other")
    assert response.status == 200

    response = await agent.get("/test/trace_check/failures?return_all=true&use_json=true")
    assert response.status == 400
    resp = await response.json()
    assert resp.keys() == results.keys()
    assert len(resp["trace_count_header"]) == 2

    response = await agent.get("/test/trace_check/clear?clear_all=true")
    assert response.status == 200

    response = await agent.get("/test/trace_check/summary?return_all=true&use_json=true")
    assert response.status == 200
    assert await response.json() == {}


async def test_integrations_from_trace(
    agent, v04_reference_http_trace_payload_headers, v04_reference_http_trace_payload_data
):
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/integrations/tested_versions")
    assert resp.status == 200

    text = await resp.text()

    assert (
        text
        == "language_name,tracer_version,integration_name,integration_version,dependency_name\npython,v0.1,express,1.2.3,express\n"
    )


async def test_put_integrations(
    agent,
):
    resp = await agent.put(
        "/test/session/integrations",
        data=json.dumps(
            {
                "integration_name": "flask",
                "integration_version": "1.1.1",
                "dependency_name": "not_flask",
                "tracer_version": "v1",
                "tracer_language": "python",
            }
        ),
    )
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/integrations/tested_versions")
    assert resp.status == 200

    text = await resp.text()

    assert (
        text
        == "language_name,tracer_version,integration_name,integration_version,dependency_name\npython,v1,flask,1.1.1,not_flask\n"
    )


def test_uds(tmp_path, available_port):
    env = os.environ.copy()
    env["DD_APM_RECEIVER_SOCKET"] = str(tmp_path / "apm.socket")
    env["PORT"] = str(available_port)
    p = subprocess.Popen(["ddapm-test-agent"], env=env)

    # Check for the socket
    for i in range(50):
        if (tmp_path / "apm.socket").exists():
            break
        time.sleep(0.01)
    else:
        raise AssertionError("Test agent did not create the socket in time")

    # Check the permissions
    assert (tmp_path / "apm.socket").stat().st_mode & 0o722 == 0o722

    # Kill the process without atexit handlers
    os.kill(p.pid, signal.SIGKILL)

    # Ensure the test agent can start again
    try:
        subprocess.run(["ddapm-test-agent"], env=env, timeout=0.1)
    except subprocess.TimeoutExpired:
        # Expected since the test agent should start up normally
        pass
    else:
        raise Exception("Test agent failed to start")


async def test_post_known_settings(agent):
    resp = await agent.post(
        "/test/settings",
        data='{ "trace_request_delay": 5 }',
    )

    assert resp.status == 202, await resp.text()
    assert agent.app["trace_request_delay"] == 5

    resp = await agent.post(
        "/test/settings",
        data='{ "trace_request_delay": 0 }',
    )

    assert resp.status == 202, await resp.text()
    assert agent.app["trace_request_delay"] == 0


async def test_post_unknown_settings(
    agent,
):
    resp = await agent.post(
        "/test/settings",
        data='{ "dummy_setting": 5 }',
    )

    assert resp.status == 422
    text = await resp.text()
    assert text == "Unknown key: 'dummy_setting'"
    assert "dummy_setting" not in agent.app


async def test_evp_proxy_v2_api_v2_llmobs(agent):
    resp = await agent.post("/evp_proxy/v2/api/v2/llmobs", data='{"key": "value"}')
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/session/requests")
    assert resp.status == 200
    reqs = await resp.json()
    assert len(reqs) == 1


async def test_evp_proxy_v2_api_intake_llmobs_v1_eval_metric(agent):
    resp = await agent.post("/evp_proxy/v2/api/intake/llm-obs/v1/eval-metric", data='{"key": "value"}')
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/session/requests")
    assert resp.status == 200
    reqs = await resp.json()
    assert len(reqs) == 1


async def test_evp_proxy_v2_api_intake_llmobs_v2_eval_metric(agent):
    resp = await agent.post("/evp_proxy/v2/api/intake/llm-obs/v2/eval-metric", data='{"key": "value"}')
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/session/requests")
    assert resp.status == 200
    reqs = await resp.json()
    assert len(reqs) == 1


async def test_trace_v1(
    agent,
    v04_reference_http_trace_payload_headers,
    v1_reference_http_trace_payload_data,
):
    resp = await agent.put(
        "/v1.0/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v1_reference_http_trace_payload_data,
    )
    assert resp.status == 200, await resp.text()

    result_resp = await agent.get("/test/traces", params={"trace_ids": str(8675)})

    assert result_resp.status == 200
    result = json.loads(await result_resp.text())
    assert len(result) == 1
    assert len(result[0]) == 1, result
    assert result[0][0]["trace_id"] == 8675
    assert result[0][0]["_dd.p.tid"] == 85
    assert result[0][0]["service"] == "my-service"


async def test_trace_v1_basic():
    data = msgpack.packb(
        {2: "hello",
         11: [{1: 1,
               2: "rum",
               3: ["some-global", 1, "cool-value"],
               4: [{1: "my-service", 2: "span-name", 3: 1, 4: 1234, 5: 5555, 6: 987, 7: 150, 8: True, 9: ["foo", 1, "bar", "fooNum", 3, 3.14],
                    10: "span-type", 13: "some-env", 14: "my-version", 15: "my-component", 16: 1}],
               6: bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0xe3]),
               7: "-4",
               }]})
    result = decode_v1(data)
    assert len(result) == 1
    assert len(result[0]) == 1
    assert result[0][0]["service"] == "my-service"
    assert result[0][0]["name"] == "span-name"
    assert result[0][0]["resource"] == "hello"
    assert result[0][0]["span_id"] == 1234
    assert result[0][0]["parent_id"] == 5555
    assert result[0][0]["start"] == 987
    assert result[0][0]["duration"] == 150
    assert result[0][0]["error"] == 1
    assert result[0][0]["meta"] == {"foo": "bar", "env": "some-env", "version": "my-version", "component": "my-component", "span.kind": "internal", "some-global": "cool-value"}
    assert result[0][0]["metrics"] == {"fooNum": 3.14}
    assert result[0][0]["type"] == "span-type"
    assert result[0][0]["trace_id"] == 8675
    assert result[0][0]["_dd.p.tid"] == 85
    assert result[0][0]["_dd.p.dm"] == "-4"
    assert result[0][0]["_dd.origin"] == "rum"
    assert result[0][0]["_sampling_priority_v1"] == 1


async def test_trace_v1_span_event():
    data = msgpack.packb(
        {11: [{
            4: [{1: "my-service", 2: "span-name", 3: 1, 4: 1234, 5: 5555, 6: 987, 7: 150,
                    10: "span-type", 13: "some-env", 14: "my-version", 15: "my-component", 16: 1,
                    12: [{1: 9876, 2: "event-name", 3: ["event-key", 1, "event-value", "event-key2", 2, True, "event-key3", 3, 3.14, "event-key4", 4, 123]}]}],
            6: bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0xe3]),
            7: "-4",
        }]})
    result = decode_v1(data)
    assert len(result) == 1
    assert len(result[0]) == 1
    assert result[0][0]["service"] == "my-service"
    assert len(result[0][0]["span_events"]) == 1
    assert result[0][0]["span_events"][0]["name"] == "event-name"
    assert result[0][0]["span_events"][0]["attributes"] == {
        "event-key": {"type": 0, "string_value": "event-value"},
        "event-key2": {"type": 1, "bool_value": True},
        "event-key3": {"type": 3, "double_value": 3.14},
        "event-key4": {"type": 2, "int_value": 123},
    }


async def test_trace_v1_span_links():
    data = msgpack.packb(
        {11: [{
            4: [{1: "my-service", 2: "span-name", 3: 1, 4: 1234, 5: 5555, 6: 987, 7: 150,
                    10: "span-type", 13: "some-env", 14: "my-version", 15: "my-component", 16: 1,
                    11: [{1: bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0xe4]), 2: 1234,
                          3: ["some-key", 1, "potato", "some-key2", 2, True, "some-key3", 3, 3.14, "some-key4", 4, 123]}]}],
            6: bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0xe3]),
            7: "-4",
        }]})
    result = decode_v1(data)
    assert len(result) == 1
    assert len(result[0]) == 1
    assert result[0][0]["service"] == "my-service"
    assert len(result[0][0]["span_links"]) == 1
    assert result[0][0]["span_links"][0]["trace_id"] == 8676
    assert result[0][0]["span_links"][0]["trace_id_high"] == 86
    assert result[0][0]["span_links"][0]["span_id"] == 1234
    assert result[0][0]["span_links"][0]["attributes"] == {"some-key": "potato", "some-key2": "true", "some-key3": "3.14", "some-key4": "123"}
