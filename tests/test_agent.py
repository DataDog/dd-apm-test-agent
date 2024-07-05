import json
import os
import signal
import subprocess
import time

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
