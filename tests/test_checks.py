import pytest


async def test_reference(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
):
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 200, await resp.text()


@pytest.mark.parametrize("agent_disabled_checks", [[], ["trace_count_header"]])
async def test_trace_count_header(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
    agent_disabled_checks,
):
    del v04_reference_http_trace_payload_headers["X-Datadog-Trace-Count"]
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    if "trace_count_header" in agent_disabled_checks:
        assert resp.status == 200, await resp.text()
    else:
        assert resp.status == 400, await resp.text()
        assert "Check 'trace_count_header' failed." in await resp.text()


async def test_trace_count_header_mismatch(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
):
    v04_reference_http_trace_payload_headers["X-Datadog-Trace-Count"] += "1"
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 400, await resp.text()
    assert "Check 'trace_count_header' failed." in await resp.text()


@pytest.mark.parametrize("agent_disabled_checks", [[], ["meta_tracer_version_header"]])
async def test_meta_tracer_version_header(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
    agent_disabled_checks,
):
    del v04_reference_http_trace_payload_headers["Datadog-Meta-Tracer-Version"]
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    if "meta_tracer_version_header" in agent_disabled_checks:
        assert resp.status == 200, await resp.text()
    else:
        assert resp.status == 400, await resp.text()
        assert "Check 'meta_tracer_version_header' failed." in await resp.text()
