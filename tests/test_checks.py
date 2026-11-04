import json
import platform
import time

import msgpack
import pytest

from .conftest import v04_trace
from .trace_utils import span


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


async def test_reference_case_insensitive(
    agent,
    v04_reference_http_trace_payload_data,
):
    resp = await agent.put(
        "/v0.4/traces",
        headers={
            "content-type": "application/msgpack",
            "x-datadog-trace-count": "1",
            "datadog-meta-tracer-version": "v0.1",
        },
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 200, await resp.text()


@pytest.mark.parametrize("agent_enabled_checks", [["trace_count_header"], []])
async def test_trace_count_header(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
    agent_enabled_checks,
):
    del v04_reference_http_trace_payload_headers["X-Datadog-Trace-Count"]
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    if "trace_count_header" in agent_enabled_checks:
        assert resp.status == 400, await resp.text()
        assert "Check 'trace_count_header' failed" in await resp.text()
    else:
        assert resp.status == 200, await resp.text()


@pytest.mark.parametrize("agent_enabled_checks", ["trace_count_header"])
async def test_trace_count_header_mismatch(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
    agent_enabled_checks,
):
    v04_reference_http_trace_payload_headers["X-Datadog-Trace-Count"] += "1"
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 400, await resp.text()
    assert "Check 'trace_count_header' failed" in await resp.text()


@pytest.mark.parametrize("agent_enabled_checks", [["meta_tracer_version_header"], []])
async def test_meta_tracer_version_header(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
    agent_enabled_checks,
):
    del v04_reference_http_trace_payload_headers["Datadog-Meta-Tracer-Version"]
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    if "meta_tracer_version_header" in agent_enabled_checks:
        assert resp.status == 400, await resp.text()
        assert "Check 'meta_tracer_version_header' failed" in await resp.text()
    else:
        assert resp.status == 200, await resp.text()


@pytest.mark.parametrize("agent_enabled_checks", ["trace_content_length"])
async def test_trace_content_length(agent, agent_enabled_checks):
    # Assume a trace will be at least 100 bytes each
    s = span()
    trace = [s for _ in range(int(5e7 / 100))]
    resp = await v04_trace(agent, [trace], "msgpack")
    assert resp.status == 400, await resp.text()
    assert "Check 'trace_content_length' failed: content length" in await resp.text()


@pytest.mark.skipif(platform.system() == "Windows", reason="Test doesn't work on Windows")
@pytest.mark.parametrize("agent_enabled_checks", ["trace_stall"])
async def test_trace_stall(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
    agent_enabled_checks,
):
    v04_reference_http_trace_payload_headers["X-Datadog-Test-Stall-Seconds"] = "0.8"
    start = time.monotonic_ns()
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 200, await resp.text()
    end = time.monotonic_ns()
    assert (end - start) / 1e9 >= 0.8


@pytest.mark.parametrize("agent_enabled_checks", [["meta_events_is_valid_json"], []])
async def test_meta_events_is_valid_json_invalid(agent, agent_enabled_checks):
    """A span with invalid JSON in meta.events should fail the check when enabled."""
    s = span(meta={"events": "not valid json"})
    resp = await v04_trace(agent, [[s]], "msgpack")
    if "meta_events_is_valid_json" in agent_enabled_checks:
        assert resp.status == 400, await resp.text()
        assert "Check 'meta_events_is_valid_json' failed" in await resp.text()
    else:
        assert resp.status == 200, await resp.text()


@pytest.mark.parametrize("agent_enabled_checks", [["meta_events_is_valid_json"]])
async def test_meta_events_is_valid_json_not_array(agent, agent_enabled_checks):
    """meta.events must be a JSON array, not an object or scalar."""
    s = span(meta={"events": json.dumps({"name": "not-an-array"})})
    resp = await v04_trace(agent, [[s]], "msgpack")
    assert resp.status == 400, await resp.text()
    assert "meta.events is not a JSON array" in await resp.text()


@pytest.mark.parametrize("agent_enabled_checks", [["meta_events_is_valid_json"]])
async def test_meta_events_is_valid_json_valid(agent, agent_enabled_checks):
    """A span with valid JSON array in meta.events should pass the check."""
    events = [{"name": "my.event", "time_unix_nano": 1234, "attributes": {"key": "val"}}]
    s = span(meta={"events": json.dumps(events)})
    resp = await v04_trace(agent, [[s]], "msgpack")
    assert resp.status == 200, await resp.text()


@pytest.mark.parametrize("agent_enabled_checks", [["meta_events_is_valid_json"]])
async def test_meta_events_is_valid_json_missing(agent, agent_enabled_checks):
    """A span without meta.events should pass the check silently."""
    s = span()
    resp = await v04_trace(agent, [[s]], "msgpack")
    assert resp.status == 200, await resp.text()


def _v1_servlet_trace_request(agent, trace):
    return agent.put(
        "/v0.4/traces",
        headers={
            "Content-Type": "application/msgpack",
            "X-Datadog-Trace-Count": "1",
            "Datadog-Meta-Tracer-Version": "v0.1",
            "X-Datadog-Trace-Env-Variables": "DD_SERVICE=my-service,DD_TRACE_SPAN_ATTRIBUTE_SCHEMA=v1",
        },
        data=msgpack.packb([trace]),
    )


def _servlet_spans(forward_service="ctx"):
    root = span(
        name="servlet.request",
        type="web",
        service="ctx",
        meta={"component": "undertow-http-server", "servlet.context": "/ctx"},
    )
    forward = span(
        name="servlet.forward",
        type="web",
        service=forward_service,
        parent_id=root["span_id"],
        meta={"component": "java-web-servlet-dispatcher"},
    )
    return root, forward


@pytest.mark.parametrize("agent_enabled_checks", [["trace_dd_service"]])
@pytest.mark.parametrize("root_first", [True, False])
async def test_trace_dd_service_servlet_context(agent, agent_enabled_checks, root_first):
    """Spans without servlet.context can use the context from another span, in either order."""
    root, forward = _servlet_spans()
    trace = [root, forward] if root_first else [forward, root]
    resp = await _v1_servlet_trace_request(agent, trace)
    assert resp.status == 200, await resp.text()


@pytest.mark.parametrize("agent_enabled_checks", [["trace_dd_service"]])
@pytest.mark.parametrize("root_first", [True, False])
async def test_trace_dd_service_servlet_context_mismatch(agent, agent_enabled_checks, root_first):
    """A span whose service matches neither DD_SERVICE nor the servlet context fails."""
    root, forward = _servlet_spans(forward_service="other")
    trace = [root, forward] if root_first else [forward, root]
    resp = await _v1_servlet_trace_request(agent, trace)
    assert resp.status == 400, await resp.text()
    assert "Check 'trace_dd_service' failed" in await resp.text()
