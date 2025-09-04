"""
If snapshots need to be (re)generated, set GENERATE_SNAPSHOTS=1
and run the tests as usual.
"""

import asyncio
import os
import subprocess
from typing import Callable
from typing import Dict
from typing import Generator

import aiohttp
from ddtrace._trace.sampler import DatadogSampler
from ddtrace._trace.sampling_rule import SamplingRule
from ddtrace.trace import Tracer
from ddtrace.profiling import Profiler
from ddtrace.propagation.http import HTTPPropagator
import pytest


@pytest.fixture
def tracer(testagent_port: str, testagent: aiohttp.ClientSession) -> Tracer:
    tracer = Tracer()
    tracer._agent_url = f"http://localhost:{testagent_port}"
    return tracer


@pytest.fixture
def trace_sample_rate() -> float:
    return 1.0


@pytest.fixture
def stats_tracer(
    tracer: Tracer, trace_sample_rate: float
) -> Generator[Tracer, None, None]:
    tracer.configure(compute_stats_enabled=True)
    tracer._sampler = DatadogSampler(
        rules=[SamplingRule(sample_rate=trace_sample_rate)]
    )
    for processor in tracer._span_processors:
        if processor.__class__.__name__ == "SpanStatsProcessorV06":
            processor._agent_url = tracer._agent_url
    yield tracer


@pytest.mark.parametrize(
    "operation_name,service,resource,error,span_type,meta,metrics,response_code",
    [
        # First value is the reference data (also stored in the snapshot)
        ("root", "custom_service", "/url/endpoint", 0, "web", {}, {}, 200),
        ("root2", "custom_service", "/url/endpoint", 0, "web", {}, {}, 400),
        ("root", "custom_service2", "/url/endpoint", 0, "web", {}, {}, 400),
        ("root", "custom_service", "/url/endpoint/2", 0, "web", {}, {}, 400),
        ("root", "custom_service", "/url/endpoint", 1, "web", {}, {}, 400),
        ("root", "custom_service", "/url/endpoint", 0, "http", {}, {}, 400),
        (
            "root",
            "custom_service",
            "/url/endpoint",
            0,
            "http",
            {"meta": "value"},
            {},
            400,
        ),
        (
            "root",
            "custom_service",
            "/url/endpoint",
            0,
            "http",
            {},
            {"metrics": 2.3},
            400,
        ),
        ("root", "custom_service", "/url/endpoint", 0, "web", {}, {}, 200),
    ],
)
async def test_single_trace(
    testagent,
    testagent_url,
    tracer,
    operation_name,
    service,
    resource,
    error,
    span_type,
    meta,
    metrics,
    response_code,
):
    await testagent.get(f"{testagent_url}/test/session/start?test_session_token=test_single_trace")
    tracer = Tracer(url=testagent_url)
    with tracer.trace(operation_name, service=service, resource=resource, span_type=span_type) as span:
        if error is not None:
            span.error = error
        for k, v in meta.items():
            span.set_tag(k, v)
        for k, v in metrics.items():
            span.set_metric(k, v)
    tracer.shutdown()
    resp = await testagent.get(f"{testagent_url}/test/session/snapshot?test_session_token=test_single_trace")

    assert resp.status == response_code


async def test_multi_trace(testagent_url, testagent, tracer):
    await testagent.get(f"{testagent_url}/test/session/start?test_session_token=test_multi_trace")
    with tracer.trace("root0"):
        with tracer.trace("child0"):
            pass
    with tracer.trace("root1"):
        with tracer.trace("child1"):
            pass
    tracer.flush()
    resp = await testagent.get(f"{testagent_url}/test/session/snapshot?test_session_token=test_multi_trace")
    assert resp.status == 200

    # Run the snapshot test again.
    await testagent.get(f"{testagent_url}/test/session/start?test_session_token=test_multi_trace")
    with tracer.trace("root0"):
        with tracer.trace("child0"):
            pass
    with tracer.trace("root1"):
        with tracer.trace("child1"):
            pass
    tracer.flush()
    resp = await testagent.get(f"{testagent_url}/test/session/snapshot?test_session_token=test_multi_trace")
    assert resp.status == 200

    # Simulate a failed snapshot with a missing trace.
    await testagent.get(f"{testagent_url}/test/session/start?test_session_token=test_multi_trace")
    with tracer.trace("root0"):
        with tracer.trace("child0"):
            pass
    tracer.flush()
    resp = await testagent.get(f"{testagent_url}/test/session/snapshot?test_session_token=test_multi_trace")
    assert resp.status == 400
    tracer.shutdown()


async def test_trace_distributed_same_payload(testagent_url, testagent, tracer):
    await testagent.get(f"{testagent_url}/test/session/start?test_session_token=test_trace_distributed_same_payload")
    with tracer.trace("root0"):
        with tracer.trace("child0") as span:
            ctx = span.context

    tracer.context_provider.activate(ctx)
    with tracer.trace("root1"):
        with tracer.trace("child1"):
            pass
    tracer.flush()
    resp = await testagent.get(
        f"{testagent_url}/test/session/snapshot?test_session_token=test_trace_distributed_same_payload"
    )
    assert resp.status == 200


async def test_trace_distributed_propagated(testagent_url, testagent, tracer):
    await testagent.get(f"{testagent_url}/test/session/start?test_session_token=test_trace_distributed_propagated")
    headers = {
        "x-datadog-trace-id": "1234",
        "x-datadog-parent-id": "5678",
    }
    context = HTTPPropagator.extract(headers)
    tracer.context_provider.activate(context)

    with tracer.trace("root"):
        with tracer.trace("child"):
            pass
    tracer.flush()
    resp = await testagent.get(
        f"{testagent_url}/test/session/snapshot?test_session_token=test_trace_distributed_propagated"
    )

    assert resp.status == 200, await resp.text()


async def test_trace_missing_received(testagent_url, testagent, tracer):
    resp = await testagent.get(f"{testagent_url}/test/session/start?test_session_token=test_trace_missing_received")
    assert resp.status == 200, await resp.text()

    with tracer.trace("root0"):
        with tracer.trace("child0"):
            pass
    tracer.flush()
    resp = await testagent.get(f"{testagent_url}/test/session/snapshot?test_session_token=test_trace_missing_received")
    assert resp.status == 200

    # Do another snapshot without sending any traces.
    resp = await testagent.get(f"{testagent_url}/test/session/start?test_session_token=test_trace_missing_received")
    assert resp.status == 200, await resp.text()
    resp = await testagent.get(f"{testagent_url}/test/session/snapshot?test_session_token=test_trace_missing_received")
    assert resp.status == 400


def _tracestats_traces(tracer: Tracer) -> None:
    for i in range(5):
        with tracer.trace("http.request", resource="/users/view") as span:
            if i == 4:
                span.error = 1


def _tracestats_traces_no_error(tracer: Tracer) -> None:
    for i in range(5):
        with tracer.trace("http.request", resource="/users/view"):
            pass


def _tracestats_traces_missing_trace(tracer: Tracer) -> None:
    for i in range(4):
        with tracer.trace("http.request", resource="/users/view") as span:
            if i == 3:
                span.error = 1


def _tracestats_traces_extra_trace(tracer: Tracer) -> None:
    _tracestats_traces(tracer)
    with tracer.trace("http.request", resource="/users/list"):
        pass


@pytest.mark.parametrize("trace_sample_rate", [0.0])  # Don't send any traces
@pytest.mark.parametrize(
    "do_traces,fail",
    [
        (
            _tracestats_traces,
            False,
        ),  # Keep this parametrization first as the next ones depend on it.
        (_tracestats_traces_no_error, True),
        (_tracestats_traces_missing_trace, True),
        (_tracestats_traces_extra_trace, True),
    ],
)
async def test_tracestats(
    testagent_url: str,
    testagent: aiohttp.ClientSession,
    stats_tracer: Tracer,
    testagent_snapshot_ci_mode: bool,
    trace_sample_rate: float,
    do_traces: Callable[[Tracer], None],
    fail: bool,
) -> None:
    await testagent.get(f"{testagent_url}/test/session/start?test_session_token=test_trace_stats")
    do_traces(stats_tracer)
    stats_tracer.shutdown()  # force out the stats
    resp = await testagent.get(f"{testagent_url}/test/session/snapshot?test_session_token=test_trace_stats")
    if fail:
        assert resp.status == 400
    else:
        assert resp.status == 200, await resp.text()


async def test_cmd(testagent_url: str, testagent: aiohttp.ClientSession, tracer: Tracer) -> None:
    """Test the commands provided with the library.

    Note that this test reuses the trace/snapshot from test_single_trace above.
    """
    env = os.environ.copy()
    env["DD_TRACE_AGENT_URL"] = testagent_url
    p = subprocess.run(
        ["ddapm-test-agent-session-start", "--test-session-token=test_single_trace"],
        env=env,
    )
    assert p.returncode == 0
    with tracer.trace("root", service="custom_service", resource="/url/endpoint", span_type="web"):
        pass
    tracer.flush()
    p = subprocess.run(["ddapm-test-agent-snapshot", "--test-session-token=test_single_trace"], env=env)
    assert p.returncode == 0

    # Ensure failing snapshots work.
    p = subprocess.run(
        ["ddapm-test-agent-session-start", "--test-session-token=test_single_trace"],
        env=env,
    )
    assert p.returncode == 0
    with tracer.trace("root1234", service="custom_service", resource="/url/endpoint", span_type="web"):
        pass
    tracer.shutdown()
    p = subprocess.run(["ddapm-test-agent-snapshot", "--test-session-token=test_single_trace"], env=env)
    assert p.returncode == 1


async def test_profiling_endpoint(
    testagent_url: str, testagent: aiohttp.ClientSession, tracer: Tracer
) -> None:
    p = Profiler(tracer=tracer)
    p.start()
    p.stop(flush=True)
    resp = await testagent.get(f"{testagent_url}/test/session/requests")
    assert resp.status == 200
    data = await resp.json()
    assert len(data) >= 1
    assert data[-1]["url"].endswith("/profiling/v1/input")


async def test_race_condition(
    testagent: aiohttp.ClientSession,
    testagent_port: int,
    v04_reference_http_trace_payload_headers: Dict[str, str],
    v04_reference_http_trace_payload_data: bytes,
    testagent_url: str,
) -> None:
    """
    Reproduction of: "RuntimeError: readany() called while another coroutine is already waiting for incoming data"
    when trace requests are made and being read simultaneously
    """
    reqs = []
    for i in range(50):
        reqs.append(
            testagent.put(
                testagent_url + "/v0.4/traces",
                headers=v04_reference_http_trace_payload_headers,
                data=v04_reference_http_trace_payload_data,
            )
        )
        reqs.append(testagent.get(testagent_url + "/test/session/traces"))

    resps = await asyncio.gather(*reqs)
    for r in resps:
        assert r.status == 200
