"""
If snapshots need to be (re)generated, set GENERATE_SNAPSHOTS=1
and run the tests as usual.
"""
import asyncio
import os
import subprocess
from typing import Callable
from typing import Generator

import aiohttp
from aiohttp.client_exceptions import ClientConnectorError
from aiohttp.client_exceptions import ClientOSError
from ddtrace import Tracer
from ddtrace.propagation.http import HTTPPropagator
from ddtrace.sampler import DatadogSampler
import pytest


@pytest.fixture
def testagent_port():
    yield 8126


@pytest.fixture(scope="module")
def testagent_snapshot_ci_mode():
    # Default all tests in this module to be run in CI mode
    # unless a special env var is passed to make generating
    # the snapshots easier.
    yield os.getenv("GENERATE_SNAPSHOTS") != "1"


@pytest.fixture
async def testagent(loop, testagent_port, testagent_snapshot_ci_mode):
    env = os.environ.copy()
    env.update(
        {
            "PORT": str(testagent_port),
            "SNAPSHOT_CI": "1" if testagent_snapshot_ci_mode else "0",
            "SNAPSHOT_DIR": os.path.join(
                os.path.dirname(__file__), "integration_snapshots"
            ),
        }
    )
    p = subprocess.Popen(["ddapm-test-agent"], env=env)

    # Wait for server to start
    try:
        async with aiohttp.ClientSession() as session:
            for _ in range(20):
                try:
                    r = await session.get(f"http://localhost:{testagent_port}")
                except (ClientConnectorError, ClientOSError):
                    pass
                else:
                    if r.status == 404:
                        break
                await asyncio.sleep(0.05)
            else:
                assert 0
            yield session
    finally:
        p.terminate()


@pytest.fixture
def tracer(testagent_port, testagent):
    tracer = Tracer(url=f"http://localhost:{testagent_port}")
    yield tracer


@pytest.fixture
def trace_sample_rate():
    yield 1.0


@pytest.fixture
def stats_tracer(
    tracer: Tracer, trace_sample_rate: float
) -> Generator[Tracer, None, None]:
    tracer.configure(
        compute_stats_enabled=True,
        sampler=DatadogSampler(
            default_sample_rate=trace_sample_rate,
        ),
    )
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
    await testagent.get(
        "http://localhost:8126/test/session/start?test_session_token=test_single_trace"
    )
    tracer = Tracer(url="http://localhost:8126")
    with tracer.trace(
        operation_name, service=service, resource=resource, span_type=span_type
    ) as span:
        if error is not None:
            span.error = error
        for k, v in meta.items():
            span.set_tag(k, v)
        for k, v in metrics.items():
            span.set_metric(k, v)
    tracer.shutdown()
    resp = await testagent.get(
        "http://localhost:8126/test/session/snapshot?test_session_token=test_single_trace"
    )
    assert resp.status == response_code


async def test_multi_trace(testagent, tracer):
    await testagent.get(
        "http://localhost:8126/test/session/start?test_session_token=test_multi_trace"
    )
    with tracer.trace("root0"):
        with tracer.trace("child0"):
            pass
    with tracer.trace("root1"):
        with tracer.trace("child1"):
            pass
    tracer.flush()
    resp = await testagent.get(
        "http://localhost:8126/test/session/snapshot?test_session_token=test_multi_trace"
    )
    assert resp.status == 200

    # Run the snapshot test again.
    await testagent.get(
        "http://localhost:8126/test/session/start?test_session_token=test_multi_trace"
    )
    with tracer.trace("root0"):
        with tracer.trace("child0"):
            pass
    with tracer.trace("root1"):
        with tracer.trace("child1"):
            pass
    tracer.flush()
    resp = await testagent.get(
        "http://localhost:8126/test/session/snapshot?test_session_token=test_multi_trace"
    )
    assert resp.status == 200

    # Simulate a failed snapshot with a missing trace.
    await testagent.get(
        "http://localhost:8126/test/session/start?test_session_token=test_multi_trace"
    )
    with tracer.trace("root0"):
        with tracer.trace("child0"):
            pass
    tracer.flush()
    resp = await testagent.get(
        "http://localhost:8126/test/session/snapshot?test_session_token=test_multi_trace"
    )
    assert resp.status == 400
    tracer.shutdown()


async def test_trace_distributed_same_payload(testagent, tracer):
    await testagent.get(
        "http://localhost:8126/test/session/start?test_session_token=test_trace_distributed_same_payload"
    )
    with tracer.trace("root0"):
        with tracer.trace("child0") as span:
            ctx = span.context

    tracer.context_provider.activate(ctx)
    with tracer.trace("root1"):
        with tracer.trace("child1"):
            pass
    tracer.flush()
    resp = await testagent.get(
        "http://localhost:8126/test/session/snapshot?test_session_token=test_trace_distributed_same_payload"
    )
    assert resp.status == 200


async def test_trace_distributed_propagated(testagent, tracer):
    await testagent.get(
        "http://localhost:8126/test/session/start?test_session_token=test_trace_distributed_propagated"
    )
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
        "http://localhost:8126/test/session/snapshot?test_session_token=test_trace_distributed_propagated"
    )
    assert resp.status == 200


async def test_trace_missing_received(testagent, tracer):
    resp = await testagent.get(
        "http://localhost:8126/test/session/start?test_session_token=test_trace_missing_received"
    )
    assert resp.status == 200, await resp.text()

    with tracer.trace("root0"):
        with tracer.trace("child0"):
            pass
    tracer.flush()
    resp = await testagent.get(
        "http://localhost:8126/test/session/snapshot?test_session_token=test_trace_missing_received"
    )
    assert resp.status == 200

    # Do another snapshot without sending any traces.
    resp = await testagent.get(
        "http://localhost:8126/test/session/start?test_session_token=test_trace_missing_received"
    )
    assert resp.status == 200, await resp.text()
    resp = await testagent.get(
        "http://localhost:8126/test/session/snapshot?test_session_token=test_trace_missing_received"
    )
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
    testagent: aiohttp.ClientSession,
    stats_tracer: Tracer,
    testagent_snapshot_ci_mode: bool,
    trace_sample_rate: float,
    do_traces: Callable[[Tracer], None],
    fail: bool,
) -> None:
    do_traces(stats_tracer)
    stats_tracer.shutdown()  # force out the stats
    resp = await testagent.get(
        "http://localhost:8126/test/session/snapshot?test_session_token=test_trace_stats"
    )
    if fail:
        assert resp.status == 400
    else:
        assert resp.status == 200


async def test_cmd(testagent: aiohttp.ClientSession, tracer: Tracer) -> None:
    """Test the commands provided with the library.

    Note that this test reuses the trace/snapshot from test_single_trace above.
    """
    env = os.environ.copy()
    p = subprocess.run(
        ["ddapm-test-agent-session-start", "--test-session-token=test_single_trace"],
        env=env,
    )
    assert p.returncode == 0
    with tracer.trace(
        "root", service="custom_service", resource="/url/endpoint", span_type="web"
    ):
        pass
    tracer.flush()
    p = subprocess.run(
        ["ddapm-test-agent-snapshot", "--test-session-token=test_single_trace"], env=env
    )
    assert p.returncode == 0

    # Ensure failing snapshots work.
    p = subprocess.run(
        ["ddapm-test-agent-session-start", "--test-session-token=test_single_trace"],
        env=env,
    )
    assert p.returncode == 0
    with tracer.trace(
        "root1234", service="custom_service", resource="/url/endpoint", span_type="web"
    ):
        pass
    tracer.shutdown()
    p = subprocess.run(
        ["ddapm-test-agent-snapshot", "--test-session-token=test_single_trace"], env=env
    )
    assert p.returncode == 1
