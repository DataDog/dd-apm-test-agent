import asyncio
import os
import subprocess

import aiohttp
from aiohttp.client_exceptions import ClientConnectorError
from ddtrace import Tracer
import pytest


@pytest.fixture
def testagent_port():
    yield 8126


@pytest.fixture
async def testagent(loop, testagent_port):
    env = os.environ.copy()
    env.update(
        {
            "PORT": str(testagent_port),
            "SNAPSHOT_CI": "1",
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
                except ClientConnectorError:
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
            span.set_meta(k, v)
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
    tracer.writer.flush_queue()
    resp = await testagent.get(
        "http://localhost:8126/test/session/snapshot?test_session_token=test_multi_trace"
    )
    assert resp.status == 200

    await testagent.get(
        "http://localhost:8126/test/session/start?test_session_token=test_multi_trace"
    )
    with tracer.trace("root0"):
        with tracer.trace("child0"):
            pass
    tracer.writer.flush_queue()
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
    tracer.writer.flush_queue()
    resp = await testagent.get(
        "http://localhost:8126/test/session/snapshot?test_session_token=test_trace_distributed_same_payload"
    )
    assert resp.status == 200
