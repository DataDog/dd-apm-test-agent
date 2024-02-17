from ddtrace import Tracer
import pytest

from ddapm_test_agent.client import TestAgentClient


@pytest.fixture
async def client(testagent, testagent_url):
    return TestAgentClient(testagent_url)


@pytest.fixture
async def tracer(testagent_url):
    t = Tracer(testagent_url)
    yield t
    t.shutdown()


async def test_client_traces(client: TestAgentClient, tracer: Tracer) -> None:
    assert client.traces() == []
    with tracer.trace("test"):
        pass
    traces = client.wait_for_num_traces(1)
    assert len(traces) == 1


async def test_client_requests(client: TestAgentClient, tracer: Tracer) -> None:
    assert client.requests() == []
    with tracer.trace("test"):
        pass
    tracer.flush()
    assert len(client.requests()) == 1
