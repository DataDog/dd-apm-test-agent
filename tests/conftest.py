from typing import Dict
from typing import Generator
from typing import List

from aiohttp import web
from aiohttp.test_utils import TestClient
import msgpack
import pytest

from retriever.agent import make_app

pytest_plugins = "aiohttp.pytest_plugin"


@pytest.fixture
def agent_disabled_checks() -> Generator[List[str], None, None]:
    yield []


@pytest.fixture
async def agent_app(
    aiohttp_server, agent_disabled_checks
) -> Generator[web.Application, None, None]:
    app = await aiohttp_server(make_app(agent_disabled_checks))
    yield app


@pytest.fixture
async def agent(agent_app, aiohttp_client, loop) -> Generator[TestClient, None, None]:
    client = await aiohttp_client(agent_app)
    yield client


@pytest.fixture
def v04_reference_http_trace_payload_data() -> Generator[bytes, None, None]:
    data = msgpack.packb(
        [
            {
                "name": "http.request",
                "service": "my-http-server",
                "resource": "/users/",
                "type": "http",
                "meta": {},
                "metrics": {
                    "sampling_priority_v1": "1",
                },
            }
        ]
    )
    yield data


@pytest.fixture
def v04_reference_http_trace_payload_headers() -> Generator[Dict[str, str], None, None]:
    headers = {
        "Content-Type": "application/msgpack",
        "X-Datadog-Trace-Count": "1",
        "Datadog-Meta-Tracer-Version": "v0.1",
    }
    yield headers
