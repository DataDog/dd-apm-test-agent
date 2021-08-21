from pathlib import Path
from typing import Dict
from typing import Generator
from typing import List

import msgpack
import pytest

from dd_apm_test_agent.agent import make_app


pytest_plugins = "aiohttp.pytest_plugin"


@pytest.fixture
def agent_disabled_checks() -> Generator[List[str], None, None]:
    yield []


@pytest.fixture
def snapshot_dir(tmp_path: Path) -> Generator[Path, None, None]:
    yield tmp_path


@pytest.fixture
def snapshot_ci_mode() -> Generator[bool, None, None]:
    yield False


@pytest.fixture
async def agent_app(
    aiohttp_server, agent_disabled_checks, snapshot_dir, snapshot_ci_mode
):
    app = await aiohttp_server(
        make_app(agent_disabled_checks, str(snapshot_dir), snapshot_ci_mode)
    )
    yield app


@pytest.fixture
async def agent(agent_app, aiohttp_client, loop):
    client = await aiohttp_client(agent_app)
    yield client


@pytest.fixture
def v04_reference_http_trace_payload_data_raw():
    data = [
        [
            {
                "name": "http.request",
                "service": "my-http-server",
                "trace_id": 123456,
                "span_id": 654321,
                "parent_id": None,
                "resource": "/users/",
                "type": "http",
                "meta": {},
                "metrics": {
                    "sampling_priority_v1": 1.0,
                },
            }
        ]
    ]
    yield data


@pytest.fixture
def v04_reference_http_trace_payload_data(
    v04_reference_http_trace_payload_data_raw,
):
    yield msgpack.packb(v04_reference_http_trace_payload_data_raw)


@pytest.fixture
def v04_reference_http_trace_payload_headers() -> Generator[Dict[str, str], None, None]:
    headers = {
        "Content-Type": "application/msgpack",
        "X-Datadog-Trace-Count": "1",
        "Datadog-Meta-Tracer-Version": "v0.1",
    }
    yield headers


@pytest.fixture
def do_reference_http_trace(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
):
    def fn():
        return agent.put(
            "/v0.4/traces",
            headers=v04_reference_http_trace_payload_headers,
            data=v04_reference_http_trace_payload_data,
        )

    yield fn
