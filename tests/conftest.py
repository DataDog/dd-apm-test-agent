import json
from pathlib import Path
import random
from typing import Awaitable
from typing import Dict
from typing import Generator
from typing import List
from typing import Literal
from typing import Optional
from typing import Set

from aiohttp.web import Response
import msgpack
import pytest

from ddapm_test_agent.agent import _parse_csv
from ddapm_test_agent.agent import make_app
from ddapm_test_agent.snapshot import DEFAULT_SNAPSHOT_IGNORES
from ddapm_test_agent.trace import Trace


pytest_plugins = "aiohttp.pytest_plugin"


@pytest.fixture
def agent_disabled_checks() -> Generator[List[str], None, None]:
    yield []


@pytest.fixture
def log_span_fmt() -> Generator[str, None, None]:
    yield "[{name}]"


@pytest.fixture
def snapshot_dir(tmp_path: Path) -> Generator[Path, None, None]:
    yield tmp_path


@pytest.fixture
def snapshot_ci_mode() -> Generator[bool, None, None]:
    yield False


@pytest.fixture
def snapshot_ignored_attrs() -> Generator[Set[str], None, None]:
    yield set(_parse_csv(DEFAULT_SNAPSHOT_IGNORES))


@pytest.fixture
def agent_url() -> Generator[str, None, None]:
    yield ""


@pytest.fixture
async def agent_app(
    aiohttp_server,
    agent_disabled_checks,
    log_span_fmt,
    snapshot_dir,
    snapshot_ci_mode,
    snapshot_ignored_attrs,
    agent_url,
):
    app = await aiohttp_server(
        make_app(
            agent_disabled_checks,
            log_span_fmt,
            str(snapshot_dir),
            snapshot_ci_mode,
            snapshot_ignored_attrs,
            agent_url,
        )
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
                "trace_id": random.randint(0, 2 ** 64),
                "span_id": random.randint(0, 2 ** 64),
                "parent_id": None,
                "resource": "/users/",
                "type": "http",
                "start": 1342343123,
                "duration": 123214,
                "meta": {
                    "http.url": "http://localhost:8080/users",
                    "http.method": "GET",
                    "http.status_code": "200",
                    "http.status_msg": "OK",
                },
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


def v04_trace(  # type: ignore
    agent,
    traces: List[Trace],
    encoding: Literal["msgpack", "json"] = "msgpack",
    token: Optional[str] = None,
):
    params = {"test_session_token": token} if token is not None else {}
    if encoding == "msgpack":
        content_type = "application/msgpack"
        encode = msgpack.packb
    else:
        content_type = "application/json"
        encode = json.dumps

    headers = {
        "Content-Type": content_type,
        "X-Datadog-Trace-Count": str(len(traces)),
        "Datadog-Meta-Tracer-Version": "v0.1",
    }

    return agent.put(
        "/v0.4/traces",
        params=params,
        headers=headers,
        data=encode(traces),
    )


@pytest.fixture
def do_reference_v04_http_trace(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
):
    def fn(token: Optional[str] = None) -> Awaitable[Response]:
        params = {"test_session_token": token} if token is not None else {}
        return agent.put(  # type: ignore
            "/v0.4/traces",
            params=params,
            headers=v04_reference_http_trace_payload_headers,
            data=v04_reference_http_trace_payload_data,
        )

    yield fn
