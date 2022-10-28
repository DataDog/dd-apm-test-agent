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
from typing import cast

from aiohttp.web import Response
from ddsketch import LogCollapsingLowestDenseDDSketch
from ddsketch.pb.proto import DDSketchProto
import msgpack
import pytest

from ddapm_test_agent.agent import _parse_csv
from ddapm_test_agent.agent import make_app
from ddapm_test_agent.apmtelemetry import TelemetryEvent
from ddapm_test_agent.trace import Span
from ddapm_test_agent.trace import Trace
from ddapm_test_agent.trace_snapshot import DEFAULT_SNAPSHOT_IGNORES


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
def trace_request_delay() -> Generator[float, None, None]:
    yield 0.0


@pytest.fixture
async def agent_app(
    aiohttp_server,
    agent_disabled_checks,
    log_span_fmt,
    snapshot_dir,
    snapshot_ci_mode,
    snapshot_ignored_attrs,
    agent_url,
    trace_request_delay,
):
    app = await aiohttp_server(
        make_app(
            agent_disabled_checks,
            log_span_fmt,
            str(snapshot_dir),
            snapshot_ci_mode,
            snapshot_ignored_attrs,
            agent_url,
            trace_request_delay,
        )
    )
    yield app


@pytest.fixture
async def agent(agent_app, aiohttp_client, loop):
    client = await aiohttp_client(agent_app)
    yield client


@pytest.fixture
def v04_reference_http_trace_payload_data_raw() -> List[Trace]:
    data = [
        [
            Span(
                {
                    "name": "http.request",
                    "service": "my-http-server",
                    "trace_id": random.randint(0, 2**64),
                    "span_id": random.randint(0, 2**64),
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
            ),
        ]
    ]
    return data


@pytest.fixture
def v04_reference_http_trace_payload_data(
    v04_reference_http_trace_payload_data_raw: List[Trace],
) -> bytes:
    return cast(bytes, msgpack.packb(v04_reference_http_trace_payload_data_raw))


@pytest.fixture
def v04_reference_http_trace_payload_headers() -> Dict[str, str]:
    headers = {
        "Content-Type": "application/msgpack",
        "X-Datadog-Trace-Count": "1",
        "Datadog-Meta-Tracer-Version": "v0.1",
    }
    return headers


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


@pytest.fixture
def v06_reference_http_stats_payload_headers():
    headers = {
        "Content-Type": "application/msgpack",
        "Datadog-Meta-Lang": "python",
        "Datadog-Meta-Tracer-Version": "v0.1",
    }
    yield headers


@pytest.fixture
def v06_reference_http_stats_payload_data_raw():
    ok_dist = LogCollapsingLowestDenseDDSketch(0.00775, bin_limit=2048)
    err_dist = LogCollapsingLowestDenseDDSketch(0.00775, bin_limit=2048)

    rng = random.Random(0)
    total = 0
    ok_n = 97
    err_n = 3
    for _ in range(ok_n):
        n = rng.randint(1e9, 2e9)
        total += n
        ok_dist.add(n)
    for _ in range(err_n):
        n = rng.randint(2e9, 3e9)
        total += n
        err_dist.add(n)

    data = {
        "Env": "dev",
        "Version": "v0.1",
        "Hostname": "Host-1234",
        "Stats": [
            {
                "Start": 0,
                "Duration": 100000,
                "Stats": [
                    {
                        "Name": "http.request",
                        "Resource": "/user/profile",
                        "Service": "web-svc",
                        "Synthetics": False,
                        "Hits": ok_n + err_n,
                        "TopLevelHits": ok_n + err_n,
                        "Duration": total,
                        "Errors": err_n,
                        "OkSummary": DDSketchProto.to_proto(
                            ok_dist
                        ).SerializeToString(),
                        "ErrorSummary": DDSketchProto.to_proto(
                            err_dist
                        ).SerializeToString(),
                    },
                ],
            }
        ],
    }
    yield data


@pytest.fixture
def v06_reference_http_stats_payload_data(v06_reference_http_stats_payload_data_raw):
    yield msgpack.packb(v06_reference_http_stats_payload_data_raw)


@pytest.fixture
def do_reference_v06_http_stats(
    agent,
    v06_reference_http_stats_payload_headers,
    v06_reference_http_stats_payload_data,
):
    def fn(token: Optional[str] = None) -> Awaitable[Response]:
        params = {"test_session_token": token} if token is not None else {}
        return agent.put(  # type: ignore
            "/v0.6/stats",
            params=params,
            headers=v06_reference_http_stats_payload_headers,
            data=v06_reference_http_stats_payload_data,
        )

    yield fn


@pytest.fixture
def v2_reference_http_apmtelemetry_payload_data_raw():
    data = {
        "tracer_time": 1658439039,
        "runtime_id": "3cac6e9599564813977aace04bf37d57",
        "api_version": "v1",
        "seq_id": 1,
        "application": {
            "service_name": "my-svc",
            "service_version": "1.0.0",
            "env": "prod",
            "language_name": "python",
            "language_version": "3.9.10",
            "tracer_version": "1.3.0",
            "runtime_name": "CPython",
            "runtime_version": "3.9.10",
        },
        "host": {
            "os": "macOS-12.4",
            "hostname": "HELLO-COMPUTER",
            "os_version": "12.4",
            "kernel_name": "Darwin",
            "kernel_release": "21.5.0",
            "kernel_version": "Darwin Kernel Version 21.5.0: Tue Apr 26 21:08:22 PDT 2022; root:xnu-8020.121.3~4/RELEASE_X86_64",
            "container_id": "",
        },
        "payload": {
            "dependencies": [
                {"name": "pyparsing", "version": "3.0.9"},
                {"name": "pytest-mock", "version": "3.8.2"},
                {"name": "setuptools", "version": "62.6.0"},
                {"name": "sortedcontainers", "version": "2.4.0"},
                {"name": "attrs", "version": "21.4.0"},
                {"name": "wheel", "version": "0.37.1"},
                {"name": "protobuf", "version": "4.21.2"},
                {"name": "packaging", "version": "21.3"},
                {"name": "tomli", "version": "2.0.1"},
                {"name": "msgpack", "version": "1.0.4"},
                {"name": "bytecode", "version": "0.13.0"},
                {"name": "pip", "version": "22.1.2"},
                {"name": "py", "version": "1.11.0"},
                {"name": "ddsketch", "version": "2.0.3"},
                {"name": "coverage", "version": "6.4.2"},
                {"name": "pytest-cov", "version": "3.0.0"},
                {"name": "iniconfig", "version": "1.1.1"},
                {"name": "py-cpuinfo", "version": "8.0.0"},
                {"name": "toml", "version": "0.10.2"},
                {"name": "pluggy", "version": "1.0.0"},
                {"name": "mock", "version": "4.0.3"},
                {"name": "six", "version": "1.16.0"},
                {"name": "opentracing", "version": "2.4.0"},
                {"name": "pytest", "version": "6.2.5"},
                {"name": "ddtrace", "version": "1.3.0"},
                {"name": "tenacity", "version": "8.0.1"},
                {"name": "hypothesis", "version": "6.45.0"},
            ],
            "integrations": [],
            "configurations": [],
        },
        "request_type": "app-started",
    }
    yield data


@pytest.fixture
def v2_reference_http_apmtelemetry_payload_data(
    v2_reference_http_apmtelemetry_payload_data_raw,
):
    yield json.dumps(v2_reference_http_apmtelemetry_payload_data_raw)


@pytest.fixture
def v2_reference_http_apmtelemetry_payload_headers(  # type: ignore
    v2_reference_http_apmtelemetry_payload_data_raw,
) -> Generator[Dict[str, str], None, None]:
    headers = {
        "Content-type": "application/json",
        "DD-Telemetry-Request-Type": v2_reference_http_apmtelemetry_payload_data_raw[
            "request_type"
        ],
        "DD-Telemetry-API-Version": "v1",
    }
    yield headers


def v2_apmtelemetry(  # type: ignore
    agent,
    event: TelemetryEvent,
    token: Optional[str] = None,
):
    params = {"test_session_token": token} if token is not None else {}
    headers = {
        "Content-type": "application/json",
        "DD-Telemetry-Request-Type": event["request_type"],
        "DD-Telemetry-API-Version": "v1",
    }

    return agent.post(
        "/telemetry/proxy/api/v2/apmtelemetry",
        params=params,
        headers=headers,
        data=json.dumps(event),
    )


@pytest.fixture
def do_reference_v2_http_apmtelemetry(
    agent,
    v2_reference_http_apmtelemetry_payload_headers,
    v2_reference_http_apmtelemetry_payload_data,
):
    def fn(token: Optional[str] = None) -> Awaitable[Response]:
        params = {"test_session_token": token} if token is not None else {}
        return agent.post(  # type: ignore
            "/telemetry/proxy/api/v2/apmtelemetry",
            params=params,
            headers=v2_reference_http_apmtelemetry_payload_headers,
            data=v2_reference_http_apmtelemetry_payload_data,
        )

    yield fn
