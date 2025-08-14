import base64
import json
from urllib.parse import urlparse

from aiohttp import web
from google.protobuf.json_format import MessageToDict
import grpc.aio as grpc_aio
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2_grpc import MetricsServiceStub
from opentelemetry.proto.common.v1.common_pb2 import AnyValue
from opentelemetry.proto.common.v1.common_pb2 import KeyValue
from opentelemetry.proto.metrics.v1.metrics_pb2 import Gauge
from opentelemetry.proto.metrics.v1.metrics_pb2 import Metric
from opentelemetry.proto.metrics.v1.metrics_pb2 import NumberDataPoint
from opentelemetry.proto.metrics.v1.metrics_pb2 import ResourceMetrics
from opentelemetry.proto.metrics.v1.metrics_pb2 import ScopeMetrics
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
import pytest

from ddapm_test_agent.agent import DEFAULT_OTLP_GRPC_PORT
from ddapm_test_agent.agent import DEFAULT_OTLP_HTTP_PORT
from ddapm_test_agent.agent import make_otlp_grpc_server_async
from ddapm_test_agent.client import TestOTLPClient
from ddapm_test_agent.metrics import METRICS_ENDPOINT


PROTOBUF_HEADERS = {"Content-Type": "application/x-protobuf"}
JSON_HEADERS = {"Content-Type": "application/json"}


async def _get_http_status_from_metadata(call):
    """Extract HTTP status from GRPC trailing metadata."""
    trailing_metadata = await call.trailing_metadata()
    for key, value in trailing_metadata:
        if key == "http-status":
            return int(value)
    return None


@pytest.fixture
def service_name():
    return "ddservice"


@pytest.fixture
def environment():
    return "ddenv"


@pytest.fixture
def version():
    return "ddv1"


@pytest.fixture
def metric_name():
    return "test.counter"


@pytest.fixture
def metric_value():
    return 42.0


@pytest.fixture
def otlp_metrics_protobuf(service_name, environment, version, metric_name, metric_value):
    """Complete OTLP metrics export request with test data."""
    resource = Resource()
    resource.attributes.extend(
        [
            KeyValue(key="service.name", value=AnyValue(string_value=service_name)),
            KeyValue(key="deployment.environment.name", value=AnyValue(string_value=environment)),
            KeyValue(key="service.version", value=AnyValue(string_value=version)),
        ]
    )

    # Create a gauge metric data point
    data_point = NumberDataPoint()
    data_point.as_double = metric_value
    data_point.time_unix_nano = 1609459200000000000

    # Create gauge metric
    gauge = Gauge()
    gauge.data_points.append(data_point)

    # Create metric
    metric = Metric()
    metric.name = metric_name
    metric.description = "Test gauge metric"
    metric.unit = "1"
    metric.gauge.CopyFrom(gauge)

    scope_metrics = ScopeMetrics()
    scope_metrics.metrics.append(metric)

    resource_metrics = ResourceMetrics()
    resource_metrics.resource.CopyFrom(resource)
    resource_metrics.scope_metrics.append(scope_metrics)

    export_request = ExportMetricsServiceRequest()
    export_request.resource_metrics.append(resource_metrics)

    return export_request


@pytest.fixture
def otlp_metrics_string(otlp_metrics_protobuf):
    return otlp_metrics_protobuf.SerializeToString()


@pytest.fixture
def otlp_metrics_json(otlp_metrics_protobuf):
    return json.dumps(MessageToDict(otlp_metrics_protobuf, preserving_proto_field_name=True))


@pytest.fixture
def otlp_http_url(testagent_url):
    parsed_url = urlparse(testagent_url)
    return f"{parsed_url.scheme}://{parsed_url.hostname}:{DEFAULT_OTLP_HTTP_PORT}"


@pytest.fixture
def otlp_test_client(otlp_http_url):
    """OTLP client for retrieving stored metrics and requests."""
    parsed_url = urlparse(otlp_http_url)
    client = TestOTLPClient(parsed_url.hostname, parsed_url.port, parsed_url.scheme)
    client.clear()
    client.wait_to_start()
    yield client
    client.clear()


@pytest.fixture
async def otlp_grpc_client():
    channel = grpc_aio.insecure_channel(f"127.0.0.1:{DEFAULT_OTLP_GRPC_PORT}")
    stub = MetricsServiceStub(channel)

    yield stub

    await channel.close()


@pytest.fixture
async def grpc_server_with_failure_type(agent_app, available_port, aiohttp_server, request):
    """GRPC server with configurable HTTP backend failure scenarios."""
    grpc_port = int(available_port)
    failure_type = getattr(request, "param", "connection_failure")

    http_handlers = {
        "http_400": lambda _: web.HTTPBadRequest(text="invalid"),
        "http_500": lambda _: web.HTTPInternalServerError(text="boom"),
    }

    if failure_type == "connection_failure":
        http_port = 99999  # Non-existent port
    elif failure_type in http_handlers:
        app = web.Application()
        app.router.add_post(METRICS_ENDPOINT, http_handlers[failure_type])
        http_server = await aiohttp_server(app)
        http_port = http_server.port
    else:
        raise ValueError(f"Unknown failure_type: {failure_type}")

    grpc_server = await make_otlp_grpc_server_async(agent_app.app["agent"], http_port=http_port, grpc_port=grpc_port)
    channel = grpc_aio.insecure_channel(f"localhost:{grpc_port}")
    stub = MetricsServiceStub(channel)

    yield grpc_server, stub

    await channel.close()
    await grpc_server.stop(grace=0)


async def test_metrics_endpoint_basic_http(testagent, otlp_http_url, otlp_metrics_string, loop):
    """OTLP metrics HTTP endpoint accepts protobuf data."""
    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_metrics_string
    )
    assert resp.status == 200


@pytest.mark.parametrize(
    "service_name,environment,version,metric_name,metric_value",
    [
        (
            "web-service",
            "production",
            "1.0.0",
            "http.requests.total",
            123.0,
        ),
        (
            "api-service",
            "staging",
            "2.1.3",
            "db.connections.active",
            15.0,
        ),
        (
            "payment-service",
            "development",
            "0.9.5",
            "payments.processed",
            456.0,
        ),
    ],
)
async def test_session_metrics_endpoint_http(
    testagent,
    otlp_http_url,
    otlp_metrics_string,
    service_name,
    environment,
    version,
    metric_name,
    metric_value,
    loop,
):
    """Session endpoint returns metrics with all attributes preserved."""
    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_metrics_string
    )
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/metrics")
    assert resp.status == 200
    metrics = await resp.json()
    assert len(metrics) == 1
    assert "resource_metrics" in metrics[0]

    resource_metrics = metrics[0]["resource_metrics"]
    assert len(resource_metrics) == 1
    resource = resource_metrics[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
    ]
    scope_metrics = resource_metrics[0].get("scope_metrics", [])
    assert len(scope_metrics) == 1
    metrics_list = scope_metrics[0]["metrics"]
    assert len(metrics_list) == 1
    assert metrics_list[0]["name"] == metric_name
    assert metrics_list[0]["gauge"]["data_points"][0]["as_double"] == metric_value


async def test_otlp_client_metrics(testagent, otlp_test_client, otlp_http_url, otlp_metrics_string, loop):
    """OTLP test client correctly captures and retrieves metrics."""
    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_metrics_string
    )
    assert resp.status == 200

    otlp_test_client.wait_for_num_metrics(1)

    resp = otlp_test_client.requests()
    assert len(resp) == 1
    assert resp[0]["method"] == "POST"
    assert resp[0]["url"] == f"{otlp_http_url}{METRICS_ENDPOINT}"
    assert resp[0]["headers"]["Content-Type"] == PROTOBUF_HEADERS["Content-Type"]
    decoded_body = base64.b64decode(resp[0]["body"])
    assert (
        decoded_body == otlp_metrics_string
    ), f"body: {resp[0]['body']} decoded: {decoded_body}, otlp_metrics_string: {otlp_metrics_string}"

    metrics = otlp_test_client.metrics()
    assert len(metrics) == 1
    assert "resource_metrics" in metrics[0]

    otlp_test_client.clear()
    metrics = otlp_test_client.metrics()
    assert len(metrics) == 0


async def test_metrics_endpoint_integration_http(
    testagent, otlp_http_url, otlp_metrics_string, service_name, environment, version, metric_name, loop
):
    """End-to-end OTLP metrics flow validation."""
    resp = await testagent.get(f"{otlp_http_url}/test/session/clear")
    assert resp.status == 200

    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_metrics_string
    )
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/metrics")
    assert resp.status == 200
    captured_metrics_list = await resp.json()

    assert len(captured_metrics_list) > 0, "Expected at least one resource metric"

    captured_metrics = captured_metrics_list[0]
    resource_metrics = captured_metrics["resource_metrics"]
    assert len(resource_metrics) == 1

    # Check resource has expected attributes
    resource = resource_metrics[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
    ]

    scope_metrics = resource_metrics[0].get("scope_metrics", [])
    assert len(scope_metrics) == 1
    metrics_list = scope_metrics[0]["metrics"]
    assert len(metrics_list) == 1
    assert metrics_list[0]["name"] == metric_name


async def test_multiple_metrics_sessions_http(testagent, otlp_http_url, otlp_metrics_string, loop):
    """Metrics are isolated between sessions."""
    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_metrics_string
    )
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/start")
    assert resp.status == 200

    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_metrics_string
    )
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/metrics")
    assert resp.status == 200
    metrics = await resp.json()
    assert len(metrics) == 1  # Only the metric from the current session


async def test_metrics_endpoint_json_http(
    testagent, otlp_http_url, otlp_metrics_json, service_name, environment, version, loop
):
    """OTLP metrics HTTP endpoint accepts JSON data."""
    resp = await testagent.post(f"{otlp_http_url}{METRICS_ENDPOINT}", headers=JSON_HEADERS, data=otlp_metrics_json)
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/metrics")
    assert resp.status == 200
    metrics = await resp.json()
    assert len(metrics) == 1

    resource_metrics = metrics[0]["resource_metrics"]
    assert len(resource_metrics) == 1

    # Check resource has expected attributes
    resource = resource_metrics[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
    ]


async def test_metrics_endpoint_invalid_content_type(testagent, otlp_http_url, otlp_metrics_string, loop):
    """Endpoint rejects invalid content types."""
    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers={"Content-Type": "application/xml"}, data=otlp_metrics_string
    )
    assert resp.status == 400

    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers={"Content-Type": "text/plain"}, data=b"some plain text"
    )
    assert resp.status == 400

    resp = await testagent.post(f"{otlp_http_url}{METRICS_ENDPOINT}", data=otlp_metrics_string)
    assert resp.status == 400


async def test_metrics_endpoint_invalid_json(testagent, otlp_http_url, loop):
    """Endpoint rejects malformed JSON."""
    resp = await testagent.post(f"{otlp_http_url}{METRICS_ENDPOINT}", headers=JSON_HEADERS, data=b'{"invalid": json}')
    assert resp.status == 400

    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=JSON_HEADERS, data=b'["not", "an", "object"]'
    )
    assert resp.status == 400

    resp = await testagent.post(f"{otlp_http_url}{METRICS_ENDPOINT}", headers=JSON_HEADERS, data=b'"just a string"')
    assert resp.status == 400


async def test_metrics_endpoint_basic_grpc(testagent, otlp_grpc_client, otlp_metrics_protobuf, loop):
    """GRPC metrics export with successful forwarding."""
    call = otlp_grpc_client.Export(otlp_metrics_protobuf)
    response = await call

    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 200, f"Expected HTTP 200, got {http_status}"

    # For successful requests, partial_success should be empty
    assert response.partial_success.rejected_data_points == 0
    assert response.partial_success.error_message == ""


async def test_session_metrics_endpoint_grpc_forwarding(
    testagent,
    otlp_grpc_client,
    otlp_test_client,
    otlp_metrics_protobuf,
    service_name,
    environment,
    version,
    metric_name,
    loop,
):
    """GRPC metrics forwarded to HTTP are retrievable via session endpoint."""
    call = otlp_grpc_client.Export(otlp_metrics_protobuf)
    response = await call
    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 200, f"Expected HTTP 200, got {http_status}"

    metrics = otlp_test_client.metrics()

    resource_metrics = metrics[0]["resource_metrics"]
    assert len(resource_metrics) == 1

    # Check resource has expected attributes
    resource = resource_metrics[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
    ]

    scope_metrics = resource_metrics[0].get("scope_metrics", [])
    assert len(scope_metrics) == 1
    metrics_list = scope_metrics[0]["metrics"]
    assert len(metrics_list) == 1
    assert metrics_list[0]["name"] == metric_name


@pytest.mark.parametrize("grpc_server_with_failure_type", ["http_400"], indirect=True)
async def test_grpc_maps_http_400_to_metadata(grpc_server_with_failure_type):
    """GRPC forwarding preserves HTTP 400 status in metadata and partial_success."""

    _, stub = grpc_server_with_failure_type

    call = stub.Export(ExportMetricsServiceRequest())
    response = await call
    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 400, f"Expected HTTP 400, got {http_status}"

    assert response.partial_success.rejected_data_points == 0  # Empty request
    assert "HTTP 400" in response.partial_success.error_message


@pytest.mark.parametrize("grpc_server_with_failure_type", ["http_500"], indirect=True)
async def test_grpc_maps_http_500_to_metadata(grpc_server_with_failure_type):
    """GRPC forwarding preserves HTTP 500 status in metadata and partial_success."""

    _, stub = grpc_server_with_failure_type

    call = stub.Export(ExportMetricsServiceRequest())
    response = await call
    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 500, f"Expected HTTP 500, got {http_status}"

    assert response.partial_success.rejected_data_points == 0  # Empty request
    assert "HTTP 500" in response.partial_success.error_message


@pytest.mark.parametrize("grpc_server_with_failure_type", ["connection_failure"], indirect=True)
async def test_grpc_server_resilience_after_failure(grpc_server_with_failure_type, otlp_metrics_protobuf):
    """GRPC server remains operational after processing failed requests."""

    _, stub = grpc_server_with_failure_type

    call1 = stub.Export(otlp_metrics_protobuf)
    response1 = await call1
    assert response1 is not None

    assert response1.partial_success.rejected_data_points > 0
    assert "Forward failed" in response1.partial_success.error_message

    http_status = await _get_http_status_from_metadata(call1)
    assert http_status == 500  # Connection failure mapped to 500

    call2 = stub.Export(otlp_metrics_protobuf)
    response2 = await call2
    assert response2 is not None

    assert response2.partial_success.rejected_data_points > 0
    assert "Forward failed" in response2.partial_success.error_message

    call3 = stub.Export(ExportMetricsServiceRequest())
    response3 = await call3
    assert response3 is not None
