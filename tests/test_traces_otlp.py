import base64
import json

from google.protobuf.json_format import MessageToDict
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceResponse
from opentelemetry.proto.common.v1.common_pb2 import AnyValue
from opentelemetry.proto.common.v1.common_pb2 import KeyValue
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
from opentelemetry.proto.trace.v1.trace_pb2 import ResourceSpans
from opentelemetry.proto.trace.v1.trace_pb2 import ScopeSpans
from opentelemetry.proto.trace.v1.trace_pb2 import Span
import pytest

from ddapm_test_agent.traces_otlp import TRACES_ENDPOINT
from tests.conftest import JSON_HEADERS
from tests.conftest import PROTOBUF_HEADERS
from tests.conftest import _get_http_status_from_metadata


def _find_service_name_in_resource(resource_spans, expected_service_name):
    if not resource_spans or not resource_spans[0].get("resource"):
        return False

    resource = resource_spans[0]["resource"]
    for attr in resource.get("attributes", []):
        if attr.get("key") == "service.name" and attr.get("value", {}).get("string_value") == expected_service_name:
            return True
    return False


@pytest.fixture
def span_name():
    return "test_otel_traces_exporter_auto_configured_http"


@pytest.fixture
def trace_id():
    return b"\x01\x23\x45\x67\x89\xab\xcd\xef\x00\x00\x00\x00\x00\x00\x00\x00"


@pytest.fixture
def span_id():
    return b"\xdd\x00\x00\x00\x00\x00\x00\x00"


@pytest.fixture
def parent_span_id():
    return b""


@pytest.fixture
def otlp_traces_protobuf(
    service_name,
    environment,
    version,
    span_name,
    trace_id,
    span_id,
    parent_span_id
):
    resource = Resource()
    resource.attributes.extend(
        [
            KeyValue(key="service.name", value=AnyValue(string_value=service_name)),
            KeyValue(key="deployment.environment.name", value=AnyValue(string_value=environment)),
            KeyValue(key="service.version", value=AnyValue(string_value=version)),
        ]
    )

    span = Span()
    span.name = span_name
    span.trace_id = trace_id
    span.span_id = span_id
    span.parent_span_id = parent_span_id
    span.start_time_unix_nano = 1000000000
    span.end_time_unix_nano = 2000000000
    span.kind = Span.SPAN_KIND_INTERNAL

    scope_spans = ScopeSpans()
    scope_spans.spans.append(span)

    resource_spans = ResourceSpans()
    resource_spans.resource.CopyFrom(resource)
    resource_spans.scope_spans.append(scope_spans)

    export_request = ExportTraceServiceRequest()
    export_request.resource_spans.append(resource_spans)

    return export_request


@pytest.fixture
def otlp_traces_string(otlp_traces_protobuf):
    return otlp_traces_protobuf.SerializeToString()


@pytest.fixture
def otlp_traces_json(otlp_traces_protobuf):
    return json.dumps(MessageToDict(otlp_traces_protobuf, preserving_proto_field_name=True))


async def test_traces_endpoint_basic_http(testagent, otlp_http_url, otlp_traces_string, loop):
    resp = await testagent.post(f"{otlp_http_url}{TRACES_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_traces_string)
    assert resp.status == 200
    assert resp.content_type == "application/x-protobuf"
    body = await resp.read()
    assert body == ExportTraceServiceResponse().SerializeToString()


@pytest.mark.parametrize(
    "service_name,environment,version,span_name,trace_id,span_id,parent_span_id",
    [
        (
            "web-service",
            "prod",
            "1.0.0",
            "GET /api/users",
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\x00\x00\x00\x00\x00\x00\x00\x01",
            b"\xdd\x00\x00\x00\x00\x00\x00\x01",
            b"",
        ),
        (
            "api-service",
            "staging",
            "2.1.3",
            "POST /api/login",
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\x00\x00\x00\x00\x00\x00\x00\x02",
            b"\xdd\x00\x00\x00\x00\x00\x00\x02",
            b"\xdd\x00\x00\x00\x00\x00\x00\x03",
        ),
        (
            "payment-service",
            "dev",
            "0.9.5",
            "process_payment",
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\x00\x00\x00\x00\x00\x00\x00\x03",
            b"\xdd\x00\x00\x00\x00\x00\x00\x04",
            b"\xdd\x00\x00\x00\x00\x00\x00\x05",
        ),
        (
            "auth-service",
            "test",
            "3.2.1",
            "validate_token",
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\x00\x00\x00\x00\x00\x00\x00\x04",
            b"\xdd\x00\x00\x00\x00\x00\x00\x06",
            b"",
        ),
        (
            "notification-service",
            "prod",
            "1.5.7",
            "send_email",
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\x00\x00\x00\x00\x00\x00\x00\x05",
            b"\xdd\x00\x00\x00\x00\x00\x00\x07",
            b"\xdd\x00\x00\x00\x00\x00\x00\x08",
        ),
    ],
)
async def test_session_traces_endpoint_http(
    testagent,
    otlp_http_url,
    otlp_traces_string,
    service_name,
    environment,
    version,
    span_name,
    span_id,
    trace_id,
    parent_span_id,
    loop,
):
    resp = await testagent.post(
        f"{otlp_http_url}{TRACES_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_traces_string
    )
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/traces")
    assert resp.status == 200
    traces = await resp.json()
    assert len(traces) == 1
    assert "resource_spans" in traces[0]

    resource_spans = traces[0]["resource_spans"]
    assert len(resource_spans) == 1
    resource = resource_spans[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
    ]
    scope_spans = resource_spans[0].get("scope_spans", [])
    assert len(scope_spans) == 1
    spans = scope_spans[0]["spans"]
    assert len(spans) == 1
    assert spans[0]["name"] == span_name
    # trace_id, span_id, and parent_span_id are stored as base64 encoded strings in JSON
    expected_trace_id = base64.b64encode(trace_id).decode("ascii") if trace_id else None
    expected_span_id = base64.b64encode(span_id).decode("ascii") if span_id else None
    expected_parent_span_id = base64.b64encode(parent_span_id).decode("ascii") if parent_span_id else None
    assert spans[0].get("trace_id") == expected_trace_id
    assert spans[0].get("span_id") == expected_span_id
    assert spans[0].get("parent_span_id") == expected_parent_span_id


async def test_otlp_client_traces(testagent, otlp_test_client, otlp_http_url, otlp_traces_string, loop):
    resp = await testagent.post(
        f"{otlp_http_url}{TRACES_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_traces_string
    )
    assert resp.status == 200

    otlp_test_client.wait_for_num_traces(1)

    resp = otlp_test_client.requests()
    assert len(resp) == 1
    assert resp[0]["method"] == "POST"
    assert resp[0]["url"] == f"{otlp_http_url}{TRACES_ENDPOINT}"
    assert resp[0]["headers"]["Content-Type"] == PROTOBUF_HEADERS["Content-Type"]
    decoded_body = base64.b64decode(resp[0]["body"])
    assert (
        decoded_body == otlp_traces_string
    ), f"body: {resp[0]['body']} decoded: {decoded_body}, otlp_traces_string: {otlp_traces_string}"

    traces = otlp_test_client.traces()
    assert len(traces) == 1
    assert "resource_spans" in traces[0]

    otlp_test_client.clear()
    traces = otlp_test_client.traces()
    assert len(traces) == 0


async def test_traces_endpoint_integration_http(
    testagent, otlp_http_url, otlp_traces_string, service_name, environment, version, span_name, loop
):
    resp = await testagent.get(f"{otlp_http_url}/test/session/clear")
    assert resp.status == 200

    resp = await testagent.post(
        f"{otlp_http_url}{TRACES_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_traces_string
    )
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/traces")
    assert resp.status == 200
    captured_traces_list = await resp.json()

    assert len(captured_traces_list) > 0, "Expected at least one resource span"

    captured_traces = captured_traces_list[0]
    resource_spans = captured_traces["resource_spans"]
    assert len(resource_spans) == 1

    # Check resource has expected attributes
    resource = resource_spans[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
    ]

    scope_spans = resource_spans[0].get("scope_spans", [])
    assert len(scope_spans) == 1
    spans = scope_spans[0]["spans"]
    assert len(spans) == 1
    assert spans[0]["name"] == span_name


async def test_multiple_traces_sessions_http(testagent, otlp_http_url, otlp_traces_string, loop):
    """Traces are isolated between sessions."""
    resp = await testagent.post(
        f"{otlp_http_url}{TRACES_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_traces_string
    )
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/start")
    assert resp.status == 200

    resp = await testagent.post(
        f"{otlp_http_url}{TRACES_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_traces_string
    )
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/traces")
    assert resp.status == 200
    traces = await resp.json()
    assert len(traces) == 1  # Only the trace from the current session


async def test_traces_endpoint_json_http(
    testagent, otlp_http_url, otlp_traces_json, service_name, environment, version, loop
):
    resp = await testagent.post(f"{otlp_http_url}{TRACES_ENDPOINT}", headers=JSON_HEADERS, data=otlp_traces_json)
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/traces")
    assert resp.status == 200
    traces = await resp.json()
    assert len(traces) == 1

    resource_spans = traces[0]["resource_spans"]
    assert len(resource_spans) == 1

    # Check resource has expected attributes
    resource = resource_spans[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
    ]


async def test_traces_endpoint_invalid_content_type(testagent, otlp_http_url, otlp_traces_string, loop):
    resp = await testagent.post(
        f"{otlp_http_url}{TRACES_ENDPOINT}", headers={"Content-Type": "application/xml"}, data=otlp_traces_string
    )
    assert resp.status == 400

    resp = await testagent.post(
        f"{otlp_http_url}{TRACES_ENDPOINT}", headers={"Content-Type": "text/plain"}, data=b"some plain text"
    )
    assert resp.status == 400

    resp = await testagent.post(f"{otlp_http_url}{TRACES_ENDPOINT}", data=otlp_traces_string)
    assert resp.status == 400


async def test_traces_endpoint_invalid_json(testagent, otlp_http_url, loop):
    resp = await testagent.post(f"{otlp_http_url}{TRACES_ENDPOINT}", headers=JSON_HEADERS, data=b'{"invalid": json}')
    assert resp.status == 400

    resp = await testagent.post(
        f"{otlp_http_url}{TRACES_ENDPOINT}", headers=JSON_HEADERS, data=b'["not", "an", "object"]'
    )
    assert resp.status == 400

    resp = await testagent.post(f"{otlp_http_url}{TRACES_ENDPOINT}", headers=JSON_HEADERS, data=b'"just a string"')
    assert resp.status == 400


async def test_traces_endpoint_basic_grpc(testagent, otlp_traces_grpc_client, otlp_traces_protobuf, loop):
    call = otlp_traces_grpc_client.Export(otlp_traces_protobuf)
    response = await call

    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 200, f"Expected HTTP 200, got {http_status}"

    # For successful requests, partial_success should be empty
    assert response.partial_success.rejected_spans == 0
    assert response.partial_success.error_message == ""


async def test_session_traces_endpoint_grpc_forwarding(
    testagent,
    otlp_traces_grpc_client,
    otlp_test_client,
    otlp_traces_protobuf,
    service_name,
    environment,
    version,
    span_name,
    loop
):
    call = otlp_traces_grpc_client.Export(otlp_traces_protobuf)
    response = await call
    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 200, f"Expected HTTP 200, got {http_status}"

    traces = otlp_test_client.traces()

    resource_spans = traces[0]["resource_spans"]
    assert len(resource_spans) == 1

    # Check resource has expected attributes
    resource = resource_spans[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
    ]

    scope_spans = resource_spans[0].get("scope_spans", [])
    assert len(scope_spans) == 1
    spans = scope_spans[0]["spans"]
    assert len(spans) == 1
    assert spans[0]["name"] == span_name


@pytest.mark.parametrize("grpc_client_with_failure_type", [("http_400", "traces")], indirect=True)
async def test_grpc_maps_http_400_to_metadata(grpc_client_with_failure_type):
    """GRPC forwarding preserves HTTP 400 status in metadata and partial_success."""

    call = grpc_client_with_failure_type.Export(ExportTraceServiceRequest())
    response = await call
    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 400, f"Expected HTTP 400, got {http_status}"

    assert response.partial_success.rejected_spans == 0  # Empty request
    assert "HTTP 400" in response.partial_success.error_message


@pytest.mark.parametrize("grpc_client_with_failure_type", [("http_500", "traces")], indirect=True)
async def test_grpc_maps_http_500_to_metadata(grpc_client_with_failure_type):
    """GRPC forwarding preserves HTTP 500 status in metadata and partial_success."""
    call = grpc_client_with_failure_type.Export(ExportTraceServiceRequest())
    response = await call
    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 500, f"Expected HTTP 500, got {http_status}"

    assert response.partial_success.rejected_spans == 0  # Empty request
    assert "HTTP 500" in response.partial_success.error_message


@pytest.mark.parametrize("grpc_client_with_failure_type", [("connection_failure", "traces")], indirect=True)
async def test_grpc_server_resilience_after_failure(grpc_client_with_failure_type, otlp_traces_protobuf):
    """GRPC server remains operational after processing failed requests."""
    call1 = grpc_client_with_failure_type.Export(otlp_traces_protobuf)
    response1 = await call1
    assert response1 is not None

    assert response1.partial_success.rejected_spans == 1  # 1 span in request
    assert "Forward failed" in response1.partial_success.error_message

    http_status = await _get_http_status_from_metadata(call1)
    assert http_status == 500  # Connection failure mapped to 500

    call2 = grpc_client_with_failure_type.Export(otlp_traces_protobuf)
    response2 = await call2
    assert response2 is not None

    assert response2.partial_success.rejected_spans == 1  # 1 span in request
    assert "Forward failed" in response2.partial_success.error_message

    call3 = grpc_client_with_failure_type.Export(ExportTraceServiceRequest())
    response3 = await call3
    assert response3 is not None
