import base64
import json

from google.protobuf.json_format import MessageToDict
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.common.v1.common_pb2 import AnyValue
from opentelemetry.proto.common.v1.common_pb2 import KeyValue
from opentelemetry.proto.logs.v1.logs_pb2 import LogRecord
from opentelemetry.proto.logs.v1.logs_pb2 import ResourceLogs
from opentelemetry.proto.logs.v1.logs_pb2 import ScopeLogs
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
import pytest

from ddapm_test_agent.logs import LOGS_ENDPOINT
from tests.conftest import JSON_HEADERS
from tests.conftest import PROTOBUF_HEADERS
from tests.conftest import _get_http_status_from_metadata


def _find_service_name_in_resource(resource_logs, expected_service_name):
    if not resource_logs or not resource_logs[0].get("resource"):
        return False

    resource = resource_logs[0]["resource"]
    for attr in resource.get("attributes", []):
        if attr.get("key") == "service.name" and attr.get("value", {}).get("string_value") == expected_service_name:
            return True
    return False


@pytest.fixture
def log_message():
    return "test_otel_logs_exporter_auto_configured_http"


@pytest.fixture
def trace_id():
    return b""


@pytest.fixture
def span_id():
    return b""


@pytest.fixture
def otlp_logs_protobuf(service_name, environment, version, host_name, log_message, trace_id, span_id):
    resource = Resource()
    resource.attributes.extend(
        [
            KeyValue(key="service.name", value=AnyValue(string_value=service_name)),
            KeyValue(key="deployment.environment.name", value=AnyValue(string_value=environment)),
            KeyValue(key="service.version", value=AnyValue(string_value=version)),
            KeyValue(key="host.name", value=AnyValue(string_value=host_name)),
        ]
    )

    log_record = LogRecord()
    log_record.body.string_value = log_message
    log_record.trace_id = trace_id
    log_record.span_id = span_id

    scope_logs = ScopeLogs()
    scope_logs.log_records.append(log_record)

    resource_logs = ResourceLogs()
    resource_logs.resource.CopyFrom(resource)
    resource_logs.scope_logs.append(scope_logs)

    export_request = ExportLogsServiceRequest()
    export_request.resource_logs.append(resource_logs)

    return export_request


@pytest.fixture
def otlp_logs_string(otlp_logs_protobuf):
    return otlp_logs_protobuf.SerializeToString()


@pytest.fixture
def otlp_logs_json(otlp_logs_protobuf):
    return json.dumps(MessageToDict(otlp_logs_protobuf, preserving_proto_field_name=True))


async def test_logs_endpoint_basic_http(testagent, otlp_http_url, otlp_logs_string, loop):
    resp = await testagent.post(f"{otlp_http_url}{LOGS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_logs_string)
    assert resp.status == 200


@pytest.mark.parametrize(
    "service_name,environment,version,host_name,log_message,trace_id,span_id",
    [
        (
            "web-service",
            "production",
            "1.0.0",
            "web-01",
            "User login successful",
            b"\xdd\xda\xa1\xa9\xa5y\xc1\xbd",
            b"h\x9b[\xe5\x00\x00\x00\x00\x80\x1b\\]\x1c#\xe6\xfb",
        ),
        (
            "api-service",
            "staging",
            "2.1.3",
            "api-02",
            "Database connection established",
            b"h\xb8\xcf\xb9\xa5;\x0f\x87",
            b"h\x9b[\xe5\x00\x00\x00\x00\x83\x0f\xb8M\xc8\xac\xd6Z",
        ),
        (
            "payment-service",
            "development",
            "0.9.5",
            "payment-03",
            "Payment processed successfully",
            b"\xee\x1fl\xf8d\x9a\xc2+",
            b"h\x9b[\xe5\x00\x00\x00\x00v{\xd8\xfd5+K(",
        ),
        ("auth-service", "test", "3.2.1", "auth-04", "Token validation failed", b"", b""),  # Empty trace/span IDs
        (
            "notification-service",
            "production",
            "1.5.7",
            "notify-05",
            "Email sent to user@example.com",
            b"\xb0\x10)\xbaI\xbc\x9d\xf1",
            b"h\x9b[\xe5\x00\x00\x00\x00k_$\x95`\n\xbf\xc5",
        ),
    ],
)
async def test_session_logs_endpoint_http(
    testagent,
    otlp_http_url,
    otlp_logs_string,
    service_name,
    environment,
    version,
    host_name,
    log_message,
    span_id,
    trace_id,
    loop,
):
    """Session endpoint returns logs with all attributes preserved."""
    resp = await testagent.post(f"{otlp_http_url}{LOGS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_logs_string)
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/logs")
    assert resp.status == 200
    logs = await resp.json()
    assert len(logs) == 1
    assert "resource_logs" in logs[0]

    resource_logs = logs[0]["resource_logs"]
    assert len(resource_logs) == 1

    assert _find_service_name_in_resource(
        resource_logs, service_name
    ), f"service.name should be set to '{service_name}' in resource attributes"

    assert len(resource_logs) == 1
    resource = resource_logs[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
        {"key": "host.name", "value": {"string_value": host_name}},
    ]
    scope_logs = resource_logs[0].get("scope_logs", [])
    assert len(scope_logs) == 1
    log_records = scope_logs[0]["log_records"]
    assert len(log_records) == 1
    assert log_records[0]["body"].get("string_value") == log_message
    # trace_id and span_id are stored as base64 encoded strings in JSON
    expected_trace_id = base64.b64encode(trace_id).decode("ascii") if trace_id else None
    expected_span_id = base64.b64encode(span_id).decode("ascii") if span_id else None
    assert log_records[0].get("trace_id") == expected_trace_id
    assert log_records[0].get("span_id") == expected_span_id


async def test_otlp_client_logs(testagent, otlp_test_client, otlp_http_url, otlp_logs_string, loop):
    resp = await testagent.post(f"{otlp_http_url}{LOGS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_logs_string)
    assert resp.status == 200

    otlp_test_client.wait_for_num_logs(1)

    resp = otlp_test_client.requests()
    assert len(resp) == 1
    assert resp[0]["method"] == "POST"
    assert resp[0]["url"] == f"{otlp_http_url}{LOGS_ENDPOINT}"
    assert resp[0]["headers"]["Content-Type"] == PROTOBUF_HEADERS["Content-Type"]
    decoded_body = base64.b64decode(resp[0]["body"])
    assert (
        decoded_body == otlp_logs_string
    ), f"body: {resp[0]['body']} decoded: {decoded_body}, otlp_logs_string: {otlp_logs_string}"

    logs = otlp_test_client.logs()
    assert len(logs) == 1
    assert "resource_logs" in logs[0]

    otlp_test_client.clear()
    logs = otlp_test_client.logs()
    assert len(logs) == 0


async def test_logs_endpoint_integration_http(
    testagent, otlp_http_url, otlp_logs_string, service_name, log_message, loop
):
    resp = await testagent.get(f"{otlp_http_url}/test/session/clear")
    assert resp.status == 200

    resp = await testagent.post(f"{otlp_http_url}{LOGS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_logs_string)
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/logs")
    assert resp.status == 200
    captured_logs_list = await resp.json()

    assert len(captured_logs_list) > 0, "Expected at least one resource log"

    captured_logs = captured_logs_list[0]
    resource_logs = captured_logs["resource_logs"]
    assert len(resource_logs) > 0

    assert _find_service_name_in_resource(
        resource_logs, service_name
    ), f"service.name should be set to '{service_name}' in resource attributes"

    scope_logs = resource_logs[0].get("scope_logs", [])
    assert len(scope_logs) == 1
    log_records = scope_logs[0]["log_records"]
    assert len(log_records) == 1
    assert log_records[0]["body"].get("string_value") == log_message


async def test_multiple_logs_sessions_http(testagent, otlp_http_url, otlp_logs_string, loop):
    """Logs are isolated between sessions."""
    resp = await testagent.post(f"{otlp_http_url}{LOGS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_logs_string)
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/start")
    assert resp.status == 200

    resp = await testagent.post(f"{otlp_http_url}{LOGS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_logs_string)
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/logs")
    assert resp.status == 200
    logs = await resp.json()
    assert len(logs) == 1  # Only the log from the current session


async def test_logs_endpoint_json_http(testagent, otlp_http_url, otlp_logs_json, service_name, loop):
    resp = await testagent.post(f"{otlp_http_url}{LOGS_ENDPOINT}", headers=JSON_HEADERS, data=otlp_logs_json)
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/logs")
    assert resp.status == 200
    logs = await resp.json()
    assert len(logs) == 1

    resource_logs = logs[0]["resource_logs"]
    assert _find_service_name_in_resource(
        resource_logs, service_name
    ), f"service.name should be set to '{service_name}' in resource attributes"


async def test_logs_endpoint_invalid_content_type(testagent, otlp_http_url, otlp_logs_string, loop):
    resp = await testagent.post(
        f"{otlp_http_url}{LOGS_ENDPOINT}", headers={"Content-Type": "application/xml"}, data=otlp_logs_string
    )
    assert resp.status == 400

    resp = await testagent.post(
        f"{otlp_http_url}{LOGS_ENDPOINT}", headers={"Content-Type": "text/plain"}, data=b"some plain text"
    )
    assert resp.status == 400

    resp = await testagent.post(f"{otlp_http_url}{LOGS_ENDPOINT}", data=otlp_logs_string)
    assert resp.status == 400


async def test_logs_endpoint_invalid_json(testagent, otlp_http_url, loop):
    resp = await testagent.post(f"{otlp_http_url}{LOGS_ENDPOINT}", headers=JSON_HEADERS, data=b'{"invalid": json}')
    assert resp.status == 400

    resp = await testagent.post(
        f"{otlp_http_url}{LOGS_ENDPOINT}", headers=JSON_HEADERS, data=b'["not", "an", "object"]'
    )
    assert resp.status == 400

    resp = await testagent.post(f"{otlp_http_url}{LOGS_ENDPOINT}", headers=JSON_HEADERS, data=b'"just a string"')
    assert resp.status == 400


async def test_logs_endpoint_basic_grpc(testagent, otlp_logs_grpc_client, otlp_logs_protobuf, loop):
    call = otlp_logs_grpc_client.Export(otlp_logs_protobuf)
    response = await call

    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 200, f"Expected HTTP 200, got {http_status}"

    # For successful requests, partial_success should be empty
    assert response.partial_success.rejected_log_records == 0
    assert response.partial_success.error_message == ""


async def test_session_logs_endpoint_grpc_forwarding(
    testagent, otlp_logs_grpc_client, otlp_test_client, otlp_logs_protobuf, service_name, log_message, loop
):
    call = otlp_logs_grpc_client.Export(otlp_logs_protobuf)
    response = await call
    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 200, f"Expected HTTP 200, got {http_status}"

    logs = otlp_test_client.logs()

    resource_logs = logs[0]["resource_logs"]
    assert _find_service_name_in_resource(
        resource_logs, service_name
    ), f"service.name should be set to '{service_name}' in resource attributes"

    scope_logs = resource_logs[0].get("scope_logs", [])
    assert len(scope_logs) == 1
    log_records = scope_logs[0]["log_records"]
    assert len(log_records) == 1
    assert log_records[0]["body"].get("string_value") == log_message


@pytest.mark.parametrize("grpc_client_with_failure_type", [("http_400", "logs")], indirect=True)
async def test_grpc_maps_http_400_to_metadata(grpc_client_with_failure_type):
    """GRPC forwarding preserves HTTP 400 status in metadata and partial_success."""
    call = grpc_client_with_failure_type.Export(ExportLogsServiceRequest())
    response = await call
    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 400, f"Expected HTTP 400, got {http_status}"

    assert response.partial_success.rejected_log_records == 0  # Empty request
    assert "HTTP 400" in response.partial_success.error_message


@pytest.mark.parametrize("grpc_client_with_failure_type", [("http_500", "logs")], indirect=True)
async def test_grpc_maps_http_500_to_metadata(grpc_client_with_failure_type):
    """GRPC forwarding preserves HTTP 500 status in metadata and partial_success."""
    call = grpc_client_with_failure_type.Export(ExportLogsServiceRequest())
    response = await call
    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 500, f"Expected HTTP 500, got {http_status}"

    assert response.partial_success.rejected_log_records == 0  # Empty request
    assert "HTTP 500" in response.partial_success.error_message


@pytest.mark.parametrize("grpc_client_with_failure_type", [("connection_failure", "logs")], indirect=True)
async def test_grpc_server_resilience_after_failure(grpc_client_with_failure_type, otlp_logs_protobuf):
    """GRPC server remains operational after processing failed requests."""
    call1 = grpc_client_with_failure_type.Export(otlp_logs_protobuf)
    response1 = await call1
    assert response1 is not None

    assert response1.partial_success.rejected_log_records == 1  # 1 ResourceLogs object
    assert "Forward failed" in response1.partial_success.error_message

    http_status = await _get_http_status_from_metadata(call1)
    assert http_status == 500  # Connection failure mapped to 500

    call2 = grpc_client_with_failure_type.Export(otlp_logs_protobuf)
    response2 = await call2
    assert response2 is not None

    assert response2.partial_success.rejected_log_records == 1  # 1 ResourceLogs object
    assert "Forward failed" in response2.partial_success.error_message

    call3 = grpc_client_with_failure_type.Export(ExportLogsServiceRequest())
    response3 = await call3
    assert response3 is not None
