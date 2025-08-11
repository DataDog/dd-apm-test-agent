from urllib.parse import urlparse

import aiohttp
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.common.v1.common_pb2 import AnyValue
from opentelemetry.proto.common.v1.common_pb2 import KeyValue
from opentelemetry.proto.logs.v1.logs_pb2 import LogRecord
from opentelemetry.proto.logs.v1.logs_pb2 import ResourceLogs
from opentelemetry.proto.logs.v1.logs_pb2 import ScopeLogs
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
import pytest

from ddapm_test_agent.agent import make_otlp_http_app
from ddapm_test_agent.client import TestAgentClient


# Constants
PROTOBUF_HEADERS = {"Content-Type": "application/x-protobuf"}
JSON_HEADERS = {"Content-Type": "application/json"}
OTLP_HTTP_PORT = 4318
OTLP_GRPC_PORT = 4317  # Future: GRPC support


def _find_service_name_in_resource(resource_logs, expected_service_name):
    """Check if service.name matches expected value in resource attributes."""
    if not resource_logs or not resource_logs[0].get("resource"):
        return False

    resource = resource_logs[0]["resource"]
    for attr in resource.get("attributes", []):
        if attr.get("key") == "service.name" and attr.get("value", {}).get("string_value") == expected_service_name:
            return True
    return False


def _get_log_body(resource_logs):
    """Extract log message body from resource logs."""
    if (
        not resource_logs
        or not resource_logs[0].get("scope_logs")
        or not resource_logs[0]["scope_logs"][0].get("log_records")
        or not resource_logs[0]["scope_logs"][0]["log_records"][0].get("body")
    ):
        return None

    scope_logs = resource_logs[0]["scope_logs"]
    log_records = scope_logs[0]["log_records"]
    return log_records[0]["body"].get("string_value")


@pytest.fixture
def service_name():
    """Service name."""
    return "ddservice"


@pytest.fixture
def environment():
    """Environment name."""
    return "ddenv"


@pytest.fixture
def version():
    """Service version."""
    return "ddv1"


@pytest.fixture
def host_name():
    """Host name."""
    return "ddhost"


@pytest.fixture
def log_message():
    """Log message content."""
    return "test_otel_logs_exporter_auto_configured_http"


@pytest.fixture
def trace_id():
    """Trace ID."""
    return b""


@pytest.fixture
def span_id():
    """Span ID."""
    return b""


@pytest.fixture
def otlp_logs(service_name, environment, version, host_name, log_message, trace_id, span_id):
    """Serialize OTLP logs protobuf payload."""
    # Create resource attributes
    resource = Resource()
    resource.attributes.extend(
        [
            KeyValue(key="service.name", value=AnyValue(string_value=service_name)),
            KeyValue(key="deployment.environment", value=AnyValue(string_value=environment)),
            KeyValue(key="service.version", value=AnyValue(string_value=version)),
            KeyValue(key="host.name", value=AnyValue(string_value=host_name)),
        ]
    )

    # Create log record
    log_record = LogRecord()
    log_record.body.string_value = log_message
    log_record.trace_id = trace_id
    log_record.span_id = span_id

    # Create scope logs
    scope_logs = ScopeLogs()
    scope_logs.log_records.append(log_record)

    # Create resource logs
    resource_logs = ResourceLogs()
    resource_logs.resource.CopyFrom(resource)
    resource_logs.scope_logs.append(scope_logs)

    # Create export request
    export_request = ExportLogsServiceRequest()
    export_request.resource_logs.append(resource_logs)

    return export_request.SerializeToString()


@pytest.fixture
def otlp_logs_json(service_name, environment, version, host_name, log_message, trace_id, span_id):
    """JSON representation of OTLP logs payload."""
    return {
        "resource_logs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"string_value": service_name}},
                        {"key": "deployment.environment", "value": {"string_value": environment}},
                        {"key": "service.version", "value": {"string_value": version}},
                        {"key": "host.name", "value": {"string_value": host_name}},
                    ]
                },
                "scope_logs": [
                    {
                        "log_records": [
                            {
                                "body": {"string_value": log_message},
                                "trace_id": trace_id.hex() if trace_id else "",
                                "span_id": span_id.hex() if span_id else "",
                            }
                        ]
                    }
                ],
            }
        ]
    }


@pytest.fixture
async def otlp_http_agent(agent_app, aiohttp_client):
    """Test client for OTLP HTTP app."""
    # Get the shared agent instance from the main app
    agent = agent_app.app["agent"]
    otlp_http_app = make_otlp_http_app(agent)

    # Create a client for the OTLP HTTP app
    client = await aiohttp_client(otlp_http_app)
    yield client


# Future: GRPC support fixtures
# @pytest.fixture
# async def otlp_grpc_client():
#     """Test client for OTLP GRPC server."""
#     # Create GRPC channel and LogsService stub for port 4317
#     pass
#
#
# @pytest.fixture
# async def otlp_grpc_agent(agent_app):
#     """Test client for OTLP GRPC server that forwards to HTTP."""
#     # Return GRPC client for testing GRPC→HTTP forwarding
#     pass


# Future: GRPC support
# @pytest.fixture
# def otlp_grpc_url(testagent_url):
#     """URL for OTLP GRPC logs endpoint."""
#     pass


@pytest.fixture
def otlp_http_url(testagent_url):
    """URL for OTLP HTTP logs endpoint."""
    parsed_url = urlparse(testagent_url)
    return f"{parsed_url.scheme}://{parsed_url.hostname}:{OTLP_HTTP_PORT}"


@pytest.fixture
def otlp_http_client(otlp_http_url):
    """Test Agent client for retrieving logs from the OTLP HTTP endpoint."""
    return TestAgentClient(otlp_http_url)


async def test_logs_endpoint_basic_http(otlp_http_agent, otlp_logs):
    """POST /v1/logs accepts OTLP logs over HTTP and returns 200."""
    resp = await otlp_http_agent.post("/v1/logs", headers=PROTOBUF_HEADERS, data=otlp_logs)
    assert resp.status == 200


async def test_session_logs_endpoint_http(otlp_http_agent, otlp_logs, service_name):
    """GET /test/session/logs returns stored logs with correct attributes via HTTP."""
    # Send logs
    resp = await otlp_http_agent.post("/v1/logs", headers=PROTOBUF_HEADERS, data=otlp_logs)
    assert resp.status == 200

    # Get logs from session
    resp = await otlp_http_agent.get("/test/session/logs")
    assert resp.status == 200
    logs = await resp.json()
    assert len(logs) == 1
    assert "resource_logs" in logs[0]

    # Verify basic structure and content
    resource_logs = logs[0]["resource_logs"]
    assert len(resource_logs) == 1

    # Check that service.name is set in resource attributes
    assert _find_service_name_in_resource(
        resource_logs, service_name
    ), f"service.name should be set to '{service_name}' in resource attributes"

    # Check that log message body is not null
    log_body = _get_log_body(resource_logs)
    assert log_body is not None and log_body != "", "Log message body should not be null or empty"


async def test_client_logs_method_http(testagent, otlp_http_client, otlp_http_url, otlp_logs, service_name):
    """TestAgentClient.logs() retrieves stored logs correctly via HTTP."""
    # Send logs via aiohttp session to the OTLP HTTP port
    async with aiohttp.ClientSession() as session:
        resp = await session.post(f"{otlp_http_url}/v1/logs", headers=PROTOBUF_HEADERS, data=otlp_logs)
        assert resp.status == 200

    # Get logs via TestAgentClient from the OTLP HTTP port
    logs = otlp_http_client.logs()
    assert len(logs) == 1
    assert "resource_logs" in logs[0]

    # Verify service.name is set in resource attributes
    resource_logs = logs[0]["resource_logs"]
    assert _find_service_name_in_resource(
        resource_logs, service_name
    ), f"service.name should be set to '{service_name}' in resource attributes"


async def test_logs_endpoint_integration_http(otlp_http_agent, otlp_logs, service_name):
    """End-to-end OTLP logs flow via HTTP: send logs, retrieve them, validate content."""
    # Clear any existing data
    resp = await otlp_http_agent.get("/test/session/clear")
    assert resp.status == 200

    # Send logs request
    resp = await otlp_http_agent.post("/v1/logs", headers=PROTOBUF_HEADERS, data=otlp_logs)
    assert resp.status == 200

    # Retrieve the logs
    resp = await otlp_http_agent.get("/test/session/logs")
    assert resp.status == 200
    captured_logs_list = await resp.json()

    # Verify we got at least one resource log
    assert len(captured_logs_list) > 0, "Expected at least one resource log"

    captured_logs = captured_logs_list[0]
    resource_logs = captured_logs["resource_logs"]
    assert len(resource_logs) > 0

    # Verify service.name is set in resource attributes
    assert _find_service_name_in_resource(
        resource_logs, service_name
    ), f"service.name should be set to '{service_name}' in resource attributes"

    # Verify log message body is not null
    log_body = _get_log_body(resource_logs)
    assert log_body is not None and log_body != "", "Log message body should not be null or empty"


async def test_multiple_logs_sessions_http(otlp_http_agent, otlp_logs):
    """Logs are isolated between sessions via HTTP."""
    # Send first log
    resp = await otlp_http_agent.post("/v1/logs", headers=PROTOBUF_HEADERS, data=otlp_logs)
    assert resp.status == 200

    # Start a new session
    resp = await otlp_http_agent.get("/test/session/start")
    assert resp.status == 200

    # Send second log in new session
    resp = await otlp_http_agent.post("/v1/logs", headers=PROTOBUF_HEADERS, data=otlp_logs)
    assert resp.status == 200

    # Get logs from current session (should only have one log)
    resp = await otlp_http_agent.get("/test/session/logs")
    assert resp.status == 200
    logs = await resp.json()
    assert len(logs) == 1  # Only the log from the current session


async def test_logs_endpoint_json_http(otlp_http_agent, otlp_logs_json, service_name):
    """POST /v1/logs accepts JSON logs and returns 200."""
    import json

    resp = await otlp_http_agent.post("/v1/logs", headers=JSON_HEADERS, data=json.dumps(otlp_logs_json))
    assert resp.status == 200

    # Verify logs were stored
    resp = await otlp_http_agent.get("/test/session/logs")
    assert resp.status == 200
    logs = await resp.json()
    assert len(logs) == 1

    # Verify service.name is set in resource attributes
    resource_logs = logs[0]["resource_logs"]
    assert _find_service_name_in_resource(
        resource_logs, service_name
    ), f"service.name should be set to '{service_name}' in resource attributes"


async def test_logs_endpoint_invalid_content_type(otlp_http_agent, otlp_logs):
    """POST /v1/logs rejects invalid content types."""
    # Test with XML content type (unsupported)
    resp = await otlp_http_agent.post("/v1/logs", headers={"Content-Type": "application/xml"}, data=otlp_logs)
    assert resp.status == 400

    # Test with plain text content type (unsupported)
    resp = await otlp_http_agent.post("/v1/logs", headers={"Content-Type": "text/plain"}, data=b"some plain text")
    assert resp.status == 400

    # Test with no content type header
    resp = await otlp_http_agent.post("/v1/logs", data=otlp_logs)
    assert resp.status == 400


async def test_logs_endpoint_invalid_json(otlp_http_agent):
    """POST /v1/logs rejects malformed JSON."""
    # Test malformed JSON syntax
    resp = await otlp_http_agent.post("/v1/logs", headers=JSON_HEADERS, data=b'{"invalid": json}')
    assert resp.status == 400

    # Test JSON array (should be object)
    resp = await otlp_http_agent.post("/v1/logs", headers=JSON_HEADERS, data=b'["not", "an", "object"]')
    assert resp.status == 400

    # Test JSON primitive (should be object)
    resp = await otlp_http_agent.post("/v1/logs", headers=JSON_HEADERS, data=b'"just a string"')
    assert resp.status == 400


# Future: GRPC support tests
# Future: GRPC support tests
# async def test_logs_endpoint_basic_grpc(otlp_grpc_client, otlp_logs):
#     """Export logs via GRPC and verify they're forwarded to HTTP server."""
#     # Convert protobuf payload to GRPC request and call Export method
#     pass
#
#
# async def test_session_logs_endpoint_grpc_forwarding(otlp_grpc_client, otlp_http_agent, otlp_logs, service_name):
#     """Verify GRPC logs are forwarded to HTTP and retrievable via session endpoint."""
#     # Test end-to-end GRPC→HTTP→Session flow and verify data preservation
#     pass
